//! The user-memory side of `AF_UNIX` sockets: `struct sockaddr_un` and the
//! ancillary data (`struct cmsghdr`) of `sendmsg` and `recvmsg`.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_sync::fallible::try_zeroed;

use crate::bytes;
use crate::process::Process;
use crate::unix::{Addr, Anc, Cred, MAX_FDS_PER_MSG, SOCKADDR_UN_MAX};

pub(crate) const AF_UNIX: u64 = 1;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
/// `sizeof(struct cmsghdr)`.
const CMSG_HDR: usize = 16;
/// `sizeof(struct ucred)`.
pub(crate) const UCRED_LEN: usize = 12;
/// Most bytes of ancillary data one call takes or gives.
const CONTROL_MAX: u64 = 64 * 1024;

/// The credentials of `p`. There are no users: everything is root.
pub(crate) fn cred(p: &Process) -> Cred {
    Cred { pid: p.pid().0, uid: 0, gid: 0 }
}

/// Reads the `struct sockaddr_un` of `len` bytes at `va`: `None` for the
/// request of an automatic name.
pub(crate) fn get_addr(p: &Process, va: u64, len: u64) -> Result<Option<Addr>, Errno> {
    let len = usize::try_from(len).map_err(|_| Errno::EINVAL)?;
    if !(2..=SOCKADDR_UN_MAX).contains(&len) {
        return Err(Errno::EINVAL);
    }
    let mut b = [0u8; SOCKADDR_UN_MAX];
    let b = bytes::slice_mut(&mut b, 0, len)?;
    p.memory().read(va, b)?;
    if u64::from(bytes::u16_at(b, 0)?) != AF_UNIX {
        return Err(Errno::EAFNOSUPPORT);
    }
    Addr::parse(bytes::slice(b, 2, len - 2)?)
}

/// Writes `addr` (the family alone for `None`) as a `struct sockaddr_un`,
/// truncated to the `u32` length at `lenp`, which gets the full size. Does
/// nothing if `va` is 0.
pub(crate) fn put_addr(p: &Process, va: u64, lenp: u64, addr: Option<&Addr>) -> Result<(), Errno> {
    if va == 0 {
        return Ok(());
    }
    let mut cap = [0u8; 4];
    p.memory().read(lenp, &mut cap)?;
    let full = match addr {
        Some(a) => a.encode()?,
        None => (AF_UNIX as u16).to_ne_bytes().to_vec(),
    };
    let n = (u32::from_ne_bytes(cap) as usize).min(full.len());
    p.memory().write(va, bytes::slice(&full, 0, n)?)?;
    p.memory().write(lenp, &(full.len() as u32).to_ne_bytes())
}

/// Rounds up to the alignment of a `cmsghdr`.
fn align(n: usize) -> usize {
    n.saturating_add(7) & !7
}

/// Reads the ancillary data of `len` bytes at `va` that a `sendmsg` carries.
pub(crate) fn read_control(p: &Process, va: u64, len: u64) -> Result<Option<Anc>, Errno> {
    if len == 0 {
        return Ok(None);
    }
    if len > CONTROL_MAX {
        return Err(Errno::ENOBUFS);
    }
    let mut buf = try_zeroed(len as usize).map_err(crate::oom)?;
    p.memory().read(va, &mut buf)?;
    let mut files = Vec::new();
    let mut sent_cred = None;
    let mut off = 0usize;
    while off.saturating_add(CMSG_HDR) <= buf.len() {
        let cmsg_len = usize::try_from(bytes::u64_at(&buf, off)?).map_err(|_| Errno::EINVAL)?;
        let (level, kind) = (bytes::i32_at(&buf, off + 8)?, bytes::i32_at(&buf, off + 12)?);
        let end = off.checked_add(cmsg_len).filter(|&e| cmsg_len >= CMSG_HDR && e <= buf.len()).ok_or(Errno::EINVAL)?;
        let data = bytes::slice(&buf, off + CMSG_HDR, cmsg_len - CMSG_HDR)?;
        match (level, kind) {
            (SOL_SOCKET, SCM_RIGHTS) => {
                if data.len() % 4 != 0 {
                    return Err(Errno::EINVAL);
                }
                for chunk in data.chunks(4) {
                    if files.len() >= MAX_FDS_PER_MSG {
                        return Err(Errno::EINVAL);
                    }
                    let fd = bytes::i32_at(chunk, 0)?;
                    let file = p.files().lock().get(fd)?;
                    files.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                    files.push(file);
                }
            }
            (SOL_SOCKET, SCM_CREDENTIALS) => {
                if data.len() < UCRED_LEN {
                    return Err(Errno::EINVAL);
                }
                let c =
                    Cred { pid: bytes::u32_at(data, 0)?, uid: bytes::u32_at(data, 4)?, gid: bytes::u32_at(data, 8)? };
                // Only one's own identity may be claimed.
                if c != cred(p) {
                    return Err(Errno::EPERM);
                }
                sent_cred = Some(c);
            }
            _ => return Err(Errno::EINVAL),
        }
        off = align(end);
    }
    if files.is_empty() && sent_cred.is_none() {
        return Ok(None);
    }
    Anc::new(files, sent_cred).map(Some)
}

/// Delivers the ancillary data of a received message into the `cap` bytes at
/// `va`: the files go into `p`'s descriptor table (close-on-exec if
/// `cloexec`), the credentials only if `want_cred`. Returns the bytes written
/// and whether something did not fit (`MSG_CTRUNC`). What does not fit is
/// dropped.
pub(crate) fn write_control(
    p: &Process,
    va: u64,
    cap: u64,
    anc: Option<Anc>,
    cloexec: bool,
    want_cred: bool,
) -> Result<(usize, bool), Errno> {
    let Some(mut anc) = anc else { return Ok((0, false)) };
    let cap = usize::try_from(cap.min(CONTROL_MAX)).unwrap_or(0);
    let files = anc.take_files();
    let mut truncated = false;
    let mut installed: Vec<i32> = Vec::new();
    if !files.is_empty() {
        let fit = cap.saturating_sub(CMSG_HDR) / 4;
        truncated |= fit < files.len();
        installed.try_reserve_exact(files.len().min(fit)).map_err(|_| Errno::ENOMEM)?;
        let mut table = p.files().lock();
        for file in files.into_iter().take(fit) {
            match table.insert_from(0, file, cloexec) {
                Ok(fd) => installed.push(fd),
                Err(_) => {
                    truncated = true;
                    break;
                }
            }
        }
    }
    let mut out: Vec<u8> = Vec::new();
    let built = (|| {
        let cmsg_len = CMSG_HDR + 4 * installed.len();
        let cred_len = CMSG_HDR + UCRED_LEN;
        out.try_reserve_exact(align(cmsg_len) + align(cred_len)).map_err(|_| Errno::ENOMEM)?;
        if !installed.is_empty() {
            out.extend_from_slice(&(cmsg_len as u64).to_ne_bytes());
            out.extend_from_slice(&SOL_SOCKET.to_ne_bytes());
            out.extend_from_slice(&SCM_RIGHTS.to_ne_bytes());
            for fd in &installed {
                out.extend_from_slice(&fd.to_ne_bytes());
            }
            out.resize(align(out.len()), 0);
        }
        if let (true, Some(c)) = (want_cred, anc.cred()) {
            if cap >= out.len() + cred_len {
                out.extend_from_slice(&(cred_len as u64).to_ne_bytes());
                out.extend_from_slice(&SOL_SOCKET.to_ne_bytes());
                out.extend_from_slice(&SCM_CREDENTIALS.to_ne_bytes());
                for v in [c.pid, c.uid, c.gid] {
                    out.extend_from_slice(&v.to_ne_bytes());
                }
            } else {
                truncated = true;
            }
        }
        // The last message is not padded out past what the program has room for.
        out.truncate(cap);
        if !out.is_empty() {
            p.memory().write(va, &out)?;
        }
        Ok::<(), Errno>(())
    })();
    match built {
        Ok(()) => Ok((out.len(), truncated)),
        Err(e) => {
            let mut table = p.files().lock();
            for fd in installed {
                let _ = table.close(fd);
            }
            Err(e)
        }
    }
}

/// A `Cred` as `struct ucred` bytes.
pub(crate) fn ucred_bytes(c: Cred) -> [u8; UCRED_LEN] {
    let mut b = [0u8; UCRED_LEN];
    for (i, v) in [c.pid, c.uid, c.gid].into_iter().enumerate() {
        let _ = bytes::put(&mut b, i * 4, &v.to_ne_bytes());
    }
    b
}
