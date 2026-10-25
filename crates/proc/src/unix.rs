//! `AF_UNIX` sockets, stream or datagram, backed by memory.
//!
//! A socket is made by `socket` or `socketpair`. It may be given a name by
//! `bind`: either a path in the file system (which makes a socket node there,
//! and which `connect` and `sendto` find by the node's identity, so a rename
//! is harmless but an unlink and re-bind is a new name) or an abstract name
//! (a byte string with no file behind it). Streams then `listen`, `connect`
//! and `accept`; datagram sockets `connect` to fix a destination or `sendto`
//! a name.
//!
//! A message may carry ancillary data: open files (`SCM_RIGHTS`) and the
//! sender's credentials (`SCM_CREDENTIALS`). Files in transit are counted
//! ([`in_flight`]) and limited ([`MAX_IN_FLIGHT`]); a message that would go
//! over the limit fails with `ETOOMANYREFS`. A socket that is sent over
//! itself (directly or through a loop of sockets) is never freed, as the
//! queued file keeps its holder open; the limit bounds what such loops can
//! pin.
//!
//! # Locking
//!
//! Each socket has one lock. No code holds two at once and none holds one
//! while it drops a queued file (which may be a socket), so there is no lock
//! order to keep. Peers refer to each other weakly.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use osmium_fs::{Errno, File, FileKind, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, Stat};
use osmium_sync::IrqSpinLock;
use osmium_sync::fallible::{try_arc, try_string, try_to_vec};

use crate::fd::OpenFile;
use crate::poll::{notify, wait};

/// Bytes a stream buffers in each direction.
const STREAM_CAP: usize = 64 * 1024;
/// Datagrams queued in each direction.
const DGRAM_QUEUE: usize = 64;
/// Largest datagram.
pub(crate) const DGRAM_MAX: usize = 64 * 1024;
/// Most files one message carries (`SCM_MAX_FD`).
pub(crate) const MAX_FDS_PER_MSG: usize = 253;
/// Most files in transit, across all sockets, at once.
pub const MAX_IN_FLIGHT: usize = 4096;
/// Longest `struct sockaddr_un`.
pub(crate) const SOCKADDR_UN_MAX: usize = 110;
/// Connections that may wait to be accepted, at most.
const MAX_BACKLOG: usize = 128;

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// Files currently queued in messages that nobody has received yet.
pub fn in_flight() -> usize {
    IN_FLIGHT.load(Ordering::Relaxed)
}

/// A claim on `n` places of the in-flight limit, given back on drop.
struct InFlight(usize);

impl InFlight {
    /// Claims `n` places, or fails with `ETOOMANYREFS`.
    fn claim(n: usize) -> Result<Self, Errno> {
        let mut cur = IN_FLIGHT.load(Ordering::Relaxed);
        loop {
            let next = cur.checked_add(n).filter(|&t| t <= MAX_IN_FLIGHT).ok_or(Errno::ETOOMANYREFS)?;
            match IN_FLIGHT.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(Self(n)),
                Err(now) => cur = now,
            }
        }
    }

    /// Claims `n` places whatever the limit (for a copy that is received at
    /// once).
    fn force(n: usize) -> Self {
        IN_FLIGHT.fetch_add(n, Ordering::Relaxed);
        Self(n)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(self.0, Ordering::Relaxed);
    }
}

/// The identity a message is sent with (`struct ucred`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// What rides along with a message: open files and credentials.
pub(crate) struct Anc {
    files: Vec<Arc<OpenFile>>,
    _in_flight: InFlight,
    cred: Option<Cred>,
}

impl Anc {
    /// Ancillary data of `files` (counted as in flight until this is dropped)
    /// and `cred`.
    pub(crate) fn new(files: Vec<Arc<OpenFile>>, cred: Option<Cred>) -> Result<Self, Errno> {
        let guard = InFlight::claim(files.len())?;
        Ok(Self { files, _in_flight: guard, cred })
    }

    fn cred_only(cred: Cred) -> Self {
        Self { files: Vec::new(), _in_flight: InFlight(0), cred: Some(cred) }
    }

    /// A copy, for a peek.
    fn duplicate(&self) -> Result<Self, Errno> {
        let mut files = Vec::new();
        files.try_reserve_exact(self.files.len()).map_err(|_| Errno::ENOMEM)?;
        files.extend(self.files.iter().cloned());
        Ok(Self { _in_flight: InFlight::force(files.len()), files, cred: self.cred })
    }

    /// The files, leaving none behind.
    pub(crate) fn take_files(&mut self) -> Vec<Arc<OpenFile>> {
        core::mem::take(&mut self.files)
    }

    /// The sender's credentials, if it sent them.
    pub(crate) fn cred(&self) -> Option<Cred> {
        self.cred
    }
}

/// A socket's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Addr {
    /// A path, as the program gave it.
    Path(String),
    /// An abstract name (the bytes after the leading NUL).
    Abstract(Vec<u8>),
}

impl Addr {
    /// Reads the part of a `struct sockaddr_un` after the family; `None` if
    /// it is empty (the request for an automatic name).
    pub(crate) fn parse(body: &[u8]) -> Result<Option<Self>, Errno> {
        match body.split_first() {
            None => Ok(None),
            Some((0, name)) => Ok(Some(Addr::Abstract(try_to_vec(name).map_err(crate::oom)?))),
            Some(_) => {
                let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
                let path = body.get(..end).ok_or(Errno::EINVAL)?;
                let path = core::str::from_utf8(path).map_err(|_| Errno::EINVAL)?;
                Ok(Some(Addr::Path(try_string(path).map_err(crate::oom)?)))
            }
        }
    }

    /// The address as `struct sockaddr_un` bytes, family included.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Errno> {
        let mut v = Vec::new();
        let (len, body): (usize, &[u8]) = match self {
            Addr::Path(p) => (p.len() + 1, p.as_bytes()),
            Addr::Abstract(n) => (n.len() + 1, n),
        };
        v.try_reserve_exact(2 + len).map_err(|_| Errno::ENOMEM)?;
        v.extend_from_slice(&1u16.to_ne_bytes());
        match self {
            Addr::Path(_) => {
                v.extend_from_slice(body);
                v.push(0);
            }
            Addr::Abstract(_) => {
                v.push(0);
                v.extend_from_slice(body);
            }
        }
        Ok(v)
    }
}

/// The path `path` names from `cwd`.
fn absolute(cwd: &str, path: &str) -> Result<String, Errno> {
    let mut s = String::new();
    if path.starts_with('/') {
        s.try_reserve_exact(path.len()).map_err(|_| Errno::ENOMEM)?;
    } else {
        let base = cwd.trim_end_matches('/');
        s.try_reserve_exact(base.len() + 1 + path.len()).map_err(|_| Errno::ENOMEM)?;
        s.push_str(base);
        s.push('/');
    }
    s.push_str(path);
    Ok(s)
}

/// The names in use: file system nodes by identity, and abstract names.
struct Names {
    paths: Vec<((u64, u64), Weak<Sock>)>,
    names: Vec<(Vec<u8>, Weak<Sock>)>,
}

impl Names {
    fn prune(&mut self) {
        self.paths.retain(|(_, w)| w.strong_count() > 0);
        self.names.retain(|(_, w)| w.strong_count() > 0);
    }
}

static NAMES: IrqSpinLock<Names> = IrqSpinLock::new(Names { paths: Vec::new(), names: Vec::new() });

/// Alive and still open.
fn live(w: &Weak<Sock>) -> Option<Arc<Sock>> {
    w.upgrade().filter(|s| !s.st.lock().closed)
}

/// The socket named `addr`, for `connect` and `sendto`. Paths are relative to
/// `cwd`.
pub(crate) fn lookup(addr: &Addr, cwd: &str) -> Result<Arc<Sock>, Errno> {
    match addr {
        Addr::Abstract(name) => {
            let names = NAMES.lock();
            let found = names.names.iter().find(|(n, _)| n == name).and_then(|(_, w)| live(w));
            drop(names);
            found.ok_or(Errno::ECONNREFUSED)
        }
        Addr::Path(path) => {
            let st = crate::vfs().ok_or(Errno::ENOENT)?.stat(&absolute(cwd, path)?, true)?;
            if st.kind != FileKind::Socket {
                return Err(Errno::ECONNREFUSED);
            }
            let names = NAMES.lock();
            let found = names.paths.iter().find(|(k, _)| *k == (st.dev, st.ino)).and_then(|(_, w)| live(w));
            drop(names);
            found.ok_or(Errno::ECONNREFUSED)
        }
    }
}

/// A message waiting in a datagram socket.
struct Dgram {
    data: Vec<u8>,
    anc: Option<Anc>,
    from: Option<Arc<Addr>>,
}

/// Connections waiting to be accepted by a listening socket.
struct Backlog {
    queue: VecDeque<Arc<Sock>>,
    max: usize,
}

struct St {
    stream: VecDeque<u8>,
    /// Bytes ever queued and ever read, to place ancillary data in the
    /// stream (compared for equality only, so wrapping is harmless).
    queued: u64,
    consumed: u64,
    /// Ancillary data of a stream, with the stream position of the first
    /// byte it belongs to.
    ancs: VecDeque<(u64, Anc)>,
    dgrams: VecDeque<Dgram>,
    /// The socket was closed.
    closed: bool,
    shut_rd: bool,
    shut_wr: bool,
    /// The other end, once connected.
    peer: Option<Weak<Sock>>,
    /// The other end's going away is end of file here (streams and socket
    /// pairs, not a datagram socket that was `connect`ed).
    hangup: bool,
    addr: Option<Arc<Addr>>,
    listen: Option<Backlog>,
    /// Who made the socket, and who the other end was when it connected.
    owner: Cred,
    peer_cred: Option<Cred>,
}

/// The state both a socket's file and its peer see.
pub(crate) struct Sock {
    dgram: bool,
    passcred: AtomicBool,
    st: IrqSpinLock<St>,
}

impl Sock {
    fn new(dgram: bool, owner: Cred) -> Result<Arc<Self>, Errno> {
        let st = St {
            stream: VecDeque::new(),
            queued: 0,
            consumed: 0,
            ancs: VecDeque::new(),
            dgrams: VecDeque::new(),
            closed: false,
            shut_rd: false,
            shut_wr: false,
            peer: None,
            hangup: false,
            addr: None,
            listen: None,
            owner,
            peer_cred: None,
        };
        try_arc(Sock { dgram, passcred: AtomicBool::new(false), st: IrqSpinLock::new(st) }).map_err(crate::oom)
    }

    /// Whether a receive would return something or fail at once.
    fn readable(&self) -> bool {
        let peer = {
            let g = self.st.lock();
            if let Some(b) = &g.listen {
                return !b.queue.is_empty();
            }
            if !g.stream.is_empty() || !g.dgrams.is_empty() || g.shut_rd {
                return true;
            }
            if !g.hangup {
                return false;
            }
            g.peer.clone()
        };
        match peer {
            None => false,
            Some(w) => w.upgrade().is_none_or(|p| {
                let g = p.st.lock();
                g.closed || g.shut_wr
            }),
        }
    }

    /// Whether a send to `target` would take something or fail at once.
    fn has_room(&self, target: &Sock) -> bool {
        if self.st.lock().shut_wr {
            return true;
        }
        let g = target.st.lock();
        let room = if self.dgram { g.dgrams.len() < DGRAM_QUEUE } else { g.stream.len() < STREAM_CAP };
        room || g.closed || g.shut_rd
    }

    /// The socket a send goes to, when it has no name to go to.
    fn peer(&self) -> Option<Weak<Sock>> {
        self.st.lock().peer.clone()
    }
}

/// One end of a socket pair, or a socket of its own: the file behind a
/// descriptor.
pub struct UnixSocket {
    sock: Arc<Sock>,
    nonblock: AtomicBool,
}

/// A connected pair of stream (`dgram` false) or datagram sockets, made by a
/// process with credentials `owner`.
pub(crate) fn socketpair(dgram: bool, nonblock: bool, owner: Cred) -> Result<(UnixSocket, UnixSocket), Errno> {
    let (a, b) = (Sock::new(dgram, owner)?, Sock::new(dgram, owner)?);
    for (x, y) in [(&a, &b), (&b, &a)] {
        let mut g = x.st.lock();
        g.peer = Some(Arc::downgrade(y));
        g.hangup = true;
        g.peer_cred = Some(owner);
    }
    let end = |sock| UnixSocket { sock, nonblock: AtomicBool::new(nonblock) };
    Ok((end(a), end(b)))
}

/// What a receive took.
pub(crate) struct Received {
    /// Bytes copied into the buffer.
    pub copied: usize,
    /// The datagram was longer than the buffer.
    pub truncated: bool,
    /// Files and credentials that came with the data.
    pub anc: Option<Anc>,
    /// The sender's name, for a datagram.
    pub from: Option<Arc<Addr>>,
}

/// A message to send.
pub(crate) struct Outgoing<'data> {
    pub data: &'data [u8],
    pub anc: Option<Anc>,
    /// Where a datagram goes, if not to the connected peer.
    pub to: Option<Arc<Sock>>,
    /// The sender.
    pub cred: Cred,
}

/// Adds the credentials a receiver asked for to what a message carries.
fn with_cred(anc: Option<Anc>, passcred: bool, cred: Cred) -> Option<Anc> {
    match anc {
        Some(mut a) => {
            if passcred && a.cred.is_none() {
                a.cred = Some(cred);
            }
            Some(a)
        }
        None if passcred => Some(Anc::cred_only(cred)),
        None => None,
    }
}

impl UnixSocket {
    /// A new unconnected, unnamed socket.
    pub(crate) fn new(dgram: bool, nonblock: bool, owner: Cred) -> Result<Self, Errno> {
        Ok(Self { sock: Sock::new(dgram, owner)?, nonblock: AtomicBool::new(nonblock) })
    }

    /// Whether this is a datagram socket.
    pub fn is_dgram(&self) -> bool {
        self.sock.dgram
    }

    /// Whether calls fail with `EAGAIN` instead of waiting.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Sets `O_NONBLOCK`.
    pub fn set_nonblocking(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    /// Whether `SO_PASSCRED` is on.
    pub(crate) fn passcred(&self) -> bool {
        self.sock.passcred.load(Ordering::Relaxed)
    }

    /// Sets `SO_PASSCRED`.
    pub(crate) fn set_passcred(&self, on: bool) {
        self.sock.passcred.store(on, Ordering::Relaxed);
    }

    /// `SO_PEERCRED`: who made the other end.
    pub(crate) fn peer_cred(&self) -> Option<Cred> {
        self.sock.st.lock().peer_cred
    }

    /// The socket's own name.
    pub(crate) fn local_addr(&self) -> Option<Arc<Addr>> {
        self.sock.st.lock().addr.clone()
    }

    /// The other end's name, `ENOTCONN` if there is no other end.
    pub(crate) fn peer_addr(&self) -> Result<Option<Arc<Addr>>, Errno> {
        let peer = self.sock.peer().ok_or(Errno::ENOTCONN)?;
        Ok(peer.upgrade().and_then(|p| p.st.lock().addr.clone()))
    }

    /// Gives the socket a name: a file system node of `addr` (relative to
    /// `cwd`) with permissions `0o777 & !umask`, an abstract name, or with
    /// `None` an abstract name of the system's choosing.
    pub(crate) fn bind(&self, addr: Option<Addr>, cwd: &str, umask: u32) -> Result<(), Errno> {
        let this = Arc::downgrade(&self.sock);
        let addr = match addr {
            Some(a) => a,
            None => Self::auto_name()?,
        };
        let shared = try_arc(addr.clone()).map_err(crate::oom)?;
        {
            let mut g = self.sock.st.lock();
            if g.addr.is_some() {
                return Err(Errno::EINVAL);
            }
            g.addr = Some(shared);
        }
        let undo = |e: Errno| {
            self.sock.st.lock().addr = None;
            e
        };
        match addr {
            Addr::Abstract(name) => {
                let mut names = NAMES.lock();
                names.prune();
                if names.names.iter().any(|(n, _)| *n == name) {
                    drop(names);
                    return Err(undo(Errno::EADDRINUSE));
                }
                if names.names.try_reserve(1).is_err() {
                    drop(names);
                    return Err(undo(Errno::ENOMEM));
                }
                names.names.push((name, this));
            }
            Addr::Path(path) => {
                let vfs = crate::vfs().ok_or(Errno::ENOENT).map_err(undo)?;
                let abs = absolute(cwd, &path).map_err(undo)?;
                let node = vfs
                    .mknod(&abs, FileKind::Socket, 0o777 & !umask)
                    .map_err(|e| undo(if e == Errno::EEXIST { Errno::EADDRINUSE } else { e }))?;
                let st = node.try_stat().map_err(undo)?;
                let mut names = NAMES.lock();
                names.prune();
                if names.paths.try_reserve(1).is_err() {
                    drop(names);
                    let _ = vfs.unlink(&abs);
                    return Err(undo(Errno::ENOMEM));
                }
                names.paths.push(((st.dev, st.ino), this));
            }
        }
        Ok(())
    }

    /// A free abstract name, five hex digits as Linux makes them.
    fn auto_name() -> Result<Addr, Errno> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut names = NAMES.lock();
        names.prune();
        for _ in 0..0x10_0000u32 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed) & 0xf_ffff;
            let mut name = Vec::new();
            name.try_reserve_exact(5).map_err(|_| Errno::ENOMEM)?;
            for shift in [16, 12, 8, 4, 0] {
                name.push(*HEX.get(((n >> shift) & 0xf) as usize).unwrap_or(&b'0'));
            }
            if !names.names.iter().any(|(x, _)| *x == name) {
                return Ok(Addr::Abstract(name));
            }
        }
        Err(Errno::EADDRINUSE)
    }

    /// Makes a bound stream socket accept connections, up to `backlog` waiting.
    pub(crate) fn listen(&self, backlog: usize) -> Result<(), Errno> {
        if self.sock.dgram {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut g = self.sock.st.lock();
        if g.addr.is_none() || g.peer.is_some() {
            return Err(Errno::EINVAL);
        }
        let max = backlog.clamp(1, MAX_BACKLOG);
        match &mut g.listen {
            Some(b) => b.max = max,
            None => g.listen = Some(Backlog { queue: VecDeque::new(), max }),
        }
        Ok(())
    }

    /// Connects to the socket `target`: a datagram socket fixes its
    /// destination, a stream waits in `target`'s backlog (for room, if
    /// `wait_for_room`).
    pub(crate) fn connect(&self, target: &Arc<Sock>, wait_for_room: bool) -> Result<(), Errno> {
        if self.sock.dgram != target.dgram {
            return Err(Errno::EPROTOTYPE);
        }
        if self.sock.dgram {
            let cred = target.st.lock().owner;
            let mut g = self.sock.st.lock();
            g.peer = Some(Arc::downgrade(target));
            g.hangup = false;
            g.peer_cred = Some(cred);
            return Ok(());
        }
        let client_cred = {
            let g = self.sock.st.lock();
            if g.listen.is_some() {
                return Err(Errno::EINVAL);
            }
            if g.peer.is_some() {
                return Err(Errno::EISCONN);
            }
            g.owner
        };
        let (server_cred, name) = {
            let g = target.st.lock();
            (g.owner, g.addr.clone())
        };
        // The end `accept` will hand out, made before the connection is
        // queued, where running out of memory leaves nothing behind.
        let server = Sock::new(false, server_cred)?;
        {
            let mut g = server.st.lock();
            g.peer = Some(Arc::downgrade(&self.sock));
            g.hangup = true;
            g.addr = name;
            g.peer_cred = Some(client_cred);
        }
        {
            let mut g = self.sock.st.lock();
            g.peer = Some(Arc::downgrade(&server));
            g.hangup = true;
            g.peer_cred = Some(server_cred);
        }
        let undo = || {
            let mut g = self.sock.st.lock();
            g.peer = None;
            g.hangup = false;
            g.peer_cred = None;
        };
        loop {
            {
                let mut g = target.st.lock();
                let closed = g.closed;
                let Some(b) = g.listen.as_mut().filter(|_| !closed) else {
                    drop(g);
                    undo();
                    return Err(Errno::ECONNREFUSED);
                };
                if b.queue.len() < b.max {
                    if b.queue.try_reserve(1).is_err() {
                        drop(g);
                        undo();
                        return Err(Errno::ENOMEM);
                    }
                    b.queue.push_back(server);
                    drop(g);
                    notify();
                    return Ok(());
                }
            }
            if !wait_for_room {
                undo();
                return Err(Errno::EAGAIN);
            }
            let room = || {
                let g = target.st.lock();
                g.closed || g.listen.as_ref().is_none_or(|b| b.queue.len() < b.max)
            };
            if let Err(e) = wait(None, || room().then_some(())) {
                undo();
                return Err(e);
            }
        }
    }

    /// Takes the oldest waiting connection, waiting for one if `wait_for_one`.
    pub(crate) fn accept(&self, nonblock: bool, wait_for_one: bool) -> Result<(UnixSocket, Option<Arc<Addr>>), Errno> {
        loop {
            {
                let mut g = self.sock.st.lock();
                let Some(b) = g.listen.as_mut() else { return Err(Errno::EINVAL) };
                if let Some(sock) = b.queue.pop_front() {
                    drop(g);
                    notify();
                    let client = sock.st.lock().peer.as_ref().and_then(Weak::upgrade);
                    let from = client.and_then(|p| p.st.lock().addr.clone());
                    return Ok((UnixSocket { sock, nonblock: AtomicBool::new(nonblock) }, from));
                }
            }
            if !wait_for_one {
                return Err(Errno::EAGAIN);
            }
            wait(None, || self.sock.readable().then_some(()))?;
        }
    }

    /// Receives into `buf`; `peek` leaves the message queued. Returns 0 bytes
    /// at end of file.
    pub(crate) fn recv(&self, buf: &mut [u8], peek: bool, wait_for_data: bool) -> Result<Received, Errno> {
        if self.sock.st.lock().listen.is_some() {
            return Err(Errno::EINVAL);
        }
        loop {
            {
                let mut g = self.sock.st.lock();
                let dgram = self.sock.dgram;
                if dgram {
                    if let Some(d) = g.dgrams.front() {
                        let copied = d.data.len().min(buf.len());
                        for (b, x) in buf.iter_mut().zip(d.data.iter().take(copied)) {
                            *b = *x;
                        }
                        let truncated = d.data.len() > copied;
                        let (anc, from) = if peek {
                            (d.anc.as_ref().map(Anc::duplicate).transpose()?, d.from.clone())
                        } else {
                            let Some(d) = g.dgrams.pop_front() else { return Err(Errno::EINVAL) };
                            (d.anc, d.from)
                        };
                        drop(g);
                        notify();
                        return Ok(Received { copied, truncated, anc, from });
                    }
                } else if !g.stream.is_empty() {
                    let consumed = g.consumed;
                    let mut skip = 0;
                    let mut anc = None;
                    if g.ancs.front().is_some_and(|(pos, _)| *pos == consumed) {
                        if peek {
                            anc = g.ancs.front().map(|(_, a)| a.duplicate()).transpose()?;
                            skip = 1;
                        } else {
                            anc = g.ancs.pop_front().map(|(_, a)| a);
                        }
                    }
                    // Stop where the next message's ancillary data begins, so
                    // data with different ancillary data is never merged.
                    let to_next = g.ancs.get(skip).map_or(usize::MAX, |(pos, _)| {
                        usize::try_from(pos.wrapping_sub(consumed)).unwrap_or(usize::MAX)
                    });
                    let copied = buf.len().min(g.stream.len()).min(to_next);
                    if peek {
                        for (b, x) in buf.iter_mut().zip(g.stream.iter().take(copied)) {
                            *b = *x;
                        }
                    } else {
                        for (b, x) in buf.iter_mut().zip(g.stream.drain(..copied)) {
                            *b = x;
                        }
                        g.consumed = consumed.wrapping_add(copied as u64);
                    }
                    drop(g);
                    notify();
                    return Ok(Received { copied, truncated: false, anc, from: None });
                }
                drop(g);
                if self.sock.readable() {
                    return Ok(Received { copied: 0, truncated: false, anc: None, from: None });
                }
            }
            if !wait_for_data {
                return Err(Errno::EAGAIN);
            }
            wait(None, || self.sock.readable().then_some(()))?;
        }
    }

    /// Sends a message to the other end, or to `out.to`; a stream may take
    /// part of it if it does not wait.
    pub(crate) fn send(&self, mut out: Outgoing<'_>, wait_for_room: bool) -> Result<usize, Errno> {
        let dgram = self.sock.dgram;
        if dgram && out.data.len() > DGRAM_MAX {
            return Err(Errno::EMSGSIZE);
        }
        // The datagram is copied before any lock is taken, where memory
        // running out is an error that leaves nothing queued.
        let mut datagram = if dgram { Some(try_to_vec(out.data).map_err(crate::oom)?) } else { None };
        let (from, hangup) = {
            let g = self.sock.st.lock();
            (g.addr.clone(), g.hangup)
        };
        let named = out.to.is_some();
        let mut done = 0;
        loop {
            let (peer, shut_wr) = {
                let g = self.sock.st.lock();
                (g.peer.clone(), g.shut_wr)
            };
            if shut_wr {
                return if done > 0 { Ok(done) } else { Err(Errno::EPIPE) };
            }
            let target = match (&out.to, peer) {
                (Some(t), _) => t.clone(),
                (None, Some(w)) => match w.upgrade() {
                    Some(t) => t,
                    None if done > 0 => return Ok(done),
                    None => return Err(if hangup { Errno::EPIPE } else { Errno::ECONNREFUSED }),
                },
                (None, None) => return Err(if dgram { Errno::EDESTADDRREQ } else { Errno::ENOTCONN }),
            };
            {
                let mut g = target.st.lock();
                if g.closed || g.listen.is_some() {
                    drop(g);
                    return if done > 0 {
                        Ok(done)
                    } else {
                        Err(if named || !hangup { Errno::ECONNREFUSED } else { Errno::EPIPE })
                    };
                }
                if g.shut_rd {
                    return if done > 0 { Ok(done) } else { Err(Errno::EPIPE) };
                }
                let passcred = target.passcred.load(Ordering::Relaxed);
                if dgram {
                    if g.dgrams.len() < DGRAM_QUEUE {
                        g.dgrams.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                        // Made above for datagrams.
                        let Some(data) = datagram.take() else { return Err(Errno::EINVAL) };
                        let anc = with_cred(out.anc.take(), passcred, out.cred);
                        g.dgrams.push_back(Dgram { data, anc, from });
                        drop(g);
                        notify();
                        return Ok(out.data.len());
                    }
                } else {
                    let n = out.data.len().saturating_sub(done).min(STREAM_CAP.saturating_sub(g.stream.len()));
                    if n > 0 {
                        if g.stream.try_reserve(n).is_err() || g.ancs.try_reserve(1).is_err() {
                            return if done > 0 { Ok(done) } else { Err(Errno::ENOMEM) };
                        }
                        // Ancillary data belongs to the first byte sent.
                        let anc = with_cred(out.anc.take(), passcred, out.cred);
                        if let Some(anc) = anc {
                            let repeats = anc.files.is_empty()
                                && g.ancs.back().is_some_and(|(_, b)| b.files.is_empty() && b.cred == anc.cred);
                            if !repeats {
                                let at = g.queued;
                                g.ancs.push_back((at, anc));
                            }
                        }
                        g.stream.extend(out.data.get(done..done + n).unwrap_or_default());
                        g.queued = g.queued.wrapping_add(n as u64);
                        done += n;
                        drop(g);
                        notify();
                        if done == out.data.len() || !wait_for_room {
                            return Ok(done);
                        }
                        continue;
                    } else if out.data.is_empty() {
                        return Ok(0);
                    }
                }
            }
            if done > 0 {
                return Ok(done);
            }
            if !wait_for_room {
                return Err(Errno::EAGAIN);
            }
            wait(None, || self.sock.has_room(&target).then_some(()))?;
        }
    }

    /// `shutdown`: `how` is 0 (read), 1 (write) or 2 (both).
    pub fn shutdown(&self, how: u64) -> Result<(), Errno> {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        {
            let mut g = self.sock.st.lock();
            g.shut_rd |= how != 1;
            g.shut_wr |= how != 0;
        }
        notify();
        Ok(())
    }
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        let (stream, dgrams, ancs, backlog) = {
            let mut g = self.sock.st.lock();
            g.closed = true;
            (
                core::mem::take(&mut g.stream),
                core::mem::take(&mut g.dgrams),
                core::mem::take(&mut g.ancs),
                g.listen.take(),
            )
        };
        {
            let me = Arc::downgrade(&self.sock);
            let mut names = NAMES.lock();
            names.paths.retain(|(_, w)| !w.ptr_eq(&me));
            names.names.retain(|(_, w)| !w.ptr_eq(&me));
        }
        // Queued files may be sockets that take their own locks as they go.
        drop((stream, dgrams, ancs, backlog));
        notify();
    }
}

impl File for UnixSocket {
    fn read(&self, _off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.recv(buf, false, !self.is_nonblocking()).map(|r| r.copied)
    }

    fn write(&self, _off: u64, buf: &[u8]) -> Result<usize, Errno> {
        let cred = self.sock.st.lock().owner;
        self.send(Outgoing { data: buf, anc: None, to: None, cred }, !self.is_nonblocking())
    }

    fn stat(&self) -> Stat {
        Stat { kind: FileKind::Socket, mode: 0o777, nlink: 1, ..Stat::default() }
    }

    fn poll(&self) -> u32 {
        let mut m = 0;
        let (listening, peer, shut_rd, shut_wr, hangup) = {
            let g = self.sock.st.lock();
            (g.listen.is_some(), g.peer.clone(), g.shut_rd, g.shut_wr, g.hangup)
        };
        if listening {
            return if self.sock.readable() { POLLIN } else { 0 };
        }
        if self.sock.readable() {
            m |= POLLIN;
        }
        let gone = |p: &Sock| {
            let g = p.st.lock();
            (g.closed, g.shut_wr)
        };
        match peer.map(|w| w.upgrade()) {
            Some(Some(p)) => {
                if self.sock.has_room(&p) {
                    m |= POLLOUT;
                }
                let (closed, p_shut_wr) = gone(&p);
                if hangup && (closed || p_shut_wr) {
                    m |= POLLRDHUP;
                }
                if (hangup && closed) || (shut_rd && shut_wr) {
                    m |= POLLHUP;
                }
            }
            Some(None) => {
                m |= POLLOUT;
                if hangup {
                    m |= POLLRDHUP | POLLHUP;
                }
            }
            // Not connected: a datagram socket can always send to a name.
            None => {
                if self.sock.dgram {
                    m |= POLLOUT;
                }
            }
        }
        m
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}
