//! `pipe` and `pipe2`: a byte stream in memory with a read end and a write
//! end, each its own open file description.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use osmium_fs::{Errno, File, FileKind, POLLERR, POLLHUP, POLLIN, POLLOUT, Stat};
use osmium_sync::IrqSpinLock;
use osmium_sync::fallible::try_arc;

use crate::fd::{Access, OpenFile};
use crate::poll::{notify, wait};
use crate::process::Process;

type SysResult = Result<u64, Errno>;

/// Bytes a pipe buffers.
const CAPACITY: usize = 64 * 1024;
/// Writes up to this size are never interleaved with another writer's.
const PIPE_BUF: usize = 4096;
/// `O_NONBLOCK` and `O_CLOEXEC` in `pipe2` flags.
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;

#[derive(Default)]
struct State {
    data: VecDeque<u8>,
    /// The read end was closed.
    no_reader: bool,
    /// The write end was closed.
    no_writer: bool,
}

type Shared = Arc<IrqSpinLock<State>>;

/// The read end of a pipe.
pub struct PipeReader {
    pipe: Shared,
    nonblock: AtomicBool,
}

/// The write end of a pipe.
pub struct PipeWriter {
    pipe: Shared,
    nonblock: AtomicBool,
}

/// A new pipe: its read end and its write end. `ENOMEM` if there is no
/// memory for it.
pub fn try_pipe(nonblock: bool) -> Result<(PipeReader, PipeWriter), Errno> {
    let pipe = try_arc(IrqSpinLock::new(State::default())).map_err(crate::oom)?;
    Ok((
        PipeReader { pipe: pipe.clone(), nonblock: AtomicBool::new(nonblock) },
        PipeWriter { pipe, nonblock: AtomicBool::new(nonblock) },
    ))
}

impl PipeReader {
    /// Whether a read returns data or end of file.
    fn ready(s: &State) -> bool {
        !s.data.is_empty() || s.no_writer
    }
}

impl PipeReader {
    /// Whether reads fail with `EAGAIN` instead of waiting.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Sets `O_NONBLOCK`.
    pub fn set_nonblocking(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }
}

impl PipeWriter {
    /// Whether writes fail with `EAGAIN` instead of waiting.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Sets `O_NONBLOCK`.
    pub fn set_nonblocking(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }
}

impl File for PipeReader {
    fn read(&self, _off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            {
                let mut s = self.pipe.lock();
                if !s.data.is_empty() {
                    let n = buf.len().min(s.data.len());
                    for (b, x) in buf.iter_mut().zip(s.data.drain(..n)) {
                        *b = x;
                    }
                    drop(s);
                    notify();
                    return Ok(n);
                }
                if s.no_writer {
                    return Ok(0);
                }
            }
            if self.is_nonblocking() {
                return Err(Errno::EAGAIN);
            }
            wait(None, || Self::ready(&self.pipe.lock()).then_some(()))?;
        }
    }

    fn stat(&self) -> Stat {
        Stat { kind: FileKind::Fifo, mode: 0o600, nlink: 1, ..Stat::default() }
    }

    fn poll(&self) -> u32 {
        let s = self.pipe.lock();
        (if s.data.is_empty() { 0 } else { POLLIN }) | if s.no_writer { POLLHUP } else { 0 }
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        self.pipe.lock().no_reader = true;
        notify();
    }
}

impl File for PipeWriter {
    /// Up to `PIPE_BUF` bytes go in whole or not at all; a longer write fills
    /// the pipe as readers make room, and a non-blocking one returns what fit.
    fn write(&self, _off: u64, buf: &[u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        let need = buf.len().min(PIPE_BUF);
        let mut done = 0;
        loop {
            {
                let mut s = self.pipe.lock();
                if s.no_reader {
                    return if done > 0 { Ok(done) } else { Err(Errno::EPIPE) };
                }
                let room = CAPACITY - s.data.len();
                let n = if buf.len() <= PIPE_BUF {
                    if room >= need { need } else { 0 }
                } else {
                    room.min(buf.len() - done)
                };
                if n > 0 {
                    if s.data.try_reserve(n).is_err() {
                        return if done > 0 { Ok(done) } else { Err(Errno::ENOMEM) };
                    }
                    s.data.extend(buf.get(done..done + n).unwrap_or_default());
                    done += n;
                    drop(s);
                    notify();
                    if done == buf.len() {
                        return Ok(done);
                    }
                    continue;
                }
            }
            if self.is_nonblocking() {
                return if done > 0 { Ok(done) } else { Err(Errno::EAGAIN) };
            }
            let want = if buf.len() <= PIPE_BUF { need } else { 1 };
            let waited = wait(None, || {
                let s = self.pipe.lock();
                (s.no_reader || CAPACITY - s.data.len() >= want).then_some(())
            });
            if let Err(e) = waited {
                return if done > 0 { Ok(done) } else { Err(e) };
            }
        }
    }

    fn stat(&self) -> Stat {
        Stat { kind: FileKind::Fifo, mode: 0o600, nlink: 1, ..Stat::default() }
    }

    fn poll(&self) -> u32 {
        let s = self.pipe.lock();
        if s.no_reader {
            POLLERR
        } else if CAPACITY - s.data.len() >= PIPE_BUF {
            POLLOUT
        } else {
            0
        }
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.pipe.lock().no_writer = true;
        notify();
    }
}

/// `F_GETFL`'s `O_NONBLOCK` for a pipe end, else 0.
pub(crate) fn status_flags(file: &Arc<dyn File>) -> u64 {
    let any = file.as_any();
    let r = any.and_then(|a| a.downcast_ref::<PipeReader>()).is_some_and(PipeReader::is_nonblocking);
    let w = any.and_then(|a| a.downcast_ref::<PipeWriter>()).is_some_and(PipeWriter::is_nonblocking);
    if r || w { O_NONBLOCK } else { 0 }
}

/// Applies `F_SETFL` to a pipe end; other files are left alone.
pub(crate) fn set_status_flags(file: &Arc<dyn File>, flags: u64) {
    let any = file.as_any();
    if let Some(r) = any.and_then(|a| a.downcast_ref::<PipeReader>()) {
        r.set_nonblocking(flags & O_NONBLOCK != 0);
    }
    if let Some(w) = any.and_then(|a| a.downcast_ref::<PipeWriter>()) {
        w.set_nonblocking(flags & O_NONBLOCK != 0);
    }
}

/// Whether `file` is the write end of a pipe (a failed write to which raises
/// `SIGPIPE`).
pub(crate) fn is_writer(file: &Arc<dyn File>) -> bool {
    file.as_any().is_some_and(|a| a.is::<PipeWriter>())
}

/// `pipe2(fds, flags)`; `pipe` is `pipe2` with no flags.
pub(crate) fn pipe2(p: &Process, fds: u64, flags: u64) -> SysResult {
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let cloexec = flags & O_CLOEXEC != 0;
    let (r, w) = try_pipe(flags & O_NONBLOCK != 0)?;
    let (fr, fw) = {
        let mut files = p.files().lock();
        let read = Access { read: true, write: false, append: false };
        let write = Access { read: false, write: true, append: false };
        let (r, w) = (try_arc(r).map_err(crate::oom)?, try_arc(w).map_err(crate::oom)?);
        let (r, w) = (OpenFile::try_new(r, read)?, OpenFile::try_new(w, write)?);
        let fr = files.insert_from(0, r, cloexec)?;
        match files.insert_from(0, w, cloexec) {
            Ok(fw) => (fr, fw),
            Err(e) => {
                let _ = files.close(fr);
                return Err(e);
            }
        }
    };
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&fr.to_ne_bytes());
    out[4..].copy_from_slice(&fw.to_ne_bytes());
    if let Err(e) = p.memory().write(fds, &out) {
        let mut files = p.files().lock();
        let _ = files.close(fr);
        let _ = files.close(fw);
        return Err(e);
    }
    Ok(0)
}
