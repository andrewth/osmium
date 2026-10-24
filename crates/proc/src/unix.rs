//! `socketpair`: connected `AF_UNIX` sockets, stream or datagram, backed by
//! memory. There is no name space: a pair is only ever made by `socketpair`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use alloc::collections::VecDeque;
use osmium_fs::{Errno, File, FileKind, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, Stat};
use osmium_sync::IrqSpinLock;
use osmium_sync::fallible::{try_arc, try_to_vec};

use crate::poll::{notify, wait};

/// Bytes a stream buffers in each direction.
const STREAM_CAP: usize = 64 * 1024;
/// Datagrams queued in each direction.
const DGRAM_QUEUE: usize = 64;
/// Largest datagram.
pub(crate) const DGRAM_MAX: usize = 64 * 1024;

/// One side's receive queue and state.
#[derive(Default)]
struct End {
    stream: VecDeque<u8>,
    dgrams: VecDeque<Vec<u8>>,
    /// The socket was closed.
    closed: bool,
    /// This side shut down reading.
    shut_rd: bool,
    /// This side shut down writing.
    shut_wr: bool,
}

#[derive(Default)]
struct Pair {
    ends: [End; 2],
}

impl Pair {
    /// The end of `side` (0 or 1; any other value names end 1).
    fn end(&self, side: usize) -> &End {
        let [a, b] = &self.ends;
        if side == 0 { a } else { b }
    }

    /// The end opposite `side`.
    fn peer(&self, side: usize) -> &End {
        self.end(usize::from(side == 0))
    }

    /// The end of `side` and the end opposite it.
    fn both_mut(&mut self, side: usize) -> (&mut End, &mut End) {
        let [a, b] = &mut self.ends;
        if side == 0 { (a, b) } else { (b, a) }
    }
}

/// One end of a socket pair.
pub struct UnixSocket {
    pair: Arc<IrqSpinLock<Pair>>,
    side: usize,
    dgram: bool,
    nonblock: AtomicBool,
}

/// A connected pair of stream (`dgram` false) or datagram sockets.
pub fn socketpair(dgram: bool, nonblock: bool) -> Result<(UnixSocket, UnixSocket), Errno> {
    let pair = try_arc(IrqSpinLock::new(Pair::default())).map_err(crate::oom)?;
    let end = |side| UnixSocket { pair: pair.clone(), side, dgram, nonblock: AtomicBool::new(nonblock) };
    Ok((end(0), end(1)))
}

/// What a receive took.
pub(crate) struct Received {
    /// Bytes copied into the buffer.
    pub copied: usize,
    /// The datagram was longer than the buffer.
    pub truncated: bool,
}

impl UnixSocket {
    /// Whether this is a datagram socket.
    pub fn is_dgram(&self) -> bool {
        self.dgram
    }

    /// Whether calls fail with `EAGAIN` instead of waiting.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Sets `O_NONBLOCK`.
    pub fn set_nonblocking(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    /// Reading would return data or end of file.
    fn readable(p: &Pair, side: usize, dgram: bool) -> bool {
        let (me, peer) = (p.end(side), p.peer(side));
        let data = if dgram { !me.dgrams.is_empty() } else { !me.stream.is_empty() };
        data || me.shut_rd || peer.closed || peer.shut_wr
    }

    /// Writing would complete or fail at once.
    fn writable(p: &Pair, side: usize, dgram: bool) -> bool {
        let (me, peer) = (p.end(side), p.peer(side));
        let room = if dgram { peer.dgrams.len() < DGRAM_QUEUE } else { peer.stream.len() < STREAM_CAP };
        room || peer.closed || peer.shut_rd || me.shut_wr
    }

    /// Receives into `buf`; `peek` leaves the data queued. Returns 0 bytes at
    /// end of file.
    pub(crate) fn recv(&self, buf: &mut [u8], peek: bool, wait_for_data: bool) -> Result<Received, Errno> {
        loop {
            {
                let mut g = self.pair.lock();
                let (side, dgram) = (self.side, self.dgram);
                let me = g.both_mut(side).0;
                if dgram && let Some(d) = me.dgrams.front() {
                    let copied = d.len().min(buf.len());
                    for (b, x) in buf.iter_mut().zip(d.iter().take(copied)) {
                        *b = *x;
                    }
                    let truncated = d.len() > copied;
                    if !peek {
                        me.dgrams.pop_front();
                    }
                    drop(g);
                    notify();
                    return Ok(Received { copied, truncated });
                }
                if !dgram && !me.stream.is_empty() {
                    let copied = buf.len().min(me.stream.len());
                    if peek {
                        for (b, x) in buf.iter_mut().zip(me.stream.iter()) {
                            *b = *x;
                        }
                    } else {
                        for (b, x) in buf.iter_mut().zip(me.stream.drain(..copied)) {
                            *b = x;
                        }
                    }
                    drop(g);
                    notify();
                    return Ok(Received { copied, truncated: false });
                }
                if Self::readable(&g, side, dgram) {
                    return Ok(Received { copied: 0, truncated: false });
                }
            }
            if !wait_for_data {
                return Err(Errno::EAGAIN);
            }
            wait(None, || Self::readable(&self.pair.lock(), self.side, self.dgram).then_some(()))?;
        }
    }

    /// Sends `data` to the other end; a stream may take part of it if it does
    /// not wait.
    pub(crate) fn send(&self, data: &[u8], wait_for_room: bool) -> Result<usize, Errno> {
        if self.dgram && data.len() > DGRAM_MAX {
            return Err(Errno::EMSGSIZE);
        }
        // The datagram is copied before the lock is taken, where memory
        // running out is an error that leaves nothing queued.
        let mut datagram = if self.dgram { Some(try_to_vec(data).map_err(crate::oom)?) } else { None };
        let mut done = 0;
        loop {
            {
                let mut g = self.pair.lock();
                let (side, dgram) = (self.side, self.dgram);
                if g.end(side).shut_wr || g.peer(side).closed || g.peer(side).shut_rd {
                    return if done > 0 { Ok(done) } else { Err(Errno::EPIPE) };
                }
                let peer = g.both_mut(side).1;
                if dgram {
                    if peer.dgrams.len() < DGRAM_QUEUE {
                        peer.dgrams.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                        // Made above for datagrams.
                        let Some(d) = datagram.take() else { return Err(Errno::EINVAL) };
                        peer.dgrams.push_back(d);
                        drop(g);
                        notify();
                        return Ok(data.len());
                    }
                } else {
                    let n = data.len().saturating_sub(done).min(STREAM_CAP.saturating_sub(peer.stream.len()));
                    if n > 0 || data.is_empty() {
                        if peer.stream.try_reserve(n).is_err() {
                            return if done > 0 { Ok(done) } else { Err(Errno::ENOMEM) };
                        }
                        peer.stream.extend(data.get(done..done + n).unwrap_or_default());
                        done += n;
                        drop(g);
                        notify();
                        if done == data.len() || !wait_for_room {
                            return Ok(done);
                        }
                        continue;
                    }
                }
            }
            if done > 0 {
                return Ok(done);
            }
            if !wait_for_room {
                return Err(Errno::EAGAIN);
            }
            wait(None, || Self::writable(&self.pair.lock(), self.side, self.dgram).then_some(()))?;
        }
    }

    /// `shutdown`: `how` is 0 (read), 1 (write) or 2 (both).
    pub fn shutdown(&self, how: u64) -> Result<(), Errno> {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        {
            let mut g = self.pair.lock();
            let me = g.both_mut(self.side).0;
            me.shut_rd |= how != 1;
            me.shut_wr |= how != 0;
        }
        notify();
        Ok(())
    }
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        self.pair.lock().both_mut(self.side).0.closed = true;
        notify();
    }
}

impl File for UnixSocket {
    fn read(&self, _off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.recv(buf, false, !self.is_nonblocking()).map(|r| r.copied)
    }

    fn write(&self, _off: u64, buf: &[u8]) -> Result<usize, Errno> {
        self.send(buf, !self.is_nonblocking())
    }

    fn stat(&self) -> Stat {
        Stat { kind: FileKind::Socket, mode: 0o777, nlink: 1, ..Stat::default() }
    }

    fn poll(&self) -> u32 {
        let g = self.pair.lock();
        let (me, peer) = (g.end(self.side), g.peer(self.side));
        let mut m = 0;
        if Self::readable(&g, self.side, self.dgram) {
            m |= POLLIN;
        }
        if Self::writable(&g, self.side, self.dgram) {
            m |= POLLOUT;
        }
        if peer.closed || peer.shut_wr {
            m |= POLLRDHUP;
        }
        if peer.closed || (me.shut_rd && me.shut_wr) {
            m |= POLLHUP;
        }
        m
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}
