//! The network stack that sockets use.
//!
//! A kernel hands the socket calls an interface, its device and a socket set
//! with [`set_stack`]; nothing here knows which NIC it is. Calls that must
//! wait sleep on the stack's event queue, and wake when [`NetStack::poll`]
//! sees progress, so the kernel must call it regularly (from a task, a
//! timer, or a receive interrupt). System calls also poll after each
//! operation, so queued data leaves at once.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::net::NetDevice;
use osmium_net::{Instant, Interface, SocketHandle, SocketSet, TcpSocket};
use osmium_sched::WaitQueue;
use osmium_sync::{IrqSpinLock, Once};

/// An interface, its device and its sockets behind one lock, with the queue
/// of tasks waiting for any of them to change.
pub struct NetStack {
    inner: IrqSpinLock<Inner>,
    events: WaitQueue,
    now_ns: fn() -> u64,
}

struct Inner {
    iface: Interface,
    dev: Box<dyn NetDevice + Send>,
    sockets: SocketSet,
    /// Closed sockets' TCP connections, removed once they finish closing.
    reap: Vec<SocketHandle>,
}

impl NetStack {
    /// A stack over `dev`, timed by `now_ns` (monotonic nanoseconds).
    /// `sockets` may already hold sockets of the kernel's own, such as a
    /// DHCP client.
    pub fn new(iface: Interface, dev: Box<dyn NetDevice + Send>, sockets: SocketSet, now_ns: fn() -> u64) -> Self {
        Self {
            inner: IrqSpinLock::new(Inner { iface, dev, sockets, reap: Vec::new() }),
            events: WaitQueue::new(),
            now_ns,
        }
    }

    fn now(&self) -> Instant {
        Instant::from_nanos((self.now_ns)())
    }

    /// Runs the interface: receives, processes timers, sends, and wakes
    /// the tasks waiting on sockets. Returns true if a frame moved.
    pub fn poll(&self) -> bool {
        self.run(|_, _| ()).1
    }

    /// Runs `f` on the interface and sockets, then polls so what it queued
    /// goes out, and wakes waiters.
    pub fn op<R>(&self, f: impl FnOnce(&mut Interface, &mut SocketSet) -> R) -> R {
        self.run(f).0
    }

    fn run<R>(&self, f: impl FnOnce(&mut Interface, &mut SocketSet) -> R) -> (R, bool) {
        let now = self.now();
        let (r, active) = {
            let mut g = self.inner.lock();
            let inner = &mut *g;
            let r = f(&mut inner.iface, &mut inner.sockets);
            let mut active = inner.iface.poll(now, &mut *inner.dev, &mut inner.sockets);
            // Traffic to this host itself takes several rounds (a handshake
            // is three packets); finish them here, within reason.
            for _ in 0..32 {
                if !inner.iface.loopback_pending() {
                    break;
                }
                active |= inner.iface.poll(now, &mut *inner.dev, &mut inner.sockets);
            }
            inner.reap.retain(|&h| {
                let done = !inner.sockets.get::<TcpSocket>(h).is_open();
                if done {
                    inner.sockets.remove(h);
                }
                !done
            });
            (r, active)
        };
        self.events.wake_all();
        crate::poll::notify();
        (r, active)
    }

    /// Reads the interface and sockets without polling.
    pub fn peek<R>(&self, f: impl FnOnce(&Interface, &SocketSet) -> R) -> R {
        let g = self.inner.lock();
        f(&g.iface, &g.sockets)
    }

    /// Lets go of a TCP socket its file no longer holds: closes the
    /// connection gracefully (or resets it, if `abort` or unread data is
    /// left) and removes the socket once it has finished closing.
    pub(crate) fn release_tcp(&self, h: SocketHandle, abort: bool) {
        {
            let mut g = self.inner.lock();
            let inner = &mut *g;
            let t = inner.sockets.get_mut::<TcpSocket>(h);
            if abort || t.recv_queue() > 0 {
                t.abort();
            } else {
                t.close();
            }
            inner.reap.push(h);
        }
        self.poll();
    }

    /// Blocks until `ready` returns true, or until the clock reaches
    /// `deadline` (nanoseconds), and returns whether it did. `ready` is
    /// evaluated under the stack's lock, without polling, after each wake-up;
    /// every poll wakes the waiters, so a deadline is noticed within one.
    /// `EINTR` if the calling thread is interrupted by a signal or its
    /// process is ending (see [`crate::signal::current_interrupted`]).
    pub(crate) fn wait(&self, deadline: Option<u64>, mut ready: impl FnMut(&SocketSet) -> bool) -> Result<bool, Errno> {
        self.events.wait_until(|| {
            if ready(&self.inner.lock().sockets) {
                Some(Ok(true))
            } else if crate::signal::current_interrupted() {
                Some(Err(Errno::EINTR))
            } else if deadline.is_some_and(|d| (self.now_ns)() >= d) {
                Some(Ok(false))
            } else {
                None
            }
        })
    }

    /// Makes every thread blocked in [`wait`](Self::wait) look again: for
    /// signals and process exit.
    pub(crate) fn wake_waiters(&self) {
        self.events.wake_all();
    }

    /// The stack's clock, in nanoseconds.
    pub(crate) fn clock_ns(&self) -> u64 {
        (self.now_ns)()
    }

    /// The time `timeout_ns` from now, or `None` for no timeout (0).
    pub(crate) fn deadline(&self, timeout_ns: u64) -> Option<u64> {
        (timeout_ns != 0).then(|| (self.now_ns)().saturating_add(timeout_ns))
    }
}

static STACK: Once<Arc<NetStack>> = Once::new();

/// Sets the stack that `socket` and friends use. Without one they fail with
/// `EAFNOSUPPORT`. Panics if called twice.
pub fn set_stack(stack: Arc<NetStack>) {
    assert!(STACK.set(stack).is_ok(), "network stack already set");
}

/// The stack set by [`set_stack`].
pub fn stack() -> Option<&'static Arc<NetStack>> {
    STACK.get()
}
