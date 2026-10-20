//! How a session reaches the network stack.

use osmium_hal::net::NetDevice;
use osmium_net::{Instant, Interface, SocketSet};

/// The network stack a session runs on: something that can poll the
/// interface its TCP socket is served by, and lend out the socket set.
///
/// A session blocks by calling [`poll`](Self::poll) in a loop until the
/// target answers or its timeout passes, so `poll` is also where a kernel
/// can wait for an interrupt or yield. [`Stack`] implements it over
/// borrowed parts; a kernel that keeps its interface behind a lock
/// implements it on a handle that takes the lock in each call.
pub trait Net {
    /// Moves packets between the device and the sockets once
    /// ([`Interface::poll`]) and returns the time it polled at.
    fn poll(&mut self) -> Instant;

    /// Runs `f` on the socket set the session's socket lives in.
    fn with_sockets<R>(&mut self, f: impl FnOnce(&mut SocketSet) -> R) -> R;
}

impl<T: Net> Net for &mut T {
    fn poll(&mut self) -> Instant {
        (**self).poll()
    }

    fn with_sockets<R>(&mut self, f: impl FnOnce(&mut SocketSet) -> R) -> R {
        (**self).with_sockets(f)
    }
}

/// An interface, its device and socket set, and a clock, as a [`Net`].
pub struct Stack<'net, D: NetDevice + ?Sized> {
    /// The interface.
    pub iface: &'net mut Interface,
    /// The device it runs on.
    pub dev: &'net mut D,
    /// The sockets it serves, which the session adds its socket to.
    pub sockets: &'net mut SocketSet,
    /// A monotonic clock in nanoseconds.
    pub now_ns: fn() -> u64,
}

impl<D: NetDevice + ?Sized> Net for Stack<'_, D> {
    fn poll(&mut self) -> Instant {
        let now = Instant::from_nanos((self.now_ns)());
        self.iface.poll(now, self.dev, self.sockets);
        now
    }

    fn with_sockets<R>(&mut self, f: impl FnOnce(&mut SocketSet) -> R) -> R {
        f(self.sockets)
    }
}
