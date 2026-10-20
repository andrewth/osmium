//! Two interfaces joined by a simulated Ethernet link.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

use osmium_hal::net::{MacAddress, NetDevice, NetError};

use crate::{Config, Instant, Interface, Ipv4Addr, SocketSet};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// Decides whether to deliver a frame: called with each frame's sequence
/// number on the link and its bytes.
pub(crate) type Filter = Rc<RefCell<dyn FnMut(u64, &[u8]) -> bool>>;

pub(crate) struct Port {
    pub(crate) mac: MacAddress,
    rx: Queue,
    pub(crate) tx: Queue,
    filter: Option<Filter>,
    sent: u64,
}

impl NetDevice for Port {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        assert!(frame.len() <= self.max_frame_len(), "oversized frame");
        self.sent += 1;
        if self.filter.as_ref().is_none_or(|f| (f.borrow_mut())(self.sent, frame)) {
            self.tx.borrow_mut().push_back(frame.to_vec());
        }
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        let frame = self.rx.borrow_mut().pop_front().ok_or(NetError::WouldBlock)?;
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }

    fn can_receive(&self) -> bool {
        !self.rx.borrow().is_empty()
    }

    fn can_transmit(&self) -> bool {
        true
    }
}

pub(crate) struct Host {
    pub(crate) iface: Interface,
    pub(crate) dev: Port,
    pub(crate) sockets: SocketSet,
}

impl Host {
    pub(crate) fn poll(&mut self, now: Instant) -> bool {
        self.iface.poll(now, &mut self.dev, &mut self.sockets)
    }

    /// Sets a filter on frames this host sends.
    pub(crate) fn set_filter(&mut self, f: impl FnMut(u64, &[u8]) -> bool + 'static) {
        self.dev.filter = Some(Rc::new(RefCell::new(f)));
    }
}

pub(crate) const A_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub(crate) const B_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);

pub(crate) fn config(address: Ipv4Addr) -> Config {
    Config { address, prefix_len: 24, gateway: None, dns: None }
}

/// Unconfigured hosts on one link.
pub(crate) fn link() -> (Host, Host) {
    let (ab, ba): (Queue, Queue) = Default::default();
    let host = |n: u8, rx: &Queue, tx: &Queue| {
        let dev = Port { mac: MacAddress([2, 0, 0, 0, 0, n]), rx: rx.clone(), tx: tx.clone(), filter: None, sent: 0 };
        Host { iface: Interface::new(&dev, n.into()), dev, sockets: SocketSet::new() }
    };
    (host(1, &ba, &ab), host(2, &ab, &ba))
}

/// Hosts A (192.168.1.1) and B (192.168.1.2) on one /24.
pub(crate) fn pair() -> (Host, Host) {
    let (mut a, mut b) = link();
    a.iface.set_config(Some(config(A_IP)));
    b.iface.set_config(Some(config(B_IP)));
    (a, b)
}

/// Polls both hosts every millisecond from `*now` until `done` holds or
/// `limit` milliseconds pass; returns whether `done` held.
pub(crate) fn run(
    a: &mut Host,
    b: &mut Host,
    now: &mut Instant,
    limit: u64,
    mut done: impl FnMut(&mut Host, &mut Host) -> bool,
) -> bool {
    let end = now.as_millis() + limit;
    while now.as_millis() < end {
        a.poll(*now);
        b.poll(*now);
        if done(a, b) {
            return true;
        }
        *now = Instant::from_millis(now.as_millis() + 1);
    }
    false
}
