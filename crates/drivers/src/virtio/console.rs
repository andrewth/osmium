//! virtio-console (spec §5.3): a byte stream per port.
//!
//! Without `VIRTIO_CONSOLE_F_MULTIPORT` the device has one port (queues 0 and
//! 1). With it, queues 2 and 3 carry control messages, port `n > 0` has
//! queues `2 + 2n` and `3 + 2n`, and ports come and go as the device sends
//! `DEVICE_ADD` and `DEVICE_REMOVE`. The driver handles up to [`MAX_PORTS`]
//! ports; more are ignored.
//!
//! Port 0 implements [`SerialPort`], so `SerialConsole::new(console)` makes it
//! the global console. Reads never block; writes are synchronous (the driver
//! polls the transmit queue for completion, at most [`POLL_LIMIT`] times).
//!
//! Not supported: `VIRTIO_CONSOLE_F_EMERG_WRITE` (it needs a configuration
//! space write, which [`Transport`] does not offer); port names are read and
//! ignored.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::serial::SerialPort;

use super::queue::{Segment, VirtQueue};
use super::{DeviceType, POLL_LIMIT, Transport, VirtioError, driver_ok, negotiate, reset};

/// Feature: the configuration space holds the console size.
pub const F_SIZE: u64 = 1 << 0;
/// Feature: multiple ports and a control queue pair.
pub const F_MULTIPORT: u64 = 1 << 1;

/// Configuration space: columns (u16).
pub const CONFIG_COLS: usize = 0;
/// Configuration space: rows (u16).
pub const CONFIG_ROWS: usize = 2;
/// Configuration space: `max_nr_ports` (u32).
pub const CONFIG_MAX_PORTS: usize = 4;

/// Control events (`VIRTIO_CONSOLE_*`).
pub mod event {
    #![allow(missing_docs)]
    pub const DEVICE_READY: u16 = 0;
    pub const DEVICE_ADD: u16 = 1;
    pub const DEVICE_REMOVE: u16 = 2;
    pub const PORT_READY: u16 = 3;
    pub const CONSOLE_PORT: u16 = 4;
    pub const RESIZE: u16 = 5;
    pub const PORT_OPEN: u16 = 6;
    pub const PORT_NAME: u16 = 7;
}

/// Ports the driver handles.
pub const MAX_PORTS: usize = 4;

/// Bytes per receive buffer.
const RX_BUF: usize = 256;
/// Bytes per transmit chunk.
const TX_BUF: usize = 512;
/// Bytes per control buffer (a header and a short payload).
const CTRL_BUF: usize = 64;
/// Receive entries per queue, at most.
const RX_ENTRIES: u16 = 16;
/// Transmit queue entries, at most (one request is outstanding at a time).
const TX_ENTRIES: u16 = 4;

/// Size of a control message header: id (u32), event (u16), value (u16).
const CTRL_HEADER: usize = 8;

/// Queue indices of the control pair.
const CTRL_RX: u16 = 2;
const CTRL_TX: u16 = 3;

const fn rx_index(port: usize) -> u16 {
    if port == 0 { 0 } else { 2 + 2 * port as u16 }
}

const fn tx_index(port: usize) -> u16 {
    if port == 0 { 1 } else { 3 + 2 * port as u16 }
}

/// A receive queue with one `buf_len`-byte buffer per descriptor.
struct RxQueue<'d, D: DmaAllocator + ?Sized> {
    queue: VirtQueue<'d, D>,
    bufs: OwnedDma<'d, D>,
    buf_len: usize,
}

impl<'d, D: DmaAllocator + ?Sized> RxQueue<'d, D> {
    fn new<T: Transport>(transport: &T, dma: &'d D, index: u16, buf_len: usize) -> Result<(Self, u16), VirtioError> {
        let size = queue_size(transport, index, RX_ENTRIES)?;
        let queue = VirtQueue::new(dma, index, size)?;
        let bufs = OwnedDma::new(dma, size as usize * buf_len).ok_or(VirtioError::NoMemory)?;
        Ok((Self { queue, bufs, buf_len }, size))
    }

    /// Hands every free buffer to the device (no notification).
    fn fill(&mut self) {
        while let Some(head) = self.queue.next_head() {
            let seg = Segment {
                addr: self.bufs.device_addr() + (head as usize * self.buf_len) as u64,
                len: self.buf_len as u32,
                device_writes: true,
            };
            if self.queue.add(&[seg]).is_err() {
                break;
            }
        }
    }
}

/// A transmit queue with a single buffer: requests are synchronous.
struct TxQueue<'d, D: DmaAllocator + ?Sized> {
    queue: VirtQueue<'d, D>,
    buf: OwnedDma<'d, D>,
    index: u16,
}

impl<'d, D: DmaAllocator + ?Sized> TxQueue<'d, D> {
    fn new<T: Transport>(transport: &T, dma: &'d D, index: u16, buf_len: usize) -> Result<(Self, u16), VirtioError> {
        let size = queue_size(transport, index, TX_ENTRIES)?;
        let queue = VirtQueue::new(dma, index, size)?;
        let buf = OwnedDma::new(dma, buf_len).ok_or(VirtioError::NoMemory)?;
        Ok((Self { queue, buf, index }, size))
    }

    /// Sends `data` (at most the buffer size) and waits for the device to take it.
    fn send<T: Transport>(&mut self, transport: &T, data: &[u8]) -> Result<(), VirtioError> {
        self.buf.write(0, data);
        let seg = Segment { addr: self.buf.device_addr(), len: data.len() as u32, device_writes: false };
        self.queue.add(&[seg])?;
        if self.queue.needs_notify() {
            transport.notify(self.index);
        }
        self.queue.wait_used(POLL_LIMIT).map(|_| ()).ok_or(VirtioError::BadQueue)
    }
}

/// The control transmit queue: messages are posted without waiting and
/// completions reaped on the next send, so the device need not answer
/// before the driver goes on (it may be waiting for the driver's next move).
struct CtrlTx<'d, D: DmaAllocator + ?Sized> {
    queue: VirtQueue<'d, D>,
    bufs: OwnedDma<'d, D>,
}

impl<'d, D: DmaAllocator + ?Sized> CtrlTx<'d, D> {
    fn new<T: Transport>(transport: &T, dma: &'d D) -> Result<(Self, u16), VirtioError> {
        let size = queue_size(transport, CTRL_TX, RX_ENTRIES)?;
        let queue = VirtQueue::new(dma, CTRL_TX, size)?;
        let bufs = OwnedDma::new(dma, size as usize * CTRL_BUF).ok_or(VirtioError::NoMemory)?;
        Ok((Self { queue, bufs }, size))
    }

    fn send<T: Transport>(&mut self, transport: &T, id: u32, event: u16, value: u16) -> Result<(), VirtioError> {
        while self.queue.pop_used().is_some() {}
        let head = self.queue.next_head().ok_or(VirtioError::QueueFull)?;
        let mut msg = [0u8; CTRL_HEADER];
        msg[..4].copy_from_slice(&id.to_le_bytes());
        msg[4..6].copy_from_slice(&event.to_le_bytes());
        msg[6..].copy_from_slice(&value.to_le_bytes());
        let off = head as usize * CTRL_BUF;
        self.bufs.write(off, &msg);
        let seg = Segment { addr: self.bufs.device_addr() + off as u64, len: CTRL_HEADER as u32, device_writes: false };
        self.queue.add(&[seg])?;
        if self.queue.needs_notify() {
            transport.notify(CTRL_TX);
        }
        Ok(())
    }
}

fn queue_size<T: Transport>(transport: &T, index: u16, cap: u16) -> Result<u16, VirtioError> {
    match transport.max_queue_size(index).min(cap) {
        0 => Err(VirtioError::BadQueue),
        // Split queues come in powers of two.
        n => Ok(1 << n.ilog2()),
    }
}

/// A buffer received and partly consumed.
#[derive(Clone, Copy)]
struct Pending {
    head: u16,
    len: usize,
    off: usize,
}

struct Port<'d, D: DmaAllocator + ?Sized> {
    rx: RxQueue<'d, D>,
    tx: TxQueue<'d, D>,
    pending: Option<Pending>,
    /// The device announced the port (always true without multiport).
    present: bool,
    host_open: bool,
    console: bool,
}

struct Control<'d, D: DmaAllocator + ?Sized> {
    rx: RxQueue<'d, D>,
    tx: CtrlTx<'d, D>,
}

struct Inner<'d, D: DmaAllocator + ?Sized> {
    ports: [Option<Port<'d, D>>; MAX_PORTS],
    control: Option<Control<'d, D>>,
    size: Option<(u16, u16)>,
}

/// A virtio console device. Dropping it resets the device and frees its memory.
pub struct VirtioConsole<'d, T: Transport, D: DmaAllocator + ?Sized> {
    transport: T,
    // Freed in `drop` only once the device has acknowledged its reset.
    inner: ManuallyDrop<Inner<'d, D>>,
    num_ports: usize,
}

impl<'d, T: Transport, D: DmaAllocator + ?Sized> VirtioConsole<'d, T, D> {
    /// Initializes the device behind `transport`, allocating queues and buffers
    /// from `dma`, and posts receive buffers.
    ///
    /// With multiport, no port exists until the device announces it; call
    /// [`poll`](Self::poll) (or read or write, which do) to process the
    /// announcements.
    pub fn new(transport: T, dma: &'d D) -> Result<Self, VirtioError> {
        if transport.device_type() != DeviceType::Console {
            return Err(VirtioError::WrongDevice);
        }
        let features = negotiate(&transport, 0, F_SIZE | F_MULTIPORT)?;
        let multiport = features & F_MULTIPORT != 0;
        let num_ports = if multiport {
            let n = u32::from(transport.config_read16(CONFIG_MAX_PORTS))
                | u32::from(transport.config_read16(CONFIG_MAX_PORTS + 2)) << 16;
            (n as usize).clamp(1, MAX_PORTS)
        } else {
            1
        };
        let size = (features & F_SIZE != 0)
            .then(|| (transport.config_read16(CONFIG_COLS), transport.config_read16(CONFIG_ROWS)))
            .filter(|&(c, r)| c != 0 && r != 0);

        // Build everything before touching the device's queues, so a failure frees it all.
        let mut sizes = [(0u16, 0u16); MAX_PORTS];
        let mut ports: [Option<Port<'d, D>>; MAX_PORTS] = [const { None }; MAX_PORTS];
        for (i, slot) in ports.iter_mut().enumerate().take(num_ports) {
            let (rx, rx_size) = RxQueue::new(&transport, dma, rx_index(i), RX_BUF)?;
            let (tx, tx_size) = TxQueue::new(&transport, dma, tx_index(i), TX_BUF)?;
            if let Some(s) = sizes.get_mut(i) {
                *s = (rx_size, tx_size);
            }
            *slot = Some(Port { rx, tx, pending: None, present: !multiport, host_open: false, console: i == 0 });
        }
        let control = if multiport {
            let (rx, rx_size) = RxQueue::new(&transport, dma, CTRL_RX, CTRL_BUF)?;
            let (tx, tx_size) = CtrlTx::new(&transport, dma)?;
            Some((Control { rx, tx }, rx_size, tx_size))
        } else {
            None
        };

        let mut inner = Inner { ports, control: None, size };
        for (port, &(rx_size, tx_size)) in inner.ports.iter_mut().zip(&sizes) {
            if let Some(p) = port {
                transport.setup_queue(p.rx.queue.index(), rx_size, p.rx.queue.addrs());
                transport.setup_queue(p.tx.queue.index(), tx_size, p.tx.queue.addrs());
                // Transmit completions are polled; don't interrupt for them.
                p.tx.queue.set_interrupts(false);
                p.rx.fill();
            }
        }
        if let Some((mut control, rx_size, tx_size)) = control {
            transport.setup_queue(CTRL_RX, rx_size, control.rx.queue.addrs());
            transport.setup_queue(CTRL_TX, tx_size, control.tx.queue.addrs());
            control.tx.queue.set_interrupts(false);
            control.rx.fill();
            inner.control = Some(control);
        }
        let mut con = Self { transport, inner: ManuallyDrop::new(inner), num_ports };
        driver_ok(&con.transport);
        for i in 0..num_ports {
            con.transport.notify(rx_index(i));
        }
        if multiport {
            con.transport.notify(CTRL_RX);
            con.send_control(0, event::DEVICE_READY, 1)?;
        }
        Ok(con)
    }

    /// The transport, for interrupt acknowledgement
    /// ([`Transport::ack_interrupt`]) from the driver's IRQ handler.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Number of ports the driver set up (announced or not).
    pub fn num_ports(&self) -> usize {
        self.num_ports
    }

    /// True if the device has announced `port` (always true for port 0
    /// without multiport) and it has not been removed.
    pub fn port_present(&self, port: usize) -> bool {
        self.inner.ports.get(port).and_then(Option::as_ref).is_some_and(|p| p.present)
    }

    /// True if the host side of `port` is connected (multiport only).
    pub fn host_connected(&self, port: usize) -> bool {
        self.inner.ports.get(port).and_then(Option::as_ref).is_some_and(|p| p.host_open)
    }

    /// True if the device designated `port` a console (`CONSOLE_PORT`).
    pub fn is_console(&self, port: usize) -> bool {
        self.inner.ports.get(port).and_then(Option::as_ref).is_some_and(|p| p.console)
    }

    /// The console size in (columns, rows), if the device reports one.
    pub fn size(&self) -> Option<(u16, u16)> {
        self.inner.size
    }

    /// Sends a control message with this device's `id` field.
    fn send_control(&mut self, id: u32, event: u16, value: u16) -> Result<(), VirtioError> {
        let Self { transport, inner, .. } = self;
        match inner.control.as_mut() {
            Some(c) => c.tx.send(transport, id, event, value),
            None => Ok(()),
        }
    }

    /// Processes control messages from the device (multiport; otherwise a
    /// no-op): announces ports, answers them, tracks host connections and
    /// console resizes.
    pub fn poll(&mut self) {
        let Self { transport, inner, .. } = self;
        let Inner { ports, control, size } = &mut **inner;
        let Some(ctrl) = control.as_mut() else { return };
        let mut reposted = false;
        while let Some((head, len)) = ctrl.rx.queue.pop_used() {
            let mut msg = [0u8; CTRL_BUF];
            let n = (len as usize).min(CTRL_BUF);
            if let Some(dst) = msg.get_mut(..n) {
                ctrl.rx.bufs.read(head as usize * CTRL_BUF, dst);
            }
            ctrl.rx.fill();
            reposted = true;
            handle_control(transport, &mut ctrl.tx, ports, size, msg.get(..n).unwrap_or_default());
        }
        if reposted && ctrl.rx.queue.needs_notify() {
            transport.notify(CTRL_RX);
        }
    }

    /// True if `read` on `port` would return data.
    pub fn can_read(&self, port: usize) -> bool {
        self.inner
            .ports
            .get(port)
            .and_then(Option::as_ref)
            .is_some_and(|p| p.present && (p.pending.is_some() || p.rx.queue.has_used()))
    }

    /// Reads up to `buf.len()` bytes from `port` without blocking, returning
    /// how many (0 if none are waiting). Fails if the port does not exist.
    pub fn read(&mut self, port: usize, buf: &mut [u8]) -> Result<usize, VirtioError> {
        self.poll();
        let Self { transport, inner, .. } = self;
        let p =
            inner.ports.get_mut(port).and_then(Option::as_mut).filter(|p| p.present).ok_or(VirtioError::NotPresent)?;
        let mut done = 0;
        while done < buf.len() {
            let cur = match p.pending {
                Some(cur) => cur,
                None => match p.rx.queue.pop_used() {
                    // The device chooses the length; never trust it past the buffer.
                    Some((head, len)) => Pending { head, len: (len as usize).min(RX_BUF), off: 0 },
                    None => break,
                },
            };
            let n = (cur.len - cur.off).min(buf.len() - done);
            if let Some(dst) = buf.get_mut(done..done + n) {
                p.rx.bufs.read(cur.head as usize * RX_BUF + cur.off, dst);
            }
            done += n;
            let off = cur.off + n;
            if off >= cur.len {
                p.pending = None;
                // Popping freed exactly this descriptor; give it back.
                p.rx.fill();
                if p.rx.queue.needs_notify() {
                    transport.notify(p.rx.queue.index());
                }
            } else {
                p.pending = Some(Pending { off, ..cur });
            }
        }
        Ok(done)
    }

    /// Writes all of `data` to `port`, waiting for the device to take each
    /// chunk. Fails if the port does not exist or the device stops answering
    /// (the transmit queue is then broken).
    pub fn write(&mut self, port: usize, data: &[u8]) -> Result<(), VirtioError> {
        self.poll();
        let Self { transport, inner, .. } = self;
        let p =
            inner.ports.get_mut(port).and_then(Option::as_mut).filter(|p| p.present).ok_or(VirtioError::NotPresent)?;
        for chunk in data.chunks(TX_BUF) {
            p.tx.send(transport, chunk)?;
        }
        Ok(())
    }
}

fn handle_control<T: Transport, D: DmaAllocator + ?Sized>(
    transport: &T,
    tx: &mut CtrlTx<'_, D>,
    ports: &mut [Option<Port<'_, D>>; MAX_PORTS],
    size: &mut Option<(u16, u16)>,
    msg: &[u8],
) {
    let Some(&[i0, i1, i2, i3, e0, e1, v0, v1]) = msg.first_chunk::<CTRL_HEADER>() else { return };
    let id = u32::from_le_bytes([i0, i1, i2, i3]);
    let (ev, value) = (u16::from_le_bytes([e0, e1]), u16::from_le_bytes([v0, v1]));
    // An id beyond the ports we set up is ignored (the device may know more).
    let Some(port) = usize::try_from(id).ok().and_then(|i| ports.get_mut(i)).and_then(Option::as_mut) else { return };
    match ev {
        event::DEVICE_ADD if !port.present => {
            port.present = true;
            // Failures leave the control queue broken; later calls report it.
            let _ = tx.send(transport, id, event::PORT_READY, 1);
            let _ = tx.send(transport, id, event::PORT_OPEN, 1);
        }
        event::DEVICE_REMOVE => {
            port.present = false;
            port.host_open = false;
        }
        event::CONSOLE_PORT => port.console = true,
        event::PORT_OPEN => port.host_open = value != 0,
        event::RESIZE => {
            if let Some(&[c0, c1, r0, r1]) = msg.get(CTRL_HEADER..).and_then(|m| m.first_chunk::<4>()) {
                let (cols, rows) = (u16::from_le_bytes([c0, c1]), u16::from_le_bytes([r0, r1]));
                if cols != 0 && rows != 0 {
                    *size = Some((cols, rows));
                }
            }
        }
        _ => {}
    }
}

/// Port 0 as a serial port, so `SerialConsole` can use it. Output errors are
/// dropped (there is nowhere to report them); input is polled.
impl<T: Transport, D: DmaAllocator + ?Sized> SerialPort for VirtioConsole<'_, T, D> {
    fn write_byte(&mut self, byte: u8) {
        let _ = self.write(0, &[byte]);
    }

    fn read_byte(&mut self) -> Option<u8> {
        let mut b = [0u8];
        match self.read(0, &mut b) {
            Ok(1) => Some(b[0]),
            _ => None,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        let _ = self.write(0, bytes);
    }
}

impl<T: Transport, D: DmaAllocator + ?Sized> Drop for VirtioConsole<'_, T, D> {
    fn drop(&mut self) {
        // Stop the device before freeing memory it may still be using; if it
        // never stops, leak the memory instead.
        if reset(&self.transport) {
            // SAFETY: dropped once, here; the device is reset.
            unsafe { ManuallyDrop::drop(&mut self.inner) }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::vec::Vec;

    use super::*;
    use crate::virtio::queue::tests::DeviceSide;
    use crate::virtio::testing::{FakeTransport, HostDma};
    use crate::virtio::{feature, status};

    fn mem(addr: u64, len: usize) -> &'static mut [u8] {
        // SAFETY: test DMA memory is identity-mapped and outlives the call.
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
    }

    fn device(features: u64, max_ports: u32) -> FakeTransport {
        let mut config = std::vec![100, 0, 30, 0];
        config.extend(max_ports.to_le_bytes());
        let mut t = FakeTransport::new(DeviceType::Console, feature::VERSION_1 | features, &config);
        t.max_queue = 8;
        t
    }

    fn dev(con: &VirtioConsole<'_, FakeTransport, HostDma>, index: u16) -> DeviceSide {
        let (size, addrs) = con.transport().queue(index);
        DeviceSide::new(size, addrs)
    }

    /// Plays the device for one transmit request: takes the next buffer from
    /// `side` once it appears and returns its contents.
    fn take_tx(side: &mut DeviceSide) -> Vec<u8> {
        loop {
            if let Some((head, chain)) = side.pop_avail() {
                let (addr, len, _) = chain[0];
                let data = mem(addr, len as usize).to_vec();
                side.push_used(head, 0);
                return data;
            }
            std::hint::spin_loop();
        }
    }

    /// Delivers `data` into the next receive buffer of `side`.
    fn give_rx(side: &mut DeviceSide, data: &[u8]) {
        let (head, chain) = side.pop_avail().expect("receive buffer posted");
        mem(chain[0].0, data.len()).copy_from_slice(data);
        side.push_used(head, data.len() as u32);
    }

    fn msg(id: u32, ev: u16, value: u16) -> Vec<u8> {
        let mut m = id.to_le_bytes().to_vec();
        m.extend(ev.to_le_bytes());
        m.extend(value.to_le_bytes());
        m
    }

    #[test]
    fn single_port() {
        let dma = HostDma::default();
        let mut con = VirtioConsole::new(device(F_SIZE, 1), &dma).unwrap();
        assert_eq!(con.num_ports(), 1);
        assert_eq!(con.size(), Some((100, 30)));
        assert!(con.port_present(0) && !con.port_present(1));
        assert_eq!(con.transport().queues.borrow().len(), 2, "no control queues");
        assert_eq!(con.transport().status() & status::DRIVER_OK, status::DRIVER_OK);

        // Output, in chunks, to the device.
        let mut tx = dev(&con, 1);
        let big: Vec<u8> = (0..1200u32).map(|i| i as u8).collect();
        let got = thread::scope(|s| {
            let h = s.spawn(|| (0..3).flat_map(|_| take_tx(&mut tx)).collect::<Vec<u8>>());
            con.write(0, &big).unwrap();
            h.join().unwrap()
        });
        assert_eq!(got, big);
        assert_eq!(con.write(1, b"x"), Err(VirtioError::NotPresent));

        // Input, read in pieces smaller than a buffer.
        let mut rx = dev(&con, 0);
        let mut buf = [0u8; 4];
        assert_eq!(con.read(0, &mut buf), Ok(0));
        assert!(!con.can_read(0));
        give_rx(&mut rx, b"hello world");
        assert!(con.can_read(0));
        assert_eq!(con.read(0, &mut buf), Ok(4));
        assert_eq!(&buf, b"hell");
        assert!(rx.pop_avail().is_some(), "other buffers still posted");
        let mut rest = [0u8; 16];
        assert_eq!(con.read(0, &mut rest), Ok(7));
        assert_eq!(&rest[..7], b"o world");
        assert_eq!(con.read(0, &mut rest), Ok(0));

        // A lying length is clamped to the buffer.
        let (head, chain) = rx.pop_avail().unwrap();
        mem(chain[0].0, RX_BUF).fill(b'z');
        rx.push_used(head, 1 << 30);
        let mut big_buf = [0u8; 1024];
        assert_eq!(con.read(0, &mut big_buf), Ok(RX_BUF));

        // As a serial port.
        give_rx(&mut rx, b"k");
        assert_eq!(con.read_byte(), Some(b'k'));
        assert_eq!(con.read_byte(), None);
    }

    #[test]
    fn serial_port_write() {
        let dma = HostDma::default();
        let mut con = VirtioConsole::new(device(0, 1), &dma).unwrap();
        assert_eq!(con.size(), None);
        let mut tx = dev(&con, 1);
        let got = thread::scope(|s| {
            let h = s.spawn(|| (0..2).flat_map(|_| take_tx(&mut tx)).collect::<Vec<u8>>());
            con.write_byte(b'a');
            con.write_bytes(b"bc");
            h.join().unwrap()
        });
        assert_eq!(got, b"abc");
    }

    #[test]
    fn multiport() {
        let dma = HostDma::default();
        let mut con = VirtioConsole::new(device(F_MULTIPORT, 2), &dma).unwrap();
        assert_eq!(con.num_ports(), 2);
        let queues: Vec<u16> = con.transport().queues.borrow().iter().map(|q| q.0).collect();
        assert!(queues.iter().all(|q| [0, 1, 2, 3, 4, 5].contains(q)) && queues.len() == 6, "{queues:?}");
        assert!(!con.port_present(0), "no port until announced");
        assert_eq!(con.write(0, b"x"), Err(VirtioError::NotPresent));

        let mut ctrl_tx = dev(&con, CTRL_TX);
        let mut ctrl_rx = dev(&con, CTRL_RX);
        // DEVICE_READY went out during init; the buffer sits in the queue.
        let (head, chain) = ctrl_tx.pop_avail().expect("DEVICE_READY sent");
        assert_eq!(mem(chain[0].0, chain[0].1 as usize), &msg(0, event::DEVICE_READY, 1)[..]);
        ctrl_tx.push_used(head, 0);

        // The device announces port 1 and makes port 0 the console; the
        // driver answers PORT_READY and PORT_OPEN for each announcement.
        give_rx(&mut ctrl_rx, &msg(1, event::DEVICE_ADD, 0));
        con.poll();
        let replies: Vec<_> = (0..2).map(|_| take_tx(&mut ctrl_tx)).collect();
        assert_eq!(replies, [msg(1, event::PORT_READY, 1), msg(1, event::PORT_OPEN, 1)]);
        assert!(con.port_present(1) && !con.port_present(0));

        give_rx(&mut ctrl_rx, &msg(1, event::PORT_OPEN, 1));
        give_rx(&mut ctrl_rx, &msg(1, event::CONSOLE_PORT, 1));
        give_rx(&mut ctrl_rx, &msg(9, event::DEVICE_ADD, 0)); // unknown port: ignored
        let mut resize = msg(1, event::RESIZE, 0);
        resize.extend([132, 0, 43, 0]);
        give_rx(&mut ctrl_rx, &resize);
        con.poll();
        assert!(con.host_connected(1) && con.is_console(1));
        assert_eq!(con.size(), Some((132, 43)));

        // Data on port 1 uses queues 4 and 5.
        give_rx(&mut dev(&con, 4), b"abc");
        let mut buf = [0u8; 8];
        assert_eq!(con.read(1, &mut buf), Ok(3));
        let mut tx = dev(&con, 5);
        let got = thread::scope(|s| {
            let h = s.spawn(|| take_tx(&mut tx));
            con.write(1, b"out").unwrap();
            h.join().unwrap()
        });
        assert_eq!(got, b"out");

        give_rx(&mut ctrl_rx, &msg(1, event::DEVICE_REMOVE, 0));
        con.poll();
        assert!(!con.port_present(1));
        assert_eq!(con.read(1, &mut buf), Err(VirtioError::NotPresent));
    }

    #[test]
    fn drop_frees_and_probe_failures() {
        let dma = HostDma::default();
        let con = VirtioConsole::new(device(0, 1), &dma).unwrap();
        assert_eq!(dma.live.get(), 4);
        drop(con);
        assert_eq!(dma.live.get(), 0);

        let con = VirtioConsole::new(device(F_MULTIPORT, 3), &dma).unwrap();
        drop(con);
        assert_eq!(dma.live.get(), 0);

        let mut no_queue = device(0, 1);
        no_queue.max_queue = 0;
        assert_eq!(VirtioConsole::new(no_queue, &dma).err(), Some(VirtioError::BadQueue));
        let net = FakeTransport::new(DeviceType::Net, feature::VERSION_1, &[]);
        assert_eq!(VirtioConsole::new(net, &dma).err(), Some(VirtioError::WrongDevice));
        assert_eq!(dma.live.get(), 0, "failed probes leak nothing");
    }
}
