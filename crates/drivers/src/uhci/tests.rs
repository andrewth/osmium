use core::cell::{Cell, RefCell};
use std::boxed::Box;
use std::rc::Rc;

use osmium_hal::pci::{Address, ConfigAccess};

use super::*;
use crate::usbhc::fakedev::{self, Device, IN, LowDma, OUT, Reply, SETUP, TickClock};
use crate::usbhc::sim;

/// A register window in plain memory.
struct Win(*mut u8);

impl Win {
    fn r16(&self, off: usize) -> u16 {
        // SAFETY: within the test's register array.
        unsafe { self.0.add(off).cast::<u16>().read_volatile() }
    }

    fn w16(&self, off: usize, v: u16) {
        // SAFETY: within the test's register array.
        unsafe { self.0.add(off).cast::<u16>().write_volatile(v) }
    }

    fn r32(&self, off: usize) -> u32 {
        // SAFETY: within the test's register array.
        unsafe { self.0.add(off).cast::<u32>().read_volatile() }
    }
}

use fakedev::{r32 as mem32, rbytes as read_bytes, w32 as put32, wbytes as write_bytes};

/// What the simulated controller saw.
#[derive(Default)]
struct Seen {
    low_speed_tds: Cell<usize>,
}

/// Plays the controller once per call: reset and halt bits, a device reset
/// when a port's reset bit is up, the frame counter, and one pass over the
/// schedule for the frame it names.
fn controller(win: Win, dev: Rc<RefCell<Device>>, seen: Rc<Seen>) -> impl FnMut() {
    let mut resetting = [false; 2];
    move || {
        let cmd = win.r16(USBCMD);
        if cmd & CMD_HCRESET != 0 {
            win.w16(USBCMD, cmd & !CMD_HCRESET);
        }
        let sts = win.r16(USBSTS);
        let running = cmd & CMD_RUN != 0;
        win.w16(USBSTS, if running { sts & !STS_HALTED } else { sts | STS_HALTED });
        for (i, was) in resetting.iter_mut().enumerate() {
            let reset = win.r16(PORTSC + 2 * i) & PORT_RESET != 0;
            if reset && !*was {
                dev.borrow_mut().reset();
            }
            *was = reset;
        }
        if !running {
            return;
        }
        let frame = win.r16(FRNUM).wrapping_add(1) & 0x7ff;
        win.w16(FRNUM, frame);
        let base = win.r32(FRBASEADD) as u64;
        let mut link = mem32(base + (frame as u64 % FRAMES as u64) * 4);
        for _ in 0..64 {
            if link & LINK_TERMINATE != 0 {
                break;
            }
            assert!(link & LINK_QH != 0, "the frame list holds queue heads");
            let qh = (link & !0xf) as u64;
            run_queue(qh, &dev, &seen);
            link = mem32(qh);
        }
    }
}

fn run_queue(qh: u64, dev: &RefCell<Device>, seen: &Seen) {
    for _ in 0..4096 {
        let element = mem32(qh + 4);
        if element & LINK_TERMINATE != 0 {
            return;
        }
        assert_eq!(element & LINK_QH, 0, "queue elements are descriptors here");
        let td = (element & !0xf) as u64;
        if mem32(td + 4) & TD_ACTIVE == 0 {
            return;
        }
        match transact(td, dev, seen) {
            Some(true) => put32(qh + 4, mem32(td)),
            _ => return,
        }
    }
}

/// Executes one descriptor. `None` if it did not complete (NAK or error),
/// else whether the queue advances (it does not after a short packet that
/// asked to stop the queue).
fn transact(td: u64, dev: &RefCell<Device>, seen: &Seen) -> Option<bool> {
    let ctrl = mem32(td + 4);
    let token = mem32(td + 8);
    let buffer = mem32(td + 12) as u64;
    let pid = token & 0xff;
    let address = (token >> 8 & 0x7f) as u8;
    let ep = (token >> 15 & 0xf) as u8;
    let toggle = token >> 19 & 1 != 0;
    let max = ((token >> 21).wrapping_add(1) & 0x7ff) as usize;
    if ctrl & TD_LOW_SPEED != 0 {
        seen.low_speed_tds.set(seen.low_speed_tds.get() + 1);
    }
    let finish = |bits: u32| put32(td + 4, ctrl & !TD_ACTIVE & !0x7ff | bits);
    let mut d = dev.borrow_mut();
    let reply = match pid {
        PID_IN => d.transact(address, if ep == 0 { 0 } else { ep | 0x80 }, IN, toggle, &[], max),
        PID_OUT | PID_SETUP => {
            let data = read_bytes(buffer, max);
            d.transact(address, ep, if pid == PID_OUT { OUT } else { SETUP }, toggle, &data, 0)
        }
        _ => panic!("unknown PID {pid:#x}"),
    };
    match reply {
        Reply::Nak => {
            put32(td + 4, ctrl | 1 << 19);
            None
        }
        Reply::Stall => {
            finish(TD_STALLED);
            None
        }
        Reply::None => {
            finish(TD_CRC_TIMEOUT);
            None
        }
        Reply::Ack(data) if pid == PID_IN => {
            if data.len() > max {
                finish(TD_BABBLE);
                return None;
            }
            write_bytes(buffer, &data);
            finish((data.len() as u32).wrapping_sub(1) & 0x7ff);
            Some(!(data.len() < max && ctrl & TD_SHORT_PACKET_DETECT != 0))
        }
        Reply::Ack(_) => {
            finish((max as u32).wrapping_sub(1) & 0x7ff);
            Some(true)
        }
    }
}

struct Rig {
    dev: Rc<RefCell<Device>>,
    seen: Rc<Seen>,
    win: Box<[u32; 32]>,
}

impl Rig {
    /// A controller with two ports and a device on port 1.
    fn new(low_speed: bool) -> Self {
        let mut win = Box::new([0u32; 32]);
        let regs = win.as_mut_ptr().cast::<u8>();
        let w = Win(regs);
        w.w16(USBSTS, STS_HALTED);
        w.w16(PORTSC, 0x80 | PORT_CONNECTED | if low_speed { PORT_LOW_SPEED } else { 0 });
        w.w16(PORTSC + 2, 0x80);
        let dev = Rc::new(RefCell::new(Device::new()));
        let seen = Rc::new(Seen::default());
        sim::install(controller(Win(regs), dev.clone(), seen.clone()));
        Self { dev, seen, win }
    }

    fn regs(&mut self) -> UhciRegs {
        // SAFETY: the window is the rig's array, which outlives the controller.
        UhciRegs::Mmio(unsafe { IoMem::new(self.win.as_mut_ptr().cast(), 32 * 4) })
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        sim::remove();
    }
}

#[test]
fn full_host_surface_against_a_device() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).expect("start");
    assert_eq!(hc.ports(), 2);
    fakedev::exercise(&mut hc, &rig.dev, 1);
    assert_eq!(rig.seen.low_speed_tds.get(), 0);
    drop(hc);
    assert_eq!(dma.live.get(), 0, "all DMA memory freed");
}

#[test]
fn low_speed_devices_set_the_low_speed_bit() {
    let mut rig = Rig::new(true);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).unwrap();
    assert_eq!(hc.port_status(1).speed, Some(Speed::Low));
    // The device model's 64-byte endpoint 0 is not a legal low-speed one.
    assert_eq!(hc.attach(1), Err(UsbError::BadDescriptor));
    assert!(rig.seen.low_speed_tds.get() > 0);
}

#[test]
fn an_empty_port_has_no_device() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).unwrap();
    assert!(!hc.port_status(2).connected);
    assert_eq!(hc.attach(2), Err(UsbError::NoDevice));
    assert_eq!(hc.attach(3), Err(UsbError::NoDevice));
}

#[test]
fn a_nak_forever_times_out_and_frees_the_queue() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    let mut buf = [0u8; 8];
    // Nothing was written, so the loopback endpoint NAKs.
    assert_eq!(hc.transfer_in(dev.id, 0x81, &mut buf), Err(UsbError::Timeout));
    assert_eq!(hc.element(QH_SYNC), LINK_TERMINATE, "the queue head is empty again");
    hc.transfer_out(dev.id, 0x02, &[1, 2]).unwrap();
    assert_eq!(hc.transfer_in(dev.id, 0x81, &mut buf), Ok(2));
}

#[test]
fn a_device_that_does_not_answer_fails_the_transfer() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    rig.dev.borrow_mut().address = 77; // it no longer answers to ours
    assert_eq!(hc.transfer_out(dev.id, 0x02, &[1]), Err(UsbError::Transaction));
    let mut buf = [0u8; 4];
    assert_eq!(hc.control_in(dev.id, SetupPacket::get_descriptor(1, 0, 4), &mut buf), Err(UsbError::Transaction));
}

#[test]
fn control_transfers_cut_short_by_the_device_reach_the_status_stage() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    // Ask for far more than the 18-byte descriptor: the short packet ends the data stage.
    let mut big = [0u8; 200];
    let n = hc.control_in(dev.id, SetupPacket::get_descriptor(1, 0, 200), &mut big).unwrap();
    assert_eq!(n, 18);
    assert_eq!(&big[..18], &fakedev::DEVICE);
    // Unsupported requests stall.
    assert_eq!(hc.control_in(dev.id, SetupPacket::get_descriptor(3, 0, 4), &mut big), Err(UsbError::Stall));
    assert_eq!(hc.control_in(dev.id, SetupPacket::get_descriptor(1, 0, 18), &mut big), Ok(18), "and recovers");
}

#[test]
fn legacy_support_register_is_taken_over() {
    struct Cfg(Cell<u32>);
    impl ConfigAccess for Cfg {
        fn read32(&self, _: Address, off: u16) -> u32 {
            if off == LEGACY_SUPPORT { self.0.get() } else { 0x1234_8086 }
        }
        fn write32(&self, _: Address, off: u16, v: u32) {
            assert_eq!(off, LEGACY_SUPPORT);
            self.0.set(v);
        }
    }
    let cfg = Cfg(Cell::new(0xabcd_0000 | 0x0f00));
    let func = Function::new(&cfg, Address::new(0, 1, 2)).unwrap();
    release_from_firmware(&func);
    assert_eq!(cfg.0.get(), 0xabcd_0000 | (LEGACY_STATUS | LEGACY_PIRQ) as u32);
}

#[test]
fn rejects_windows_that_are_not_uhci() {
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut small = [0u32; 2];
    // SAFETY: the window covers the array.
    let io = unsafe { IoMem::new(small.as_mut_ptr().cast(), 8) };
    assert_eq!(Uhci::new(UhciRegs::Mmio(io), &dma, &clock).err(), Some(UhciError::BadRegisters));
    let mut none = [0u32; 32];
    // SAFETY: as above; no port has the reserved-one bit.
    let io = unsafe { IoMem::new(none.as_mut_ptr().cast(), 128) };
    assert_eq!(Uhci::new(UhciRegs::Mmio(io), &dma, &clock).err(), Some(UhciError::BadRegisters));
    assert_eq!(dma.live.get(), 0);
}

#[test]
fn a_hub_port_device_is_addressed_without_a_port_reset() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let hub = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    hc.configure_hub(hub.id, 4, 0, false).unwrap();
    // The simulated bus has one device, already addressed: a new one would
    // answer at address 0, so the request fails and gives the address back.
    assert_eq!(hc.attach_hub_port(hub.id, 1, Speed::Full), Err(UsbError::Transaction));
    assert_eq!(hc.attach_hub_port(hub.id, 1, Speed::High), Err(UsbError::Unsupported));
    assert_eq!(hc.configure_hub(DeviceId(7), 4, 0, false), Err(UsbError::NoDevice));
    hc.detach(hub.id);
    assert_eq!(hc.attach_hub_port(hub.id, 1, Speed::Full), Err(UsbError::NoDevice));
}

#[test]
fn a_bulk_in_ended_by_a_zero_length_packet_keeps_the_toggles_in_step() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).unwrap();
    fakedev::zlp_terminated_in(&mut hc, &rig.dev, 1);
}

#[test]
fn a_rejected_endpoint_table_leaves_a_started_transfer_alone() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Uhci::new(rig.regs(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    hc.submit_in(dev.id, 0x83, 8).unwrap();
    // An endpoint without a packet size is refused before anything is cancelled.
    let bad = [EndpointDescriptor { address: 0x85, attributes: 3, max_packet_size_raw: 0, interval: 1 }];
    assert_eq!(hc.configure_endpoints(dev.id, &bad), Err(UsbError::BadDescriptor));
    rig.dev.borrow_mut().report = Some(std::vec![7; 8]);
    let mut report = [0u8; 8];
    let got = (0..1000).find_map(|_| {
        sim::run();
        hc.poll_in(dev.id, 0x83, &mut report)
    });
    assert_eq!(got, Some(Ok(8)));
    assert_eq!(report, [7; 8]);
}
