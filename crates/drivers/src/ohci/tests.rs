use core::cell::{Cell, RefCell};
use std::boxed::Box;
use std::rc::Rc;

use super::*;
use crate::usbhc::fakedev::{self, Device, IN, LowDma, OUT, Reply, SETUP, TickClock};
use crate::usbhc::fakedev::{r32 as mem32, rbytes as read_bytes, w32 as put32, wbytes as write_bytes};
use crate::usbhc::sim;

/// A register window in plain memory.
struct Win(*mut u8);

impl Win {
    fn r(&self, off: usize) -> u32 {
        // SAFETY: within the test's register array.
        unsafe { self.0.add(off).cast::<u32>().read_volatile() }
    }

    fn w(&self, off: usize, v: u32) {
        // SAFETY: within the test's register array.
        unsafe { self.0.add(off).cast::<u32>().write_volatile(v) }
    }
}

/// What the simulated controller saw.
#[derive(Default)]
struct Seen {
    low_speed_eds: Cell<usize>,
    smm_handoffs: Cell<usize>,
}

const PORTS: usize = 2;

/// Plays the controller once per call: software reset, handoff from SMM,
/// the root hub's port commands, the frame counter and one pass over the
/// three lists.
fn controller(win: Win, dev: Rc<RefCell<Device>>, seen: Rc<Seen>) -> impl FnMut() {
    // The port status as the controller holds it; a register that differs
    // from it was written by the driver, and is a command.
    let mut state = [win.r(RH_PORT_STATUS), win.r(RH_PORT_STATUS + 4)];
    move || {
        let cs = win.r(COMMAND_STATUS);
        if cs & CMD_OCR != 0 {
            seen.smm_handoffs.set(seen.smm_handoffs.get() + 1);
            win.w(CONTROL, win.r(CONTROL) & !CTRL_INTERRUPT_ROUTING);
        }
        if cs & CMD_HCR != 0 {
            win.w(CONTROL, win.r(CONTROL) & !CTRL_HCFS | CTRL_HCFS);
        }
        win.w(COMMAND_STATUS, cs & !(CMD_HCR | CMD_OCR | CMD_CLF | CMD_BLF));

        for (i, status) in state.iter_mut().enumerate() {
            let reg = RH_PORT_STATUS + 4 * i;
            let written = win.r(reg);
            if written == *status {
                continue;
            }
            let mut now = *status;
            if written & PORT_SET_RESET != 0 && now & PORT_CONNECTED != 0 {
                dev.borrow_mut().reset();
                now |= PORT_RESET_CHANGE;
                now |= PORT_ENABLED;
            }
            if written & PORT_SET_ENABLE != 0 && now & PORT_CONNECTED != 0 {
                now |= PORT_ENABLED;
            }
            if written & PORT_SET_POWER != 0 {
                now |= PORT_SET_POWER;
            }
            now &= !(written & PORT_CHANGES);
            *status = now;
            win.w(reg, now);
        }

        if win.r(CONTROL) & CTRL_HCFS != CTRL_OPERATIONAL {
            return;
        }
        let frame = win.r(FM_NUMBER).wrapping_add(1) & 0xffff;
        win.w(FM_NUMBER, frame);
        let control = win.r(CONTROL);
        if control & CTRL_CLE != 0 {
            run_list(win.r(CONTROL_HEAD_ED), &dev, &seen);
        }
        if control & CTRL_BLE != 0 {
            run_list(win.r(BULK_HEAD_ED), &dev, &seen);
        }
        if control & CTRL_PLE != 0 {
            let entry = mem32(win.r(HCCA) as u64 + 4 * (frame as u64 % 32));
            run_list(entry, &dev, &seen);
        }
    }
}

fn run_list(mut ed: u32, dev: &RefCell<Device>, seen: &Seen) {
    for _ in 0..64 {
        if ed == 0 {
            return;
        }
        run_ed(ed as u64, dev, seen);
        ed = mem32(ed as u64 + 12);
    }
    panic!("endpoint descriptor list does not end");
}

fn run_ed(ed: u64, dev: &RefCell<Device>, seen: &Seen) {
    for _ in 0..64 {
        let d0 = mem32(ed);
        let d2 = mem32(ed + 8);
        let head = (d2 & !0xf) as u64;
        if d0 & ED_SKIP != 0 || d2 & ED_HALTED != 0 || head == (mem32(ed + 4) & !0xf) as u64 {
            return;
        }
        if d0 & ED_LOW_SPEED != 0 {
            seen.low_speed_eds.set(seen.low_speed_eds.get() + 1);
        }
        let next = mem32(head + 8) & !0xf;
        match transact(head, d0, dev) {
            // Retiring a descriptor links it to the done queue.
            Some(true) => {
                put32(head + 8, 0);
                put32(ed + 8, d2 & 0xf | next);
            }
            Some(false) => {
                put32(head + 8, 0);
                put32(ed + 8, d2 | ED_HALTED);
                return;
            }
            None => return,
        }
    }
}

/// Executes one descriptor for the endpoint `ed0`. `None` if the device
/// NAKed before anything moved; else whether it completed without error.
fn transact(td: u64, ed0: u32, dev: &RefCell<Device>) -> Option<bool> {
    let d0 = mem32(td);
    let cbp = mem32(td + 4) as u64;
    let be = mem32(td + 12) as u64;
    let address = (ed0 & 0x7f) as u8;
    let ep = (ed0 >> 7 & 0xf) as u8;
    let mps = (ed0 >> 16 & 0x7ff) as usize;
    let len = if cbp == 0 { 0 } else { (be - cbp + 1) as usize };
    let mut toggle = d0 & TD_TOGGLE != 0;
    assert!(d0 & TD_USE_TOGGLE != 0, "this driver always supplies the toggle");
    let dp = d0 & (3 << 19);
    let retire = |cc: u32, remaining: Option<u64>| {
        let flags = d0 & !(0xf << 28) | cc << 28;
        put32(td, flags);
        put32(td + 4, remaining.unwrap_or(0) as u32);
    };
    let mut d = dev.borrow_mut();
    let mut pos = 0;
    loop {
        let want = (len - pos).min(mps);
        let reply = if dp == TD_IN {
            d.transact(address, if ep == 0 { 0 } else { ep | 0x80 }, IN, toggle, &[], want)
        } else {
            let data = read_bytes(cbp + pos as u64, want);
            d.transact(address, ep, if dp == TD_OUT { OUT } else { SETUP }, toggle, &data, 0)
        };
        match reply {
            Reply::Nak => {
                if pos == 0 {
                    return None;
                }
                // Partway through: what moved stays moved.
                put32(td + 4, (cbp + pos as u64) as u32);
                put32(td, d0 ^ TD_TOGGLE ^ if pos / mps % 2 == 0 { TD_TOGGLE } else { 0 });
                return None;
            }
            Reply::Stall => {
                retire(CC_STALL, Some(cbp + pos as u64));
                return Some(false);
            }
            Reply::None => {
                retire(5, Some(cbp + pos as u64));
                return Some(false);
            }
            Reply::Ack(data) => {
                toggle = !toggle;
                if dp == TD_IN {
                    if data.len() > want {
                        retire(8, Some(cbp + pos as u64));
                        return Some(false);
                    }
                    write_bytes(cbp + pos as u64, &data);
                    pos += data.len();
                    if data.len() < mps {
                        // A short packet ends the descriptor.
                        if pos < len && d0 & TD_ROUNDING == 0 {
                            retire(9, Some(cbp + pos as u64));
                            return Some(false);
                        }
                        retire(0, (pos < len).then_some(cbp + pos as u64));
                        return Some(true);
                    }
                } else {
                    pos += want;
                }
                if pos >= len {
                    retire(0, None);
                    return Some(true);
                }
            }
        }
    }
}

struct Rig {
    dev: Rc<RefCell<Device>>,
    seen: Rc<Seen>,
    win: Box<[u32; 64]>,
}

impl Rig {
    /// A controller with two ports and a device on port 1.
    fn new(low_speed: bool) -> Self {
        let mut win = Box::new([0u32; 64]);
        let w = Win(win.as_mut_ptr().cast());
        w.w(REVISION, 0x10);
        w.w(RH_DESCRIPTOR_A, PORTS as u32 | 1 << RH_POWER_ON_TO_GOOD_SHIFT);
        w.w(RH_PORT_STATUS, PORT_CONNECTED | if low_speed { PORT_LOW_SPEED } else { 0 });
        let dev = Rc::new(RefCell::new(Device::new()));
        let seen = Rc::new(Seen::default());
        sim::install(controller(Win(win.as_mut_ptr().cast()), dev.clone(), seen.clone()));
        Self { dev, seen, win }
    }

    fn io(&mut self) -> IoMem {
        // SAFETY: the window is the rig's array, which outlives the controller.
        unsafe { IoMem::new(self.win.as_mut_ptr().cast(), 64 * 4) }
    }

    fn win(&mut self) -> Win {
        Win(self.win.as_mut_ptr().cast())
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
    let mut hc = Ohci::new(rig.io(), &dma, &clock).expect("start");
    assert_eq!(hc.ports(), 2);
    fakedev::exercise(&mut hc, &rig.dev, 1);
    assert_eq!(rig.seen.low_speed_eds.get(), 0);
    drop(hc);
    assert_eq!(dma.live.get(), 0, "all DMA memory freed");
}

#[test]
fn low_speed_devices_set_the_low_speed_bit() {
    let mut rig = Rig::new(true);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ohci::new(rig.io(), &dma, &clock).unwrap();
    assert_eq!(hc.port_status(1).speed, Some(Speed::Low));
    // The device model's 64-byte endpoint 0 is not a legal low-speed one.
    assert_eq!(hc.attach(1), Err(UsbError::BadDescriptor));
    assert!(rig.seen.low_speed_eds.get() > 0);
}

#[test]
fn an_empty_port_has_no_device() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ohci::new(rig.io(), &dma, &clock).unwrap();
    assert!(!hc.port_status(2).connected);
    assert_eq!(hc.attach(2), Err(UsbError::NoDevice));
    assert_eq!(hc.attach(3), Err(UsbError::NoDevice));
}

#[test]
fn the_controller_is_taken_from_smm_firmware() {
    let mut rig = Rig::new(false);
    let w = rig.win();
    w.w(CONTROL, CTRL_INTERRUPT_ROUTING);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let hc = Ohci::new(rig.io(), &dma, &clock).unwrap();
    assert_eq!(rig.seen.smm_handoffs.get(), 1);
    drop(hc);
}

#[test]
fn the_ports_are_powered_and_the_lists_run() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let hc = Ohci::new(rig.io(), &dma, &clock).unwrap();
    let w = rig.win();
    assert_eq!(w.r(CONTROL) & CTRL_HCFS, CTRL_OPERATIONAL);
    assert_eq!(w.r(CONTROL) & (CTRL_CLE | CTRL_BLE | CTRL_PLE), CTRL_CLE | CTRL_BLE | CTRL_PLE);
    assert_eq!(w.r(RH_PORT_STATUS) & PORT_SET_POWER, PORT_SET_POWER);
    assert_eq!(w.r(RH_PORT_STATUS + 4) & PORT_SET_POWER, PORT_SET_POWER);
    assert_eq!(w.r(FM_INTERVAL) & 0x3fff, DEFAULT_FRAME_INTERVAL);
    assert_eq!(w.r(FM_INTERVAL) & FM_INTERVAL_TOGGLE, FM_INTERVAL_TOGGLE, "the frame interval toggle flipped");
    assert_eq!(w.r(PERIODIC_START), DEFAULT_FRAME_INTERVAL * 9 / 10);
    drop(hc);
    assert_eq!(w.r(CONTROL) & CTRL_HCFS, 0, "dropping resets the controller");
}

#[test]
fn a_nak_forever_times_out_and_skips_the_endpoint() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ohci::new(rig.io(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    let mut buf = [0u8; 8];
    // Nothing was written, so the loopback endpoint NAKs.
    assert_eq!(hc.transfer_in(dev.id, 0x81, &mut buf), Err(UsbError::Timeout));
    assert_ne!(hc.ed_word(ED_SYNC_BULK, 0) & ED_SKIP, 0, "the endpoint is skipped again");
    hc.transfer_out(dev.id, 0x02, &[1, 2]).unwrap();
    assert_eq!(hc.transfer_in(dev.id, 0x81, &mut buf), Ok(2));
}

#[test]
fn a_device_that_does_not_answer_fails_the_transfer() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ohci::new(rig.io(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    rig.dev.borrow_mut().address = 77; // it no longer answers to ours
    assert_eq!(hc.transfer_out(dev.id, 0x02, &[1]), Err(UsbError::Transaction));
    // The halted endpoint is armed afresh by the next transfer.
    rig.dev.borrow_mut().address = dev.id.0;
    hc.transfer_out(dev.id, 0x02, &[1]).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(hc.transfer_in(dev.id, 0x81, &mut buf), Ok(1));
}

#[test]
fn control_transfers_cut_short_by_the_device_complete() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ohci::new(rig.io(), &dma, &clock).unwrap();
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
fn rejects_windows_that_are_not_ohci() {
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut blank = [0u32; 64];
    // SAFETY: the window covers the array.
    let io = unsafe { IoMem::new(blank.as_mut_ptr().cast(), 256) };
    assert_eq!(Ohci::new(io, &dma, &clock).err(), Some(OhciError::BadRegisters));
    let mut short = [0u32; 24];
    short[0] = 0x10;
    short[RH_DESCRIPTOR_A / 4] = 2;
    // SAFETY: as above; the window ends before the second port.
    let io = unsafe { IoMem::new(short.as_mut_ptr().cast(), 88) };
    assert_eq!(Ohci::new(io, &dma, &clock).err(), Some(OhciError::BadRegisters));
    assert_eq!(dma.live.get(), 0);
}

#[test]
fn memory_above_4g_is_refused() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (crate::virtio::testing::HostDma::default(), TickClock::default());
    assert_eq!(Ohci::new(rig.io(), &dma, &clock).err(), Some(OhciError::HighMemory));
    assert_eq!(dma.live.get(), 0, "nothing leaks");
}

#[test]
fn a_hub_port_device_is_addressed_without_a_port_reset() {
    let mut rig = Rig::new(false);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ohci::new(rig.io(), &dma, &clock).unwrap();
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
