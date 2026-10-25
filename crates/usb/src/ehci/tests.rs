use core::cell::{Cell, RefCell};
use std::boxed::Box;
use std::rc::Rc;

use osmium_hal::pci::{Address, ConfigAccess};

use super::*;
use crate::usbhc::fakedev::{self, Device, IN, LowDma, OUT, Reply, SETUP, TickClock};
use crate::usbhc::fakedev::{r32 as mem32, w32 as put32};
use crate::usbhc::sim;

const OP: usize = 0x20;

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
    doorbells: Cell<usize>,
    /// Transactions run per queue head chain: (async, periodic).
    async_transactions: Cell<usize>,
    periodic_transactions: Cell<usize>,
}

/// How the simulated device presents itself.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    High,
    Full,
    Low,
}

const PORTS: usize = 2;

std::thread_local! {
    /// Whether the simulated controller is 64-bit capable and acts on it.
    static EXT64: Cell<bool> = const { Cell::new(false) };
}

/// Plays the controller once per call: reset, the doorbell, the root
/// ports, the frame index and one pass over both schedules.
fn controller(win: Win, dev: Rc<RefCell<Device>>, kind: Kind, seen: Rc<Seen>) -> impl FnMut() {
    let portsc = |i: usize| OP + PORTSC + 4 * i;
    let mut state = [win.r(portsc(0)), win.r(portsc(1))];
    move || {
        let cmd = win.r(OP + USBCMD);
        // The driver acknowledges a status bit by writing it, which plain
        // memory keeps as set: the acknowledgement is taken as read.
        let mut sts = win.r(OP + USBSTS) & !STS_ASYNC_ADVANCE;
        if cmd & CMD_HCRESET != 0 {
            win.w(OP + USBCMD, cmd & !CMD_HCRESET);
        }
        let running = cmd & CMD_RUN != 0;
        sts = if running { sts & !STS_HALTED } else { sts | STS_HALTED };
        if cmd & CMD_DOORBELL != 0 {
            seen.doorbells.set(seen.doorbells.get() + 1);
            win.w(OP + USBCMD, cmd & !CMD_DOORBELL);
            sts |= STS_ASYNC_ADVANCE;
        }
        win.w(OP + USBSTS, sts);

        for (i, status) in state.iter_mut().enumerate() {
            let written = win.r(portsc(i));
            if written == *status {
                continue;
            }
            let mut now = *status;
            if written & PORT_RESET != 0 {
                if now & PORT_RESET == 0 {
                    dev.borrow_mut().reset();
                    now &= !PORT_ENABLED;
                }
                now |= PORT_RESET;
            } else if now & PORT_RESET != 0 {
                now &= !PORT_RESET;
                if kind == Kind::High {
                    now |= PORT_ENABLED;
                }
            } else if written & PORT_ENABLED == 0 {
                now &= !PORT_ENABLED;
            }
            if written & PORT_OWNER != 0 {
                now = now & !PORT_CONNECTED | PORT_OWNER;
            }
            if written & PORT_POWER != 0 {
                now |= PORT_POWER;
            }
            now &= !(written & PORT_CHANGES);
            *status = now;
            win.w(portsc(i), now);
        }

        if !running {
            return;
        }
        let frindex = win.r(OP + FRINDEX).wrapping_add(8) & 0x3fff;
        win.w(OP + FRINDEX, frindex);
        if cmd & CMD_ASYNC_ENABLE != 0 {
            let head = win.r(OP + ASYNCLISTADDR);
            let mut qh = head;
            for _ in 0..64 {
                if run_qh(qh as u64, &dev, 0) {
                    seen.async_transactions.set(seen.async_transactions.get() + 1);
                }
                qh = mem32(qh as u64) & !0x1f;
                if qh == head {
                    break;
                }
            }
        }
        if cmd & CMD_PERIODIC_ENABLE != 0 {
            let entry = win.r(OP + PERIODICLISTBASE) as u64 + ((frindex >> 3) as u64 % FRAMES as u64) * 4;
            let mut link = mem32(entry);
            for _ in 0..64 {
                if link & LINK_TERMINATE != 0 {
                    break;
                }
                assert!(link & LINK_QH != 0, "the frame list holds queue heads");
                let qh = (link & !0x1f) as u64;
                if run_qh(qh, &dev, frindex & 7) {
                    seen.periodic_transactions.set(seen.periodic_transactions.get() + 1);
                }
                link = mem32(qh);
            }
        }
    }
}

/// Advances one queue head as far as it will go. True if a transaction ran.
fn run_qh(qh: u64, dev: &RefCell<Device>, uframe: u32) -> bool {
    let ext = EXT64.with(Cell::get);
    let chars = mem32(qh + 4);
    let caps = mem32(qh + 8);
    // A periodic queue head runs in the microframes its S-mask names.
    if uframe != 0 || caps & 0xff != 0 {
        if caps & 0xff == 0 && uframe == 0 {
            // asynchronous, fine
        } else if caps & 0xff & (1 << uframe) == 0 {
            return false;
        }
    }
    let mut ran = false;
    for _ in 0..16 {
        let token = mem32(qh + 24);
        if token & QTD_HALTED != 0 {
            return ran;
        }
        if token & QTD_ACTIVE == 0 {
            // Advance the queue: load the next qTD into the overlay.
            let next = mem32(qh + 16);
            if next & LINK_TERMINATE != 0 {
                return ran;
            }
            let qtd = (next & !0x1f) as u64;
            put32(qh + 12, qtd as u32);
            put32(qh + 16, mem32(qtd));
            put32(qh + 20, mem32(qtd + 4));
            put32(qh + 24, mem32(qtd + 8));
            for k in 0..5 {
                put32(qh + 28 + 4 * k, mem32(qtd + 12 + 4 * k));
            }
            if ext {
                // A 64-bit controller also loads the buffer pointers' high halves,
                // and they are the first dwords after the qTD's and the overlay's
                // 32-bit part.
                for k in 0..5 {
                    assert_eq!(mem32(qtd + 32 + 4 * k), 0, "high half of buffer pointer {k}");
                    put32(qh + 48 + 4 * k, mem32(qtd + 32 + 4 * k));
                }
            }
            if mem32(qtd + 8) & QTD_ACTIVE == 0 {
                return ran;
            }
            continue;
        }
        match transact(qh, chars, dev) {
            Some(()) => ran = true,
            None => return ran,
        }
    }
    ran
}

/// Runs the overlay's transfer on the device. `None` if it NAKed before
/// anything moved. Otherwise the overlay is updated and written back.
fn transact(qh: u64, chars: u32, dev: &RefCell<Device>) -> Option<()> {
    let token = mem32(qh + 24);
    let qtd = mem32(qh + 12) as u64;
    let pid = token & (3 << 8);
    let total = (token >> 16 & 0x7fff) as usize;
    let address = (chars & 0x7f) as u8;
    let ep = (chars >> 8 & 0xf) as u8;
    let mps = (chars >> 16 & 0x7ff) as usize;
    let mut toggle = token >> 31 != 0;
    let mut cpage = (token >> 12 & 7) as usize;
    let mut offset = (mem32(qh + 28) & 0xfff) as usize;
    let page = |i: usize| (mem32(qh + 28 + 4 * i as u64) & !0xfff) as u64;
    let mut left = total;
    let mut short = false;
    let mut status = token & !(QTD_ACTIVE);
    let mut d = dev.borrow_mut();
    loop {
        let want = left.min(mps);
        let here = page(cpage) + offset as u64;
        let reply = if pid == QTD_IN {
            d.transact(address, if ep == 0 { 0 } else { ep | 0x80 }, IN, toggle, &[], want)
        } else {
            let data = fakedev::rbytes(here, want);
            d.transact(address, ep, if pid == QTD_OUT { OUT } else { SETUP }, toggle, &data, 0)
        };
        let moved = match reply {
            Reply::Nak => {
                if left == total {
                    return None;
                }
                // Partway: write the progress into the overlay and retry later.
                write_progress(qh, token, left, toggle, cpage, offset);
                return None;
            }
            Reply::Stall => {
                status |= QTD_HALTED;
                break;
            }
            Reply::None => {
                status |= QTD_HALTED | QTD_TRANSACTION_ERROR;
                break;
            }
            Reply::Ack(data) => {
                if pid == QTD_IN {
                    if data.len() > want {
                        status |= QTD_HALTED | QTD_BABBLE;
                        break;
                    }
                    fakedev::wbytes(here, &data);
                    short = data.len() < mps;
                    data.len()
                } else {
                    want
                }
            }
        };
        toggle = !toggle;
        left -= moved;
        offset += moved;
        if offset >= 4096 {
            offset -= 4096;
            cpage += 1;
        }
        if left == 0 || short {
            break;
        }
    }
    // The qTD ends: the overlay's status goes back into it.
    status = status & !(0x7fff << 16) | (left as u32) << 16;
    status = status & !QTD_TOGGLE | if toggle { QTD_TOGGLE } else { 0 };
    put32(qh + 24, status);
    put32(qtd + 8, status);
    // After a short packet the queue follows the alternate pointer, if it has one.
    let alt = mem32(qh + 20);
    if short && alt & LINK_TERMINATE == 0 {
        put32(qh + 16, alt);
    }
    Some(())
}

fn write_progress(qh: u64, token: u32, left: usize, toggle: bool, cpage: usize, offset: usize) {
    let mut t = token & !(0x7fff << 16) & !(7 << 12) & !QTD_TOGGLE;
    t |= (left as u32) << 16 | (cpage as u32) << 12 | if toggle { QTD_TOGGLE } else { 0 };
    put32(qh + 24, t);
    put32(qh + 28, mem32(qh + 28) & !0xfff | offset as u32);
}

struct Rig {
    dev: Rc<RefCell<Device>>,
    seen: Rc<Seen>,
    win: Box<[u32; 64]>,
}

impl Rig {
    /// A controller with two ports and a device on port 1.
    fn new(kind: Kind) -> Self {
        Self::with(kind, HCS_PORT_POWER_CONTROL | PORTS as u32, 0)
    }

    fn with(kind: Kind, hcsparams: u32, hccparams: u32) -> Self {
        let mut win = Box::new([0u32; 64]);
        let w = Win(win.as_mut_ptr().cast());
        w.w(CAPLENGTH, OP as u32 | 0x0100 << 16);
        w.w(HCSPARAMS, hcsparams);
        w.w(HCCPARAMS, hccparams);
        EXT64.with(|e| e.set(hccparams & HCC_64BIT != 0));
        w.w(OP + USBSTS, STS_HALTED);
        let line = if kind == Kind::Low { PORT_LINE_K } else { 0 };
        let power = if hcsparams & HCS_PORT_POWER_CONTROL == 0 { PORT_POWER } else { 0 };
        w.w(OP + PORTSC, PORT_CONNECTED | line | power);
        w.w(OP + PORTSC + 4, power);
        let dev = Rc::new(RefCell::new(Device::new()));
        let seen = Rc::new(Seen::default());
        sim::install(controller(Win(win.as_mut_ptr().cast()), dev.clone(), kind, seen.clone()));
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
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).expect("start");
    assert_eq!(hc.ports(), 2);
    assert_eq!(hc.port_status(1).speed, Some(Speed::Full), "the speed is known after the reset");
    fakedev::exercise(&mut hc, &rig.dev, 1);
    assert!(rig.seen.async_transactions.get() > 0);
    assert!(rig.seen.periodic_transactions.get() > 0, "the interrupt endpoint ran on the periodic list");
    drop(hc);
    assert_eq!(dma.live.get(), 0, "all DMA memory freed");
}

#[test]
fn the_controller_is_started_with_both_schedules_and_the_ports_routed() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    let w = rig.win();
    let cmd = w.r(OP + USBCMD);
    assert_eq!(
        cmd & (CMD_RUN | CMD_ASYNC_ENABLE | CMD_PERIODIC_ENABLE),
        CMD_RUN | CMD_ASYNC_ENABLE | CMD_PERIODIC_ENABLE
    );
    assert_eq!(w.r(OP + CONFIGFLAG), 1);
    assert_eq!(w.r(OP + ASYNCLISTADDR), hc.qh_addr(QH_ASYNC_HEAD));
    assert_eq!(w.r(OP + PORTSC) & PORT_POWER, PORT_POWER, "ports with power control are powered");
    assert_eq!(w.r(OP + PORTSC + 4) & PORT_POWER, PORT_POWER);
    drop(hc);
    assert_eq!(w.r(OP + CONFIGFLAG), 0, "the ports go back to the companions");
    assert_eq!(w.r(OP + USBCMD) & CMD_RUN, 0);
}

#[test]
fn a_full_speed_device_is_handed_to_the_companion() {
    let mut rig = Rig::new(Kind::Full);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    assert!(hc.port_status(1).connected);
    assert_eq!(hc.attach(1), Err(UsbError::Unsupported));
    let sc = rig.win().r(OP + PORTSC);
    assert_ne!(sc & PORT_OWNER, 0, "the port is the companion's now");
    assert!(!hc.port_status(1).connected, "and shows nothing here");
    assert_eq!(hc.attach(1), Err(UsbError::NoDevice));
}

#[test]
fn a_low_speed_device_is_handed_over_without_a_reset() {
    let mut rig = Rig::new(Kind::Low);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    assert_eq!(hc.port_status(1).speed, Some(Speed::Low));
    assert_eq!(hc.attach(1), Err(UsbError::Unsupported));
    assert_ne!(rig.win().r(OP + PORTSC) & PORT_OWNER, 0);
    assert_eq!(rig.dev.borrow().log.len(), 0, "the device never saw a request");
}

#[test]
fn an_empty_port_has_no_device() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    assert!(!hc.port_status(2).connected);
    assert_eq!(hc.attach(2), Err(UsbError::NoDevice));
    assert_eq!(hc.attach(3), Err(UsbError::NoDevice));
}

#[test]
fn hubs_are_not_supported() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let hub = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    assert_eq!(hc.configure_hub(hub.id, 4, 0, false), Err(UsbError::Unsupported));
    assert_eq!(hc.attach_hub_port(hub.id, 1, Speed::Full), Err(UsbError::Unsupported));
}

#[test]
fn a_nak_forever_times_out_and_the_queue_head_is_unlinked_and_relinked() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    let mut buf = [0u8; 8];
    // Nothing was written, so the loopback endpoint NAKs.
    assert_eq!(hc.transfer_in(dev.id, 0x81, &mut buf), Err(UsbError::Timeout));
    assert_eq!(rig.seen.doorbells.get(), 1, "the controller was told to let go of the queue head");
    assert_eq!(hc.qh_word(QH_SYNC, 6) & QTD_ACTIVE, 0);
    assert_eq!(hc.qh_word(QH_ASYNC_HEAD, 0), hc.qh_addr(QH_SYNC) | LINK_QH, "and it is linked again");
    hc.transfer_out(dev.id, 0x02, &[1, 2]).unwrap();
    assert_eq!(hc.transfer_in(dev.id, 0x81, &mut buf), Ok(2));
}

#[test]
fn cancelling_an_interrupt_transfer_leaves_the_periodic_list_intact() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    hc.submit_in(dev.id, 0x83, 8).unwrap();
    // Re-configuring the endpoints abandons what was in flight.
    let eps = [EndpointDescriptor { address: 0x83, attributes: 3, max_packet_size_raw: 8, interval: 4 }];
    hc.configure_endpoints(dev.id, &eps).unwrap();
    assert_eq!(hc.qh_word(QH_PERIODIC_ROOT, 0), hc.qh_addr(QH_PERIODIC) | LINK_QH);
    assert_eq!(hc.qh_word(QH_PERIODIC, 0), hc.qh_addr(QH_PERIODIC + 1) | LINK_QH);
    hc.submit_in(dev.id, 0x83, 8).unwrap();
    rig.dev.borrow_mut().report = Some(std::vec![7; 8]);
    let mut report = [0u8; 8];
    let got = (0..1000).find_map(|_| {
        sim::run();
        hc.poll_in(dev.id, 0x83, &mut report)
    });
    assert_eq!(got, Some(Ok(8)));
    assert_eq!(report, [7; 8]);
}

#[test]
fn a_device_that_does_not_answer_fails_the_transfer_and_recovers() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    rig.dev.borrow_mut().address = 77; // it no longer answers to ours
    assert_eq!(hc.transfer_out(dev.id, 0x02, &[1]), Err(UsbError::Transaction));
    // The halted queue head is filled in afresh by the next transfer.
    rig.dev.borrow_mut().address = dev.id.0;
    hc.transfer_out(dev.id, 0x02, &[1]).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(hc.transfer_in(dev.id, 0x81, &mut buf), Ok(1));
}

#[test]
fn control_transfers_cut_short_by_the_device_reach_the_status_stage() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
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
fn large_transfers_span_pages() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    let mut cfg = [0u8; 128];
    let dev = osmium_hal::usb::enumerate(&mut hc, 1, &mut cfg).unwrap();
    // More than one piece, so the transfer is split, and each piece crosses pages.
    let data: std::vec::Vec<u8> = (0..PIECE * 2 + 1000).map(|i| (i % 251) as u8).collect();
    hc.transfer_out(dev.id, 0x02, &data).unwrap();
    let mut back = std::vec![0u8; data.len()];
    let mut got = 0;
    while got < back.len() {
        got += hc.transfer_in(dev.id, 0x81, &mut back[got..]).unwrap();
    }
    assert_eq!(back, data);
    assert_eq!(rig.dev.borrow().toggle_errors, 0);
}

#[test]
fn firmware_is_asked_to_let_go() {
    struct Cfg {
        dwords: RefCell<[u32; 64]>,
    }
    impl ConfigAccess for Cfg {
        fn read32(&self, _: Address, off: u16) -> u32 {
            self.dwords.borrow()[off as usize / 4]
        }
        fn write32(&self, _: Address, off: u16, v: u32) {
            let mut d = self.dwords.borrow_mut();
            d[off as usize / 4] = v;
            // BIOS lets go when it sees the OS ask.
            if off == 0x50 && v & LEGACY_OS_OWNED != 0 {
                d[off as usize / 4] &= !LEGACY_BIOS_OWNED;
            }
        }
    }
    let mut rig = Rig::with(Kind::High, PORTS as u32, 0x50 << 8);
    let cfg = Cfg { dwords: RefCell::new([0; 64]) };
    {
        let mut d = cfg.dwords.borrow_mut();
        d[0] = 0x1234_8086; // a function is there
        d[0x40 / 4] = 0x0000_0a09; // a capability that is not ours, next at 0x50
        d[0x40 / 4] = 0x0000_5000 | 0x0a; // id 0x0a, next 0x50
        d[0x50 / 4] = EXT_CAP_LEGACY | LEGACY_BIOS_OWNED; // ours, last
        d[0x54 / 4] = 0xffff_ffff; // SMI enables
    }
    let func = Function::new(&cfg, Address::new(0, 1, 7)).unwrap();
    // The walk starts at EECP, here 0x50.
    let io = rig.io();
    release_from_firmware(&func, &io, &TickClock::default());
    let d = cfg.dwords.borrow();
    assert_ne!(d[0x50 / 4] & LEGACY_OS_OWNED, 0);
    assert_eq!(d[0x50 / 4] & LEGACY_BIOS_OWNED, 0, "the BIOS let go");
    assert_eq!(d[0x54 / 4], 0, "and its SMIs are off");
}

#[test]
fn rejects_windows_that_are_not_ehci() {
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut blank = [0u32; 64];
    // SAFETY: the window covers the array.
    let io = unsafe { IoMem::new(blank.as_mut_ptr().cast(), 256) };
    assert_eq!(Ehci::new(io, &dma, &clock).err(), Some(EhciError::BadRegisters));
    // Right registers, but the window ends before the ports do.
    let mut rig = Rig::new(Kind::High);
    // SAFETY: as above.
    let io = unsafe { IoMem::new(rig.win.as_mut_ptr().cast(), OP + PORTSC + 4) };
    assert_eq!(Ehci::new(io, &dma, &clock).err(), Some(EhciError::BadRegisters));
    assert_eq!(dma.live.get(), 0);
}

#[test]
fn memory_above_4g_is_refused() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (crate::testing::HostDma::default(), TickClock::default());
    assert_eq!(Ehci::new(rig.io(), &dma, &clock).err(), Some(EhciError::HighMemory));
    assert_eq!(dma.live.get(), 0, "nothing leaks");
}

#[test]
fn a_64_bit_controller_finds_its_extended_dwords_inside_the_structures() {
    let mut rig = Rig::with(Kind::High, HCS_PORT_POWER_CONTROL | PORTS as u32, HCC_64BIT);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    assert_eq!(rig.win().r(OP + CTRLDSSEGMENT), 0);
    const { assert!(QTD_SIZE >= QTD_EXT_OFFSET + 20 && QH_SIZE >= 4 * QH_EXT_WORD + 20) };
    fakedev::exercise(&mut hc, &rig.dev, 1);
    drop(hc);
    assert_eq!(dma.live.get(), 0);
}

#[test]
fn a_bulk_in_ended_by_a_zero_length_packet_keeps_the_toggles_in_step() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    fakedev::zlp_terminated_in(&mut hc, &rig.dev, 1);
}

#[test]
fn a_rejected_endpoint_table_leaves_a_started_transfer_alone() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
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

#[test]
fn interrupts_are_serviced_only_when_enabled_and_asserted() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    let w = rig.win();
    assert_eq!(w.r(OP + USBINTR), 0, "polled until asked");
    w.w(OP + USBSTS, STS_USBINT);
    assert!(!hc.handle_interrupt(), "not enabled");
    hc.enable_interrupts();
    assert_eq!(w.r(OP + USBINTR), STS_EVENTS);
    assert_eq!(STS_EVENTS & STS_ASYNC_ADVANCE, 0, "abort polls for it");
    w.w(OP + USBSTS, STS_ASYNC_ADVANCE);
    assert!(!hc.handle_interrupt(), "not one the handler takes");
    w.w(OP + USBSTS, STS_PORT_CHANGE);
    assert!(hc.handle_interrupt());
    assert_eq!(hc.interrupts_handled(), 1);
    hc.disable_interrupts();
    assert_eq!(w.r(OP + USBINTR), 0);
}

#[test]
fn polled_operations_work_with_interrupts_enabled() {
    let mut rig = Rig::new(Kind::High);
    let (dma, clock) = (LowDma::default(), TickClock::default());
    let mut hc = Ehci::new(rig.io(), &dma, &clock).unwrap();
    hc.enable_interrupts();
    fakedev::exercise(&mut hc, &rig.dev, 1);
}
