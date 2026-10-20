//! Drives `run_vcpu` with a scripted vCPU standing in for a hardware backend.

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};

use osmium_virt::devices::Uart16550;
use osmium_virt::{Bus, GuestPhysAddr, Vcpu, VmExit, run_vcpu};

/// Replays exits and records what the hypervisor fed back.
struct ScriptedVcpu {
    exits: VecDeque<VmExit>,
    reads: Vec<u64>,
    hypercall_ret: Option<u64>,
}

impl Vcpu for ScriptedVcpu {
    fn run(&mut self) -> VmExit {
        self.exits.pop_front().unwrap_or(VmExit::Shutdown)
    }
    fn complete_read(&mut self, value: u64) {
        self.reads.push(value);
    }
    fn complete_hypercall(&mut self, ret: u64) {
        self.hypercall_ret = Some(ret);
    }
}

const UART: u64 = 0x1000_0000;

fn mmio_write(off: u64, byte: u8) -> VmExit {
    VmExit::MmioWrite { addr: GuestPhysAddr(UART + off), size: 1, data: byte as u64 }
}

#[test]
fn guest_console_and_hypercalls() {
    let out = Arc::new(Mutex::new(Vec::new()));
    let uart = Arc::new(Uart16550::new({
        let out = out.clone();
        move |b| out.lock().unwrap().push(b)
    }));
    uart.push_input(b'y');
    let mmio = Bus::new();
    mmio.insert(UART, 8, uart.clone()).unwrap();
    let pio = Bus::new();

    let mut exits: VecDeque<VmExit> = VecDeque::new();
    // Guest: program divisor latch, print "ok", check LSR, read a byte.
    exits.extend([mmio_write(3, 0x80), mmio_write(0, 1), mmio_write(3, 0x03)]);
    exits.extend(b"ok\n".iter().map(|&b| mmio_write(0, b)));
    exits.push_back(VmExit::MmioRead { addr: GuestPhysAddr(UART + 5), size: 1 });
    exits.push_back(VmExit::MmioRead { addr: GuestPhysAddr(UART), size: 1 });
    // Nothing decodes this port or address: reads float high.
    exits.push_back(VmExit::PioIn { port: 0x80, size: 2 });
    exits.push_back(VmExit::MmioRead { addr: GuestPhysAddr(0xdead_0000), size: 4 });
    exits.push_back(VmExit::Hypercall { nr: 7, args: [1, 2, 3, 0, 0, 0] });
    exits.push_back(VmExit::Halt);
    exits.push_back(VmExit::Shutdown);

    let mut vcpu = ScriptedVcpu { exits, reads: Vec::new(), hypercall_ret: None };
    let mut halts = 0;
    let last = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { nr, args } => {
            v.complete_hypercall(nr + args.iter().sum::<u64>());
            ControlFlow::Continue(())
        }
        VmExit::Halt => {
            halts += 1;
            ControlFlow::Continue(())
        }
        other => ControlFlow::Break(other),
    });

    assert_eq!(last, VmExit::Shutdown);
    assert_eq!(*out.lock().unwrap(), b"ok\n");
    assert_eq!(vcpu.reads, [0x61, b'y' as u64, 0xffff, 0xffff_ffff], "LSR had THRE|TEMT|DR");
    assert_eq!(vcpu.hypercall_ret, Some(13));
    assert_eq!(halts, 1);
    assert!(!uart.irq_pending());
}
