//! Booting a whole guest kernel: an ELF image QEMU's loader places in host
//! RAM (`-device loader,file=...,addr=0x58000000,force-raw=on`), run with
//! one vCPU per host CPU under a generated device tree, an emulated GICv2
//! and PL011, the virtual timer and PSCI. Its console lines are printed
//! with a `| ` prefix.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use osmium::boot::elf::Elf;
use osmium::hal::irq::InterruptController;
use osmium::hal::println;
use osmium::mm::{FrameAllocator, PAGE_SIZE, PageTable, PhysAddr};
use osmium::sync::IrqSpinLock;
use osmium::virt::aarch64::fdt::ArmMachine;
use osmium::virt::aarch64::{self as vm, Aarch64Vcpu};
use osmium::virt::devices::{GIC_WINDOW, PL011_WINDOW, Pl011, VirtualGicV2};
use osmium::virt::smp::GuestCpus;
use osmium::virt::stage2::{Stage2Table, map_guest_memory, vttbr};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

use crate::{FRAMES, KICK_SGI, PHYS_GIC, VTIMER_INTID};

/// Where QEMU's loader puts the guest kernel, and the window kept free for it.
pub const IMAGE_BASE: u64 = 0x5800_0000;
pub const IMAGE_WINDOW: u64 = 0x0800_0000;

const GUEST_RAM: u64 = 0x4000_0000;
const GUEST_RAM_ORDER: u32 = 14; // 64 MiB
const GICD: u64 = 0x0800_0000;
const GICC: u64 = 0x0801_0000;
const UART: u64 = 0x0900_0000;
const UART_SPI: u32 = 1;
const MAX_CPUS: usize = 8;

/// A guest shared by every host CPU, each running one of its vCPUs.
pub struct KernelVm {
    cpus: Arc<GuestCpus>,
    vttbr: u64,
    /// Per vCPU: its MMIO bus (its own GIC views plus the shared PL011),
    /// its IRQ line.
    buses: Vec<Bus>,
    lines: Vec<Arc<AtomicBool>>,
    gic: Arc<VirtualGicV2>,
    done: AtomicBool,
    running: AtomicUsize,
}

pub static KERNEL_VM: AtomicPtr<KernelVm> = AtomicPtr::new(core::ptr::null_mut());

/// The guest image QEMU's loader left in the window, if any.
pub fn image() -> Option<Elf<'static>> {
    // SAFETY: the caller reserved the window (it is RAM the loader filled or left zero).
    let window = unsafe { core::slice::from_raw_parts(IMAGE_BASE as *const u8, IMAGE_WINDOW as usize) };
    Elf::new(window).ok()
}

/// The guest's console: whole lines, prefixed so they stand apart from the host's.
fn guest_console() -> impl Fn(u8) + Send + Sync + 'static {
    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    move |b| {
        let mut l = line.lock();
        match b {
            b'\n' => {
                println!("| {}", core::str::from_utf8(&l).unwrap_or("?"));
                l.clear();
            }
            b'\r' => {}
            _ => l.push(b),
        }
    }
}

/// Runs vCPU `me` on this host CPU each time the guest starts it, until the
/// guest is done. Returns the exit that ended the guest, if it was this
/// vCPU's.
pub fn vcpu_loop(vm: &KernelVm, me: usize) -> Option<VmExit> {
    let pio = Bus::new();
    let mut last = None;
    while !vm.done.load(Ordering::Acquire) {
        let Some((entry, context)) = vm.cpus.take_start(me) else {
            core::hint::spin_loop();
            continue;
        };
        let mut vcpu = Aarch64Vcpu::new(GuestPhysAddr(entry), context, vm.vttbr).with_irq_line(vm.lines[me].clone());
        // The virtual timer feeds the vGIC; while its line is up, the
        // physical PPI stays masked on this CPU so it does not keep exiting
        // the guest.
        let gic = vm.gic.clone();
        let masked = AtomicBool::new(false);
        vcpu.connect_timer(move |level| {
            gic.set_private_level(me, VTIMER_INTID, level);
            if masked.swap(level, Ordering::Relaxed) != level {
                let g = PHYS_GIC.get().unwrap();
                if level { g.disable(VTIMER_INTID) } else { g.enable(VTIMER_INTID) }
            }
        });
        vm.cpus.attach_arm(me, &mut vcpu);
        let mut stopped = false;
        let exit = run_vcpu(&mut vcpu, &vm.buses[me], &pio, |v, exit| match exit {
            VmExit::Hypercall { .. } => match vm::psci::handle_smp(v, exit, Some((&vm.cpus, me))) {
                Some(vm::psci::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                Some(vm::psci::Outcome::Stop) => {
                    stopped = true;
                    ControlFlow::Break(VmExit::Halt)
                }
                _ => ControlFlow::Continue(()),
            },
            VmExit::Halt => {
                // The guest idles in wfi: run it again once it has an
                // interrupt, or stop when another vCPU ended the guest.
                while !v.interrupt_pending(vm::counter()) {
                    if vm.done.load(Ordering::Acquire) {
                        return ControlFlow::Break(VmExit::Halt);
                    }
                    core::hint::spin_loop();
                }
                ControlFlow::Continue(())
            }
            VmExit::ExternalInterrupt => {
                // The timer's PPI or a kick: acknowledge it; the next entry
                // delivers what the guest now has pending.
                let g = PHYS_GIC.get().unwrap();
                if let Some(irq) = g.claim() {
                    g.complete(irq);
                }
                if vm.done.load(Ordering::Acquire) {
                    return ControlFlow::Break(VmExit::Halt);
                }
                ControlFlow::Continue(())
            }
            other => ControlFlow::Break(other),
        });
        // Leave the physical timer PPI as the next guest expects it.
        PHYS_GIC.get().unwrap().enable(VTIMER_INTID);
        if stopped {
            continue; // CPU_OFF: wait for CPU_ON
        }
        if !vm.done.swap(true, Ordering::AcqRel) {
            for i in 0..vm.lines.len() {
                vm.cpus.kick(i);
            }
            if exit != VmExit::Shutdown {
                println!("[hyp]   vCPU {me} stopped the guest: {exit:?} at pc {:#x}", vcpu.state.pc);
            }
            last = Some(exit);
        }
    }
    vm.running.fetch_sub(1, Ordering::AcqRel);
    last
}

/// Loads `elf` into fresh guest RAM and runs it with one vCPU per host CPU
/// until it shuts down.
pub fn boot(elf: &Elf<'_>, ncpus: usize) {
    let ncpus = ncpus.min(MAX_CPUS);
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by the guest for the rest of the run.
    unsafe { mem.add_region(GuestPhysAddr(GUEST_RAM), ram.0 as *mut u8, len) };
    // The image is linked where it runs: physical = virtual.
    let image = match mem.load_elf(elf) {
        Ok(r) => r,
        Err(e) => {
            println!("[hyp]   the guest kernel does not fit its RAM ({e:?})");
            return;
        }
    };
    let kib = (image.end - image.start) >> 10;
    println!("[hyp]   guest kernel: {kib} KiB loaded, entry {:#x}, {ncpus} vCPUs", elf.entry());
    // The device tree at the base of RAM, where QEMU puts it for ELF kernels.
    let dtb = ArmMachine {
        cpus: ncpus as u32,
        memory: &[(GUEST_RAM, len)],
        gic: (GICD, GICC),
        uarts: &[(UART, UART_SPI)],
        virtio: &[],
        bootargs: "",
    }
    .to_dtb();
    if image.start < GUEST_RAM + dtb.len() as u64 {
        println!("[hyp]   the guest kernel overlaps its device tree at {GUEST_RAM:#x}");
        return;
    }
    mem.write(GuestPhysAddr(GUEST_RAM), &dtb).unwrap();

    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).expect("stage-2 root");
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).unwrap();
    let vttbr = vttbr(s2.root(), 4);
    core::mem::forget(s2); // in use until power-off
    core::mem::forget(mem);

    // A vCPU's interrupt arriving while it runs guest code on another host
    // CPU kicks that CPU with a physical SGI.
    let cpus = GuestCpus::with_kick(ncpus, |host| PHYS_GIC.get().unwrap().send_sgi(1 << host, KICK_SGI));
    let lines: Vec<Arc<AtomicBool>> = (0..ncpus).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let (l, c) = (lines.clone(), cpus.clone());
    let gic = Arc::new(VirtualGicV2::with_cpus(ncpus, 64, move |cpu, level| {
        l[cpu].store(level, Ordering::Release);
        if level {
            c.kick(cpu);
        }
    }));
    let g = gic.clone();
    let uart = Arc::new(Pl011::new(guest_console()).with_irq(move |level| g.set_level(32 + UART_SPI, level)));
    let buses = (0..ncpus)
        .map(|cpu| {
            let bus = Bus::new();
            bus.insert(GICD, GIC_WINDOW, gic.distributor_for(cpu)).unwrap();
            bus.insert(GICC, GIC_WINDOW, gic.cpu_interface_for(cpu)).unwrap();
            bus.insert(UART, PL011_WINDOW, uart.clone()).unwrap();
            bus
        })
        .collect();
    // The boot CPU starts with x0 = the device tree.
    cpus.request_start(0, elf.entry(), GUEST_RAM).unwrap();

    let vm =
        KernelVm { cpus, vttbr, buses, lines, gic, done: AtomicBool::new(false), running: AtomicUsize::new(ncpus) };
    KERNEL_VM.store(&raw const vm as *mut KernelVm, Ordering::Release);
    let exit = vcpu_loop(&vm, 0);
    while vm.running.load(Ordering::Acquire) > 0 {
        core::hint::spin_loop();
    }
    KERNEL_VM.store(core::ptr::null_mut(), Ordering::Release);
    match exit {
        Some(e) => println!("[hyp]   guest exit {e:?} from vCPU 0"),
        None => println!("[hyp]   guest ended by another vCPU"),
    }
}
