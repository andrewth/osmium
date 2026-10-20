//! Booting a whole guest kernel the PVH way: an ELF image QEMU's loader
//! places in host RAM (`-device loader,file=...,addr=0x18000000,force-raw=on`)
//! entered at its `XEN_ELFNOTE_PHYS32_ENTRY` with `ebx` = an
//! `hvm_start_info`, one vCPU per host CPU, ACPI tables listing their local
//! APICs and an I/O APIC, COM1, the PIT (with port 0x61) and QEMU's power-off
//! ports. Its console lines are printed with a `| ` prefix.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use osmium::boot::elf::Elf;
use osmium::hal::println;
use osmium::mm::paging::formats::X86_64;
use osmium::mm::{FrameAllocator, MapFlags, PAGE_SIZE, PageTable, PhysAddr, VirtAddr};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::devices::{
    IOAPIC_WINDOW, IpiKind, IpiTarget, LAPIC_WINDOW, Uart16550 as Uart16550Model, VirtualIoApic, VirtualLapic,
    VirtualPit, decode_icr,
};
use osmium::virt::smp::GuestCpus;
use osmium::virt::x86::pc::{PcBoot, pvh_entry};
use osmium::virt::x86::{SvmPages, SvmVcpu};
use osmium::virt::{Bus, BusDevice, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

use crate::{FRAMES, Frames, HOST_APIC_IDS, KICK_VECTOR, LAPIC, block, clock};

/// Where QEMU's loader puts the guest kernel, and the window kept free for it.
pub const IMAGE_BASE: u64 = 0x1800_0000;
pub const IMAGE_WINDOW: u64 = 0x0800_0000;

const GUEST_RAM_ORDER: u32 = 14; // 64 MiB at 0
/// The PVH start info and ACPI tables, in the guest's first page above 0.
const BOOT_INFO: u64 = 0x1000;
const LAPIC_BASE: u64 = 0xfee0_0000;
const IOAPIC_BASE: u64 = 0xfec0_0000;
const COM1_GSI: u32 = 4;
/// The emulated local APIC timers' input clock.
const LAPIC_HZ: u64 = 100_000_000;
const MAX_CPUS: usize = 2;
/// The host's own local APIC timer, which makes a busy guest exit so its
/// virtual timers are delivered on time: vector and period.
pub const HOST_TICK_VECTOR: u8 = 0xef;
const HOST_TICK_NS: u64 = 1_000_000;
static HOST_TICK_COUNT: AtomicU32 = AtomicU32::new(0);

/// A guest shared by every host CPU, each running one of its vCPUs.
pub struct KernelVm {
    cpus: Arc<GuestCpus>,
    mem: Arc<GuestMemory>,
    ncr3: u64,
    pio: Bus,
    buses: Vec<Bus>,
    lines: Vec<Arc<AtomicBool>>,
    apics: Arc<[Once<Arc<VirtualLapic>>; MAX_CPUS]>,
    pit: Arc<VirtualPit>,
    com1: Arc<Uart16550Model>,
    done: Arc<AtomicBool>,
    running: AtomicUsize,
}

pub static KERNEL_VM: AtomicPtr<KernelVm> = AtomicPtr::new(core::ptr::null_mut());

/// The guest image QEMU's loader left in the window, if any.
pub fn image() -> Option<(Elf<'static>, u32)> {
    // SAFETY: the caller reserved the window (RAM the loader filled or left zero).
    let window = unsafe { core::slice::from_raw_parts(IMAGE_BASE as *const u8, IMAGE_WINDOW as usize) };
    let elf = Elf::new(window).ok()?;
    let entry = pvh_entry(&window[..0x10_0000])?;
    Some((elf, entry))
}

/// QEMU's power-off ports (ACPI PM1a control at 0x604, isa-debug-exit at
/// 0xf4): any write ends the guest.
struct PowerOff(Arc<AtomicBool>);

/// Set when the guest powered itself off (as opposed to a vCPU failing).
static POWERED_OFF: AtomicBool = AtomicBool::new(false);

impl BusDevice for PowerOff {
    fn read(&self, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }
    fn write(&self, _offset: u64, _data: &[u8]) {
        POWERED_OFF.store(true, Ordering::Release);
        self.0.store(true, Ordering::Release);
    }
}

/// Set when the guest says it listens on COM1: the next halt types a line.
static TYPE_NOW: AtomicBool = AtomicBool::new(false);
const TYPED: &[u8] = b"hello from the host\n";

/// The guest's console: whole lines, prefixed so they stand apart from the host's.
fn guest_console() -> impl Fn(u8) + Send + Sync + 'static {
    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    move |b| {
        let mut l = line.lock();
        match b {
            b'\n' => {
                let s = core::str::from_utf8(&l).unwrap_or("?");
                // x86_64-pc's serial demo routes COM1 and waits for a line.
                if s.contains("COM1 IRQ 4 ->") {
                    TYPE_NOW.store(true, Ordering::Release);
                }
                println!("| {s}");
                l.clear();
            }
            b'\r' => {}
            _ => l.push(b),
        }
    }
}

/// Starts this host CPU's 1 ms local APIC tick (calibrated by `boot`).
pub fn start_host_tick() {
    let count = HOST_TICK_COUNT.load(Ordering::Relaxed);
    if count != 0 {
        LAPIC.get().unwrap().start_timer(HOST_TICK_VECTOR, count, true);
    }
}

/// Runs vCPU `me` on this host CPU each time the guest starts it, until
/// the guest is done.
pub fn vcpu_loop(vm: &KernelVm, me: usize) -> Option<VmExit> {
    start_host_tick();
    let mut last = None;
    while !vm.done.load(Ordering::Acquire) {
        let Some((entry, info)) = vm.cpus.take_start(me) else {
            core::hint::spin_loop();
            continue;
        };
        let (vmcb, iopm, msrpm, host) = (block(0), block(2), block(1), block(0));
        // SAFETY: fresh blocks of at least the required sizes, owned by the vCPU.
        let mut v = unsafe { SvmVcpu::new(SvmPages { vmcb, iopm, msrpm, host }, vm.ncr3, entry as u32, 0) }
            .with_memory(vm.mem.clone())
            .with_irq_line(vm.lines[me].clone());
        v.set_apic_id(me as u8); // CPUID agrees with the vCPU's APIC
        if me == 0 {
            v.regs.rbx = info; // PVH: ebx = hvm_start_info
        } else {
            v.set_real_mode((entry >> 12) as u8); // started by STARTUP
            v.set_application_processor();
        }
        let apic = vm.apics[me].get().unwrap().clone();
        let a = apic.clone();
        v.connect_intr(move || a.acknowledge());
        vm.cpus.attach_svm(me, &mut v);
        let poll = |vm: &KernelVm| {
            apic.poll();
            if me == 0 {
                vm.pit.poll();
            }
        };
        let exit = run_vcpu(&mut v, &vm.buses[me], &vm.pio, |v, exit| {
            if vm.done.load(Ordering::Acquire) {
                return ControlFlow::Break(VmExit::Shutdown);
            }
            match exit {
                VmExit::Halt => loop {
                    if TYPE_NOW.swap(false, Ordering::AcqRel) {
                        TYPED.iter().for_each(|&b| vm.com1.push_input(b));
                    }
                    // Idle in hlt: wait for an interrupt, polling the timers.
                    poll(vm);
                    if v.interrupt_pending() {
                        break ControlFlow::Continue(());
                    }
                    if vm.done.load(Ordering::Acquire) {
                        break ControlFlow::Break(VmExit::Shutdown);
                    }
                    core::hint::spin_loop();
                },
                // The host tick or a kick: deliver what is now due.
                VmExit::ExternalInterrupt => {
                    poll(vm);
                    ControlFlow::Continue(())
                }
                other => ControlFlow::Break(other),
            }
        });
        if !vm.done.load(Ordering::Acquire) {
            use osmium::virt::x86::vmcb;
            println!(
                "[hyp]   vCPU {me}: {exit:?} at rip {:#x}, info1 {:#x}, info2 {:#x}, cr3 {:#x}",
                v.rip(),
                v.read64(vmcb::EXITINFO1),
                v.read64(vmcb::EXITINFO2),
                v.read64(vmcb::CR3)
            );
        }
        drop(v);
        // SAFETY: the vCPU that owned these blocks is gone.
        unsafe {
            let mut f = FRAMES.lock();
            f.dealloc(PhysAddr::new(vmcb.1), 0);
            f.dealloc(PhysAddr::new(iopm.1), 2);
            f.dealloc(PhysAddr::new(msrpm.1), 1);
            f.dealloc(PhysAddr::new(host.1), 0);
        }
        if !vm.done.swap(true, Ordering::AcqRel) {
            for i in 0..vm.lines.len() {
                vm.cpus.kick(i);
            }
            if exit != VmExit::Shutdown {
                println!("[hyp]   vCPU {me} stopped the guest: {exit:?}");
            }
            last = Some(exit);
        }
    }
    LAPIC.get().unwrap().stop_timer();
    vm.running.fetch_sub(1, Ordering::AcqRel);
    last
}

/// Loads `elf` into fresh guest RAM and runs it, entered at `entry`, with
/// one vCPU per host CPU until it powers off.
pub fn boot(elf: &Elf<'_>, entry: u32, ncpus: usize) {
    let ncpus = ncpus.min(MAX_CPUS);
    // The host tick: calibrate this CPU's local APIC timer against the PIT.
    let lapic = LAPIC.get().unwrap();
    lapic.start_timer(HOST_TICK_VECTOR, u32::MAX, false);
    // SAFETY: nothing else uses the host's PIT.
    let pit = osmium::drivers::pit::Pit::new(unsafe { osmium::drivers::pit::Pio::new() });
    let hz = pit.calibrate(10_000_000, || u32::MAX as u64 - lapic.timer_remaining() as u64);
    lapic.stop_timer();
    HOST_TICK_COUNT.store((hz * HOST_TICK_NS / 1_000_000_000).max(1) as u32, Ordering::Relaxed);

    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by the guest for the rest of the run.
    unsafe { mem.add_region(GuestPhysAddr(0), ram.0 as *mut u8, len) };
    // The image is linked where it runs: physical = virtual.
    let image = match mem.load_elf(elf) {
        Ok(r) => r,
        Err(e) => {
            println!("[hyp]   the guest kernel does not fit its RAM ({e:?})");
            return;
        }
    };
    let kib = (image.end - image.start) >> 10;
    println!("[hyp]   guest kernel: {kib} KiB loaded, PVH entry {entry:#x}, {ncpus} vCPUs");
    let blob = PcBoot {
        cpus: ncpus as u32,
        memory: &[(0, 0xa_0000), (0x10_0000, len - 0x10_0000)],
        ioapic: Some((ncpus as u8, IOAPIC_BASE as u32)),
        cmdline: "",
    }
    .build(BOOT_INFO);
    if image.start < BOOT_INFO + blob.bytes.len() as u64 && BOOT_INFO < image.end {
        println!("[hyp]   the guest kernel overlaps its boot information at {BOOT_INFO:#x}");
        return;
    }
    mem.write(GuestPhysAddr(BOOT_INFO), &blob.bytes).unwrap();
    let mem = Arc::new(mem);

    let mut npt: PageTable<X86_64, &'static Frames> = PageTable::new(&FRAMES).expect("NPT root");
    let flags = MapFlags::RW | MapFlags::EXEC | MapFlags::USER;
    npt.map_range(VirtAddr::new(0), PhysAddr::new(ram.0), len, flags).unwrap();
    let ncr3 = npt.root().0;
    core::mem::forget(npt); // in use until power-off

    let done = Arc::new(AtomicBool::new(false));
    let cpus = GuestCpus::with_kick(ncpus, |host| {
        LAPIC.get().unwrap().send_ipi(HOST_APIC_IDS[host].load(Ordering::Relaxed), KICK_VECTOR);
    });
    // Interrupt routing: COM1 -> I/O APIC -> the destination's local APIC.
    let apics: Arc<[Once<Arc<VirtualLapic>>; MAX_CPUS]> = Arc::new([const { Once::new() }; MAX_CPUS]);
    let deliver = |apics: &Weak<[Once<Arc<VirtualLapic>>; MAX_CPUS]>, cpus: &GuestCpus, n: usize, v: u8| {
        if let Some(apic) = apics.upgrade().and_then(|a| a.get(n).and_then(|o| o.get()).cloned()) {
            apic.deliver(v);
            cpus.kick(n);
        }
    };
    let (a, c) = (Arc::downgrade(&apics), cpus.clone());
    let ioapic = Arc::new(VirtualIoApic::new(ncpus as u8, move |m| {
        if m.mode == 0 {
            deliver(&a, &c, m.dest as usize, m.vector);
        }
    }));
    let lines: Vec<Arc<AtomicBool>> = (0..ncpus).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let mut buses = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let (l, c, a, io) = (l.clone(), cpus.clone(), Arc::downgrade(&apics), ioapic.clone());
        let apic = VirtualLapic::new(i as u8, LAPIC_HZ, clock(), move |level| l.store(level, Ordering::Release))
            .with_eoi(move |v| io.eoi(v))
            .with_ipi(move |high, low| {
                let (target, kind) = decode_icr(high, low);
                let targets: Vec<usize> = match target {
                    IpiTarget::Apic(n) => alloc::vec![n as usize],
                    IpiTarget::All | IpiTarget::AllButSelf => (0..ncpus).filter(|&n| n != i).collect(),
                };
                for n in targets {
                    match kind {
                        IpiKind::Startup(page) => {
                            let _ = c.request_start(n, (page as u64) << 12, 0);
                        }
                        IpiKind::Fixed(v) => deliver(&a, &c, n, v),
                        _ => {} // INIT: the target is already waiting for STARTUP
                    }
                }
            });
        let apic = apics[i].call_once(|| Arc::new(apic)).clone();
        let mmio = Bus::new();
        mmio.insert(LAPIC_BASE, LAPIC_WINDOW, apic).unwrap();
        mmio.insert(IOAPIC_BASE, IOAPIC_WINDOW, ioapic.clone()).unwrap();
        buses.push(mmio);
    }
    let pio = Bus::new();
    let io = ioapic.clone();
    let com1 = Arc::new(Uart16550Model::new(guest_console()).with_irq(move |level| io.set_level(COM1_GSI, level)));
    pio.insert(0x3f8, 8, com1.clone()).unwrap();
    let pit = Arc::new(VirtualPit::new(clock(), |_| {}));
    pio.insert(0x40, 4, pit.clone()).unwrap();
    pio.insert(0x61, 1, pit.port_b()).unwrap();
    pio.insert(0x604, 2, Arc::new(PowerOff(done.clone()))).unwrap();
    pio.insert(0xf4, 1, Arc::new(PowerOff(done.clone()))).unwrap();

    cpus.request_start(0, entry as u64, blob.start_info).unwrap();
    let vm = KernelVm { cpus, mem, ncr3, pio, buses, lines, apics, pit, com1, done, running: AtomicUsize::new(ncpus) };
    KERNEL_VM.store(&raw const vm as *mut KernelVm, Ordering::Release);
    let exit = vcpu_loop(&vm, 0);
    while vm.running.load(Ordering::Acquire) > 0 {
        core::hint::spin_loop();
    }
    KERNEL_VM.store(core::ptr::null_mut(), Ordering::Release);
    match exit {
        _ if POWERED_OFF.load(Ordering::Acquire) => println!("[hyp]   guest powered off"),
        Some(e) => println!("[hyp]   guest exit {e:?} from vCPU 0"),
        None => println!("[hyp]   guest stopped by vCPU 1 (see above)"),
    }
}
