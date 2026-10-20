//! Scheduler demos shared by the example kernels. Each prints one line that
//! `scripts/check.sh` looks for.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium::hal::println;
use osmium::sched::timer::TimerQueue;
use osmium::sched::{Mutex, TaskBuilder};

/// What the demos need from the kernel.
pub struct Env {
    /// Timer callbacks, processed from the timer interrupt.
    pub timers: &'static TimerQueue,
    /// Timer interrupts so far.
    pub ticks: &'static AtomicU64,
    /// Monotonic time in nanoseconds.
    pub now_ns: fn() -> u64,
}

/// Runs every demo in turn.
pub fn run_all(env: &Env) {
    cooperative();
    mutex();
    preemption(env);
    sleep(env);
}

/// Tasks that yield to each other interleave in FIFO order.
pub fn cooperative() {
    let tasks: Vec<_> = ["A", "B", "C"]
        .into_iter()
        .map(|name| {
            TaskBuilder::new(name).spawn(move || {
                for i in 0..2 {
                    println!("[task]  {name}{i}");
                    osmium::sched::yield_now();
                }
            })
        })
        .collect();
    for t in tasks {
        t.join();
    }
}

/// A sleeping mutex keeps its data consistent across yields.
pub fn mutex() {
    static COUNTER: Mutex<u64> = Mutex::new(0);
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            TaskBuilder::new("adder").spawn(|| {
                for _ in 0..1000 {
                    let mut g = COUNTER.lock();
                    let v = *g;
                    osmium::sched::yield_now();
                    *g = v + 1;
                }
            })
        })
        .collect();
    for t in tasks {
        t.join();
    }
    println!("[mutex] 4 tasks x 1000 increments across yields = {}", *COUNTER.lock());
}

/// A task that never yields is preempted by the timer interrupt; otherwise
/// the task it waits for could never run on this CPU.
pub fn preemption(env: &Env) {
    static FLAG: AtomicBool = AtomicBool::new(false);
    let start = env.ticks.load(Ordering::Relaxed);
    let cpu = osmium::arch::cpu::current_id();
    let spinner = TaskBuilder::new("spinner").cpu(cpu).spawn(|| {
        while !FLAG.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    });
    let setter = TaskBuilder::new("setter").cpu(cpu).spawn(|| FLAG.store(true, Ordering::Release));
    spinner.join();
    setter.join();
    println!("[preempt] busy-looping task was preempted after {} ticks", env.ticks.load(Ordering::Relaxed) - start);
}

/// A task sleeps on the timer queue.
pub fn sleep(env: &Env) {
    let (timers, now_ns) = (env.timers, env.now_ns);
    let t = TaskBuilder::new("sleeper").spawn(move || {
        let t0 = now_ns();
        timers.sleep_until(t0 + 50_000_000);
        println!("[timer] slept {} ms (asked for 50)", (now_ns() - t0) / 1_000_000);
    });
    t.join();
}

/// Work spread over `ncpus` CPUs: tasks pinned to every CPU contend for one
/// sleeping mutex (so wake-ups cross CPUs), and one task migrates through
/// all of them.
pub fn smp(ncpus: usize) {
    use core::sync::atomic::AtomicUsize;
    use osmium::arch::cpu;

    static TOTAL: Mutex<u64> = Mutex::new(0);
    static SEEN: AtomicUsize = AtomicUsize::new(0);
    let workers: Vec<_> = (0..ncpus * 2)
        .map(|i| {
            TaskBuilder::new("worker").cpu(i % ncpus).spawn(|| {
                for _ in 0..250 {
                    let mut g = TOTAL.lock();
                    SEEN.fetch_or(1 << cpu::current_id(), Ordering::Relaxed);
                    let v = *g;
                    osmium::sched::yield_now();
                    *g = v + 1;
                }
            })
        })
        .collect();
    for w in workers {
        w.join();
    }
    println!(
        "[smp]   {} tasks on {ncpus} CPUs (ran on mask {:#b}), mutex total {}",
        ncpus * 2,
        SEEN.load(Ordering::Relaxed),
        *TOTAL.lock()
    );

    let path = alloc::sync::Arc::new(osmium::sync::IrqSpinLock::new(Vec::new()));
    let p = path.clone();
    let hopper = TaskBuilder::new("hopper").spawn(move || {
        for _ in 0..=ncpus {
            let here = cpu::current_id();
            p.lock().push(here);
            osmium::sched::current().set_cpu((here + 1) % ncpus);
            osmium::sched::yield_now();
        }
    });
    hopper.join();
    println!("[smp]   migrating task visited CPUs {:?}", *path.lock());
}

/// Resolves the QEMU user-mode network's gateway (10.0.2.2) with ARP,
/// proving that `dev` can both transmit and receive. Gives up after a second.
pub fn arp(dev: &mut impl osmium::hal::net::NetDevice, now_ns: fn() -> u64) {
    const ME: [u8; 4] = [10, 0, 2, 15];
    const GATEWAY: [u8; 4] = [10, 0, 2, 2];
    let mac = dev.mac_address();
    let mut req = [0u8; 42];
    req[0..6].copy_from_slice(&[0xff; 6]);
    req[6..12].copy_from_slice(&mac.0);
    req[12..14].copy_from_slice(&[0x08, 0x06]); // ARP
    req[14..22].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]); // Ethernet/IPv4, request
    req[22..28].copy_from_slice(&mac.0);
    req[28..32].copy_from_slice(&ME);
    req[38..42].copy_from_slice(&GATEWAY);
    println!("[net]   {mac}, link {}", if dev.link_up() { "up" } else { "down" });
    dev.transmit(&req).expect("transmit failed");

    let deadline = now_ns() + 1_000_000_000;
    let mut frame = [0u8; 1514];
    while now_ns() < deadline {
        let Ok(n) = dev.receive(&mut frame) else { continue };
        let f = &frame[..n];
        if n >= 42 && f[12..14] == [0x08, 0x06] && f[20..22] == [0, 2] && f[28..32] == GATEWAY {
            let gw = osmium::hal::net::MacAddress(f[22..28].try_into().unwrap());
            println!("[net]   ARP: {}.{}.{}.{} is at {gw}", GATEWAY[0], GATEWAY[1], GATEWAY[2], GATEWAY[3]);
            return;
        }
    }
    println!("[net]   no ARP reply");
}

/// Enumerates every device on `host`'s root ports and prints what it finds.
/// A mass-storage stick is also asked for its SCSI INQUIRY data, which
/// exercises bulk transfers in both directions.
pub fn usb(host: &mut impl osmium::hal::usb::UsbHost) {
    use osmium::hal::usb::{Descriptor, Descriptors, Direction, TransferType, enumerate};
    for port in 1..=host.num_ports() {
        let status = host.port_status(port);
        if !status.connected {
            continue;
        }
        let mut config = [0u8; 256];
        let dev = match enumerate(host, port, &mut config) {
            Ok(dev) => dev,
            Err(e) => {
                println!("[usb]   port {port}: enumeration failed: {e}");
                continue;
            }
        };
        let d = dev.device;
        println!("[usb]   port {port}: {:04x}:{:04x} {:?}-speed, {} interface(s)", d.vendor_id, d.product_id,
            status.speed.unwrap(), dev.config.num_interfaces);

        let (mut class, mut bulk_in, mut bulk_out) = (None, None, None);
        for desc in Descriptors::new(&config[..dev.config_len]).flatten() {
            match desc {
                Descriptor::Interface(i) if i.alternate == 0 => {
                    println!("[usb]     interface {}: class {:02x}/{:02x}/{:02x}", i.number, i.class, i.subclass, i.protocol);
                    class = Some((i.class, i.subclass, i.protocol));
                }
                Descriptor::Endpoint(e) if class == Some((8, 6, 0x50)) && e.transfer_type() == TransferType::Bulk => {
                    match e.direction() {
                        Direction::In => bulk_in = Some(e.address),
                        Direction::Out => bulk_out = Some(e.address),
                    }
                }
                _ => {}
            }
        }
        if let (Some(i), Some(o)) = (bulk_in, bulk_out) {
            match inquiry(host, dev.id, i, o) {
                Ok((vendor, product)) => println!("[usb]     mass storage: INQUIRY \"{vendor}\" \"{product}\""),
                Err(e) => println!("[usb]     mass storage: INQUIRY failed: {e}"),
            }
        }
    }
}

/// SCSI INQUIRY over USB Bulk-Only Transport; returns the vendor and
/// product strings.
fn inquiry(
    host: &mut impl osmium::hal::usb::UsbHost,
    dev: osmium::hal::usb::DeviceId,
    bulk_in: u8,
    bulk_out: u8,
) -> Result<(alloc::string::String, alloc::string::String), osmium::hal::usb::UsbError> {
    use osmium::hal::usb::UsbError;
    const LEN: u32 = 36;
    let mut cbw = [0u8; 31];
    cbw[0..4].copy_from_slice(b"USBC");
    cbw[4..8].copy_from_slice(&0x0511_u32.to_le_bytes()); // tag
    cbw[8..12].copy_from_slice(&LEN.to_le_bytes());
    cbw[12] = 0x80; // data in
    cbw[14] = 6; // command length
    cbw[15..21].copy_from_slice(&[0x12, 0, 0, 0, LEN as u8, 0]); // INQUIRY
    host.transfer_out(dev, bulk_out, &cbw)?;
    let mut data = [0u8; LEN as usize];
    let n = host.transfer_in(dev, bulk_in, &mut data)?;
    let mut csw = [0u8; 13];
    let m = host.transfer_in(dev, bulk_in, &mut csw)?;
    if n < 32 || m != 13 || &csw[0..4] != b"USBS" || csw[4..8] != cbw[4..8] || csw[12] != 0 {
        return Err(UsbError::Transaction);
    }
    let text = |b: &[u8]| alloc::string::String::from_utf8_lossy(b).trim_end().into();
    Ok((text(&data[8..16]), text(&data[16..32])))
}
