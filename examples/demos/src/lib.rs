//! Scheduler demos shared by the example kernels. Each prints one line that
//! `scripts/check.sh` looks for.
#![no_std]

extern crate alloc;

pub mod user;

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

/// Enumerates every device on `shared`'s root ports, then drives what it
/// recognises: a mass-storage device gets a block written and read back
/// while a keyboard's interrupt transfer is outstanding, which checks that
/// the two drivers can share the controller, and is then mounted as FAT32
/// (see [`fat`]).
pub fn usb<H: osmium::hal::usb::UsbHost + Send + 'static>(shared: &'static osmium::sync::SpinLock<H>) {
    use osmium::drivers::usb::hid::BootKeyboard;
    use osmium::drivers::usb::storage::UsbStorage;
    use osmium::hal::block::BlockDevice;
    use osmium::hal::usb::{Descriptor, Descriptors, UsbHost, enumerate};

    let mut host = shared;
    let mut found = Vec::new();
    for port in 1..=host.num_ports() {
        let status = host.port_status(port);
        if !status.connected {
            continue;
        }
        let mut config = alloc::vec![0u8; 512];
        let dev = match enumerate(&mut host, port, &mut config) {
            Ok(dev) => dev,
            Err(e) => {
                println!("[usb]   port {port}: enumeration failed: {e}");
                continue;
            }
        };
        let d = dev.device;
        println!(
            "[usb]   port {port}: {:04x}:{:04x} {:?}-speed, {} interface(s)",
            d.vendor_id,
            d.product_id,
            status.speed.unwrap(),
            dev.config.num_interfaces
        );
        for desc in Descriptors::new(&config[..dev.config_len]).flatten() {
            if let Descriptor::Interface(i) = desc
                && i.alternate == 0
            {
                println!("[usb]     interface {}: class {:02x}/{:02x}/{:02x}", i.number, i.class, i.subclass, i.protocol);
            }
        }
        config.truncate(dev.config_len);
        found.push((dev.id, config));
    }

    // Both drivers hold the controller through its lock.
    let mut keyboard = None;
    for (id, config) in &found {
        if let Ok(mut kb) = BootKeyboard::new(shared, *id, config) {
            // Starts the interrupt transfer that stays outstanding below.
            match kb.poll() {
                Ok(_) => println!("[usb]     boot keyboard ready"),
                Err(e) => println!("[usb]     keyboard poll failed: {e}"),
            }
            keyboard = Some(kb);
        }
    }
    for (id, config) in &found {
        let Ok(mut disk) = UsbStorage::new(shared, *id, config) else { continue };
        if let Ok(inq) = disk.inquiry() {
            println!("[usb]     mass storage: INQUIRY \"{}\" \"{}\"", inq.vendor(), inq.product());
        }
        let (bs, n) = (disk.block_size(), disk.num_blocks());
        println!("[usb]     disk: {n} blocks of {bs} bytes");
        let lba = n - 1;
        let pattern: Vec<u8> = (0..bs).map(|i| (i * 7 + 3) as u8).collect();
        let mut back = alloc::vec![0u8; bs];
        let ok = disk.write_blocks(lba, &pattern).and_then(|_| disk.flush()).and_then(|_| disk.read_blocks(lba, &mut back));
        match ok {
            Ok(()) if back == pattern => println!("[usb]     disk: wrote and read back block {lba}"),
            Ok(()) => println!("[usb]     disk: block {lba} read back wrong"),
            Err(e) => println!("[usb]     disk: I/O failed: {e:?}"),
        }
        fat(disk);
    }
    if let Some(kb) = &mut keyboard {
        match kb.poll() {
            Ok(None) => println!("[usb]     keyboard transfer still pending after disk I/O"),
            Ok(Some(ev)) => println!("[usb]     key event {ev:?}"),
            Err(e) => println!("[usb]     keyboard poll failed: {e}"),
        }
    }
}

/// Mounts `disk` as FAT32, then creates `/osmium/Hello from osmium.txt`
/// (a long name), writes it, reads it back and syncs, leaving the file for
/// the host to check with `fsck.fat`.
pub fn fat<D: osmium::hal::block::BlockDevice + Send + 'static>(disk: D) {
    use osmium::fs::{Errno, OpenFlags, Vfs};
    use osmium::fs_fat::FatFs;

    let fs = match FatFs::mount(disk, 1) {
        Ok(fs) => fs,
        Err(e) => return println!("[fat]   not mounted: {e}"),
    };
    let free = fs.free_bytes().map_or(0, |b| b >> 20);
    let vfs = Vfs::new(fs.root());
    println!("[fat]   mounted FAT32, {free} MiB free");
    let result = (|| {
        match vfs.mkdir("/osmium", 0o755) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
        let path = "/osmium/Hello from osmium.txt";
        let text = b"Written by osmium over xHCI, USB mass storage and FAT32.\n";
        let flags = OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC;
        let f = vfs.open(path, flags, 0o644)?;
        f.write(0, text)?;
        let mut back = [0u8; 64];
        let n = f.read(0, &mut back)?;
        f.sync()?;
        Ok((path, n == text.len() && back[..n] == text[..]))
    })();
    match result {
        Ok((path, true)) => println!("[fat]   wrote and read back \"{path}\""),
        Ok((path, false)) => println!("[fat]   {path} read back wrong"),
        Err(e) => println!("[fat]   failed: {e}"),
    }
}

/// Writes a pattern to the middle sector of `disk`, flushes, reads it back
/// and returns the sector number if the data matched.
pub fn block_roundtrip<D: osmium::hal::block::BlockDevice>(disk: &mut D) -> Result<u64, osmium::hal::block::BlockError> {
    let bs = disk.block_size();
    let lba = disk.num_blocks() / 2;
    let pattern: Vec<u8> = (0..bs).map(|i| (i * 13 + 5) as u8).collect();
    let mut back = alloc::vec![0u8; bs];
    disk.write_blocks(lba, &pattern)?;
    disk.flush()?;
    disk.read_blocks(lba, &mut back)?;
    if back == pattern { Ok(lba) } else { Err(osmium::hal::block::BlockError::Io) }
}
