//! The interpreter's budgets cover the work and the memory inside a term, not only the number of terms:
//! hostile AML that makes each term allocate megabytes or touch a register a hundred thousand times must
//! still stop within the configured limits. These tests count the bytes the heap hands out (with a counting
//! global allocator) and the accesses the host sees.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use common::table;
use osmium_acpi::aml::{AmlError, Config, Host, HostError, Interpreter, Value};

// ----- counting what the heap hands out, per thread -----

struct Counting;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
    static TOTAL: Cell<usize> = const { Cell::new(0) };
}

fn note(delta: isize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + delta;
        live.set(now);
        let _ = PEAK.try_with(|p| p.set(p.get().max(now)));
    });
    if delta > 0 {
        let _ = TOTAL.try_with(|t| t.set(t.get() + delta as usize));
    }
}

// SAFETY: every call is passed straight to `System`, which upholds the `GlobalAlloc` contract; the
// bookkeeping only touches const-initialized thread locals, which never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's obligations for `alloc` are the same as `System.alloc`'s.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            note(layout.size() as isize);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` or `realloc` above with this layout, as the caller guarantees.
        unsafe { System.dealloc(ptr, layout) };
        note(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's obligations for `realloc` are the same as `System.realloc`'s.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            note(new_size as isize - layout.size() as isize);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// What `f` did to this thread's heap: the most it held at once above where it started, and the total it
/// asked for.
struct HeapUse {
    peak: usize,
    total: usize,
    /// What it still held when it returned (including what it returned).
    held: usize,
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, HeapUse) {
    let start = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(start));
    let total = TOTAL.with(Cell::get);
    let r = f();
    let peak = (PEAK.with(Cell::get) - start).max(0) as usize;
    let held = (LIVE.with(Cell::get) - start).max(0) as usize;
    (r, HeapUse { peak, total: TOTAL.with(Cell::get) - total, held })
}

const MIB: usize = 1 << 20;

// ----- a host that counts accesses and keeps nothing -----

#[derive(Default)]
struct CountingHost {
    reads: u64,
    writes: u64,
}

impl Host for CountingHost {
    fn read_memory(&mut self, _addr: u64, _bits: u8) -> Result<u64, HostError> {
        self.reads += 1;
        Ok(0)
    }

    fn write_memory(&mut self, _addr: u64, _bits: u8, _value: u64) -> Result<(), HostError> {
        self.writes += 1;
        Ok(())
    }
}

// ----- AML -----

fn pkg_len(body: usize) -> Vec<u8> {
    for n in 1..=3usize {
        let total = body + n;
        let ok = if n == 1 { total < 0x40 } else { total < 1 << (4 + 8 * (n - 1)) };
        if ok {
            if n == 1 {
                return vec![total as u8];
            }
            let mut v = vec![((n - 1) as u8) << 6 | (total & 0xf) as u8];
            for i in 0..n - 1 {
                v.push((total >> (4 + 8 * i)) as u8);
            }
            return v;
        }
    }
    panic!("body too long for a 3-byte PkgLength")
}

fn with_len(op: &[u8], body: &[u8]) -> Vec<u8> {
    [op, &pkg_len(body.len()), body].concat()
}

fn method(name: &[u8; 4], args: u8, body: &[u8]) -> Vec<u8> {
    with_len(&[0x14], &[&name[..], &[args], body].concat())
}

fn forever(body: &[u8]) -> Vec<u8> {
    with_len(&[0xA2], &[&[ONE][..], body].concat())
}

fn dsdt(items: &[Vec<u8>]) -> Vec<u8> {
    table(b"DSDT", 2, &items.concat())
}

fn interpreter<H: Host>(host: H, config: Config, items: &[Vec<u8>]) -> Interpreter<H> {
    let mut aml = Interpreter::new(host, config);
    aml.load_table(&dsdt(items)).expect("loads");
    aml
}

const ZERO: u8 = 0x00;
const ONE: u8 = 0x01;
const RETURN: u8 = 0xA4;

/// `VarPackage (0xFFFF) {}`: 7 bytes of AML for a package of 65535 elements.
fn big_package() -> Vec<u8> {
    with_len(&[0x13], &[0x0B, 0xFF, 0xFF])
}

// ----- memory -----

#[test]
fn a_loop_that_keeps_huge_packages_alive_stops_at_the_memory_budget() {
    // While (One) { RefOf (VarPackage (0xFFFF) {}) }: each RefOf keeps its package alive in a nameless
    // object until the method returns, 2 MiB per seven bytes of AML.
    let body = forever(&[&[0x71][..], &big_package()].concat());
    for budget in [8 * MIB, 64 * MIB] {
        let config = Config { max_alloc_bytes: budget as u64, ..Config::default() };
        let mut aml = interpreter(CountingHost::default(), config, &[method(b"HOLD", 0, &body)]);
        let (r, heap) = measure(|| aml.evaluate("\\HOLD", &[]));
        assert_eq!(r, Err(AmlError::OutOfMemory));
        assert!(heap.peak <= budget + 4 * MIB, "held {} MiB with a {} MiB budget", heap.peak / MIB, budget / MIB);
    }
}

#[test]
fn a_huge_package_stored_over_and_over_is_charged_each_time() {
    // Local0 = VarPackage (0xFFFF) {}; While (One) { Local1 = Local0 }: every copy is 2 MiB of allocation.
    let init = [&[0x70][..], &big_package(), &[0x60]].concat();
    let body = [init, forever(&[0x70, 0x60, 0x61])].concat();
    let config = Config { max_alloc_bytes: 16 * MIB as u64, max_steps: u64::MAX, ..Config::default() };
    let mut aml = interpreter(CountingHost::default(), config, &[method(b"COPY", 0, &body)]);
    let (r, heap) = measure(|| aml.evaluate("\\COPY", &[]));
    assert_eq!(r, Err(AmlError::OutOfMemory));
    assert!(heap.total <= 20 * MIB, "allocated {} MiB with a 16 MiB budget", heap.total / MIB);
}

#[test]
fn hex_strings_of_large_buffers_are_refused_before_they_are_built() {
    // Return (ToHexString (Buffer (0x100000) {})): 3 MiB of text, over the 1 MiB object limit.
    let buf = with_len(&[0x11], &[0x0C, 0x00, 0x00, 0x10, 0x00]);
    let body = [&[RETURN, 0x98][..], &buf, &[ZERO]].concat();
    let mut aml = interpreter(CountingHost::default(), Config::default(), &[method(b"HEX_", 0, &body)]);
    let (r, heap) = measure(|| aml.evaluate("\\HEX_", &[]));
    assert_eq!(r, Err(AmlError::TooLarge));
    assert!(heap.peak < 3 * MIB, "held {} KiB", heap.peak / 1024);
}

#[test]
fn the_namespace_cannot_grow_without_bound_across_calls() {
    // Name (PKG_, Package (0xFF) {}) and Method (GROW, 1) { Store (Buffer (0x100000) {}, Index (PKG_, Arg0)) }:
    // each call is well within its own budget but leaves another megabyte behind.
    let pkg = [&[0x08][..], b"PKG_", &with_len(&[0x12], &[0xFF])].concat();
    let buf = with_len(&[0x11], &[0x0C, 0x00, 0x00, 0x10, 0x00]);
    let grow = method(b"GROW", 1, &[&[0x70][..], &buf, &[0x88], b"PKG_", &[0x68, ZERO]].concat());
    let cap = 8 * MIB;
    let config = Config { max_retained_bytes: cap as u64, ..Config::default() };
    let ((aml, refused), heap) = measure(|| {
        let mut aml = interpreter(CountingHost::default(), config, &[pkg, grow]);
        let mut refused = None;
        for i in 0..64u64 {
            match aml.evaluate("\\GROW", &[Value::Integer(i)]) {
                Ok(_) => assert!(aml.namespace().retained_bytes() <= cap),
                Err(e) => {
                    refused = Some((i, e));
                    break;
                }
            }
        }
        (aml, refused)
    });
    let (i, e) = refused.expect("some call is refused");
    assert_eq!(e, AmlError::OutOfMemory);
    assert_eq!(i, 7, "the eighth megabyte goes over");
    assert!(aml.namespace().retained_bytes() <= cap);
    // What went over was dropped, so the heap holds less than the cap, not 64 MiB.
    assert!(heap.held <= cap, "the interpreter holds {} MiB", heap.held / MIB);
}

#[test]
fn reading_a_bit_of_a_large_buffer_does_not_copy_the_buffer() {
    // Name (BUF_, Buffer (0x100000) {}), CreateBitField (BUF_, 0, BIT_), and a loop reading BIT_ and
    // SizeOf (BUF_).
    let buf = [&[0x08][..], b"BUF_", &with_len(&[0x11], &[0x0C, 0x00, 0x00, 0x10, 0x00])].concat();
    let field = [&[0x8D][..], b"BUF_", &[ZERO], b"BIT_"].concat();
    let body = forever(&[&[0x70][..], b"BIT_", &[0x60, 0x70, 0x87], b"BUF_", &[0x61]].concat());
    let config = Config { max_steps: 50_000, ..Config::default() };
    let mut aml = interpreter(CountingHost::default(), config, &[buf, field, method(b"READ", 0, &body)]);
    let (r, heap) = measure(|| aml.evaluate("\\READ", &[]));
    assert_eq!(r, Err(AmlError::Timeout));
    // One megabyte for the buffer when it is first read, and little else.
    assert!(heap.total < 4 * MIB, "allocated {} MiB", heap.total / MIB);
}

// ----- work: host accesses and bits moved -----

/// `OperationRegion (RAM_, SystemMemory, 0, 0x20000)` and `Field (RAM_, ByteAcc, NoLock, Preserve)
/// { BIG_, 0x100000 }`: a field of a megabit, read a byte at a time.
fn big_field() -> Vec<Vec<u8>> {
    let region = [&[0x5B, 0x80][..], b"RAM_", &[0x00, ZERO, 0x0C, 0x00, 0x00, 0x02, 0x00]].concat();
    // The bit length 0x100000 as a 4-byte PkgLength: bits 0-3 in the lead byte, then 4-11, 12-19, 20-27.
    let field = with_len(&[0x5B, 0x81], &[&b"RAM_"[..], &[0x01], b"BIG_", &[0xC0, 0x00, 0x00, 0x01]].concat());
    vec![region, field]
}

#[test]
fn each_access_a_field_makes_counts_against_the_step_budget() {
    let steps = 100_000u64;
    let config = Config { max_steps: steps, ..Config::default() };
    // While (One) { Local0 = BIG_ }: each read is 131072 byte reads.
    let read = forever(&[&[0x70][..], b"BIG_", &[0x60]].concat());
    let mut items = big_field();
    items.push(method(b"READ", 0, &read));
    let mut aml = interpreter(CountingHost::default(), config.clone(), &items);
    assert_eq!(aml.evaluate("\\READ", &[]), Err(AmlError::Timeout));
    assert!(aml.host().reads <= steps, "{} reads within a budget of {steps} steps", aml.host().reads);

    // While (One) { BIG_ = Zero }: each write is 131072 byte writes.
    let write = forever(&[&[0x70, ZERO][..], b"BIG_"].concat());
    let mut items = big_field();
    items.push(method(b"WRIT", 0, &write));
    let mut aml = interpreter(CountingHost::default(), config, &items);
    assert_eq!(aml.evaluate("\\WRIT", &[]), Err(AmlError::Timeout));
    let host = aml.host();
    assert!(host.reads + host.writes <= steps, "{} accesses within {steps} steps", host.reads + host.writes);
}

#[test]
fn ordinary_field_and_buffer_work_still_fits_the_default_budgets() {
    // One read of the megabit field, a hex string of a 64 KiB buffer and a 1 MiB package of copies: well
    // within the defaults, so none of it is refused.
    let buf = with_len(&[0x11], &[0x0C, 0x00, 0x00, 0x01, 0x00]);
    let body = [
        &[0x70][..],
        b"BIG_",
        &[0x60],
        &[0x70, 0x98],
        &buf,
        &[ZERO, 0x61],
        &[0x70],
        &big_package(),
        &[0x62],
        &[RETURN, 0x87, 0x61],
    ]
    .concat();
    let mut items = big_field();
    items.push(method(b"OK__", 0, &body));
    let mut aml = interpreter(CountingHost::default(), Config::default(), &items);
    assert_eq!(aml.evaluate("\\OK__", &[]), Ok(Value::Integer(0x10000 * 3 - 1)));
    assert_eq!(aml.host().reads, 0x20000);
}

// ----- references that outlive what they refer to -----

#[test]
fn a_reference_to_a_returned_methods_local_is_stale() {
    // Method (LEAK) { Local0 = 5; Return (RefOf (Local0)) }
    // Method (OTHR, 1) { Local0 = 0x99; Return (DerefOf (Arg0)) }
    // Method (MAIN) { Return (OTHR (LEAK ())) }: OTHR runs at the depth LEAK ran at, so a reference that
    // named the frame by its depth would read OTHR's own Local0.
    let leak = method(b"LEAK", 0, &[0x70, 0x0A, 5, 0x60, RETURN, 0x71, 0x60]);
    let othr = method(b"OTHR", 1, &[0x70, 0x0A, 0x99, 0x60, RETURN, 0x83, 0x68]);
    let main = method(b"MAIN", 0, &[&[RETURN][..], b"OTHR", b"LEAK"].concat());
    let mut aml = interpreter(CountingHost::default(), Config::default(), &[leak, othr, main]);
    assert_eq!(aml.evaluate("\\MAIN", &[]), Err(AmlError::StaleReference));
}

#[test]
fn a_reference_passed_down_to_a_callee_still_works() {
    // Method (SET_, 1) { Arg0 = 7 } and Method (MAIN) { Local0 = 1; SET_ (RefOf (Local0)); Return (Local0) }
    let set = method(b"SET_", 1, &[0x70, 0x0A, 7, 0x68]);
    let main = method(b"MAIN", 0, &[&[0x70, ONE, 0x60][..], b"SET_", &[0x71, 0x60, RETURN, 0x60]].concat());
    let mut aml = interpreter(CountingHost::default(), Config::default(), &[set, main]);
    assert_eq!(aml.evaluate("\\MAIN", &[]), Ok(Value::Integer(7)));
}

#[test]
fn a_reference_to_a_removed_object_does_not_alias_its_successor() {
    // Method (MKRF) { Return (RefOf (0x11)) }: the nameless object holding 0x11 goes when MKRF returns.
    // Method (MAIN) { Local0 = MKRF (); RefOf (0x22); Return (DerefOf (Local0)) }: the second RefOf's
    // object takes the freed slot.
    let mkrf = method(b"MKRF", 0, &[RETURN, 0x71, 0x0A, 0x11]);
    let main = method(b"MAIN", 0, &[&[0x70][..], b"MKRF", &[0x60, 0x71, 0x0A, 0x22, RETURN, 0x83, 0x60]].concat());
    let mut aml = interpreter(CountingHost::default(), Config::default(), &[mkrf, main]);
    assert_eq!(aml.evaluate("\\MAIN", &[]), Err(AmlError::NotFound));
}
