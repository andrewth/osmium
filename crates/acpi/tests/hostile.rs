//! AML is firmware's, and firmware is not trusted: hostile and broken tables must fail cleanly. Nothing
//! here may panic (debug builds also trap arithmetic overflow), hang, recurse off the stack or allocate
//! without bound.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use osmium_acpi::aml::{AmlError, Config, Interpreter, ObjectKind, ROOT, Value};
use osmium_acpi::fadt::Fadt;
use osmium_acpi::resource;
use osmium_boot::acpi::Table;

// ----- a tiny AML assembler -----

fn pkg_len(body: usize) -> Vec<u8> {
    // Up to a 3-byte PkgLength (a 28-bit length would take four).
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

fn dsdt(items: &[Vec<u8>]) -> Vec<u8> {
    table(b"DSDT", 2, &items.concat())
}

fn small_config() -> Config {
    Config { max_steps: 100_000, max_depth: 32, ..Config::default() }
}

fn run(items: &[Vec<u8>], method: &str, args: &[Value]) -> Result<Value, AmlError> {
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    aml.load_table(&dsdt(items)).expect("loads");
    aml.evaluate(method, args)
}

const ZERO: u8 = 0x00;
const ONE: u8 = 0x01;
const RETURN: u8 = 0xA4;

#[test]
fn a_loop_that_never_ends_times_out() {
    let body = with_len(&[0xA2], &[ONE]);
    assert_eq!(run(&[method(b"LOOP", 0, &body)], "\\LOOP", &[]), Err(AmlError::Timeout));
}

#[test]
fn a_loop_of_sleeps_runs_out_of_sleep_budget() {
    // While (One) { Sleep (0xFFFF) }
    let body = with_len(&[0xA2], &[ONE, 0x5B, 0x22, 0x0B, 0xFF, 0xFF]);
    let mut aml = Interpreter::new(TestHost::default(), Config { max_steps: u64::MAX, ..Config::default() });
    aml.load_table(&dsdt(&[method(b"SLP_", 0, &body)])).unwrap();
    assert_eq!(aml.evaluate("\\SLP_", &[]), Err(AmlError::Timeout));
    // It slept for about the budget (10 s), not for ever.
    assert!(aml.host().slept_ms <= 10_000 + 0xFFFF);
}

#[test]
fn recursion_stops() {
    // Method (REC) { Return (REC ()) }
    let body = [RETURN, b'R', b'E', b'C', b'_'];
    assert_eq!(run(&[method(b"REC_", 0, &body)], "\\REC_", &[]), Err(AmlError::TooDeep));
}

#[test]
fn deep_nesting_stops() {
    // Return (Not (Not (... Not (0) ...))) nested far deeper than the limit.
    let mut body = vec![RETURN];
    body.extend(std::iter::repeat_n([0x80u8], 5000).flatten().chain([ZERO]));
    // Each Not also takes a target (Zero), so give them: Not (x, Zero) is 0x80 x 0x00.
    let mut nested = vec![ZERO];
    for _ in 0..5000 {
        nested = [vec![0x80], nested, vec![ZERO]].concat();
    }
    body.truncate(1);
    body.extend(nested);
    // The method body is longer than a one-byte PkgLength; pkg_len handles that.
    assert_eq!(run(&[method(b"DEEP", 0, &body)], "\\DEEP", &[]), Err(AmlError::TooDeep));
}

#[test]
fn deep_nesting_fits_in_a_small_stack_at_the_default_limit() {
    // The default max_depth must not overflow a modest stack: here 1 MiB, in a debug build (a release
    // build needs under 64 KiB).
    let t = std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(|| {
            let mut nested = vec![ZERO];
            for _ in 0..1000 {
                nested = [vec![0x80], nested, vec![ZERO]].concat();
            }
            let body = [vec![RETURN], nested].concat();
            let mut aml = Interpreter::new(TestHost::default(), Config::default());
            aml.load_table(&dsdt(&[method(b"DEEP", 0, &body)])).unwrap();
            assert_eq!(aml.evaluate("\\DEEP", &[]), Err(AmlError::TooDeep));
            let rec = [RETURN, b'R', b'E', b'C', b'_'];
            let mut aml = Interpreter::new(TestHost::default(), Config::default());
            aml.load_table(&dsdt(&[method(b"REC_", 0, &rec)])).unwrap();
            assert_eq!(aml.evaluate("\\REC_", &[]), Err(AmlError::TooDeep));
        })
        .unwrap();
    t.join().unwrap();
}

#[test]
fn huge_objects_are_refused() {
    // Return (Buffer (0xFFFFFFFF) {})
    let buf = with_len(&[0x11], &[0x0C, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(run(&[method(b"BUF_", 0, &[vec![RETURN], buf].concat())], "\\BUF_", &[]), Err(AmlError::TooLarge));
    // Return (Package (0xFFFFFF) {}) built with VarPackage.
    let pkg = with_len(&[0x13], &[0x0C, 0xFF, 0xFF, 0xFF, 0x00]);
    assert_eq!(run(&[method(b"PKG_", 0, &[vec![RETURN], pkg].concat())], "\\PKG_", &[]), Err(AmlError::TooLarge));
    // A field of 2^28 - 1 bits: Field (RAM, ByteAcc, NoLock, Preserve) { BIG_, 0xFFFFFFF }, with a
    // 4-byte PkgLength for the length.
    let region =
        [vec![0x5B, 0x80, b'R', b'A', b'M', b'_', 0x00, 0x0C, 0, 0, 0, 0, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF]].concat();
    let field_body = [&b"RAM_"[..], &[0x01], &b"BIG_"[..], &[0xCF, 0xFF, 0xFF, 0xFF]].concat();
    let field = with_len(&[0x5B, 0x81], &field_body);
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    let r = aml.load_table(&dsdt(&[region, field]));
    assert_eq!(r.err(), Some(AmlError::TooLarge));
}

#[test]
fn arithmetic_that_cannot_work_is_an_error() {
    // Divide (1, Arg0, , Local0) and Mod (1, Arg0).
    let div = [RETURN, 0x78, ONE, 0x68, ZERO, 0x60];
    assert_eq!(run(&[method(b"DIV_", 1, &div)], "\\DIV_", &[Value::Integer(0)]), Err(AmlError::DivideByZero));
    assert_eq!(run(&[method(b"DIV_", 1, &div)], "\\DIV_", &[Value::Integer(1)]), Ok(Value::Integer(1)));
    let modulo = [RETURN, 0x85, ONE, 0x68, ZERO];
    assert_eq!(run(&[method(b"MOD_", 1, &modulo)], "\\MOD_", &[Value::Integer(0)]), Err(AmlError::DivideByZero));
}

#[test]
fn misplaced_control_flow_is_an_error() {
    let brk = [0xA5];
    assert_eq!(run(&[method(b"BRK_", 0, &brk)], "\\BRK_", &[]), Err(AmlError::BadControlFlow));
    let cont = [0x9F];
    assert_eq!(run(&[method(b"CNT_", 0, &cont)], "\\CNT_", &[]), Err(AmlError::BadControlFlow));
    // An Else with no If.
    let els = with_len(&[0xA1], &[]);
    assert_eq!(run(&[method(b"ELS_", 0, &els)], "\\ELS_", &[]), Err(AmlError::InvalidOpcode(0xA1)));
}

#[test]
fn indexing_outside_an_object_is_an_error() {
    // Return (DerefOf (Index (Package (1) { 1 }, 5)))
    let pkg = with_len(&[0x12], &[1, ONE]);
    let body = [vec![RETURN, 0x83, 0x88], pkg, vec![0x0A, 5, ZERO]].concat();
    assert_eq!(run(&[method(b"IDX_", 0, &body)], "\\IDX_", &[]), Err(AmlError::OutOfBounds));
}

#[test]
fn undefined_names_and_bad_calls_are_errors() {
    let body = [RETURN, b'N', b'O', b'P', b'E'];
    assert_eq!(run(&[method(b"NOPE", 0, &[RETURN, b'Z', b'Z', b'Z', b'Z'])], "\\NOPE", &[]), Err(AmlError::NotFound));
    // Calling a one-argument method as if it had two is parsed by the callee's declared count, so the
    // second argument is read as the next term: here the code ends.
    let one_arg = method(b"ONE_", 1, &[RETURN, 0x68]);
    let caller = method(b"CALL", 0, &[RETURN, b'O', b'N', b'E', b'_']);
    assert_eq!(run(&[one_arg, caller], "\\CALL", &[]), Err(AmlError::UnexpectedEnd));
    let _ = body;
}

#[test]
fn fatal_reaches_the_host_and_fails_the_method() {
    // Fatal (1, 2, 3)
    let body = [0x5B, 0x32, 0x01, 0x02, 0, 0, 0, 0x0A, 3];
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    aml.load_table(&dsdt(&[method(b"FTL_", 0, &body)])).unwrap();
    assert_eq!(aml.evaluate("\\FTL_", &[]), Err(AmlError::Fatal { kind: 1, code: 2, arg: 3 }));
    assert_eq!(aml.host().fatals, [(1, 2, 3)]);
}

#[test]
fn truncated_tables_fail_at_the_break() {
    // A method whose PkgLength claims more bytes than the table has.
    let mut m = method(b"CUT_", 0, &[RETURN, ONE]);
    m[1] += 20;
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    assert_eq!(aml.load_table(&dsdt(&[m])).err(), Some(AmlError::InvalidPkgLength));
    // What was declared before the break stays.
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    let good = method(b"GOOD", 0, &[RETURN, ONE]);
    let mut bad = method(b"BAD_", 0, &[RETURN, ONE]);
    bad[1] += 20;
    assert!(aml.load_table(&dsdt(&[good, bad])).is_err());
    assert_eq!(aml.evaluate("\\GOOD", &[]), Ok(Value::Integer(1)));
    assert_eq!(aml.evaluate("\\BAD_", &[]), Err(AmlError::NotFound));
}

#[test]
fn a_failed_call_leaves_the_interpreter_usable() {
    let loop_ = method(b"LOOP", 0, &with_len(&[0xA2], &[ONE]));
    let ok = method(b"OK__", 0, &[RETURN, 0x0A, 42]);
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    aml.load_table(&dsdt(&[loop_, ok])).unwrap();
    for _ in 0..3 {
        assert_eq!(aml.evaluate("\\LOOP", &[]), Err(AmlError::Timeout));
        assert_eq!(aml.evaluate("\\OK__", &[]), Ok(Value::Integer(42)));
    }
}

#[test]
fn a_32_bit_table_wraps_at_32_bits() {
    let ones = [RETURN, 0x72, 0xFF, ONE, ZERO];
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    aml.load_table(&table(b"DSDT", 1, &method(b"ADD_", 0, &ones))).unwrap();
    assert_eq!(aml.evaluate("\\ADD_", &[]), Ok(Value::Integer(0)));
    let all = [RETURN, 0xFF];
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    aml.load_table(&table(b"DSDT", 1, &method(b"ONES", 0, &all))).unwrap();
    assert_eq!(aml.evaluate("\\ONES", &[]), Ok(Value::Integer(0xFFFF_FFFF)));
    // The same in a revision 2 table is 64 bits wide.
    let mut aml = Interpreter::new(TestHost::default(), small_config());
    aml.load_table(&dsdt(&[method(b"ONES", 0, &all)])).unwrap();
    assert_eq!(aml.evaluate("\\ONES", &[]), Ok(Value::Integer(u64::MAX)));
}

// ----- fuzzing -----

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        self.next() as usize % n.max(1)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// `seed` with a few bytes replaced (some with values AML cares about), sometimes truncated or with
    /// a chunk repeated.
    fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut v = seed.to_vec();
        for _ in 0..1 + self.below(8) {
            let at = 36 + self.below(v.len().saturating_sub(36));
            if at >= v.len() {
                break;
            }
            v[at] = match self.below(6) {
                0 => 0,
                1 => 0xff,
                2 => [0x5B, 0xA0, 0xA2, 0x14, 0x10, 0x11, 0x12, 0x70, 0x72, 0x88, 0x83][self.below(11)],
                _ => self.next() as u8,
            };
        }
        match self.below(6) {
            0 => v.truncate(36 + self.below(v.len().saturating_sub(36) + 1)),
            1 if v.len() > 80 => {
                let from = 36 + self.below(v.len() - 80);
                let chunk = v[from..from + 40].to_vec();
                let at = 36 + self.below(v.len() - 36);
                v.splice(at..at, chunk);
            }
            _ => {}
        }
        seal(v)
    }
}

/// Loads `table` and exercises everything in it, with small budgets.
fn exercise(table: &[u8]) {
    let config = Config { max_steps: 5_000, max_depth: 24, max_sleep_us: 1_000, ..Config::default() };
    let mut aml = Interpreter::new(TestHost::default(), config);
    if aml.load_table(table).is_err() && aml.namespace().descendants(ROOT).is_empty() {
        return;
    }
    let _ = aml.initialize();
    let ids = aml.namespace().descendants(ROOT);
    for id in ids {
        match aml.namespace().kind(id) {
            Some(ObjectKind::Method) => {
                for argc in 0..=7 {
                    let args = vec![Value::Integer(1); argc];
                    if aml.evaluate_node(id, &args) != Err(AmlError::WrongArgCount) {
                        break;
                    }
                }
            }
            Some(ObjectKind::Device) => {
                let _ = aml.current_resources(id);
                let _ = aml.pci_routing_table(id);
                let _ = aml.route_pci_irq(id, 1, 0, 0);
            }
            Some(_) => {
                let _ = aml.evaluate_node(id, &[]);
            }
            None => {}
        }
    }
    let _ = aml.devices();
}

/// How many mutations to try per seed table; `FUZZ_ITERS` raises it for a long run.
fn iterations(default: usize) -> usize {
    std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[test]
fn mutated_tables_never_panic_or_hang() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let seeds: [&[u8]; 4] = [
        include_bytes!("asl/lang.aml"),
        include_bytes!("asl/regions.aml"),
        include_bytes!("asl/devices.aml"),
        include_bytes!("asl/ssdt.aml"),
    ];
    for seed in seeds {
        exercise(seed);
        for _ in 0..iterations(1500) {
            let m = rng.mutate(seed);
            exercise(&m);
        }
    }
}

#[test]
fn garbage_bodies_never_panic_or_hang() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..iterations(4000) {
        let n = rng.below(300);
        let body = rng.bytes(n);
        exercise(&table(b"DSDT", 2, &body));
    }
}

#[test]
fn garbage_in_the_other_parsers() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let sample = [0x47, 1, 0x60, 0, 0x60, 0, 1, 1, 0x23, 0x10, 0, 1, 0x89, 6, 0, 1, 1, 9, 0, 0, 0, 0x79, 0];
    for _ in 0..20_000 {
        let n = rng.below(64);
        let junk = rng.bytes(n);
        if let Ok(r) = resource::decode(&junk) {
            let _ = resource::encode(&r);
        }
        let mutated: Vec<u8> = sample.iter().map(|&b| if rng.below(8) == 0 { rng.next() as u8 } else { b }).collect();
        let _ = resource::decode(&mutated);
        let _ = resource::decode(mutated.get(..rng.below(mutated.len())).unwrap_or(&[]));
        let body = rng.bytes(240);
        let mut t = table(b"FACP", 6, &body);
        t.truncate(36 + rng.below(240));
        let _ = Fadt::parse(Table { data: &t });
    }
}
