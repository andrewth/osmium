use super::*;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}

/// A source that counts its calls and can be made to fail.
struct TestSource {
    calls: AtomicUsize,
    fail: AtomicBool,
}

impl TestSource {
    const fn new() -> Self {
        Self { calls: AtomicUsize::new(0), fail: AtomicBool::new(false) }
    }
}

impl EntropySource for TestSource {
    fn fill(&self, out: &mut [u8]) -> Result<(), EntropyError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(EntropyError);
        }
        out.fill(n as u8 ^ 0x5a);
        Ok(())
    }
}

#[test]
fn output_matches_an_independent_chacha20_implementation() {
    // Reference computed with Python `cryptography`'s ChaCha20 running the
    // same construction: four blocks per refill, the first 32 bytes rekey.
    let mut rng = ChaChaRng::from_seed(core::array::from_fn(|i| i as u8));
    let mut out = [0u8; 1000];
    rng.fill(&mut out);
    assert_eq!(hex(&out[..32]), "2b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0485b410c");
    assert_eq!(hex(&Sha256::digest(&out)), "7d11528e97de1d34a222e3e9d83ca335ca909297fdc466fb0a27ebab6ccb9785");
}

#[test]
fn split_requests_give_the_same_stream() {
    let mut a = ChaChaRng::from_seed([7; 32]);
    let mut b = ChaChaRng::from_seed([7; 32]);
    let mut whole = [0u8; 700];
    a.fill(&mut whole);
    let mut parts = [0u8; 700];
    let (x, rest) = parts.split_at_mut(1);
    let (y, z) = rest.split_at_mut(300);
    b.fill(x);
    b.fill(y);
    b.fill(z);
    assert_eq!(whole, parts);
}

#[test]
fn reseed_changes_output_and_a_failed_reseed_changes_nothing() {
    let src = TestSource::new();
    let mut plain = ChaChaRng::from_seed([1; 32]);
    let mut reseeded = ChaChaRng::from_seed([1; 32]);
    let mut failed = ChaChaRng::from_seed([1; 32]);
    reseeded.reseed(&src).expect("source works");
    src.fail.store(true, Ordering::SeqCst);
    assert_eq!(failed.reseed(&src), Err(EntropyError));
    let (p, r, f) = (plain.next_u64(), reseeded.next_u64(), failed.next_u64());
    assert_ne!(p, r);
    assert_eq!(p, f);
}

#[test]
fn reseed_discards_buffered_output() {
    let src = TestSource::new();
    let mut a = ChaChaRng::from_seed([2; 32]);
    let mut b = ChaChaRng::from_seed([2; 32]);
    a.next_u64();
    b.next_u64();
    b.reseed(&src).expect("source works");
    // Without the discard, b would keep handing out a's buffered bytes.
    assert_ne!(a.next_u64(), b.next_u64());
}

#[test]
fn seeding_uses_the_source() {
    let src = TestSource::new();
    let a = ChaChaRng::new(&src).expect("source works").next_u64();
    let b = ChaChaRng::new(&src).expect("source works").next_u64();
    assert_eq!(src.calls.load(Ordering::SeqCst), 2);
    assert_ne!(a, b);
}

#[test]
fn shared_rng_refuses_until_seeded_then_reseeds_on_schedule() {
    static SRC: TestSource = TestSource::new();
    let rng = SharedRng::new();
    assert_eq!(rng.next_u64(), Err(NotSeeded));
    assert!(!rng.is_seeded());
    rng.seed(&SRC).expect("source works");
    assert!(rng.is_seeded());
    assert_eq!(SRC.calls.load(Ordering::SeqCst), 1);

    let mut buf = std::vec![0u8; RESEED_INTERVAL];
    rng.fill(&mut buf).expect("seeded");
    assert_eq!(SRC.calls.load(Ordering::SeqCst), 1);
    rng.next_u64().expect("seeded");
    assert_eq!(SRC.calls.load(Ordering::SeqCst), 2);

    // A failing source doesn't stop output.
    SRC.fail.store(true, Ordering::SeqCst);
    rng.fill(&mut buf).expect("seeded");
    rng.next_u64().expect("still works");
    assert_eq!(SRC.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn cpu_entropy_on_the_host() {
    assert!(CpuEntropy::available());
    let mut a = [0u8; 13];
    let mut b = [0u8; 13];
    CpuEntropy.fill(&mut a).expect("urandom");
    CpuEntropy.fill(&mut b).expect("urandom");
    assert_ne!(a, b);
}

#[test]
fn wipe_zeroes() {
    let mut b = [0xffu8; 9];
    wipe(&mut b);
    assert_eq!(b, [0; 9]);
}
