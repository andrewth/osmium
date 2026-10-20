# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

The toolchain is nightly (`rust-toolchain.toml`) with the bare-metal and UEFI targets preinstalled.

```sh
cargo test --workspace --all-features            # all host tests
cargo test -p osmium-net                         # one crate
cargo test -p osmium-fs-fat <test_name>          # one test (substring match)
cargo clippy --workspace --all-features --all-targets -- -D warnings
./scripts/check.sh                               # full gate: tests, clippy, rustdoc, bare-metal builds, QEMU boots
```

Examples are not workspace members and each has its own `Cargo.lock`. Run them from inside their directory, since `.cargo/config.toml` there sets the target and the QEMU runner:

```sh
cd examples/riscv-virt && cargo run --release    # Ctrl-A X quits QEMU
```

`check.sh` skips any step whose QEMU or optional tool is missing and prints a message. It does not fail.

## Formatting

Do not run `cargo fmt` on the workspace; there is no `rustfmt.toml` and the existing code is hand-formatted to 120 columns. Format only the files you touched:

```sh
rustfmt --edition 2024 --config max_width=120,use_small_heuristics=Max path/to/file.rs
```

## Architecture

**Layering.** `osmium-arch` sits at the bottom: IRQ flags, traps, CPU id, MMU and system registers for x86_64, AArch64 and RISC-V. `osmium-sync` and `osmium-mm` build on it, then `osmium-hal` (MMIO, device traits, console) and `osmium-drivers`, and then the higher components: `sched`, `proc`, `fs*`, `net`, `iscsi`, `virt`, `exec`. The `osmium` crate is a facade that re-exports each component behind a feature of the same name; `full` enables all of them. Dependencies only point downward, so keep a new component in the lowest layer that can hold it.

**Library, not a kernel.** No crate defines an entry point, panic handler or global allocator. Each example kernel (`examples/*-virt`, `x86_64-pc`, `riscv-firmware`, `uefi`) supplies those and assembles the components it needs. The examples are the integration tests for the library.

**Host simulation.** `osmium-arch` swaps privileged instructions for simulations when the target is not `none` or `uefi`: IRQ flags and CPU id are per-thread, TLB flushes are no-ops, and the context switch runs for real on host threads. This is what lets most of the code be unit-tested with plain `cargo test`. Code that depends on the simulation's behaviour (for example, trap handling via `osmium::arch::trap::simulate`) should be tested through it.

**Shared demos.** `examples/demos` holds the scheduler, mutex, IPI and fault demos that every scheduler-capable example runs. `examples/user` holds the user programs (ELF) that the `proc` examples load.

**Hypervisor nesting.** `examples/*-hyp` are hypervisors built on `osmium-virt`. Their `check.sh` boots load the `*-virt` or `x86_64-pc` kernel as a guest (QEMU's `-device loader` places the ELF in host RAM), so a change to a guest kernel is also exercised under its hypervisor.

## The QEMU boot checks

Each example's serial output is grepped against a list of expected lines in `scripts/check.sh`. When you add a feature to an example, add its log line to that boot's `EXPECT` list. Match on what happened, not on counts or timing, since multi-threaded TCG makes those flaky. Serial lines end in `\r\n`, so don't anchor patterns with `$`.

## Things that will bite

- Release profiles do not enable `overflow-checks`, so arithmetic wraps silently in release kernels while debug builds panic. Use explicit checked operations on values that come from untrusted sources (hardware registers, disk images, network packets).
- `missing_docs` is a warning and `undocumented_unsafe_blocks` is a clippy warning. `check.sh` promotes clippy warnings to errors, so both need to be clean.
- Only QEMU has been used. Nothing has run on physical hardware. The Intel VMX backend has only run under nested KVM, because QEMU's TCG does not emulate VMX.


# Rust Coding Guidelines

## Naming (Rust-Specific)

| Rule | Guideline |
|------|-----------|
| No `get_` prefix | `fn name()` not `fn get_name()` |
| Iterator convention | `iter()` / `iter_mut()` / `into_iter()` |
| Conversion naming | `as_` (cheap &), `to_` (expensive), `into_` (ownership) |

## Data Types

| Rule | Guideline |
|------|-----------|
| Use newtypes | `struct Email(String)` for domain semantics |
| Prefer slice patterns | `if let [first, .., last] = slice` |
| Pre-allocate | `Vec::with_capacity()`, `String::with_capacity()` |
| Avoid Vec abuse | Use arrays for fixed sizes |

## Strings

| Rule | Guideline |
|------|-----------|
| Prefer bytes | `s.bytes()` over `s.chars()` when ASCII |
| Use `Cow<str>` | When might modify borrowed data |
| Use `format!` | Over string concatenation with `+` |
| Avoid nested iteration | `contains()` on string is O(n*m) |

## Error Handling

| Rule | Guideline |
|------|-----------|
| Use `?` propagation | Not `try!()` macro |
| `expect()` over `unwrap()` | When value guaranteed |
| Assertions for invariants | `assert!` at function entry |

## Memory

| Rule | Guideline |
|------|-----------|
| Meaningful lifetimes | `'src`, `'ctx` not just `'a` |
| `try_borrow()` for RefCell | Avoid panic |
| Shadowing for transformation | `let x = x.parse()?` |

## Concurrency

| Rule | Guideline |
|------|-----------|
| Identify lock ordering | Prevent deadlocks |
| Atomics for primitives | Not Mutex for bool/usize |
| Choose memory order carefully | Relaxed/Acquire/Release/SeqCst |

## Async

| Rule | Guideline |
|------|-----------|
| Sync for CPU-bound | Async is for I/O |
| Don't hold locks across await | Use scoped guards |

## Macros

| Rule | Guideline |
|------|-----------|
| Avoid unless necessary | Prefer functions/generics |
| Follow Rust syntax | Macro input should look like Rust |