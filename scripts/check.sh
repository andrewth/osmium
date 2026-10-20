#!/usr/bin/env bash
# Full verification: host tests, lints, docs, every bare-metal target, and
# the RISC-V example kernel booted under QEMU.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== host tests"
cargo test -q --workspace --all-features

echo "== clippy"
cargo clippy -q --workspace --all-features --all-targets -- -D warnings

echo "== rustdoc"
RUSTDOCFLAGS="-D warnings" cargo doc -q --workspace --all-features --no-deps

for target in x86_64-unknown-none aarch64-unknown-none-softfloat riscv64imac-unknown-none-elf; do
    echo "== build $target"
    cargo build -q --workspace --all-features --target "$target"
done

# Variants that save FP registers in the context switch.
for target in aarch64-unknown-linux-musl riscv64gc-unknown-linux-musl; do
    echo "== check $target"
    cargo check -q --workspace --all-features --target "$target"
done

if command -v qemu-system-riscv64 >/dev/null; then
    echo "== boot examples/riscv-virt under QEMU"
    log=$(mktemp)
    (cd examples/riscv-virt && cargo build -q --release)
    timeout 60 qemu-system-riscv64 -machine virt -nographic -bios default -m 128M -smp 1 \
        -kernel examples/riscv-virt/target/riscv64imac-unknown-none-elf/release/riscv-virt \
        -serial "file:$log" -monitor none </dev/null >/dev/null
    sed -n '/osmium riscv-virt/,$p' "$log"
    grep -q '^\[preempt\]' "$log" && grep -q '^\[done\]' "$log" || { echo "kernel did not finish"; exit 1; }
    rm -f "$log"
else
    echo "== qemu-system-riscv64 not found; skipping the boot test"
fi

echo "all checks passed"
