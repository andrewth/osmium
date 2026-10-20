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

# Boots an example kernel under QEMU and checks that every demo ran.
boot() {
    local name=$1 qemu=$2 target=$3
    shift 3
    if ! command -v "$qemu" >/dev/null; then
        echo "== $qemu not found; skipping $name"
        return
    fi
    echo "== boot examples/$name under QEMU"
    local log
    log=$(mktemp)
    (cd "examples/$name" && cargo build -q --release)
    timeout 60 "$qemu" "$@" -nographic -m 128M \
        -kernel "examples/$name/target/$target/release/$name" \
        -serial "file:$log" -monitor none </dev/null >/dev/null
    sed -n '/^osmium/,$p' "$log"
    for line in '\[mutex\] .* = 4000' '\[preempt\]' '\[timer\]' '4 CPUs online' \
        'mask 0b1111), mutex total 2000' 'visited CPUs \[0, 1, 2, 3, 0\]' 'PageFault' '\[done\]'; do
        grep -q "$line" "$log" || { echo "$name: missing '$line'"; exit 1; }
    done
    # Lines only some kernels print: the caller's $EXPECT, ';'-separated.
    local extra=()
    IFS=';' read -ra extra <<<"${EXPECT:-}"
    for line in "${extra[@]}"; do
        grep -q "$line" "$log" || { echo "$name: missing '$line'"; exit 1; }
    done
    rm -f "$log"
}

# Multi-threaded TCG runs the four CPUs in parallel on host threads.
# QEMU's user network answers the kernel's ARP request over virtio-net, and a
# USB stick behind the xHCI controller answers a SCSI INQUIRY.
EXPECT='ARP: 10.0.2.2 is at;INQUIRY "QEMU" "QEMU HARDDISK";interface 0: class 03/01/01;\[guard\] task "deep" overflowed;nested Breakpoint on the exception stack;user-bad killed: PageFault;user-1 exited with status 0 (kernel sees CPU 1)' \
boot riscv-virt qemu-system-riscv64 riscv64imac-unknown-none-elf \
    -machine virt -bios default -smp 4 -accel tcg,thread=multi \
    -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -device qemu-xhci -device usb-kbd \
    -blockdev null-co,node-name=stick,size=1048576 -device usb-storage,drive=stick
EXPECT='\[guard\] task "deep" overflowed;nested Breakpoint on the exception stack;user-bad killed: PageFault;user-1 exited with status 0 (kernel sees CPU 1)' \
boot aarch64-virt qemu-system-aarch64 aarch64-unknown-none-softfloat \
    -machine virt,gic-version=2 -cpu cortex-a72 -smp 4 -accel tcg,thread=multi
EXPECT='\[guard\] task "deep" overflowed;user-bad killed: PageFault;user-1 exited with status 0;user-2 exited with status 0;\[uart\]  COM1 IRQ 4' \
boot x86_64-pc qemu-system-x86_64 x86_64-unknown-none \
    -machine q35 -cpu max -smp 4 -accel tcg,thread=multi -display none -no-reboot

echo "all checks passed"
