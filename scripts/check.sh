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
# QEMU's user network answers the kernel's ARP request over virtio-net, then
# osmium-net gets a DHCP lease, pings the gateway and round-trips a TCP echo
# through a guestfwd to cat. Behind
# the xHCI controller, a USB stick on a scratch image answers a SCSI INQUIRY and
# takes a block write while the keyboard's interrupt transfer stays pending. A
# guest runs in VS-mode under the H extension. With dosfstools installed the
# stick is formatted FAT32, the kernel writes a file on it, and fsck.fat must
# accept the result. A SATA disk behind AHCI and an NVMe namespace each take
# a sector round trip, as does an iSCSI LUN that scripts/iscsi-target.py
# serves through a second guestfwd.
stick=$(mktemp)
vdisk=$(mktemp)
sata=$(mktemp)
nvdisk=$(mktemp)
iscsi=$(mktemp)
truncate -s 8M "$vdisk" "$sata" "$nvdisk" "$iscsi"
truncate -s 40000K "$stick"
fat_expect=
if PATH=$PATH:/usr/sbin command -v mkfs.fat >/dev/null; then
    PATH=$PATH:/usr/sbin mkfs.fat -F 32 -s 1 "$stick" >/dev/null
    fat_expect=';\[fat\]   wrote and read back "/osmium/Hello from osmium.txt"'
fi
EXPECT='ARP: 10.0.2.2 is at;DHCP: 10.0.2.15/24 via 10.0.2.2;ping 10.0.2.2: seq 1 in;TCP echo from 10.0.2.100:7: "hello over TCP";\[blk\]   virtio-blk .*: 16384 sectors;wrote and read back sector 8192;INQUIRY "QEMU" "QEMU HARDDISK";interface 0: class 03/01/01;wrote and read back block 79999;keyboard transfer still pending after disk I/O;\[guard\] task "deep" overflowed;nested Breakpoint on the exception stack;user-bad killed: PageFault;user-1 exited with status 0 (kernel sees CPU 1);hello from process 2;4 of 4 address spaces torn down;hello from a Rust ELF: 46 primes below 200;pid [0-9]* on Osmium/riscv64: brk ok, mmap ok, writev ok;init: fork: pid [0-9]* reaped child [0-9]* (status 7); parent.s memory unchanged: ok;exec.d as "init child" with HOME=/;execve: child [0-9]* exited with status 5; then wait4 says -10;1 of 1 init address space torn down;/etc/motd: "welcome to osmium"; /tmp/note ok; / has 5 entries;\[balance\] 8 unpinned tasks spawned on CPU 0 ran on CPUs 0b1111;\[guest\] hello over MMIO;\[guest\] hello over SBI;guest exit Shutdown: 2 hypercalls, 1 halt, [1-9][0-9]* host interrupts, LSR 0x60, DBCN error 0;\[vguest\] timer interrupt after;\[vguest\] PLIC claim 10: received "ping";\[vguest\] PLIC claim 1: ARP reply, 10.0.2.2 is at 52:55:0a:00:02:02;\[vguest\] virtio-blk: 64 sectors; sector 3 written and read back;the host RAM disk holds the sector the guest wrote;driver guest exit Shutdown;\[smp-guest\] hart 0: got the IPI; hart 1 is stopped;SMP guest: 2 vCPUs on .*hart_start returned 0, hart 1 got opaque 0x1234;xHCI interrupts: [1-9];FP guests interleaved on one hart: vCPU a0=1 got 12, a0=2 got 14 (expected 12 and 14);\[usb\]     ecm: ARP: 10.0.2.2 is at;\[ahci\]  port 0 "QEMU HARDDISK": 16384 sectors of 512; round trip Ok(8192);\[nvme\]  .* "QEMU NVMe Ctrl" namespace 1: 16384 blocks of 512; round trip Ok(8192);\[iscsi\] 10.0.2.100:3260: "OSMIUM" "iscsi-target.py", 16384 blocks of 512;\[iscsi\] wrote and read back block 8192'"$fat_expect" \
boot riscv-virt qemu-system-riscv64 riscv64imac-unknown-none-elf \
    -machine virt -bios default -smp 4 -accel tcg,thread=multi \
    -netdev user,id=n0,guestfwd=tcp:10.0.2.100:7-cmd:cat,guestfwd=tcp:10.0.2.100:3260-cmd:"python3 scripts/iscsi-target.py $iscsi" -device virtio-net-device,netdev=n0 \
    -device qemu-xhci -device usb-kbd \
    -drive if=none,id=vd0,format=raw,file="$vdisk" -device virtio-blk-device,drive=vd0 \
    -netdev user,id=n1 -device usb-net,netdev=n1 \
    -drive if=none,id=stick,format=raw,file="$stick" -device usb-storage,drive=stick \
    -device ahci,id=ahci0 -drive if=none,id=sd0,format=raw,file="$sata" -device ide-hd,drive=sd0,bus=ahci0.0 \
    -drive if=none,id=nv0,format=raw,file="$nvdisk" -device nvme,serial=osmium0,drive=nv0
if [ -n "$fat_expect" ]; then
    echo "== fsck.fat the USB stick the kernel wrote"
    report=$(PATH=$PATH:/usr/sbin fsck.fat -n -l "$stick") || { echo "$report"; echo "riscv-virt: fsck.fat rejected the USB stick"; exit 1; }
    grep -q "/OSMIUM/Hello from osmium.txt" <<<"$report" || { echo "$report"; echo "riscv-virt: file missing on the USB stick"; exit 1; }
fi
rm -f "$stick" "$vdisk" "$sata" "$nvdisk" "$iscsi"
EXPECT='\[guard\] task "deep" overflowed;nested Breakpoint on the exception stack;user-bad killed: PageFault;user-1 exited with status 0 (kernel sees CPU 1);hello from process 2;4 of 4 address spaces torn down;hello from a Rust ELF: 46 primes below 200;pid [0-9]* on Osmium/aarch64: brk ok, mmap ok, writev ok;init: fork: pid [0-9]* reaped child [0-9]* (status 7); parent.s memory unchanged: ok;exec.d as "init child" with HOME=/;execve: child [0-9]* exited with status 5; then wait4 says -10;1 of 1 init address space torn down;/etc/motd: "welcome to osmium"; /tmp/note ok; / has 5 entries;\[balance\] 8 unpinned tasks spawned on CPU 0 ran on CPUs 0b1111' \
boot aarch64-virt qemu-system-aarch64 aarch64-unknown-none-softfloat \
    -machine virt,gic-version=2 -cpu cortex-a72 -smp 4 -accel tcg,thread=multi
EXPECT='\[guard\] task "deep" overflowed;user-bad killed: PageFault;user-1 exited with status 0 (kernel sees CPU 1);user-2 exited with status 0;\[uart\]  COM1 IRQ 4;hello from process 2;4 of 4 address spaces torn down;hello from a Rust ELF: 46 primes below 200;pid [0-9]* on Osmium/x86_64: brk ok, mmap ok, writev ok;init: fork: pid [0-9]* reaped child [0-9]* (status 7); parent.s memory unchanged: ok;exec.d as "init child" with HOME=/;execve: child [0-9]* exited with status 5; then wait4 says -10;1 of 1 init address space torn down;/etc/motd: "welcome to osmium"; /tmp/note ok; / has 5 entries;\[balance\] 8 unpinned tasks spawned on CPU 0 ran on CPUs 0b1111' \
boot x86_64-pc qemu-system-x86_64 x86_64-unknown-none \
    -machine q35 -cpu max -smp 4 -accel tcg,thread=multi -display none -no-reboot

# Heap-free M-mode firmware (no OpenSBI): checked for its own lines, since it
# runs none of the scheduler demos.
if command -v qemu-system-riscv64 >/dev/null; then
    echo "== boot examples/riscv-firmware under QEMU"
    fwlog=$(mktemp)
    (cd examples/riscv-firmware && cargo build -q --release)
    timeout 60 qemu-system-riscv64 -machine virt -bios none -smp 1 -m 128M -nographic \
        -kernel examples/riscv-firmware/target/riscv64imac-unknown-none-elf/release/riscv-firmware \
        -serial "file:$fwlog" -monitor none </dev/null >/dev/null
    sed -n '/^osmium/,$p' "$fwlog"
    for line in 'awaited 5 timer interrupts' 'console task:' 'all tasks finished'; do
        grep -q "$line" "$fwlog" || { echo "riscv-firmware: missing '$line'"; exit 1; }
    done
    rm -f "$fwlog"
fi

# RISC-V hypervisor booting a whole guest kernel: the riscv-virt kernel
# built above runs in VS-mode under riscv-hyp (QEMU's loader places the ELF
# raw in host RAM), with one vCPU on each of two host harts, a virtio-blk
# disk over a host RAM disk, and a virtio-net card bridged to the host's
# QEMU user network (DHCP, ping and the TCP echo all from inside the guest).
# Guest lines carry a "| " prefix.
if command -v qemu-system-riscv64 >/dev/null; then
    echo "== boot examples/riscv-virt as a guest of examples/riscv-hyp under QEMU"
    nestlog=$(mktemp)
    (cd examples/riscv-hyp && cargo build -q --release)
    timeout 120 qemu-system-riscv64 -machine virt -bios default -smp 2 -accel tcg,thread=multi -m 512M -nographic \
        -kernel examples/riscv-hyp/target/riscv64imac-unknown-none-elf/release/riscv-hyp \
        -device loader,file=examples/riscv-virt/target/riscv64imac-unknown-none-elf/release/riscv-virt,addr=0x98000000,force-raw=on \
        -netdev user,id=n0,guestfwd=tcp:10.0.2.100:7-cmd:cat -device virtio-net-device,netdev=n0 \
        -serial "file:$nestlog" -monitor none </dev/null >/dev/null
    sed -n '/^osmium/,$p' "$nestlog"
    for line in 'guest kernel: [0-9]* KiB loaded, entry 0x80200000' '| osmium riscv-virt example (hart 0)' \
        '| \[mmu\]   Sv39 on' '| \[mutex\] 4 tasks x 1000 increments across yields = 4000' '| \[preempt\]' \
        '| \[smp\]   2 CPUs online' '| \[smp\]   migrating task visited CPUs \[0, 1, 0\]' \
        '| \[balance\] 4 unpinned tasks spawned on CPU 0 ran on CPUs 0b11' \
        '| \[net\]   DHCP: 10.0.2.15/24 via 10.0.2.2' '| \[net\]   ping 10.0.2.2: seq 1 in' \
        '| \[net\]   TCP echo from 10.0.2.100:7: "hello over TCP"' \
        '| \[blk\]   virtio-blk (1.x) at 0x10001000: 8192 sectors; wrote and read back sector 4096' \
        "the host RAM disk holds the guest's write to sector 4096" \
        '| \[user\]  user-elf exited with status 0' '| \[user\]  init and its children reaped' \
        '| \[hyp\]   no H extension in riscv,isa: skipping the guests' '| \[done\]' 'guest exit Shutdown'; do
        grep -q "$line" "$nestlog" || { echo "riscv-hyp: missing '$line'"; exit 1; }
    done
    rm -f "$nestlog"
fi

# EL2 hypervisor (QEMU starts it at EL2 with virtualization=on): checked for
# its own lines, since it runs none of the scheduler demos.
if command -v qemu-system-aarch64 >/dev/null; then
    echo "== boot examples/aarch64-hyp under QEMU"
    hyplog=$(mktemp)
    (cd examples/aarch64-hyp && cargo build -q --release)
    timeout 60 qemu-system-aarch64 -machine virt,virtualization=on,gic-version=2 -cpu max -smp 2 -m 128M -nographic \
        -kernel examples/aarch64-hyp/target/aarch64-unknown-none-softfloat/release/aarch64-hyp \
        -serial "file:$hyplog" -monitor none </dev/null >/dev/null
    sed -n '/^osmium/,$p' "$hyplog"
    for line in 'example (EL2)' 'EL2 MMU on' '\[guest\] hello from EL1 over MMIO' \
        'guest exit Shutdown: 1 hypercall, 1 halt, 0 host interrupts, LSR 0x60' \
        '\[guest\] UART interrupt, received: ping' \
        'vGIC guest exit Shutdown: INTID 27 (timer) then INTID 33 (UART), [0-9]* halts, [0-9]* timer exits' \
        'FP guests interleaved on one CPU: vCPU x0=1 got 12, x0=2 got 14 (expected 12 and 14)' \
        '2 CPUs online at EL2' '\[smp-guest\] cpu 0: got the SGI in guest code; cpu 1 is off' \
        'vCPU 0 kicked out of guest code by a host SGI [1-9]' \
        'SMP guest: 2 vCPUs on host CPUs 0 and 1; CPU_ON returned 0, cpu 1 got context 0x1234, IAR 0x401' '\[done\]'; do
        grep -q "$line" "$hyplog" || { echo "aarch64-hyp: missing '$line'"; exit 1; }
    done
    rm -f "$hyplog"
fi

# AMD SVM hypervisor (QEMU's TCG implements SVM with nested paging).
if command -v qemu-system-x86_64 >/dev/null; then
    echo "== boot examples/x86_64-hyp under QEMU"
    svmlog=$(mktemp)
    (cd examples/x86_64-hyp && cargo build -q --release)
    timeout 60 qemu-system-x86_64 -machine q35 -cpu max -smp 2 -m 128M -nographic -no-reboot -display none \
        -kernel examples/x86_64-hyp/target/x86_64-unknown-none/release/x86_64-hyp \
        -serial "file:$svmlog" -monitor none </dev/null >/dev/null
    sed -n '/^osmium/,$p' "$svmlog"
    for line in 'SVM on, nested paging' '\[guest\] hello from SVM over port I/O' \
        '\[guest\] and over MMIO (nested page faults)' '\[guest\] IRQ 4 through the 8259 PIC, received: k' \
        '\[guest\] 5 ticks from the 8254 PIT on IRQ 0' \
        'guest exit Shutdown: 1 hypercall, LSR 0x60 (port) 0x60 (MMIO)' \
        "\\[guest\\] 64-bit, paging on, MMIO through the guest's page tables" \
        '\[guest\] 3 local APIC timer interrupts through a 64-bit IDT' \
        '\[guest\] COM1 IRQ 4 through the I/O APIC, received: z' \
        '64-bit guest exit Shutdown, LSR 0x60 in r12' \
        '\[smp-guest\] cpu 1: up in real mode at 0x8000 after INIT/STARTUP' \
        '\[smp-guest\] cpu 0: IPI 0x41 from cpu 1 through the local APICs' \
        'SMP guest done: 2 vCPUs on host CPUs 0 and 1, [1-9]' '\[done\]'; do
        grep -q "$line" "$svmlog" || { echo "x86_64-hyp: missing '$line'"; exit 1; }
    done
    rm -f "$svmlog"
fi

echo "all checks passed"
