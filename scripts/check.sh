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

# Cleans up on every exit: the screen.py helper may still be waiting for a
# QEMU that never came up (a failed build, a crashed or hung kernel).
screen_pid=0
qmp_dir=
cleanup() {
    [ "$screen_pid" = 0 ] || kill "$screen_pid" 2>/dev/null || true
    [ -z "$qmp_dir" ] || rm -rf "$qmp_dir"
}
trap cleanup EXIT

# `expect NAME LOG PATTERN...` fails the gate unless every grep pattern
# matches somewhere in LOG.
expect() {
    local name=$1 log=$2 line
    shift 2
    for line in "$@"; do
        [ -n "$line" ] || { echo "$name: empty pattern"; exit 1; }
        grep -aq -- "$line" "$log" || { echo "$name: missing '$line'"; exit 1; }
    done
}

# `run_qemu NAME LOG LIMIT QEMU ARG...` runs QEMU with its serial port on LOG
# and prints what the kernel logged (from its banner on, or everything when
# it died before printing one) before judging the exit status, so a hang or
# crash leaves its log behind. Escape sequences and CRs are stripped from LOG.
run_qemu() {
    local name=$1 log=$2 limit=$3 status=0
    shift 3
    timeout "$limit" "$@" -serial "file:$log" -monitor none </dev/null >/dev/null || status=$?
    sed -i 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\r$//' "$log"
    if grep -aq '^osmium' "$log"; then sed -n '/^osmium/,$p' "$log"; else cat "$log"; fi
    if [ "$status" -ne 0 ]; then
        [ "$status" -eq 124 ] && echo "$name: QEMU timed out after $limit s" || echo "$name: QEMU exited with status $status"
        exit 1
    fi
}

# Boots an example kernel under QEMU and checks that every demo ran. The
# caller's $EXPECT array lists the lines only some kernels print.
boot() {
    local name=$1 qemu=$2 target=$3
    shift 3
    if ! command -v "$qemu" >/dev/null; then
        echo "== $qemu not found; skipping $name"
        EXPECT=()
        return
    fi
    echo "== boot examples/$name under QEMU"
    local log
    log=$(mktemp)
    (cd "examples/$name" && cargo build -q --release)
    run_qemu "$name" "$log" 60 "$qemu" "$@" -nographic -m 128M \
        -kernel "examples/$name/target/$target/release/$name"
    expect "$name" "$log" '\[mutex\] .* = 4000' '\[preempt\]' '\[timer\]' '4 CPUs online' \
        'mask 0b1111), mutex total 2000' 'visited CPUs \[0, 1, 2, 3, 0\]' 'PageFault' '\[done\]'
    expect "$name" "$log" ${EXPECT[@]+"${EXPECT[@]}"}
    EXPECT=()
    rm -f "$log"
}

# Checks a display while QEMU runs: scripts/screen.py screendumps over QMP
# until it sees the demos' colour bars. `screen QEMU WIDTH HEIGHT [DEVICE]`
# sets $qmp to a fresh socket for QEMU's -qmp and starts the checker in the
# background as $screen_pid (0 when QEMU is missing); `screen_wait NAME`
# collects its verdict.
screen() {
    # A socket in a fresh private directory, not a guessable /tmp name.
    qmp_dir=$(mktemp -d)
    qmp=$qmp_dir/qmp.sock
    screen_pid=0
    command -v "$1" >/dev/null || return 0
    python3 -I scripts/screen.py "$qmp" "$2" "$3" 600 ${4:-} &
    screen_pid=$!
}
screen_wait() {
    if [ "$screen_pid" != 0 ]; then
        local pid=$screen_pid
        screen_pid=0
        wait "$pid" || { echo "$1: screen check failed"; exit 1; }
    fi
    rm -rf "$qmp_dir"
    qmp_dir=
}

# Multi-threaded TCG runs the four CPUs in parallel on host threads.
# QEMU's user network answers the kernel's ARP request over virtio-net, then
# osmium-net gets a DHCP lease, pings the gateway, resolves a name through
# the user network's DNS and round-trips a TCP echo through a guestfwd to cat. Behind
# the xHCI controller (and likewise EHCI and OHCI, each with its own stick), a USB stick on a scratch image answers a SCSI INQUIRY and
# takes a block write while the keyboard's interrupt transfer stays pending. A
# guest runs in VS-mode under the H extension. With dosfstools installed the
# stick is formatted FAT32, the kernel writes a file on it, and fsck.fat must
# accept the result. A SATA disk behind AHCI and an NVMe namespace each take
# a sector round trip, as does an iSCSI LUN that scripts/iscsi-target.py
# serves through a second guestfwd. Colour bars go up on virtio-gpu over
# PCI and MMIO and on bochs-display (Bochs DISPI registers, no BIOS); the
# PCI GPU's screen is checked.
stick=$(mktemp)
stick_ehci=$(mktemp)
stick_ohci=$(mktemp)
vdisk=$(mktemp)
sata=$(mktemp)
nvdisk=$(mktemp)
iscsi=$(mktemp)
truncate -s 8M "$vdisk" "$sata" "$nvdisk" "$iscsi"
truncate -s 40000K "$stick" "$stick_ehci" "$stick_ohci"
tftp=$(mktemp -d)
echo "hello over UDP" >"$tftp/osmium.txt"
fat_expect=()
if PATH=$PATH:/usr/sbin command -v mkfs.fat >/dev/null && PATH=$PATH:/usr/sbin command -v fsck.fat >/dev/null; then
    PATH=$PATH:/usr/sbin mkfs.fat -F 32 -s 1 "$stick" >/dev/null
    PATH=$PATH:/usr/sbin mkfs.fat -F 32 -s 1 "$stick_ehci" >/dev/null
    PATH=$PATH:/usr/sbin mkfs.fat -F 32 -s 1 "$stick_ohci" >/dev/null
    fat_expect=('\[fat\]   wrote and read back "/osmium/Hello from osmium.txt"')
fi
screen qemu-system-riscv64 640 400 gpu
EXPECT=(
    'ARP: 10.0.2.2 is at'
    'DHCP: 10.0.2.15/24 via 10.0.2.2'
    'ping 10.0.2.2: seq 1 in'
    'TCP echo from 10.0.2.100:7: "hello over TCP"'
    '\[blk\]   virtio-blk .*: 16384 sectors'
    'wrote and read back sector 8192'
    'INQUIRY "QEMU" "QEMU HARDDISK"'
    'interface 0: class 03/01/01'
    'wrote and read back block 79999'
    'keyboard transfer still pending after disk I/O'
    '\[guard\] task "deep" overflowed'
    'nested Breakpoint on the exception stack'
    'user-bad killed: PageFault'
    'user-1 exited with status 0 (kernel sees CPU 1)'
    'hello from process 2'
    '4 of 4 address spaces torn down'
    'hello from a Rust ELF: 46 primes below 200'
    'pid [0-9]* on Osmium/riscv64: brk ok, mmap ok, writev ok'
    'init: fork: pid [0-9]* reaped child [0-9]* (status 7); parent.s memory unchanged: ok'
    'exec.d as "init child" with HOME=/'
    'execve: child [0-9]* exited with status 5; then wait4 says -10'
    'init: fp: exec.d program starts with cleared FP registers: ok'
    'init: fp: FP registers inherited by fork and kept across switches: ok'
    'init: signals: SIGUSR1 sent to myself ran its handler and returned: ok'
    'init: signals: SIGSEGV handled in child [0-9]*, exit status 42: ok'
    'init: signals: SIGCHLD handler ran when child [0-9]* exited: ok'
    'init: threads: thread [0-9]* of process [0-9]* joined with futex; shared counter, thread id, TLS: ok'
    'init: threads: 3 threads slept on a futex, were requeued and woken, and joined: ok'
    'init: threads: exit_group ended a spinning thread, process [0-9]* status 9: ok'
    '1 of 1 init address space torn down'
    '/etc/motd: "welcome to osmium"; /tmp/note ok; / has 5 entries'
    '\[balance\] 8 unpinned tasks spawned on CPU 0 ran on CPUs 0b1111'
    '\[guest\] hello over MMIO'
    '\[guest\] hello over SBI'
    'guest exit Shutdown: 2 hypercalls, 1 halt, [1-9][0-9]* host interrupts, LSR 0x60, DBCN error 0'
    '\[vguest\] timer interrupt after'
    '\[vguest\] PLIC claim 10: received "ping"'
    '\[vguest\] PLIC claim 1: ARP reply, 10.0.2.2 is at 52:55:0a:00:02:02'
    '\[vguest\] virtio-blk: 64 sectors; sector 3 written and read back'
    'the host RAM disk holds the sector the guest wrote'
    'driver guest exit Shutdown'
    '\[smp-guest\] hart 0: got the IPI; hart 1 is stopped'
    'SMP guest: 2 vCPUs on .*hart_start returned 0, hart 1 got opaque 0x1234'
    'xHCI interrupts: [1-9]'
    'FP guests interleaved on one hart: vCPU a0=1 got 12, a0=2 got 14 (expected 12 and 14)'
    '\[usb\]     ecm: ARP: 10.0.2.2 is at'
    '\[usb\]   EHCI at .*, 6 ports'
    'EHCI interrupts: [1-9]'
    '\[usb\]   OHCI at .*, 3 ports'
    'OHCI interrupts: [1-9]'
    '\[ahci\]  port 0 "QEMU HARDDISK": 16384 sectors of 512; round trip Ok(8192)'
    '\[nvme\]  .* "QEMU NVMe Ctrl" namespace 1: 16384 blocks of 512; round trip Ok(8192)'
    '\[iscsi\] 10.0.2.100:3260: "OSMIUM" "iscsi-target.py", 16384 blocks of 512'
    '\[iscsi\] wrote and read back block 8192'
    '\[virtio-gpu\] 640x400 32bpp, stride 2560: colour bars drawn'
    '\[bochs\] 640x480 32bpp, stride 2560: colour bars drawn'
    '\[virtio-gpu-mmio\] 640x400 32bpp, stride 2560: colour bars drawn'
    'DNS: localhost is 127.0.0.1'
    '\[sock\]  10.0.2.15 on the socket stack'
    'net: TCP echo from 10.0.2.100:7 via 10.0.2.15:[0-9]*: sent 18, got "hello over sockets"'
    'net: TCP read after the server closed: 0'
    'net: UDP TFTP from 10.0.2.2:[0-9]*: opcode 3 block 1: "hello over UDP"'
    'net: socketpair: epoll idle 0, ready 1 with data 42; sendmsg 9, recvmsg 9: "ping-pong"'
    'net: UDP loopback: bind 0, sent 5, peeked 5 then read 5 from 127.0.0.1:[0-9]*: "local"'
    '\[sock\]  net exited'
    ${fat_expect[@]+"${fat_expect[@]}"}
)
boot riscv-virt qemu-system-riscv64 riscv64imac-unknown-none-elf \
    -machine virt -bios default -smp 4 -accel tcg,thread=multi \
    -netdev user,id=n0,tftp="$tftp",guestfwd=tcp:10.0.2.100:7-cmd:cat,guestfwd=tcp:10.0.2.100:3260-cmd:"python3 scripts/iscsi-target.py $iscsi" -device virtio-net-device,netdev=n0 \
    -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
    -device usb-ehci,id=ehci -drive if=none,id=stick-ehci,format=raw,file="$stick_ehci" -device usb-storage,bus=ehci.0,drive=stick-ehci \
    -device pci-ohci,id=ohci -drive if=none,id=stick-ohci,format=raw,file="$stick_ohci" -device usb-storage,bus=ohci.0,drive=stick-ohci \
    -drive if=none,id=vd0,format=raw,file="$vdisk" -device virtio-blk-device,drive=vd0 \
    -netdev user,id=n1 -device usb-net,netdev=n1,bus=xhci.0 \
    -drive if=none,id=stick,format=raw,file="$stick" -device usb-storage,bus=xhci.0,drive=stick \
    -device ahci,id=ahci0 -drive if=none,id=sd0,format=raw,file="$sata" -device ide-hd,drive=sd0,bus=ahci0.0 \
    -drive if=none,id=nv0,format=raw,file="$nvdisk" -device nvme,serial=osmium0,drive=nv0 \
    -device virtio-gpu-device -device virtio-gpu-pci,id=gpu -device bochs-display -qmp "unix:$qmp,server=on,wait=off"
screen_wait riscv-virt
if [ "${#fat_expect[@]}" -gt 0 ] && command -v qemu-system-riscv64 >/dev/null; then
    echo "== fsck.fat the USB stick the kernel wrote"
    report=$(PATH=$PATH:/usr/sbin fsck.fat -n -l "$stick") || { echo "$report"; echo "riscv-virt: fsck.fat rejected the USB stick"; exit 1; }
    grep -q "/OSMIUM/Hello from osmium.txt" <<<"$report" || { echo "$report"; echo "riscv-virt: file missing on the USB stick"; exit 1; }
    for extra in "$stick_ehci" "$stick_ohci"; do
        report=$(PATH=$PATH:/usr/sbin fsck.fat -n -l "$extra") || { echo "$report"; echo "riscv-virt: fsck.fat rejected a stick behind EHCI or OHCI"; exit 1; }
        grep -q "/OSMIUM/Hello from osmium.txt" <<<"$report" || { echo "$report"; echo "riscv-virt: file missing on a stick behind EHCI or OHCI"; exit 1; }
    done
fi
rm -f "$stick" "$stick_ehci" "$stick_ohci" "$vdisk" "$sata" "$nvdisk" "$iscsi"
rm -rf "$tftp"
# RISC-V IOMMU: QEMU's riscv-iommu-pci translates the DMA of every PCI device
# on the bus, so this boot carries only an NVMe disk and QEMU's iommu-testdev.
# The test device DMAs through a mapping, to an unmapped address and after
# being detached; the NVMe driver then runs on addresses from an IommuDma
# allocator, with the faults it would cause logged.
if command -v qemu-system-riscv64 >/dev/null && qemu-system-riscv64 -device help 2>&1 | grep -q 'iommu-testdev'; then
    iommu_disk=$(mktemp)
    truncate -s 8M "$iommu_disk"
    EXPECT=(
        '\[iommu\] [0-9a-f:.]* RISC-V IOMMU: Sv39 domains'
        'riscv-iommu: device wrote 0x12345678 through IOVA 0x[0-9a-f]* into physical page PA(0x[0-9a-f]*) (16/16 words)'
        'riscv-iommu: DMA to an unmapped IOVA blocked'
        'riscv-iommu: detached device blocked'
        '\[iommu\] NVMe .* attached to domain 1'
        '\[nvme\]  .* "QEMU NVMe Ctrl" namespace 1: 16384 blocks of 512. round trip Ok(8192)'
        '\[iommu\] NVMe detached: Ok(()), 0 faults logged'
    )
    boot riscv-virt qemu-system-riscv64 riscv64imac-unknown-none-elf \
        -machine virt -bios default -smp 4 -accel tcg,thread=multi \
        -device riscv-iommu-pci -device iommu-testdev \
        -drive if=none,id=nv0,format=raw,file="$iommu_disk" -device nvme,serial=osmium0,drive=nv0
    rm -f "$iommu_disk"
else
    echo "== QEMU lacks riscv-iommu-pci or iommu-testdev; skipping the RISC-V IOMMU boot"
fi
EXPECT=(
    '\[guard\] task "deep" overflowed'
    'nested Breakpoint on the exception stack'
    'user-bad killed: PageFault'
    'user-1 exited with status 0 (kernel sees CPU 1)'
    'hello from process 2'
    '4 of 4 address spaces torn down'
    'hello from a Rust ELF: 46 primes below 200'
    'pid [0-9]* on Osmium/aarch64: brk ok, mmap ok, writev ok'
    'init: fork: pid [0-9]* reaped child [0-9]* (status 7); parent.s memory unchanged: ok'
    'exec.d as "init child" with HOME=/'
    'execve: child [0-9]* exited with status 5; then wait4 says -10'
    'init: fp: exec.d program starts with cleared FP registers: ok'
    'init: fp: FP registers inherited by fork and kept across switches: ok'
    'init: signals: SIGUSR1 sent to myself ran its handler and returned: ok'
    'init: signals: SIGSEGV handled in child [0-9]*, exit status 42: ok'
    'init: signals: SIGCHLD handler ran when child [0-9]* exited: ok'
    'init: threads: thread [0-9]* of process [0-9]* joined with futex; shared counter, thread id, TLS: ok'
    'init: threads: 3 threads slept on a futex, were requeued and woken, and joined: ok'
    'init: threads: exit_group ended a spinning thread, process [0-9]* status 9: ok'
    '1 of 1 init address space torn down'
    '/etc/motd: "welcome to osmium"; /tmp/note ok; / has 5 entries'
    '\[balance\] 8 unpinned tasks spawned on CPU 0 ran on CPUs 0b1111'
)
boot aarch64-virt qemu-system-aarch64 aarch64-unknown-none-softfloat \
    -machine virt,gic-version=2 -cpu cortex-a72 -smp 4 -accel tcg,thread=multi
# Arm SMMUv3 in front of the PCI bus (virt,iommu=smmuv3), with QEMU's
# iommu-testdev: stage-2 translation of the test device's DMA, a blocked
# unmapped address and a blocked detached device.
if command -v qemu-system-aarch64 >/dev/null && qemu-system-aarch64 -device help 2>&1 | grep -q 'iommu-testdev'; then
    EXPECT=(
        '\[iommu\] SMMUv3 at 0x[0-9a-f]*: 44 bit I/O addresses'
        'smmuv3: device wrote 0x12345678 through IOVA 0x[0-9a-f]* into physical page PA(0x[0-9a-f]*) (16/16 words)'
        'smmuv3: DMA to an unmapped IOVA blocked'
        'smmuv3: detached device blocked'
    )
    boot aarch64-virt qemu-system-aarch64 aarch64-unknown-none-softfloat \
        -machine virt,gic-version=2,iommu=smmuv3 -cpu cortex-a72 -smp 4 -accel tcg,thread=multi \
        -device iommu-testdev
else
    echo "== QEMU lacks iommu-testdev; skipping the SMMUv3 boot"
fi
# The VESA BIOS sets the mode through a real-mode thunk, then virtio-vga's
# virtio-gpu side takes over the screen, which is checked. An NVMe controller
# (on a null block device) raises its admin completions as MSI-X interrupts.
# A USB stick behind a UHCI controller (I/O ports) gets the same block write
# and, with dosfstools, the same FAT32 file as riscv-virt's sticks, as does
# a high-speed stick on an ICH9 EHCI controller. The full-speed usb-net on
# that EHCI is handed to one of its three companion UHCI controllers, which
# resolves ARP through it.
stick_uhci=$(mktemp)
stick_ehci=$(mktemp)
truncate -s 40000K "$stick_uhci" "$stick_ehci"
for s in "$stick_uhci" "$stick_ehci"; do
    [ "${#fat_expect[@]}" -eq 0 ] || PATH=$PATH:/usr/sbin mkfs.fat -F 32 -s 1 "$s" >/dev/null
done
screen qemu-system-x86_64 640 400
EXPECT=(
    '\[guard\] task "deep" overflowed'
    'user-bad killed: PageFault'
    'user-1 exited with status 0 (kernel sees CPU 1)'
    'user-2 exited with status 0'
    '\[uart\]  COM1 IRQ 4'
    'hello from process 2'
    '4 of 4 address spaces torn down'
    'hello from a Rust ELF: 46 primes below 200'
    'pid [0-9]* on Osmium/x86_64: brk ok, mmap ok, writev ok'
    'init: fork: pid [0-9]* reaped child [0-9]* (status 7); parent.s memory unchanged: ok'
    'exec.d as "init child" with HOME=/'
    'execve: child [0-9]* exited with status 5; then wait4 says -10'
    'init: fp: exec.d program starts with cleared FP registers: ok'
    'init: fp: FP registers inherited by fork and kept across switches: ok'
    'init: signals: SIGUSR1 sent to myself ran its handler and returned: ok'
    'init: signals: SIGSEGV handled in child [0-9]*, exit status 42: ok'
    'init: signals: SIGCHLD handler ran when child [0-9]* exited: ok'
    'init: threads: thread [0-9]* of process [0-9]* joined with futex; shared counter, thread id, TLS: ok'
    'init: threads: 3 threads slept on a futex, were requeued and woken, and joined: ok'
    'init: threads: exit_group ended a spinning thread, process [0-9]* status 9: ok'
    '1 of 1 init address space torn down'
    '/etc/motd: "welcome to osmium"; /tmp/note ok; / has 5 entries'
    '\[balance\] 8 unpinned tasks spawned on CPU 0 ran on CPUs 0b1111'
    '\[vesa\]  VBE 3.0, .* set mode 0x[0-9a-f]*: 800x600 32bpp at'
    '\[vesa\]  DISPI 0xb0c5 reads back the BIOS.s mode'
    '\[vesa\] 800x600 32bpp, stride 3200: colour bars drawn'
    '\[virtio-vga\] DISPI 0xb0c5: firmware left 800x600 32bpp'
    '\[virtio-vga\] 640x400 32bpp, stride 2560: colour bars drawn'
    '\[msi\]   nvme MSI-X vector 0x50 delivered to APIC'
    '\[msi\]   masked entry 0 held an IDENTIFY completion pending in the PBA; unmasking delivered it'
    '\[msi\]   nvme completions by interrupt: 512 KiB read in commands of up to [0-9]* KiB, up to [0-9]* in flight, [1-9][0-9]* interrupts'
    '\[usb\]   UHCI at .*, 2 ports'
    'UHCI interrupts: [1-9]'
    '\[usb\]   EHCI at .*, 6 ports'
    'EHCI interrupts: [1-9]'
    '\[usb\]   port [0-9]: handed to a companion controller'
    '\[usb\]     ecm: ARP: 10.0.2.2 is at'
    '\[usb\]     mass storage: INQUIRY "QEMU" "QEMU HARDDISK"'
    '\[usb\]     disk: wrote and read back block 79999'
    ${fat_expect[@]+"${fat_expect[@]}"}
)
boot x86_64-pc qemu-system-x86_64 x86_64-unknown-none \
    -machine q35 -cpu max -smp 4 -accel tcg,thread=multi -display none -no-reboot \
    -vga none -device virtio-vga -qmp "unix:$qmp,server=on,wait=off" \
    -blockdev driver=null-co,node-name=nv0,read-zeroes=on -device nvme,serial=osmium1,drive=nv0 \
    -device piix3-usb-uhci,id=uhci -drive if=none,id=stick-uhci,format=raw,file="$stick_uhci" -device usb-storage,bus=uhci.0,drive=stick-uhci \
    -device ich9-usb-ehci1,id=ehci -device ich9-usb-uhci1,masterbus=ehci.0,firstport=0 \
    -device ich9-usb-uhci2,masterbus=ehci.0,firstport=2 -device ich9-usb-uhci3,masterbus=ehci.0,firstport=4 \
    -drive if=none,id=stick-ehci,format=raw,file="$stick_ehci" -device usb-storage,bus=ehci.0,drive=stick-ehci \
    -netdev user,id=n1 -device usb-net,netdev=n1,bus=ehci.0
screen_wait x86_64-pc
if [ "${#fat_expect[@]}" -gt 0 ] && command -v qemu-system-x86_64 >/dev/null; then
    for s in "$stick_uhci" "$stick_ehci"; do
        report=$(PATH=$PATH:/usr/sbin fsck.fat -n -l "$s") || { echo "$report"; echo "x86_64-pc: fsck.fat rejected a stick behind UHCI or EHCI"; exit 1; }
        grep -q "/OSMIUM/Hello from osmium.txt" <<<"$report" || { echo "$report"; echo "x86_64-pc: file missing on a stick behind UHCI or EHCI"; exit 1; }
    done
fi
rm -f "$stick_uhci" "$stick_ehci"

# Intel VT-d and AMD-Vi, each in front of QEMU's iommu-testdev (the DMAR or
# IVRS table says where the unit is): a DMA through a mapping reaches memory,
# one to an unmapped address and one after detaching are blocked. QEMU's AMD
# model translates DMA only with dma-remap=on.
if command -v qemu-system-x86_64 >/dev/null && qemu-system-x86_64 -device help 2>&1 | grep -q 'iommu-testdev'; then
    EXPECT=(
        '\[iommu\] VT-d unit at 0xfed90000: 48 bit I/O addresses'
        'vt-d: device wrote 0x12345678 through IOVA 0x[0-9a-f]* into physical page PA(0x[0-9a-f]*) (16/16 words)'
        'vt-d: DMA to an unmapped IOVA blocked'
        'vt-d: detached device blocked'
    )
    boot x86_64-pc qemu-system-x86_64 x86_64-unknown-none \
        -machine q35 -cpu max -smp 4 -accel tcg,thread=multi -display none -no-reboot \
        -device intel-iommu,aw-bits=48 -device iommu-testdev
    EXPECT=(
        '\[iommu\] AMD-Vi unit at 0xfed80000: 48 bit I/O addresses'
        'amd-vi: device wrote 0x12345678 through IOVA 0x[0-9a-f]* into physical page PA(0x[0-9a-f]*) (16/16 words)'
        'amd-vi: DMA to an unmapped IOVA blocked'
        'amd-vi: detached device blocked'
    )
    boot x86_64-pc qemu-system-x86_64 x86_64-unknown-none \
        -machine q35 -cpu max -smp 4 -accel tcg,thread=multi -display none -no-reboot \
        -device amd-iommu,dma-remap=on -device iommu-testdev
else
    echo "== QEMU lacks iommu-testdev; skipping the x86 IOMMU boots"
fi

# Heap-free M-mode firmware (no OpenSBI): checked for its own lines, since it
# runs none of the scheduler demos.
if command -v qemu-system-riscv64 >/dev/null; then
    echo "== boot examples/riscv-firmware under QEMU"
    fwlog=$(mktemp)
    (cd examples/riscv-firmware && cargo build -q --release)
    run_qemu "riscv-firmware" "$fwlog" 60 qemu-system-riscv64 -machine virt -bios none -smp 1 -m 128M -nographic \
        -kernel examples/riscv-firmware/target/riscv64imac-unknown-none-elf/release/riscv-firmware
    expect "riscv-firmware" "$fwlog" 'awaited 5 timer interrupts' 'console task:' 'all tasks finished'
    rm -f "$fwlog"
fi

# RISC-V hypervisor booting a whole guest kernel: the riscv-virt kernel
# built above runs in VS-mode under riscv-hyp (QEMU's loader places the ELF
# raw in host RAM), with one vCPU on each of two host harts, a virtio-blk
# disk over a host RAM disk, and a virtio-net card bridged to the host's
# QEMU user network (DHCP, ping, the TCP echo and an iSCSI LUN all from
# inside the guest).
# Guest lines carry a "| " prefix.
if command -v qemu-system-riscv64 >/dev/null; then
    echo "== boot examples/riscv-virt as a guest of examples/riscv-hyp under QEMU"
    nestlog=$(mktemp)
    nestiscsi=$(mktemp)
    truncate -s 8M "$nestiscsi"
    (cd examples/riscv-hyp && cargo build -q --release)
    run_qemu "riscv-hyp" "$nestlog" 120 qemu-system-riscv64 -machine virt -bios default -smp 2 -accel tcg,thread=multi -m 512M -nographic \
        -kernel examples/riscv-hyp/target/riscv64imac-unknown-none-elf/release/riscv-hyp \
        -device loader,file=examples/riscv-virt/target/riscv64imac-unknown-none-elf/release/riscv-virt,addr=0x98000000,force-raw=on \
        -netdev user,id=n0,guestfwd=tcp:10.0.2.100:7-cmd:cat,guestfwd=tcp:10.0.2.100:3260-cmd:"python3 scripts/iscsi-target.py $nestiscsi" \
        -device virtio-net-device,netdev=n0
    expect "riscv-hyp" "$nestlog" 'guest kernel: [0-9]* KiB loaded, entry 0x80200000' '| osmium riscv-virt example (hart 0)' \
        '| \[mmu\]   Sv39 on' '| \[mutex\] 4 tasks x 1000 increments across yields = 4000' '| \[preempt\]' \
        '| \[smp\]   2 CPUs online' '| \[smp\]   migrating task visited CPUs \[0, 1, 0\]' \
        '| \[balance\] 4 unpinned tasks spawned on CPU 0 ran on CPUs 0b11' \
        '| \[net\]   DHCP: 10.0.2.15/24 via 10.0.2.2' '| \[net\]   ping 10.0.2.2: seq 1 in' \
        '| \[net\]   TCP echo from 10.0.2.100:7: "hello over TCP"' \
        '| \[iscsi\] 10.0.2.100:3260: "OSMIUM" "iscsi-target.py", 16384 blocks of 512' \
        '| \[iscsi\] wrote and read back block 8192' \
        '| \[blk\]   virtio-blk (1.x) at 0x10001000: 8192 sectors; wrote and read back sector 4096' \
        "the host RAM disk holds the guest's write to sector 4096" \
        '| \[user\]  user-elf exited with status 0' '| \[user\]  init and its children reaped' \
        '| \[hyp\]   no H extension in riscv,isa: skipping the guests' '| \[done\]' 'guest exit Shutdown' \
        'fp: the kernel does not offer FP'
    rm -f "$nestlog" "$nestiscsi"
    # On a hart with Ssaia the hypervisor first runs a guest with an emulated
    # APLIC (MSI delivery) and IMSIC: it enables the interrupt file through
    # siselect/sireg and claims three interrupts with stopei, all completed
    # by the hypervisor (virtual-instruction traps). Needs a QEMU with Ssaia.
    if timeout 2 qemu-system-riscv64 -machine virt -cpu rv64,ssaia=true -nographic -S -monitor none -serial none >/dev/null 2>&1 || [ $? -eq 124 ]; then
        echo "== boot examples/riscv-hyp with an APLIC and IMSIC guest under QEMU"
        aialog=$(mktemp)
        run_qemu "riscv-hyp (AIA)" "$aialog" 60 qemu-system-riscv64 -machine virt -bios default -cpu rv64,ssaia=true -smp 2 -m 512M -nographic \
            -kernel examples/riscv-hyp/target/riscv64imac-unknown-none-elf/release/riscv-hyp
        expect "riscv-hyp (AIA)" "$aialog" '| \[guest\] AIA UART interrupt, received: ping' \
            'AIA guest exit Shutdown: eie0 0x2a0, APLIC domaincfg 0x[0-9a-f]*80000104; stopei claimed 0x50005 (APLIC setipnum), 0x70007 (IMSIC page write), 0x90009 (UART via APLIC), then 0x0'
        rm -f "$aialog"
    else
        echo "== QEMU lacks the Ssaia CPU option; skipping the riscv-hyp APLIC/IMSIC boot"
    fi
fi

# EL2 hypervisor (QEMU starts it at EL2 with virtualization=on): checked for
# its own lines, since it runs none of the scheduler demos.
if command -v qemu-system-aarch64 >/dev/null; then
    echo "== boot examples/aarch64-hyp under QEMU"
    hyplog=$(mktemp)
    (cd examples/aarch64-hyp && cargo build -q --release)
    run_qemu "aarch64-hyp" "$hyplog" 60 qemu-system-aarch64 -machine virt,virtualization=on,gic-version=2 -cpu max -smp 2 -m 128M -nographic \
        -kernel examples/aarch64-hyp/target/aarch64-unknown-none-softfloat/release/aarch64-hyp
    expect "aarch64-hyp" "$hyplog" 'example (EL2)' 'EL2 MMU on' '\[guest\] hello from EL1 over MMIO' \
        'guest exit Shutdown: 1 hypercall, 1 halt, 0 host interrupts, LSR 0x60' \
        '\[guest\] UART interrupt, received: ping' \
        'vGIC guest exit Shutdown: INTID 27 (timer) then INTID 33 (UART), [0-9]* halts, [0-9]* timer exits' \
        'FP guests interleaved on one CPU: vCPU x0=1 got 12, x0=2 got 14 (expected 12 and 14)' \
        '2 CPUs online at EL2' '\[smp-guest\] cpu 0: got the SGI in guest code; cpu 1 is off' \
        'vCPU 0 kicked out of guest code by a host SGI [1-9]' \
        'SMP guest: 2 vCPUs on host CPUs 0 and 1; CPU_ON returned 0, cpu 1 got context 0x1234, IAR 0x401' '\[done\]'
    rm -f "$hyplog"
    # On a GICv3 host the hypervisor also runs guests that use an emulated
    # GICv3 (distributor and redistributors in software, the CPU interface
    # through list registers; ICC_SGI1R_EL1 writes trap), on one vCPU and on
    # two, next to the GICv2 guests above.
    echo "== boot examples/aarch64-hyp on a GICv3 host under QEMU"
    hyplog=$(mktemp)
    run_qemu "aarch64-hyp (GICv3)" "$hyplog" 60 qemu-system-aarch64 -machine virt,virtualization=on,gic-version=3 -cpu max -smp 2 -m 128M -nographic \
        -kernel examples/aarch64-hyp/target/aarch64-unknown-none-softfloat/release/aarch64-hyp
    expect "aarch64-hyp (GICv3)" "$hyplog" 'physical GICv3 (distributor/redistributors) at' '2 CPUs online at EL2' \
        'vGIC guest exit Shutdown: INTID 27 (timer) then INTID 33 (UART), [0-9]* halts, [0-9]* timer exits' \
        '\[guest\] GICv3 UART interrupt, received: ping' \
        'vGICv3 guest exit Shutdown: MPIDR 0x80000000, INTID 3 (SGI via ICC_SGI1R), INTID 27 (timer) then INTID 33 (UART)' \
        '\[smp-guest\] cpu 1: up, sending cpu 0 SGI 1 with ICC_SGI1R_EL1, turning off' \
        '\[smp-guest\] cpu 0: got the SGI in guest code; cpu 1 is off' \
        'SMP GICv3 guest: 2 vCPUs on host CPUs 0 and 1; CPU_ON returned 0, cpu 1 got context 0x1234, IAR 0x1' '\[done\]'
    rm -f "$hyplog"
    # The same hypervisor booting the aarch64-virt kernel built above as a
    # two-vCPU EL1 guest (QEMU's loader places the ELF raw in host RAM).
    echo "== boot examples/aarch64-virt as a guest of examples/aarch64-hyp under QEMU"
    nestlog=$(mktemp)
    run_qemu "aarch64-hyp (guest kernel)" "$nestlog" 120 qemu-system-aarch64 -machine virt,virtualization=on,gic-version=2 -cpu max -smp 2 \
        -accel tcg,thread=multi -m 512M -nographic \
        -kernel examples/aarch64-hyp/target/aarch64-unknown-none-softfloat/release/aarch64-hyp \
        -device loader,file=examples/aarch64-virt/target/aarch64-unknown-none-softfloat/release/aarch64-virt,addr=0x58000000,force-raw=on
    expect "aarch64-hyp (guest kernel)" "$nestlog" 'guest kernel: [0-9]* KiB loaded, entry 0x40200000, 2 vCPUs' '| osmium aarch64-virt example (EL1)' \
        '| \[uart\]  pl011 at 0x9000000' 'virtual timer is INTID 27; PSCI via Hvc' '| \[smp\]   2 CPUs online' \
        '| \[mutex\] 4 tasks x 1000 increments across yields = 4000' '| \[preempt\]' \
        '| \[smp\]   migrating task visited CPUs \[0, 1, 0\]' '| \[balance\] 4 unpinned tasks spawned on CPU 0 ran on CPUs 0b11' \
        '| \[user\]  user-elf exited with status 0' '| \[user\]  init and its children reaped' '| \[done\]' \
        'fp: FP registers inherited by fork and kept across switches: ok' 'guest exit Shutdown'
    rm -f "$nestlog"
fi

# AMD SVM hypervisor (QEMU's TCG implements SVM with nested paging).
if command -v qemu-system-x86_64 >/dev/null; then
    echo "== boot examples/x86_64-hyp under QEMU"
    svmlog=$(mktemp)
    (cd examples/x86_64-hyp && cargo build -q --release)
    run_qemu "x86_64-hyp" "$svmlog" 60 qemu-system-x86_64 -machine q35 -cpu max -smp 2 -m 128M -nographic -no-reboot -display none \
        -kernel examples/x86_64-hyp/target/x86_64-unknown-none/release/x86_64-hyp
    expect "x86_64-hyp" "$svmlog" 'SVM on, nested paging' '\[guest\] hello from SVM over port I/O' \
        '\[guest\] and over MMIO (nested page faults)' '\[guest\] IRQ 4 through the 8259 PIC, received: k' \
        '\[guest\] 5 ticks from the 8254 PIT on IRQ 0' \
        'guest exit Shutdown: 1 hypercall, LSR 0x60 (port) 0x60 (MMIO)' \
        "\\[guest\\] 64-bit, paging on, MMIO through the guest's page tables" \
        '\[guest\] 3 local APIC timer interrupts through a 64-bit IDT' \
        '\[guest\] COM1 IRQ 4 through the I/O APIC, received: z' \
        '64-bit guest exit Shutdown, LSR 0x60 in r12' \
        'SSE guests interleaved on one CPU: vCPU edi=1 got 12, edi=2 got 14 (expected 12 and 14)' \
        '\[smp-guest\] cpu 1: up in real mode at 0x8000 after INIT/STARTUP' \
        '\[smp-guest\] cpu 0: IPI 0x41 from cpu 1 through the local APICs' \
        'SMP guest done: 2 vCPUs on host CPUs 0 and 1, [1-9]' '\[done\]'
    rm -f "$svmlog"
    # The same hypervisor booting the x86_64-pc kernel built above as a
    # two-vCPU PVH guest (QEMU's loader places the ELF raw in host RAM).
    echo "== boot examples/x86_64-pc as a guest of examples/x86_64-hyp under QEMU"
    nestlog=$(mktemp)
    run_qemu "x86_64-hyp (guest kernel)" "$nestlog" 120 qemu-system-x86_64 -machine q35 -cpu max -smp 2 -accel tcg,thread=multi -m 512M -nographic \
        -no-reboot -display none -kernel examples/x86_64-hyp/target/x86_64-unknown-none/release/x86_64-hyp \
        -device loader,file=examples/x86_64-pc/target/x86_64-unknown-none/release/x86_64-pc,addr=0x18000000,force-raw=on
    expect "x86_64-hyp (guest kernel)" "$nestlog" 'guest kernel: [0-9]* KiB loaded, PVH entry 0x[0-9a-f]*, 2 vCPUs' '| osmium x86_64-pc example' \
        '| \[acpi\]  MADT lists 2 enabled CPUs' '| \[smp\]   2 CPUs online' \
        '| \[mutex\] 4 tasks x 1000 increments across yields = 4000' '| \[preempt\]' \
        '| \[smp\]   migrating task visited CPUs \[0, 1, 0\]' '| \[balance\] 4 unpinned tasks spawned on CPU 0 ran on CPUs 0b11' \
        '| \[user\]  user-elf exited with status 0' '| \[user\]  init and its children reaped' \
        '| \[uart\]  interrupt-driven input: "hello from the host"' '| \[done\]' 'guest powered off' \
        'fp: FP registers inherited by fork and kept across switches: ok'
    rm -f "$nestlog"
fi

# Intel VMX hypervisor: needs KVM with nested virtualization (TCG has no VMX).
if command -v qemu-system-x86_64 >/dev/null && [ -r /dev/kvm ] && [ -w /dev/kvm ] \
    && grep -qx '[Y1]' /sys/module/kvm_intel/parameters/nested 2>/dev/null; then
    # The SVM hypervisor on an Intel CPU picks VMX: the same demos, then the
    # x86_64-pc kernel as a two-vCPU guest. Nested exits are slow, so allow time.
    echo "== boot examples/x86_64-hyp on VMX under QEMU/KVM"
    hyplog=$(mktemp)
    run_qemu "x86_64-hyp on VMX" "$hyplog" 150 qemu-system-x86_64 -machine q35 -accel kvm -cpu host -smp 2 -m 128M -nographic -no-reboot -display none \
        -kernel examples/x86_64-hyp/target/x86_64-unknown-none/release/x86_64-hyp
    expect "x86_64-hyp on VMX" "$hyplog" 'VMX on: EPT, VPID and unrestricted guest' '\[guest\] hello from SVM over port I/O' \
        'guest exit Shutdown: 1 hypercall, LSR 0x60 (port) 0x60 (MMIO)' \
        '\[guest\] 3 local APIC timer interrupts through a 64-bit IDT' \
        '\[guest\] COM1 IRQ 4 through the I/O APIC, received: z' \
        'SSE guests interleaved on one CPU: vCPU edi=1 got 12, edi=2 got 14 (expected 12 and 14)' \
        'vCPU moved from host CPU 0 to 1 between runs, SSE result 12 (expected 12)' \
        '\[smp-guest\] cpu 0: IPI 0x41 from cpu 1 through the local APICs' '\[done\]'
    rm -f "$hyplog"
    echo "== boot examples/x86_64-pc as a guest of examples/x86_64-hyp on VMX under QEMU/KVM"
    hyplog=$(mktemp)
    run_qemu "x86_64-hyp on VMX (guest kernel)" "$hyplog" 300 qemu-system-x86_64 -machine q35 -accel kvm -cpu host -smp 2 -m 512M -nographic \
        -no-reboot -display none -kernel examples/x86_64-hyp/target/x86_64-unknown-none/release/x86_64-hyp \
        -device loader,file=examples/x86_64-pc/target/x86_64-unknown-none/release/x86_64-pc,addr=0x18000000,force-raw=on
    expect "x86_64-hyp on VMX (guest kernel)" "$hyplog" 'guest kernel: [0-9]* KiB loaded, PVH entry 0x[0-9a-f]*, 2 vCPUs' '| osmium x86_64-pc example' \
        '| \[smp\]   2 CPUs online' '| \[mutex\] 4 tasks x 1000 increments across yields = 4000' \
        '| \[user\]  user-elf exited with status 0' '| \[user\]  init and its children reaped' \
        '| \[uart\]  interrupt-driven input: "hello from the host"' '| \[done\]' 'guest powered off'
    rm -f "$hyplog"
else
    echo "== skipping x86_64-hyp on VMX: needs /dev/kvm and nested VMX"
fi

# UEFI application on OVMF (x86_64) and AAVMF (AArch64): GOP sets a mode and
# the app draws on its framebuffer, or with Blt where virtio-gpu's GOP has
# none; the screens are checked.
uefi() {
    local arch=$1 qemu=$2 boot_efi=$3 width=$4 height=$5
    shift 5
    command -v "$qemu" >/dev/null || { echo "== $qemu not found; skipping UEFI $arch"; return; }
    echo "== boot examples/uefi ($arch) under QEMU"
    (cd examples/uefi && cargo build -q --release --target "$arch-unknown-uefi")
    local esp log
    esp=$(mktemp -d)
    log=$(mktemp)
    mkdir -p "$esp/EFI/BOOT"
    cp "examples/uefi/target/$arch-unknown-uefi/release/uefi.efi" "$esp/EFI/BOOT/$boot_efi"
    screen "$qemu" "$width" "$height"
    run_qemu "uefi ($arch)" "$log" 120 "$qemu" "$@" -m 256M -nographic -display none -no-reboot \
        -drive if=none,id=esp,format=raw,file="fat:rw:$esp" -device virtio-blk-pci,drive=esp \
        -qmp "unix:$qmp,server=on,wait=off"
    screen_wait "uefi ($arch)"
    expect "uefi ($arch)" "$log" '\[gop\] .*colour bars drawn' '\[done\]  shutting down'
    rm -rf "$esp" "$log"
}
ovmf=
for f in /usr/share/ovmf/OVMF.fd /usr/share/qemu/OVMF.fd; do
    [ -f "$f" ] && { ovmf=$f; break; }
done
if [ -n "$ovmf" ]; then
    uefi x86_64 qemu-system-x86_64 BOOTX64.EFI 800 600 -machine q35 -bios "$ovmf"
else
    echo "== no OVMF; skipping UEFI x86_64"
fi
aavmf=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd
if [ -f "$aavmf" ] && [ -f /usr/share/AAVMF/AAVMF_VARS.fd ]; then
    vars=$(mktemp)
    cp /usr/share/AAVMF/AAVMF_VARS.fd "$vars"
    uefi aarch64 qemu-system-aarch64 BOOTAA64.EFI 1280 800 -machine virt -cpu cortex-a72 \
        -drive if=pflash,format=raw,readonly=on,file="$aavmf" -drive if=pflash,format=raw,file="$vars" -device virtio-gpu-pci
    rm -f "$vars"
else
    echo "== no AAVMF; skipping UEFI aarch64"
fi

echo "all checks passed"
