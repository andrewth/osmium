#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Linux reads what the driver wrote, and the driver reads what Linux wrote.
//!
//! Boots a Linux kernel under QEMU with a busybox initramfs that mounts the
//! image read-write, lists and checksums every file, makes changes of its own
//! and unmounts; the console must show no btrfs error or warning. In between,
//! `btrfs check` runs on the image and the driver reads Linux's changes and
//! makes more. A volume over several devices is checked by `btrfs check` in
//! the guest, which sees them all (on the host it takes one image only).
//!
//! Opt-in: set `OSMIUM_LINUX_KERNEL` to a bootable x86-64 kernel image and
//! `OSMIUM_LINUX_MODULES` to its `/lib/modules/<version>` directory (with
//! `btrfs` as a module or built in; so may be `virtio_blk` and the checksum
//! algorithms, as in distribution kernels). Needs `qemu-system-x86_64`, a static
//! `busybox`, `zstd`, `cpio`, `md5sum` and btrfs-progs; skipped, with a
//! note, without them.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use osmium_fs::{File, OpenFlags, Vfs};
use osmium_fs_btrfs::BtrfsFs;
use osmium_hal::block::{BlockDevice, BlockError};

#[derive(Clone)]
struct FileDisk {
    file: Arc<std::fs::File>,
    len: u64,
}

impl BlockDevice for FileDisk {
    fn block_size(&self) -> usize {
        512
    }
    fn num_blocks(&self) -> u64 {
        self.len / 512
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.file.read_exact_at(buf, lba * 512).map_err(|_| BlockError::Io)
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.file.write_all_at(buf, lba * 512).map_err(|_| BlockError::Io)
    }
}

fn mount(img: &Path) -> BtrfsFs<FileDisk> {
    let file = std::fs::OpenOptions::new().read(true).write(true).open(img).unwrap();
    let len = file.metadata().unwrap().len();
    let fs = BtrfsFs::mount(FileDisk { file: Arc::new(file), len }, 9).unwrap();
    assert!(!fs.is_read_only());
    fs
}

fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists())
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
}

fn md5(data: &[u8]) -> String {
    let mut child = Command::new("md5sum").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap().split_whitespace().next().unwrap().to_string()
}

fn check(img: &Path) {
    let out = Command::new(tool("btrfs").unwrap())
        .args(["check", "--readonly", "--check-data-csum"])
        .arg(img)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && !text.contains("ERROR"), "btrfs check:\n{text}");
}

fn read_all(f: &dyn File) -> Vec<u8> {
    let mut out = vec![0u8; f.stat().size as usize];
    let mut done = 0;
    while done < out.len() {
        let n = f.read(done as u64, &mut out[done..]).unwrap();
        assert!(n > 0);
        done += n;
    }
    out
}

/// The kernel, its modules directory and the tools, if all are there.
struct Linux {
    kernel: PathBuf,
    initrd: PathBuf,
    qemu: PathBuf,
    /// Whether `fx` (see [`FX`]) is in the initramfs.
    has_fx: bool,
}

/// A static helper for the initramfs: `fx setxattr FILE NAME VALUE`, `fx getxattr FILE NAME`,
/// `fx punch FILE OFFSET LENGTH`, `fx falloc FILE OFFSET LENGTH` (keeping the size).
const FX: &str = r#"
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>
int main(int c, char **v) {
    if (c < 3) return 2;
    if (!strcmp(v[1], "setxattr") && c == 5) return setxattr(v[2], v[3], v[4], strlen(v[4]), 0) ? 1 : 0;
    if (!strcmp(v[1], "getxattr") && c == 4) {
        char b[256];
        ssize_t n = getxattr(v[2], v[3], b, sizeof b);
        if (n < 0) { puts("(none)"); return 0; }
        fwrite(b, 1, n, stdout);
        puts("");
        return 0;
    }
    if ((!strcmp(v[1], "punch") || !strcmp(v[1], "falloc")) && c == 5) {
        int f = open(v[2], O_RDWR);
        int mode = FALLOC_FL_KEEP_SIZE | (v[1][0] == 'p' ? FALLOC_FL_PUNCH_HOLE : 0);
        return f < 0 || fallocate(f, mode, atoll(v[3]), atoll(v[4])) ? 1 : 0;
    }
    return 2;
}
"#;

impl Linux {
    fn new(dir: &Path) -> Option<Self> {
        let (Some(kernel), Some(modules)) =
            (std::env::var_os("OSMIUM_LINUX_KERNEL"), std::env::var_os("OSMIUM_LINUX_MODULES"))
        else {
            eprintln!("OSMIUM_LINUX_KERNEL and OSMIUM_LINUX_MODULES not set; skipping");
            return None;
        };
        let (Some(qemu), Some(busybox)) = (tool("qemu-system-x86_64"), tool("busybox")) else {
            eprintln!("qemu-system-x86_64 or busybox missing; skipping");
            return None;
        };
        tool("btrfs")?;
        // The initramfs: busybox, the btrfs module and its dependencies, an init.
        let root = dir.join("initramfs");
        for d in ["bin", "dev", "proc", "sys", "mnt", "lib"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::copy(busybox, root.join("bin/busybox")).unwrap();
        // A helper for what busybox cannot do (extended attributes, holes), if there is a C compiler.
        let helper = dir.join("fx.c");
        std::fs::write(&helper, FX).unwrap();
        let built = ["cc", "gcc"].iter().find_map(|cc| {
            let ok = Command::new(cc).args(["-static", "-O1", "-o"]).arg(root.join("bin/fx")).arg(&helper).status();
            ok.ok().filter(|s| s.success())
        });
        // btrfs-progs too, with the libraries it needs, for the scripts that make subvolumes.
        if let Some(btrfs) = tool("btrfs") {
            std::fs::copy(&btrfs, root.join("bin/btrfs")).unwrap();
            let ldd = Command::new("ldd").arg(&btrfs).output().unwrap();
            for line in String::from_utf8_lossy(&ldd.stdout).lines() {
                let Some(lib) = line.split_whitespace().find(|w| w.starts_with('/') && w.contains(".so")) else {
                    continue;
                };
                let name = Path::new(lib).file_name().unwrap();
                let dest = if lib.contains("ld-linux") { "lib64" } else { "lib/x86_64-linux-gnu" };
                std::fs::create_dir_all(root.join(dest)).unwrap();
                std::fs::copy(lib, root.join(dest).join(name)).unwrap();
            }
            // The program interpreter, which `ldd` lists without an arrow.
            std::fs::create_dir_all(root.join("lib64")).unwrap();
            let _ = std::fs::copy("/lib64/ld-linux-x86-64.so.2", root.join("lib64/ld-linux-x86-64.so.2"));
        }
        let modules = PathBuf::from(modules);
        let mut insmods = String::new();
        // The virtio block driver and the checksum algorithms too, for kernels that build them as modules.
        let names = [
            "virtio_ring",
            "virtio",
            "virtio_pci_legacy_dev",
            "virtio_pci_modern_dev",
            "virtio_pci",
            "virtio_blk",
            "xor",
            "raid6_pq",
            "libblake2b",
            "crc32c-cryptoapi",
            "xxhash_generic",
            "blake2b_generic",
            "btrfs",
        ];
        for name in names {
            let found = ["drivers/virtio", "drivers/block", "crypto", "lib/raid6", "lib/crypto", "fs/btrfs", "lib"]
                .iter()
                .flat_map(|d| [format!("kernel/{d}/{name}.ko.zst"), format!("kernel/{d}/{name}.ko")])
                .map(|p| modules.join(p))
                .find(|p| p.exists());
            let Some(path) = found else { continue };
            let dest = root.join(format!("lib/{name}.ko"));
            if path.extension().is_some_and(|e| e == "zst") {
                let ok = Command::new("zstd").args(["-d", "-q", "-f", "-o"]).arg(&dest).arg(&path).status().unwrap();
                assert!(ok.success());
            } else {
                std::fs::copy(&path, &dest).unwrap();
            }
            insmods += &format!("insmod /lib/{name}.ko\n");
        }
        let init = format!(
            "#!/bin/busybox sh\n/bin/busybox --install -s /bin\nmount -t proc proc /proc\nmount -t sysfs sys /sys\nmount -t devtmpfs dev /dev\n{insmods}\
             btrfs device scan --all-devices >/dev/null 2>&1\n\
             if head -n 1 /dev/vdb | grep -q '^#check'; then\n  btrfs check --readonly --check-data-csum /dev/vda 2>&1\n  echo \"CHECK-EXIT $?\"\nfi\n\
             if mount -t btrfs /dev/vda /mnt; then\n  echo MOUNTED\n  cd /mnt && sh /dev/vdb\n  cd /\n  umount /mnt && echo UNMOUNTED\nfi\ndmesg | grep -i btrfs\necho LINUX-DONE\npoweroff -f\n"
        );
        std::fs::write(root.join("init"), init).unwrap();
        std::os::unix::fs::PermissionsExt::set_mode(
            &mut std::fs::metadata(root.join("init")).unwrap().permissions(),
            0o755,
        );
        Command::new("chmod").arg("755").arg(root.join("init")).status().unwrap();
        let initrd = dir.join("initrd.cpio");
        let script = format!("cd {} && find . | cpio -o -H newc > {}", root.display(), initrd.display());
        assert!(Command::new("sh").args(["-c", &script]).status().unwrap().success());
        Some(Linux { kernel: kernel.into(), initrd, qemu, has_fx: built.is_some() })
    }

    /// Boots with `img` as `/dev/vda`, runs `script` in its root, and
    /// returns the console output.
    fn run(&self, dir: &Path, img: &Path, script: &str) -> String {
        self.boot(dir, img, script, false)
    }

    /// Like [`Linux::run`], but `script` ends by powering off without
    /// unmounting, so that what it `fsync`ed is only in the fsync log.
    fn crash(&self, dir: &Path, img: &Path, script: &str) -> String {
        self.boot(dir, img, &format!("{script}\necho POWER-OFF\npoweroff -n -f\n"), true)
    }

    fn boot(&self, dir: &Path, img: &Path, script: &str, crash: bool) -> String {
        self.boot_devices(dir, &[img], script, crash)
    }

    /// Boots with the devices `imgs` of one volume as `/dev/vda` and, after
    /// the script's `/dev/vdb`, `/dev/vdc` on. A script whose first line is
    /// `#check` has `btrfs check` look at the volume, with all its devices,
    /// before it is mounted; it prints `CHECK-EXIT` and the exit status.
    fn boot_devices(&self, dir: &Path, imgs: &[&Path], script: &str, crash: bool) -> String {
        let s = dir.join("script.sh");
        let mut body = script.as_bytes().to_vec();
        body.resize(body.len().next_multiple_of(512) + 512, b'\n');
        std::fs::write(&s, body).unwrap();
        let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok();
        let mut cmd = Command::new(&self.qemu);
        cmd.args(["-nographic", "-no-reboot", "-m", "1024", "-smp", "2"])
            .arg("-kernel")
            .arg(&self.kernel)
            .arg("-initrd")
            .arg(&self.initrd)
            .args(["-append", "console=ttyS0 panic=-1 quiet loglevel=4"])
            .arg("-drive")
            .arg(format!("file={},format=raw,if=virtio,cache=unsafe", imgs[0].display()))
            .arg("-drive")
            .arg(format!("file={},format=raw,if=virtio,readonly=on", s.display()));
        for img in &imgs[1..] {
            cmd.arg("-drive").arg(format!("file={},format=raw,if=virtio,cache=unsafe", img.display()));
        }
        if kvm {
            cmd.args(["-enable-kvm", "-cpu", "host"]);
        }
        let out = cmd.stdin(Stdio::null()).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if std::env::var_os("OSMIUM_LINUX_SHOW").is_some() {
            eprintln!("{text}");
        }
        if crash {
            assert!(text.contains("POWER-OFF"), "Linux did not finish:\n{text}");
            assert!(text.contains("MOUNTED"), "Linux could not mount:\n{text}");
            return text;
        }
        assert!(text.contains("LINUX-DONE"), "Linux did not finish:\n{text}");
        assert!(text.contains("MOUNTED") && text.contains("UNMOUNTED"), "Linux could not mount:\n{text}");
        // The one warning that is about the volume's layout, not its state.
        let benign = "space cache v1 is being deprecated";
        let console: String = text.lines().filter(|l| !l.contains(benign)).collect::<Vec<_>>().join("\n");
        for bad in ["BTRFS error", "BTRFS critical", "BTRFS warning", "corrupt", "WARNING:", "Call Trace"] {
            assert!(!console.contains(bad), "Linux said {bad:?}:\n{text}");
        }
        text
    }
}

/// `md5sum` lines printed between `BEGIN` and `END`: checksum by path.
fn sums(text: &str) -> BTreeMap<String, String> {
    let body = text.split("BEGIN-SUMS").nth(1).unwrap().split("END-SUMS").next().unwrap();
    body.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let sum = it.next()?.to_string();
            Some((it.next()?.trim_start_matches("./").to_string(), sum))
        })
        .collect()
}

const SUMS: &str = "echo BEGIN-SUMS\nfind . -type f | sort | xargs md5sum\necho END-SUMS\n";

#[test]
fn linux_round_trip() {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-linux-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(linux) = Linux::new(&dir) else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let Some(mkfs) = tool("mkfs.btrfs") else { return };
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(512 << 20).unwrap();
    assert!(Command::new(mkfs).args(["-q", "-n", "4096"]).arg(&img).status().unwrap().success());

    // The driver writes a tree.
    let mut want: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        vfs.mkdir("/d", 0o755).unwrap();
        vfs.mkdir("/d/e", 0o700).unwrap();
        for (path, data) in [
            ("/small", b"hello, linux\n".to_vec()),
            ("/d/big", pattern(20 << 20, 1)),
            ("/d/e/mid", pattern(300_001, 2)),
            ("/sparse", Vec::new()),
        ] {
            let f = vfs.open(path, OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
            f.write(0, &data).unwrap();
            want.insert(path.trim_start_matches('/').into(), data);
        }
        let s = vfs.open("/sparse", OpenFlags::WRITE, 0).unwrap();
        s.write(10 << 20, b"far out").unwrap();
        let mut sparse = vec![0u8; 10 << 20];
        sparse.extend_from_slice(b"far out");
        want.insert("sparse".into(), sparse);
        let m = vfs.open("/d/e/mid", OpenFlags::WRITE, 0).unwrap();
        m.write(1000, b"patched").unwrap();
        want.get_mut("d/e/mid").unwrap()[1000..1007].copy_from_slice(b"patched");
        for i in 0..400 {
            let path = format!("/d/n{i}");
            vfs.open(&path, OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap().write(0, path.as_bytes()).unwrap();
            want.insert(path.trim_start_matches('/').into(), path.into_bytes());
        }
        for i in (0..400).step_by(4) {
            vfs.unlink(&format!("/d/n{i}")).unwrap();
            want.remove(&format!("d/n{i}"));
        }
        vfs.link("/small", "/d/also-small").unwrap();
        want.insert("d/also-small".into(), want["small"].clone());
        vfs.symlink("d/big", "/link").unwrap();
        vfs.rename("/d/n1", "/renamed").unwrap();
        let moved = want.remove("d/n1").unwrap();
        want.insert("renamed".into(), moved);
        vfs.lookup("/small").unwrap().xattr_set(b"user.k", b"v", osmium_fs::XattrSet::Any).unwrap();
    }
    check(&img);

    // Linux reads it all, checks it, and changes some of it.
    let text = linux.run(
        &dir,
        &img,
        &format!(
            "{SUMS}readlink link\nyes 'from linux' | head -c 3000000 > made-by-linux\necho appended >> small\nrm d/e/mid\nmv renamed d/renamed-by-linux\nmkdir -p x/y\necho deep > x/y/z\nsync\n"
        ),
    );
    let got = sums(&text);
    for (path, data) in &want {
        assert_eq!(got.get(path), Some(&md5(data)), "Linux read {path} differently");
    }
    assert_eq!(got.len(), want.len(), "Linux saw other files: {got:?}");
    assert!(text.contains("d/big"), "Linux readlink");
    check(&img);

    // The driver reads Linux's changes and makes more.
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let made: Vec<u8> = b"from linux\n".iter().copied().cycle().take(3_000_000).collect();
        assert_eq!(read_all(&*vfs.lookup("/made-by-linux").unwrap()), made);
        assert_eq!(read_all(&*vfs.lookup("/small").unwrap()), b"hello, linux\nappended\n");
        assert_eq!(read_all(&*vfs.lookup("/x/y/z").unwrap()), b"deep\n");
        assert!(vfs.lookup("/d/e/mid").is_err());
        let f = vfs.open("/made-by-linux", OpenFlags::WRITE, 0).unwrap();
        f.write(1_000_000, b"OSMIUM").unwrap();
        f.truncate(2_000_000).unwrap();
        vfs.unlink("/x/y/z").unwrap();
        vfs.rmdir("/x/y").unwrap();
        vfs.open("/after", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap().write(0, &pattern(77_777, 5)).unwrap();
    }
    check(&img);
    let text = linux.run(&dir, &img, &format!("{SUMS}ls x\n"));
    let got = sums(&text);
    let mut made: Vec<u8> = b"from linux\n".iter().copied().cycle().take(2_000_000).collect();
    made[1_000_000..1_000_006].copy_from_slice(b"OSMIUM");
    assert_eq!(got.get("made-by-linux"), Some(&md5(&made)));
    assert_eq!(got.get("after"), Some(&md5(&pattern(77_777, 5))));
    assert!(!got.contains_key("x/y/z"));
    check(&img);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn linux_reads_other_layouts() {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-linux2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(linux) = Linux::new(&dir) else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let Some(mkfs) = tool("mkfs.btrfs") else { return };
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let text: Vec<u8> = (0..).flat_map(|i| format!("line {i}\n").into_bytes()).take(700_000).collect();
    std::fs::write(src.join("text"), &text).unwrap();
    std::fs::write(src.join("tiny"), b"tiny").unwrap();
    for args in [
        &["--csum", "xxhash"][..],
        &["-O", "block-group-tree"],
        &["-O", "^free-space-tree"],
        &["-n", "65536", "-d", "dup"],
        &["--compress", "zstd"],
    ] {
        eprintln!("{args:?}");
        let img = dir.join("img");
        let _ = std::fs::remove_file(&img);
        std::fs::File::create(&img).unwrap().set_len(256 << 20).unwrap();
        let ok = Command::new(&mkfs).arg("-q").arg("--rootdir").arg(&src).args(args).arg(&img).status().unwrap();
        assert!(ok.success());
        let mut text = text.clone();
        {
            let fs = mount(&img);
            let vfs = Vfs::new(fs.root());
            let f = vfs.open("/text", OpenFlags::WRITE, 0).unwrap();
            f.write(123_456, b"EDITED BY OSMIUM").unwrap();
            text[123_456..123_472].copy_from_slice(b"EDITED BY OSMIUM");
            f.truncate(600_000).unwrap();
            text.truncate(600_000);
            vfs.open("/tiny", OpenFlags::WRITE, 0).unwrap().write(4, &pattern(20_000, 9)).unwrap();
            vfs.open("/new", OpenFlags::WRITE | OpenFlags::CREATE, 0o644)
                .unwrap()
                .write(0, &pattern(12 << 20, 3))
                .unwrap();
        }
        check(&img);
        let out = linux.run(&dir, &img, &format!("{SUMS}echo linux >> new\nsync\n"));
        let got = sums(&out);
        let mut tiny = b"tiny".to_vec();
        tiny.extend_from_slice(&pattern(20_000, 9));
        assert_eq!(got.get("text"), Some(&md5(&text)), "{args:?}");
        assert_eq!(got.get("tiny"), Some(&md5(&tiny)), "{args:?}");
        assert_eq!(got.get("new"), Some(&md5(&pattern(12 << 20, 3))), "{args:?}");
        check(&img);
        let fs = mount(&img);
        let n = read_all(&*Vfs::new(fs.root()).lookup("/new").unwrap());
        assert_eq!(&n[12 << 20..], b"linux\n");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every file under the directory `dir` of `vfs`: path to contents.
fn read_tree(vfs: &Vfs, dir: &str, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
    let d = vfs.lookup(dir).unwrap();
    for e in (0..).map_while(|i| d.readdir(i).unwrap()) {
        let path = format!("{dir}/{}", e.name);
        let key = format!("{prefix}/{}", e.name);
        if e.kind == osmium_fs::FileKind::Directory {
            read_tree(vfs, &path, &key, out);
        } else {
            out.insert(key, read_all(&*vfs.lookup(&path).unwrap()));
        }
    }
}

/// What the driver sees under each of `subvols`, as paths from the volume's root.
fn read_subvols(fs: &BtrfsFs<FileDisk>, subvols: &[&str]) -> BTreeMap<String, Vec<u8>> {
    let vfs = Vfs::new(fs.root());
    let mut out = BTreeMap::new();
    for s in subvols {
        read_tree(&vfs, &format!("/{s}"), s, &mut out);
    }
    out
}

/// Linux's checksums are the driver's.
fn same_as_linux(text: &str, want: &BTreeMap<String, Vec<u8>>) {
    let got = sums(text);
    for (path, data) in want {
        assert_eq!(got.get(path), Some(&md5(data)), "Linux read {path} differently");
    }
    assert_eq!(got.len(), want.len(), "Linux saw other files");
}

#[test]
fn linux_snapshots() {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-linux3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(linux) = Linux::new(&dir) else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let Some(mkfs) = tool("mkfs.btrfs") else { return };
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(256 << 20).unwrap();
    assert!(Command::new(mkfs).args(["-q", "-n", "4096"]).arg(&img).status().unwrap().success());

    // Linux makes a subvolume, snapshots of it and a snapshot of a snapshot, and
    // changes each of them in turn.
    let text = linux.run(
        &dir,
        &img,
        "btrfs subvolume create sv >/dev/null\nmkdir sv/d\ni=0\nwhile [ $i -lt 1200 ]; do echo \"file number $i\" > sv/d/file-with-a-long-name-$i; i=$((i+1)); done\n\
         yes 'big file' | head -c 3000000 > sv/big\nsync\n\
         btrfs subvolume snapshot sv snap >/dev/null\nsync\n\
         echo changed-in-src > sv/d/file-with-a-long-name-17\nrm sv/d/file-with-a-long-name-5*\nsync\n\
         btrfs subvolume snapshot -r sv rosnap >/dev/null\nsync\n\
         echo changed-in-snap > snap/d/file-with-a-long-name-18\nrm snap/d/file-with-a-long-name-6*\nsync\n\
         btrfs subvolume snapshot snap snap2 >/dev/null\nsync\n\
         echo changed-in-snap2 > snap2/d/file-with-a-long-name-19\nsync\n\
         echo BEGIN-SUMS\nfind sv snap rosnap snap2 -type f | sort | xargs md5sum\necho END-SUMS\n",
    );
    check(&img);
    let all = ["sv", "snap", "rosnap", "snap2"];

    // The driver reads what Linux wrote, then changes it all sorts of ways.
    let mut want;
    {
        let fs = mount(&img);
        want = read_subvols(&fs, &all);
        same_as_linux(&text, &want);
        let vfs = Vfs::new(fs.root());
        let root = vfs.lookup("/").unwrap();
        let dir_of = |s: &str| fs.subvolume_id(&*vfs.lookup(s).unwrap()).unwrap();
        assert!(dir_of("/snap2") > dir_of("/snap"));

        // Writes in the source and the snapshots, over blocks and extents they share.
        let new = pattern(5000, 1);
        let f = vfs.open("/sv/d/file-with-a-long-name-100", OpenFlags::WRITE | OpenFlags::TRUNC, 0).unwrap();
        f.write(0, &new).unwrap();
        want.insert("sv/d/file-with-a-long-name-100".into(), new);
        vfs.unlink("/snap/d/file-with-a-long-name-200").unwrap();
        want.remove("snap/d/file-with-a-long-name-200");
        let patch = pattern(100_000, 2);
        vfs.open("/snap/big", OpenFlags::WRITE, 0).unwrap().write(1_000_000, &patch).unwrap();
        want.get_mut("snap/big").unwrap()[1_000_000..1_100_000].copy_from_slice(&patch);
        vfs.open("/sv/big", OpenFlags::WRITE, 0).unwrap().truncate(1_500_000).unwrap();
        want.get_mut("sv/big").unwrap().truncate(1_500_000);
        vfs.open("/snap2/made-by-osmium", OpenFlags::WRITE | OpenFlags::CREATE, 0o644)
            .unwrap()
            .write(0, &pattern(70_000, 3))
            .unwrap();
        want.insert("snap2/made-by-osmium".into(), pattern(70_000, 3));
        assert_eq!(
            vfs.open("/rosnap/big", OpenFlags::WRITE, 0).and_then(|f| f.write(0, b"no")).err(),
            Some(osmium_fs::Errno::EROFS)
        );

        // Snapshots of those, written to as well.
        fs.create_snapshot(&*vfs.lookup("/snap2").unwrap(), &*root, "drv", false).unwrap();
        fs.create_snapshot(&*vfs.lookup("/sv").unwrap(), &*root, "drvro", true).unwrap();
        for (k, v) in want.clone() {
            if let Some(rest) = k.strip_prefix("snap2/") {
                want.insert(format!("drv/{rest}"), v);
            } else if let Some(rest) = k.strip_prefix("sv/") {
                want.insert(format!("drvro/{rest}"), v);
            }
        }
        let more = pattern(40_000, 4);
        vfs.open("/drv/d/file-with-a-long-name-300", OpenFlags::WRITE | OpenFlags::TRUNC, 0)
            .unwrap()
            .write(0, &more)
            .unwrap();
        want.insert("drv/d/file-with-a-long-name-300".into(), more);
        vfs.unlink("/sv/d/file-with-a-long-name-1").unwrap();
        want.remove("sv/d/file-with-a-long-name-1");

        // Deleting the middle of the chain leaves its neighbours whole.
        fs.delete_subvolume(&*root, "snap").unwrap();
        fs.delete_subvolume(&*root, "rosnap").unwrap();
        want.retain(|k, _| !k.starts_with("snap/") && !k.starts_with("rosnap/"));
        let after = pattern(9000, 5);
        vfs.open("/snap2/d/file-with-a-long-name-400", OpenFlags::WRITE | OpenFlags::TRUNC, 0)
            .unwrap()
            .write(0, &after)
            .unwrap();
        want.insert("snap2/d/file-with-a-long-name-400".into(), after);
        assert!(vfs.lookup("/snap").is_err());
    }
    check(&img);

    // Linux reads all that, changes more, and deletes the source.
    let text = linux.run(
        &dir,
        &img,
        "echo BEGIN-SUMS\nfind sv snap2 drv drvro -type f | sort | xargs md5sum\necho END-SUMS\n\
         echo linux-says > drv/d/file-with-a-long-name-500\n\
         echo more >> snap2/big\n\
         btrfs subvolume snapshot drv drv2 >/dev/null\nsync\n\
         echo in-drv2 > drv2/d/file-with-a-long-name-600\nsync\n\
         btrfs subvolume delete sv >/dev/null\nsync\n",
    );
    same_as_linux(&text, &want);
    check(&img);

    // And the driver reads what Linux did, carries on, and empties the volume.
    {
        let fs = mount(&img);
        let got = read_subvols(&fs, &["snap2", "drv", "drv2", "drvro"]);
        assert_eq!(got["drv/d/file-with-a-long-name-500"], b"linux-says\n");
        assert_eq!(got["drv2/d/file-with-a-long-name-600"], b"in-drv2\n");
        assert!(got["snap2/big"].ends_with(b"more\n"));
        let vfs = Vfs::new(fs.root());
        assert!(vfs.lookup("/sv").is_err());
        vfs.open("/drv2/d/file-with-a-long-name-700", OpenFlags::WRITE | OpenFlags::TRUNC, 0)
            .unwrap()
            .write(0, b"osmium")
            .unwrap();
        let root = vfs.lookup("/").unwrap();
        for s in ["snap2", "drv", "drvro"] {
            fs.delete_subvolume(&*root, s).unwrap();
        }
    }
    check(&img);
    let fs = mount(&img);
    let got = read_subvols(&fs, &["drv2"]);
    assert_eq!(got["drv2/d/file-with-a-long-name-700"], b"osmium");
    assert_eq!(got["drv2/d/file-with-a-long-name-600"], b"in-drv2\n");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Linux's balance moves every tree block, leaving blocks of the subvolumes flagged `RELOC` and owned by the
/// relocation tree, some of them `FULL_BACKREF`; the driver can still change every file across them.
#[test]
fn linux_balance_then_write() {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-linux6-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(linux) = Linux::new(&dir) else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let Some(mkfs) = tool("mkfs.btrfs") else { return };
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    assert!(Command::new(mkfs).args(["-q", "-n", "4096"]).arg(&img).status().unwrap().success());

    // Files in the top subvolume, a subvolume, and snapshots of that, then a balance of it all.
    let text = linux.run(
        &dir,
        &img,
        "mkdir top\ni=0\nwhile [ $i -lt 300 ]; do echo \"top file $i\" > top/file-with-a-long-name-$i; i=$((i+1)); done\n\
         btrfs subvolume create sv >/dev/null\nmkdir sv/d\n\
         i=0\nwhile [ $i -lt 800 ]; do echo \"file number $i\" > sv/d/file-with-a-long-name-$i; i=$((i+1)); done\n\
         yes 'big file' | head -c 1000000 > sv/big\nsync\n\
         btrfs subvolume snapshot sv snap >/dev/null\nsync\n\
         echo changed > sv/d/file-with-a-long-name-17\nsync\n\
         btrfs subvolume snapshot -r sv rosnap >/dev/null\nsync\n\
         btrfs balance start --full-balance . 2>&1 | tail -1\nsync\n\
         btrfs balance start --full-balance . 2>&1 | tail -1\nsync\n\
         echo BEGIN-SUMS\nfind top sv snap rosnap -type f | sort | xargs md5sum\necho END-SUMS\n",
    );
    assert!(text.contains("Done, had to relocate"), "Linux did not balance:\n{text}");
    check(&img);
    if let Some(keep) = std::env::var_os("OSMIUM_LINUX_KEEP") {
        std::fs::copy(&img, keep).unwrap();
    }

    // The driver rewrites every file of each writable subvolume, so every leaf is copied.
    let mut want;
    {
        let fs = mount(&img);
        want = read_subvols(&fs, &["top", "sv", "snap", "rosnap"]);
        same_as_linux(&text, &want);
        let vfs = Vfs::new(fs.root());
        for (path, data) in want.iter_mut() {
            if path.starts_with("rosnap/") {
                continue;
            }
            let f = vfs.open(&format!("/{path}"), OpenFlags::WRITE, 0).unwrap();
            f.write(0, b"OSMIUM").unwrap_or_else(|e| panic!("writing {path}: {e:?}"));
            let n = data.len().min(6);
            data[..n].copy_from_slice(&b"OSMIUM"[..n]);
            data.extend_from_slice(&b"OSMIUM"[n..]);
        }
        for i in (0..800).step_by(7) {
            vfs.unlink(&format!("/snap/d/file-with-a-long-name-{i}")).unwrap();
            want.remove(&format!("snap/d/file-with-a-long-name-{i}"));
        }
        let root = vfs.lookup("/").unwrap();
        fs.delete_subvolume(&*root, "rosnap").unwrap();
        want.retain(|k, _| !k.starts_with("rosnap/"));
    }
    check(&img);
    let text =
        linux.run(&dir, &img, "echo BEGIN-SUMS\nfind top sv snap -type f | sort | xargs md5sum\necho END-SUMS\n");
    same_as_linux(&text, &want);
    let _ = std::fs::remove_dir_all(&dir);
}

/// What the driver writes over several devices `btrfs check` accepts with all of them (which it cannot be given
/// as image files on the host), and Linux reads it; then the driver reads what Linux wrote there.
#[test]
fn linux_checks_multi_device() {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-linux7-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(linux) = Linux::new(&dir) else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let Some(mkfs) = tool("mkfs.btrfs") else { return };
    let mount_all = |imgs: &[PathBuf]| {
        let mut md = osmium_fs_btrfs::MultiDevice::new();
        for img in imgs {
            let file = std::fs::OpenOptions::new().read(true).write(true).open(img).unwrap();
            let len = file.metadata().unwrap().len();
            md.add(FileDisk { file: Arc::new(file), len }).unwrap();
        }
        BtrfsFs::mount_multi(md, 9, osmium_fs_btrfs::MountOptions::default()).unwrap()
    };
    for (d, m, n) in [("raid1", "raid1", 2), ("raid10", "raid10", 4), ("raid1c3", "raid1c3", 3), ("raid0", "raid1", 2)]
    {
        eprintln!("-d {d} -m {m} over {n}");
        let imgs: Vec<PathBuf> = (0..n).map(|i| dir.join(format!("dev{i}"))).collect();
        for img in &imgs {
            std::fs::File::create(img).unwrap().set_len(256 << 20).unwrap();
        }
        let out = Command::new(&mkfs).args(["-q", "-f", "-n", "4096", "-d", d, "-m", m]).args(&imgs).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let mut want: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        {
            let fs = mount_all(&imgs);
            assert!(!fs.is_read_only());
            let vfs = Vfs::new(fs.root());
            vfs.mkdir("/d", 0o755).unwrap();
            for i in 0..300 {
                let (path, data) = (format!("d/f{i}"), pattern(100 + i * 37, i as u8));
                vfs.open(&format!("/{path}"), OpenFlags::WRITE | OpenFlags::CREATE, 0o644)
                    .unwrap()
                    .write(0, &data)
                    .unwrap();
                want.insert(path, data);
            }
            let big = pattern(6 << 20, 7);
            vfs.open("/big", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap().write(0, &big).unwrap();
            want.insert("big".into(), big);
            let patch = pattern(200_000, 8);
            vfs.open("/big", OpenFlags::WRITE, 0).unwrap().write(1_000_000, &patch).unwrap();
            want.get_mut("big").unwrap()[1_000_000..1_200_000].copy_from_slice(&patch);
            for i in (0..300).step_by(5) {
                vfs.unlink(&format!("/d/f{i}")).unwrap();
                want.remove(&format!("d/f{i}"));
            }
        }
        let paths: Vec<&Path> = imgs.iter().map(PathBuf::as_path).collect();
        let text = linux.boot_devices(&dir, &paths, &format!("#check\n{SUMS}echo from-linux > linux\nsync\n"), false);
        assert!(text.contains("CHECK-EXIT 0") && !text.contains("ERROR"), "btrfs check, -d {d} -m {m}:\n{text}");
        same_as_linux(&text, &want);
        let fs = mount_all(&imgs);
        assert_eq!(read_all(&*Vfs::new(fs.root()).lookup("/linux").unwrap()), b"from-linux\n");
        drop(fs);
        let text = linux.boot_devices(&dir, &paths, "#check\n", false);
        assert!(text.contains("CHECK-EXIT 0") && !text.contains("ERROR"), "btrfs check after Linux, -d {d}:\n{text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The listing a script prints to compare two views of one volume: type, size, links, mode and blocks of every
/// path.
const STATS: &str = "echo BEGIN-STAT\nfind . | sort | xargs stat -c '%n %F %s %h %a %b'\necho END-STAT\n";

fn stats(text: &str) -> Vec<String> {
    text.split("BEGIN-STAT").nth(1).unwrap().split("END-STAT").next().unwrap().lines().map(str::to_string).collect()
}

/// Whether the superblock of `img` has a log.
fn has_log(img: &Path) -> bool {
    let out = Command::new(tool("btrfs").unwrap()).args(["inspect-internal", "dump-super"]).arg(img).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = text.lines().find(|l| l.starts_with("log_root\t")).unwrap();
    line.split_whitespace().nth(1) != Some("0")
}

/// Replays the log in `img` twice, once by the driver at mount (`mid` then looks at what it made) and once by
/// Linux on a copy, and checks that `btrfs check` accepts both and that Linux sees the same files in each.
fn compare_replays(linux: &Linux, dir: &Path, img: &Path, extra: &str, mid: impl FnOnce(&Vfs)) {
    assert!(has_log(img), "Linux left no log");
    let linux_img = dir.join("img-linux");
    std::fs::copy(img, &linux_img).unwrap();
    // To look at the log with `btrfs inspect-internal dump-tree`.
    if let Some(keep) = std::env::var_os("OSMIUM_LINUX_KEEP") {
        std::fs::copy(img, keep).unwrap();
    }
    {
        let fs = mount(img);
        let vfs = Vfs::new(fs.root());
        mid(&vfs);
        // The volume is writable.
        vfs.open("/after", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap().write(0, b"after").unwrap();
        vfs.unlink("/after").unwrap();
    }
    assert!(!has_log(img), "the log is cleared");
    check(img);
    // Linux agrees with what the driver made of it, and with what it makes of it itself.
    let ours = linux.run(dir, img, &format!("{SUMS}{STATS}{extra}sync\n"));
    let theirs = linux.run(dir, &linux_img, &format!("{SUMS}{STATS}{extra}sync\n"));
    assert_eq!(sums(&ours), sums(&theirs));
    assert_eq!(stats(&ours), stats(&theirs));
    check(&linux_img);
    check(img);
}

#[test]
fn linux_log_is_replayed() {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-linux5-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(linux) = Linux::new(&dir) else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let Some(mkfs) = tool("mkfs.btrfs") else { return };
    if !linux.has_fx {
        eprintln!("no C compiler for the helper; skipping");
        return;
    }
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("d")).unwrap();
    std::fs::write(src.join("old"), pattern(100_000, 7)).unwrap();
    std::fs::write(src.join("big"), pattern(2_000_000, 9)).unwrap();
    std::fs::write(src.join("trunc"), pattern(200_000, 3)).unwrap();
    std::fs::write(src.join("ren"), b"rename me").unwrap();
    std::fs::write(src.join("d/gone"), b"gone soon").unwrap();
    std::fs::write(src.join("d/stay"), b"stay").unwrap();
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(256 << 20).unwrap();
    assert!(Command::new(mkfs).args(["-q", "--rootdir"]).arg(&src).arg(&img).status().unwrap().success());

    // Linux changes things and loses power; what it fsynced is only in the log.
    let text = linux.crash(
        &dir,
        &img,
        "yes 'new data' | head -c 300000 > newbig\nsync newbig\n\
         mkdir -p nd/sub\necho deep > nd/sub/f\nsync nd/sub/f\n\
         echo appended >> old\nsync old\n\
         dd if=/dev/zero of=big bs=4096 seek=10 count=3 conv=notrunc,fsync 2>/dev/null\n\
         rm d/gone\nsync d\n\
         ln d/stay hl2\nsync hl2\n\
         mv ren renamed\nsync renamed\n\
         truncate -s 50000 trunc\nsync trunc\n\
         chmod 600 d/stay\nsync d/stay\n\
         ln -s old sl\nsync .\n\
         echo xv > fresh\nfx setxattr fresh user.k value1\nsync fresh\n\
         fx punch big 500000 100000\nsync big\n",
    );
    assert!(!text.contains("BTRFS error"), "{text}");
    compare_replays(&linux, &dir, &img, "fx getxattr fresh user.k\n", |vfs| {
        let cycle = |s: &[u8]| s.iter().copied().cycle().take(300_000).collect::<Vec<u8>>();
        assert_eq!(read_all(&*vfs.lookup("/newbig").unwrap()), cycle(b"new data\n"));
        assert_eq!(read_all(&*vfs.lookup("/nd/sub/f").unwrap()), b"deep\n");
        let mut old = pattern(100_000, 7);
        old.extend_from_slice(b"appended\n");
        assert_eq!(read_all(&*vfs.lookup("/old").unwrap()), old);
        let mut big = pattern(2_000_000, 9);
        big[40960..53248].fill(0);
        big[500_000..600_000].fill(0);
        assert_eq!(read_all(&*vfs.lookup("/big").unwrap()), big);
        assert!(vfs.lookup("/d/gone").is_err());
        assert_eq!(read_all(&*vfs.lookup("/hl2").unwrap()), b"stay");
        assert_eq!(read_all(&*vfs.lookup("/d/stay").unwrap()), b"stay");
        assert_eq!(vfs.lookup("/d/stay").unwrap().stat().nlink, 2);
        assert!(vfs.lookup("/ren").is_err());
        assert_eq!(read_all(&*vfs.lookup("/renamed").unwrap()), b"rename me");
        assert_eq!(read_all(&*vfs.lookup("/trunc").unwrap()), pattern(200_000, 3)[..50_000]);
        assert_eq!(vfs.readlink("/sl").unwrap(), "old");
        assert_eq!(read_all(&*vfs.lookup("/fresh").unwrap()), b"xv\n");
        assert_eq!(vfs.lookup("/fresh").unwrap().xattr_get(b"user.k").unwrap(), b"value1");
    });
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn linux_log_is_replayed_more() {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-linux4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(linux) = Linux::new(&dir) else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let Some(mkfs) = tool("mkfs.btrfs") else { return };
    if !linux.has_fx {
        eprintln!("no C compiler for the helper; skipping");
        return;
    }
    let src = dir.join("src");
    for d in ["a", "b", "b/empty", "m"] {
        std::fs::create_dir_all(src.join(d)).unwrap();
    }
    for i in 1..=5 {
        std::fs::write(src.join(format!("a/f{i}")), format!("file {i}")).unwrap();
    }
    std::fs::write(src.join("mid"), pattern(1 << 20, 11)).unwrap();
    std::fs::write(src.join("prealloc"), pattern(10_000, 12)).unwrap();
    std::fs::write(src.join("inline"), b"short").unwrap();
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(256 << 20).unwrap();
    assert!(Command::new(mkfs).args(["-q", "-n", "4096", "--rootdir"]).arg(&src).arg(&img).status().unwrap().success());

    let text = linux.crash(
        &dir,
        &img,
        "mv a/f1 b/f1\nsync b/f1\nsync a\n\
         rm a/f2\nsync a\n\
         rmdir b/empty\nsync b\n\
         dd if=/dev/zero of=mid bs=1000 seek=300 count=5 conv=notrunc,fsync 2>/dev/null\n\
         fx falloc prealloc 20000 100000\nsync prealloc\n\
         echo 'a much longer text than before' > inline\nsync inline\n\
         i=0; while [ $i -lt 400 ]; do echo $i > m/file-with-a-long-name-$i; i=$((i+1)); done\nsync m\n\
         rm m/file-with-a-long-name-7 m/file-with-a-long-name-300\nsync m\n\
         ln -s b/f1 m/link\nsync m\n\
         fx setxattr a/f3 user.one 1\nfx setxattr a/f3 user.two 22\nsync a/f3\n",
    );
    assert!(!text.contains("BTRFS error"), "{text}");
    compare_replays(&linux, &dir, &img, "fx getxattr a/f3 user.one\nfx getxattr a/f3 user.two\n", |vfs| {
        assert_eq!(read_all(&*vfs.lookup("/b/f1").unwrap()), b"file 1");
        assert!(vfs.lookup("/a/f1").is_err());
        assert!(vfs.lookup("/a/f2").is_err());
        assert_eq!(read_all(&*vfs.lookup("/a/f3").unwrap()), b"file 3");
        assert!(vfs.lookup("/b/empty").is_err());
        let mut mid = pattern(1 << 20, 11);
        mid[300_000..305_000].fill(0);
        assert_eq!(read_all(&*vfs.lookup("/mid").unwrap()), mid);
        assert_eq!(vfs.lookup("/prealloc").unwrap().stat().size, 10_000);
        assert_eq!(read_all(&*vfs.lookup("/prealloc").unwrap()), pattern(10_000, 12));
        assert_eq!(read_all(&*vfs.lookup("/inline").unwrap()), b"a much longer text than before\n");
        assert!(vfs.lookup("/m/file-with-a-long-name-7").is_err());
        assert!(vfs.lookup("/m/file-with-a-long-name-300").is_err());
        vfs.lookup("/m/file-with-a-long-name-399").unwrap();
        assert_eq!(vfs.readlink("/m/link").unwrap(), "b/f1");
        assert_eq!(vfs.lookup("/a/f3").unwrap().xattr_get(b"user.two").unwrap(), b"22");
    });
    let _ = std::fs::remove_dir_all(&dir);
}
