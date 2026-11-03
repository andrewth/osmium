#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Linux reads what the driver wrote, and the driver reads what Linux wrote.
//!
//! Boots a Linux kernel under QEMU with a busybox initramfs that mounts the
//! image read-write, lists and checksums every file, makes changes of its own
//! and unmounts; the console must show no btrfs error or warning. In between,
//! `btrfs check` runs on the image and the driver reads Linux's changes and
//! makes more.
//!
//! Opt-in: set `OSMIUM_LINUX_KERNEL` to a bootable x86-64 kernel image and
//! `OSMIUM_LINUX_MODULES` to its `/lib/modules/<version>` directory (with
//! `btrfs` as a module or built in). Needs `qemu-system-x86_64`, a static
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
}

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
        let modules = PathBuf::from(modules);
        let mut insmods = String::new();
        for name in ["xor", "raid6_pq", "libblake2b", "btrfs"] {
            let found = ["crypto", "lib/raid6", "lib/crypto", "fs/btrfs", "lib"]
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
        Some(Linux { kernel: kernel.into(), initrd, qemu })
    }

    /// Boots with `img` as `/dev/vda`, runs `script` in its root, and
    /// returns the console output.
    fn run(&self, dir: &Path, img: &Path, script: &str) -> String {
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
            .arg(format!("file={},format=raw,if=virtio,cache=unsafe", img.display()))
            .arg("-drive")
            .arg(format!("file={},format=raw,if=virtio,readonly=on", s.display()));
        if kvm {
            cmd.args(["-enable-kvm", "-cpu", "host"]);
        }
        let out = cmd.stdin(Stdio::null()).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if std::env::var_os("OSMIUM_LINUX_SHOW").is_some() {
            eprintln!("{text}");
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
