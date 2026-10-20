//! End-to-end tests against images made by `xorriso` and `genisoimage`.
//! Each test is skipped, with a note, if its tool is missing.

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use osmium_fs::{Errno, File, FileKind, OpenFlags, Vfs};
use osmium_fs_iso9660::{IsoFs, Names};
use osmium_hal::block::{BlockDevice, BlockError};

/// An image in memory, read in `block`-byte blocks.
struct MemDisk {
    bytes: Arc<Vec<u8>>,
    block: usize,
}

impl BlockDevice for MemDisk {
    fn block_size(&self) -> usize {
        self.block
    }
    fn num_blocks(&self) -> u64 {
        (self.bytes.len() / self.block) as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let off = lba as usize * self.block;
        buf.copy_from_slice(&self.bytes[off..off + buf.len()]);
        Ok(())
    }
    fn write_blocks(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
}

fn tool(name: &str) -> Option<PathBuf> {
    let found = ["/usr/bin", "/usr/sbin", "/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists());
    if found.is_none() {
        eprintln!("{name} not found; skipping");
    }
    found
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osmium-fs-iso9660-{}", std::process::id())).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
}

/// A source tree with long names, a multi-block file, links and a
/// directory nested deeper than ISO 9660's eight levels.
fn tree(name: &str) -> PathBuf {
    let src = scratch(name).join("src");
    std::fs::create_dir_all(src.join("docs")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello, iso\n").unwrap();
    std::fs::write(src.join("Mixed Case Long Name.data"), pattern(5000, 1)).unwrap();
    std::fs::write(src.join("docs/big.bin"), pattern(3 << 20, 2)).unwrap();
    std::fs::write(src.join("docs/empty"), b"").unwrap();
    std::fs::set_permissions(src.join("hello.txt"), std::fs::Permissions::from_mode(0o640)).unwrap();
    symlink("hello.txt", src.join("link")).unwrap();
    symlink("/usr/lib/../share/x", src.join("abs")).unwrap();
    let deep = src.join("d1/d2/d3/d4/d5/d6/d7/d8/d9/d10");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("bottom.txt"), b"ten levels down\n").unwrap();
    src
}

/// Runs `cmd` with `args`, writing `out.iso` next to `src`, and loads it.
fn image(cmd: &Path, args: &[&str], src: &Path) -> Arc<Vec<u8>> {
    let iso = src.parent().unwrap().join("out.iso");
    let out = Command::new(cmd).args(args).arg("-o").arg(&iso).arg(src).output().unwrap();
    assert!(out.status.success(), "{}: {}", cmd.display(), String::from_utf8_lossy(&out.stderr));
    Arc::new(std::fs::read(&iso).unwrap())
}

fn mount(bytes: &Arc<Vec<u8>>, block: usize) -> IsoFs<MemDisk> {
    IsoFs::mount(MemDisk { bytes: bytes.clone(), block }, 9).unwrap()
}

fn read_all(f: &dyn File) -> Vec<u8> {
    let mut out = vec![0u8; f.stat().size as usize];
    let mut done = 0;
    while done < out.len() {
        let n = f.read(done as u64, &mut out[done..]).unwrap();
        assert!(n > 0, "short file");
        done += n;
    }
    out
}

fn names(dir: &dyn File) -> Vec<String> {
    let mut v: Vec<String> = (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect();
    v.sort();
    v
}

fn cat(vfs: &Vfs, path: &str) -> Vec<u8> {
    read_all(&*vfs.open(path, OpenFlags::READ, 0).unwrap())
}

#[test]
fn rejects_non_iso() {
    let disk = MemDisk { bytes: Arc::new(vec![0u8; 1 << 20]), block: 512 };
    assert_eq!(IsoFs::mount(disk, 1).err(), Some(Errno::EINVAL));
    let tiny = MemDisk { bytes: Arc::new(vec![0u8; 4096]), block: 512 };
    assert_eq!(IsoFs::mount(tiny, 1).err(), Some(Errno::EINVAL));
}

#[test]
fn rock_ridge() {
    let Some(xorriso) = tool("xorriso") else { return };
    let src = tree("rr");
    let iso = image(&xorriso, &["-as", "mkisofs", "-R", "-J", "-V", "OSMIUM_RR"], &src);
    // A CD's 2048-byte sectors and a disk's 512-byte blocks read the same.
    for block in [2048, 512] {
        let fs = mount(&iso, block);
        assert_eq!((fs.names(), fs.volume_id()), (Names::RockRidge, "OSMIUM_RR"));
        let vfs = Vfs::new(fs.root());
        let root = vfs.lookup("/").unwrap();
        assert_eq!(names(&*root), ["Mixed Case Long Name.data", "abs", "d1", "docs", "hello.txt", "link"]);

        assert_eq!(cat(&vfs, "/hello.txt"), b"hello, iso\n");
        assert_eq!(cat(&vfs, "/Mixed Case Long Name.data"), pattern(5000, 1));
        assert_eq!(cat(&vfs, "/docs/big.bin"), pattern(3 << 20, 2));
        assert_eq!(cat(&vfs, "/docs/empty"), b"");
        assert_eq!(cat(&vfs, "/link"), b"hello, iso\n", "followed through the Vfs");
        assert_eq!(cat(&vfs, "/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/bottom.txt"), b"ten levels down\n");

        // Reads at odd offsets and past the end.
        let big = vfs.open("/docs/big.bin", OpenFlags::READ, 0).unwrap();
        let mut buf = vec![0u8; 10_000];
        assert_eq!(big.read(1_234_567, &mut buf), Ok(10_000));
        assert_eq!(buf, pattern(3 << 20, 2)[1_234_567..1_244_567]);
        assert_eq!(big.read((3 << 20) - 5, &mut buf), Ok(5));
        assert_eq!(big.read(3 << 20, &mut buf), Ok(0));

        // Modes, kinds, links and inode numbers.
        let hello = vfs.stat("/hello.txt", true).unwrap();
        assert_eq!((hello.kind, hello.mode, hello.nlink, hello.size, hello.dev), (FileKind::Regular, 0o640, 1, 11, 9));
        let link = vfs.stat("/link", false).unwrap();
        assert_eq!((link.kind, link.size), (FileKind::Symlink, 9));
        assert_eq!(vfs.readlink("/link").unwrap(), "hello.txt");
        assert_eq!(vfs.readlink("/abs").unwrap(), "/usr/lib/../share/x");
        let docs = vfs.stat("/docs", true).unwrap();
        assert_eq!(docs.kind, FileKind::Directory);
        assert_eq!(vfs.lookup("/docs/..").unwrap().stat().ino, root.stat().ino);
        assert_ne!(docs.ino, hello.ino);

        // Names are exact under Rock Ridge.
        assert_eq!(vfs.lookup("/HELLO.TXT").err(), Some(Errno::ENOENT));
        check_read_only(&vfs);
    }
}

#[test]
fn relocated_directories() {
    // genisoimage, unlike xorriso, moves directories past depth eight into
    // rr_moved and leaves CL/RE entries behind.
    let Some(genisoimage) = tool("genisoimage") else { return };
    let src = tree("reloc");
    let iso = image(&genisoimage, &["-quiet", "-R"], &src);
    let vfs = Vfs::new(mount(&iso, 2048).root());
    assert_eq!(cat(&vfs, "/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/bottom.txt"), b"ten levels down\n");
    // d7 holds a CL entry pointing at d8, which really lives in rr_moved.
    assert_eq!(names(&*vfs.lookup("/d1/d2/d3/d4/d5/d6/d7").unwrap()), ["d8"]);
    let d8 = vfs.stat("/d1/d2/d3/d4/d5/d6/d7/d8", true).unwrap();
    assert_eq!(d8.kind, FileKind::Directory);
    assert_eq!(names(&*vfs.lookup("/d1/d2/d3/d4/d5/d6/d7/d8").unwrap()), ["d9"]);
    // rr_moved's own record of d8 carries RE, so it is not listed twice.
    assert_eq!(names(&*vfs.lookup("/rr_moved").unwrap()), Vec::<String>::new());
}

#[test]
fn joliet() {
    let Some(genisoimage) = tool("genisoimage") else { return };
    let src = tree("joliet");
    let iso = image(&genisoimage, &["-quiet", "-J", "-V", "JOLIET"], &src);
    let fs = mount(&iso, 512);
    assert_eq!((fs.names(), fs.volume_id()), (Names::Joliet, "JOLIET"));
    let vfs = Vfs::new(fs.root());
    // No Rock Ridge: symbolic links are not recorded at all.
    let root = names(&*vfs.lookup("/").unwrap());
    assert_eq!(root, ["Mixed Case Long Name.data", "d1", "docs", "hello.txt"]);
    assert_eq!(cat(&vfs, "/Mixed Case Long Name.data"), pattern(5000, 1));
    assert_eq!(cat(&vfs, "/docs/big.bin"), pattern(3 << 20, 2));
    let hello = vfs.stat("/hello.txt", true).unwrap();
    assert_eq!((hello.mode, hello.nlink), (0o444, 1));
    assert_eq!(vfs.stat("/docs", true).unwrap().mode, 0o555);
    check_read_only(&vfs);
}

#[test]
fn plain_iso_and_multi_extent_files() {
    let Some(genisoimage) = tool("genisoimage") else { return };
    let src = scratch("plain").join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("HELLO.TXT"), b"plain\n").unwrap();
    std::fs::write(src.join("PARTA"), pattern(3000, 3)).unwrap();
    std::fs::write(src.join("PARTB"), pattern(2500, 4)).unwrap();
    std::fs::write(src.join("sub/README"), b"nested\n").unwrap();
    let iso = image(&genisoimage, &["-quiet"], &src);
    let fs = mount(&iso, 2048);
    assert_eq!(fs.names(), Names::Iso);
    let vfs = Vfs::new(fs.root());
    assert_eq!(names(&*vfs.lookup("/").unwrap()), ["hello.txt", "parta", "partb", "sub"]);
    // Shown in lower case, found in any case.
    assert_eq!(cat(&vfs, "/hello.txt"), b"plain\n");
    assert_eq!(cat(&vfs, "/HELLO.txt"), b"plain\n");
    assert_eq!(cat(&vfs, "/sub/readme"), b"nested\n");

    // Turn PARTA and PARTB into one file of two extents: mark PARTA's
    // record "more extents follow" and give PARTB's record the same name.
    let mut patched = (*iso).clone();
    let at = |name: &[u8]| patched.windows(name.len()).position(|w| w == name).expect("record") - 33;
    let (a, b) = (at(b"PARTA.;1"), at(b"PARTB.;1"));
    patched[a + 25] |= 0x80;
    patched[b + 33 + 4] = b'A';
    let vfs = Vfs::new(mount(&Arc::new(patched), 512).root());
    assert_eq!(names(&*vfs.lookup("/").unwrap()), ["hello.txt", "parta", "sub"]);
    let whole = [pattern(3000, 3), pattern(2500, 4)].concat();
    assert_eq!(cat(&vfs, "/parta"), whole);
    let f = vfs.open("/parta", OpenFlags::READ, 0).unwrap();
    let mut buf = [0u8; 200];
    assert_eq!(f.read(2900, &mut buf), Ok(200), "a read across the extents");
    assert_eq!(buf[..], whole[2900..3100]);
}

/// Every way of changing the volume fails.
fn check_read_only(vfs: &Vfs) {
    let rw = OpenFlags::READ | OpenFlags::WRITE;
    let hello = vfs.open("/hello.txt", OpenFlags::READ, 0).unwrap();
    assert_eq!(hello.write(0, b"x"), Err(Errno::EROFS));
    assert_eq!(hello.truncate(0), Err(Errno::EROFS));
    assert_eq!(vfs.lookup("/docs").unwrap().write(0, b"x"), Err(Errno::EISDIR));
    assert_eq!(vfs.open("/new", rw | OpenFlags::CREATE, 0o644).err(), Some(Errno::EROFS));
    assert_eq!(vfs.mkdir("/newdir", 0o755), Err(Errno::EROFS));
    assert_eq!(vfs.unlink("/hello.txt"), Err(Errno::EROFS));
    assert_eq!(vfs.lookup("/hello.txt/x").err(), Some(Errno::ENOTDIR));
    assert_eq!(vfs.lookup("/missing").err(), Some(Errno::ENOENT));
}
