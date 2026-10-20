//! A file system kept entirely in memory (tmpfs).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use osmium_sync::RwSpinLock;

use crate::{DirEntry, Errno, File, FileKind, NAME_MAX, Stat};

/// Largest file the RAM file system holds.
const MAX_SIZE: u64 = isize::MAX as u64;

/// A file system kept in memory: directories, regular files, symbolic
/// links and empty device, FIFO and socket nodes. Contents are lost when
/// the last reference goes.
pub struct RamFs {
    root: Arc<RamNode>,
}

struct Shared {
    dev: u64,
    next_ino: AtomicU64,
}

struct RamNode {
    fs: Arc<Shared>,
    ino: u64,
    kind: FileKind,
    mode: AtomicU32,
    /// 1 while linked into a directory, 0 once removed (no hard links).
    linked: AtomicU32,
    body: Body,
}

enum Body {
    /// A regular file's contents or a symbolic link's target.
    Data(RwSpinLock<Vec<u8>>),
    Dir(RwSpinLock<BTreeMap<String, Arc<RamNode>>>),
    /// A device, FIFO or socket node: metadata only.
    Node,
}

impl RamFs {
    /// An empty file system whose root has permission bits `0o755`; `dev`
    /// is reported as every node's `st_dev`.
    pub fn new(dev: u64) -> Self {
        let fs = Arc::new(Shared { dev, next_ino: AtomicU64::new(1) });
        RamFs { root: RamNode::new(&fs, FileKind::Directory, 0o755) }
    }

    /// The root directory, to pass to [`Vfs::new`](crate::Vfs::new) or
    /// [`Vfs::mount`](crate::Vfs::mount).
    pub fn root(&self) -> Arc<dyn File> {
        self.root.clone()
    }
}

impl RamNode {
    fn new(fs: &Arc<Shared>, kind: FileKind, mode: u32) -> Arc<Self> {
        let body = match kind {
            FileKind::Regular | FileKind::Symlink => Body::Data(RwSpinLock::new(Vec::new())),
            FileKind::Directory => Body::Dir(RwSpinLock::new(BTreeMap::new())),
            _ => Body::Node,
        };
        Arc::new(RamNode {
            fs: fs.clone(),
            ino: fs.next_ino.fetch_add(1, Ordering::Relaxed),
            kind,
            mode: AtomicU32::new(mode & 0o7777),
            linked: AtomicU32::new(1),
            body,
        })
    }

    fn dir(&self) -> Result<&RwSpinLock<BTreeMap<String, Arc<RamNode>>>, Errno> {
        match &self.body {
            Body::Dir(entries) => Ok(entries),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn data(&self) -> Result<&RwSpinLock<Vec<u8>>, Errno> {
        match &self.body {
            Body::Data(data) => Ok(data),
            Body::Dir(_) => Err(Errno::EISDIR),
            Body::Node => Err(Errno::EINVAL),
        }
    }

    fn is_empty_dir(&self) -> bool {
        matches!(&self.body, Body::Dir(entries) if entries.read().is_empty())
    }
}

/// Checks a name passed to `create`: not empty, `.` or `..`, no `/` or NUL.
fn check_name(name: &str) -> Result<(), Errno> {
    if name.len() > NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

impl File for RamNode {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let data = self.data()?.read();
        let Ok(off) = usize::try_from(off) else { return Ok(0) };
        let Some(src) = data.get(off..) else { return Ok(0) };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        let mut guard = self.data()?.write();
        let data = &mut *guard;
        let end = off.checked_add(buf.len() as u64).filter(|&end| end <= MAX_SIZE).ok_or(Errno::EFBIG)?;
        let (off, end) = (off as usize, end as usize);
        if end > data.len() {
            data.try_reserve(end - data.len()).map_err(|_| Errno::ENOMEM)?;
            data.resize(end, 0);
        }
        data[off..end].copy_from_slice(buf);
        Ok(buf.len())
    }

    fn stat(&self) -> Stat {
        let (size, nlink) = match &self.body {
            Body::Data(data) => (data.read().len() as u64, self.linked.load(Ordering::Relaxed)),
            // A directory is linked from its parent, its own `.` and each
            // subdirectory's `..`.
            Body::Dir(entries) => {
                let entries = entries.read();
                let subdirs = entries.values().filter(|n| n.kind == FileKind::Directory).count() as u32;
                (entries.len() as u64, 2 + subdirs)
            }
            Body::Node => (0, self.linked.load(Ordering::Relaxed)),
        };
        Stat {
            dev: self.fs.dev,
            ino: self.ino,
            kind: self.kind,
            mode: self.mode.load(Ordering::Relaxed),
            nlink,
            size,
            rdev: 0,
        }
    }

    fn truncate(&self, len: u64) -> Result<(), Errno> {
        if self.kind != FileKind::Regular {
            return Err(if self.kind == FileKind::Directory { Errno::EISDIR } else { Errno::EINVAL });
        }
        if len > MAX_SIZE {
            return Err(Errno::EFBIG);
        }
        let mut guard = self.data()?.write();
        let data = &mut *guard;
        let len = len as usize;
        if len > data.len() {
            data.try_reserve(len - data.len()).map_err(|_| Errno::ENOMEM)?;
        }
        data.resize(len, 0);
        Ok(())
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        let entries = self.dir()?.read();
        Ok(entries.iter().nth(index).map(|(name, node)| DirEntry {
            ino: node.ino,
            kind: node.kind,
            name: name.clone(),
        }))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let entries = self.dir()?.read();
        match entries.get(name) {
            Some(node) => Ok(node.clone()),
            None => Err(Errno::ENOENT),
        }
    }

    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        check_name(name)?;
        let mut entries = self.dir()?.write();
        if entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let node = RamNode::new(&self.fs, kind, mode);
        entries.insert(String::from(name), node.clone());
        Ok(node)
    }

    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        let mut entries = self.dir()?.write();
        let node = entries.get(name).ok_or(Errno::ENOENT)?;
        match (dir, node.kind == FileKind::Directory) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            (true, true) if !node.is_empty_dir() => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        let node = entries.remove(name).expect("checked above");
        node.linked.store(0, Ordering::Relaxed);
        Ok(())
    }

    fn readlink(&self) -> Result<String, Errno> {
        if self.kind != FileKind::Symlink {
            return Err(Errno::EINVAL);
        }
        let data = self.data()?.read();
        String::from_utf8(data.clone()).map_err(|_| Errno::EINVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenFlags, Vfs};
    use alloc::vec;

    const RW: OpenFlags = OpenFlags::READ.union(OpenFlags::WRITE);

    fn vfs() -> Vfs {
        Vfs::new(RamFs::new(1).root())
    }

    fn read_all(file: &dyn File) -> Vec<u8> {
        let mut buf = vec![0; file.stat().size as usize];
        let n = file.read(0, &mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    fn names(dir: &dyn File) -> Vec<String> {
        (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect()
    }

    #[test]
    fn create_write_read() {
        let vfs = vfs();
        let f = vfs.open("/hello", RW | OpenFlags::CREATE, 0o644).unwrap();
        assert_eq!(f.write(0, b"hello").unwrap(), 5);
        assert_eq!(f.write(7, b"world").unwrap(), 5);
        assert_eq!(read_all(&*f), b"hello\0\0world");
        let mut buf = [0; 4];
        assert_eq!(f.read(10, &mut buf).unwrap(), 2);
        assert_eq!(f.read(100, &mut buf).unwrap(), 0);
        let st = vfs.stat("/hello", true).unwrap();
        assert_eq!((st.kind, st.mode, st.size, st.nlink, st.dev), (FileKind::Regular, 0o644, 12, 1, 1));
        // Opening again finds the same node.
        let g = vfs.open("/hello", OpenFlags::READ, 0).unwrap();
        assert_eq!(g.stat().ino, st.ino);
    }

    #[test]
    fn open_flags() {
        let vfs = vfs();
        assert_eq!(vfs.open("/f", OpenFlags::READ, 0).err(), Some(Errno::ENOENT));
        let f = vfs.open("/f", RW | OpenFlags::CREATE | OpenFlags::EXCL, 0o600).unwrap();
        f.write(0, b"data").unwrap();
        assert_eq!(vfs.open("/f", RW | OpenFlags::CREATE | OpenFlags::EXCL, 0).err(), Some(Errno::EEXIST));
        // TRUNC needs WRITE.
        vfs.open("/f", OpenFlags::READ | OpenFlags::TRUNC, 0).unwrap();
        assert_eq!(f.stat().size, 4);
        vfs.open("/f", OpenFlags::WRITE | OpenFlags::TRUNC, 0).unwrap();
        assert_eq!(f.stat().size, 0);
        assert_eq!(vfs.open("/f", OpenFlags::DIRECTORY, 0).err(), Some(Errno::ENOTDIR));
        assert_eq!(vfs.open("/f/", OpenFlags::READ, 0).err(), Some(Errno::ENOTDIR));
        assert_eq!(vfs.open("/f/x", OpenFlags::READ, 0).err(), Some(Errno::ENOTDIR));
        assert_eq!(vfs.open("/", OpenFlags::WRITE, 0).err(), Some(Errno::EISDIR));
        assert_eq!(vfs.open("/", OpenFlags::CREATE, 0).err(), Some(Errno::EISDIR));
        assert_eq!(vfs.open("/new/", OpenFlags::CREATE, 0).err(), Some(Errno::EISDIR));
        assert!(vfs.open("/", OpenFlags::READ | OpenFlags::DIRECTORY, 0).is_ok());
        assert_eq!(vfs.open("f", OpenFlags::READ, 0).err(), Some(Errno::EINVAL));
        assert_eq!(vfs.open("", OpenFlags::READ, 0).err(), Some(Errno::ENOENT));
        let long = std::format!("/{}", "x".repeat(NAME_MAX + 1));
        assert_eq!(vfs.open(&long, OpenFlags::READ, 0).err(), Some(Errno::ENAMETOOLONG));
    }

    #[test]
    fn directories() {
        let vfs = vfs();
        vfs.mkdir("/a", 0o755).unwrap();
        vfs.mkdir("/a/b", 0o700).unwrap();
        assert_eq!(vfs.mkdir("/a", 0o755).err(), Some(Errno::EEXIST));
        assert_eq!(vfs.mkdir("/", 0o755).err(), Some(Errno::EEXIST));
        assert_eq!(vfs.mkdir("/x/y", 0o755).err(), Some(Errno::ENOENT));
        vfs.open("/a/file", OpenFlags::CREATE, 0o644).unwrap();
        vfs.open("/a/b/../b/./inner", OpenFlags::CREATE, 0o644).unwrap();
        assert_eq!(names(&*vfs.lookup("/a").unwrap()), ["b", "file"]);
        assert_eq!(vfs.stat("/a", true).unwrap().nlink, 3);
        assert_eq!(vfs.stat("//a///b/", true).unwrap().mode, 0o700);
        // `..` at the root stays there.
        assert_eq!(vfs.canonicalize("/../../a/b/..").unwrap(), "/a");
        assert_eq!(vfs.rmdir("/a/b").err(), Some(Errno::ENOTEMPTY));
        assert_eq!(vfs.rmdir("/a/file").err(), Some(Errno::ENOTDIR));
        assert_eq!(vfs.unlink("/a/b").err(), Some(Errno::EISDIR));
        assert_eq!(vfs.rmdir("/a/b/.").err(), Some(Errno::EINVAL));
        assert_eq!(vfs.rmdir("/").err(), Some(Errno::EBUSY));
        vfs.unlink("/a/b/inner").unwrap();
        vfs.rmdir("/a/b/").unwrap();
        assert_eq!(vfs.unlink("/a/file/").err(), Some(Errno::ENOTDIR));
        vfs.unlink("/a/file").unwrap();
        assert_eq!(vfs.unlink("/a/file").err(), Some(Errno::ENOENT));
        assert!(names(&*vfs.lookup("/a").unwrap()).is_empty());
        assert_eq!(vfs.lookup("/a/file").err(), Some(Errno::ENOENT));
    }

    #[test]
    fn unlinked_file_stays_usable() {
        let vfs = vfs();
        let f = vfs.open("/tmp", RW | OpenFlags::CREATE, 0o644).unwrap();
        vfs.unlink("/tmp").unwrap();
        f.write(0, b"still here").unwrap();
        assert_eq!(read_all(&*f), b"still here");
        assert_eq!(f.stat().nlink, 0);
    }

    #[test]
    fn truncate() {
        let vfs = vfs();
        let f = vfs.open("/f", RW | OpenFlags::CREATE, 0o644).unwrap();
        f.write(0, b"abcdef").unwrap();
        f.truncate(3).unwrap();
        assert_eq!(read_all(&*f), b"abc");
        f.truncate(5).unwrap();
        assert_eq!(read_all(&*f), b"abc\0\0");
        assert_eq!(vfs.lookup("/").unwrap().truncate(0).err(), Some(Errno::EISDIR));
    }

    #[test]
    fn symlinks() {
        let vfs = vfs();
        vfs.mkdir("/dir", 0o755).unwrap();
        vfs.open("/dir/target", OpenFlags::CREATE, 0o644).unwrap().write(0, b"via link").unwrap();
        vfs.symlink("/dir/target", "/abs").unwrap();
        vfs.symlink("dir", "/rel").unwrap();
        vfs.symlink("../dir/target", "/dir/up").unwrap();
        vfs.symlink("/loop", "/loop").unwrap();
        assert_eq!(read_all(&*vfs.open("/abs", OpenFlags::READ, 0).unwrap()), b"via link");
        assert_eq!(read_all(&*vfs.open("/rel/target", OpenFlags::READ, 0).unwrap()), b"via link");
        assert_eq!(read_all(&*vfs.open("/rel/up", OpenFlags::READ, 0).unwrap()), b"via link");
        assert_eq!(vfs.canonicalize("/rel/up").unwrap(), "/dir/target");
        assert_eq!(vfs.readlink("/rel/up").unwrap(), "../dir/target");
        assert_eq!(vfs.stat("/abs", false).unwrap().kind, FileKind::Symlink);
        assert_eq!(vfs.stat("/abs", false).unwrap().size, 11);
        assert_eq!(vfs.stat("/abs", true).unwrap().kind, FileKind::Regular);
        assert_eq!(vfs.open("/abs", OpenFlags::NOFOLLOW, 0).err(), Some(Errno::ELOOP));
        assert_eq!(vfs.open("/loop", OpenFlags::READ, 0).err(), Some(Errno::ELOOP));
        assert_eq!(vfs.readlink("/dir").err(), Some(Errno::EINVAL));
        // A trailing slash follows a link to a directory.
        assert_eq!(vfs.stat("/rel/", false).unwrap().kind, FileKind::Directory);
        // O_CREAT through a link opens the target.
        vfs.open("/abs", OpenFlags::CREATE | OpenFlags::WRITE, 0).unwrap();
        vfs.unlink("/abs").unwrap();
        assert!(vfs.lookup("/dir/target").is_ok());
        // ... and through a dangling one it creates the target.
        vfs.symlink("made", "/dir/dangling").unwrap();
        vfs.symlink("/dir/dangling", "/chain").unwrap();
        vfs.open("/chain", OpenFlags::CREATE | OpenFlags::WRITE, 0o600).unwrap();
        assert_eq!(vfs.stat("/dir/made", false).unwrap().kind, FileKind::Regular);
        assert_eq!(vfs.stat("/chain", false).unwrap().kind, FileKind::Symlink);
        assert_eq!(vfs.open("/chain", OpenFlags::CREATE | OpenFlags::EXCL, 0).err(), Some(Errno::EEXIST));
        vfs.symlink("gone", "/dir/nofollow").unwrap();
        assert_eq!(vfs.open("/dir/nofollow", OpenFlags::CREATE | OpenFlags::NOFOLLOW, 0).err(), Some(Errno::ELOOP));
        assert_eq!(vfs.lookup("/dir/gone").err(), Some(Errno::ENOENT));
        vfs.symlink("/self", "/self").unwrap();
        assert_eq!(vfs.open("/self", OpenFlags::CREATE, 0).err(), Some(Errno::ELOOP));
        // A trailing slash is a directory request.
        assert_eq!(vfs.open("/dir/made/", OpenFlags::CREATE, 0).err(), Some(Errno::ENOTDIR));
        assert_eq!(vfs.open("/dir/new/", OpenFlags::CREATE, 0).err(), Some(Errno::EISDIR));
        assert_eq!(vfs.open("/dir/", OpenFlags::CREATE, 0).err(), Some(Errno::EISDIR));
        assert_eq!(vfs.lookup("/dir/new").err(), Some(Errno::ENOENT));
    }

    #[test]
    fn mounts() {
        let vfs = vfs();
        vfs.mkdir("/mnt", 0o755).unwrap();
        vfs.open("/mnt/hidden", OpenFlags::CREATE, 0o644).unwrap();
        let other = RamFs::new(2);
        other.root().create("inside", FileKind::Regular, 0o644).unwrap();
        vfs.mount("/mnt", other.root()).unwrap();
        assert_eq!(vfs.stat("/mnt/inside", true).unwrap().dev, 2);
        assert_eq!(vfs.lookup("/mnt/hidden").err(), Some(Errno::ENOENT));
        assert_eq!(vfs.stat("/mnt", true).unwrap().dev, 2);
        // O_CREAT on the mount point itself is the mounted root.
        assert_eq!(vfs.open("/mnt", OpenFlags::CREATE, 0).unwrap().stat().dev, 2);
        assert_eq!(vfs.open("/mnt", OpenFlags::CREATE | OpenFlags::EXCL, 0).err(), Some(Errno::EEXIST));
        // `..` leaves the mount.
        assert_eq!(vfs.stat("/mnt/..", true).unwrap().dev, 1);
        assert_eq!(vfs.canonicalize("/mnt/../mnt/inside").unwrap(), "/mnt/inside");
        vfs.mkdir("/mnt/sub", 0o755).unwrap();
        assert_eq!(vfs.rmdir("/mnt").err(), Some(Errno::EBUSY));
        // A mount inside the mount keeps the outer one busy.
        vfs.mount("/mnt/sub", RamFs::new(3).root()).unwrap();
        assert_eq!(vfs.stat("/mnt/sub/.", true).unwrap().dev, 3);
        assert_eq!(vfs.unmount("/mnt").err(), Some(Errno::EBUSY));
        vfs.unmount("/mnt/sub").unwrap();
        vfs.unmount("/mnt").unwrap();
        assert!(vfs.lookup("/mnt/hidden").is_ok());
        assert_eq!(vfs.unmount("/mnt").err(), Some(Errno::EINVAL));
        assert_eq!(vfs.unmount("/").err(), Some(Errno::EBUSY));
        assert_eq!(vfs.mount("/mnt/hidden", other.root()).err(), Some(Errno::ENOTDIR));
        // Mounting over `/` covers the original root until unmounted.
        vfs.mount("/", other.root()).unwrap();
        assert!(vfs.lookup("/inside").is_ok());
        vfs.unmount("/").unwrap();
        assert!(vfs.lookup("/mnt").is_ok());
    }

    #[test]
    fn bad_names() {
        let root = RamFs::new(1).root();
        for name in ["", ".", "..", "a/b"] {
            assert_eq!(root.create(name, FileKind::Regular, 0).err(), Some(Errno::EINVAL));
        }
        let f = root.create("f", FileKind::Regular, 0).unwrap();
        assert_eq!(f.lookup("x").err(), Some(Errno::ENOTDIR));
        assert_eq!(root.read(0, &mut [0; 4]).err(), Some(Errno::EISDIR));
    }
}
