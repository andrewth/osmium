//! A file system kept entirely in memory (tmpfs).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::ops::Deref;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use osmium_sync::arc::ArcTree;
use osmium_sync::fallible::{try_arc, try_string, try_to_vec};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Shared as SharedLink, TreeLink};
use osmium_sync::{RwSpinLock, SpinLock};

use crate::{Clock, ClockSlot, DirEntry, Errno, File, FileKind, NAME_MAX, Stat, Timestamp};

/// Largest file the RAM file system holds.
const MAX_SIZE: u64 = isize::MAX as u64;

/// A file system kept in memory: directories, regular files, symbolic
/// links and empty device, FIFO and socket nodes, with hard links and
/// `rename`. Contents are lost when the last reference goes. Times come from
/// the clock given to [`RamFs::set_clock`] or else the global one; access
/// times are set at creation and not updated by reads.
pub struct RamFs {
    root: Arc<RamNode>,
}

struct Shared {
    dev: u64,
    next_ino: AtomicU64,
    clock: ClockSlot,
    /// Held across a `rename`, so that two of them never wait on each
    /// other's directories and the loop check sees a still tree.
    rename: SpinLock<()>,
}

#[derive(Clone, Copy, Default)]
struct Times {
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
}

/// What every name of a file shares.
struct Inner {
    fs: Arc<Shared>,
    mode: AtomicU32,
    /// Names it has in directories; 0 once all are removed.
    linked: AtomicU32,
    body: Body,
    times: SpinLock<Times>,
}

/// One name of a file in a directory. Hard links and renames make new
/// `RamNode`s around the same [`Inner`].
struct RamNode {
    ino: u64,
    kind: FileKind,
    /// The name it has in its directory.
    name: String,
    /// Links it into its directory by `name`.
    entry: SharedLink<TreeLink>,
    inner: Arc<Inner>,
}

impl Deref for RamNode {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.inner
    }
}

/// Where [`RamNode::entry`] sits in a [`RamNode`], and the key: the name.
struct ByName;

// SAFETY: `offset_of!` of a `SharedLink<TreeLink>`, which is a `TreeLink`.
unsafe impl Adapter<TreeLink> for ByName {
    type Value = RamNode;
    const OFFSET: usize = offset_of!(RamNode, entry);
}

impl KeyAdapter<TreeLink> for ByName {
    type Key = str;

    fn key(node: &RamNode) -> &str {
        &node.name
    }
}

type Entries = ArcTree<ByName>;

enum Body {
    /// A regular file's contents or a symbolic link's target.
    Data(RwSpinLock<Vec<u8>>),
    Dir(RwSpinLock<Entries>),
    /// A device, FIFO or socket node: metadata only.
    Node,
}

impl RamFs {
    /// An empty file system whose root has permission bits `0o755`; `dev`
    /// is reported as every node's `st_dev`.
    ///
    /// # Panics
    /// If memory runs out: [`RamFs::try_new`] reports that instead.
    #[allow(clippy::expect_used)] // documented `# Panics` on OOM at boot; `try_new` is the fallible form.
    pub fn new(dev: u64) -> Self {
        Self::try_new(dev).expect("out of memory for a file system")
    }

    /// [`RamFs::new`], failing with `ENOMEM` instead of panicking.
    pub fn try_new(dev: u64) -> Result<Self, Errno> {
        let fs =
            try_arc(Shared { dev, next_ino: AtomicU64::new(1), clock: ClockSlot::new(), rename: SpinLock::new(()) })?;
        Ok(RamFs { root: RamNode::new(&fs, FileKind::Directory, 0o755, "")? })
    }

    /// Stamps files with `clock` instead of the global one.
    pub fn set_clock(&self, clock: Arc<dyn Clock>) {
        self.root.fs.clock.set(clock);
    }

    /// The root directory, to pass to [`Vfs::new`](crate::Vfs::new) or
    /// [`Vfs::mount`](crate::Vfs::mount).
    pub fn root(&self) -> Arc<dyn File> {
        self.root.clone()
    }
}

impl RamNode {
    fn new(fs: &Arc<Shared>, kind: FileKind, mode: u32, name: &str) -> Result<Arc<Self>, Errno> {
        let body = match kind {
            FileKind::Regular | FileKind::Symlink => Body::Data(RwSpinLock::new(Vec::new())),
            FileKind::Directory => Body::Dir(RwSpinLock::new(ArcTree::new())),
            _ => Body::Node,
        };
        let name = try_string(name)?;
        let now = fs.clock.now();
        let inner = try_arc(Inner {
            fs: fs.clone(),
            mode: AtomicU32::new(mode & 0o7777),
            linked: AtomicU32::new(1),
            body,
            times: SpinLock::new(Times { atime: now, mtime: now, ctime: now }),
        })?;
        Ok(try_arc(RamNode {
            ino: fs.next_ino.fetch_add(1, Ordering::Relaxed),
            kind,
            name,
            entry: SharedLink::new(TreeLink::new()),
            inner,
        })?)
    }

    /// Another name for the same file.
    fn alias(&self, name: &str) -> Result<Arc<Self>, Errno> {
        Ok(try_arc(RamNode {
            ino: self.ino,
            kind: self.kind,
            name: try_string(name)?,
            entry: SharedLink::new(TreeLink::new()),
            inner: self.inner.clone(),
        })?)
    }

    /// Records a change of the contents (`contents`) or only of the metadata.
    fn touch(&self, contents: bool) {
        let now = self.fs.clock.now();
        let mut t = self.times.lock();
        if contents {
            t.mtime = now;
        }
        t.ctime = now;
    }

    /// A name of this file was removed.
    #[allow(deprecated)] // `fetch_update` is the spelling the MSRV has
    fn unlinked(&self) {
        if self.kind == FileKind::Directory {
            self.linked.store(0, Ordering::Relaxed);
        } else {
            let _ = self.linked.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
            self.touch(false);
        }
    }

    /// Whether `other` is this directory or somewhere below it.
    fn contains(&self, other: &Inner) -> bool {
        if core::ptr::eq(&*self.inner, other) {
            return true;
        }
        match &self.body {
            Body::Dir(entries) => entries.read().iter().any(|n| n.kind == FileKind::Directory && n.contains(other)),
            _ => false,
        }
    }

    fn dir(&self) -> Result<&RwSpinLock<Entries>, Errno> {
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
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let data = self.data()?.read();
        let Ok(off) = usize::try_from(off) else { return Ok(0) };
        let Some(src) = data.get(off..) else { return Ok(0) };
        let n = src.len().min(buf.len());
        let (src, dst) = src.get(..n).zip(buf.get_mut(..n)).ok_or(Errno::EIO)?;
        dst.copy_from_slice(src);
        Ok(n)
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        let mut guard = self.data()?.write();
        let data = &mut *guard;
        let end = off.checked_add(buf.len() as u64).filter(|&end| end <= MAX_SIZE).ok_or(Errno::EFBIG)?;
        let (Ok(off), Ok(end)) = (usize::try_from(off), usize::try_from(end)) else { return Err(Errno::EFBIG) };
        if end > data.len() {
            data.try_reserve(end - data.len()).map_err(|_| Errno::ENOMEM)?;
            data.resize(end, 0);
        }
        data.get_mut(off..end).ok_or(Errno::EIO)?.copy_from_slice(buf);
        drop(guard);
        self.touch(true);
        Ok(buf.len())
    }

    fn stat(&self) -> Stat {
        let (size, nlink) = match &self.body {
            Body::Data(data) => (data.read().len() as u64, self.linked.load(Ordering::Relaxed)),
            // A directory is linked from its parent, its own `.` and each
            // subdirectory's `..`.
            Body::Dir(entries) => {
                let entries = entries.read();
                let subdirs = entries.iter().filter(|n| n.kind == FileKind::Directory).count() as u32;
                (entries.len() as u64, 2 + subdirs)
            }
            Body::Node => (0, self.linked.load(Ordering::Relaxed)),
        };
        let t = *self.times.lock();
        Stat {
            atime: t.atime,
            mtime: t.mtime,
            ctime: t.ctime,
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
        drop(guard);
        self.touch(true);
        Ok(())
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        let entries = self.dir()?.read();
        let Some(node) = entries.iter().nth(index) else { return Ok(None) };
        Ok(Some(DirEntry { ino: node.ino, kind: node.kind, name: try_string(&node.name)? }))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let entries = self.dir()?.read();
        match entries.clone_key(name) {
            Some(node) => Ok(node),
            None => Err(Errno::ENOENT),
        }
    }

    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        check_name(name)?;
        // Made first: running out of memory then changes nothing.
        let node = RamNode::new(&self.fs, kind, mode, name)?;
        let mut entries = self.dir()?.write();
        if entries.insert(node.clone()).is_err() {
            return Err(Errno::EEXIST);
        }
        drop(entries);
        self.touch(true);
        Ok(node)
    }

    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        let mut entries = self.dir()?.write();
        let node = entries.find(name).ok_or(Errno::ENOENT)?;
        match (dir, node.kind == FileKind::Directory) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            (true, true) if !node.is_empty_dir() => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        let node = entries.take_key(name).ok_or(Errno::ENOENT)?;
        drop(entries);
        node.unlinked();
        self.touch(true);
        Ok(())
    }

    #[allow(deprecated)] // `fetch_update` is the spelling the MSRV has
    fn link(&self, name: &str, target: &dyn File) -> Result<(), Errno> {
        check_name(name)?;
        let target = target.as_any().and_then(|a| a.downcast_ref::<RamNode>()).ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&target.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        if target.kind == FileKind::Directory {
            return Err(Errno::EPERM);
        }
        let alias = target.alias(name)?;
        let mut entries = self.dir()?.write();
        // A file with no names left cannot be given one again.
        target
            .linked
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| if n == 0 { None } else { n.checked_add(1) })
            .map_err(|_| Errno::ENOENT)?;
        if entries.insert(alias).is_err() {
            target.linked.fetch_sub(1, Ordering::Relaxed);
            return Err(Errno::EEXIST);
        }
        drop(entries);
        target.touch(false);
        self.touch(true);
        Ok(())
    }

    fn rename(&self, old_name: &str, new_dir: &dyn File, new_name: &str) -> Result<(), Errno> {
        check_name(new_name)?;
        let dst = new_dir.as_any().and_then(|a| a.downcast_ref::<RamNode>()).ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&dst.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        let same_dir = Arc::ptr_eq(&self.inner, &dst.inner);
        let _serial = self.fs.rename.lock();
        let moved = self.dir()?.read().clone_key(old_name).ok_or(Errno::ENOENT)?;
        dst.dir()?;
        if moved.kind == FileKind::Directory && moved.contains(dst) {
            return Err(Errno::EINVAL);
        }
        // Made before anything changes.
        let renamed = moved.alias(new_name)?;
        let mut src_entries = self.dir()?.write();
        let mut other_entries = if same_dir { None } else { Some(dst.dir()?.write()) };
        let dst_entries = match &mut other_entries {
            Some(guard) => &mut **guard,
            None => &mut *src_entries,
        };
        let replaced = match dst_entries.find(new_name) {
            None => None,
            // Two names of one file: nothing to do.
            Some(existing) if Arc::ptr_eq(&existing.inner, &moved.inner) => return Ok(()),
            Some(existing) => {
                match (moved.kind == FileKind::Directory, existing.kind == FileKind::Directory) {
                    (true, false) => return Err(Errno::ENOTDIR),
                    (false, true) => return Err(Errno::EISDIR),
                    (true, true) if !existing.is_empty_dir() => return Err(Errno::ENOTEMPTY),
                    _ => {}
                }
                dst_entries.take_key(new_name)
            }
        };
        if let Some(old) = replaced {
            old.unlinked();
        }
        if dst_entries.insert(renamed).is_err() {
            return Err(Errno::EEXIST);
        }
        drop(src_entries.take_key(old_name));
        drop(other_entries);
        drop(src_entries);
        moved.touch(false);
        self.touch(true);
        if !same_dir {
            dst.touch(true);
        }
        Ok(())
    }

    fn readlink(&self) -> Result<String, Errno> {
        if self.kind != FileKind::Symlink {
            return Err(Errno::EINVAL);
        }
        let data = self.data()?.read();
        String::from_utf8(try_to_vec(&data)?).map_err(|_| Errno::EINVAL)
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

    /// A directory that loses a creation race: its first lookup misses, and
    /// by the time `create` runs the name exists.
    struct Racy {
        inner: Arc<dyn File>,
        missed: core::sync::atomic::AtomicBool,
    }

    impl File for Racy {
        fn stat(&self) -> crate::Stat {
            self.inner.stat()
        }

        fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
            if !self.missed.swap(true, core::sync::atomic::Ordering::SeqCst) {
                return Err(Errno::ENOENT);
            }
            self.inner.lookup(name)
        }

        fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
            self.inner.create(name, kind, mode)?;
            Err(Errno::EEXIST)
        }
    }

    #[test]
    fn open_create_retries_after_losing_a_race() {
        let racy = |_| Vfs::new(Arc::new(Racy { inner: RamFs::new(1).root(), missed: false.into() }));
        let f = racy(0).open("/f", RW | OpenFlags::CREATE, 0o644).unwrap();
        assert_eq!(f.stat().kind, FileKind::Regular);
        assert_eq!(racy(0).open("/f", RW | OpenFlags::CREATE | OpenFlags::EXCL, 0o644).err(), Some(Errno::EEXIST));
    }

    fn put(vfs: &Vfs, path: &str, data: &[u8]) {
        let f = vfs.open(path, RW | OpenFlags::CREATE, 0o644).unwrap();
        f.write(0, data).unwrap();
    }

    fn contents(vfs: &Vfs, path: &str) -> Vec<u8> {
        read_all(&*vfs.open(path, OpenFlags::READ, 0).unwrap())
    }

    #[test]
    fn hard_links_share_the_file() {
        let vfs = vfs();
        put(&vfs, "/a", b"one");
        vfs.link("/a", "/b").unwrap();
        let (a, b) = (vfs.stat("/a", true).unwrap(), vfs.stat("/b", true).unwrap());
        assert_eq!((a.ino, a.nlink), (b.ino, 2));
        vfs.open("/b", RW, 0).unwrap().write(0, b"two").unwrap();
        assert_eq!(contents(&vfs, "/a"), b"two");
        vfs.unlink("/a").unwrap();
        assert_eq!(vfs.stat("/b", true).unwrap().nlink, 1);
        assert_eq!(contents(&vfs, "/b"), b"two");
        vfs.unlink("/b").unwrap();
        assert_eq!(vfs.stat("/b", true).err(), Some(Errno::ENOENT));
    }

    #[test]
    fn link_errors() {
        let vfs = vfs();
        put(&vfs, "/a", b"");
        put(&vfs, "/b", b"");
        vfs.mkdir("/d", 0o755).unwrap();
        assert_eq!(vfs.link("/a", "/b").err(), Some(Errno::EEXIST));
        assert_eq!(vfs.link("/d", "/e").err(), Some(Errno::EPERM));
        assert_eq!(vfs.link("/nope", "/e").err(), Some(Errno::ENOENT));
        // An open file with no names left cannot be linked again.
        let held = vfs.lookup("/a").unwrap();
        vfs.unlink("/a").unwrap();
        let other = RamFs::new(2);
        assert_eq!(other.root().link("x", &*held).err(), Some(Errno::EXDEV));
        assert_eq!(vfs.lookup("/").unwrap().link("again", &*held).err(), Some(Errno::ENOENT));
    }

    #[test]
    fn links_across_mounts_are_refused() {
        let vfs = vfs();
        vfs.mkdir("/m", 0o755).unwrap();
        vfs.mount("/m", RamFs::new(2).root()).unwrap();
        put(&vfs, "/a", b"");
        assert_eq!(vfs.link("/a", "/m/a").err(), Some(Errno::EXDEV));
        assert_eq!(vfs.rename("/a", "/m/a").err(), Some(Errno::EXDEV));
        assert_eq!(vfs.rename("/m", "/n").err(), Some(Errno::EBUSY));
    }

    #[test]
    fn rename_moves_and_replaces() {
        let vfs = vfs();
        put(&vfs, "/a", b"aa");
        put(&vfs, "/b", b"bb");
        vfs.mkdir("/d", 0o755).unwrap();
        let open = vfs.open("/a", RW, 0).unwrap();
        let ino = open.stat().ino;
        vfs.rename("/a", "/d/c").unwrap();
        assert_eq!(vfs.stat("/a", true).err(), Some(Errno::ENOENT));
        assert_eq!(vfs.stat("/d/c", true).unwrap().ino, ino);
        // The handle opened before still reaches the same file.
        open.write(0, b"zz").unwrap();
        assert_eq!(contents(&vfs, "/d/c"), b"zz");
        // Over an existing file.
        vfs.rename("/d/c", "/b").unwrap();
        assert_eq!(contents(&vfs, "/b"), b"zz");
        assert_eq!(names(&*vfs.lookup("/d").unwrap()), Vec::<String>::new());
        // To itself, and by another name of the same file.
        vfs.rename("/b", "/b").unwrap();
        vfs.link("/b", "/b2").unwrap();
        vfs.rename("/b", "/b2").unwrap();
        assert_eq!(vfs.stat("/b", true).unwrap().nlink, 2);
    }

    #[test]
    fn rename_directories() {
        let vfs = vfs();
        vfs.mkdir("/d", 0o755).unwrap();
        vfs.mkdir("/d/sub", 0o755).unwrap();
        put(&vfs, "/d/sub/f", b"x");
        vfs.mkdir("/e", 0o755).unwrap();
        vfs.mkdir("/full", 0o755).unwrap();
        put(&vfs, "/full/f", b"");
        put(&vfs, "/file", b"");
        assert_eq!(vfs.rename("/d", "/d/sub/d").err(), Some(Errno::EINVAL));
        assert_eq!(vfs.rename("/d", "/d/x").err(), Some(Errno::EINVAL));
        assert_eq!(vfs.rename("/d", "/full").err(), Some(Errno::ENOTEMPTY));
        assert_eq!(vfs.rename("/d", "/file").err(), Some(Errno::ENOTDIR));
        assert_eq!(vfs.rename("/file", "/e").err(), Some(Errno::EISDIR));
        assert_eq!(vfs.rename("/", "/x").err(), Some(Errno::EBUSY));
        assert_eq!(vfs.rename("/d/.", "/x").err(), Some(Errno::EINVAL));
        vfs.rename("/d", "/e").unwrap();
        assert_eq!(contents(&vfs, "/e/sub/f"), b"x");
        assert_eq!(vfs.stat("/d", true).err(), Some(Errno::ENOENT));
        // Back and forth between two directories, in both orders.
        vfs.rename("/e/sub", "/sub").unwrap();
        vfs.rename("/sub", "/e/sub").unwrap();
        assert_eq!(contents(&vfs, "/e/sub/f"), b"x");
    }

    #[test]
    fn times_come_from_the_clock() {
        use crate::{ManualClock, Timestamp};
        let fs = RamFs::new(1);
        let clock = Arc::new(ManualClock::new(Timestamp::from_secs(1000)));
        fs.set_clock(clock.clone());
        let vfs = Vfs::new(fs.root());
        put(&vfs, "/a", b"x");
        let st = vfs.stat("/a", true).unwrap();
        assert_eq!((st.atime.sec, st.mtime.sec, st.ctime.sec), (1000, 1000, 1000));
        clock.advance(5);
        vfs.open("/a", RW, 0).unwrap().write(0, b"y").unwrap();
        let st = vfs.stat("/a", true).unwrap();
        assert_eq!((st.atime.sec, st.mtime.sec, st.ctime.sec), (1000, 1005, 1005));
        let root = vfs.stat("/", true).unwrap();
        assert_eq!(root.mtime.sec, 1000);
        clock.advance(5);
        vfs.link("/a", "/b").unwrap();
        let st = vfs.stat("/a", true).unwrap();
        assert_eq!((st.mtime.sec, st.ctime.sec), (1005, 1010));
        assert_eq!(vfs.stat("/", true).unwrap().mtime.sec, 1010);
        clock.advance(5);
        vfs.rename("/b", "/c").unwrap();
        assert_eq!(vfs.stat("/c", true).unwrap().ctime.sec, 1015);
        vfs.open("/a", RW, 0).unwrap().truncate(0).unwrap();
        assert_eq!(vfs.stat("/a", true).unwrap().mtime.sec, 1015);
    }
}
