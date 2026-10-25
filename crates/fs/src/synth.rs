//! Synthetic trees whose contents are generated when they are read: the
//! machinery under a `/proc`- or `/sys`-like file system, with none of the
//! layout of either.
//!
//! A directory is a function returning its entries; a file is a function
//! returning its contents. Nodes are built afresh on every lookup from what
//! the directory's function returns, so an open file is the only holder of
//! its node and can keep the bytes it generated: a reader that reads in
//! pieces sees one consistent snapshot, and reading from offset 0 again
//! (`pread`, `lseek`) takes a fresh one.
//!
//! ```
//! use osmium_fs::synth::{Entry, SynthFs};
//! use osmium_fs::{File, Vfs};
//!
//! let fs = SynthFs::new(7, || {
//!     Ok(vec![
//!         Entry::text("version", || Ok("1.0\n".into())),
//!         Entry::dir("stats", || Ok(vec![Entry::text("uptime", || Ok("42\n".into()))])),
//!     ])
//! })
//! .unwrap();
//! let vfs = Vfs::new(fs.root());
//! let mut buf = [0; 16];
//! let n = vfs.lookup("/stats/uptime").unwrap().read(0, &mut buf).unwrap();
//! assert_eq!(&buf[..n], b"42\n");
//! ```
//!
//! Generated files report size 0, as the files of `/proc` do: the length is
//! not known until the contents are, and they may differ at the next read.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_sync::SpinLock;
use osmium_sync::fallible::{try_arc, try_string};

use crate::{ClockSlot, DirEntry, Errno, File, FileKind, Stat};

/// Produces a file's contents.
type GenFn = Arc<dyn Fn() -> Result<Vec<u8>, Errno> + Send + Sync>;
/// Produces a directory's entries.
type ListFn = Arc<dyn Fn() -> Result<Vec<Entry>, Errno> + Send + Sync>;
/// Acts on what is written to a control file.
type WriteFn = Arc<dyn Fn(&[u8]) -> Result<(), Errno> + Send + Sync>;
/// Makes or removes a subdirectory by name.
type NameFn = Arc<dyn Fn(&str) -> Result<(), Errno> + Send + Sync>;
/// Fills a buffer from a binary file at an offset; returns the bytes read.
type ReadAtFn = Arc<dyn Fn(u64, &mut [u8]) -> Result<usize, Errno> + Send + Sync>;

enum Body {
    File(GenFn, Option<WriteFn>),
    Dir(ListFn, Option<NameFn>, Option<NameFn>),
    Link(String),
    Binary(ReadAtFn),
    /// An existing node, spliced into the tree as it is.
    Node(Arc<dyn File>),
}

/// An entry of a synthetic directory: a name and what it is.
pub struct Entry {
    name: String,
    perm: Option<u32>,
    body: Body,
}

impl Entry {
    fn new(name: impl Into<String>, body: Body) -> Self {
        Entry { name: name.into(), perm: None, body }
    }

    /// A file whose contents are the bytes `f` returns each time it is read
    /// from offset 0. Permission bits `0o444` unless [`Entry::on_write`] or
    /// [`Entry::mode`] says otherwise.
    pub fn file(name: impl Into<String>, f: impl Fn() -> Result<Vec<u8>, Errno> + Send + Sync + 'static) -> Self {
        Self::new(name, Body::File(Arc::new(f), None))
    }

    /// [`Entry::file`] for text.
    pub fn text(name: impl Into<String>, f: impl Fn() -> Result<String, Errno> + Send + Sync + 'static) -> Self {
        Self::file(name, move || Ok(f()?.into_bytes()))
    }

    /// A directory whose entries are those `f` returns each time it is
    /// searched or listed. Permission bits `0o555`.
    pub fn dir(name: impl Into<String>, f: impl Fn() -> Result<Vec<Entry>, Errno> + Send + Sync + 'static) -> Self {
        Self::new(name, Body::Dir(Arc::new(f), None, None))
    }

    /// A symbolic link to `target`.
    pub fn link(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self::new(name, Body::Link(target.into()))
    }

    /// A binary file read in place: `f(offset, buf)` fills `buf` and returns
    /// the bytes read (0 at the end). There is no snapshot, and the size is 0.
    pub fn binary(
        name: impl Into<String>,
        f: impl Fn(u64, &mut [u8]) -> Result<usize, Errno> + Send + Sync + 'static,
    ) -> Self {
        Self::new(name, Body::Binary(Arc::new(f)))
    }

    /// An existing node under `name`, reached as it is: reads, writes and
    /// everything else go to it, and `stat` is its own.
    pub fn node(name: impl Into<String>, node: Arc<dyn File>) -> Self {
        Self::new(name, Body::Node(node))
    }

    /// The same entry with permission bits `perm`. They are reported by
    /// `stat`; checking them is the caller's business, as everywhere in the
    /// file system layer.
    pub fn mode(mut self, perm: u32) -> Self {
        self.perm = Some(perm & 0o7777);
        self
    }

    /// The same file, made a control file: what is written to it (at any
    /// offset) is passed to `f`, and the write succeeds if `f` does. Its
    /// permission bits become `0o644` unless set by [`Entry::mode`].
    pub fn on_write(mut self, f: impl Fn(&[u8]) -> Result<(), Errno> + Send + Sync + 'static) -> Self {
        if let Body::File(_, write) = &mut self.body {
            *write = Some(Arc::new(f));
        }
        self
    }

    /// The same directory, in which `mkdir` calls `f` with the new name.
    /// The directory's own function decides whether the new entry shows up.
    pub fn on_mkdir(mut self, f: impl Fn(&str) -> Result<(), Errno> + Send + Sync + 'static) -> Self {
        if let Body::Dir(_, mkdir, _) = &mut self.body {
            *mkdir = Some(Arc::new(f));
        }
        self
    }

    /// The same directory, in which removing a subdirectory calls `f` with
    /// its name.
    pub fn on_rmdir(mut self, f: impl Fn(&str) -> Result<(), Errno> + Send + Sync + 'static) -> Self {
        if let Body::Dir(_, _, rmdir) = &mut self.body {
            *rmdir = Some(Arc::new(f));
        }
        self
    }

    fn kind(&self) -> FileKind {
        match &self.body {
            Body::File(..) | Body::Binary(_) => FileKind::Regular,
            Body::Dir(..) => FileKind::Directory,
            Body::Link(_) => FileKind::Symlink,
            Body::Node(node) => node.stat().kind,
        }
    }
}

/// A synthetic file system. [`root`](SynthFs::root) is its top directory.
pub struct SynthFs {
    root: Arc<SynthNode>,
}

struct Shared {
    dev: u64,
    clock: ClockSlot,
}

impl SynthFs {
    /// A tree whose root directory lists the entries `root` returns; `dev`
    /// is reported as every node's `st_dev`.
    pub fn new(dev: u64, root: impl Fn() -> Result<Vec<Entry>, Errno> + Send + Sync + 'static) -> Result<Self, Errno> {
        let shared = try_arc(Shared { dev, clock: ClockSlot::new() })?;
        let body = NodeBody::Dir(Arc::new(root), None, None);
        Ok(SynthFs { root: SynthNode::make(&shared, ROOT_INO, 0o555, body)? })
    }

    /// Stamps nodes with `clock` instead of the global one.
    pub fn set_clock(&self, clock: Arc<dyn crate::Clock>) {
        self.root.shared.clock.set(clock);
    }

    /// The root directory, to pass to [`Vfs::new`](crate::Vfs::new) or
    /// [`Vfs::mount`](crate::Vfs::mount).
    pub fn root(&self) -> Arc<dyn File> {
        self.root.clone()
    }
}

const ROOT_INO: u64 = 1;

enum NodeBody {
    /// The snapshot is what the last read from offset 0 generated.
    File(GenFn, Option<WriteFn>, SpinLock<Option<Vec<u8>>>),
    Dir(ListFn, Option<NameFn>, Option<NameFn>),
    Link(String),
    Binary(ReadAtFn),
}

struct SynthNode {
    shared: Arc<Shared>,
    ino: u64,
    perm: u32,
    body: NodeBody,
}

/// The inode number of the child `name` of directory `parent`: stable for a
/// name, and distinct from the root's.
fn child_ino(parent: u64, name: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325_u64;
    for b in parent.to_le_bytes().into_iter().chain(name.bytes()) {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    // Never 0 or the root's.
    h | (1 << 63)
}

impl SynthNode {
    fn make(shared: &Arc<Shared>, ino: u64, perm: u32, body: NodeBody) -> Result<Arc<Self>, Errno> {
        Ok(try_arc(SynthNode { shared: shared.clone(), ino, perm, body })?)
    }

    /// The node for `entry` of this directory.
    fn of(&self, entry: Entry) -> Result<Arc<dyn File>, Errno> {
        let ino = child_ino(self.ino, &entry.name);
        let (perm, body) = match entry.body {
            Body::Node(node) => return Ok(node),
            Body::File(generate, write) => {
                let default = if write.is_some() { 0o644 } else { 0o444 };
                (entry.perm.unwrap_or(default), NodeBody::File(generate, write, SpinLock::new(None)))
            }
            Body::Dir(list, mkdir, rmdir) => (entry.perm.unwrap_or(0o555), NodeBody::Dir(list, mkdir, rmdir)),
            Body::Link(target) => (entry.perm.unwrap_or(0o777), NodeBody::Link(target)),
            Body::Binary(read) => (entry.perm.unwrap_or(0o444), NodeBody::Binary(read)),
        };
        Ok(Self::make(&self.shared, ino, perm, body)?)
    }

    /// The entries of this directory.
    fn entries(&self) -> Result<Vec<Entry>, Errno> {
        match &self.body {
            NodeBody::Dir(list, ..) => list(),
            _ => Err(Errno::ENOTDIR),
        }
    }
}

/// Copies from `src` at `off` into `buf`.
fn copy_at(src: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let Some(rest) = usize::try_from(off).ok().and_then(|off| src.get(off..)) else { return 0 };
    let n = rest.len().min(buf.len());
    if let Some((src, dst)) = rest.get(..n).zip(buf.get_mut(..n)) {
        dst.copy_from_slice(src);
    }
    n
}

impl File for SynthNode {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        match &self.body {
            NodeBody::File(generate, _, snapshot) => {
                // Generated outside the lock: a generator may be slow or take
                // locks of its own.
                let fresh = if off == 0 || snapshot.lock().is_none() { Some(generate()?) } else { None };
                let mut snapshot = snapshot.lock();
                if let Some(fresh) = fresh {
                    *snapshot = Some(fresh);
                }
                Ok(snapshot.as_deref().map_or(0, |bytes| copy_at(bytes, off, buf)))
            }
            NodeBody::Binary(read) => read(off, buf),
            NodeBody::Dir(..) => Err(Errno::EISDIR),
            NodeBody::Link(_) => Err(Errno::EINVAL),
        }
    }

    fn write(&self, _off: u64, buf: &[u8]) -> Result<usize, Errno> {
        match &self.body {
            NodeBody::File(_, Some(write), _) => {
                write(buf)?;
                Ok(buf.len())
            }
            NodeBody::File(..) | NodeBody::Binary(_) => Err(Errno::EACCES),
            NodeBody::Dir(..) => Err(Errno::EISDIR),
            NodeBody::Link(_) => Err(Errno::EINVAL),
        }
    }

    fn truncate(&self, _len: u64) -> Result<(), Errno> {
        match &self.body {
            // Opening a control file with `O_TRUNC` must work.
            NodeBody::File(_, Some(_), _) => Ok(()),
            NodeBody::File(..) | NodeBody::Binary(_) => Err(Errno::EACCES),
            NodeBody::Dir(..) => Err(Errno::EISDIR),
            NodeBody::Link(_) => Err(Errno::EINVAL),
        }
    }

    fn stat(&self) -> Stat {
        let now = self.shared.clock.now();
        let (kind, nlink, size) = match &self.body {
            NodeBody::File(..) | NodeBody::Binary(_) => (FileKind::Regular, 1, 0),
            NodeBody::Dir(..) => (FileKind::Directory, 2, 0),
            NodeBody::Link(target) => (FileKind::Symlink, 1, target.len() as u64),
        };
        Stat {
            atime: now,
            mtime: now,
            ctime: now,
            dev: self.shared.dev,
            ino: self.ino,
            kind,
            mode: self.perm,
            nlink,
            size,
            rdev: 0,
        }
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        let Some(entry) = self.entries()?.into_iter().nth(index) else { return Ok(None) };
        let kind = entry.kind();
        let ino = match &entry.body {
            Body::Node(node) => node.stat().ino,
            _ => child_ino(self.ino, &entry.name),
        };
        Ok(Some(DirEntry { ino, kind, name: entry.name }))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let entry = self.entries()?.into_iter().find(|e| e.name == name).ok_or(Errno::ENOENT)?;
        self.of(entry)
    }

    fn create(&self, name: &str, kind: FileKind, _mode: u32) -> Result<Arc<dyn File>, Errno> {
        let NodeBody::Dir(_, mkdir, _) = &self.body else { return Err(Errno::ENOTDIR) };
        if self.entries()?.iter().any(|e| e.name == name) {
            return Err(Errno::EEXIST);
        }
        match (kind, mkdir) {
            (FileKind::Directory, Some(mkdir)) => {
                mkdir(name)?;
                self.lookup(name)
            }
            _ => Err(Errno::EPERM),
        }
    }

    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        let NodeBody::Dir(_, _, rmdir) = &self.body else { return Err(Errno::ENOTDIR) };
        let entry = self.entries()?.into_iter().find(|e| e.name == name).ok_or(Errno::ENOENT)?;
        match (dir, entry.kind() == FileKind::Directory) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            _ => {}
        }
        match rmdir {
            Some(rmdir) if dir => rmdir(name),
            _ => Err(Errno::EPERM),
        }
    }

    fn readlink(&self) -> Result<String, Errno> {
        match &self.body {
            NodeBody::Link(target) => Ok(try_string(target)?),
            _ => Err(Errno::EINVAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenFlags, Vfs};
    use alloc::format;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    fn names(dir: &dyn File) -> Vec<String> {
        (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect()
    }

    fn read_all(file: &dyn File) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0; 5];
        let mut off = 0;
        loop {
            let n = file.read(off, &mut buf).unwrap();
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..n]);
            off += n as u64;
        }
    }

    fn sample() -> (Vfs, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let fs = SynthFs::new(9, move || {
            let c = c.clone();
            Ok(vec![
                Entry::text("count", move || Ok(format!("{}\n", c.fetch_add(1, Ordering::SeqCst)))),
                Entry::dir("sub", || Ok(vec![Entry::file("bytes", || Ok(vec![1, 2, 3]))])),
                Entry::link("self", "/count"),
                Entry::binary("raw", |off, buf| {
                    let n = buf.len().min(8usize.saturating_sub(off as usize));
                    buf[..n].fill(0xab);
                    Ok(n)
                }),
            ])
        })
        .unwrap();
        (Vfs::new(fs.root()), counter)
    }

    #[test]
    fn lists_and_looks_up() {
        let (vfs, _) = sample();
        assert_eq!(names(&*vfs.lookup("/").unwrap()), ["count", "sub", "self", "raw"]);
        assert_eq!(names(&*vfs.lookup("/sub").unwrap()), ["bytes"]);
        assert_eq!(vfs.lookup("/nothing").err(), Some(Errno::ENOENT));
        assert_eq!(vfs.lookup("/count/x").err(), Some(Errno::ENOTDIR));
        let st = vfs.stat("/sub/bytes", true).unwrap();
        assert_eq!((st.kind, st.mode, st.dev, st.size), (FileKind::Regular, 0o444, 9, 0));
        assert_eq!(vfs.stat("/sub", true).unwrap().mode, 0o555);
        assert_eq!(read_all(&*vfs.lookup("/sub/bytes").unwrap()), [1, 2, 3]);
        // Inode numbers agree between a listing and `stat`, and are stable.
        let root = vfs.lookup("/").unwrap();
        let entry = root.readdir(1).unwrap().unwrap();
        assert_eq!(entry.ino, vfs.stat("/sub", true).unwrap().ino);
        assert_eq!(entry.ino, vfs.stat("/sub", true).unwrap().ino);
        assert_ne!(vfs.stat("/", true).unwrap().ino, entry.ino);
        assert_eq!(entry.kind, FileKind::Directory);
        assert_eq!(root.readdir(4).unwrap(), None);
    }

    #[test]
    fn follows_links() {
        let (vfs, _) = sample();
        assert_eq!(vfs.readlink("/self").unwrap(), "/count");
        assert_eq!(vfs.stat("/self", false).unwrap().kind, FileKind::Symlink);
        assert_eq!(read_all(&*vfs.lookup("/self").unwrap()), b"0\n");
    }

    #[test]
    fn reads_are_snapshots() {
        let (vfs, count) = sample();
        let f = vfs.lookup("/count").unwrap();
        // A reader that reads in pieces sees one generation.
        assert_eq!(read_all(&*f), b"0\n");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let mut buf = [0; 1];
        f.read(1, &mut buf).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        // Reading from the start again takes a fresh one.
        assert_eq!(read_all(&*f), b"1\n");
        // A read past the end of the first generation sees none of the next.
        let mut buf = [0; 8];
        assert_eq!(f.read(2, &mut buf).unwrap(), 0);
        // A node that was never read from the start generates on first use.
        let g = vfs.lookup("/count").unwrap();
        assert_eq!(g.read(1, &mut buf).unwrap(), 1);
        assert_eq!(&buf[..1], b"\n");
    }

    #[test]
    fn binary_files_are_read_in_place() {
        let (vfs, _) = sample();
        let f = vfs.lookup("/raw").unwrap();
        let mut buf = [0; 5];
        assert_eq!(f.read(0, &mut buf).unwrap(), 5);
        assert_eq!(f.read(5, &mut buf).unwrap(), 3);
        assert_eq!(f.read(8, &mut buf).unwrap(), 0);
        assert_eq!(buf[..3], [0xab; 3]);
    }

    #[test]
    fn is_read_only_by_default() {
        let (vfs, _) = sample();
        let f = vfs.lookup("/count").unwrap();
        assert_eq!(f.write(0, b"x").err(), Some(Errno::EACCES));
        assert_eq!(f.truncate(0).err(), Some(Errno::EACCES));
        assert_eq!(vfs.mkdir("/new", 0o755).err(), Some(Errno::EPERM));
        assert_eq!(vfs.open("/new", OpenFlags::CREATE, 0o644).err(), Some(Errno::EPERM));
        assert_eq!(vfs.unlink("/count").err(), Some(Errno::EPERM));
        assert_eq!(vfs.rmdir("/sub").err(), Some(Errno::EPERM));
        assert_eq!(vfs.rmdir("/count").err(), Some(Errno::ENOTDIR));
        assert_eq!(vfs.unlink("/sub").err(), Some(Errno::EISDIR));
        assert_eq!(vfs.mkdir("/sub", 0o755).err(), Some(Errno::EEXIST));
        assert_eq!(vfs.lookup("/sub").unwrap().read(0, &mut [0; 1]).err(), Some(Errno::EISDIR));
        assert_eq!(vfs.lookup("/self").unwrap().read(0, &mut [0; 1]).err(), None);
    }

    #[test]
    fn control_files_and_directory_hooks() {
        let written: Arc<SpinLock<Vec<u8>>> = Arc::new(SpinLock::new(Vec::new()));
        let groups: Arc<SpinLock<Vec<String>>> = Arc::new(SpinLock::new(vec![String::from("a")]));
        let (w, g1, g2, g3) = (written.clone(), groups.clone(), groups.clone(), groups.clone());
        let fs = SynthFs::new(1, move || {
            let (w, g1, g2, g3) = (w.clone(), g1.clone(), g2.clone(), g3.clone());
            Ok(vec![
                Entry::text("knob", || Ok("on\n".into())).on_write(move |data| {
                    if data.contains(&b'!') {
                        return Err(Errno::EINVAL);
                    }
                    *w.lock() = data.to_vec();
                    Ok(())
                }),
                Entry::dir("groups", move || {
                    Ok(g1.lock().iter().map(|n| Entry::dir(n.clone(), || Ok(Vec::new()))).collect())
                })
                .on_mkdir(move |name| {
                    g2.lock().push(name.into());
                    Ok(())
                })
                .on_rmdir(move |name| {
                    g3.lock().retain(|n| n != name);
                    Ok(())
                })
                .mode(0o755),
            ])
        })
        .unwrap();
        let vfs = Vfs::new(fs.root());
        assert_eq!(vfs.stat("/knob", true).unwrap().mode, 0o644);
        assert_eq!(vfs.stat("/groups", true).unwrap().mode, 0o755);
        let knob = vfs.open("/knob", OpenFlags::WRITE | OpenFlags::TRUNC, 0).unwrap();
        assert_eq!(knob.write(0, b"off").unwrap(), 3);
        assert_eq!(*written.lock(), b"off");
        assert_eq!(knob.write(0, b"bad!").err(), Some(Errno::EINVAL));
        assert_eq!(*written.lock(), b"off");
        vfs.mkdir("/groups/b", 0o755).unwrap();
        assert_eq!(names(&*vfs.lookup("/groups").unwrap()), ["a", "b"]);
        assert_eq!(vfs.mkdir("/groups/b", 0o755).err(), Some(Errno::EEXIST));
        assert_eq!(vfs.open("/groups/f", OpenFlags::CREATE, 0o644).err(), Some(Errno::EPERM));
        vfs.rmdir("/groups/a").unwrap();
        assert_eq!(names(&*vfs.lookup("/groups").unwrap()), ["b"]);
        assert_eq!(vfs.rmdir("/groups/a").err(), Some(Errno::ENOENT));
        assert_eq!(vfs.unlink("/knob").err(), Some(Errno::EPERM));
    }

    #[test]
    fn splices_existing_nodes() {
        let ram = crate::RamFs::new(3);
        let ram_vfs = Vfs::new(ram.root());
        ram_vfs.open("/data", OpenFlags::WRITE | OpenFlags::CREATE, 0o600).unwrap().write(0, b"real").unwrap();
        let node = ram_vfs.lookup("/data").unwrap();
        let ino = node.stat().ino;
        let fs = SynthFs::new(4, move || Ok(vec![Entry::node("data", node.clone())])).unwrap();
        let vfs = Vfs::new(fs.root());
        let f = vfs.lookup("/data").unwrap();
        assert_eq!(read_all(&*f), b"real");
        f.write(4, b"!").unwrap();
        assert_eq!(read_all(&*ram_vfs.lookup("/data").unwrap()), b"real!");
        let st = vfs.stat("/data", true).unwrap();
        assert_eq!((st.dev, st.ino, st.mode), (3, ino, 0o600));
        assert_eq!(vfs.lookup("/").unwrap().readdir(0).unwrap().unwrap().ino, ino);
    }

    #[test]
    fn generator_errors_surface() {
        let fs = SynthFs::new(1, || {
            Ok(vec![Entry::file("broken", || Err(Errno::EIO)), Entry::dir("gone", || Err(Errno::ENOMEM))])
        })
        .unwrap();
        let vfs = Vfs::new(fs.root());
        assert_eq!(vfs.lookup("/broken").unwrap().read(0, &mut [0; 1]).err(), Some(Errno::EIO));
        assert_eq!(vfs.lookup("/gone").unwrap().readdir(0).err(), Some(Errno::ENOMEM));
        assert_eq!(vfs.lookup("/gone/x").err(), Some(Errno::ENOMEM));
        let failing = SynthFs::new(1, || Err(Errno::EIO)).unwrap();
        assert_eq!(failing.root().readdir(0).err(), Some(Errno::EIO));
    }

    #[test]
    fn mounts_under_another_file_system() {
        let vfs = Vfs::new(crate::RamFs::new(1).root());
        vfs.mkdir("/info", 0o755).unwrap();
        let fs = SynthFs::new(2, || Ok(vec![Entry::text("a", || Ok("A".into()))])).unwrap();
        vfs.mount("/info", fs.root()).unwrap();
        assert_eq!(read_all(&*vfs.lookup("/info/a").unwrap()), b"A");
        assert_eq!(vfs.stat("/info/a", true).unwrap().dev, 2);
    }
}
