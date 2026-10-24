//! A read-only ISO 9660 file system on any [`BlockDevice`], for the
//! `osmium-fs` VFS.
//!
//! [`IsoFs::mount`] reads the volume descriptors and [`IsoFs::root`] hands
//! out the root directory as an [`osmium_fs::File`], ready for `Vfs::mount`.
//! Names come from the richest source on the disc, as on Linux: Rock Ridge
//! (POSIX names, modes, link counts, symbolic links, device nodes and deep
//! directory relocation) if the primary tree carries it, else the Joliet
//! tree's Unicode names, else plain ISO 9660 names shown in lower case
//! without their `;1` version (and looked up ignoring case).
//!
//! Files of several extents (ISO level 3, larger than 4 GiB) and
//! interleaved files (a file unit size and an interleave gap size in the
//! directory record, each extent read unit by unit) are read whole. The device can have any block size; reads are byte-addressed.
//!
//! The volume is immutable, so nodes hold no shared state: a directory
//! reads and caches its entries the first time it is listed or searched.
//! Inode numbers are disk positions: a directory's is that of its extent,
//! anything else's that of its directory record.
//!
//! Not supported: timestamps (`osmium_fs::Stat` has no fields for them),
//! owners, multi-session discs beyond the first session's descriptors, and
//! UDF.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod desc;
mod name;
mod record;
mod rrip;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::mem::offset_of;

use osmium_fs::{DirEntry, Errno, File, FileKind, Stat};
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{OutOfMemory, try_arc, try_push, try_string, try_to_vec, try_zeroed};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Registry, Shared as SharedLink, TreeLink};
use osmium_sync::{Once, SpinLock};

use desc::Descriptor;
use record::{Record, Records, flag};
use rrip::RockRidge;

/// Volume descriptors read before giving up on finding the terminator.
const MAX_DESCRIPTORS: u64 = 64;

/// `CE` continuations followed for one record, against loops.
const MAX_CONTINUATIONS: usize = 16;

/// Largest single device read, so drivers see bounded transfers.
const MAX_RUN: usize = 64 * 1024;

/// Largest directory read into memory; a bigger one is taken as corrupt.
const MAX_DIR: u64 = 16 << 20;

/// Bytes of `CE` continuations and `CL` targets one directory read may
/// fetch beyond the directory itself, so a crafted image cannot turn each
/// record into many reads.
const SUSP_BUDGET: u64 = 64 * 1024;

/// Where a mounted volume's names come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Names {
    /// Plain ISO 9660 identifiers.
    Iso,
    /// The Joliet supplementary tree.
    Joliet,
    /// Rock Ridge entries in the primary tree.
    RockRidge,
}

/// File data of one directory record, contiguous or interleaved.
#[derive(Clone, Copy)]
struct Extent {
    /// Byte offset on the device.
    start: u64,
    /// Bytes of data (the gaps of an interleaved extent are not counted).
    len: u64,
    /// Bytes in each interleave unit; 0 if the data is contiguous.
    unit: u64,
    /// Bytes skipped between two units.
    gap: u64,
}

impl Extent {
    fn contiguous(start: u64, len: u64) -> Self {
        Extent { start, len, unit: 0, gap: 0 }
    }

    fn of(rec: &Record, lbs: u64) -> Self {
        let (unit, gap) = rec.interleave;
        // Both fields must be set for the extent to be interleaved.
        let (unit, gap) = if unit != 0 && gap != 0 { (unit as u64 * lbs, gap as u64 * lbs) } else { (0, 0) };
        Extent { start: rec.extent as u64 * lbs, len: rec.size as u64, unit, gap }
    }

    /// The device offset of data byte `skip` (below `len`) and how many
    /// bytes from there are contiguous; `EIO` if the arithmetic overflows.
    fn locate(&self, skip: u64) -> Result<(u64, u64), Errno> {
        let rest = self.len - skip;
        if self.unit == 0 {
            return Ok((self.start.checked_add(skip).ok_or(Errno::EIO)?, rest));
        }
        let stride = self.unit.checked_add(self.gap).ok_or(Errno::EIO)?;
        let within = skip % self.unit;
        let at = (skip / self.unit)
            .checked_mul(stride)
            .and_then(|o| o.checked_add(within))
            .and_then(|o| self.start.checked_add(o))
            .ok_or(Errno::EIO)?;
        Ok((at, rest.min(self.unit - within)))
    }
}

/// Everything known about one node, from its directory record.
struct Entry {
    name: String,
    kind: FileKind,
    ino: u64,
    mode: u32,
    nlink: u32,
    rdev: u64,
    size: u64,
    extents: Vec<Extent>,
    link: Option<String>,
}

struct Shared<D: BlockDevice + Send + 'static> {
    dev: SpinLock<D>,
    block_size: usize,
    dev_id: u64,
    /// Logical block size.
    lbs: u64,
    names: Names,
    /// Bytes skipped at the start of each system use area (from `SP`).
    susp_skip: usize,
    volume_id: String,
    /// Parsed directories by inode number, shared by every node of each. It
    /// does not own them: each [`DirBlock`] leaves it when dropped.
    dirs: SpinLock<Registry<ByIno<D>>>,
}

/// A directory's parsed entries, shared by every node of it.
struct DirBlock<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    ino: u64,
    entries: Vec<Entry>,
    /// Itself, for the cache to hand out references without allocating.
    me: Once<Weak<DirBlock<D>>>,
    link: SharedLink<TreeLink>,
}

struct ByIno<D>(core::marker::PhantomData<D>);

// SAFETY: `offset_of!` of a `SharedLink<TreeLink>`, which is a `TreeLink`.
unsafe impl<D: BlockDevice + Send + 'static> Adapter<TreeLink> for ByIno<D> {
    type Value = DirBlock<D>;
    const OFFSET: usize = offset_of!(DirBlock<D>, link);
}

impl<D: BlockDevice + Send + 'static> KeyAdapter<TreeLink> for ByIno<D> {
    type Key = u64;

    fn key(b: &DirBlock<D>) -> &u64 {
        &b.ino
    }
}

impl<D: BlockDevice + Send + 'static> Drop for DirBlock<D> {
    fn drop(&mut self) {
        // SAFETY: linked, if at all, in `dirs`.
        unsafe { self.shared.dirs.lock().remove(self) };
    }
}

/// A mounted ISO 9660 volume.
pub struct IsoFs<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    /// The root directory's node, made at mount so that handing it out cannot fail.
    root: Arc<dyn File>,
}

/// One file or directory of an [`IsoFs`].
pub struct Node<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    entry: Entry,
    children: Once<Arc<DirBlock<D>>>,
}

impl Entry {
    /// A copy, failing instead of panicking if memory runs out.
    fn try_clone(&self) -> Result<Self, OutOfMemory> {
        Ok(Entry {
            name: try_string(&self.name)?,
            kind: self.kind,
            ino: self.ino,
            mode: self.mode,
            nlink: self.nlink,
            rdev: self.rdev,
            size: self.size,
            extents: try_to_vec(&self.extents)?,
            link: self.link.as_deref().map(try_string).transpose()?,
        })
    }
}

/// One extent, as the list a new entry starts with.
fn one_extent(e: Extent) -> Result<Vec<Extent>, OutOfMemory> {
    let mut v = Vec::new();
    try_push(&mut v, e)?;
    Ok(v)
}

fn kind_of(mode: u32) -> Option<FileKind> {
    Some(match mode & 0o170000 {
        0o010000 => FileKind::Fifo,
        0o020000 => FileKind::CharDevice,
        0o040000 => FileKind::Directory,
        0o060000 => FileKind::BlockDevice,
        0o100000 => FileKind::Regular,
        0o120000 => FileKind::Symlink,
        0o140000 => FileKind::Socket,
        _ => return None,
    })
}

impl<D: BlockDevice + Send + 'static> IsoFs<D> {
    /// Mounts the ISO 9660 volume on `dev`. `dev_id` becomes `Stat::dev` of
    /// every node. Fails with `EINVAL` if the device does not hold one.
    pub fn mount(dev: D, dev_id: u64) -> Result<Self, Errno> {
        let block_size = dev.block_size();
        if block_size == 0 || block_size > MAX_RUN {
            return Err(Errno::EINVAL);
        }
        if (dev.num_blocks() as u128) * (block_size as u128) < (desc::FIRST + desc::SIZE as u64) as u128 {
            return Err(Errno::EINVAL);
        }
        let mut shared = Shared {
            dev: SpinLock::new(dev),
            block_size,
            dev_id,
            lbs: 2048,
            names: Names::Iso,
            susp_skip: 0,
            volume_id: String::new(),
            dirs: SpinLock::new(Registry::new()),
        };

        let (mut primary, mut joliet) = (None, None);
        let mut d = try_zeroed(desc::SIZE)?;
        for i in 0..MAX_DESCRIPTORS {
            shared.read_at(desc::FIRST + i * desc::SIZE as u64, &mut d).map_err(|_| Errno::EINVAL)?;
            match Descriptor::parse(&d)? {
                Descriptor::Terminator => break,
                Descriptor::Primary(v) => _ = primary.get_or_insert(v),
                Descriptor::Joliet(v) => _ = joliet.get_or_insert(v),
                Descriptor::Other => {}
            }
        }
        let primary = primary.ok_or(Errno::EINVAL)?;

        // Rock Ridge announces itself with an SP entry in the root's `.`.
        shared.lbs = primary.block_size as u64;
        let root = Record::parse(&primary.root)?;
        let mut first = try_zeroed(shared.lbs as usize)?;
        shared.read_at(root.extent as u64 * shared.lbs, &mut first)?;
        let dot = Records::new(&first, first.len()).next().ok_or(Errno::EIO)??.1;
        let volume = match rrip::sp_skip(dot.system_use) {
            Some(skip) if dot.is_dot() => {
                shared.names = Names::RockRidge;
                shared.susp_skip = skip;
                primary
            }
            _ => match joliet {
                Some(j) => {
                    shared.names = Names::Joliet;
                    j
                }
                None => primary,
            },
        };
        shared.lbs = volume.block_size as u64;
        shared.volume_id = volume.volume_id;

        let root = Record::parse(&volume.root)?;
        if root.flags & flag::DIRECTORY == 0 {
            return Err(Errno::EINVAL);
        }
        let start = root.extent as u64 * shared.lbs;
        let mut root = Entry {
            name: String::new(),
            kind: FileKind::Directory,
            ino: start,
            mode: 0o555,
            nlink: 2,
            rdev: 0,
            size: root.size as u64,
            extents: one_extent(Extent::contiguous(start, root.size as u64))?,
            link: None,
        };
        if shared.names == Names::RockRidge {
            let mut budget = SUSP_BUDGET;
            let rr = shared.rock_ridge(dot.system_use, &mut budget)?;
            if let Some(mode) = rr.mode {
                root.mode = mode & 0o7777;
            }
            root.nlink = rr.nlink.unwrap_or(root.nlink);
        }
        let shared = try_arc(shared)?;
        let root = try_arc(Node { shared: shared.clone(), entry: root, children: Once::new() })?;
        Ok(IsoFs { shared, root })
    }

    /// The root directory, to mount in a `Vfs`.
    pub fn root(&self) -> Arc<dyn File> {
        self.root.clone()
    }

    /// The volume identifier (the disc's label).
    pub fn volume_id(&self) -> &str {
        &self.shared.volume_id
    }

    /// Where the names come from.
    pub fn names(&self) -> Names {
        self.shared.names
    }
}

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// Reads `buf.len()` bytes at byte offset `off`.
    fn read_at(&self, mut off: u64, mut buf: &mut [u8]) -> Result<(), Errno> {
        let bs = self.block_size;
        let mut dev = self.dev.lock();
        let mut bounce = Vec::new();
        while !buf.is_empty() {
            let lba = off / bs as u64;
            let skip = (off % bs as u64) as usize;
            let n = if skip == 0 && buf.len() >= bs {
                let n = (buf.len() / bs * bs).min(MAX_RUN / bs * bs);
                dev.read_blocks(lba, buf.get_mut(..n).ok_or(Errno::EIO)?).map_err(|_| Errno::EIO)?;
                n
            } else {
                if bounce.is_empty() {
                    bounce = try_zeroed(bs)?;
                }
                dev.read_blocks(lba, &mut bounce).map_err(|_| Errno::EIO)?;
                let n = (bs - skip).min(buf.len());
                let (dst, src) = (buf.get_mut(..n), bounce.get(skip..skip + n));
                dst.zip(src).ok_or(Errno::EIO)?.0.copy_from_slice(src.ok_or(Errno::EIO)?);
                n
            };
            off = off.checked_add(n as u64).ok_or(Errno::EIO)?;
            buf = buf.get_mut(n..).ok_or(Errno::EIO)?;
        }
        Ok(())
    }

    /// The Rock Ridge entries of a record's system use area, following
    /// continuations as far as `budget` bytes allow.
    fn rock_ridge(&self, system_use: &[u8], budget: &mut u64) -> Result<RockRidge, Errno> {
        let mut rr = RockRidge::default();
        let mut more = rr.parse(system_use.get(self.susp_skip..).unwrap_or(&[]))?;
        let mut hops = 0;
        while let Some(ce) = more {
            hops += 1;
            if hops > MAX_CONTINUATIONS || ce.offset as u64 + ce.len as u64 > self.lbs || ce.len as u64 > *budget {
                return Err(Errno::EIO);
            }
            *budget -= ce.len as u64;
            let mut area = try_zeroed(ce.len as usize)?;
            self.read_at(ce.block as u64 * self.lbs + ce.offset as u64, &mut area)?;
            more = rr.parse(&area)?;
        }
        Ok(rr)
    }

    /// The entry for record `rec`, found at byte `pos`; `None` if it is not
    /// shown (a relocated directory's original, or a name a path cannot
    /// hold). Continuations and relocations are charged to `budget`.
    fn entry(&self, pos: u64, rec: &Record, budget: &mut u64) -> Result<Option<Entry>, Errno> {
        let dir = rec.flags & flag::DIRECTORY != 0;
        let mut e = Entry {
            name: match self.names {
                Names::Joliet => name::joliet(rec.name)?,
                _ => name::iso(rec.name)?,
            },
            kind: if dir { FileKind::Directory } else { FileKind::Regular },
            ino: pos,
            mode: if dir { 0o555 } else { 0o444 },
            nlink: if dir { 2 } else { 1 },
            rdev: 0,
            size: rec.size as u64,
            extents: one_extent(Extent::of(rec, self.lbs))?,
            link: None,
        };
        if self.names == Names::RockRidge {
            let mut rr = self.rock_ridge(rec.system_use, budget)?;
            if rr.relocated {
                return Ok(None);
            }
            if let Some(name) = rr.name()? {
                e.name = name;
            }
            if let Some(mode) = rr.mode {
                e.kind = kind_of(mode).unwrap_or(e.kind);
                e.mode = mode & 0o7777;
            }
            e.nlink = rr.nlink.unwrap_or(e.nlink);
            e.rdev = rr.rdev.unwrap_or(0);
            if let Some(block) = rr.child {
                // The directory itself lives elsewhere; its `.` has the size.
                let start = block as u64 * self.lbs;
                *budget = budget.checked_sub(self.lbs).ok_or(Errno::EIO)?;
                let mut first = try_zeroed(self.lbs as usize)?;
                self.read_at(start, &mut first)?;
                let dot = Records::new(&first, first.len()).next().ok_or(Errno::EIO)??.1;
                if !dot.is_dot() {
                    return Err(Errno::EIO);
                }
                e.kind = FileKind::Directory;
                e.size = dot.size as u64;
                e.extents = one_extent(Extent::contiguous(start, e.size))?;
            }
            if e.kind == FileKind::Symlink {
                e.link = rr.take_link();
                e.size = e.link.as_ref().map_or(0, |l| l.len() as u64);
            }
        }
        if e.kind == FileKind::Directory {
            e.ino = e.extents.first().ok_or(Errno::EIO)?.start;
        }
        if e.name.is_empty() || e.name == "." || e.name == ".." || e.name.contains(['/', '\0']) {
            return Ok(None);
        }
        Ok(Some(e))
    }

    /// Reads and parses the directory `dir`.
    fn read_dir(&self, dir: &Entry) -> Result<Vec<Entry>, Errno> {
        let ext = *dir.extents.first().ok_or(Errno::EIO)?;
        if ext.len > MAX_DIR {
            return Err(Errno::EIO);
        }
        let mut data = try_zeroed(ext.len as usize)?;
        self.read_at(ext.start, &mut data)?;
        let mut budget = SUSP_BUDGET + ext.len;
        let mut out = Vec::new();
        // A file whose earlier extents have been seen.
        let mut partial: Option<Entry> = None;
        for item in Records::new(&data, self.lbs as usize) {
            let (at, rec) = item?;
            if rec.is_dot() || rec.is_dotdot() || rec.flags & flag::ASSOCIATED != 0 {
                continue;
            }
            let last = rec.flags & flag::MULTI_EXTENT == 0;
            if let Some(p) = &mut partial {
                try_push(&mut p.extents, Extent::of(&rec, self.lbs))?;
                p.size += rec.size as u64;
                if last && let Some(done) = partial.take() {
                    try_push(&mut out, done)?;
                }
                continue;
            }
            match self.entry(ext.start + at as u64, &rec, &mut budget)? {
                Some(e) if !last && e.kind == FileKind::Regular => partial = Some(e),
                Some(e) => try_push(&mut out, e)?,
                None => {}
            }
        }
        if let Some(done) = partial {
            try_push(&mut out, done)?;
        }
        Ok(out)
    }
}

impl<D: BlockDevice + Send + 'static> Node<D> {
    fn children(&self) -> Result<&[Entry], Errno> {
        if self.entry.kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        if let Some(c) = self.children.get() {
            return Ok(&c.entries);
        }
        let ino = self.entry.ino;
        let cached = self.shared.dirs.lock().find(&ino).and_then(|b| b.me.get()?.upgrade());
        let c = match cached {
            Some(c) => c,
            None => {
                // Parsed without the lock; a racing reader's copy is as good.
                let entries = self.shared.read_dir(&self.entry)?;
                let block = try_arc(DirBlock {
                    shared: self.shared.clone(),
                    ino,
                    entries,
                    me: Once::new(),
                    link: SharedLink::new(TreeLink::new()),
                })?;
                let _ = block.me.set(Arc::downgrade(&block));
                let mut dirs = self.shared.dirs.lock();
                // A racing reader may have cached it meanwhile; or a block
                // being dropped, which waits for this lock, still has the key.
                match dirs.find(&ino).and_then(|b| b.me.get()?.upgrade()) {
                    Some(existing) => existing,
                    None => {
                        dirs.take(&ino);
                        // SAFETY: the block takes itself out when dropped, and
                        // its key never changes.
                        let fresh = unsafe { dirs.insert(&block) };
                        assert!(fresh, "the key was just freed");
                        block
                    }
                }
            }
        };
        Ok(&self.children.call_once(|| c).entries)
    }
}

impl<D: BlockDevice + Send + 'static> File for Node<D> {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        match self.entry.kind {
            FileKind::Regular => {}
            FileKind::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        if off >= self.entry.size {
            return Ok(0);
        }
        let want = buf.len().min((self.entry.size - off).min(usize::MAX as u64) as usize);
        let (mut done, mut skip) = (0, off);
        for ext in &self.entry.extents {
            if done == want {
                break;
            }
            if skip >= ext.len {
                skip -= ext.len;
                continue;
            }
            // An interleaved extent is read one unit at a time.
            while skip < ext.len && done < want {
                let (at, run) = ext.locate(skip)?;
                let n = run.min((want - done) as u64) as usize;
                self.shared.read_at(at, buf.get_mut(done..done + n).ok_or(Errno::EIO)?)?;
                done += n;
                skip += n as u64;
            }
            skip = 0;
        }
        Ok(done)
    }

    fn write(&self, _off: u64, _buf: &[u8]) -> Result<usize, Errno> {
        match self.entry.kind {
            FileKind::Directory => Err(Errno::EISDIR),
            _ => Err(Errno::EROFS),
        }
    }

    fn stat(&self) -> Stat {
        let e = &self.entry;
        Stat {
            dev: self.shared.dev_id,
            ino: e.ino,
            kind: e.kind,
            mode: e.mode,
            nlink: e.nlink,
            size: e.size,
            rdev: e.rdev,
        }
    }

    fn truncate(&self, _len: u64) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        let Some(e) = self.children()?.get(index) else { return Ok(None) };
        Ok(Some(DirEntry { ino: e.ino, kind: e.kind, name: try_string(&e.name)? }))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let children = self.children()?;
        let found = match self.shared.names {
            // Plain names are upper case on disc and shown in lower case.
            Names::Iso => children.iter().find(|e| e.name.eq_ignore_ascii_case(name)),
            _ => children.iter().find(|e| e.name == name),
        };
        let entry = found.ok_or(Errno::ENOENT)?.try_clone()?;
        Ok(try_arc(Node { shared: self.shared.clone(), entry, children: Once::new() })?)
    }

    fn create(&self, _name: &str, _kind: FileKind, _mode: u32) -> Result<Arc<dyn File>, Errno> {
        self.children()?;
        Err(Errno::EROFS)
    }

    fn remove(&self, _name: &str, _dir: bool) -> Result<(), Errno> {
        self.children()?;
        Err(Errno::EROFS)
    }

    fn readlink(&self) -> Result<String, Errno> {
        Ok(try_string(self.entry.link.as_deref().ok_or(Errno::EINVAL)?)?)
    }
}
