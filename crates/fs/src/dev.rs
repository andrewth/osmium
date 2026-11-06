//! Device nodes: a directory of kernel-provided files, `/dev/null` and
//! `/dev/zero`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use osmium_sync::RwSpinLock;
use osmium_sync::fallible::try_string;

use crate::{DirEntry, Errno, File, FileKind, Stat};

/// A directory whose entries the kernel adds itself, such as `/dev`: each
/// one any [`File`], like a console or a disk. Users cannot create or remove
/// entries.
pub struct DevDir {
    dev: u64,
    ino: u64,
    /// Sorted by name.
    entries: RwSpinLock<Vec<(String, Arc<dyn File>)>>,
}

/// Where `name` is in `entries`, or where it would go.
fn position(entries: &[(String, Arc<dyn File>)], name: &str) -> Result<usize, usize> {
    entries.binary_search_by(|(n, _)| n.as_str().cmp(name))
}

impl DevDir {
    /// An empty directory reporting `dev` and inode 1.
    pub fn new(dev: u64) -> Self {
        DevDir { dev, ino: 1, entries: RwSpinLock::new(Vec::new()) }
    }

    /// Adds `file` as `name`, replacing any entry of that name.
    ///
    /// # Panics
    ///
    /// If memory runs out; see [`try_insert`](DevDir::try_insert).
    pub fn insert(&self, name: &str, file: Arc<dyn File>) {
        self.try_insert(name, file).expect("out of memory adding a device node");
    }

    /// [`insert`](DevDir::insert), failing with `ENOMEM` (and changing
    /// nothing) if memory runs out.
    pub fn try_insert(&self, name: &str, file: Arc<dyn File>) -> Result<(), Errno> {
        let mut entries = self.entries.write();
        match position(&entries, name) {
            Ok(i) => {
                if let Some(slot) = entries.get_mut(i) {
                    slot.1 = file;
                }
            }
            Err(i) => {
                let name = try_string(name)?;
                entries.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                entries.insert(i, (name, file));
            }
        }
        Ok(())
    }

    /// Removes the entry `name`, returning it.
    pub fn take(&self, name: &str) -> Option<Arc<dyn File>> {
        let mut entries = self.entries.write();
        let i = position(&entries, name).ok()?;
        Some(entries.remove(i).1)
    }
}

impl File for DevDir {
    fn read(&self, _: u64, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EISDIR)
    }

    fn stat(&self) -> Stat {
        Stat { dev: self.dev, ino: self.ino, kind: FileKind::Directory, mode: 0o755, nlink: 2, ..Stat::default() }
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        let entries = self.entries.read();
        let Some((name, file)) = entries.get(index) else { return Ok(None) };
        let st = file.try_stat()?;
        Ok(Some(DirEntry { ino: st.ino, kind: st.kind, name: try_string(name)? }))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let entries = self.entries.read();
        let i = position(&entries, name).map_err(|_| Errno::ENOENT)?;
        entries.get(i).map(|(_, f)| f.clone()).ok_or(Errno::ENOENT)
    }

    fn create(&self, _: &str, _: FileKind, _: u32) -> Result<Arc<dyn File>, Errno> {
        Err(Errno::EPERM)
    }

    fn remove(&self, name: &str, _: bool) -> Result<(), Errno> {
        if position(&self.entries.read(), name).is_ok() { Err(Errno::EPERM) } else { Err(Errno::ENOENT) }
    }
}

/// `makedev(major, minor)` as Linux encodes `st_rdev`.
pub const fn makedev(major: u32, minor: u32) -> u64 {
    let (major, minor) = (major as u64, minor as u64);
    (major & 0xfff) << 8 | (major & !0xfff) << 32 | (minor & 0xff) | (minor & !0xff) << 12
}

/// The major number of the device number `rdev`, as Linux's `major(3)`
/// decodes it (the inverse of [`makedev`]).
pub const fn major(rdev: u64) -> u32 {
    ((rdev >> 8) & 0xfff | (rdev >> 32) & !0xfff) as u32
}

/// The minor number of the device number `rdev`, as Linux's `minor(3)`
/// decodes it (the inverse of [`makedev`]).
pub const fn minor(rdev: u64) -> u32 {
    ((rdev & 0xff) | (rdev >> 12) & 0xffff_ff00) as u32
}

static NEXT_INO: AtomicU64 = AtomicU64::new(1 << 32);

fn char_stat(ino: u64, rdev: u64) -> Stat {
    Stat { ino, kind: FileKind::CharDevice, mode: 0o666, nlink: 1, rdev, ..Stat::default() }
}

/// `/dev/null`: reads return end of file, writes are discarded.
pub struct Null(u64);

impl Null {
    /// A new null device.
    pub fn new() -> Self {
        Null(NEXT_INO.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for Null {
    fn default() -> Self {
        Self::new()
    }
}

impl File for Null {
    fn read(&self, _: u64, _: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }

    fn write(&self, _: u64, buf: &[u8]) -> Result<usize, Errno> {
        Ok(buf.len())
    }

    fn stat(&self) -> Stat {
        char_stat(self.0, makedev(1, 3))
    }

    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Ok(())
    }
}

/// `/dev/zero`: reads return zeroes, writes are discarded.
pub struct Zero(u64);

impl Zero {
    /// A new zero device.
    pub fn new() -> Self {
        Zero(NEXT_INO.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for Zero {
    fn default() -> Self {
        Self::new()
    }
}

impl File for Zero {
    fn read(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, _: u64, buf: &[u8]) -> Result<usize, Errno> {
        Ok(buf.len())
    }

    fn stat(&self) -> Stat {
        char_stat(self.0, makedev(1, 5))
    }

    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenFlags, RamFs, Vfs};

    #[test]
    fn device_numbers_round_trip() {
        for (major, minor) in [(0, 0), (1, 3), (8, 0), (255, 255), (256, 1), (4095, 0xf_ffff), (u32::MAX, u32::MAX)] {
            let rdev = makedev(major, minor);
            assert_eq!((super::major(rdev), super::minor(rdev)), (major, minor), "{rdev:#x}");
        }
        // glibc's encoding.
        assert_eq!(makedev(0x123, 0x45678), 0x4561_2378);
    }

    #[test]
    fn dev_directory() {
        let vfs = Vfs::new(RamFs::new(1).root());
        vfs.mkdir("/dev", 0o755).unwrap();
        let dev = Arc::new(DevDir::new(2));
        dev.insert("null", Arc::new(Null::new()));
        dev.insert("zero", Arc::new(Zero::new()));
        vfs.mount("/dev", dev.clone()).unwrap();

        let null = vfs.open("/dev/null", OpenFlags::READ | OpenFlags::WRITE | OpenFlags::TRUNC, 0).unwrap();
        assert_eq!(null.write(0, b"gone").unwrap(), 4);
        assert_eq!(null.read(0, &mut [0; 8]).unwrap(), 0);
        let st = null.stat();
        assert_eq!((st.kind, st.rdev), (FileKind::CharDevice, 0x103));

        let mut buf = [1; 8];
        assert_eq!(vfs.lookup("/dev/zero").unwrap().read(123, &mut buf).unwrap(), 8);
        assert_eq!(buf, [0; 8]);

        assert_eq!(dev.readdir(0).unwrap().unwrap().name, "null");
        assert_eq!(dev.readdir(2).unwrap(), None);
        assert_eq!(vfs.open("/dev/new", OpenFlags::CREATE, 0).err(), Some(Errno::EPERM));
        assert_eq!(vfs.unlink("/dev/null").err(), Some(Errno::EPERM));
        assert!(dev.take("zero").is_some());
        assert_eq!(vfs.lookup("/dev/zero").err(), Some(Errno::ENOENT));
        assert_eq!(makedev(259, 70000), 0x1111_0370);
        assert_eq!(makedev(0x1234, 1), 0x0000_1000_0002_3401);
    }
}
