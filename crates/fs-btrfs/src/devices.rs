//! Devices: adding one to a mounted volume, removing one, and replacing one
//! with another.
//!
//! The volume keeps its devices in a map by device id (the mounted one and
//! those added since); chunks name the device of each stripe, and the chunk
//! allocator picks the device with the most room for each new chunk.
//!
//! * **Add** puts a `DEV_ITEM` for the new device in the chunk tree and writes
//!   its superblocks in the same commit. The superblocks of devices other
//!   than the mounted one go first, so that a crash in between leaves either
//!   the old volume or one the new device alone can describe.
//! * **Remove** keeps new chunks off the device, balances every chunk with a
//!   stripe on it onto the others, and then deletes its `DEV_ITEM`; the
//!   device's superblocks are wiped and the device handed back. The mounted
//!   device cannot be removed, and neither can one that holds a system chunk.
//! * **Replace** copies every device extent of a device, in place, onto a new
//!   device at least as large, and then switches to it in one commit. The new
//!   device takes over the old one's id and UUID, so the chunk and device
//!   extent items stay as they are; the old device's superblocks are wiped
//!   and it is handed back.
//!
//! A volume mounted afterwards sees the devices only if the mount knows all
//! of them; this driver's mount takes one device, and mounts a volume with
//! more read-only.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_zeroed};

use crate::balance::BalanceFilter;
use crate::disk::{Key, item, le64, put, put64, tree};
use crate::tree::Cursor;
use crate::write::Tx;
use crate::{MAX_RUN, Shared, csum, disk};

/// Smallest device that can be added.
const MIN_DEVICE: u64 = 16 << 20;

/// Bytes copied at a time by a replace.
const SLICE: u64 = 1 << 20;

/// A device of the volume, from its `DEV_ITEM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The device's id within the volume.
    pub devid: u64,
    /// Bytes of the device the volume may use.
    pub total_bytes: u64,
    /// Bytes of it in chunks.
    pub bytes_used: u64,
    /// The device's UUID.
    pub uuid: [u8; 16],
}

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// The devices in the chunk tree as of `st`.
    pub(crate) fn device_items(&self, st: &crate::State) -> Result<Vec<DeviceInfo>, Errno> {
        let mut c = Cursor::new(self, &st.chunks, st.chunk_root);
        let mut v = Vec::new();
        let mut cur = c.seek(Key::new(1, item::DEV_ITEM, 0))?;
        while let Some((k, d)) = cur {
            if k.objectid != 1 || k.ty != item::DEV_ITEM {
                break;
            }
            try_push(
                &mut v,
                DeviceInfo {
                    devid: le64(d, 0)?,
                    total_bytes: le64(d, 8)?,
                    bytes_used: le64(d, 16)?,
                    uuid: disk::array(d, 66)?,
                },
            )?;
            cur = c.next()?;
        }
        Ok(v)
    }

    /// A UUID for a new device, from what is known of the volume and the
    /// moment (there is no random source here).
    fn device_uuid(&self, devid: u64, size: u64) -> [u8; 16] {
        let now = self.now();
        let mut seed = [0u8; 48];
        seed[..16].copy_from_slice(&self.fsid);
        seed[16..24].copy_from_slice(&devid.to_le_bytes());
        seed[24..32].copy_from_slice(&size.to_le_bytes());
        seed[32..40].copy_from_slice(&(now.sec as u64).to_le_bytes());
        seed[40..44].copy_from_slice(&now.nsec.to_le_bytes());
        seed[44..48].copy_from_slice(&(self.label.len() as u32).to_le_bytes());
        let mut u = [0u8; 16];
        for (i, chunk) in u.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&csum::crc32c(!(i as u32).wrapping_mul(0x9E37_79B9), &seed).to_le_bytes());
        }
        // Version 4, variant 1, as a random UUID looks.
        u[6] = u[6] & 0x0F | 0x40;
        u[8] = u[8] & 0x3F | 0x80;
        u
    }

    /// Wipes the superblocks of `dev`, so that it no longer looks like part
    /// of a volume. Best effort: the device has left the volume already.
    fn wipe_supers(&self, dev: &mut D) {
        let bs = self.block_size as u64;
        let Ok(zeros) = try_zeroed(disk::SUPER_SIZE.max(self.block_size)) else { return };
        for at in [disk::SUPER_OFFSET, 64 << 20, 256 << 30] {
            if at + disk::SUPER_SIZE as u64 <= dev.num_blocks().saturating_mul(bs) {
                let _ = dev.write_blocks(at / bs, zeros.get(..disk::SUPER_SIZE.max(self.block_size)).unwrap_or(&[]));
            }
        }
        let _ = dev.flush();
    }

    /// Adds `dev` to the volume as a new device; returns its id.
    pub(crate) fn add_device(&self, dev: D) -> Result<u64, Errno> {
        let writer = self.writer.as_ref().ok_or(Errno::EROFS)?;
        if dev.block_size() != self.block_size {
            return Err(Errno::EINVAL);
        }
        let bytes = dev.num_blocks().checked_mul(self.block_size as u64).ok_or(Errno::EINVAL)?;
        let size = bytes / self.sectorsize * self.sectorsize;
        if size < MIN_DEVICE {
            return Err(Errno::EINVAL);
        }
        let mut w = writer.lock();
        if w.broken {
            return Err(Errno::EIO);
        }
        let devid = {
            let st = self.state();
            self.device_items(&st)?.iter().map(|d| d.devid).max().and_then(|m| m.checked_add(1)).ok_or(Errno::EIO)?
        };
        let uuid = self.device_uuid(devid, size);
        {
            let mut others = self.others.lock();
            others.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            others.push((devid, dev));
        }
        let r = self.transact_locked(&mut w, |tx| tx.add_dev_item(devid, size, uuid));
        if r.is_err() {
            self.others.lock().retain(|(id, _)| *id != devid);
        }
        r.map(|()| devid)
    }

    /// Takes device `devid` out of the volume, moving its chunks to the other
    /// devices first, and returns it.
    pub(crate) fn remove_device(&self, devid: u64) -> Result<D, Errno> {
        let writer = self.writer.as_ref().ok_or(Errno::EROFS)?;
        if devid == self.devid {
            return Err(Errno::EOPNOTSUPP);
        }
        {
            let mut w = writer.lock();
            if !self.has_dev(devid) {
                return Err(Errno::ENOENT);
            }
            if w.no_alloc.contains(&devid) {
                return Err(Errno::EBUSY);
            }
            w.no_alloc.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            w.no_alloc.push(devid);
        }
        let done = self.drain_device(devid);
        let mut w = writer.lock();
        w.no_alloc.retain(|&d| d != devid);
        done?;
        // Nothing is on it: delete its item, and then it is not part of the volume.
        self.transact_locked(&mut w, |tx| tx.drop_dev_item(devid))?;
        let mut others = self.others.lock();
        let i = others.iter().position(|(id, _)| *id == devid).ok_or(Errno::EIO)?;
        let (_, mut dev) = others.remove(i);
        drop(others);
        self.wipe_supers(&mut dev);
        Ok(dev)
    }

    /// Balances every chunk with a stripe on `devid` away from it.
    fn drain_device(&self, devid: u64) -> Result<(), Errno> {
        let f = BalanceFilter { devid: Some(devid), ..BalanceFilter::default() };
        let rep = self.balance(&f)?;
        if let Some(&(_, e)) = rep.skipped.first() {
            return Err(e);
        }
        if !rep.busy.is_empty() {
            return Err(Errno::EBUSY);
        }
        Ok(())
    }

    /// Replaces device `devid` with `new`, which must be at least as large;
    /// returns the old device.
    pub(crate) fn replace_device(&self, devid: u64, mut new: D) -> Result<D, Errno> {
        let writer = self.writer.as_ref().ok_or(Errno::EROFS)?;
        let mut w = writer.lock();
        if w.broken {
            return Err(Errno::EIO);
        }
        if new.block_size() != self.block_size {
            return Err(Errno::EINVAL);
        }
        let st = self.state();
        let info = self.device_items(&st)?.into_iter().find(|d| d.devid == devid).ok_or(Errno::ENOENT)?;
        if !self.has_dev(devid) {
            return Err(Errno::ENOENT);
        }
        let bs = self.block_size as u64;
        if new.num_blocks().saturating_mul(bs) < info.total_bytes {
            return Err(Errno::ENOSPC);
        }

        // Every device extent, as it is, to the same place on the new device.
        let dev_root = self.tree_root(&st, tree::DEV)?.ok_or(Errno::EIO)?;
        let mut extents: Vec<(u64, u64)> = Vec::new();
        {
            let mut c = Cursor::new(self, &st.chunks, (dev_root.bytenr, dev_root.level));
            let mut cur = c.seek(Key::new(devid, item::DEV_EXTENT, 0))?;
            while let Some((k, d)) = cur {
                if k.objectid != devid || k.ty != item::DEV_EXTENT {
                    break;
                }
                try_push(&mut extents, (k.offset, le64(d, 24)?))?;
                cur = c.next()?;
            }
        }
        let mut buf = try_zeroed(SLICE as usize)?;
        for (start, len) in extents {
            let mut off = 0;
            while off < len {
                let n = (len - off).min(SLICE);
                let part = buf.get_mut(..n as usize).ok_or(Errno::EIO)?;
                self.read_phys_dev(devid, start + off, part)?;
                let mut at = start + off;
                for run in part.chunks(MAX_RUN / self.block_size * self.block_size) {
                    new.write_blocks(at / bs, run).map_err(|_| Errno::EIO)?;
                    at += run.len() as u64;
                }
                off += n;
            }
        }
        new.flush().map_err(|_| Errno::EIO)?;

        // Switch, and commit so that the new device gets its superblocks.
        let old = self.swap_dev(devid, new)?;
        match self.transact_locked(&mut w, |tx| tx.touch()) {
            Ok(()) => {
                let mut old = old;
                self.wipe_supers(&mut old);
                Ok(old)
            }
            Err(e) => {
                // Put the old one back.
                let _ = self.swap_dev(devid, old);
                Err(e)
            }
        }
    }

    /// Puts `new` in place of device `devid`; returns the one that was there.
    fn swap_dev(&self, devid: u64, new: D) -> Result<D, Errno> {
        if devid == self.devid {
            return Ok(core::mem::replace(&mut *self.dev.lock(), new));
        }
        let mut others = self.others.lock();
        let (_, slot) = others.iter_mut().find(|(id, _)| *id == devid).ok_or(Errno::ENOENT)?;
        Ok(core::mem::replace(slot, new))
    }
}

impl<D: BlockDevice + Send + 'static> Tx<'_, D> {
    /// Inserts the item of a new device `devid` of `size` bytes, made from the
    /// mounted device's.
    pub(crate) fn add_dev_item(&mut self, devid: u64, size: u64, uuid: [u8; 16]) -> Result<(), Errno> {
        let mut di = self.find(tree::CHUNK, Key::new(1, item::DEV_ITEM, self.sh.devid))?.ok_or(Errno::EIO)?;
        di.truncate(98);
        put64(&mut di, 0, devid)?;
        put64(&mut di, 8, size)?;
        put64(&mut di, 16, 0)?;
        put(&mut di, 66, &uuid)?;
        self.insert(tree::CHUNK, Key::new(1, item::DEV_ITEM, devid), &di)?;
        self.touch()
    }

    /// Makes this transaction commit even if it changes nothing else: the
    /// root tree's root is rewritten, as every commit does, so that the new
    /// generation has a block of it, and the superblocks go out.
    pub(crate) fn touch(&mut self) -> Result<(), Errno> {
        self.path(tree::ROOT, Key::new(0, 0, 0), 0)?;
        self.force = true;
        Ok(())
    }

    /// Deletes the item of device `devid`, which holds no chunk.
    pub(crate) fn drop_dev_item(&mut self, devid: u64) -> Result<(), Errno> {
        if self.chunks().iter().any(|c| c.stripes.iter().any(|s| s.devid == devid)) {
            // Only a system chunk can still be there.
            return Err(Errno::EOPNOTSUPP);
        }
        let first = Key::new(devid, item::DEV_EXTENT, 0);
        if self.next_item(tree::DEV, first)?.is_some_and(|(k, _)| k.objectid == devid && k.ty == item::DEV_EXTENT) {
            return Err(Errno::EBUSY);
        }
        self.delete(tree::CHUNK, Key::new(1, item::DEV_ITEM, devid))?;
        self.touch()
    }
}
