//! Hashed (htree) directories.
//!
//! An indexed directory's first block holds `.`, `..` and the root of a tree
//! of index entries `(hash, block)` sorted by hash; each leaf is an ordinary
//! directory block holding the names whose hashes fall in its range, and
//! there may be one more level of index blocks between the root and the
//! leaves. A name is looked up, added or removed in the one leaf its hash
//! leads to; a full leaf is split by hash order into a new block, and a full
//! index block is split (or the tree grows a level) the same way. A one-block
//! directory that fills up is given an index on volumes with `dir_index`;
//! bigger linear ones stay linear. Every change touches a few blocks (the
//! tree's depth plus two).
//!
//! An index that cannot be trusted (bad hash version, depth or limits, a
//! block out of range or met twice, a bad checksum) is never followed: a
//! lookup reads such a directory linearly, and an insertion drops the index
//! first (`Fs::drop_index`).
//!
//! The hash functions and the pure parts of the layout come first; they are
//! checked against vectors from e2fsprogs.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_to_vec, try_zeroed};

use super::{
    COMPAT_DIR_INDEX, Csum, DIR_TAIL_LEN, Fs, INDEX_FL, Inode, byte, crc32c, get16, get32, put_bytes, put16, put32,
    rec_len_for, sb, sub,
};

/// `s_def_hash_version` / `dx_root_info.hash_version` values. The unsigned
/// variants (+3) are what a volume flagged `EXT2_FLAGS_UNSIGNED_HASH` uses
/// for the first three: they differ only for bytes >= 0x80, which the
/// signed ones read as negative `char`s.
const LEGACY: u8 = 0;
const HALF_MD4: u8 = 1;
const TEA: u8 = 2;
const LEGACY_UNSIGNED: u8 = 3;
const HALF_MD4_UNSIGNED: u8 = 4;
const TEA_UNSIGNED: u8 = 5;

/// `(hash, minor hash)` of `name` with hash `version` and the superblock's
/// `s_hash_seed` (all zeros means the default seed), as Linux's
/// `ext4fs_dirhash`. The hash's low bit is always clear: in an index entry
/// it marks a run of equal hashes continued from the previous block. None
/// for a version we do not know (or SipHash, which needs casefolding).
fn dirhash(version: u8, seed: [u32; 4], name: &[u8]) -> Option<(u32, u32)> {
    let mut buf = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    if seed.iter().any(|&w| w != 0) {
        buf = seed;
    }
    let unsigned = version >= LEGACY_UNSIGNED;
    let (hash, minor) = match version {
        LEGACY | LEGACY_UNSIGNED => (legacy(name, unsigned), 0),
        HALF_MD4 | HALF_MD4_UNSIGNED => {
            let mut input = [0u32; 8];
            for chunk in (0..name.len()).step_by(32) {
                str2hashbuf(name.get(chunk..).unwrap_or(&[]), unsigned, &mut input);
                half_md4(&mut buf, &input);
            }
            (buf[1], buf[2])
        }
        TEA | TEA_UNSIGNED => {
            let mut input = [0u32; 4];
            for chunk in (0..name.len()).step_by(16) {
                str2hashbuf(name.get(chunk..).unwrap_or(&[]), unsigned, &mut input);
                tea(&mut buf, &input);
            }
            (buf[0], buf[1])
        }
        _ => return None,
    };
    let mut hash = hash & !1;
    // The largest hash is the end-of-directory marker of 32-bit readdir
    // cookies.
    if hash == 0x7fff_ffff << 1 {
        hash = (0x7fff_ffff - 1) << 1;
    }
    Some((hash, minor))
}

/// A byte as C's `char`: signed for the signed hashes.
fn signed_byte(c: u8, unsigned: bool) -> u32 {
    if unsigned { c as u32 } else { c as i8 as i32 as u32 }
}

fn legacy(name: &[u8], unsigned: bool) -> u32 {
    let (mut h0, mut h1) = (0x12a3_fe2du32, 0x37ab_e8f9u32);
    for &c in name {
        let mut h = h1.wrapping_add(h0 ^ signed_byte(c, unsigned).wrapping_mul(7_152_373));
        if h & 0x8000_0000 != 0 {
            h = h.wrapping_sub(0x7fff_ffff);
        }
        h1 = h0;
        h0 = h;
    }
    h0 << 1
}

/// Pack (the rest of) a name into `out.len()` words, padded with its
/// length, as `str2hashbuf_{signed,unsigned}`.
fn str2hashbuf(msg: &[u8], unsigned: bool, out: &mut [u32]) {
    let len = msg.len() as u32;
    let mut pad = len | (len << 8);
    pad |= pad << 16;
    let mut val = pad;
    let n = out.len() * 4;
    let mut words = out.iter_mut();
    for (i, &c) in msg.iter().take(n).enumerate() {
        val = signed_byte(c, unsigned).wrapping_add(val << 8);
        if i % 4 == 3 {
            if let Some(w) = words.next() {
                *w = val;
            }
            val = pad;
        }
    }
    if let Some(w) = words.next() {
        *w = val;
    }
    for w in words {
        *w = pad;
    }
}

fn tea(buf: &mut [u32; 4], input: &[u32; 4]) {
    const DELTA: u32 = 0x9e37_79b9;
    let (mut sum, mut b0, mut b1) = (0u32, buf[0], buf[1]);
    let [a, b, c, d] = *input;
    for _ in 0..16 {
        sum = sum.wrapping_add(DELTA);
        b0 = b0.wrapping_add((b1 << 4).wrapping_add(a) ^ b1.wrapping_add(sum) ^ (b1 >> 5).wrapping_add(b));
        b1 = b1.wrapping_add((b0 << 4).wrapping_add(c) ^ b0.wrapping_add(sum) ^ (b0 >> 5).wrapping_add(d));
    }
    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

fn half_md4(buf: &mut [u32; 4], x: &[u32; 8]) {
    const K2: u32 = 0x5a82_7999;
    const K3: u32 = 0x6ed9_eba1;
    let f = |x: u32, y: u32, z: u32| z ^ (x & (y ^ z));
    let g = |x: u32, y: u32, z: u32| (x & y).wrapping_add((x ^ y) & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    let [mut a, mut b, mut c, mut d] = *buf;
    let round = |fun: &dyn Fn(u32, u32, u32) -> u32, a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32| {
        *a = a.wrapping_add(fun(b, c, d)).wrapping_add(x).rotate_left(s);
    };
    // Round 1.
    round(&f, &mut a, b, c, d, x[0], 3);
    round(&f, &mut d, a, b, c, x[1], 7);
    round(&f, &mut c, d, a, b, x[2], 11);
    round(&f, &mut b, c, d, a, x[3], 19);
    round(&f, &mut a, b, c, d, x[4], 3);
    round(&f, &mut d, a, b, c, x[5], 7);
    round(&f, &mut c, d, a, b, x[6], 11);
    round(&f, &mut b, c, d, a, x[7], 19);
    // Round 2.
    round(&g, &mut a, b, c, d, x[1].wrapping_add(K2), 3);
    round(&g, &mut d, a, b, c, x[3].wrapping_add(K2), 5);
    round(&g, &mut c, d, a, b, x[5].wrapping_add(K2), 9);
    round(&g, &mut b, c, d, a, x[7].wrapping_add(K2), 13);
    round(&g, &mut a, b, c, d, x[0].wrapping_add(K2), 3);
    round(&g, &mut d, a, b, c, x[2].wrapping_add(K2), 5);
    round(&g, &mut c, d, a, b, x[4].wrapping_add(K2), 9);
    round(&g, &mut b, c, d, a, x[6].wrapping_add(K2), 13);
    // Round 3.
    round(&h, &mut a, b, c, d, x[3].wrapping_add(K3), 3);
    round(&h, &mut d, a, b, c, x[7].wrapping_add(K3), 9);
    round(&h, &mut c, d, a, b, x[2].wrapping_add(K3), 11);
    round(&h, &mut b, c, d, a, x[6].wrapping_add(K3), 15);
    round(&h, &mut a, b, c, d, x[1].wrapping_add(K3), 3);
    round(&h, &mut d, a, b, c, x[5].wrapping_add(K3), 9);
    round(&h, &mut c, d, a, b, x[0].wrapping_add(K3), 11);
    round(&h, &mut b, c, d, a, x[4].wrapping_add(K3), 15);
    buf[0] = buf[0].wrapping_add(a);
    buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c);
    buf[3] = buf[3].wrapping_add(d);
}

/// Where a full leaf block of `block_size` bytes is split, given the sizes
/// of its live entries in hash order: the index of the first entry that
/// moves to the new block. As Linux's `do_split`, entries move from the top
/// while they fill no more than half a block, so that each block keeps at
/// least about half its space; when that leaves only one entry behind, the
/// split is by count. None with fewer than two entries, which no full block
/// has.
fn split_point(sizes: &[usize], block_size: usize) -> Option<usize> {
    let count = sizes.len();
    if count < 2 {
        return None;
    }
    let mut moved = 0;
    for (i, &s) in sizes.iter().enumerate().rev() {
        if moved + s / 2 > block_size / 2 {
            if i > 0 {
                return Some(i + 1);
            }
            break;
        }
        moved += s;
    }
    Some(count / 2)
}

/// The entry of an index node to follow for `hash`: the last one whose hash
/// is at most `hash` (entry 0 has none: it covers everything below entry
/// 1). `hash_at(i)` is entry `i`'s hash, continuation bit included, for
/// `0 < i < count`. Entries out of order make this pick some entry, never
/// one out of range.
fn search(count: usize, hash: u32, hash_at: impl Fn(usize) -> u32) -> usize {
    let (mut lo, mut hi) = (1, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if hash_at(mid) > hash { hi = mid } else { lo = mid + 1 }
    }
    lo - 1
}

/// How many 8-byte index entries the root block (`info_length` 8) and an
/// interior node hold, leaving room for the 8-byte `dx_tail` checksum
/// under `metadata_csum`.
fn limits(block_size: usize, csum: bool) -> (usize, usize) {
    let tail = if csum { 8 } else { 0 };
    (block_size.saturating_sub(32 + tail) / 8, block_size.saturating_sub(8 + tail) / 8)
}

const SB_FLAGS_UNSIGNED_HASH: u32 = 0x2;
/// The bits of an index entry's block number (the rest are reserved).
const DX_BLOCK_MASK: u32 = 0x0fff_ffff;
/// Where `dx_root_info` and the root's entry array start.
pub(super) const DX_INFO: usize = 24;
const DX_ROOT_BASE: usize = 32;
/// Where an interior node's entry array starts.
const DX_NODE_BASE: usize = 8;
/// The most levels an index may have, the root included (without `largedir`).
const DX_MAX_LEVELS: usize = 2;

/// How an indexed directory's names are hashed.
#[derive(Clone, Copy)]
struct DxHash {
    version: u8,
    seed: [u32; 4],
}

impl DxHash {
    /// The major hash. (The version was checked when the root was read.)
    fn of(&self, name: &[u8]) -> u32 {
        dirhash(self.version, self.seed, name).map_or(0, |h| h.0)
    }
}

/// An indexed directory, as its root describes it.
struct Dx {
    hash: DxHash,
    /// Interior levels below the root (0: the root points at leaves).
    levels: usize,
    /// The directory's size in blocks: every block named must be below.
    nblocks: u64,
    /// The seed of the directory's block checksums.
    seed: u32,
}

/// An index block on the way from the root to a leaf, and the entry
/// followed in it.
struct DxFrame {
    lblk: u64,
    phys: u64,
    block: Vec<u8>,
    /// Offset of the entry array.
    base: usize,
    at: usize,
}

impl DxFrame {
    fn limit(&self) -> usize {
        get16(&self.block, self.base) as usize
    }

    fn count(&self) -> usize {
        get16(&self.block, self.base + 2) as usize
    }

    fn set_count(&mut self, n: usize) {
        put16(&mut self.block, self.base + 2, n as u16);
    }

    fn set_limit(&mut self, n: usize) {
        put16(&mut self.block, self.base, n as u16);
    }

    /// Entry `i`'s hash (for `i > 0`), continuation bit included.
    fn hash(&self, i: usize) -> u32 {
        get32(&self.block, self.base + 8 * i)
    }

    fn child(&self, i: usize) -> u64 {
        (get32(&self.block, self.base + 8 * i + 4) & DX_BLOCK_MASK) as u64
    }

    fn set_child(&mut self, i: usize, b: u64) {
        put32(&mut self.block, self.base + 8 * i + 4, b as u32);
    }

    /// Entries `from..to` as bytes.
    fn entries(&self, from: usize, to: usize) -> Result<&[u8], Errno> {
        self.block.get(self.base + 8 * from..self.base + 8 * to).ok_or(Errno::EIO)
    }

    /// Inserts `(hash, block)` after entry `at`; `ENOSPC` if the node is
    /// full.
    fn insert_after(&mut self, at: usize, hash: u32, block: u64) -> Result<(), Errno> {
        let count = self.count();
        if count >= self.limit() || at >= count {
            return Err(Errno::EIO);
        }
        let start = self.base + 8 * (at + 1);
        let end = self.base + 8 * count;
        if end + 8 > self.block.len() {
            return Err(Errno::EIO);
        }
        self.block.copy_within(start..end, start + 8);
        put32(&mut self.block, start, hash);
        put32(&mut self.block, start + 4, block as u32);
        self.set_count(count + 1);
        Ok(())
    }
}

/// A live directory entry, as a leaf block holds it.
struct Entry {
    name: Vec<u8>,
    ino: u32,
    ftype: u8,
}

/// Where an entry was found: the physical block, its bytes and the entry's
/// offset in them.
pub(super) type Located = (u64, Vec<u8>, usize);

impl<D: BlockDevice + Send + 'static> Fs<D> {
    fn dx_enabled(&self) -> bool {
        get32(&self.sb, sb::FEATURE_COMPAT) & COMPAT_DIR_INDEX != 0
    }

    /// The length of the name of the entry at `off`.
    fn name_len_at(&self, data: &[u8], off: usize) -> usize {
        if self.filetype { byte(data, off + 6) as usize } else { get16(data, off + 6) as usize }
    }

    /// The superblock's hash seed, default hash version and whether hashes
    /// read bytes as unsigned.
    fn dx_params(&self) -> ([u32; 4], u8, bool) {
        let seed = core::array::from_fn(|i| get32(&self.sb, sb::HASH_SEED + 4 * i));
        (seed, byte(&self.sb, sb::DEF_HASH_VERSION), get32(&self.sb, sb::FLAGS) & SB_FLAGS_UNSIGNED_HASH != 0)
    }

    fn dx_hash(&self, stored: u8) -> DxHash {
        let (seed, _, unsigned) = self.dx_params();
        DxHash { version: stored + if unsigned { LEGACY_UNSIGNED } else { 0 }, seed }
    }

    /// The checksum of an index block whose entry array is at `base`, and
    /// where it goes; None if the array overruns its room.
    fn dx_csum(seed: u32, b: &[u8], base: usize) -> Option<(usize, u32)> {
        let (limit, count) = (get16(b, base) as usize, get16(b, base + 2) as usize);
        let tail = base + 8 * limit;
        if count > limit || tail + 8 > b.len() {
            return None;
        }
        let c = crc32c(seed, sub(b, 0..base + 8 * count));
        let c = crc32c(c, sub(b, tail..tail + 4));
        Some((tail, crc32c(c, &[0; 4])))
    }

    /// Sets the checksum of the index block `b` whose entry array is at
    /// `base`.
    fn seal_dx(&self, seed: u32, b: &mut [u8], base: usize) {
        if self.csum != Csum::Crc32c {
            return;
        }
        if let Some((tail, c)) = Self::dx_csum(seed, b, base) {
            put32(b, tail + 4, c);
        }
    }

    /// Whether `b` is shaped like the root of an index: `.` and `..` spanning
    /// the block, then a `dx_root_info` we understand.
    fn dx_root_shaped(&self, b: &[u8]) -> bool {
        get16(b, 4) == 12
            && self.name_len_at(b, 0) == 1
            && get16(b, 16) as usize == self.block_size.saturating_sub(12)
            && self.name_len_at(b, 12) == 2
            && get32(b, DX_INFO) == 0
            && byte(b, DX_INFO + 5) == 8
            && byte(b, DX_INFO + 7) & 1 == 0
    }

    /// Reads index block `lblk` (the root, or an interior node) and checks
    /// its shape; None if it is not one we can trust.
    fn dx_read(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        seed: u32,
        lblk: u64,
        root: bool,
        nblocks: u64,
    ) -> Result<Option<DxFrame>, Errno> {
        if lblk >= nblocks {
            return Ok(None);
        }
        let phys = self.bmap(ino, inode, lblk, false)?;
        if phys == 0 {
            return Ok(None);
        }
        let block = self.read_block(phys)?;
        let bs = self.block_size;
        let (root_limit, node_limit) = limits(bs, self.csum == Csum::Crc32c);
        let (base, limit) = if root {
            if !self.dx_root_shaped(&block) {
                return Ok(None);
            }
            (DX_ROOT_BASE, root_limit)
        } else {
            if get16(&block, 4) as usize != bs || get32(&block, 0) != 0 {
                return Ok(None);
            }
            (DX_NODE_BASE, node_limit)
        };
        let f = DxFrame { lblk, phys, block, base, at: 0 };
        if f.limit() != limit || f.count() == 0 || f.count() > limit {
            return Ok(None);
        }
        if self.csum == Csum::Crc32c {
            match Self::dx_csum(seed, &f.block, base) {
                Some((tail, c)) if get32(&f.block, tail + 4) == c => {}
                _ => return Ok(None),
            }
        }
        Ok(Some(f))
    }

    /// An indexed directory's root, checked; None if the directory has no
    /// index, or none we can use.
    fn dx_root(&mut self, ino: u32, inode: &mut Inode) -> Result<Option<(Dx, DxFrame)>, Errno> {
        if inode.flags() & INDEX_FL == 0 || !self.dx_enabled() {
            return Ok(None);
        }
        let bs = self.block_size as u64;
        if !inode.size().is_multiple_of(bs) {
            return Ok(None);
        }
        let nblocks = inode.size() / bs;
        let seed = self.inode_seed(ino, inode);
        let Some(root) = self.dx_read(ino, inode, seed, 0, true, nblocks)? else { return Ok(None) };
        let (version, levels) = (byte(&root.block, DX_INFO + 4), byte(&root.block, DX_INFO + 6) as usize);
        if version > TEA || levels >= DX_MAX_LEVELS {
            return Ok(None);
        }
        Ok(Some((Dx { hash: self.dx_hash(version), levels, nblocks, seed }, root)))
    }

    /// Whether `lblk` can be the child of the last frame of `path`: inside
    /// the directory, not the root nor a block already on the path (which
    /// would make the tree a loop).
    fn dx_child_ok(dx: &Dx, path: &[DxFrame], lblk: u64) -> bool {
        lblk != 0 && lblk < dx.nblocks && path.iter().all(|f| f.lblk != lblk)
    }

    /// Walks from the root down to the leaf for `hash`; the path, its last
    /// frame's `at` naming the leaf. None if the index is unusable.
    fn dx_probe(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        dx: &Dx,
        root: DxFrame,
        hash: u32,
    ) -> Result<Option<Vec<DxFrame>>, Errno> {
        let mut path = Vec::new();
        try_push(&mut path, root)?;
        loop {
            let last = path.last_mut().ok_or(Errno::EIO)?;
            let at = search(last.count(), hash, |i| last.hash(i));
            last.at = at;
            let child = last.child(at);
            if !Self::dx_child_ok(dx, &path, child) {
                return Ok(None);
            }
            if path.len() > dx.levels {
                return Ok(Some(path));
            }
            let Some(node) = self.dx_read(ino, inode, dx.seed, child, false, dx.nblocks)? else { return Ok(None) };
            try_push(&mut path, node)?;
        }
    }

    /// The leaf `path` leads to.
    fn dx_leaf(path: &[DxFrame]) -> Result<u64, Errno> {
        let f = path.last().ok_or(Errno::EIO)?;
        Ok(f.child(f.at))
    }

    /// Moves `path` to the next leaf if it may hold more names with `hash`
    /// (a run of equal hashes continued there, as Linux's
    /// `ext4_htree_next_block`). A bad node there is an I/O error.
    fn dx_next(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        dx: &Dx,
        path: &mut Vec<DxFrame>,
        hash: u32,
    ) -> Result<bool, Errno> {
        let Some(i) = path.iter().rposition(|f| f.at + 1 < f.count()) else { return Ok(false) };
        let f = path.get_mut(i).ok_or(Errno::EIO)?;
        f.at += 1;
        if f.hash(f.at) & !1 != hash {
            return Ok(false);
        }
        path.truncate(i + 1);
        while path.len() <= dx.levels {
            let child = Self::dx_leaf(path)?;
            if !Self::dx_child_ok(dx, path, child) {
                return Err(Errno::EIO);
            }
            let node = self.dx_read(ino, inode, dx.seed, child, false, dx.nblocks)?.ok_or(Errno::EIO)?;
            try_push(path, node)?;
        }
        if !Self::dx_child_ok(dx, path, Self::dx_leaf(path)?) {
            return Err(Errno::EIO);
        }
        Ok(true)
    }

    /// Reads leaf `lblk` of a directory, verifying its checksum tail if it
    /// has one.
    fn read_leaf(&mut self, ino: u32, inode: &mut Inode, seed: u32, lblk: u64) -> Result<(u64, Vec<u8>), Errno> {
        let phys = self.bmap(ino, inode, lblk, false)?;
        if phys == 0 {
            return Err(Errno::EIO);
        }
        let data = self.read_block(phys)?;
        if self.has_dir_tail(&data) {
            let t = data.len() - DIR_TAIL_LEN;
            if get32(&data, t + 8) != crc32c(seed, sub(&data, 0..t)) {
                return Err(Errno::EIO);
            }
        }
        Ok((phys, data))
    }

    /// The offset of the live entry `name` in the leaf `data`.
    fn leaf_find(&self, data: &[u8], name: &[u8]) -> Result<Option<usize>, Errno> {
        let (mut off, space) = (0, self.dir_space(data));
        while off < space {
            let (ino, rec_len, entry) = self.record(data, off)?;
            if ino != 0 && entry == name {
                return Ok(Some(off));
            }
            off += rec_len;
        }
        Ok(None)
    }

    /// Finds the live entry `name` through the index: None if the directory
    /// has no usable index; otherwise the leaf holding it, if any.
    pub(super) fn dx_locate(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        name: &[u8],
    ) -> Result<Option<Option<Located>>, Errno> {
        let Some((dx, root)) = self.dx_root(ino, inode)? else { return Ok(None) };
        let hash = dx.hash.of(name);
        let Some(mut path) = self.dx_probe(ino, inode, &dx, root, hash)? else { return Ok(None) };
        // (Each step moves on along the index: no more steps than blocks.)
        for _ in 0..dx.nblocks {
            let lblk = Self::dx_leaf(&path)?;
            let (phys, data) = self.read_leaf(ino, inode, dx.seed, lblk)?;
            if let Some(off) = self.leaf_find(&data, name)? {
                return Ok(Some(Some((phys, data, off))));
            }
            if !self.dx_next(ino, inode, &dx, &mut path, hash)? {
                break;
            }
        }
        Ok(Some(None))
    }

    fn put_record(
        &self,
        data: &mut [u8],
        off: usize,
        ino: u32,
        rec_len: usize,
        name: &[u8],
        ftype: u8,
    ) -> Result<(), Errno> {
        put32(data, off, ino);
        put16(data, off + 4, rec_len as u16);
        if self.filetype {
            put_bytes(data, off + 6, &[name.len() as u8, ftype])?;
        } else {
            put16(data, off + 6, name.len() as u16);
        }
        put_bytes(data, off + 8, name)
    }

    /// Puts an entry into the leaf `data` if it has room.
    pub(super) fn block_insert(&self, data: &mut [u8], name: &[u8], ino: u32, ftype: u8) -> Result<bool, Errno> {
        let need = rec_len_for(name.len());
        let (mut off, space) = (0, self.dir_space(data));
        while off < space {
            let (used_ino, rec_len, used_name) = self.record(data, off)?;
            let used = if used_ino == 0 { 0 } else { rec_len_for(used_name.len()) };
            if rec_len - used >= need {
                if used_ino == 0 {
                    self.put_record(data, off, ino, rec_len, name, ftype)?;
                } else {
                    put16(data, off + 4, used as u16);
                    self.put_record(data, off + used, ino, rec_len - used, name, ftype)?;
                }
                return Ok(true);
            }
            off += rec_len;
        }
        Ok(false)
    }

    /// The live entries of a leaf block, with their hashes, in hash order.
    fn leaf_entries(&self, hash: DxHash, data: &[u8]) -> Result<Vec<(u32, Entry)>, Errno> {
        let mut map = Vec::new();
        let (mut off, space) = (0, self.dir_space(data));
        while off < space {
            let (ino, rec_len, name) = self.record(data, off)?;
            if ino != 0 && !name.is_empty() {
                let ftype = if self.filetype { byte(data, off + 7) } else { 0 };
                try_push(&mut map, (hash.of(name), Entry { name: try_to_vec(name)?, ino, ftype }))?;
            }
            off += rec_len;
        }
        map.sort_unstable_by_key(|e| e.0);
        Ok(map)
    }

    /// Packs entries into one leaf block; `EIO` if they do not fit.
    fn pack_leaf<'e>(&self, entries: impl Iterator<Item = &'e Entry>) -> Result<Vec<u8>, Errno> {
        let (mut data, space) = self.new_dir_block()?;
        let (mut off, mut last) = (0usize, None);
        for e in entries {
            let need = rec_len_for(e.name.len());
            if off.checked_add(need).is_none_or(|end| end > space) {
                return Err(Errno::EIO);
            }
            self.put_record(&mut data, off, e.ino, need, &e.name, e.ftype)?;
            last = Some(off);
            off += need;
        }
        // The last record absorbs the rest of the block.
        let last = last.ok_or(Errno::EIO)?;
        put16(&mut data, last + 4, (space - last) as u16);
        Ok(data)
    }

    /// Appends `n` (1 or 2) blocks to a directory and returns the logical
    /// number of the first and the physical numbers of both; unused ones are
    /// 0. All or nothing. The blocks are not written.
    pub(super) fn grow_dir(&mut self, dir: u32, n: u64) -> Result<(u64, [u64; 2]), Errno> {
        let mut inode = self.read_inode(dir)?;
        let bs = self.block_size as u64;
        // A size that is not a block multiple still ends in a partial block.
        let next = inode.size().div_ceil(bs);
        let mut phys = [0u64; 2];
        for (k, slot) in phys.iter_mut().enumerate().take(n as usize) {
            match self.bmap(dir, &mut inode, next + k as u64, true) {
                Ok(b) => *slot = b,
                Err(e) => {
                    // Give back what the first took.
                    if k > 0 {
                        self.truncate_blocks(dir, &mut inode, next)?;
                        self.write_inode(dir, &inode)?;
                    }
                    return Err(e);
                }
            }
        }
        inode.set_size(next.saturating_add(n).saturating_mul(bs));
        self.write_inode(dir, &inode)?;
        Ok((next, phys))
    }

    /// Appends the leaf or index block `data` to a directory; its logical
    /// number.
    fn append_dir_block(&mut self, dir: u32, data: &mut [u8]) -> Result<u64, Errno> {
        let (lblk, [phys, _]) = self.grow_dir(dir, 1)?;
        self.write_dir_block(dir, phys, data)?;
        Ok(lblk)
    }

    /// Adds an entry through the index. Ok(false): the index turned out to
    /// be unusable (what was changed before that, a split of an index node,
    /// left it consistent).
    pub(super) fn dx_add(&mut self, dir: u32, name: &[u8], target: u32, ftype: u8) -> Result<bool, Errno> {
        // Each pass adds the entry, or makes room in the index for one more
        // leaf by splitting one index block or adding a level (as Linux
        // does), and starts again: the passes are bounded by the depth.
        for _ in 0..2 * DX_MAX_LEVELS + 2 {
            let mut inode = self.read_inode(dir)?;
            let Some((dx, root)) = self.dx_root(dir, &mut inode)? else { return Ok(false) };
            let hash = dx.hash.of(name);
            let Some(mut path) = self.dx_probe(dir, &mut inode, &dx, root, hash)? else { return Ok(false) };
            let lblk = Self::dx_leaf(&path)?;
            let (phys, mut block) = self.read_leaf(dir, &mut inode, dx.seed, lblk)?;
            if self.csum == Csum::Crc32c && !self.has_dir_tail(&block) {
                // No room for a checksum: not a leaf we can keep.
                return Ok(false);
            }
            if self.block_insert(&mut block, name, target, ftype)? {
                self.write_dir_block(dir, phys, &mut block)?;
                return Ok(true);
            }
            // Free space scattered between entries: repacking the leaf may
            // make room without a split.
            let map = self.leaf_entries(dx.hash, &block)?;
            let live: usize = map.iter().map(|e| rec_len_for(e.1.name.len())).sum();
            if live + rec_len_for(name.len()) <= self.dir_space(&block) {
                let mut packed = self.pack_leaf(map.iter().map(|e| &e.1))?;
                if self.block_insert(&mut packed, name, target, ftype)? {
                    self.write_dir_block(dir, phys, &mut packed)?;
                    return Ok(true);
                }
                return Err(Errno::EIO);
            }
            let last = path.last().ok_or(Errno::EIO)?;
            if last.count() < last.limit() {
                self.dx_split_leaf(dir, dx.seed, &mut path, phys, &map, hash, (name, target, ftype))?;
                return Ok(true);
            }
            self.dx_grow_index(dir, dx.seed, &mut path)?;
        }
        Err(Errno::EIO)
    }

    /// Splits `map` (a full leaf's entries in hash order) in two leaf blocks
    /// by hash, the new entry going to the one its hash belongs to: `(lower
    /// block, upper block, the upper's index hash)`.
    fn dx_split(
        &self,
        map: &[(u32, Entry)],
        hash: u32,
        (name, target, ftype): (&[u8], u32, u8),
    ) -> Result<(Vec<u8>, Vec<u8>, u32), Errno> {
        let mut sizes = Vec::new();
        for e in map {
            try_push(&mut sizes, rec_len_for(e.1.name.len()))?;
        }
        let split = split_point(&sizes, self.block_size).ok_or(Errno::EIO)?;
        let hash2 = map.get(split).ok_or(Errno::EIO)?.0;
        // Equal hashes on both sides: the upper block continues the run.
        let before = map.get(split.checked_sub(1).ok_or(Errno::EIO)?).ok_or(Errno::EIO)?.0;
        let continued = (before == hash2) as u32;
        let (lower, upper) = map.split_at_checked(split).ok_or(Errno::EIO)?;
        let mut lo = self.pack_leaf(lower.iter().map(|e| &e.1))?;
        let mut hi = self.pack_leaf(upper.iter().map(|e| &e.1))?;
        let into = if hash >= hash2 { &mut hi } else { &mut lo };
        if !self.block_insert(into, name, target, ftype)? {
            return Err(Errno::ENOSPC);
        }
        Ok((lo, hi, hash2 | continued))
    }

    /// Splits the full leaf (at `phys`) that `path` leads to, whose entries
    /// are `map` (in hash order) and whose index node has room for one more
    /// entry, and adds the new entry: the leaf's upper half by hash moves to
    /// a new block at the end of the directory.
    #[allow(clippy::too_many_arguments)]
    fn dx_split_leaf(
        &mut self,
        dir: u32,
        seed: u32,
        path: &mut [DxFrame],
        phys: u64,
        map: &[(u32, Entry)],
        hash: u32,
        entry: (&[u8], u32, u8),
    ) -> Result<(), Errno> {
        let (mut lo, mut hi, hash2) = self.dx_split(map, hash, entry)?;
        // The new block first: until the index names it, nothing else has
        // changed, and a failure here leaves the directory as it was.
        let new = self.append_dir_block(dir, &mut hi)?;
        let f = path.last_mut().ok_or(Errno::EIO)?;
        f.insert_after(f.at, hash2, new)?;
        self.seal_dx(seed, &mut f.block, f.base);
        self.write_dir_block(dir, phys, &mut lo)?;
        self.write_block(f.phys, &f.block)
    }

    /// The index node at the end of `path` is full: makes room in it for one
    /// more entry, splitting the lowest full node whose parent has room (the
    /// parent gains an entry for the new half), or, everything full up to the
    /// root, moving the root's entries to a new node below it.
    fn dx_grow_index(&mut self, dir: u32, seed: u32, path: &mut [DxFrame]) -> Result<(), Errno> {
        let bs = self.block_size;
        let (_, node_limit) = limits(bs, self.csum == Csum::Crc32c);
        let mut k = path.len().checked_sub(1).ok_or(Errno::EIO)?;
        while k > 0 {
            let parent = path.get(k - 1).ok_or(Errno::EIO)?;
            if parent.count() < parent.limit() {
                break;
            }
            k -= 1;
        }
        let mut block = try_zeroed(bs)?;
        put16(&mut block, 4, bs as u16); // the empty record
        let mut node = DxFrame { lblk: 0, phys: 0, block, base: DX_NODE_BASE, at: 0 };
        if k == 0 {
            if path.len() >= DX_MAX_LEVELS {
                return Err(Errno::ENOSPC);
            }
            let root = path.first().ok_or(Errno::EIO)?;
            put_bytes(&mut node.block, DX_NODE_BASE, root.entries(0, root.count())?)?;
            node.set_limit(node_limit);
            self.seal_dx(seed, &mut node.block, DX_NODE_BASE);
            let new = self.append_dir_block(dir, &mut node.block)?;
            let root = path.first_mut().ok_or(Errno::EIO)?;
            root.set_count(1);
            root.set_child(0, new);
            let levels = byte(&root.block, DX_INFO + 6);
            put_bytes(&mut root.block, DX_INFO + 6, &[levels.saturating_add(1)])?;
            self.seal_dx(seed, &mut root.block, root.base);
            return self.write_block(root.phys, &root.block);
        }
        let f = path.get(k).ok_or(Errno::EIO)?;
        let n = f.count();
        let (n1, n2) = (n / 2, n - n / 2);
        let hash2 = f.hash(n1);
        // (The first entry moved gives up its hash, which its parent holds,
        // for the new node's limit and count.)
        put_bytes(&mut node.block, DX_NODE_BASE, f.entries(n1, n)?)?;
        node.set_limit(node_limit);
        node.set_count(n2);
        self.seal_dx(seed, &mut node.block, DX_NODE_BASE);
        let new = self.append_dir_block(dir, &mut node.block)?;
        let f = path.get_mut(k).ok_or(Errno::EIO)?;
        f.set_count(n1);
        self.seal_dx(seed, &mut f.block, f.base);
        self.write_block(f.phys, &f.block)?;
        let parent = path.get_mut(k - 1).ok_or(Errno::EIO)?;
        parent.insert_after(parent.at, hash2, new)?;
        self.seal_dx(seed, &mut parent.block, parent.base);
        self.write_block(parent.phys, &parent.block)
    }

    /// Gives the one-block linear directory whose full block (at `phys`) is
    /// `block` an index, as Linux's `make_indexed_dir`, adding the new
    /// entry: block 0 becomes the root and its entries are split by hash into
    /// two new leaves. Ok(false): its block is not shaped for that, and
    /// nothing changed.
    pub(super) fn dx_make_index(
        &mut self,
        dir: u32,
        phys: u64,
        block: &[u8],
        name: &[u8],
        target: u32,
        ftype: u8,
    ) -> Result<bool, Errno> {
        let bs = self.block_size;
        if !self.dx_enabled() || (self.csum == Csum::Crc32c && !self.has_dir_tail(block)) {
            return Ok(false);
        }
        let space = self.dir_space(block);
        // `.` and `..` first, where the root keeps them.
        let dotdot_len = get16(block, 16) as usize;
        let dots = get16(block, 4) == 12
            && self.name_len_at(block, 0) == 1
            && byte(block, 8) == b'.'
            && self.name_len_at(block, 12) == 2
            && sub(block, 20..22) == b".."
            && dotdot_len >= 12;
        let start = 12 + dotdot_len;
        if !dots || start >= space {
            return Ok(false);
        }
        let (_, def, _) = self.dx_params();
        let version = if def <= TEA { def } else { HALF_MD4 };
        let hash = self.dx_hash(version);
        let mut map = Vec::new();
        let mut off = start;
        while off < space {
            let (e_ino, rec_len, e_name) = self.record(block, off)?;
            if e_ino != 0 && !e_name.is_empty() {
                let e_type = if self.filetype { byte(block, off + 7) } else { 0 };
                try_push(&mut map, (hash.of(e_name), Entry { name: try_to_vec(e_name)?, ino: e_ino, ftype: e_type }))?;
            }
            off += rec_len;
        }
        if map.len() < 2 {
            return Ok(false);
        }
        map.sort_unstable_by_key(|e| e.0);
        let (mut lo, mut hi, hash2) = self.dx_split(&map, hash.of(name), (name, target, ftype))?;
        let (first, [lo_phys, hi_phys]) = self.grow_dir(dir, 2)?;
        self.write_dir_block(dir, lo_phys, &mut lo)?;
        self.write_dir_block(dir, hi_phys, &mut hi)?;
        let mut root = try_zeroed(bs)?;
        put_bytes(&mut root, 0, sub(block, 0..24))?;
        put16(&mut root, 16, (bs - 12) as u16);
        put_bytes(&mut root, DX_INFO + 4, &[version, 8])?; // hash_version, info_length
        let mut f = DxFrame { lblk: 0, phys, block: root, base: DX_ROOT_BASE, at: 0 };
        f.set_limit(limits(bs, self.csum == Csum::Crc32c).0);
        f.set_count(1);
        f.set_child(0, first);
        f.insert_after(0, hash2, first + 1)?;
        let mut inode = self.read_inode(dir)?;
        let seed = self.inode_seed(dir, &inode);
        self.seal_dx(seed, &mut f.block, f.base);
        self.write_block(phys, &f.block)?;
        inode.set_flags(inode.flags() | INDEX_FL);
        self.write_inode(dir, &inode)?;
        Ok(true)
    }

    /// Points the `..` of the indexed directory `ino` at `parent`, if its
    /// first block is an index root, whose checksum is not that of a plain
    /// entry block. Ok(false): it is not one.
    pub(super) fn dx_set_dotdot(&mut self, ino: u32, inode: &mut Inode, parent: u32) -> Result<bool, Errno> {
        if inode.flags() & INDEX_FL == 0 {
            return Ok(false);
        }
        let phys = self.bmap(ino, inode, 0, false)?;
        if phys == 0 {
            return Ok(false);
        }
        let mut block = self.read_block(phys)?;
        if !self.dx_root_shaped(&block) {
            return Ok(false);
        }
        put32(&mut block, 12, parent);
        let seed = self.inode_seed(ino, inode);
        self.seal_dx(seed, &mut block, DX_ROOT_BASE);
        self.write_block(phys, &block)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `0123abcd-5566-7788-99aa-bbccddeeff00` as debugfs reads a seed.
    const SEED: [u32; 4] = [0xcdab_2301, 0x8877_6655, 0xccbb_aa99, 0x00ff_eedd];
    const LONG: &[u8] = &[b'x'; 100];
    const HIGH: &[u8] = "héllo-wörld-ÿ".as_bytes();

    /// Vectors from e2fsprogs 1.47: `debugfs -R "dx_hash -h ALG -s SEED NAME"`.
    #[test]
    fn matches_e2fsprogs() {
        let zero = [0; 4];
        type Case = (u8, [u32; 4], &'static [u8], u32, u32);
        let cases: &[Case] = &[
            (LEGACY, zero, b"a", 0xe74b53e2, 0),
            (LEGACY, zero, b"hello", 0x32252546, 0),
            (LEGACY, zero, b"entry-001-with-a-reasonably-long-name", 0xa8f4fbe4, 0),
            (LEGACY, SEED, LONG, 0xf985a9f6, 0),
            (LEGACY, zero, HIGH, 0x8fa0e526, 0),
            (LEGACY_UNSIGNED, zero, HIGH, 0xd0e15474, 0),
            (HALF_MD4, zero, b"a", 0xd5fa7d7a, 0xacb48187),
            (HALF_MD4, zero, b"hello", 0x1746da32, 0x420013b5),
            (HALF_MD4, zero, b"entry-001-with-a-reasonably-long-name", 0x4f27574a, 0x2487ba1d),
            (HALF_MD4, zero, LONG, 0x23aa98ac, 0x9a974df1),
            (HALF_MD4, zero, HIGH, 0xb6065696, 0x63bf65a4),
            (HALF_MD4, SEED, b"a", 0xc9db3bfa, 0x1bb2259f),
            (HALF_MD4, SEED, b"hello", 0xbf66c29e, 0x823ac580),
            (HALF_MD4, SEED, LONG, 0xa5921e08, 0x6a6b83f8),
            (HALF_MD4, SEED, HIGH, 0xb5107812, 0xf9d2b328),
            (HALF_MD4_UNSIGNED, zero, HIGH, 0x5147f5e6, 0x0baa66b1),
            (HALF_MD4_UNSIGNED, SEED, HIGH, 0x8c5669f6, 0xab7bb9be),
            (HALF_MD4_UNSIGNED, SEED, b"hello", 0xbf66c29e, 0x823ac580),
            (TEA, zero, b"a", 0x6d0ea4c0, 0xc18922df),
            (TEA, zero, b"hello", 0x6f5bb1a8, 0x231917c2),
            (TEA, zero, b"entry-001-with-a-reasonably-long-name", 0xf37f62c2, 0xd83fde25),
            (TEA, zero, LONG, 0x7353ab0e, 0xcecc2718),
            (TEA, zero, HIGH, 0x3d0ddd44, 0x52697751),
            (TEA, SEED, b"hello", 0x5e65acda, 0x17012b55),
            (TEA, SEED, LONG, 0x11295dd8, 0xcb867b3c),
            (TEA, SEED, HIGH, 0xafe7eab0, 0xd01f2d18),
            (TEA_UNSIGNED, zero, HIGH, 0x9012cd46, 0x1b2fd6cf),
            (TEA_UNSIGNED, SEED, HIGH, 0x30742f54, 0x3d3d4cc9),
        ];
        for &(v, seed, name, hash, minor) in cases {
            assert_eq!(dirhash(v, seed, name), Some((hash, minor)), "version {v} name {name:?}");
        }
        assert_eq!(dirhash(6, [0; 4], b"x"), None);
        assert_eq!(dirhash(200, [0; 4], b"x"), None);
    }

    #[test]
    fn low_bit_clear() {
        for i in 0..2000u32 {
            let name = i.to_le_bytes();
            for v in 0..6 {
                let (h, _) = dirhash(v, SEED, &name).unwrap();
                assert_eq!(h & 1, 0);
                assert_ne!(h, 0xffff_fffe);
            }
        }
    }

    #[test]
    fn split() {
        assert_eq!(split_point(&[], 4096), None);
        assert_eq!(split_point(&[4096], 4096), None);
        // Equal entries: half move.
        assert_eq!(split_point(&[16; 256], 4096), Some(128));
        assert_eq!(split_point(&[16; 255], 4096), Some(127));
        // A few big entries at the top take half the block on their own.
        let mut sizes = [12usize; 100].to_vec();
        sizes.extend([264; 8]);
        let at = split_point(&sizes, 4096).unwrap();
        let moved: usize = sizes[at..].iter().sum();
        assert!(moved <= 2048 + 132 && at > 0 && at < sizes.len());
        // Two huge entries: by count.
        assert_eq!(split_point(&[2000, 2000], 4096), Some(1));
    }

    #[test]
    fn index_search() {
        let hashes = [0u32, 10, 20, 21, 40];
        let at = |h| search(hashes.len(), h, |i| hashes[i]);
        assert_eq!(at(0), 0);
        assert_eq!(at(9), 0);
        assert_eq!(at(10), 1);
        assert_eq!(at(19), 1);
        // 20 continued into the next block (21): the run starts at 20's.
        assert_eq!(at(20), 2);
        assert_eq!(at(39), 3);
        assert_eq!(at(u32::MAX), 4);
        assert_eq!(search(1, 5, |_| panic!("no entry to compare")), 0);
    }

    #[test]
    fn limit_values() {
        assert_eq!(limits(4096, true), (507, 510));
        assert_eq!(limits(4096, false), (508, 511));
        assert_eq!(limits(1024, false), (124, 127));
    }
}
