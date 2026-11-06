// SPDX-License-Identifier: GPL-2.0-only
//! Tree blocks as a transaction edits them: decoded into items or pointers,
//! and encoded back with a fresh checksum when the transaction commits.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_sync::fallible::{try_push, try_to_vec, try_zeroed};

use crate::csum;
use crate::disk::{CSUM_SPACE, Key, header, le32, le64};

/// Bytes of a leaf's item header: key, data offset, data size.
pub const ITEM: usize = Key::SIZE + 8;
/// Bytes of a node's pointer: key, child address, generation.
pub const PTR: usize = Key::SIZE + 16;

/// `BTRFS_HEADER_FLAG_WRITTEN` and the mixed back reference revision.
const FLAGS: u64 = 1 | 1 << 56;
/// Where a block's header keeps its flags.
const FLAGS_AT: usize = 56;
/// `BTRFS_HEADER_FLAG_RELOC`: a relocation (Linux's balance) wrote the block,
/// and it may be shared whatever its generation.
pub const FLAG_RELOC: u64 = 1 << 1;

/// One item of a leaf.
pub struct Item {
    /// Its key.
    pub key: Key,
    /// Its data.
    pub data: Vec<u8>,
}

/// One pointer of a node.
#[derive(Clone, Copy)]
pub struct Ptr {
    /// The first key of the child.
    pub key: Key,
    /// The child's address.
    pub addr: u64,
    /// The generation the child was written in.
    pub generation: u64,
}

/// What a block holds.
pub enum Body {
    /// Items (level 0).
    Leaf(Vec<Item>),
    /// Pointers to children.
    Node(Vec<Ptr>),
}

/// A tree block being edited.
pub struct TNode {
    /// Its address.
    pub addr: u64,
    /// The tree it belongs to.
    pub owner: u64,
    /// Its level.
    pub level: u8,
    /// The generation it was last written in.
    pub generation: u64,
    /// Whether its header has [`FLAG_RELOC`]. It is never written: a copy
    /// does not have it.
    pub reloc: bool,
    /// Its items or pointers.
    pub body: Body,
}

impl TNode {
    /// Decodes block `b`, which `Shared::block` has checked.
    pub fn decode(b: &[u8]) -> Result<Self, Errno> {
        let n = le32(b, header::NRITEMS)? as usize;
        let level = crate::disk::byte(b, header::LEVEL)?;
        let body = if level == 0 {
            let mut items = Vec::new();
            items.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
            for i in 0..n {
                let at = header::SIZE + i * ITEM;
                let off = le32(b, at + Key::SIZE)? as usize;
                let size = le32(b, at + Key::SIZE + 4)? as usize;
                let data = crate::disk::bytes(b, header::SIZE + off, size)?;
                try_push(&mut items, Item { key: Key::parse(b, at)?, data: try_to_vec(data)? })?;
            }
            Body::Leaf(items)
        } else {
            let mut ptrs = Vec::new();
            ptrs.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
            for i in 0..n {
                let at = header::SIZE + i * PTR;
                let p = Ptr {
                    key: Key::parse(b, at)?,
                    addr: le64(b, at + Key::SIZE)?,
                    generation: le64(b, at + Key::SIZE + 8)?,
                };
                try_push(&mut ptrs, p)?;
            }
            Body::Node(ptrs)
        };
        let reloc = le64(b, FLAGS_AT)? & FLAG_RELOC != 0;
        Ok(TNode { addr: le64(b, header::BYTENR)?, owner: le64(b, 88)?, level, generation: le64(b, 80)?, reloc, body })
    }

    /// Encodes the block for writing: header, items or pointers, checksum.
    pub fn encode(
        &self,
        nodesize: usize,
        fsid: &[u8; 16],
        chunk_uuid: &[u8; 16],
        csum_type: u16,
    ) -> Result<Vec<u8>, Errno> {
        let mut b = try_zeroed(nodesize)?;
        let put = |b: &mut [u8], at: usize, v: &[u8]| -> Result<(), Errno> {
            b.get_mut(at..at + v.len()).ok_or(Errno::EIO)?.copy_from_slice(v);
            Ok(())
        };
        put(&mut b, header::FSID, fsid)?;
        put(&mut b, header::BYTENR, &self.addr.to_le_bytes())?;
        put(&mut b, FLAGS_AT, &FLAGS.to_le_bytes())?;
        put(&mut b, 64, chunk_uuid)?;
        put(&mut b, 80, &self.generation.to_le_bytes())?;
        put(&mut b, 88, &self.owner.to_le_bytes())?;
        put(&mut b, header::LEVEL, &[self.level])?;
        let n = match &self.body {
            Body::Leaf(items) => {
                let mut end = nodesize - header::SIZE;
                for (i, it) in items.iter().enumerate() {
                    end = end.checked_sub(it.data.len()).ok_or(Errno::EIO)?;
                    let at = header::SIZE + i * ITEM;
                    if at + ITEM > header::SIZE + end {
                        return Err(Errno::EIO);
                    }
                    put(&mut b, at, &key_bytes(&it.key))?;
                    put(&mut b, at + Key::SIZE, &(end as u32).to_le_bytes())?;
                    put(&mut b, at + Key::SIZE + 4, &(it.data.len() as u32).to_le_bytes())?;
                    put(&mut b, header::SIZE + end, &it.data)?;
                }
                items.len()
            }
            Body::Node(ptrs) => {
                for (i, p) in ptrs.iter().enumerate() {
                    let at = header::SIZE + i * PTR;
                    put(&mut b, at, &key_bytes(&p.key))?;
                    put(&mut b, at + Key::SIZE, &p.addr.to_le_bytes())?;
                    put(&mut b, at + Key::SIZE + 8, &p.generation.to_le_bytes())?;
                }
                ptrs.len()
            }
        };
        put(&mut b, header::NRITEMS, &(n as u32).to_le_bytes())?;
        let sum = csum::compute(csum_type, b.get(CSUM_SPACE..).ok_or(Errno::EIO)?);
        put(&mut b, 0, &sum)?;
        Ok(b)
    }

    /// The items, if a leaf.
    pub fn items(&self) -> Result<&Vec<Item>, Errno> {
        match &self.body {
            Body::Leaf(v) => Ok(v),
            Body::Node(_) => Err(Errno::EIO),
        }
    }

    /// The items, if a leaf.
    pub fn items_mut(&mut self) -> Result<&mut Vec<Item>, Errno> {
        match &mut self.body {
            Body::Leaf(v) => Ok(v),
            Body::Node(_) => Err(Errno::EIO),
        }
    }

    /// The pointers, if a node.
    pub fn ptrs_mut(&mut self) -> Result<&mut Vec<Ptr>, Errno> {
        match &mut self.body {
            Body::Node(v) => Ok(v),
            Body::Leaf(_) => Err(Errno::EIO),
        }
    }

    /// Items or pointers.
    pub fn len(&self) -> usize {
        match &self.body {
            Body::Leaf(v) => v.len(),
            Body::Node(v) => v.len(),
        }
    }

    /// The first key, if any.
    pub fn first_key(&self) -> Option<Key> {
        match &self.body {
            Body::Leaf(v) => v.first().map(|i| i.key),
            Body::Node(v) => v.first().map(|p| p.key),
        }
    }
}

/// A key as it is stored.
pub fn key_bytes(k: &Key) -> [u8; Key::SIZE] {
    let mut b = [0u8; Key::SIZE];
    let (o, rest) = b.split_at_mut(8);
    o.copy_from_slice(&k.objectid.to_le_bytes());
    let (t, off) = rest.split_at_mut(1);
    t.copy_from_slice(&[k.ty]);
    off.copy_from_slice(&k.offset.to_le_bytes());
    b
}
