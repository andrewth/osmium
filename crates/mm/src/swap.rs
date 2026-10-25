//! Swap: pages written out to a backing store so that their frames can be
//! used for something else, and read back when touched.
//!
//! This is the storage half. A [`SwapSpace`] holds [`SwapArea`]s, each a
//! run of page-sized slots on a [`SwapBacking`] (a block device, a file, a
//! compressed RAM pool, whatever the caller adapts to the trait). It hands
//! out slots, counts the users of each (a page that several address spaces
//! have swapped out, as after a fork, is stored once and freed with its last
//! user) and moves one page of data to or from a slot. It knows nothing of
//! page tables, address spaces or which pages to evict; recording where a
//! page went, choosing victims and reading pages back at fault time belong
//! to the memory manager that owns those.
//!
//! An area's layout is `mkswap`'s: a header page ([`SwapHeader`]) and then
//! one slot per page. The header is read when an area is added, and
//! [`SwapHeader::write`] makes one, so areas can be created and used
//! without any other tool.
//!
//! Removing an area is a protocol, because the pages in it must come back
//! first: [`SwapSpace::begin_removal`] stops new pages going to it, the
//! caller reads back and [`put`](SwapSpace::put)s each page it had there,
//! and [`SwapSpace::finish_removal`] drops the area once it is empty (or
//! [`SwapSpace::cancel_removal`] re-enables it if the pages did not fit).
//!
//! # Locking
//!
//! Slot bookkeeping is under one spin lock per area and the list of areas
//! under another; neither is held across backing I/O.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use osmium_sync::SpinLock;
use osmium_sync::fallible::try_arc;

use crate::addr::PAGE_SIZE;

/// The magic string that ends the header page.
const MAGIC: &[u8; 10] = b"SWAPSPACE2";
/// The only header version.
const VERSION: u32 = 1;
/// Offsets within the header page.
const OFF_VERSION: usize = 1024;
const OFF_LAST_PAGE: usize = 1028;
const OFF_NR_BAD: usize = 1032;
const OFF_UUID: usize = 1036;
const OFF_LABEL: usize = 1052;
const OFF_BAD_PAGES: usize = 1536;
/// The most bad pages a header may list.
pub const MAX_BAD_PAGES: usize = 512;
/// The most users one stored page may have.
pub const MAX_USERS: u16 = 0x7fff;
/// A slot that must not be used: the header, or a bad page.
const BAD: u16 = 0xffff;

/// One page of data, as stored in a slot.
pub type Page = [u8; PAGE_SIZE];

/// Why a swap operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapError {
    /// The backing store reported an error.
    Io,
    /// The area's header is not usable.
    Header(HeaderError),
    /// No area has that id, or the slot is not in use.
    NoSuchArea,
    /// Memory for bookkeeping ran out.
    OutOfMemory,
    /// The area still holds pages.
    InUse,
}

impl From<osmium_sync::fallible::OutOfMemory> for SwapError {
    fn from(_: osmium_sync::fallible::OutOfMemory) -> Self {
        SwapError::OutOfMemory
    }
}

/// Why a swap header was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// Smaller than a header page.
    TooShort,
    /// No `SWAPSPACE2` signature.
    BadMagic,
    /// A version other than 1.
    BadVersion,
    /// No slots after the header.
    Empty,
    /// More bad pages than the format has room for, or a bad page that
    /// is the header or beyond the end.
    BadPages,
}

/// A byte store that swap slots live on. Offsets are bytes from the start
/// of the area (the header page is at 0). Implementations do their own
/// locking; calls may come from several CPUs at once.
pub trait SwapBacking: Send + Sync {
    /// Size in bytes.
    fn size(&self) -> u64;
    /// Reads `buf.len()` bytes at `offset`.
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), SwapError>;
    /// Writes `buf` at `offset`.
    fn write(&self, offset: u64, buf: &[u8]) -> Result<(), SwapError>;
}

fn get32(page: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(page.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn put32(page: &mut [u8], at: usize, value: u32) {
    if let Some(dst) = page.get_mut(at..at + 4) {
        dst.copy_from_slice(&value.to_le_bytes());
    }
}

/// The header page of a swap area, as `mkswap` writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapHeader {
    /// Index of the last slot, so the area has `last_page + 1` pages with
    /// the header.
    pub last_page: u32,
    /// Pages that must not be used.
    pub bad_pages: Vec<u32>,
    /// The area's UUID (all zeros if none).
    pub uuid: [u8; 16],
    /// The area's label, NUL padded.
    pub label: [u8; 16],
}

impl SwapHeader {
    /// A header for an area of `pages` pages in all (header included) with
    /// no bad pages and no UUID or label.
    pub fn new(pages: u32) -> Self {
        SwapHeader { last_page: pages.saturating_sub(1), bad_pages: Vec::new(), uuid: [0; 16], label: [0; 16] }
    }

    /// Reads a header from the first page of an area.
    pub fn parse(page: &[u8]) -> Result<Self, HeaderError> {
        let end = PAGE_SIZE;
        if page.len() < end {
            return Err(HeaderError::TooShort);
        }
        if page.get(end - MAGIC.len()..end) != Some(MAGIC.as_slice()) {
            return Err(HeaderError::BadMagic);
        }
        let word = |at| get32(page, at).ok_or(HeaderError::TooShort);
        if word(OFF_VERSION)? != VERSION {
            return Err(HeaderError::BadVersion);
        }
        let last_page = word(OFF_LAST_PAGE)?;
        if last_page == 0 {
            return Err(HeaderError::Empty);
        }
        let nbad = word(OFF_NR_BAD)? as usize;
        if nbad > MAX_BAD_PAGES {
            return Err(HeaderError::BadPages);
        }
        let mut bad_pages = Vec::new();
        bad_pages.try_reserve_exact(nbad).map_err(|_| HeaderError::BadPages)?;
        for k in 0..nbad {
            bad_pages.push(word(OFF_BAD_PAGES + 4 * k)?);
        }
        let mut uuid = [0; 16];
        let mut label = [0; 16];
        uuid.copy_from_slice(page.get(OFF_UUID..OFF_UUID + 16).ok_or(HeaderError::TooShort)?);
        label.copy_from_slice(page.get(OFF_LABEL..OFF_LABEL + 16).ok_or(HeaderError::TooShort)?);
        Ok(SwapHeader { last_page, bad_pages, uuid, label })
    }

    /// Writes the header into `page`, clearing the rest of it. Fails if
    /// there are too many bad pages.
    pub fn write(&self, page: &mut Page) -> Result<(), HeaderError> {
        if self.bad_pages.len() > MAX_BAD_PAGES {
            return Err(HeaderError::BadPages);
        }
        page.fill(0);
        put32(page, OFF_VERSION, VERSION);
        put32(page, OFF_LAST_PAGE, self.last_page);
        put32(page, OFF_NR_BAD, self.bad_pages.len() as u32);
        if let Some(dst) = page.get_mut(OFF_UUID..OFF_UUID + 16) {
            dst.copy_from_slice(&self.uuid);
        }
        if let Some(dst) = page.get_mut(OFF_LABEL..OFF_LABEL + 16) {
            dst.copy_from_slice(&self.label);
        }
        for (k, &bad) in self.bad_pages.iter().enumerate() {
            put32(page, OFF_BAD_PAGES + 4 * k, bad);
        }
        if let Some(dst) = page.get_mut(PAGE_SIZE - MAGIC.len()..) {
            dst.copy_from_slice(MAGIC);
        }
        Ok(())
    }
}

/// A page of swap: which area and which slot in it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Slot {
    area: u32,
    index: u32,
}

impl Slot {
    /// The id of the area the page is in (what removal brings back pages
    /// of).
    pub fn area_id(self) -> u32 {
        self.area
    }

    /// The slot's index in its area (slot 0 is the first after the header).
    pub fn index(self) -> u32 {
        self.index.saturating_sub(1)
    }

    /// A packed form for storing in a page table entry or a map.
    pub fn to_raw(self) -> u64 {
        (self.area as u64) << 32 | self.index as u64
    }

    /// The inverse of [`to_raw`](Self::to_raw).
    pub fn from_raw(raw: u64) -> Self {
        Slot { area: (raw >> 32) as u32, index: raw as u32 }
    }
}

struct State {
    /// Per page of the area (the header is entry 0): users of the page
    /// stored there, 0 if free, `BAD` if unusable.
    map: Vec<u16>,
    used: u32,
    /// Where the search for a free slot starts.
    hint: u32,
    /// Slots that can ever hold a page.
    usable: u32,
    /// False once removal has begun: no new pages.
    enabled: bool,
}

/// One swap area.
pub struct SwapArea {
    id: u32,
    prio: i32,
    backing: Box<dyn SwapBacking>,
    state: SpinLock<State>,
}

/// What a listing says about an area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AreaInfo {
    /// The area's id.
    pub id: u32,
    /// Its priority: areas with higher ones are used first.
    pub priority: i32,
    /// Slots that can ever hold a page.
    pub slots: u32,
    /// Slots in use.
    pub used: u32,
    /// Whether it takes new pages.
    pub enabled: bool,
}

impl SwapArea {
    /// Opens the area on `backing`: reads and checks its header. A backing
    /// larger than the header says is used only as far as the header goes;
    /// one smaller loses the pages past its end.
    fn open(id: u32, prio: i32, backing: Box<dyn SwapBacking>) -> Result<Self, SwapError> {
        let size = backing.size();
        if size < PAGE_SIZE as u64 {
            return Err(SwapError::Header(HeaderError::TooShort));
        }
        let mut head: Page = [0; PAGE_SIZE];
        backing.read(0, &mut head)?;
        let header = SwapHeader::parse(&head).map_err(SwapError::Header)?;
        let pages = (header.last_page as u64 + 1).min(size / PAGE_SIZE as u64);
        if pages < 2 || pages > u32::MAX as u64 / 2 {
            return Err(SwapError::Header(HeaderError::Empty));
        }
        let mut map: Vec<u16> = Vec::new();
        map.try_reserve_exact(pages as usize).map_err(|_| SwapError::OutOfMemory)?;
        map.resize(pages as usize, 0);
        let mut usable = pages as u32 - 1;
        if let Some(first) = map.first_mut() {
            *first = BAD;
        }
        for &bad in &header.bad_pages {
            match map.get_mut(bad as usize) {
                Some(slot) if bad != 0 => {
                    if *slot != BAD {
                        *slot = BAD;
                        usable -= 1;
                    }
                }
                _ => return Err(SwapError::Header(HeaderError::BadPages)),
            }
        }
        if usable == 0 {
            return Err(SwapError::Header(HeaderError::Empty));
        }
        Ok(SwapArea { id, prio, backing, state: SpinLock::new(State { map, used: 0, hint: 1, usable, enabled: true }) })
    }

    fn info(&self) -> AreaInfo {
        let s = self.state.lock();
        AreaInfo { id: self.id, priority: self.prio, slots: s.usable, used: s.used, enabled: s.enabled }
    }

    /// Takes a free slot, with one user.
    fn alloc(&self) -> Option<u32> {
        let mut s = self.state.lock();
        if !s.enabled || s.used >= s.usable {
            return None;
        }
        // Entries 1..n are slots; the search wraps around from the hint.
        let slots = (s.map.len() as u32).saturating_sub(1).max(1);
        for k in 0..slots {
            let i = 1 + (s.hint.saturating_sub(1) + k) % slots;
            let free = s.map.get(i as usize) == Some(&0);
            if free {
                if let Some(count) = s.map.get_mut(i as usize) {
                    *count = 1;
                }
                s.used += 1;
                s.hint = i % slots + 1;
                return Some(i);
            }
        }
        None
    }

    fn offset(index: u32) -> u64 {
        index as u64 * PAGE_SIZE as u64
    }
}

struct Areas {
    /// Sorted by priority, highest first; equal priorities in the order added.
    list: Vec<Arc<SwapArea>>,
    next_id: u32,
    /// The priority the next [`Priority::Auto`] area gets.
    next_prio: i32,
}

/// How an area ranks when added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    /// Below every area added so far with this setting (each automatic area
    /// gets the next lower negative number, so earlier ones fill first).
    Auto,
    /// This priority; higher is used first.
    Fixed(i32),
}

/// A set of swap areas, used in priority order.
pub struct SwapSpace {
    areas: SpinLock<Areas>,
    /// Whether some area takes pages (a cheap check for fault paths).
    active: AtomicBool,
}

impl Default for SwapSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl SwapSpace {
    /// An empty set.
    pub const fn new() -> Self {
        SwapSpace {
            areas: SpinLock::new(Areas { list: Vec::new(), next_id: 1, next_prio: -1 }),
            active: AtomicBool::new(false),
        }
    }

    /// Whether some area takes new pages.
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    fn refresh_active(&self, list: &[Arc<SwapArea>]) {
        self.active.store(list.iter().any(|a| a.state.lock().enabled), Ordering::Relaxed);
    }

    fn area(&self, id: u32) -> Option<Arc<SwapArea>> {
        self.areas.lock().list.iter().find(|a| a.id == id).cloned()
    }

    /// Adds the area on `backing` and returns its id. Which area a backing
    /// is must be tracked by the caller if it wants to refuse adding one
    /// twice.
    pub fn add(&self, backing: Box<dyn SwapBacking>, priority: Priority) -> Result<u32, SwapError> {
        // Open (which does I/O) outside the lock, under an id taken first.
        // (An id is lost if the open fails; ids only need to be unique.)
        let id = {
            let mut a = self.areas.lock();
            let id = a.next_id;
            a.next_id = id.wrapping_add(1).max(1);
            id
        };
        let mut area = SwapArea::open(id, 0, backing)?;
        let mut a = self.areas.lock();
        area.prio = match priority {
            Priority::Fixed(p) => p,
            Priority::Auto => a.next_prio,
        };
        let area = try_arc(area)?;
        a.list.try_reserve(1).map_err(|_| SwapError::OutOfMemory)?;
        if priority == Priority::Auto {
            a.next_prio = a.next_prio.saturating_sub(1);
        }
        let prio = area.prio;
        let at = a.list.iter().position(|x| x.prio < prio).unwrap_or(a.list.len());
        a.list.insert(at, area);
        self.refresh_active(&a.list);
        Ok(id)
    }

    /// A free slot, from the highest-priority area that has one. It has one
    /// user.
    pub fn alloc_slot(&self) -> Option<Slot> {
        if !self.active() {
            return None;
        }
        // (Cloned out so that the list's lock is not held while searching.)
        let list = self.areas.lock().list.clone();
        list.iter().find_map(|a| a.alloc().map(|index| Slot { area: a.id, index }))
    }

    /// Another user of the page in `slot` (a fork copying a swapped-out
    /// page). False if the slot is not in use or has too many users.
    pub fn dup(&self, slot: Slot) -> bool {
        let Some(a) = self.area(slot.area) else { return false };
        let mut s = a.state.lock();
        match s.map.get_mut(slot.index as usize) {
            Some(c) if *c != 0 && *c < MAX_USERS => {
                *c += 1;
                true
            }
            _ => false,
        }
    }

    /// One user less of the page in `slot`; the slot is free with the last.
    /// False if the slot was not in use (nothing changes).
    pub fn put(&self, slot: Slot) -> bool {
        let Some(a) = self.area(slot.area) else { return false };
        let mut s = a.state.lock();
        let Some(c) = s.map.get_mut(slot.index as usize) else { return false };
        if *c == 0 || *c == BAD {
            return false;
        }
        *c -= 1;
        if *c == 0 {
            s.used -= 1;
        }
        true
    }

    /// How many users the page in `slot` has (0 if none, or no such slot).
    pub fn users(&self, slot: Slot) -> u16 {
        let Some(a) = self.area(slot.area) else { return 0 };
        match a.state.lock().map.get(slot.index as usize) {
            Some(&BAD) | None => 0,
            Some(&c) => c,
        }
    }

    fn checked(&self, slot: Slot) -> Result<Arc<SwapArea>, SwapError> {
        let a = self.area(slot.area).ok_or(SwapError::NoSuchArea)?;
        if a.state.lock().map.get(slot.index as usize).is_none_or(|&c| c == 0 || c == BAD) {
            return Err(SwapError::NoSuchArea);
        }
        Ok(a)
    }

    /// Stores `page` in `slot`, which must be in use.
    pub fn write(&self, slot: Slot, page: &Page) -> Result<(), SwapError> {
        self.checked(slot)?.backing.write(SwapArea::offset(slot.index), page)
    }

    /// Reads the page stored in `slot`, which must be in use.
    pub fn read(&self, slot: Slot, page: &mut Page) -> Result<(), SwapError> {
        self.checked(slot)?.backing.read(SwapArea::offset(slot.index), page)
    }

    /// (slots, slots in use) over all areas.
    pub fn stats(&self) -> (u64, u64) {
        self.areas.lock().list.iter().fold((0, 0), |(t, u), a| {
            let s = a.state.lock();
            (t + s.usable as u64, u + s.used as u64)
        })
    }

    /// A snapshot of the areas, highest priority first.
    pub fn infos(&self) -> Result<Vec<AreaInfo>, SwapError> {
        let list = self.areas.lock().list.clone();
        let mut out = Vec::new();
        out.try_reserve_exact(list.len()).map_err(|_| SwapError::OutOfMemory)?;
        out.extend(list.iter().map(|a| a.info()));
        Ok(out)
    }

    /// Starts removing area `id`: it takes no more pages. The caller then
    /// reads back and [`put`](Self::put)s the pages it has in the area and
    /// calls [`finish_removal`](Self::finish_removal).
    pub fn begin_removal(&self, id: u32) -> Result<(), SwapError> {
        let a = self.area(id).ok_or(SwapError::NoSuchArea)?;
        a.state.lock().enabled = false;
        self.refresh_active(&self.areas.lock().list);
        Ok(())
    }

    /// Takes the area back into use after a [`begin_removal`](Self::begin_removal)
    /// that could not be completed.
    pub fn cancel_removal(&self, id: u32) -> Result<(), SwapError> {
        let a = self.area(id).ok_or(SwapError::NoSuchArea)?;
        a.state.lock().enabled = true;
        self.refresh_active(&self.areas.lock().list);
        Ok(())
    }

    /// Drops area `id` if it holds no pages ([`SwapError::InUse`] if it does,
    /// and it stays).
    pub fn finish_removal(&self, id: u32) -> Result<(), SwapError> {
        let mut areas = self.areas.lock();
        let at = areas.list.iter().position(|a| a.id == id).ok_or(SwapError::NoSuchArea)?;
        if areas.list.get(at).is_some_and(|a| a.state.lock().used != 0) {
            return Err(SwapError::InUse);
        }
        areas.list.remove(at);
        self.refresh_active(&areas.list);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::vec;

    /// A swap area in memory.
    struct Ram(Mutex<std::vec::Vec<u8>>);

    impl Ram {
        fn with_header(header: &SwapHeader, pages: usize) -> Box<Self> {
            let mut bytes = vec![0u8; pages * PAGE_SIZE];
            let mut head = [0u8; PAGE_SIZE];
            header.write(&mut head).unwrap();
            bytes[..PAGE_SIZE].copy_from_slice(&head);
            Box::new(Ram(Mutex::new(bytes)))
        }

        fn made(pages: u32) -> Box<Self> {
            Self::with_header(&SwapHeader::new(pages), pages as usize)
        }
    }

    impl SwapBacking for Ram {
        fn size(&self) -> u64 {
            self.0.lock().unwrap().len() as u64
        }
        fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), SwapError> {
            let d = self.0.lock().unwrap();
            let src = d.get(offset as usize..offset as usize + buf.len()).ok_or(SwapError::Io)?;
            buf.copy_from_slice(src);
            Ok(())
        }
        fn write(&self, offset: u64, buf: &[u8]) -> Result<(), SwapError> {
            let mut d = self.0.lock().unwrap();
            d.get_mut(offset as usize..offset as usize + buf.len()).ok_or(SwapError::Io)?.copy_from_slice(buf);
            Ok(())
        }
    }

    #[test]
    fn header_round_trip() {
        let h = SwapHeader {
            last_page: 99,
            bad_pages: vec![3, 7],
            uuid: *b"0123456789abcdef",
            label: *b"swap\0\0\0\0\0\0\0\0\0\0\0\0",
        };
        let mut page = [0xaa; PAGE_SIZE];
        h.write(&mut page).unwrap();
        assert_eq!(&page[PAGE_SIZE - 10..], b"SWAPSPACE2");
        assert_eq!(SwapHeader::parse(&page), Ok(h));
    }

    #[test]
    fn header_matches_mkswap_layout() {
        // From `mkswap -U 01234567-... ` on a 100-page file: version, last
        // page and bad page count at their fixed offsets.
        let mut page = [0u8; PAGE_SIZE];
        SwapHeader::new(100).write(&mut page).unwrap();
        assert_eq!(&page[1024..1036], &[1, 0, 0, 0, 99, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn header_refusals() {
        let mut page = [0u8; PAGE_SIZE];
        SwapHeader::new(10).write(&mut page).unwrap();
        assert_eq!(SwapHeader::parse(&page[..100]), Err(HeaderError::TooShort));
        let mut bad = page;
        bad[PAGE_SIZE - 1] = b'3';
        assert_eq!(SwapHeader::parse(&bad), Err(HeaderError::BadMagic));
        let mut bad = page;
        bad[1024] = 2;
        assert_eq!(SwapHeader::parse(&bad), Err(HeaderError::BadVersion));
        let mut bad = [0u8; PAGE_SIZE];
        SwapHeader::new(1).write(&mut bad).unwrap();
        assert_eq!(SwapHeader::parse(&bad), Err(HeaderError::Empty));
        let mut bad = page;
        bad[1032] = 0xff;
        bad[1033] = 0xff;
        assert_eq!(SwapHeader::parse(&bad), Err(HeaderError::BadPages));
        let many = SwapHeader { bad_pages: vec![1; MAX_BAD_PAGES + 1], ..SwapHeader::new(10) };
        assert_eq!(many.write(&mut [0; PAGE_SIZE]), Err(HeaderError::BadPages));
    }

    #[test]
    fn add_rejects_bad_areas() {
        let s = SwapSpace::new();
        assert_eq!(
            s.add(Box::new(Ram(Mutex::new(vec![0; 100]))), Priority::Auto).err(),
            Some(SwapError::Header(HeaderError::TooShort))
        );
        assert_eq!(
            s.add(Box::new(Ram(Mutex::new(vec![0; 4 * PAGE_SIZE]))), Priority::Auto).err(),
            Some(SwapError::Header(HeaderError::BadMagic))
        );
        // A bad page that is the header or past the end.
        for bad in [0, 50] {
            let h = SwapHeader { bad_pages: vec![bad], ..SwapHeader::new(10) };
            assert_eq!(
                s.add(Ram::with_header(&h, 10), Priority::Auto).err(),
                Some(SwapError::Header(HeaderError::BadPages))
            );
        }
        // Every slot bad.
        let h = SwapHeader { bad_pages: vec![1, 2], ..SwapHeader::new(3) };
        assert_eq!(s.add(Ram::with_header(&h, 3), Priority::Auto).err(), Some(SwapError::Header(HeaderError::Empty)));
        assert!(!s.active());
    }

    #[test]
    fn slots_fill_free_and_reuse() {
        let s = SwapSpace::new();
        let h = SwapHeader { bad_pages: vec![2], ..SwapHeader::new(6) };
        let id = s.add(Ram::with_header(&h, 6), Priority::Auto).unwrap();
        assert_eq!(s.stats(), (4, 0));
        let slots: std::vec::Vec<Slot> = (0..4).map(|_| s.alloc_slot().unwrap()).collect();
        // Slot 1..=5 minus bad 2.
        let mut raw: std::vec::Vec<u32> = slots.iter().map(|x| x.index).collect();
        raw.sort();
        assert_eq!(raw, [1, 3, 4, 5]);
        assert!(slots.iter().all(|x| x.area_id() == id));
        assert_eq!(s.alloc_slot(), None);
        assert!(s.put(slots[1]));
        assert_eq!(s.stats(), (4, 3));
        assert_eq!(s.alloc_slot(), Some(slots[1]));
    }

    #[test]
    fn shared_pages_are_counted() {
        let s = SwapSpace::new();
        s.add(Ram::made(4), Priority::Auto).unwrap();
        let a = s.alloc_slot().unwrap();
        assert_eq!(s.users(a), 1);
        assert!(s.dup(a));
        assert_eq!(s.users(a), 2);
        assert!(s.put(a));
        assert_eq!(s.stats().1, 1);
        assert!(s.put(a));
        assert_eq!(s.stats().1, 0);
        // Freed: no more users to give up or share.
        assert!(!s.put(a));
        assert!(!s.dup(a));
        assert_eq!(s.users(a), 0);
        // The header and unknown slots.
        assert!(!s.put(Slot { area: a.area, index: 0 }));
        assert!(!s.put(Slot { area: a.area, index: 99 }));
        assert!(!s.put(Slot { area: 77, index: 1 }));
    }

    #[test]
    fn user_count_saturates() {
        let s = SwapSpace::new();
        s.add(Ram::made(3), Priority::Auto).unwrap();
        let a = s.alloc_slot().unwrap();
        for _ in 1..MAX_USERS {
            assert!(s.dup(a));
        }
        assert!(!s.dup(a));
        assert_eq!(s.users(a), MAX_USERS);
    }

    #[test]
    fn pages_round_trip() {
        let s = SwapSpace::new();
        s.add(Ram::made(4), Priority::Auto).unwrap();
        let (a, b) = (s.alloc_slot().unwrap(), s.alloc_slot().unwrap());
        let (pa, pb) = ([0x11; PAGE_SIZE], [0x22; PAGE_SIZE]);
        s.write(a, &pa).unwrap();
        s.write(b, &pb).unwrap();
        let mut got = [0; PAGE_SIZE];
        s.read(a, &mut got).unwrap();
        assert_eq!(got, pa);
        s.read(b, &mut got).unwrap();
        assert_eq!(got, pb);
        // The header is not touched.
        assert!(
            SwapHeader::parse(&{
                let mut h = [0; PAGE_SIZE];
                s.areas.lock().list[0].backing.read(0, &mut h).unwrap();
                h
            })
            .is_ok()
        );
        // A slot not in use is not readable or writable.
        s.put(a);
        assert_eq!(s.read(a, &mut got), Err(SwapError::NoSuchArea));
        assert_eq!(s.write(a, &pa), Err(SwapError::NoSuchArea));
    }

    #[test]
    fn smaller_backing_loses_the_tail() {
        let s = SwapSpace::new();
        // The header says 10 pages, the store has 4.
        s.add(Ram::with_header(&SwapHeader::new(10), 4), Priority::Auto).unwrap();
        assert_eq!(s.stats().0, 3);
    }

    #[test]
    fn priorities() {
        let s = SwapSpace::new();
        let first = s.add(Ram::made(3), Priority::Auto).unwrap();
        let second = s.add(Ram::made(3), Priority::Auto).unwrap();
        let top = s.add(Ram::made(3), Priority::Fixed(5)).unwrap();
        let order: std::vec::Vec<u32> = s.infos().unwrap().iter().map(|i| i.id).collect();
        assert_eq!(order, [top, first, second]);
        let prios: std::vec::Vec<i32> = s.infos().unwrap().iter().map(|i| i.priority).collect();
        assert_eq!(prios, [5, -1, -2]);
        // Fills the highest first.
        let ids: std::vec::Vec<u32> = (0..6).map(|_| s.alloc_slot().unwrap().area_id()).collect();
        assert_eq!(ids, [top, top, first, first, second, second]);
        assert_eq!(s.alloc_slot(), None);
    }

    #[test]
    fn removal_protocol() {
        let s = SwapSpace::new();
        let one = s.add(Ram::made(3), Priority::Fixed(1)).unwrap();
        let two = s.add(Ram::made(3), Priority::Fixed(0)).unwrap();
        let held = s.alloc_slot().unwrap();
        assert_eq!(held.area_id(), one);
        s.begin_removal(one).unwrap();
        // New pages go elsewhere, and the area cannot go with a page in it.
        assert_eq!(s.alloc_slot().unwrap().area_id(), two);
        assert_eq!(s.finish_removal(one), Err(SwapError::InUse));
        // The pages are still readable meanwhile.
        s.write(held, &[7; PAGE_SIZE]).unwrap();
        s.cancel_removal(one).unwrap();
        assert!(s.infos().unwrap()[0].enabled);
        s.begin_removal(one).unwrap();
        s.put(held);
        s.finish_removal(one).unwrap();
        assert_eq!(s.infos().unwrap().len(), 1);
        assert_eq!(s.finish_removal(one), Err(SwapError::NoSuchArea));
        s.begin_removal(two).unwrap();
        assert!(!s.active());
        assert_eq!(s.alloc_slot(), None);
    }

    #[test]
    fn raw_slots() {
        let s = SwapSpace::new();
        s.add(Ram::made(3), Priority::Auto).unwrap();
        let a = s.alloc_slot().unwrap();
        assert_eq!(Slot::from_raw(a.to_raw()), a);
        assert_eq!(a.index(), 0);
    }
}
