//! The on-disk layout: the BIOS Parameter Block in sector 0 and the FSInfo
//! sector (Microsoft FAT specification §3, §5).

use osmium_fs::Errno;

/// The FAT variant, decided by the number of data clusters alone (§3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatKind {
    /// 12-bit entries, fixed root directory.
    Fat12,
    /// 16-bit entries, fixed root directory.
    Fat16,
    /// 28-bit entries, root directory in a cluster chain.
    Fat32,
}

/// The `first` cluster that stands for the fixed root directory region of a
/// FAT12/16 volume. It is no data cluster, so chain walks stop at once.
pub const ROOT_FIXED: u32 = u32::MAX;

/// Where everything is, from the boot sector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Which FAT variant the volume is.
    pub kind: FatKind,
    /// Bytes per sector (512-4096).
    pub sector_size: u32,
    /// Sectors per cluster.
    pub sectors_per_cluster: u32,
    /// First sector of the first FAT.
    pub fat_start: u32,
    /// Sectors per FAT.
    pub fat_sectors: u32,
    /// Number of FAT copies.
    pub fats: u32,
    /// First sector of the fixed root directory (FAT12/16; 0 for FAT32).
    pub root_start: u32,
    /// Sectors of the fixed root directory (0 for FAT32).
    pub root_sectors: u32,
    /// First sector of cluster 2.
    pub data_start: u32,
    /// Number of data clusters; valid cluster numbers are 2..cluster_count+2.
    pub cluster_count: u32,
    /// First cluster of the root directory, or [`ROOT_FIXED`] for FAT12/16.
    pub root_cluster: u32,
    /// Sector of the FSInfo structure (0 if none).
    pub fsinfo_sector: u32,
}

/// Most data clusters a FAT32 volume can have (§3.5): numbers from
/// 0x0ffffff7 up mean bad cluster and end of chain.
const MAX_CLUSTERS: u32 = 0x0fff_fff5;

fn le16(b: &[u8], at: usize) -> u32 {
    u16::from_le_bytes([b[at], b[at + 1]]) as u32
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("fixed-width slice"))
}

impl FatKind {
    /// Mask of the bits of an entry that hold a cluster number.
    pub fn mask(self) -> u32 {
        match self {
            FatKind::Fat12 => 0x0fff,
            FatKind::Fat16 => 0xffff,
            FatKind::Fat32 => 0x0fff_ffff,
        }
    }

    /// The bad-cluster mark; the end-of-chain marks start one above it.
    pub fn bad(self) -> u32 {
        self.mask() - 8
    }

    /// The mark this implementation writes for the end of a chain.
    pub fn eoc(self) -> u32 {
        self.mask()
    }

    /// Size in bytes of the FAT needed for `clusters` data clusters (two
    /// more entries are reserved at the start).
    fn fat_bytes(self, clusters: u32) -> u64 {
        let entries = clusters as u64 + 2;
        match self {
            FatKind::Fat12 => (entries * 3).div_ceil(2),
            FatKind::Fat16 => entries * 2,
            FatKind::Fat32 => entries * 4,
        }
    }
}

impl Geometry {
    /// Parses boot sector `b` (at least 512 bytes). FAT12, FAT16 and FAT32
    /// are told apart by the cluster count; anything inconsistent returns
    /// `EINVAL`.
    pub fn parse(b: &[u8]) -> Result<Self, Errno> {
        if b.len() < 512 || b[510] != 0x55 || b[511] != 0xaa {
            return Err(Errno::EINVAL);
        }
        let sector_size = le16(b, 11);
        let sectors_per_cluster = b[13] as u32;
        let reserved = le16(b, 14);
        let fats = b[16] as u32;
        let root_entries = le16(b, 17);
        let total = match le16(b, 19) {
            0 => le32(b, 32),
            n => n,
        };
        let fat_sectors = match le16(b, 22) {
            0 => le32(b, 36),
            n => n,
        };
        let valid = matches!(sector_size, 512 | 1024 | 2048 | 4096)
            && sectors_per_cluster.is_power_of_two()
            && sectors_per_cluster * sector_size <= 64 * 1024
            && reserved > 0
            && fats > 0
            && fat_sectors > 0;
        if !valid {
            return Err(Errno::EINVAL);
        }
        // The fixed root directory (none on FAT32) follows the FATs, which
        // follow the reserved sectors; all of it lies inside the volume.
        let root_sectors = (root_entries * 32).div_ceil(sector_size);
        let root_start = fats.checked_mul(fat_sectors).and_then(|f| f.checked_add(reserved)).ok_or(Errno::EINVAL)?;
        let data_start = root_start.checked_add(root_sectors).ok_or(Errno::EINVAL)?;
        let cluster_count = total.checked_sub(data_start).ok_or(Errno::EINVAL)? / sectors_per_cluster;
        // The type is decided by the cluster count alone (§3.5); above
        // 0x0ffffff5 cluster numbers would collide with the reserved values.
        let kind = match cluster_count {
            0 => return Err(Errno::EINVAL),
            1..4085 => FatKind::Fat12,
            4085..65525 => FatKind::Fat16,
            65525..=MAX_CLUSTERS => FatKind::Fat32,
            _ => return Err(Errno::EINVAL),
        };
        // FAT12/16 have a root directory and a 16-bit FAT size; FAT32 has
        // neither.
        let fat32_fields = root_entries == 0 && le16(b, 22) == 0;
        let fat16_fields = root_entries != 0 && le16(b, 22) != 0;
        if if kind == FatKind::Fat32 { !fat32_fields } else { !fat16_fields } {
            return Err(Errno::EINVAL);
        }
        // The FAT must have an entry for every cluster.
        if kind.fat_bytes(cluster_count) > fat_sectors as u64 * sector_size as u64 {
            return Err(Errno::EINVAL);
        }
        let (root_cluster, fsinfo_sector) = if kind == FatKind::Fat32 {
            let root_cluster = le32(b, 44);
            if root_cluster < 2 || root_cluster >= cluster_count + 2 {
                return Err(Errno::EINVAL);
            }
            let fsinfo = match le16(b, 48) {
                n if n > 0 && n < reserved => n,
                _ => 0,
            };
            (root_cluster, fsinfo)
        } else {
            (ROOT_FIXED, 0)
        };
        let fixed = kind != FatKind::Fat32;
        Ok(Self {
            kind,
            sector_size,
            sectors_per_cluster,
            fat_start: reserved,
            fat_sectors,
            fats,
            root_start: if fixed { root_start } else { 0 },
            root_sectors: if fixed { root_sectors } else { 0 },
            data_start,
            cluster_count,
            root_cluster,
            fsinfo_sector,
        })
    }

    /// Bytes per cluster.
    pub fn cluster_size(&self) -> u32 {
        self.sector_size * self.sectors_per_cluster
    }

    /// Bytes in the fixed root directory (0 for FAT32).
    pub fn root_bytes(&self) -> u64 {
        self.root_sectors as u64 * self.sector_size as u64
    }

    /// First sector of data cluster `c`.
    pub fn cluster_sector(&self, c: u32) -> u32 {
        self.data_start + (c - 2) * self.sectors_per_cluster
    }

    /// True if `c` names a data cluster.
    pub fn is_data_cluster(&self, c: u32) -> bool {
        c >= 2 && c < self.cluster_count + 2
    }
}

/// FSInfo signatures.
const LEAD: u32 = 0x4161_5252;
const STRUCT: u32 = 0x6141_7272;
const TRAIL: u32 = 0xaa55_0000;
/// "Unknown" for both FSInfo counters.
pub const UNKNOWN: u32 = 0xffff_ffff;

/// The FSInfo hints: free cluster count and where to start looking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsInfo {
    /// Free clusters, if known.
    pub free: Option<u32>,
    /// Cluster to start searching from.
    pub next_free: u32,
}

impl FsInfo {
    /// Parses an FSInfo sector; `None` if its signatures are wrong.
    pub fn parse(b: &[u8], geo: &Geometry) -> Option<Self> {
        if le32(b, 0) != LEAD || le32(b, 484) != STRUCT || le32(b, 508) != TRAIL {
            return None;
        }
        let free = le32(b, 488);
        let next = le32(b, 492);
        Some(Self {
            free: (free != UNKNOWN && free <= geo.cluster_count).then_some(free),
            next_free: if geo.is_data_cluster(next) { next } else { 2 },
        })
    }

    /// Writes the counters into FSInfo sector `b`, leaving the rest alone.
    pub fn store(&self, b: &mut [u8]) {
        b[488..492].copy_from_slice(&self.free.unwrap_or(UNKNOWN).to_le_bytes());
        b[492..496].copy_from_slice(&self.next_free.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A FAT32 boot sector like `mkfs.fat -F 32 -s 1` makes for 64 MiB.
    pub fn boot_sector() -> [u8; 512] {
        let mut b = [0u8; 512];
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 1;
        b[14..16].copy_from_slice(&32u16.to_le_bytes());
        b[16] = 2;
        b[32..36].copy_from_slice(&131072u32.to_le_bytes());
        b[36..40].copy_from_slice(&1009u32.to_le_bytes());
        b[44..48].copy_from_slice(&2u32.to_le_bytes());
        b[48..50].copy_from_slice(&1u16.to_le_bytes());
        b[510] = 0x55;
        b[511] = 0xaa;
        b
    }

    #[test]
    fn geometry() {
        let g = Geometry::parse(&boot_sector()).unwrap();
        assert_eq!((g.fat_start, g.data_start, g.root_cluster, g.fsinfo_sector), (32, 32 + 2 * 1009, 2, 1));
        assert_eq!(g.cluster_count, 131072 - 2050);
        assert_eq!(g.cluster_sector(3), 2051);
        assert_eq!(g.cluster_size(), 512);
        assert_eq!((g.kind, g.root_sectors, g.root_start), (FatKind::Fat32, 0, 0));
    }

    /// A FAT12/16 boot sector: one-sector clusters, one reserved sector, two
    /// FATs of `fat` sectors, `root` root entries and `clusters` clusters.
    fn boot_sector16(clusters: u32, fat: u16, root: u16) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 1;
        b[14..16].copy_from_slice(&1u16.to_le_bytes());
        b[16] = 2;
        b[17..19].copy_from_slice(&root.to_le_bytes());
        let total = 1 + 2 * fat as u32 + (root as u32 * 32).div_ceil(512) + clusters;
        b[32..36].copy_from_slice(&total.to_le_bytes());
        b[22..24].copy_from_slice(&fat.to_le_bytes());
        b[510] = 0x55;
        b[511] = 0xaa;
        b
    }

    #[test]
    fn type_follows_the_cluster_count() {
        // 4084 clusters is FAT12, 4085 FAT16; 65524 is FAT16 (a FAT32 volume
        // needs 65525).
        let g = Geometry::parse(&boot_sector16(4084, 12, 512)).unwrap();
        assert_eq!(
            (g.kind, g.cluster_count, g.root_start, g.root_sectors, g.data_start),
            (FatKind::Fat12, 4084, 25, 32, 57)
        );
        assert_eq!(g.root_cluster, ROOT_FIXED);
        assert_eq!(g.fsinfo_sector, 0);
        assert_eq!(Geometry::parse(&boot_sector16(4085, 17, 512)).unwrap().kind, FatKind::Fat16);
        assert_eq!(Geometry::parse(&boot_sector16(65524, 256, 512)).unwrap().kind, FatKind::Fat16);
        assert_eq!(Geometry::parse(&boot_sector16(1, 1, 16)).unwrap().kind, FatKind::Fat12);
        // A root directory that is not a whole number of sectors is rounded up.
        assert_eq!(Geometry::parse(&boot_sector16(100, 1, 17)).unwrap().root_sectors, 2);
        // The entry marks per variant.
        assert_eq!((FatKind::Fat12.bad(), FatKind::Fat16.bad(), FatKind::Fat32.bad()), (0xff7, 0xfff7, 0x0fff_fff7));
    }

    #[test]
    fn rejects_inconsistent_fat12_16() {
        // The FAT is one entry short: 4084 + 2 entries of 12 bits = 6129 bytes.
        assert_eq!(Geometry::parse(&boot_sector16(4084, 11, 512)), Err(Errno::EINVAL));
        assert!(Geometry::parse(&boot_sector16(4084, 12, 512)).is_ok());
        assert_eq!(Geometry::parse(&boot_sector16(5000, 19, 512)), Err(Errno::EINVAL)); // needs 20
        // FAT12/16 need a root directory; FAT32 must not have one.
        assert_eq!(Geometry::parse(&boot_sector16(4084, 12, 0)), Err(Errno::EINVAL));
        let mut b = boot_sector();
        b[17..19].copy_from_slice(&512u16.to_le_bytes());
        assert_eq!(Geometry::parse(&b), Err(Errno::EINVAL));
        // No clusters at all, a root directory bigger than the volume, no
        // FAT size in the 16-bit field.
        assert_eq!(Geometry::parse(&boot_sector16(0, 1, 16)), Err(Errno::EINVAL));
        let mut big_root = boot_sector16(100, 1, 16);
        big_root[17..19].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(Geometry::parse(&big_root), Err(Errno::EINVAL));
        let mut no_fat = boot_sector16(100, 1, 16);
        no_fat[22..24].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(Geometry::parse(&no_fat), Err(Errno::EINVAL));
    }

    #[test]
    fn rejects_mislabelled_and_garbage() {
        let mut small = boot_sector();
        small[32..36].copy_from_slice(&40000u32.to_le_bytes()); // FAT16 size, FAT32 fields
        assert_eq!(Geometry::parse(&small), Err(Errno::EINVAL));
        let mut unsigned = boot_sector();
        unsigned[510] = 0;
        assert_eq!(Geometry::parse(&unsigned), Err(Errno::EINVAL));
        let mut odd = boot_sector();
        odd[13] = 3;
        assert_eq!(Geometry::parse(&odd), Err(Errno::EINVAL));
    }

    #[test]
    fn rejects_impossible_sizes() {
        // FATs so big their sector count overflows.
        let mut huge_fats = boot_sector();
        huge_fats[16] = 255;
        huge_fats[36..40].copy_from_slice(&0x0200_0000u32.to_le_bytes());
        assert_eq!(Geometry::parse(&huge_fats), Err(Errno::EINVAL));
        // FATs that run past the end of the volume.
        let mut past_end = boot_sector();
        past_end[36..40].copy_from_slice(&70000u32.to_le_bytes());
        assert_eq!(Geometry::parse(&past_end), Err(Errno::EINVAL));
        // More clusters than FAT32 can number (and a FAT big enough for them).
        let mut too_many = boot_sector();
        too_many[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        too_many[36..40].copy_from_slice(&0x0200_0000u32.to_le_bytes());
        assert_eq!(Geometry::parse(&too_many), Err(Errno::EINVAL));
        let mut most = too_many;
        let total = 32 + 2 * 0x0200_0000 + MAX_CLUSTERS;
        most[32..36].copy_from_slice(&total.to_le_bytes());
        assert_eq!(Geometry::parse(&most).map(|g| g.cluster_count), Ok(MAX_CLUSTERS));
    }

    #[test]
    fn fsinfo_round_trip() {
        let g = Geometry::parse(&boot_sector()).unwrap();
        let mut s = [0u8; 512];
        s[0..4].copy_from_slice(&LEAD.to_le_bytes());
        s[484..488].copy_from_slice(&STRUCT.to_le_bytes());
        s[508..512].copy_from_slice(&TRAIL.to_le_bytes());
        s[488..492].copy_from_slice(&UNKNOWN.to_le_bytes());
        let info = FsInfo::parse(&s, &g).unwrap();
        assert_eq!(info, FsInfo { free: None, next_free: 2 });
        FsInfo { free: Some(100), next_free: 7 }.store(&mut s);
        assert_eq!(FsInfo::parse(&s, &g), Some(FsInfo { free: Some(100), next_free: 7 }));
        s[0] = 0;
        assert_eq!(FsInfo::parse(&s, &g), None);
    }
}
