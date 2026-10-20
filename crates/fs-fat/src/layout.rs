//! The on-disk layout: the BIOS Parameter Block in sector 0 and the FSInfo
//! sector (Microsoft FAT specification §3, §5).

use osmium_fs::Errno;

/// Where everything is, from the boot sector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Bytes per sector (512–4096).
    pub sector_size: u32,
    /// Sectors per cluster.
    pub sectors_per_cluster: u32,
    /// First sector of the first FAT.
    pub fat_start: u32,
    /// Sectors per FAT.
    pub fat_sectors: u32,
    /// Number of FAT copies.
    pub fats: u32,
    /// First sector of cluster 2.
    pub data_start: u32,
    /// Number of data clusters; valid cluster numbers are 2..cluster_count+2.
    pub cluster_count: u32,
    /// First cluster of the root directory.
    pub root_cluster: u32,
    /// Sector of the FSInfo structure (0 if none).
    pub fsinfo_sector: u32,
}

fn le16(b: &[u8], at: usize) -> u32 {
    u16::from_le_bytes([b[at], b[at + 1]]) as u32
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

impl Geometry {
    /// Parses boot sector `b` (at least 512 bytes). Only FAT32 volumes are
    /// accepted: FAT12 and FAT16 return `EINVAL`.
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
        let data_start = reserved + fats * fat_sectors;
        let cluster_count = total.checked_sub(data_start).ok_or(Errno::EINVAL)? / sectors_per_cluster;
        // The FAT type is decided by the cluster count alone (§3.5).
        if cluster_count < 65525 || root_entries != 0 || le16(b, 22) != 0 {
            return Err(Errno::EINVAL);
        }
        // The FAT must have an entry for every cluster.
        if (cluster_count as u64 + 2) * 4 > fat_sectors as u64 * sector_size as u64 {
            return Err(Errno::EINVAL);
        }
        let root_cluster = le32(b, 44);
        if root_cluster < 2 || root_cluster >= cluster_count + 2 {
            return Err(Errno::EINVAL);
        }
        let fsinfo_sector = match le16(b, 48) {
            n if n > 0 && n < reserved => n,
            _ => 0,
        };
        Ok(Self {
            sector_size,
            sectors_per_cluster,
            fat_start: reserved,
            fat_sectors,
            fats,
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
    }

    #[test]
    fn rejects_fat16_and_garbage() {
        let mut small = boot_sector();
        small[32..36].copy_from_slice(&40000u32.to_le_bytes()); // < 65525 clusters
        assert_eq!(Geometry::parse(&small), Err(Errno::EINVAL));
        let mut unsigned = boot_sector();
        unsigned[510] = 0;
        assert_eq!(Geometry::parse(&unsigned), Err(Errno::EINVAL));
        let mut odd = boot_sector();
        odd[13] = 3;
        assert_eq!(Geometry::parse(&odd), Err(Errno::EINVAL));
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
