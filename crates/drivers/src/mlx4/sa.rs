//! Subnet administration: the one request IPoIB needs, joining a multicast
//! group (a SubnAdmSet of a MCMemberRecord), and its answer.
//!
//! The subnet administrator lives with the subnet manager; requests go to
//! its LID on queue pair 1, on the service level the subnet manager
//! reported, and are answered with the record as the group has it.

use super::ib::Gid;
use super::mad::{self, MAD_LEN};

/// The subnet administration class version.
const SA_CLASS_VERSION: u8 = 2;
const METHOD_SET: u8 = 0x02;
const METHOD_GET_RESP: u8 = 0x81;
const ATTR_MC_MEMBER_RECORD: u16 = 0x0038;
/// Where the record starts in the datagram: the common header, the RMPP
/// header and the subnet administration header.
const DATA: usize = 56;
const COMP_MASK: usize = 48;

// Component mask bits of a MCMemberRecord.
const MASK_MGID: u64 = 1 << 0;
const MASK_PORT_GID: u64 = 1 << 1;
const MASK_PKEY: u64 = 1 << 7;
const MASK_JOIN_STATE: u64 = 1 << 16;

/// The join state of a full member.
const FULL_MEMBER: u8 = 1;

/// A multicast group, as the subnet administrator describes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Group {
    /// The group's GID.
    pub mgid: Gid,
    /// The queue key datagrams to the group use.
    pub qkey: u32,
    /// The multicast LID the group's traffic is routed by.
    pub mlid: u16,
    /// The group's MTU, as the IB enumeration (1 for 256 bytes … 5 for 4096).
    pub mtu: u8,
    /// Traffic class.
    pub traffic_class: u8,
    /// Partition key.
    pub pkey: u16,
    /// The rate, as the IB enumeration.
    pub rate: u8,
    /// Service level.
    pub sl: u8,
    /// Flow label (20 bits).
    pub flow_label: u32,
    /// Hop limit.
    pub hop_limit: u8,
}

impl Group {
    /// The group's MTU in bytes (0 if the enumeration is out of range).
    pub fn mtu_bytes(&self) -> usize {
        match self.mtu {
            n @ 1..=5 => 128 << n,
            _ => 0,
        }
    }
}

/// Why the subnet administrator refused, or why its answer is unusable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// The administrator answered with this status (the MAD status field).
    Refused(u16),
    /// The answer was not for this request, or was cut short.
    Malformed,
}

/// The transaction identifier of requests from this driver: the high half
/// names the driver, the low half counts.
pub fn transaction(counter: u32) -> u64 {
    0x6d6c_7834_0000_0000 | counter as u64
}

/// Builds the request to join `mgid` as a full member from `port_gid` on
/// partition `pkey`.
pub fn join_request(tid: u64, mgid: Gid, port_gid: Gid, pkey: u16) -> [u8; MAD_LEN] {
    let mut m = [0u8; MAD_LEN];
    let mask = MASK_MGID | MASK_PORT_GID | MASK_PKEY | MASK_JOIN_STATE;
    // base version, class, class version, method
    mad::put(&mut m, 0, &[1, mad::CLASS_SUBN_ADM, SA_CLASS_VERSION, METHOD_SET]);
    mad::put(&mut m, 8, &tid.to_be_bytes());
    mad::put(&mut m, 16, &ATTR_MC_MEMBER_RECORD.to_be_bytes());
    mad::put(&mut m, COMP_MASK, &mask.to_be_bytes());
    mad::put(&mut m, DATA, &mgid.0);
    mad::put(&mut m, DATA + 16, &port_gid.0);
    mad::put(&mut m, DATA + 40, &pkey.to_be_bytes());
    mad::put(&mut m, DATA + 48, &[FULL_MEMBER]); // scope 0, join state in the low nibble
    m
}

/// Reads the answer to a join request with transaction `tid`.
pub fn join_response(tid: u64, m: &[u8; MAD_LEN]) -> Result<Group, JoinError> {
    let id = u64::from(mad::be32(m, 8)) << 32 | u64::from(mad::be32(m, 12));
    if m.get(1) != Some(&mad::CLASS_SUBN_ADM)
        || m.get(3) != Some(&METHOD_GET_RESP)
        || id != tid
        || mad::be16(m, 16) != ATTR_MC_MEMBER_RECORD
    {
        return Err(JoinError::Malformed);
    }
    match mad::be16(m, 4) {
        0 => {}
        status => return Err(JoinError::Refused(status)),
    }
    let r = m.get(DATA..).ok_or(JoinError::Malformed)?;
    let byte = |i: usize| r.get(i).copied().ok_or(JoinError::Malformed);
    let words = mad::be32(r, 44);
    let mut mgid = [0u8; 16];
    mgid.copy_from_slice(r.get(0..16).ok_or(JoinError::Malformed)?);
    Ok(Group {
        mgid: Gid(mgid),
        qkey: mad::be32(r, 32),
        mlid: mad::be16(r, 36),
        mtu: byte(38)? & 0x3f,
        traffic_class: byte(39)?,
        pkey: mad::be16(r, 40),
        rate: byte(42)? & 0x3f,
        sl: (words >> 28) as u8,
        flow_label: words >> 8 & 0xf_ffff,
        hop_limit: byte(47)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout() {
        let (mgid, port) =
            (Gid::new(0xff12_401b_ffff_0000, 0xffff_ffff), Gid::new(0xfe80_0000_0000_0000, 0x0002_c903_0012_3456));
        let m = join_request(transaction(7), mgid, port, 0xffff);
        assert_eq!(m[..4], [1, 3, 2, 2], "base version, subnet administration, version 2, Set");
        assert_eq!(mad::be16(&m, 16), 0x0038);
        assert_eq!(u64::from_be_bytes(m[48..56].try_into().unwrap()), 1 << 0 | 1 << 1 | 1 << 7 | 1 << 16);
        assert_eq!((m[56..72].to_vec(), m[72..88].to_vec()), (mgid.0.to_vec(), port.0.to_vec()));
        assert_eq!((mad::be16(&m, 56 + 40), m[56 + 48]), (0xffff, 1));
        assert!(m[24..48].iter().all(|&b| b == 0), "no SM key, no RMPP, no attribute offset");
        assert!(m[88..96].iter().all(|&b| b == 0) && m[56 + 49..].iter().all(|&b| b == 0));
    }

    #[test]
    fn response_fields() {
        let mut m = join_request(transaction(9), Gid::new(1, 2), Gid::new(3, 4), 0x8001);
        m[3] = METHOD_GET_RESP;
        let r = &mut m[56..];
        r[32..36].copy_from_slice(&0x0b1bu32.to_be_bytes());
        r[36..38].copy_from_slice(&0xc004u16.to_be_bytes());
        r[38] = 2 << 6 | 4; // selector "exactly", 2048 bytes
        r[39] = 0x20;
        r[42] = 3 << 6 | 6;
        r[44..48].copy_from_slice(&(5u32 << 28 | 0xa_bcde << 8 | 64).to_be_bytes());
        let g = join_response(transaction(9), &m).unwrap();
        assert_eq!(
            g,
            Group {
                mgid: Gid::new(1, 2),
                qkey: 0x0b1b,
                mlid: 0xc004,
                mtu: 4,
                traffic_class: 0x20,
                pkey: 0x8001,
                rate: 6,
                sl: 5,
                flow_label: 0xa_bcde,
                hop_limit: 64,
            }
        );
        assert_eq!(g.mtu_bytes(), 2048);
        assert_eq!(join_response(transaction(8), &m), Err(JoinError::Malformed), "someone else's transaction");
        m[4..6].copy_from_slice(&0x0300u16.to_be_bytes());
        assert_eq!(join_response(transaction(9), &m), Err(JoinError::Refused(0x0300)));
        m[3] = METHOD_SET;
        assert_eq!(join_response(transaction(9), &m), Err(JoinError::Malformed), "a request, not a response");
    }

    #[test]
    fn hostile_answers_are_errors() {
        let mut m = [0u8; MAD_LEN];
        for len_filled in [0u8, 0xff] {
            m.fill(len_filled);
            let _ = join_response(0, &m);
        }
        m.fill(0);
        assert_eq!(join_response(transaction(1), &m), Err(JoinError::Malformed));
    }
}
