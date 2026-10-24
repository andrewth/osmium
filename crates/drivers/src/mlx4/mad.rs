//! Management datagrams: the wire headers the special queue pairs build by
//! hand, and the directed-route rules a channel adapter follows (IBA
//! volume 1, section 14.2.2).

/// Bytes of a management datagram.
pub const MAD_LEN: usize = 256;
/// Bytes of the global route header slot ahead of a received datagram.
pub const GRH_LEN: usize = 40;
/// The LID of a directed-route packet whose end has none yet.
pub const LID_PERMISSIVE: u16 = 0xffff;
/// The queue key of queue pair 1 (and any queue pair that asks for the
/// "controlled" one): the top bit says "use the queue pair's own".
pub const QP1_QKEY: u32 = 0x8001_0000;

// Management classes.
pub const CLASS_SUBN_LID_ROUTED: u8 = 0x01;
pub const CLASS_SUBN_ADM: u8 = 0x03;
pub const CLASS_PERF: u8 = 0x04;
pub const CLASS_SUBN_DIRECTED_ROUTE: u8 = 0x81;

// Methods.
pub const METHOD_GET: u8 = 0x01;
pub const METHOD_SET: u8 = 0x02;
pub const METHOD_TRAP: u8 = 0x05;
pub const METHOD_TRAP_REPRESS: u8 = 0x07;

// Subnet management attributes.
pub const ATTR_SM_INFO: u16 = 0x0020;
pub const ATTR_SL_TO_VL_TABLE: u16 = 0x0017;

/// The directed-route direction bit of the status field: set on responses.
const DIRECTION: u16 = 0x8000;
const MAX_PATH_HOPS: usize = 64;

// Offsets in a subnet management packet.
const STATUS: usize = 4;
const HOP_PTR: usize = 6;
const HOP_CNT: usize = 7;
const DR_SLID: usize = 32;
const DR_DLID: usize = 34;
const RETURN_PATH: usize = 192;

/// Reads a big-endian `u16` at `at`; zero if the bytes are not there, so callers that
/// care check the length first.
pub fn be16(b: &[u8], at: usize) -> u16 {
    at.checked_add(2)
        .and_then(|end| b.get(at..end))
        .and_then(|s| s.first_chunk::<2>())
        .map_or(0, |a| u16::from_be_bytes(*a))
}

/// Reads a big-endian `u32` at `at`; zero if the bytes are not there.
pub fn be32(b: &[u8], at: usize) -> u32 {
    at.checked_add(4)
        .and_then(|end| b.get(at..end))
        .and_then(|s| s.first_chunk::<4>())
        .map_or(0, |a| u32::from_be_bytes(*a))
}

/// Writes `bytes` at `at`; returns false (writing nothing) if they do not fit.
pub(super) fn put(b: &mut [u8], at: usize, bytes: &[u8]) -> bool {
    match at.checked_add(bytes.len()).and_then(|end| b.get_mut(at..end)) {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            true
        }
        None => false,
    }
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    put(b, at, &v.to_be_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    put(b, at, &v.to_be_bytes());
}

/// The work completion of a received datagram, as MAD_IFC takes it.
pub struct MadWc {
    pub slid: u16,
    pub my_qpn: u32,
    pub src_qpn: u32,
    pub sl: u8,
    pub path_bits: u8,
    pub pkey_index: u8,
    pub grh: Option<[u8; GRH_LEN]>,
}

/// A global route header's fields (the addresses are raw 16 bytes).
#[derive(Clone, Copy)]
pub struct GrhFields {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub hop_limit: u8,
    pub source: [u8; 16],
    pub dest: [u8; 16],
}

/// The headers of a UD "send only" packet: local route, optional global
/// route, base transport, datagram extended transport.
pub struct UdHeader {
    pub vl: u8,
    pub sl: u8,
    pub dlid: u16,
    pub slid: u16,
    pub grh: Option<GrhFields>,
    pub pkey: u16,
    pub solicited: bool,
    pub dest_qpn: u32,
    pub psn: u32,
    pub qkey: u32,
    pub src_qpn: u32,
    /// Bytes of payload that follow (the packet's pad count and lengths).
    pub payload: usize,
}

/// The longest packed header: LRH, GRH, BTH, DETH.
pub const UD_HEADER_MAX: usize = 8 + GRH_LEN + 12 + 8;
const OPCODE_UD_SEND_ONLY: u8 = 0x64;

impl UdHeader {
    /// Packs the headers in wire format into `out` and returns their length.
    pub fn pack(&self, out: &mut [u8; UD_HEADER_MAX]) -> usize {
        let grh = self.grh.is_some();
        // LRH: VL, version | SL, next header (2 local, 3 global) | DLID | length, SLID.
        let length = (8 + 12 + 8 + if grh { GRH_LEN } else { 0 } + self.payload + 4).div_ceil(4);
        out[0] = self.vl << 4;
        out[1] = self.sl << 4 | if grh { 3 } else { 2 };
        put16(out, 2, self.dlid);
        put16(out, 4, length as u16 & 0x7ff);
        put16(out, 6, self.slid);
        let mut at = 8;
        if let Some(g) = &self.grh {
            put32(out, at, 6 << 28 | (g.traffic_class as u32) << 20 | g.flow_label & 0xf_ffff);
            // The payload length counts from the BTH through the ICRC.
            let paylen = (12 + 8 + self.payload + 4 + 3) & !3;
            put16(out, at + 4, paylen as u16);
            put(out, at + 6, &[0x1b, g.hop_limit]); // next header: InfiniBand transport, hop limit
            put(out, at + 8, &g.source);
            put(out, at + 24, &g.dest);
            at += GRH_LEN;
        }
        let pad = (4 - (self.payload as u32 & 3)) & 3;
        put32(
            out,
            at,
            (OPCODE_UD_SEND_ONLY as u32) << 24 | (self.solicited as u32) << 23 | pad << 20 | self.pkey as u32,
        );
        put32(out, at + 4, self.dest_qpn & 0xff_ffff);
        put32(out, at + 8, self.psn & 0xff_ffff);
        put32(out, at + 12, self.qkey);
        put32(out, at + 16, self.src_qpn & 0xff_ffff);
        at + 20
    }
}

/// What to do with a directed-route packet that arrived at port `port`.
/// Applies the receive and send rules for a channel adapter (not a switch)
/// to `smp`, which is changed as the specification says; returns false if
/// the packet is to be discarded. A packet that is handled is given to the
/// subnet management agent.
pub fn dr_receive(smp: &mut [u8; MAD_LEN], port: u8) -> bool {
    let (hop_ptr, hop_cnt) = (smp[HOP_PTR], smp[HOP_CNT]);
    let outbound = be16(smp, STATUS) & DIRECTION == 0;
    let dlid_permissive = be16(smp, DR_DLID) == LID_PERMISSIVE;
    if hop_cnt as usize >= MAX_PATH_HOPS || !outbound {
        // A response is for the subnet manager, which is not here.
        return false;
    }
    match hop_ptr {
        0 if hop_cnt > 0 => false, // the sender should have counted the hop
        // At the end of the path: record the way back, then step past it.
        p if p == hop_cnt => {
            if hop_cnt > 0 {
                put(smp, RETURN_PATH + p as usize, &[port]);
            }
            if !dlid_permissive {
                return false;
            }
            smp[HOP_PTR] = p + 1;
            true
        }
        // Already past the end: for the agent.
        p if p == hop_cnt + 1 => true,
        // An intermediate hop: only switches forward.
        _ => false,
    }
}

/// The directed-route rules for sending the response the agent produced:
/// sets the direction bit and steps the hop pointer back. Returns false if
/// the response must not be sent from `port`.
pub fn dr_respond(smp: &mut [u8; MAD_LEN], port: u8) -> bool {
    let status = be16(smp, STATUS);
    put16(smp, STATUS, status | DIRECTION);
    let (hop_ptr, hop_cnt) = (smp[HOP_PTR], smp[HOP_CNT]);
    let slid_permissive = be16(smp, DR_SLID) == LID_PERMISSIVE;
    // The answer comes from the firmware; its path length is checked again.
    if hop_cnt as usize >= MAX_PATH_HOPS {
        return false;
    }
    if hop_cnt > 0 && hop_ptr == hop_cnt + 1 {
        smp[HOP_PTR] = hop_ptr - 1;
        return smp.get(RETURN_PATH + (hop_ptr - 1) as usize) == Some(&port);
    }
    match hop_ptr {
        1 => {
            smp[HOP_PTR] = 0;
            slid_permissive
        }
        0 => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smp(hop_ptr: u8, hop_cnt: u8, status: u16, dlid: u16, slid: u16) -> [u8; MAD_LEN] {
        let mut m = [0u8; MAD_LEN];
        m[HOP_PTR] = hop_ptr;
        m[HOP_CNT] = hop_cnt;
        put16(&mut m, STATUS, status);
        put16(&mut m, DR_DLID, dlid);
        put16(&mut m, DR_SLID, slid);
        m
    }

    #[test]
    fn directed_route_requests_and_responses() {
        // The end of a 2-hop path: the way back is recorded, the pointer steps past the end.
        let mut m = smp(2, 2, 0, LID_PERMISSIVE, LID_PERMISSIVE);
        assert!(dr_receive(&mut m, 1));
        assert_eq!((m[HOP_PTR], m[RETURN_PATH + 2]), (3, 1));
        // The answer goes back the way it came.
        let mut answer = m;
        assert!(dr_respond(&mut answer, 1));
        assert_eq!((answer[HOP_PTR], be16(&answer, STATUS)), (2, DIRECTION));
        assert!(!dr_respond(&mut m, 2), "this is not the port the request came in on");

        // Nothing for an end node to do with an intermediate hop, a response, or a path
        // that is too long; a firmware answer cannot walk off the packet either.
        assert!(!dr_receive(&mut smp(1, 2, 0, LID_PERMISSIVE, LID_PERMISSIVE), 1));
        assert!(!dr_receive(&mut smp(0, 0, DIRECTION, LID_PERMISSIVE, LID_PERMISSIVE), 1));
        assert!(!dr_receive(&mut smp(64, 64, 0, LID_PERMISSIVE, LID_PERMISSIVE), 1));
        assert!(!dr_receive(&mut smp(0, 0, 0, 7, LID_PERMISSIVE), 1), "a real destination LID is not ours");
        for (ptr, cnt) in [(255, 254), (0, 255), (255, 255), (64, 63), (64, 64)] {
            assert!(!dr_respond(&mut smp(ptr, cnt, 0, LID_PERMISSIVE, LID_PERMISSIVE), 1), "{ptr}/{cnt}");
        }
        // A packet whose source is a real LID has nowhere to go back to without a subnet manager's help.
        assert!(!dr_respond(&mut smp(1, 0, 0, LID_PERMISSIVE, 5), 1));
        assert!(dr_respond(&mut smp(1, 0, 0, LID_PERMISSIVE, LID_PERMISSIVE), 1));
    }

    #[test]
    fn short_buffers_read_as_zero_and_write_nothing() {
        assert_eq!((be16(&[1], 0), be16(&[1, 2], usize::MAX), be32(&[1, 2, 3], 0), be32(&[], 7)), (0, 0, 0, 0));
        assert_eq!(be16(&[0, 0, 1, 2], 2), 0x0102);
        let mut b = [0u8; 3];
        assert!(!put(&mut b, 2, &[1, 2]) && !put(&mut b, usize::MAX, &[1, 2]));
        assert_eq!(b, [0; 3]);
        // A path as long as the packet allows must not walk off it.
        let mut m = smp(255, 254, DIRECTION, LID_PERMISSIVE, LID_PERMISSIVE);
        assert!(!dr_respond(&mut m, 1));
    }

    #[test]
    fn headers_pack_the_way_the_wire_has_them() {
        let h = UdHeader {
            vl: 15,
            sl: 9,
            dlid: 0x1234,
            slid: 0x56,
            grh: None,
            pkey: 0xffff,
            solicited: true,
            dest_qpn: 0xab_cdef,
            psn: 0x12_3456,
            qkey: 0x8001_0000,
            src_qpn: 0x11_2233,
            payload: 255,
        };
        let mut raw = [0u8; UD_HEADER_MAX];
        let n = h.pack(&mut raw);
        assert_eq!(n, 28);
        assert_eq!(raw[..8], [0xf0, 0x92, 0x12, 0x34, 0x00, 0x48, 0x00, 0x56], "LRH: VL 15, SL 9, local, 72 words");
        // BTH: UD send only, solicited, pad of 1 byte, the partition key; DETH.
        assert_eq!(raw[8..12], [0x64, 0x80 | 1 << 4, 0xff, 0xff]);
        assert_eq!(raw[12..16], [0, 0xab, 0xcd, 0xef]);
        assert_eq!(raw[16..20], [0, 0x12, 0x34, 0x56]);
        assert_eq!(raw[20..28], [0x80, 0x01, 0, 0, 0, 0x11, 0x22, 0x33]);

        let g = GrhFields { traffic_class: 0xa5, flow_label: 0xf_edcb, hop_limit: 9, source: [1; 16], dest: [2; 16] };
        let n = UdHeader { grh: Some(g), payload: 256, solicited: false, ..h }.pack(&mut raw);
        assert_eq!(n, 68);
        assert_eq!(raw[1] & 3, 3, "next header: global");
        assert_eq!(raw[8..12], [0x6a, 0x5f, 0xed, 0xcb], "version 6, class, flow label");
        assert_eq!(raw[12..16], [0x01, 0x18, 0x1b, 9], "payload length 280, next header 0x1b, hop limit");
        assert_eq!((raw[16..32].to_vec(), raw[32..48].to_vec()), ([1; 16].to_vec(), [2; 16].to_vec()));
        assert_eq!(raw[48], 0x64);
        assert_eq!(raw[49] >> 4 & 3, 0, "no padding");
    }
}
