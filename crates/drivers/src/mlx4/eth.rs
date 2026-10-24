//! An Ethernet port: one completion queue and one raw Ethernet queue pair
//! (see [`queue`](super::queue) for the rings they share with InfiniBand
//! ports).
//!
//! Offloads are opt-in per frame through
//! [`transmit_offload`](EthPort::transmit_offload) and
//! [`receive_checked`](EthPort::receive_checked).
//! A segmentation (LSO) frame is staged in a dedicated buffer, one at a
//! time, since the regular transmit slots hold one Ethernet frame each.

use osmium_hal::dma::DmaAllocator;
use osmium_hal::net::{MacAddress, NetDevice, NetError};

use super::cmd::{Ctx, Input, op};
use super::queue::{CTRL_COMPLETE, Geometry, OPCODE_SEND, QpSetup, Queues, SEG_LEN, SET_DATA, SQ_STRIDE};
use super::{Mlx4, Mlx4Error, put32};

/// Bytes per buffer slot.
pub const SLOT_LEN: usize = 2048;

/// Largest frame: 1514 bytes plus a VLAN tag.
const MAX_FRAME: usize = 1518;
/// Port MTU as the firmware counts it: frame, VLAN tag and FCS (Linux's).
const PORT_MTU: u32 = 1500 + 14 + 4 + 4;

const OPCODE_LSO: u32 = 0x0e;
const CTRL_IP_CSUM: u32 = 1 << 4;
const CTRL_L4_CSUM: u32 = 1 << 5;
/// Bytes of the LSO segment's fixed part.
const LSO_FIXED: usize = 4;
/// Largest header the LSO segment can carry in a 128-byte entry with
/// a control segment and one data segment around it.
pub const TSO_MAX_HEADER: usize = SQ_STRIDE - 2 * SEG_LEN - LSO_FIXED;
/// Bytes of the buffer a segmentation frame is staged in.
const LSO_BUF_LEN: usize = 16 * 1024;

const SET_PORT_GENERAL: u32 = 0x0000;
const SET_PORT_RECEIVE_QP: u32 = 0x0100;

const _: () = assert!(2 * SEG_LEN + (LSO_FIXED + TSO_MAX_HEADER).next_multiple_of(SEG_LEN) <= SQ_STRIDE);

/// What a port can offload to the adapter, from [`EthPort::offloads`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offloads {
    /// The adapter can fill in IPv4 header and TCP/UDP checksums on
    /// transmit ([`TxOffload::checksum`]).
    pub tx_checksum: bool,
    /// Received frames come with a verdict on their checksums
    /// ([`EthPort::receive_checked`]).
    pub rx_checksum: bool,
    /// Largest frame (headers included) [`Tso`] can take, or 0 if the
    /// adapter cannot segment.
    pub tso_max_frame: usize,
}

/// Whether the adapter verified a received frame's checksums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxChecksum {
    /// No verdict: not IP over TCP or UDP, or the adapter found a problem.
    /// The stack must check for itself.
    Unverified,
    /// The IP header and the TCP or UDP checksum are both correct.
    Verified,
}

/// TCP segmentation (large send): the adapter cuts one big frame into
/// frames of `mss` payload bytes, copying `header_len` bytes of headers to
/// each and fixing up lengths and checksums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tso {
    /// TCP payload bytes per segment.
    pub mss: u16,
    /// Bytes of Ethernet, IP and TCP headers at the start of the frame
    /// (at most [`TSO_MAX_HEADER`]).
    pub header_len: u16,
}

/// Offloads requested for one transmitted frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxOffload {
    /// Compute the IPv4 header checksum and the TCP/UDP checksum (the TCP
    /// or UDP checksum field must hold the pseudo-header sum).
    pub checksum: bool,
    /// Segment the frame. Implies `checksum`.
    pub tso: Option<Tso>,
}

/// Why [`EthPort::transmit_offload`] refused a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    /// The ordinary transmit errors (queue full, frame too large).
    Net(NetError),
    /// The adapter cannot segment.
    Unsupported,
    /// Zero MSS, or a header length that is zero, longer than
    /// [`TSO_MAX_HEADER`] or than the frame.
    BadSegmentation,
}

impl From<NetError> for TxError {
    fn from(e: NetError) -> Self {
        Self::Net(e)
    }
}

/// A port of an [`Mlx4`] in Ethernet mode. Dropping it closes the port and
/// frees its queues.
pub struct EthPort<'h, 'd, D: DmaAllocator + ?Sized> {
    q: Queues<'h, 'd, D>,
    mac: MacAddress,
    /// Segmentation frame in flight: the value of `tx_done` that frees the
    /// staging buffer.
    lso_until: Option<u32>,
}

impl<'h, 'd, D: DmaAllocator + ?Sized> EthPort<'h, 'd, D> {
    pub(super) fn open(hca: &'h Mlx4<'d, D>, port: u8) -> Result<Self, Mlx4Error> {
        let mut query = Ctx::new();
        hca.hcr.exec_out(op::QUERY_PORT, 0, port as u32, Input::None, &mut query, 64)?;
        let (ib, eth) = (query.get(0, 24, 1) != 0, query.get(0, 25, 1) != 0);
        let ethernet = match (ib, eth) {
            (_, false) => false,
            (true, true) if hca.caps.dpdp => hca.sense_port(port)?.is_none_or(|sensed| sensed.is_ethernet()),
            _ => true,
        };
        if !ethernet {
            return Err(Mlx4Error::NotEthernet);
        }
        let hi = query.get(4, 0, 16).to_be_bytes();
        let lo = query.dword(5).to_be_bytes();
        let mac = MacAddress([hi[2], hi[3], lo[0], lo[1], lo[2], lo[3]]);
        hca.set_link(port, query.get(0, 31, 1) != 0);

        let lso = if hca.caps.max_gso > 0 { LSO_BUF_LEN } else { 0 };
        let geometry = Geometry { rx_slot: SLOT_LEN, tx_slot: SLOT_LEN, lso };
        let mut eth = Self { q: Queues::new(hca, port, SET_DATA, geometry)?, mac, lso_until: None };
        hca.open.set(hca.open.get() | 1 << (port - 1));
        eth.q.create_cq()?;
        eth.create_qp()?;
        eth.q.arm_cq();
        eth.start_port()?;
        Ok(eth)
    }

    /// What this port can offload to the adapter.
    pub fn offloads(&self) -> Offloads {
        Offloads {
            tx_checksum: true,
            rx_checksum: true,
            tso_max_frame: if self.q.mem.lso.is_some() {
                (self.q.hca.caps.max_gso as usize).min(LSO_BUF_LEN)
            } else {
                0
            },
        }
    }

    /// The port number (1-based).
    pub fn port(&self) -> u8 {
        self.q.port
    }

    fn create_qp(&mut self) -> Result<(), Mlx4Error> {
        let port = self.q.port as u32;
        self.q.create_qp(&QpSetup {
            service: 7, // raw Ethernet ("MLX")
            init_mtu_msgmax: 7 << 5 | 31,
            mtu_msgmax: 7 << 5 | 31, // Ethernet MTU, largest message
            init_optpar: 0,
            rtr_optpar: 0,
            rts_optpar: 0,
            init: &|c| {
                // Leave VLAN tags in received frames (Linux sets this
                // whenever VLAN stripping is off).
                c.set(50, 30, 1, 1);
            },
            rtr: &|c| {
                c.set(16, 24, 8, 0x83 | (port - 1) << 6); // default schedule queue of this port
            },
            // Ack timeout and retries (unused).
            rts: &|c| {
                c.set(10, 27, 5, 14).set(30, 16, 3, 7).set(30, 13, 3, 7);
            },
        })
    }

    fn start_port(&mut self) -> Result<(), Mlx4Error> {
        let port = self.q.port as u32;
        let (hcr, qpn) = (&self.q.hca.hcr, self.q.qpn);
        let mut general = Ctx::new();
        general.set(0, 0, 3, 0b111).set(1, 0, 16, PORT_MTU); // MTU and pause settings valid; pause off
        hcr.exec(op::SET_PORT, 1, SET_PORT_GENERAL | port, Input::Mailbox(&general, 16))?;

        // Every MAC and VLAN misses the (empty) tables, and misses go to
        // the promiscuous queue pair: this one.
        let mut rqp = Ctx::new();
        rqp.set(0, 0, 24, qpn).set(2, 0, 8, 128);
        rqp.set(3, 0, 7, 127).set(3, 16, 7, 126);
        rqp.set(5, 0, 24, qpn).set(5, 31, 1, 1); // unicast promiscuous
        rqp.set(6, 0, 24, qpn).set(6, 30, 2, 2); // every multicast
        hcr.exec(op::SET_PORT, 1, SET_PORT_RECEIVE_QP | port, Input::Mailbox(&rqp, 32))?;

        hcr.exec(op::INIT_PORT, 0, port, Input::None)?;
        self.q.stage.port_up = true;
        Ok(())
    }

    /// Transmits `frame` with the offloads in `offload`.
    ///
    /// With [`TxOffload::checksum`] the adapter fills in the IPv4 header
    /// checksum and the TCP or UDP checksum. With [`TxOffload::tso`] the
    /// frame may be up to [`Offloads::tso_max_frame`] bytes and is cut into
    /// segments by the adapter; only one such frame is in flight at a time
    /// (the next returns [`NetError::WouldBlock`] until it completes).
    pub fn transmit_offload(&mut self, frame: &[u8], offload: TxOffload) -> Result<(), TxError> {
        let tso = offload.tso;
        let limit = if tso.is_some() { LSO_BUF_LEN } else { MAX_FRAME };
        if tso.is_some() && self.q.mem.lso.is_none() {
            return Err(TxError::Unsupported);
        }
        if frame.len() > limit || tso.is_some() && frame.len() > self.offloads().tso_max_frame {
            return Err(NetError::TooLarge.into());
        }
        if let Some(t) = tso {
            let h = t.header_len as usize;
            if t.mss == 0 || h == 0 || h > TSO_MAX_HEADER || h >= frame.len() {
                return Err(TxError::BadSegmentation);
            }
            // Each segment must be a legal frame.
            if h + t.mss as usize > MAX_FRAME {
                return Err(NetError::TooLarge.into());
            }
        }
        let lso = tso.is_some();
        if self.q.tx_full() || lso && self.lso_busy() {
            self.q.poll_cq();
            if self.q.tx_full() || lso && self.lso_busy() {
                return Err(NetError::WouldBlock.into());
            }
        }
        let (wqe, slot) = self.q.begin_send();
        let wq = self.q.wq();
        let mut flags = CTRL_COMPLETE;
        if offload.checksum || tso.is_some() {
            flags |= CTRL_IP_CSUM | CTRL_L4_CSUM;
        }
        let (opcode, segments, data_at, buf, data_off, data_len) = match (tso, &self.q.mem.lso) {
            (Some(t), Some(lso)) => {
                let h = t.header_len as usize;
                lso.write(0, frame);
                let hdr = (LSO_FIXED + h).next_multiple_of(SEG_LEN);
                put32(wq, wqe + SEG_LEN, (t.mss as u32) << 16 | h as u32);
                wq.write(wqe + SEG_LEN + LSO_FIXED, frame.get(..h).unwrap_or_default());
                (OPCODE_LSO, 2 + hdr / SEG_LEN, wqe + SEG_LEN + hdr, lso, h, frame.len().saturating_sub(h))
            }
            _ => {
                self.q.mem.tx.write(slot, frame);
                (OPCODE_SEND, 2, wqe + SEG_LEN, &self.q.mem.tx, slot, frame.len())
            }
        };
        put32(wq, wqe + 4, segments as u32); // control, optional LSO header, data
        put32(wq, wqe + 8, flags);
        put32(wq, data_at, data_len as u32);
        put32(wq, data_at + 4, self.q.hca.lkey);
        wq.store(data_at + 8, (buf.device_addr().as_u64() + data_off as u64).to_be());
        self.q.finish_send(wqe, opcode);
        if tso.is_some() {
            self.lso_until = Some(self.q.tx_head);
        }
        Ok(())
    }

    /// True while a segmentation frame still owns the staging buffer.
    fn lso_busy(&mut self) -> bool {
        match self.lso_until {
            // Wrapping comparison: `tx_done` has not reached `until` yet.
            Some(until) if (self.q.tx_done.wrapping_sub(until) as i32) < 0 => true,
            Some(_) => {
                self.lso_until = None;
                false
            }
            None => false,
        }
    }

    /// Like [`receive`](NetDevice::receive), also telling whether the
    /// adapter verified the frame's IP header and TCP/UDP checksum.
    pub fn receive_checked(&mut self, buf: &mut [u8]) -> Result<(usize, RxChecksum), NetError> {
        let Some(frame) = self.q.next_received() else {
            return Err(NetError::WouldBlock);
        };
        let len = frame.len as usize;
        let result = if frame.error {
            Err(NetError::Io)
        } else if let Some(dst) = buf.get_mut(..len) {
            self.q.read_rx(frame.slot, 0, dst);
            Ok((len, if frame.checksum { RxChecksum::Verified } else { RxChecksum::Unverified }))
        } else {
            Err(NetError::TooLarge)
        };
        self.q.repost();
        result
    }
}

impl<D: DmaAllocator + ?Sized> Drop for EthPort<'_, '_, D> {
    fn drop(&mut self) {
        self.q.hca.open.set(self.q.hca.open.get() & !(1 << (self.q.port - 1)));
    }
}

impl<D: DmaAllocator + ?Sized> NetDevice for EthPort<'_, '_, D> {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn max_frame_len(&self) -> usize {
        MAX_FRAME
    }

    fn link_up(&self) -> bool {
        self.q.hca.link_up(self.q.port)
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        match self.transmit_offload(frame, TxOffload::default()) {
            Ok(()) => Ok(()),
            Err(TxError::Net(e)) => Err(e),
            Err(_) => Err(NetError::Io),
        }
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.receive_checked(buf).map(|(len, _)| len)
    }

    fn can_receive(&self) -> bool {
        self.q.can_receive()
    }

    fn can_transmit(&self) -> bool {
        self.q.can_transmit()
    }
}
