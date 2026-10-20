//! iSCSI PDUs (RFC 7143 §11), independent of any transport.
//!
//! Every PDU is a 48-byte Basic Header Segment (BHS), optional Additional
//! Header Segments, and a data segment padded to a multiple of four bytes.
//! Header and data digests are never negotiated, so neither is present.
//!
//! [`Pdu`] is the raw form: the BHS bytes and the data segment.
//! [`Message`] is the decoded form, one variant per PDU type an initiator
//! sends or receives; [`Message::encode`] and [`Message::decode`] convert
//! between the two in both directions, so the same code serves an initiator
//! and a test target. [`PduReader`] cuts PDUs out of a byte stream.

use alloc::vec::Vec;
use core::fmt;

use crate::crc32c::crc32c;

/// Bytes in a Basic Header Segment.
pub const BHS_LEN: usize = 48;

/// The reserved tag: an Initiator or Target Transfer Tag meaning "none".
pub const RESERVED_TAG: u32 = 0xffff_ffff;

/// PDU opcodes (the low six bits of the first byte).
pub mod opcode {
    #![allow(missing_docs)]
    pub const NOP_OUT: u8 = 0x00;
    pub const SCSI_COMMAND: u8 = 0x01;
    pub const LOGIN_REQUEST: u8 = 0x03;
    pub const TEXT_REQUEST: u8 = 0x04;
    pub const DATA_OUT: u8 = 0x05;
    pub const LOGOUT_REQUEST: u8 = 0x06;
    pub const NOP_IN: u8 = 0x20;
    pub const SCSI_RESPONSE: u8 = 0x21;
    pub const LOGIN_RESPONSE: u8 = 0x23;
    pub const TEXT_RESPONSE: u8 = 0x24;
    pub const DATA_IN: u8 = 0x25;
    pub const LOGOUT_RESPONSE: u8 = 0x26;
    pub const R2T: u8 = 0x31;
    pub const ASYNC_MESSAGE: u8 = 0x32;
    pub const REJECT: u8 = 0x3f;
}

/// Login stages, as carried in the CSG and NSG fields (RFC 7143 §11.12.3).
pub mod stage {
    /// SecurityNegotiation.
    pub const SECURITY: u8 = 0;
    /// LoginOperationalNegotiation.
    pub const OPERATIONAL: u8 = 1;
    /// FullFeaturePhase.
    pub const FULL_FEATURE: u8 = 3;
}

/// Bit 6 of the first byte: the command is delivered immediately, outside
/// CmdSN order.
const IMMEDIATE: u8 = 0x40;
/// The Final bit, in byte 1 of most PDUs.
const F: u8 = 0x80;
/// Login: Transit. Text: Continue is 0x40 too.
const T: u8 = 0x80;
const C: u8 = 0x40;

/// Why bytes are not a PDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PduError {
    /// The opcode is not one this crate handles.
    UnknownOpcode(u8),
    /// The data segment is longer than allowed.
    TooLong(usize),
    /// A header or data digest does not match its contents.
    Digest,
}

impl fmt::Display for PduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PduError::UnknownOpcode(op) => write!(f, "unknown iSCSI opcode {op:#04x}"),
            PduError::TooLong(n) => write!(f, "iSCSI data segment of {n} bytes is too long"),
            PduError::Digest => write!(f, "iSCSI digest mismatch"),
        }
    }
}

/// A PDU on the wire: the Basic Header Segment and the data segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    /// The Basic Header Segment. The data segment length (bytes 5..8) is
    /// filled in from `data` by [`to_bytes`](Self::to_bytes).
    pub bhs: [u8; BHS_LEN],
    /// The data segment, without padding.
    pub data: Vec<u8>,
}

impl Pdu {
    /// A PDU with `opcode`, every other field zero, and no data.
    pub fn new(opcode: u8) -> Self {
        let mut bhs = [0; BHS_LEN];
        bhs[0] = opcode;
        Self { bhs, data: Vec::new() }
    }

    /// The opcode.
    pub fn opcode(&self) -> u8 {
        self.bhs[0] & 0x3f
    }

    /// The big-endian word at byte `at` of the BHS.
    pub fn u32_at(&self, at: usize) -> u32 {
        u32::from_be_bytes(self.bhs[at..at + 4].try_into().expect("fixed-width slice"))
    }

    /// Stores a big-endian word at byte `at` of the BHS.
    pub fn set_u32(&mut self, at: usize, v: u32) {
        self.bhs[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }

    fn u16_at(&self, at: usize) -> u16 {
        u16::from_be_bytes([self.bhs[at], self.bhs[at + 1]])
    }

    fn set_u16(&mut self, at: usize, v: u16) {
        self.bhs[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }

    fn lun(&self) -> [u8; 8] {
        self.bhs[8..16].try_into().expect("fixed-width slice")
    }

    fn set_lun(&mut self, lun: [u8; 8]) {
        self.bhs[8..16].copy_from_slice(&lun);
    }

    /// The PDU as it goes on the wire, data segment length set and the data
    /// padded to four bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_with(false, false)
    }

    /// Like [`to_bytes`](Self::to_bytes), with a CRC32C header digest after
    /// the BHS and a data digest after the padded data segment (none if
    /// there is no data), as negotiated for the connection.
    pub fn to_bytes_with(&self, header_digest: bool, data_digest: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(BHS_LEN + self.data.len().next_multiple_of(4) + 8);
        out.extend_from_slice(&self.bhs);
        out[4] = 0; // no AHS
        let len = (self.data.len() as u32).to_be_bytes();
        out[5..8].copy_from_slice(&len[1..]);
        if header_digest {
            out.extend_from_slice(&crc32c(&out).to_le_bytes());
        }
        let data_at = out.len();
        out.extend_from_slice(&self.data);
        out.resize(data_at + self.data.len().next_multiple_of(4), 0);
        if data_digest && !self.data.is_empty() {
            out.extend_from_slice(&crc32c(&out[data_at..]).to_le_bytes());
        }
        out
    }
}

/// Cuts PDUs out of a byte stream.
#[derive(Debug)]
pub struct PduReader {
    buf: Vec<u8>,
    max_data: usize,
    header_digest: bool,
    data_digest: bool,
}

impl PduReader {
    /// A reader that rejects data segments longer than `max_data` bytes.
    pub fn new(max_data: usize) -> Self {
        Self { buf: Vec::new(), max_data, header_digest: false, data_digest: false }
    }

    /// Changes the longest data segment accepted.
    pub fn set_max_data(&mut self, max_data: usize) {
        self.max_data = max_data;
    }

    /// Expects (and checks) a CRC32C header and/or data digest on every PDU
    /// from now on, as negotiated for the connection.
    pub fn set_digests(&mut self, header: bool, data: bool) {
        self.header_digest = header;
        self.data_digest = data;
    }

    /// Appends bytes received from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes received but not yet returned as a PDU.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The next complete PDU, if the stream holds one. Additional Header
    /// Segments are skipped. After an error the stream is out of step and
    /// the connection must be dropped.
    pub fn next_pdu(&mut self) -> Result<Option<Pdu>, PduError> {
        if self.buf.len() < BHS_LEN {
            return Ok(None);
        }
        let ahs = self.buf[4] as usize * 4;
        let header_end = BHS_LEN + ahs;
        let data_at = header_end + if self.header_digest { 4 } else { 0 };
        if self.header_digest {
            // Check the header before trusting the lengths in it.
            let Some(digest) = self.buf.get(header_end..data_at) else {
                return Ok(None);
            };
            if crc32c(&self.buf[..header_end]).to_le_bytes() != digest {
                return Err(PduError::Digest);
            }
        }
        let len = u32::from_be_bytes([0, self.buf[5], self.buf[6], self.buf[7]]) as usize;
        if len > self.max_data {
            return Err(PduError::TooLong(len));
        }
        let padded = len.next_multiple_of(4);
        let total = data_at + padded + if self.data_digest && len > 0 { 4 } else { 0 };
        if self.buf.len() < total {
            return Ok(None);
        }
        if self.data_digest && len > 0 {
            let end = data_at + padded;
            if crc32c(&self.buf[data_at..end]).to_le_bytes() != self.buf[end..total] {
                return Err(PduError::Digest);
            }
        }
        let mut pdu = Pdu { bhs: self.buf[..BHS_LEN].try_into().expect("fixed-width slice"), data: Vec::new() };
        pdu.data.extend_from_slice(&self.buf[data_at..data_at + len]);
        self.buf.drain(..total);
        Ok(Some(pdu))
    }
}

/// Login Request (RFC 7143 §11.12).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct LoginRequest {
    /// Transit to `nsg` once this stage's negotiation is done.
    pub transit: bool,
    /// More text follows in the next request.
    pub cont: bool,
    pub csg: u8,
    pub nsg: u8,
    pub isid: [u8; 6],
    pub tsih: u16,
    pub itt: u32,
    pub cid: u16,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    /// Text keys.
    pub data: Vec<u8>,
}

/// Login Response (RFC 7143 §11.13).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct LoginResponse {
    pub transit: bool,
    pub cont: bool,
    pub csg: u8,
    pub nsg: u8,
    pub isid: [u8; 6],
    pub tsih: u16,
    pub itt: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    /// 0 success, 1 redirection, 2 initiator error, 3 target error.
    pub status_class: u8,
    pub status_detail: u8,
    /// Text keys.
    pub data: Vec<u8>,
}

/// SCSI Command (RFC 7143 §11.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ScsiCommand {
    /// No unsolicited Data-Out follows.
    pub final_pdu: bool,
    pub read: bool,
    pub write: bool,
    /// Task attribute; 1 is SIMPLE.
    pub attr: u8,
    pub lun: [u8; 8],
    pub itt: u32,
    pub expected_len: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    /// The CDB, zero padded.
    pub cdb: [u8; 16],
    /// Immediate data.
    pub data: Vec<u8>,
}

/// SCSI Response (RFC 7143 §11.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ScsiResponse {
    /// The target had more data than the expected length (O bit).
    pub overflow: bool,
    /// The target moved less than the expected length (U bit).
    pub underflow: bool,
    /// 0 when the command completed at the target, whatever its status.
    pub response: u8,
    /// The SCSI status.
    pub status: u8,
    pub itt: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub exp_data_sn: u32,
    pub residual: u32,
    /// A two-byte SenseLength followed by sense data, or empty.
    pub data: Vec<u8>,
}

/// SCSI Data-Out (RFC 7143 §11.7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct DataOut {
    /// Last PDU of the sequence (the unsolicited burst or one R2T's).
    pub final_pdu: bool,
    pub lun: [u8; 8],
    pub itt: u32,
    /// The R2T's tag, or [`RESERVED_TAG`] for unsolicited data.
    pub ttt: u32,
    pub exp_stat_sn: u32,
    pub data_sn: u32,
    pub offset: u32,
    pub data: Vec<u8>,
}

/// SCSI Data-In (RFC 7143 §11.7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct DataIn {
    /// Last PDU of a sequence.
    pub final_pdu: bool,
    /// The target asks for a DataACK SNACK (error recovery levels above 0).
    pub ack: bool,
    pub overflow: bool,
    pub underflow: bool,
    /// The command's SCSI status, if this PDU completes it (S bit).
    pub status: Option<u8>,
    pub lun: [u8; 8],
    pub itt: u32,
    pub ttt: u32,
    /// Valid only with a status.
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data_sn: u32,
    pub offset: u32,
    pub residual: u32,
    pub data: Vec<u8>,
}

/// Ready To Transfer (RFC 7143 §11.8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct R2t {
    pub lun: [u8; 8],
    pub itt: u32,
    pub ttt: u32,
    /// The next StatSN; R2T does not advance it.
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub r2t_sn: u32,
    pub offset: u32,
    pub desired_len: u32,
}

/// NOP-Out (RFC 7143 §11.18).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct NopOut {
    pub immediate: bool,
    pub lun: [u8; 8],
    /// [`RESERVED_TAG`] when this answers a NOP-In.
    pub itt: u32,
    /// The NOP-In's tag when answering one, else [`RESERVED_TAG`].
    pub ttt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub data: Vec<u8>,
}

/// NOP-In (RFC 7143 §11.19).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct NopIn {
    pub lun: [u8; 8],
    /// [`RESERVED_TAG`] for a target-initiated ping.
    pub itt: u32,
    /// Not [`RESERVED_TAG`] if the target wants a NOP-Out back.
    pub ttt: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data: Vec<u8>,
}

/// Text Request (RFC 7143 §11.10).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct TextRequest {
    pub immediate: bool,
    pub final_pdu: bool,
    pub cont: bool,
    pub lun: [u8; 8],
    pub itt: u32,
    pub ttt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub data: Vec<u8>,
}

/// Text Response (RFC 7143 §11.11).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct TextResponse {
    pub final_pdu: bool,
    pub cont: bool,
    pub lun: [u8; 8],
    pub itt: u32,
    /// Echoed in the next Text Request while more text is to come.
    pub ttt: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data: Vec<u8>,
}

/// Logout Request (RFC 7143 §11.14). Always sent as immediate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct LogoutRequest {
    /// 0 closes the session, 1 the connection.
    pub reason: u8,
    pub itt: u32,
    pub cid: u16,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
}

/// Logout Response (RFC 7143 §11.15).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct LogoutResponse {
    /// 0 when the logout succeeded.
    pub response: u8,
    pub itt: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub time2wait: u16,
    pub time2retain: u16,
}

/// Asynchronous Message (RFC 7143 §11.9).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct AsyncMessage {
    pub lun: [u8; 8],
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    /// 0 SCSI event, 1 logout requested, 2 connection dropped, 3 session
    /// dropped, 4 renegotiate, 255 vendor specific.
    pub event: u8,
    pub vcode: u8,
    pub params: [u16; 3],
    pub data: Vec<u8>,
}

/// Reject (RFC 7143 §11.17).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Reject {
    pub reason: u8,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data_sn: u32,
    /// The header of the rejected PDU.
    pub data: Vec<u8>,
}

/// A decoded PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Message {
    NopOut(NopOut),
    ScsiCommand(ScsiCommand),
    LoginRequest(LoginRequest),
    TextRequest(TextRequest),
    DataOut(DataOut),
    LogoutRequest(LogoutRequest),
    NopIn(NopIn),
    ScsiResponse(ScsiResponse),
    LoginResponse(LoginResponse),
    TextResponse(TextResponse),
    DataIn(DataIn),
    LogoutResponse(LogoutResponse),
    R2t(R2t),
    AsyncMessage(AsyncMessage),
    Reject(Reject),
}

fn bit(on: bool, mask: u8) -> u8 {
    if on { mask } else { 0 }
}

/// Byte 1 of a Login PDU from its fields.
fn login_flags(transit: bool, cont: bool, csg: u8, nsg: u8) -> u8 {
    bit(transit, T) | bit(cont, C) | (csg & 3) << 2 | nsg & 3
}

impl Message {
    /// Decodes `pdu`.
    pub fn decode(pdu: Pdu) -> Result<Self, PduError> {
        let p = &pdu;
        let flags = p.bhs[1];
        let fin = flags & F != 0;
        let imm = p.bhs[0] & IMMEDIATE != 0;
        let (sn24, sn28, sn32) = (p.u32_at(24), p.u32_at(28), p.u32_at(32));
        Ok(match p.opcode() {
            opcode::NOP_OUT => Message::NopOut(NopOut {
                immediate: imm,
                lun: p.lun(),
                itt: p.u32_at(16),
                ttt: p.u32_at(20),
                cmd_sn: sn24,
                exp_stat_sn: sn28,
                data: pdu.data,
            }),
            opcode::SCSI_COMMAND => Message::ScsiCommand(ScsiCommand {
                final_pdu: fin,
                read: flags & 0x40 != 0,
                write: flags & 0x20 != 0,
                attr: flags & 7,
                lun: p.lun(),
                itt: p.u32_at(16),
                expected_len: p.u32_at(20),
                cmd_sn: sn24,
                exp_stat_sn: sn28,
                cdb: p.bhs[32..48].try_into().expect("fixed-width slice"),
                data: pdu.data,
            }),
            opcode::LOGIN_REQUEST => Message::LoginRequest(LoginRequest {
                transit: flags & T != 0,
                cont: flags & C != 0,
                csg: flags >> 2 & 3,
                nsg: flags & 3,
                isid: p.bhs[8..14].try_into().expect("fixed-width slice"),
                tsih: p.u16_at(14),
                itt: p.u32_at(16),
                cid: p.u16_at(20),
                cmd_sn: sn24,
                exp_stat_sn: sn28,
                data: pdu.data,
            }),
            opcode::TEXT_REQUEST => Message::TextRequest(TextRequest {
                immediate: imm,
                final_pdu: fin,
                cont: flags & C != 0,
                lun: p.lun(),
                itt: p.u32_at(16),
                ttt: p.u32_at(20),
                cmd_sn: sn24,
                exp_stat_sn: sn28,
                data: pdu.data,
            }),
            opcode::DATA_OUT => Message::DataOut(DataOut {
                final_pdu: fin,
                lun: p.lun(),
                itt: p.u32_at(16),
                ttt: p.u32_at(20),
                exp_stat_sn: sn28,
                data_sn: p.u32_at(36),
                offset: p.u32_at(40),
                data: pdu.data,
            }),
            opcode::LOGOUT_REQUEST => Message::LogoutRequest(LogoutRequest {
                reason: flags & 0x7f,
                itt: p.u32_at(16),
                cid: p.u16_at(20),
                cmd_sn: sn24,
                exp_stat_sn: sn28,
            }),
            opcode::NOP_IN => Message::NopIn(NopIn {
                lun: p.lun(),
                itt: p.u32_at(16),
                ttt: p.u32_at(20),
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                data: pdu.data,
            }),
            opcode::SCSI_RESPONSE => Message::ScsiResponse(ScsiResponse {
                overflow: flags & 0x04 != 0,
                underflow: flags & 0x02 != 0,
                response: p.bhs[2],
                status: p.bhs[3],
                itt: p.u32_at(16),
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                exp_data_sn: p.u32_at(36),
                residual: p.u32_at(44),
                data: pdu.data,
            }),
            opcode::LOGIN_RESPONSE => Message::LoginResponse(LoginResponse {
                transit: flags & T != 0,
                cont: flags & C != 0,
                csg: flags >> 2 & 3,
                nsg: flags & 3,
                isid: p.bhs[8..14].try_into().expect("fixed-width slice"),
                tsih: p.u16_at(14),
                itt: p.u32_at(16),
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                status_class: p.bhs[36],
                status_detail: p.bhs[37],
                data: pdu.data,
            }),
            opcode::TEXT_RESPONSE => Message::TextResponse(TextResponse {
                final_pdu: fin,
                cont: flags & C != 0,
                lun: p.lun(),
                itt: p.u32_at(16),
                ttt: p.u32_at(20),
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                data: pdu.data,
            }),
            opcode::DATA_IN => Message::DataIn(DataIn {
                final_pdu: fin,
                ack: flags & 0x40 != 0,
                overflow: flags & 0x04 != 0,
                underflow: flags & 0x02 != 0,
                status: (flags & 0x01 != 0).then_some(p.bhs[3]),
                lun: p.lun(),
                itt: p.u32_at(16),
                ttt: p.u32_at(20),
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                data_sn: p.u32_at(36),
                offset: p.u32_at(40),
                residual: p.u32_at(44),
                data: pdu.data,
            }),
            opcode::LOGOUT_RESPONSE => Message::LogoutResponse(LogoutResponse {
                response: p.bhs[2],
                itt: p.u32_at(16),
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                time2wait: p.u16_at(40),
                time2retain: p.u16_at(42),
            }),
            opcode::R2T => Message::R2t(R2t {
                lun: p.lun(),
                itt: p.u32_at(16),
                ttt: p.u32_at(20),
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                r2t_sn: p.u32_at(36),
                offset: p.u32_at(40),
                desired_len: p.u32_at(44),
            }),
            opcode::ASYNC_MESSAGE => Message::AsyncMessage(AsyncMessage {
                lun: p.lun(),
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                event: p.bhs[36],
                vcode: p.bhs[37],
                params: [p.u16_at(38), p.u16_at(40), p.u16_at(42)],
                data: pdu.data,
            }),
            opcode::REJECT => Message::Reject(Reject {
                reason: p.bhs[2],
                stat_sn: sn24,
                exp_cmd_sn: sn28,
                max_cmd_sn: sn32,
                data_sn: p.u32_at(36),
                data: pdu.data,
            }),
            op => return Err(PduError::UnknownOpcode(op)),
        })
    }

    /// Encodes the message as a PDU.
    pub fn encode(self) -> Pdu {
        let op = self.opcode();
        let mut p = Pdu::new(op);
        // Fields shared by the target's responses.
        fn status(p: &mut Pdu, stat_sn: u32, exp_cmd_sn: u32, max_cmd_sn: u32) {
            p.set_u32(24, stat_sn);
            p.set_u32(28, exp_cmd_sn);
            p.set_u32(32, max_cmd_sn);
        }
        match self {
            Message::NopOut(m) => {
                p.bhs[0] |= bit(m.immediate, IMMEDIATE);
                p.bhs[1] = F;
                p.set_lun(m.lun);
                p.set_u32(16, m.itt);
                p.set_u32(20, m.ttt);
                p.set_u32(24, m.cmd_sn);
                p.set_u32(28, m.exp_stat_sn);
                p.data = m.data;
            }
            Message::ScsiCommand(m) => {
                p.bhs[1] = bit(m.final_pdu, F) | bit(m.read, 0x40) | bit(m.write, 0x20) | m.attr & 7;
                p.set_lun(m.lun);
                p.set_u32(16, m.itt);
                p.set_u32(20, m.expected_len);
                p.set_u32(24, m.cmd_sn);
                p.set_u32(28, m.exp_stat_sn);
                p.bhs[32..48].copy_from_slice(&m.cdb);
                p.data = m.data;
            }
            Message::LoginRequest(m) => {
                p.bhs[0] |= IMMEDIATE; // login requests are always immediate
                p.bhs[1] = login_flags(m.transit, m.cont, m.csg, m.nsg);
                p.bhs[8..14].copy_from_slice(&m.isid);
                p.set_u16(14, m.tsih);
                p.set_u32(16, m.itt);
                p.set_u16(20, m.cid);
                p.set_u32(24, m.cmd_sn);
                p.set_u32(28, m.exp_stat_sn);
                p.data = m.data;
            }
            Message::TextRequest(m) => {
                p.bhs[0] |= bit(m.immediate, IMMEDIATE);
                p.bhs[1] = bit(m.final_pdu, F) | bit(m.cont, C);
                p.set_lun(m.lun);
                p.set_u32(16, m.itt);
                p.set_u32(20, m.ttt);
                p.set_u32(24, m.cmd_sn);
                p.set_u32(28, m.exp_stat_sn);
                p.data = m.data;
            }
            Message::DataOut(m) => {
                p.bhs[1] = bit(m.final_pdu, F);
                p.set_lun(m.lun);
                p.set_u32(16, m.itt);
                p.set_u32(20, m.ttt);
                p.set_u32(28, m.exp_stat_sn);
                p.set_u32(36, m.data_sn);
                p.set_u32(40, m.offset);
                p.data = m.data;
            }
            Message::LogoutRequest(m) => {
                p.bhs[0] |= IMMEDIATE;
                p.bhs[1] = F | m.reason & 0x7f;
                p.set_u32(16, m.itt);
                p.set_u16(20, m.cid);
                p.set_u32(24, m.cmd_sn);
                p.set_u32(28, m.exp_stat_sn);
            }
            Message::NopIn(m) => {
                p.bhs[1] = F;
                p.set_lun(m.lun);
                p.set_u32(16, m.itt);
                p.set_u32(20, m.ttt);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.data = m.data;
            }
            Message::ScsiResponse(m) => {
                p.bhs[1] = F | bit(m.overflow, 0x04) | bit(m.underflow, 0x02);
                p.bhs[2] = m.response;
                p.bhs[3] = m.status;
                p.set_u32(16, m.itt);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.set_u32(36, m.exp_data_sn);
                p.set_u32(44, m.residual);
                p.data = m.data;
            }
            Message::LoginResponse(m) => {
                p.bhs[1] = login_flags(m.transit, m.cont, m.csg, m.nsg);
                p.bhs[8..14].copy_from_slice(&m.isid);
                p.set_u16(14, m.tsih);
                p.set_u32(16, m.itt);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.bhs[36] = m.status_class;
                p.bhs[37] = m.status_detail;
                p.data = m.data;
            }
            Message::TextResponse(m) => {
                p.bhs[1] = bit(m.final_pdu, F) | bit(m.cont, C);
                p.set_lun(m.lun);
                p.set_u32(16, m.itt);
                p.set_u32(20, m.ttt);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.data = m.data;
            }
            Message::DataIn(m) => {
                p.bhs[1] = bit(m.final_pdu, F)
                    | bit(m.ack, 0x40)
                    | bit(m.overflow, 0x04)
                    | bit(m.underflow, 0x02)
                    | bit(m.status.is_some(), 0x01);
                p.bhs[3] = m.status.unwrap_or(0);
                p.set_lun(m.lun);
                p.set_u32(16, m.itt);
                p.set_u32(20, m.ttt);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.set_u32(36, m.data_sn);
                p.set_u32(40, m.offset);
                p.set_u32(44, m.residual);
                p.data = m.data;
            }
            Message::LogoutResponse(m) => {
                p.bhs[1] = F;
                p.bhs[2] = m.response;
                p.set_u32(16, m.itt);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.set_u16(40, m.time2wait);
                p.set_u16(42, m.time2retain);
            }
            Message::R2t(m) => {
                p.bhs[1] = F;
                p.set_lun(m.lun);
                p.set_u32(16, m.itt);
                p.set_u32(20, m.ttt);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.set_u32(36, m.r2t_sn);
                p.set_u32(40, m.offset);
                p.set_u32(44, m.desired_len);
            }
            Message::AsyncMessage(m) => {
                p.bhs[1] = F;
                p.set_lun(m.lun);
                p.set_u32(16, RESERVED_TAG);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.bhs[36] = m.event;
                p.bhs[37] = m.vcode;
                for (i, v) in m.params.iter().enumerate() {
                    p.set_u16(38 + 2 * i, *v);
                }
                p.data = m.data;
            }
            Message::Reject(m) => {
                p.bhs[1] = F;
                p.bhs[2] = m.reason;
                p.set_u32(16, RESERVED_TAG);
                status(&mut p, m.stat_sn, m.exp_cmd_sn, m.max_cmd_sn);
                p.set_u32(36, m.data_sn);
                p.data = m.data;
            }
        }
        p
    }

    /// The PDU's opcode.
    pub fn opcode(&self) -> u8 {
        match self {
            Message::NopOut(_) => opcode::NOP_OUT,
            Message::ScsiCommand(_) => opcode::SCSI_COMMAND,
            Message::LoginRequest(_) => opcode::LOGIN_REQUEST,
            Message::TextRequest(_) => opcode::TEXT_REQUEST,
            Message::DataOut(_) => opcode::DATA_OUT,
            Message::LogoutRequest(_) => opcode::LOGOUT_REQUEST,
            Message::NopIn(_) => opcode::NOP_IN,
            Message::ScsiResponse(_) => opcode::SCSI_RESPONSE,
            Message::LoginResponse(_) => opcode::LOGIN_RESPONSE,
            Message::TextResponse(_) => opcode::TEXT_RESPONSE,
            Message::DataIn(_) => opcode::DATA_IN,
            Message::LogoutResponse(_) => opcode::LOGOUT_RESPONSE,
            Message::R2t(_) => opcode::R2T,
            Message::AsyncMessage(_) => opcode::ASYNC_MESSAGE,
            Message::Reject(_) => opcode::REJECT,
        }
    }

    /// The StatSN this target PDU acknowledges, if it carries one that
    /// advances the connection's StatSN: every status-bearing response,
    /// but not R2T, Data-In without status, or a target ping.
    pub fn stat_sn(&self) -> Option<u32> {
        match self {
            Message::NopIn(m) if m.itt != RESERVED_TAG => Some(m.stat_sn),
            Message::ScsiResponse(m) => Some(m.stat_sn),
            Message::LoginResponse(m) => Some(m.stat_sn),
            Message::TextResponse(m) => Some(m.stat_sn),
            Message::DataIn(m) if m.status.is_some() => Some(m.stat_sn),
            Message::LogoutResponse(m) => Some(m.stat_sn),
            Message::AsyncMessage(m) => Some(m.stat_sn),
            Message::Reject(m) => Some(m.stat_sn),
            _ => None,
        }
    }

    /// ExpCmdSN and MaxCmdSN, the command window, if this is a target PDU.
    pub fn cmd_window(&self) -> Option<(u32, u32)> {
        match self {
            Message::NopIn(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            Message::ScsiResponse(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            Message::LoginResponse(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            Message::TextResponse(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            Message::DataIn(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            Message::LogoutResponse(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            Message::R2t(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            Message::AsyncMessage(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            Message::Reject(m) => Some((m.exp_cmd_sn, m.max_cmd_sn)),
            _ => None,
        }
    }
}

/// The 8-byte LUN field for logical unit `lun`: peripheral addressing below
/// 256, flat space addressing up to 16383 (SAM-5 §4.7).
pub fn lun_field(lun: u16) -> [u8; 8] {
    let mut f = [0; 8];
    if lun < 256 {
        f[1] = lun as u8;
    } else {
        f[0] = 0x40 | (lun >> 8) as u8 & 0x3f;
        f[1] = lun as u8;
    }
    f
}

/// `a < b` in serial number arithmetic (RFC 1982), as CmdSN and StatSN use.
pub fn sn_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 1 << 31
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn round_trip(m: Message) {
        let bytes = m.clone().encode().to_bytes();
        assert_eq!(bytes.len() % 4, 0);
        let mut r = PduReader::new(1 << 20);
        // Byte by byte, to exercise reassembly.
        for (i, b) in bytes.iter().enumerate() {
            assert!(r.next_pdu().unwrap().is_none(), "complete after {i} bytes");
            r.push(&[*b]);
        }
        let pdu = r.next_pdu().unwrap().unwrap();
        assert_eq!(r.buffered(), 0);
        assert_eq!(Message::decode(pdu).unwrap(), m);
    }

    #[test]
    fn every_message_round_trips() {
        let lun = lun_field(3);
        round_trip(Message::NopOut(NopOut {
            immediate: true,
            lun,
            itt: RESERVED_TAG,
            ttt: 9,
            cmd_sn: 1,
            exp_stat_sn: 2,
            data: vec![1, 2, 3],
        }));
        round_trip(Message::ScsiCommand(ScsiCommand {
            final_pdu: true,
            read: true,
            write: false,
            attr: 1,
            lun,
            itt: 7,
            expected_len: 4096,
            cmd_sn: 10,
            exp_stat_sn: 11,
            cdb: [0x28, 0, 0, 0, 0, 1, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0],
            data: vec![],
        }));
        round_trip(Message::LoginRequest(LoginRequest {
            transit: true,
            cont: false,
            csg: stage::OPERATIONAL,
            nsg: stage::FULL_FEATURE,
            isid: [0x80, 1, 2, 3, 4, 5],
            tsih: 0,
            itt: 1,
            cid: 0,
            cmd_sn: 1,
            exp_stat_sn: 0,
            data: b"a=b\0".to_vec(),
        }));
        round_trip(Message::TextRequest(TextRequest {
            immediate: false,
            final_pdu: true,
            cont: false,
            lun: [0; 8],
            itt: 2,
            ttt: RESERVED_TAG,
            cmd_sn: 3,
            exp_stat_sn: 4,
            data: b"SendTargets=All\0".to_vec(),
        }));
        round_trip(Message::DataOut(DataOut {
            final_pdu: false,
            lun,
            itt: 5,
            ttt: 6,
            exp_stat_sn: 7,
            data_sn: 8,
            offset: 512,
            data: vec![0xaa; 5],
        }));
        round_trip(Message::LogoutRequest(LogoutRequest { reason: 0, itt: 9, cid: 0, cmd_sn: 3, exp_stat_sn: 9 }));
        round_trip(Message::NopIn(NopIn {
            lun,
            itt: RESERVED_TAG,
            ttt: 0x55,
            stat_sn: 1,
            exp_cmd_sn: 2,
            max_cmd_sn: 3,
            data: vec![],
        }));
        round_trip(Message::ScsiResponse(ScsiResponse {
            overflow: false,
            underflow: true,
            response: 0,
            status: 2,
            itt: 4,
            stat_sn: 5,
            exp_cmd_sn: 6,
            max_cmd_sn: 7,
            exp_data_sn: 8,
            residual: 100,
            data: vec![0, 2, 0x70, 0],
        }));
        round_trip(Message::LoginResponse(LoginResponse {
            transit: true,
            cont: true,
            csg: 0,
            nsg: 1,
            isid: [1; 6],
            tsih: 0x1234,
            itt: 1,
            stat_sn: 1,
            exp_cmd_sn: 2,
            max_cmd_sn: 3,
            status_class: 2,
            status_detail: 3,
            data: vec![],
        }));
        round_trip(Message::TextResponse(TextResponse {
            final_pdu: false,
            cont: true,
            lun: [0; 8],
            itt: 1,
            ttt: 2,
            stat_sn: 3,
            exp_cmd_sn: 4,
            max_cmd_sn: 5,
            data: b"TargetName=x\0".to_vec(),
        }));
        round_trip(Message::DataIn(DataIn {
            final_pdu: true,
            ack: false,
            overflow: false,
            underflow: false,
            status: Some(0),
            lun,
            itt: 1,
            ttt: RESERVED_TAG,
            stat_sn: 2,
            exp_cmd_sn: 3,
            max_cmd_sn: 4,
            data_sn: 5,
            offset: 6,
            residual: 0,
            data: vec![9; 7],
        }));
        round_trip(Message::LogoutResponse(LogoutResponse {
            response: 0,
            itt: 1,
            stat_sn: 2,
            exp_cmd_sn: 3,
            max_cmd_sn: 4,
            time2wait: 2,
            time2retain: 0,
        }));
        round_trip(Message::R2t(R2t {
            lun,
            itt: 1,
            ttt: 2,
            stat_sn: 3,
            exp_cmd_sn: 4,
            max_cmd_sn: 5,
            r2t_sn: 0,
            offset: 8192,
            desired_len: 4096,
        }));
        round_trip(Message::AsyncMessage(AsyncMessage {
            lun,
            stat_sn: 1,
            exp_cmd_sn: 2,
            max_cmd_sn: 3,
            event: 1,
            vcode: 0,
            params: [0, 2, 20],
            data: vec![],
        }));
        round_trip(Message::Reject(Reject {
            reason: 4,
            stat_sn: 1,
            exp_cmd_sn: 2,
            max_cmd_sn: 3,
            data_sn: 0,
            data: vec![0; 48],
        }));
    }

    #[test]
    fn wire_layout() {
        let m = Message::LoginRequest(LoginRequest {
            transit: true,
            csg: stage::SECURITY,
            nsg: stage::OPERATIONAL,
            isid: [0x80, 0, 0, 0, 0, 1],
            itt: 0x0102_0304,
            cmd_sn: 5,
            data: b"AuthMethod=None\0".to_vec(),
            ..Default::default()
        });
        let b = m.encode().to_bytes();
        assert_eq!(&b[..4], &[0x43, 0x81, 0, 0]);
        assert_eq!(&b[4..8], &[0, 0, 0, 16], "TotalAHSLength and DataSegmentLength");
        assert_eq!(&b[8..14], &[0x80, 0, 0, 0, 0, 1]);
        assert_eq!(&b[16..20], &[1, 2, 3, 4]);
        assert_eq!(&b[24..28], &[0, 0, 0, 5]);
        assert_eq!(b.len(), 48 + 16);

        // A five-byte data segment is padded to eight.
        let d = Message::DataOut(DataOut { data: vec![1; 5], final_pdu: true, ..Default::default() });
        let b = d.encode().to_bytes();
        assert_eq!((b.len(), b[0], b[1], &b[53..56]), (56, 0x05, 0x80, &[0u8, 0, 0][..]));
    }

    #[test]
    fn reader_splits_a_stream_and_skips_ahs() {
        let mut stream = Message::NopIn(NopIn { itt: 1, data: vec![7; 3], ..Default::default() }).encode().to_bytes();
        // A second PDU with one word of AHS.
        let mut second = Message::R2t(R2t { itt: 2, ..Default::default() }).encode().to_bytes();
        second[4] = 1;
        second.splice(48..48, [0xee; 4]);
        stream.extend_from_slice(&second);
        let mut r = PduReader::new(16);
        r.push(&stream);
        let a = Message::decode(r.next_pdu().unwrap().unwrap()).unwrap();
        let b = Message::decode(r.next_pdu().unwrap().unwrap()).unwrap();
        assert!(matches!(a, Message::NopIn(NopIn { itt: 1, ref data, .. }) if data == &[7; 3]));
        assert!(matches!(b, Message::R2t(R2t { itt: 2, .. })));
        assert_eq!(r.next_pdu(), Ok(None));

        r.push(&Message::NopIn(NopIn { data: vec![0; 17], ..Default::default() }).encode().to_bytes());
        assert_eq!(r.next_pdu(), Err(PduError::TooLong(17)));
    }

    #[test]
    fn unknown_opcode_and_sequence_numbers() {
        assert_eq!(Message::decode(Pdu::new(0x1c)), Err(PduError::UnknownOpcode(0x1c)));
        assert!(sn_lt(1, 2) && !sn_lt(2, 1) && !sn_lt(5, 5));
        assert!(sn_lt(0xffff_fff0, 3), "wraps");
        assert_eq!(lun_field(0), [0; 8]);
        assert_eq!(lun_field(300), [0x41, 0x2c, 0, 0, 0, 0, 0, 0]);
        let ping = Message::NopIn(NopIn { itt: RESERVED_TAG, stat_sn: 9, ..Default::default() });
        assert_eq!(ping.stat_sn(), None, "a target ping does not advance StatSN");
        let data = Message::DataIn(DataIn { stat_sn: 9, ..Default::default() });
        assert_eq!(data.stat_sn(), None);
        assert_eq!(Message::DataIn(DataIn { stat_sn: 9, status: Some(0), ..Default::default() }).stat_sn(), Some(9));
    }
}
