//! Initiator errors.

use core::fmt;

use osmium_hal::block::BlockError;

use crate::scsi::{ASC_LBA_OUT_OF_RANGE, Sense, sense_key};

/// Why an iSCSI operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IscsiError {
    /// The TCP connection failed (refused, reset or timed out).
    Net(osmium_net::Error),
    /// The target closed the connection.
    Closed,
    /// The target did not answer in time.
    TimedOut,
    /// The target sent something the protocol does not allow. The session
    /// is dropped.
    Protocol(&'static str),
    /// The target refused the login (RFC 7143 §11.13.5). Class 1 is a
    /// redirection, which is followed unless it names no usable address or
    /// the target keeps moving us; 2 an initiator error (detail 3: no such
    /// target), 3 a target error.
    Login {
        /// Status-Class.
        class: u8,
        /// Status-Detail.
        detail: u8,
    },
    /// Login keys could not be agreed, e.g. the target insists on CHAP.
    Negotiation(&'static str),
    /// The target rejected a PDU, with this reason code.
    Reject(u8),
    /// The target could not carry out a command or logout: the iSCSI
    /// response code.
    Response(u8),
    /// The command completed with a SCSI status other than GOOD.
    Scsi {
        /// The status, one of [`crate::scsi::status`].
        status: u8,
        /// The sense data that came with a CHECK CONDITION.
        sense: Option<Sense>,
    },
    /// A PDU from the target failed its CRC32C header or data digest. The
    /// session is dropped.
    Digest,
    /// The session has logged out or failed.
    NoSession,
    /// The session is in use (borrowed) by another operation.
    Busy,
}

impl IscsiError {
    /// The sense key of a CHECK CONDITION.
    pub fn sense_key(&self) -> Option<u8> {
        match self {
            IscsiError::Scsi { sense: Some(s), .. } => Some(s.key),
            _ => None,
        }
    }
}

impl fmt::Display for IscsiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IscsiError::Net(e) => write!(f, "iSCSI connection: {e}"),
            IscsiError::Closed => f.write_str("iSCSI target closed the connection"),
            IscsiError::TimedOut => f.write_str("iSCSI target timed out"),
            IscsiError::Protocol(what) => write!(f, "iSCSI protocol error: {what}"),
            IscsiError::Login { class, detail } => write!(f, "iSCSI login refused: status {class:#04x}/{detail:#04x}"),
            IscsiError::Negotiation(what) => write!(f, "iSCSI negotiation failed: {what}"),
            IscsiError::Reject(reason) => write!(f, "iSCSI target rejected a PDU: reason {reason:#04x}"),
            IscsiError::Response(r) => write!(f, "iSCSI target failure: response {r:#04x}"),
            IscsiError::Scsi { status, sense: Some(s) } => {
                write!(f, "SCSI status {status:#04x}, sense key {:#x} ASC {:#04x} ASCQ {:#04x}", s.key, s.asc, s.ascq)
            }
            IscsiError::Scsi { status, sense: None } => write!(f, "SCSI status {status:#04x}"),
            IscsiError::Digest => f.write_str("iSCSI digest mismatch"),
            IscsiError::NoSession => f.write_str("no iSCSI session"),
            IscsiError::Busy => f.write_str("iSCSI session in use"),
        }
    }
}

impl core::error::Error for IscsiError {}

impl From<osmium_net::Error> for IscsiError {
    fn from(e: osmium_net::Error) -> Self {
        IscsiError::Net(e)
    }
}

impl From<IscsiError> for BlockError {
    /// DATA PROTECT is [`BlockError::ReadOnly`], an LBA out of range
    /// [`BlockError::OutOfRange`], anything else [`BlockError::Io`].
    fn from(e: IscsiError) -> Self {
        match e {
            IscsiError::Scsi { sense: Some(s), .. } if s.key == sense_key::DATA_PROTECT => BlockError::ReadOnly,
            IscsiError::Scsi { sense: Some(s), .. }
                if s.key == sense_key::ILLEGAL_REQUEST && s.asc == ASC_LBA_OUT_OF_RANGE =>
            {
                BlockError::OutOfRange
            }
            _ => BlockError::Io,
        }
    }
}
