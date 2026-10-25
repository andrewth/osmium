//! Socket errors.

use core::fmt;

/// Why a socket operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Nothing to receive, or no room to send; try again after a poll.
    WouldBlock,
    /// The datagram is larger than the socket can send.
    TooLarge,
    /// The socket is not in a state that allows the operation (not bound,
    /// not connected, or already closed for sending).
    InvalidState,
    /// The address is unusable: port 0, or an unspecified remote address.
    InvalidAddress,
    /// The peer answered a connection request with a reset.
    ConnectionRefused,
    /// The peer reset the connection.
    ConnectionReset,
    /// The peer stopped acknowledging data.
    TimedOut,
    /// The address and port are already bound by another socket, and the
    /// `SO_REUSEADDR` / `SO_REUSEPORT` rules do not let both share them.
    AddressInUse,
    /// There was no memory to queue the data or add the socket.
    OutOfMemory,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::WouldBlock => "operation would block",
            Error::TooLarge => "datagram too large",
            Error::InvalidState => "invalid socket state",
            Error::InvalidAddress => "invalid address",
            Error::ConnectionRefused => "connection refused",
            Error::ConnectionReset => "connection reset",
            Error::TimedOut => "connection timed out",
            Error::AddressInUse => "address already in use",
            Error::OutOfMemory => "out of memory",
        })
    }
}

impl core::error::Error for Error {}
