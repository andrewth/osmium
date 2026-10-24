//! Error numbers.

use core::fmt;

/// A Linux error number (positive, as in `errno`; system calls return it
/// negated).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Errno(pub i32);

macro_rules! errnos {
    ($($name:ident = $val:literal, $doc:literal;)*) => {
        impl Errno {
            $(#[doc = $doc] pub const $name: Errno = Errno($val);)*

            /// The constant's name, such as `"ENOENT"`, if it is one of these.
            pub const fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($val => Some(stringify!($name)),)*
                    _ => None,
                }
            }
        }
    };
}

errnos! {
    EPERM = 1, "Operation not permitted.";
    ENOENT = 2, "No such file or directory.";
    EINTR = 4, "Interrupted system call.";
    EIO = 5, "I/O error.";
    ENXIO = 6, "No such device or address.";
    E2BIG = 7, "Argument list too long.";
    ENOEXEC = 8, "Exec format error.";
    EBADF = 9, "Bad file descriptor.";
    ECHILD = 10, "No child processes.";
    EAGAIN = 11, "Try again.";
    ENOMEM = 12, "Out of memory.";
    EACCES = 13, "Permission denied.";
    EFAULT = 14, "Bad address.";
    EBUSY = 16, "Device or resource busy.";
    EEXIST = 17, "File exists.";
    EXDEV = 18, "Cross-device link.";
    ENODEV = 19, "No such device.";
    ENOTDIR = 20, "Not a directory.";
    EISDIR = 21, "Is a directory.";
    EINVAL = 22, "Invalid argument.";
    ENFILE = 23, "File table overflow.";
    EMFILE = 24, "Too many open files.";
    ENOTTY = 25, "Not a typewriter.";
    EFBIG = 27, "File too large.";
    ENOSPC = 28, "No space left on device.";
    ESPIPE = 29, "Illegal seek.";
    EROFS = 30, "Read-only file system.";
    EMLINK = 31, "Too many links.";
    EPIPE = 32, "Broken pipe.";
    ERANGE = 34, "Result too large.";
    ENAMETOOLONG = 36, "File name too long.";
    ENOSYS = 38, "Function not implemented.";
    ENOTEMPTY = 39, "Directory not empty.";
    ELOOP = 40, "Too many symbolic links encountered.";
    EOVERFLOW = 75, "Value too large for defined data type.";
    EOPNOTSUPP = 95, "Operation not supported.";
    ENOTSOCK = 88, "Socket operation on non-socket.";
    EDESTADDRREQ = 89, "Destination address required.";
    EMSGSIZE = 90, "Message too long.";
    EPROTOTYPE = 91, "Protocol wrong type for socket.";
    ENOPROTOOPT = 92, "Protocol not available.";
    EPROTONOSUPPORT = 93, "Protocol not supported.";
    EAFNOSUPPORT = 97, "Address family not supported by protocol.";
    EADDRINUSE = 98, "Address already in use.";
    EADDRNOTAVAIL = 99, "Cannot assign requested address.";
    ENETUNREACH = 101, "Network is unreachable.";
    ECONNRESET = 104, "Connection reset by peer.";
    EISCONN = 106, "Transport endpoint is already connected.";
    ENOTCONN = 107, "Transport endpoint is not connected.";
    ETIMEDOUT = 110, "Connection timed out.";
    ECONNREFUSED = 111, "Connection refused.";
    EALREADY = 114, "Operation already in progress.";
    EINPROGRESS = 115, "Operation now in progress.";
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "Errno({})", self.0),
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for Errno {}

impl From<osmium_sync::fallible::OutOfMemory> for Errno {
    fn from(_: osmium_sync::fallible::OutOfMemory) -> Self {
        Errno::ENOMEM
    }
}
