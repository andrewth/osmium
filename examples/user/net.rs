//! A user program that uses sockets: it round-trips a message through a TCP
//! echo server, and reads a file from a TFTP server over UDP (QEMU's user
//! network serves both). System calls follow Linux numbering and conventions
//! for each architecture.
#![no_std]
#![no_main]

use core::fmt::Write;

#[cfg(target_arch = "riscv64")]
mod sys {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const CLOSE: u64 = 57;
    pub const SOCKET: u64 = 198;
    pub const CONNECT: u64 = 203;
    pub const GETSOCKNAME: u64 = 204;
    pub const SENDTO: u64 = 206;
    pub const RECVFROM: u64 = 207;
    pub const SETSOCKOPT: u64 = 208;
    pub const SHUTDOWN: u64 = 210;
    pub const READ: u64 = 63;
    pub const BIND: u64 = 200;
    pub const LISTEN: u64 = 201;
    pub const ACCEPT: u64 = 202;
    pub const SOCKETPAIR: u64 = 199;
    pub const SENDMSG: u64 = 211;
    pub const RECVMSG: u64 = 212;
    pub const EPOLL_CREATE1: u64 = 20;
    pub const EPOLL_CTL: u64 = 21;
    pub const EPOLL_PWAIT: u64 = 22;

    pub fn call(nr: u64, a: [u64; 6]) -> i64 {
        let ret: u64;
        // SAFETY: a7 = number, a0-a5 = arguments, a0 = result.
        unsafe {
            core::arch::asm!("ecall", in("a7") nr, inlateout("a0") a[0] => ret, in("a1") a[1], in("a2") a[2],
                in("a3") a[3], in("a4") a[4], in("a5") a[5], options(nostack))
        };
        ret as i64
    }

    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        core::arch::naked_asm!("j {}", sym super::main)
    }
}

#[cfg(target_arch = "aarch64")]
mod sys {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const CLOSE: u64 = 57;
    pub const SOCKET: u64 = 198;
    pub const CONNECT: u64 = 203;
    pub const GETSOCKNAME: u64 = 204;
    pub const SENDTO: u64 = 206;
    pub const RECVFROM: u64 = 207;
    pub const SETSOCKOPT: u64 = 208;
    pub const SHUTDOWN: u64 = 210;
    pub const READ: u64 = 63;
    pub const BIND: u64 = 200;
    pub const LISTEN: u64 = 201;
    pub const ACCEPT: u64 = 202;
    pub const SOCKETPAIR: u64 = 199;
    pub const SENDMSG: u64 = 211;
    pub const RECVMSG: u64 = 212;
    pub const EPOLL_CREATE1: u64 = 20;
    pub const EPOLL_CTL: u64 = 21;
    pub const EPOLL_PWAIT: u64 = 22;

    pub fn call(nr: u64, a: [u64; 6]) -> i64 {
        let ret: u64;
        // SAFETY: x8 = number, x0-x5 = arguments, x0 = result.
        unsafe {
            core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a[0] => ret, in("x1") a[1], in("x2") a[2],
                in("x3") a[3], in("x4") a[4], in("x5") a[5], options(nostack))
        };
        ret as i64
    }

    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        core::arch::naked_asm!("b {}", sym super::main)
    }
}

#[cfg(target_arch = "x86_64")]
mod sys {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const CLOSE: u64 = 3;
    pub const SOCKET: u64 = 41;
    pub const CONNECT: u64 = 42;
    pub const GETSOCKNAME: u64 = 51;
    pub const SENDTO: u64 = 44;
    pub const RECVFROM: u64 = 45;
    pub const SETSOCKOPT: u64 = 54;
    pub const SHUTDOWN: u64 = 48;
    pub const READ: u64 = 0;
    pub const BIND: u64 = 49;
    pub const LISTEN: u64 = 50;
    pub const ACCEPT: u64 = 43;
    pub const SOCKETPAIR: u64 = 53;
    pub const SENDMSG: u64 = 46;
    pub const RECVMSG: u64 = 47;
    pub const EPOLL_CREATE1: u64 = 291;
    pub const EPOLL_CTL: u64 = 233;
    pub const EPOLL_PWAIT: u64 = 281;

    pub fn call(nr: u64, a: [u64; 6]) -> i64 {
        let ret: u64;
        // SAFETY: rax = number, rdi/rsi/rdx/r10/r8/r9 = arguments; the CPU
        // clobbers rcx and r11.
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") nr => ret, in("rdi") a[0], in("rsi") a[1], in("rdx") a[2],
                in("r10") a[3], in("r8") a[4], in("r9") a[5], out("rcx") _, out("r11") _, options(nostack))
        };
        ret as i64
    }

    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        core::arch::naked_asm!("and rsp, -16", "call {}", sym super::main)
    }
}

/// Formats into a fixed buffer (there is no heap here).
struct Buf {
    bytes: [u8; 160],
    len: usize,
}

impl Write for Buf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Writes one formatted line to standard output.
macro_rules! say {
    ($($arg:tt)*) => {{
        let mut buf = Buf { bytes: [0; 160], len: 0 };
        let _ = write!(buf, $($arg)*);
        sys::call(sys::WRITE, [1, buf.bytes.as_ptr() as u64, buf.len as u64, 0, 0, 0]);
    }};
}

fn exit(code: u64) -> ! {
    sys::call(sys::EXIT, [code, 0, 0, 0, 0, 0]);
    loop {}
}

const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOL_SOCKET: u64 = 1;
const SO_RCVTIMEO: u64 = 20;
const AF_UNIX: u64 = 1;
const MSG_PEEK: u64 = 2;
const EPOLLIN: u32 = 1;
const EPOLL_CTL_ADD: u64 = 1;
/// `struct epoll_event` is packed on x86_64 only.
#[cfg(target_arch = "x86_64")]
const EPOLL_DATA: usize = 4;
#[cfg(not(target_arch = "x86_64"))]
const EPOLL_DATA: usize = 8;

/// A `struct sockaddr_in`.
fn sockaddr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&ip);
    a
}

fn socket(ty: u64) -> i64 {
    sys::call(sys::SOCKET, [AF_INET, ty, 0, 0, 0, 0])
}

fn recv_timeout(fd: u64, secs: u64) {
    let tv = [secs, 0];
    sys::call(sys::SETSOCKOPT, [fd, SOL_SOCKET, SO_RCVTIMEO, tv.as_ptr() as u64, 16, 0]);
}

/// A TCP echo round trip with the server at `ip:7`.
fn tcp_echo() {
    const MESSAGE: &[u8] = b"hello over sockets";
    let fd = socket(SOCK_STREAM);
    if fd < 0 {
        say!("net: socket failed: {fd}");
        return;
    }
    let fd = fd as u64;
    recv_timeout(fd, 5);
    let server = sockaddr([10, 0, 2, 100], 7);
    let r = sys::call(sys::CONNECT, [fd, server.as_ptr() as u64, 16, 0, 0, 0]);
    if r < 0 {
        say!("net: TCP connect failed: {r}");
        return;
    }
    let mut local = [0u8; 16];
    let mut len = 16u32;
    sys::call(sys::GETSOCKNAME, [fd, local.as_mut_ptr() as u64, &mut len as *mut u32 as u64, 0, 0, 0]);
    let sent = sys::call(sys::SENDTO, [fd, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64, 0, 0, 0]);
    let mut buf = [0u8; 64];
    let mut got = 0;
    while got < MESSAGE.len() {
        let n = sys::call(sys::READ, [fd, buf[got..].as_mut_ptr() as u64, (buf.len() - got) as u64, 0, 0, 0]);
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    let text = core::str::from_utf8(&buf[..got]).unwrap_or("?");
    say!(
        "net: TCP echo from 10.0.2.100:7 via {}.{}.{}.{}:{}: sent {sent}, got \"{text}\"",
        local[4],
        local[5],
        local[6],
        local[7],
        u16::from_be_bytes([local[2], local[3]])
    );
    // The server closes when we do, which ends our reads.
    sys::call(sys::SHUTDOWN, [fd, 1, 0, 0, 0, 0]);
    let eof = sys::call(sys::READ, [fd, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0]);
    say!("net: TCP read after the server closed: {eof}");
    sys::call(sys::CLOSE, [fd, 0, 0, 0, 0, 0]);
}

/// Reads `osmium.txt` from the TFTP server at 10.0.2.2:69: a read request
/// from an unbound socket, answered with DATA, which we ACK to its sender.
fn udp_tftp() {
    let fd = socket(SOCK_DGRAM);
    if fd < 0 {
        say!("net: UDP socket failed: {fd}");
        return;
    }
    let fd = fd as u64;
    recv_timeout(fd, 5);
    let server = sockaddr([10, 0, 2, 2], 69);
    let request = b"\0\x01osmium.txt\0octet\0";
    let r = sys::call(sys::SENDTO, [fd, request.as_ptr() as u64, request.len() as u64, 0, server.as_ptr() as u64, 16]);
    if r < 0 {
        say!("net: UDP sendto failed: {r}");
        return;
    }
    let mut buf = [0u8; 600];
    let mut from = [0u8; 16];
    let mut len = 16u32;
    let n = sys::call(
        sys::RECVFROM,
        [fd, buf.as_mut_ptr() as u64, buf.len() as u64, 0, from.as_mut_ptr() as u64, &mut len as *mut u32 as u64],
    );
    if n < 4 {
        say!("net: UDP recvfrom failed: {n}");
        return;
    }
    let n = n as usize;
    let port = u16::from_be_bytes([from[2], from[3]]);
    let text = core::str::from_utf8(&buf[4..n]).unwrap_or("?").trim_end();
    say!(
        "net: UDP TFTP from {}.{}.{}.{}:{port}: opcode {} block {}: \"{text}\"",
        from[4],
        from[5],
        from[6],
        from[7],
        buf[1],
        buf[3]
    );
    // ACK block 1 to whoever answered, so the server is done.
    let ack = [0, 4, buf[2], buf[3]];
    sys::call(sys::SENDTO, [fd, ack.as_ptr() as u64, 4, 0, from.as_ptr() as u64, 16]);
    sys::call(sys::CLOSE, [fd, 0, 0, 0, 0, 0]);
}

/// A `struct msghdr` over `iov` (an array of `(base, len)` pairs).
fn msghdr(iov: &[[u64; 2]]) -> [u64; 7] {
    [0, 0, iov.as_ptr() as u64, iov.len() as u64, 0, 0, 0]
}

/// A socket pair used with `sendmsg`, `recvmsg` and `epoll`.
fn pair_epoll() {
    let mut sv = [0i32; 2];
    let r = sys::call(sys::SOCKETPAIR, [AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64, 0, 0]);
    if r < 0 {
        say!("net: socketpair failed: {r}");
        return;
    }
    let (a, b) = (sv[0] as u64, sv[1] as u64);
    let ep = sys::call(sys::EPOLL_CREATE1, [0; 6]) as u64;
    let mut ev = [0u8; 16];
    ev[..4].copy_from_slice(&EPOLLIN.to_ne_bytes());
    ev[EPOLL_DATA..EPOLL_DATA + 8].copy_from_slice(&42u64.to_ne_bytes());
    sys::call(sys::EPOLL_CTL, [ep, EPOLL_CTL_ADD, b, ev.as_ptr() as u64, 0, 0]);
    let mut out = [0u8; 16];
    let idle = sys::call(sys::EPOLL_PWAIT, [ep, out.as_mut_ptr() as u64, 1, 0, 0, 0]);
    let out_iov = [[b"ping".as_ptr() as u64, 4], [b"-pong".as_ptr() as u64, 5]];
    let out_msg = msghdr(&out_iov);
    let sent = sys::call(sys::SENDMSG, [a, out_msg.as_ptr() as u64, 0, 0, 0, 0]);
    // Waits up to a second; the data is already there.
    let ready = sys::call(sys::EPOLL_PWAIT, [ep, out.as_mut_ptr() as u64, 1, 1000, 0, 0]);
    let data = u64::from_ne_bytes(out[EPOLL_DATA..EPOLL_DATA + 8].try_into().unwrap_or([0; 8]));
    let (mut first, mut rest) = ([0u8; 3], [0u8; 16]);
    let in_iov = [[first.as_mut_ptr() as u64, 3], [rest.as_mut_ptr() as u64, 16]];
    let in_msg = msghdr(&in_iov);
    let got = sys::call(sys::RECVMSG, [b, in_msg.as_ptr() as u64, 0, 0, 0, 0]);
    let text = core::str::from_utf8(&rest[..(got.max(3) - 3) as usize]).unwrap_or("?");
    say!(
        "net: socketpair: epoll idle {idle}, ready {ready} with data {data}; sendmsg {sent}, recvmsg {got}: \"{}{text}\"",
        core::str::from_utf8(&first).unwrap_or("?")
    );
    for fd in [a, b, ep] {
        sys::call(sys::CLOSE, [fd, 0, 0, 0, 0, 0]);
    }
}

/// A named `AF_UNIX` socket in `/tmp`: a client connects by path, the server
/// accepts, and a descriptor travels between them as `SCM_RIGHTS` ancillary
/// data.
fn unix_fd_passing() {
    let mut addr = [0u8; 2 + 20];
    addr[..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    addr[2..2 + 16].copy_from_slice(b"/tmp/osmium.sock");
    let (server, client) = (
        sys::call(sys::SOCKET, [AF_UNIX, SOCK_STREAM, 0, 0, 0, 0]),
        sys::call(sys::SOCKET, [AF_UNIX, SOCK_STREAM, 0, 0, 0, 0]),
    );
    let bound = sys::call(sys::BIND, [server as u64, addr.as_ptr() as u64, 2 + 16 + 1, 0, 0, 0]);
    let listening = sys::call(sys::LISTEN, [server as u64, 1, 0, 0, 0, 0]);
    let connected = sys::call(sys::CONNECT, [client as u64, addr.as_ptr() as u64, 2 + 16 + 1, 0, 0, 0]);
    let conn = sys::call(sys::ACCEPT, [server as u64, 0, 0, 0, 0, 0]);
    if conn < 0 || client < 0 {
        say!("net: unix: bind {bound}, listen {listening}, connect {connected}, accept {conn}");
        return;
    }
    let mut sv = [0i32; 2];
    sys::call(sys::SOCKETPAIR, [AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64, 0, 0]);

    // One byte and one descriptor: cmsg_len 20, SOL_SOCKET, SCM_RIGHTS.
    let ctl = [20u64, 1 | (1 << 32), sv[0] as u32 as u64];
    let out_iov = [[b"F".as_ptr() as u64, 1]];
    let out_msg = [0, 0, out_iov.as_ptr() as u64, 1, ctl.as_ptr() as u64, 24, 0];
    let sent = sys::call(sys::SENDMSG, [client as u64, out_msg.as_ptr() as u64, 0, 0, 0, 0]);
    // The sender's copy goes away; the message holds the file.
    sys::call(sys::CLOSE, [sv[0] as u64, 0, 0, 0, 0, 0]);

    let mut byte = [0u8; 1];
    let mut got_ctl = [0u64; 4];
    let in_iov = [[byte.as_mut_ptr() as u64, 1]];
    let in_msg = [0, 0, in_iov.as_ptr() as u64, 1, got_ctl.as_mut_ptr() as u64, 32, 0];
    let got = sys::call(sys::RECVMSG, [conn as u64, in_msg.as_ptr() as u64, 0, 0, 0, 0]);
    let received = got_ctl[2] as u32 as u64;
    sys::call(sys::WRITE, [sv[1] as u64, b"via-fd".as_ptr() as u64, 6, 0, 0, 0]);
    let mut text = [0u8; 8];
    let n = sys::call(sys::READ, [received, text.as_mut_ptr() as u64, 8, 0, 0, 0]);
    let text = core::str::from_utf8(&text[..n.clamp(0, 8) as usize]).unwrap_or("?");
    say!(
        "net: unix: bind {bound}, listen {listening}, connect {connected}; sendmsg {sent}, recvmsg {got}: descriptor read \"{text}\""
    );
    for fd in [server as u64, client as u64, conn as u64, sv[1] as u64, received] {
        sys::call(sys::CLOSE, [fd, 0, 0, 0, 0, 0]);
    }
}

/// UDP to the loopback address stays inside the kernel's stack; `MSG_PEEK`
/// leaves the datagram to be read again.
fn udp_loopback() {
    let (rx, tx) = (socket(SOCK_DGRAM), socket(SOCK_DGRAM));
    if rx < 0 || tx < 0 {
        say!("net: loopback sockets failed: {rx} {tx}");
        return;
    }
    let (rx, tx) = (rx as u64, tx as u64);
    let to = sockaddr([127, 0, 0, 1], 5000);
    let r = sys::call(sys::BIND, [rx, to.as_ptr() as u64, 16, 0, 0, 0]);
    let sent = sys::call(sys::SENDTO, [tx, b"local".as_ptr() as u64, 5, 0, to.as_ptr() as u64, 16]);
    let mut buf = [0u8; 16];
    let mut from = [0u8; 16];
    let mut len = 16u32;
    let name = [from.as_mut_ptr() as u64, &mut len as *mut u32 as u64];
    let peeked = sys::call(sys::RECVFROM, [rx, buf.as_mut_ptr() as u64, 16, MSG_PEEK, name[0], name[1]]);
    let got = sys::call(sys::RECVFROM, [rx, buf.as_mut_ptr() as u64, 16, 0, 0, 0]);
    let text = core::str::from_utf8(&buf[..got.max(0) as usize]).unwrap_or("?");
    say!(
        "net: UDP loopback: bind {r}, sent {sent}, peeked {peeked} then read {got} from {}.{}.{}.{}:{}: \"{text}\"",
        from[4],
        from[5],
        from[6],
        from[7],
        u16::from_be_bytes([from[2], from[3]])
    );
    sys::call(sys::CLOSE, [rx, 0, 0, 0, 0, 0]);
    sys::call(sys::CLOSE, [tx, 0, 0, 0, 0, 0]);
}

extern "C" fn main() -> ! {
    tcp_echo();
    udp_tftp();
    pair_epoll();
    unix_fd_passing();
    udp_loopback();
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}
