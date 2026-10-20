//! TCP connections (RFC 9293), with RFC 6298 retransmission timing.
//!
//! A listening socket takes a single connection: on a SYN it turns into
//! that connection. A server that wants several at once listens with
//! several sockets on the same port.
//!
//! Data that arrives past a gap is held, within the receive window, until
//! the gap is filled; each out-of-order segment is acknowledged at once so
//! that the sender sees duplicate ACKs. Window scaling (RFC 7323) and
//! selective acknowledgments (RFC 2018) are negotiated in the handshake.
//!
//! The sender is congestion controlled (RFC 5681): slow start from a ten
//! segment initial window, congestion avoidance, and fast retransmit and
//! recovery per NewReno (RFC 6582), or per RFC 6675 when the peer supports
//! SACK, which retransmits exactly the holes its blocks report. A timeout
//! drops the window to one segment and resends from the oldest
//! unacknowledged byte.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use super::{Cx, Packet, binds};
use crate::wire::{MAX_SACK_BLOCKS, PROTO_TCP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TcpHeader};
use crate::{Error, Instant};

/// Retransmission timeout before the first round-trip measurement.
const INITIAL_RTO: Duration = Duration::from_secs(1);
const MIN_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_secs(60);
/// Retransmissions of one segment before the connection is dropped.
const MAX_RETRIES: u8 = 8;
/// How long a closed connection lingers in TIME-WAIT (2 MSL). Shorter than
/// the RFC's four minutes, as most stacks are.
const TIME_WAIT: Duration = Duration::from_secs(10);
/// MSS assumed when the peer sends none.
const DEFAULT_MSS: usize = 536;
/// The least MSS taken from a peer: a smaller one, even 0, would only make
/// the connection crawl or stall.
const MIN_MSS: usize = 64;
/// Segments sent per poll.
const MAX_BURST: usize = 16;
/// Out-of-order ranges held, and SACK ranges remembered; more are dropped.
const MAX_RANGES: usize = 64;
/// Bytes the timestamps option takes from each segment, with its padding.
const TS_OPTION_LEN: usize = 12;
/// How long `TS.Recent` is trusted without an update (RFC 7323 5.5: the
/// clock may have wrapped; 24 days is the RFC's figure).
const TS_RECENT_LIFE: Duration = Duration::from_secs(24 * 24 * 3600);
/// The largest round trip taken from a timestamp echo; more is a bogus
/// echo.
const MAX_TS_RTT: u32 = 60_000;
/// The largest window scale shift (RFC 7323).
const MAX_SHIFT: u8 = 14;
/// The largest receive buffer: what the largest shift can advertise.
const MAX_RX_CAP: usize = 65535 << MAX_SHIFT;

/// The connection states of RFC 9293.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// `a < b` in sequence-number space.
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// `a <= b` in sequence-number space.
fn before_eq(a: u32, b: u32) -> bool {
    !before(b, a)
}

/// The reset that answers `seg` (which carried `len` payload bytes) when no
/// connection takes it, or `None` if `seg` is itself a reset.
pub(crate) fn reset_for(seg: &TcpHeader, len: usize) -> Option<TcpHeader> {
    if seg.has(TCP_RST) {
        return None;
    }
    let mut rst = TcpHeader { src_port: seg.dst_port, dst_port: seg.src_port, ..TcpHeader::default() };
    if seg.has(TCP_ACK) {
        rst.seq = seg.ack;
        rst.flags = TCP_RST;
    } else {
        let seg_len = len as u32 + u32::from(seg.has(TCP_SYN)) + u32::from(seg.has(TCP_FIN));
        rst.ack = seg.seq.wrapping_add(seg_len);
        rst.flags = TCP_RST | TCP_ACK;
    }
    Some(rst)
}

/// One TCP connection, or a listener waiting for one.
pub struct TcpSocket {
    state: State,
    /// Our end. The address is unspecified on a listener and on a
    /// connection that has not sent its SYN yet; the port is 0 until an
    /// ephemeral one is chosen.
    local: SocketAddr,
    remote: SocketAddr,
    /// The SYN is still to be built: [`connect`](Self::connect) was called
    /// but the interface has not assigned the address, port and ISS yet.
    fresh: bool,
    /// The connection came from [`listen`](Self::listen); a reset in
    /// SYN-RECEIVED returns it to LISTEN.
    passive: bool,

    rx: VecDeque<u8>,
    rx_cap: usize,
    /// Data held past a gap, as sorted, disjoint `(sequence number, bytes)`
    /// ranges inside the receive window.
    ooo: Vec<(u32, Vec<u8>)>,
    /// Start of the range the latest out-of-order segment landed in, which
    /// SACK reports first.
    ooo_recent: Option<u32>,
    /// Sequence number of a FIN that arrived ahead of missing data.
    ooo_fin: Option<u32>,
    /// The window scale shift we offer, from the buffer size.
    ws_offer: u8,
    /// Window scaling was agreed: the peer's shift, ours (`ws_offer`).
    ws_active: bool,
    snd_shift: u8,
    rcv_shift: u8,
    /// SACK was agreed.
    sack_ok: bool,
    /// Ranges above `snd_una` the peer reports having, sorted and disjoint.
    scoreboard: Vec<(u32, u32)>,
    /// Holes below this are retransmitted already in this recovery (SACK).
    rexmit_next: u32,
    /// A single segment to retransmit from this sequence number.
    rexmit_one: Option<u32>,
    cwnd: u32,
    ssthresh: u32,
    /// `snd_max` when the last loss was detected: recovery ends when it is
    /// acknowledged, and no new recovery starts before.
    recover: u32,
    in_recovery: bool,
    /// Bytes acknowledged toward the next congestion avoidance increase.
    ca_acc: u32,
    /// The peer's FIN has been received; reads past the data return 0.
    rx_fin: bool,
    /// Bytes from `tx_seq` on: sent but unacknowledged, then unsent.
    tx: VecDeque<u8>,
    tx_cap: usize,
    /// The user closed the sending side; a FIN follows the last byte of `tx`.
    fin_queued: bool,

    iss: u32,
    tx_seq: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number sent, which `snd_nxt` falls back from on a
    /// retransmission.
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    snd_mss: usize,
    rcv_nxt: u32,
    /// The window in the last segment sent.
    adv_wnd: u32,

    ack_pending: bool,
    /// A reset to send, from [`abort`](Self::abort).
    rst_pending: Option<TcpHeader>,

    rto: Duration,
    /// Smoothed round-trip time and its variance, once measured.
    srtt: Option<(Duration, Duration)>,
    /// The segment being timed: the sequence number whose acknowledgment
    /// ends the measurement, and when it was sent.
    rtt_sample: Option<(u32, Instant)>,
    /// Retransmission, zero-window probe or TIME-WAIT deadline.
    timer: Option<Instant>,
    retries: u8,
    /// Duplicate ACKs in a row.
    dup_acks: u8,
    /// The timer fired with a zero window: send one byte past it.
    probe: bool,
    error: Option<Error>,
    /// Offer SACK in the handshake; off only in tests.
    sack_enabled: bool,
    /// Offer timestamps in the handshake; off only in tests.
    ts_enabled: bool,
    /// Timestamps (RFC 7323) were agreed.
    ts_ok: bool,
    /// Added to the clock to make the TSval we send, so that it does not
    /// reveal our uptime.
    ts_offset: u32,
    /// The latest in-order TSval from the peer, which we echo (`TS.Recent`).
    ts_recent: u32,
    /// When `ts_recent` was last updated, to retire it after 24 days.
    ts_recent_at: Instant,
    /// The acknowledgment number of the last segment sent (`Last.ACK.sent`).
    last_ack_sent: u32,
    /// The time of the segment being processed or built.
    clock: Instant,
}

impl TcpSocket {
    /// A closed socket with `rx_cap` and `tx_cap` bytes of buffering. The
    /// receive buffer bounds the advertised window; one over 65535 bytes
    /// needs a peer that supports window scaling to be used in full, and at
    /// most 1 GiB of it is.
    pub fn new(rx_cap: usize, tx_cap: usize) -> Self {
        Self {
            state: State::Closed,
            local: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            remote: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            fresh: false,
            passive: false,
            rx: VecDeque::new(),
            rx_cap: rx_cap.min(MAX_RX_CAP),
            ooo: Vec::new(),
            ooo_recent: None,
            ooo_fin: None,
            ws_offer: (0..=MAX_SHIFT).find(|s| rx_cap.min(MAX_RX_CAP) >> s <= 65535).unwrap_or(MAX_SHIFT),
            ws_active: false,
            snd_shift: 0,
            rcv_shift: 0,
            sack_ok: false,
            scoreboard: Vec::new(),
            rexmit_next: 0,
            rexmit_one: None,
            cwnd: 0,
            ssthresh: u32::MAX,
            recover: 0,
            in_recovery: false,
            ca_acc: 0,
            rx_fin: false,
            tx: VecDeque::new(),
            tx_cap,
            fin_queued: false,
            iss: 0,
            tx_seq: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_max: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_mss: DEFAULT_MSS,
            rcv_nxt: 0,
            adv_wnd: 0,
            ack_pending: false,
            rst_pending: None,
            rto: INITIAL_RTO,
            srtt: None,
            rtt_sample: None,
            timer: None,
            retries: 0,
            dup_acks: 0,
            probe: false,
            error: None,
            sack_enabled: true,
            ts_enabled: true,
            ts_ok: false,
            ts_offset: 0,
            ts_recent: 0,
            ts_recent_at: Instant::ZERO,
            last_ack_sent: 0,
            clock: Instant::ZERO,
        }
    }

    fn reset(&mut self) {
        let (sack_enabled, ts_enabled) = (self.sack_enabled, self.ts_enabled);
        *self = Self::new(self.rx_cap, self.tx_cap);
        self.sack_enabled = sack_enabled;
        self.ts_enabled = ts_enabled;
    }

    /// Returns a connection that came from [`listen`](Self::listen) to
    /// listening on its port.
    fn relisten(&mut self) {
        let port = self.local.port();
        let v6 = self.local.is_ipv6();
        self.reset();
        let any = if v6 { Ipv6Addr::UNSPECIFIED.into() } else { Ipv4Addr::UNSPECIFIED.into() };
        self.local = SocketAddr::new(any, port);
        self.state = State::Listen;
        self.passive = true;
    }

    /// The MSS to send with, from the peer's option and our own.
    fn peer_mss(seg: &TcpHeader, ours: u16) -> usize {
        usize::from(seg.mss.unwrap_or(DEFAULT_MSS as u16)).max(MIN_MSS).min(usize::from(ours))
    }

    /// Waits for a connection to `port` on any IPv4 address of the
    /// interface. [`listen_on`](Self::listen_on) with `[::]` waits on IPv6.
    pub fn listen(&mut self, port: u16) -> Result<(), Error> {
        self.listen_on(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))
    }

    /// Waits for a connection to `local`: an unspecified address means any
    /// address of the interface of that family (IPv4 or IPv6), a specific
    /// one only that address.
    pub fn listen_on(&mut self, local: impl Into<SocketAddr>) -> Result<(), Error> {
        let local = local.into();
        if local.port() == 0 {
            return Err(Error::InvalidAddress);
        }
        if self.state != State::Closed {
            return Err(Error::InvalidState);
        }
        self.reset();
        self.local = local;
        self.state = State::Listen;
        self.passive = true;
        Ok(())
    }

    /// Opens a connection to `remote` from `local_port`, or from an
    /// ephemeral port if it is 0. The SYN goes out on the next poll;
    /// [`state`](Self::state) reaches [`State::Established`] when the peer
    /// accepts, and [`error`](Self::error) says why if it does not.
    pub fn connect(&mut self, remote: impl Into<SocketAddr>, local_port: u16) -> Result<(), Error> {
        let remote = remote.into();
        let unusable = match remote.ip() {
            IpAddr::V4(a) => a.is_broadcast(),
            IpAddr::V6(a) => a.is_multicast(),
        };
        if remote.port() == 0 || remote.ip().is_unspecified() || unusable {
            return Err(Error::InvalidAddress);
        }
        if self.state != State::Closed {
            return Err(Error::InvalidState);
        }
        self.reset();
        let any = if remote.is_ipv6() { Ipv6Addr::UNSPECIFIED.into() } else { Ipv4Addr::UNSPECIFIED.into() };
        self.local = SocketAddr::new(any, local_port);
        self.remote = remote;
        self.state = State::SynSent;
        self.fresh = true;
        Ok(())
    }

    /// Closes the sending side: a FIN follows the data already queued. The
    /// socket keeps receiving until the peer closes too.
    pub fn close(&mut self) {
        match self.state {
            State::Listen | State::SynSent => self.state = State::Closed,
            State::SynReceived | State::Established => {
                self.state = State::FinWait1;
                self.fin_queued = true;
            }
            State::CloseWait => {
                self.state = State::LastAck;
                self.fin_queued = true;
            }
            _ => {}
        }
    }

    /// Drops the connection at once, resetting it if it was open.
    pub fn abort(&mut self) {
        if matches!(
            self.state,
            State::SynReceived
                | State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
        ) {
            let flags = TCP_RST | TCP_ACK;
            let rst = TcpHeader {
                src_port: self.local.port(),
                dst_port: self.remote.port(),
                seq: self.snd_nxt,
                ack: self.rcv_nxt,
                flags,
                ..TcpHeader::default()
            };
            self.rst_pending = Some(rst);
        }
        self.state = State::Closed;
        self.timer = None;
        self.tx.clear();
    }

    /// The connection state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Why the connection was dropped: [`Error::ConnectionRefused`],
    /// [`Error::ConnectionReset`] or [`Error::TimedOut`].
    pub fn error(&self) -> Option<Error> {
        self.error
    }

    /// Returns true unless the socket is closed (TIME-WAIT counts as open).
    pub fn is_open(&self) -> bool {
        self.state != State::Closed
    }

    /// Returns true if the connection uses the timestamps option (RFC 7323):
    /// both ends offered it in the handshake. Timestamps give a round-trip
    /// sample from every ACK and protect against old duplicate segments
    /// after the sequence numbers wrap.
    pub fn has_timestamps(&self) -> bool {
        self.ts_ok
    }

    /// Returns true while the connection is established in both directions
    /// or the peer has closed its side but ours is still open.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait)
    }

    /// Our end of the connection.
    pub fn local_endpoint(&self) -> SocketAddr {
        self.local
    }

    /// The peer's end of the connection.
    pub fn remote_endpoint(&self) -> SocketAddr {
        self.remote
    }

    /// Returns true if [`send`](Self::send) can queue data now.
    pub fn can_send(&self) -> bool {
        self.may_send() && self.tx.len() < self.tx_cap
    }

    /// Returns true if the sending side is open, even if the buffer is full.
    pub fn may_send(&self) -> bool {
        matches!(self.state, State::SynSent | State::SynReceived | State::Established | State::CloseWait)
    }

    /// Returns true if [`recv`](Self::recv) has data to return.
    pub fn can_recv(&self) -> bool {
        !self.rx.is_empty()
    }

    /// Bytes waiting to be received.
    pub fn recv_queue(&self) -> usize {
        self.rx.len()
    }

    /// Bytes queued and not yet acknowledged by the peer.
    pub fn send_queue(&self) -> usize {
        self.tx.len()
    }

    /// Queues as much of `data` as fits and returns how much did. Data sent
    /// before the connection is established goes out once it is.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        if !self.may_send() {
            return Err(self.error.unwrap_or(Error::InvalidState));
        }
        let n = data.len().min(self.tx_cap - self.tx.len());
        if n == 0 && !data.is_empty() {
            return Err(Error::WouldBlock);
        }
        self.tx.extend(&data[..n]);
        Ok(n)
    }

    /// Copies received data into `buf` and returns how much. Returns `Ok(0)`
    /// once the peer has closed and everything before its FIN has been read,
    /// and [`Error::WouldBlock`] if nothing has arrived yet.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.rx.is_empty() {
            return match (self.error, self.rx_fin) {
                (Some(e), _) => Err(e),
                (None, true) => Ok(0),
                (None, false) if self.state == State::Closed || self.state == State::Listen => Err(Error::InvalidState),
                (None, false) => Err(Error::WouldBlock),
            };
        }
        let n = buf.len().min(self.rx.len());
        for (b, byte) in buf.iter_mut().zip(self.rx.drain(..n)) {
            *b = byte;
        }
        // Tell the peer once half the buffer has opened up, rather than
        // after every read (silly-window avoidance, RFC 9293 3.8.6.2.2).
        let half = (self.rx_cap as u32).min(self.max_window()) / 2;
        if self.adv_wnd < half && self.rx_window() >= half {
            self.ack_pending = true;
        }
        Ok(n)
    }

    /// The largest window the peer can be told.
    fn max_window(&self) -> u32 {
        65535 << self.rcv_shift
    }

    fn rx_window(&self) -> u32 {
        ((self.rx_cap - self.rx.len()) as u32).min(self.max_window())
    }

    fn fail(&mut self, error: Error) {
        self.state = State::Closed;
        self.error = Some(error);
        self.timer = None;
        self.tx.clear();
    }

    fn enter_time_wait(&mut self, now: Instant) {
        self.state = State::TimeWait;
        self.timer = Some(now + TIME_WAIT);
    }

    /// Returns true if an established connection carries `dst` <- `src`.
    pub(crate) fn accepts_exact(&self, dst: SocketAddr, src: SocketAddr) -> bool {
        !matches!(self.state, State::Closed | State::Listen) && self.local == dst && self.remote == src
    }

    /// Returns true if the socket listens for connections to `dst`.
    pub(crate) fn accepts_listen(&self, dst: SocketAddr) -> bool {
        self.state == State::Listen && binds(self.local, dst)
    }

    /// The TSval we send now.
    fn tsval(&self) -> u32 {
        (self.clock.as_millis() as u32).wrapping_add(self.ts_offset)
    }

    /// Takes a round-trip sample from the echo of one of our timestamps in
    /// an ACK of new data (RFC 7323 4.1). Unlike the timed segment this is
    /// valid for retransmissions too, so it replaces that sample.
    fn sample_echo(&mut self, echo: u32) {
        let ms = self.tsval().wrapping_sub(echo);
        if ms <= MAX_TS_RTT {
            self.update_rtt(Duration::from_millis(u64::from(ms)));
            self.rtt_sample = None;
        }
    }

    fn update_rtt(&mut self, rtt: Duration) {
        // RFC 6298 2.2 and 2.3, with alpha = 1/8 and beta = 1/4.
        let (srtt, rttvar) = match self.srtt {
            None => (rtt, rtt / 2),
            Some((srtt, rttvar)) => {
                let delta = srtt.abs_diff(rtt);
                (srtt * 7 / 8 + rtt / 8, rttvar * 3 / 4 + delta / 4)
            }
        };
        self.srtt = Some((srtt, rttvar));
        self.rto = (srtt + rttvar * 4).clamp(MIN_RTO, MAX_RTO);
    }

    /// Handles a segment for this socket. Returns a segment to send back at
    /// once: a reset when the segment is unacceptable in a way that calls for
    /// one, or a duplicate ACK for out-of-order data.
    pub(crate) fn process(
        &mut self,
        cx: &mut Cx,
        dst: SocketAddr,
        src: SocketAddr,
        seg: &TcpHeader,
        payload: &[u8],
    ) -> Option<TcpHeader> {
        let now = cx.now;
        self.clock = now;
        match self.state {
            State::Closed => return None,
            State::Listen => {
                if seg.has(TCP_RST) {
                    return None;
                }
                if seg.has(TCP_ACK) || !seg.has(TCP_SYN) {
                    return reset_for(seg, payload.len());
                }
                // A SYN can only come from one host.
                let ip = src.ip();
                if ip.is_unspecified() || ip.is_multicast() || matches!(ip, IpAddr::V4(a) if a.is_broadcast()) {
                    return None;
                }
                self.local = dst;
                self.remote = src;
                self.rcv_nxt = seg.seq.wrapping_add(1);
                self.set_iss(cx.rng.isn(dst, src, now));
                self.ts_offset = cx.rng.next_u32();
                self.snd_wnd = u32::from(seg.window);
                self.snd_wl1 = seg.seq;
                self.snd_mss = Self::peer_mss(seg, cx.mss_for(&dst));
                self.negotiate(seg);
                self.state = State::SynReceived;
                return None;
            }
            State::SynSent => {
                let ack_ok = seg.ack == self.iss.wrapping_add(1);
                if seg.has(TCP_ACK) && !ack_ok {
                    return reset_for(seg, payload.len());
                }
                if seg.has(TCP_RST) {
                    if seg.has(TCP_ACK) {
                        self.fail(Error::ConnectionRefused);
                    }
                    return None;
                }
                // Simultaneous open (a bare SYN) is not supported.
                if !seg.has(TCP_SYN | TCP_ACK) {
                    return None;
                }
                self.rcv_nxt = seg.seq.wrapping_add(1);
                self.snd_mss = Self::peer_mss(seg, cx.mss_for(&dst));
                self.negotiate(seg);
                self.snd_wnd = u32::from(seg.window);
                self.snd_wl1 = seg.seq;
                self.snd_wl2 = seg.ack;
                self.ack_received(seg.ack, now);
                self.state = State::Established;
                self.ack_pending = true;
                return None;
            }
            _ => {}
        }

        // Synchronized states, and SYN-RECEIVED. First, is the segment in
        // the receive window (RFC 9293 3.10.7.4)?
        let seg_len = payload.len() as u32 + u32::from(seg.has(TCP_SYN)) + u32::from(seg.has(TCP_FIN));
        let wnd = self.rx_window();
        // PAWS (RFC 7323 5): a segment older than the newest timestamp seen
        // is a wrapped-around duplicate, and one without a timestamp on a
        // connection that agreed on them is not from the peer.
        if self.ts_ok && !seg.has(TCP_RST) {
            let (val, _) = seg.timestamps?;
            if before(val, self.ts_recent) && now - self.ts_recent_at < TS_RECENT_LIFE {
                self.ack_pending = true;
                return None;
            }
        }
        let in_window = |s: u32| s.wrapping_sub(self.rcv_nxt) < wnd;
        let acceptable = seg.seq == self.rcv_nxt
            || (wnd > 0 && (in_window(seg.seq) || (seg_len > 0 && in_window(seg.seq.wrapping_add(seg_len - 1)))));
        if !acceptable {
            if !seg.has(TCP_RST) {
                self.ack_pending = true;
            }
            return None;
        }

        if seg.has(TCP_RST) {
            // Only an exact match resets (RFC 5961 3.2); anything else in the
            // window gets a challenge ACK.
            if seg.seq != self.rcv_nxt {
                self.ack_pending = true;
            } else if self.state == State::SynReceived && self.passive {
                self.relisten();
            } else if self.state == State::TimeWait {
                // A reset must not cut TIME-WAIT short (RFC 1337).
            } else if matches!(self.state, State::Closing | State::LastAck) {
                self.state = State::Closed;
                self.timer = None;
            } else {
                self.fail(Error::ConnectionReset);
            }
            return None;
        }

        if seg.has(TCP_SYN) {
            // A SYN in a synchronized state: challenge ACK (RFC 5961 4.2).
            // In SYN-RECEIVED this resends the SYN-ACK.
            self.ack_pending = true;
            return None;
        }

        if let Some((val, _)) = seg.timestamps.filter(|_| self.ts_ok) {
            // RFC 7323 4.3: only a segment that starts at or before what we
            // last acknowledged moves `TS.Recent`.
            let stale = now - self.ts_recent_at >= TS_RECENT_LIFE;
            if (!before(val, self.ts_recent) || stale) && before_eq(seg.seq, self.last_ack_sent) {
                self.ts_recent = val;
                self.ts_recent_at = now;
            }
        }
        if !seg.has(TCP_ACK) {
            return None;
        }
        if self.state == State::SynReceived {
            if !(before(self.snd_una, seg.ack) && before_eq(seg.ack, self.snd_max)) {
                return reset_for(seg, payload.len());
            }
            self.state = State::Established;
            self.snd_wnd = u32::from(seg.window) << self.snd_shift;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
        }
        if before(self.snd_max, seg.ack) {
            // Acknowledges something never sent.
            self.ack_pending = true;
            return None;
        }
        let window = u32::from(seg.window) << self.snd_shift;
        if self.sack_ok && seg.sack_len > 0 {
            self.process_sack(seg);
        }
        if before(self.snd_una, seg.ack) {
            if let Some((_, echo)) = seg.timestamps.filter(|_| self.ts_ok) {
                self.sample_echo(echo);
            }
            self.on_new_ack(seg.ack);
            self.ack_received(seg.ack, now);
        } else if seg.ack == self.snd_una
            && payload.is_empty()
            && !seg.has(TCP_FIN)
            && self.snd_una != self.snd_max
            && window == self.snd_wnd
        {
            self.on_dup_ack();
        }
        if before(self.snd_wl1, seg.seq) || (self.snd_wl1 == seg.seq && before_eq(self.snd_wl2, seg.ack)) {
            self.snd_wnd = window;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
            if self.snd_wnd > 0 {
                self.probe = false;
            }
        }

        let fin_acked = self.fin_queued && self.tx.is_empty() && self.snd_una == self.tx_seq.wrapping_add(1);
        match self.state {
            State::FinWait1 if fin_acked => self.state = State::FinWait2,
            State::Closing if fin_acked => self.enter_time_wait(now),
            State::LastAck if fin_acked => {
                self.state = State::Closed;
                self.timer = None;
                return None;
            }
            _ => {}
        }

        let mut fin_ok = true;
        if !payload.is_empty() {
            if matches!(self.state, State::Established | State::FinWait1 | State::FinWait2) {
                // Skip what we already have.
                let data = if before(seg.seq, self.rcv_nxt) {
                    payload.get(self.rcv_nxt.wrapping_sub(seg.seq) as usize..).unwrap_or(&[])
                } else {
                    payload
                };
                let seq = if before(seg.seq, self.rcv_nxt) { self.rcv_nxt } else { seg.seq };
                let wnd = self.rx_window();
                if seq == self.rcv_nxt {
                    let take = data.len().min(wnd as usize);
                    self.rx.extend(&data[..take]);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
                    fin_ok = take == data.len();
                    self.ooo_drain();
                } else {
                    // Past a gap: hold it, and acknowledge at once so that
                    // the sender sees one duplicate ACK per segment (RFC
                    // 5681 4.2).
                    let rel = seq.wrapping_sub(self.rcv_nxt);
                    let take = if rel < wnd { data.len().min((wnd - rel) as usize) } else { 0 };
                    fin_ok = take == data.len();
                    if take > 0 {
                        self.ooo_insert(seq, &data[..take]);
                    }
                    if seg.has(TCP_FIN) && fin_ok {
                        self.ooo_fin = Some(seg.seq.wrapping_add(payload.len() as u32));
                    }
                    let ack = self.segment(TCP_ACK);
                    self.adv_wnd = u32::from(ack.window) << self.rcv_shift;
                    self.last_ack_sent = ack.ack;
                    return Some(ack);
                }
            }
            self.ack_pending = true;
        }

        if seg.has(TCP_FIN) {
            match self.state {
                State::Established | State::FinWait1 | State::FinWait2 if fin_ok => {
                    self.ooo_fin = Some(seg.seq.wrapping_add(payload.len() as u32));
                }
                State::TimeWait => self.enter_time_wait(now),
                _ => {}
            }
            self.ack_pending = true;
        }
        if matches!(self.state, State::Established | State::FinWait1 | State::FinWait2)
            && self.ooo_fin == Some(self.rcv_nxt)
        {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.rx_fin = true;
            self.state = match self.state {
                State::Established => State::CloseWait,
                State::FinWait1 if !fin_acked => State::Closing,
                _ => {
                    self.enter_time_wait(now);
                    State::TimeWait
                }
            };
        }
        None
    }

    fn set_iss(&mut self, iss: u32) {
        self.iss = iss;
        self.tx_seq = iss.wrapping_add(1);
        self.snd_una = iss;
        self.snd_nxt = iss;
        self.snd_max = iss;
        self.recover = iss;
        self.rexmit_next = iss;
    }

    /// Takes the options of the peer's SYN: window scaling and SACK are on
    /// only if both ends offered them. Also starts congestion control, now
    /// that the MSS is known.
    fn negotiate(&mut self, syn: &TcpHeader) {
        self.ws_active = syn.wscale.is_some();
        self.snd_shift = syn.wscale.map_or(0, |s| s.min(MAX_SHIFT));
        self.rcv_shift = if self.ws_active { self.ws_offer } else { 0 };
        self.sack_ok = syn.sack_permitted && self.sack_enabled;
        self.ts_ok = syn.timestamps.is_some() && self.ts_enabled;
        if let Some((val, _)) = syn.timestamps.filter(|_| self.ts_ok) {
            self.ts_recent = val;
            self.ts_recent_at = self.clock;
            self.snd_mss = self.snd_mss.saturating_sub(TS_OPTION_LEN).max(MIN_MSS);
        }
        let mss = self.snd_mss as u32;
        // RFC 6928.
        self.cwnd = (10 * mss).min((2 * mss).max(14600));
        self.ssthresh = u32::MAX;
        self.in_recovery = false;
    }

    /// Inserts `data` at `seq`, past a gap, merging it with the ranges it
    /// overlaps or touches.
    fn ooo_insert(&mut self, seq: u32, data: &[u8]) {
        let (mut start, mut end) = (seq, seq.wrapping_add(data.len() as u32));
        let mut buf = data.to_vec();
        let base = self.rcv_nxt;
        let mut i = 0;
        while i < self.ooo.len() {
            let (rs, ref rd) = self.ooo[i];
            let re = rs.wrapping_add(rd.len() as u32);
            if before(end, rs) {
                break;
            }
            if before(re, start) {
                i += 1;
                continue;
            }
            let (rs, rd) = self.ooo.remove(i);
            if before(rs, start) {
                let mut merged = rd[..start.wrapping_sub(rs) as usize].to_vec();
                merged.append(&mut buf);
                buf = merged;
                start = rs;
            }
            if before(end, re) {
                buf.extend_from_slice(&rd[end.wrapping_sub(rs) as usize..]);
                end = re;
            }
        }
        debug_assert!(self.ooo.iter().all(|(s, _)| s.wrapping_sub(base) < 1 << 31));
        if self.ooo.len() < MAX_RANGES {
            self.ooo.insert(i, (start, buf));
            self.ooo_recent = Some(start);
        }
    }

    /// Moves held ranges that `rcv_nxt` has reached into the receive buffer.
    fn ooo_drain(&mut self) {
        while let Some((start, _)) = self.ooo.first() {
            if before(self.rcv_nxt, *start) {
                break;
            }
            let (start, data) = self.ooo.remove(0);
            let skip = self.rcv_nxt.wrapping_sub(start) as usize;
            if let Some(rest) = data.get(skip..) {
                let take = rest.len().min(self.rx_window() as usize);
                self.rx.extend(&rest[..take]);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
            }
        }
        if self.ooo.is_empty() {
            self.ooo_recent = None;
        }
    }

    /// Adds the SACK blocks for the data held past a gap to `h`.
    fn fill_sack(&self, h: &mut TcpHeader) {
        if !self.sack_ok || self.ooo.is_empty() {
            return;
        }
        let block = |(s, d): &(u32, Vec<u8>)| (*s, s.wrapping_add(d.len() as u32));
        let recent = self.ooo.iter().filter(|(s, _)| Some(*s) == self.ooo_recent).map(block);
        let others = self.ooo.iter().filter(|(s, _)| Some(*s) != self.ooo_recent).map(block);
        // Timestamps leave room for three blocks.
        let room = if self.ts_ok { MAX_SACK_BLOCKS - 1 } else { MAX_SACK_BLOCKS };
        for b in recent.chain(others).take(room) {
            h.sack[usize::from(h.sack_len)] = b;
            h.sack_len += 1;
        }
    }

    /// Merges the peer's SACK blocks into the scoreboard.
    fn process_sack(&mut self, seg: &TcpHeader) {
        for &(l, r) in &seg.sack[..usize::from(seg.sack_len)] {
            // Only data in flight counts; this also drops D-SACKs.
            let l = if before(l, self.snd_una) { self.snd_una } else { l };
            if !before(l, r) || before(self.snd_max, r) {
                continue;
            }
            let base = self.snd_una;
            let (mut start, mut end) = (l, r);
            let mut i = 0;
            while i < self.scoreboard.len() {
                let (rs, re) = self.scoreboard[i];
                if before(end, rs) {
                    break;
                }
                if before(re, start) {
                    i += 1;
                    continue;
                }
                self.scoreboard.remove(i);
                if before(rs, start) {
                    start = rs;
                }
                if before(end, re) {
                    end = re;
                }
            }
            debug_assert!(start.wrapping_sub(base) < 1 << 31);
            if self.scoreboard.len() < MAX_RANGES {
                self.scoreboard.insert(i, (start, end));
            }
        }
    }

    /// Bytes of `[from, to)` the peer has reported.
    fn sacked_between(&self, from: u32, to: u32) -> u32 {
        let mut n = 0u32;
        for &(l, r) in &self.scoreboard {
            let (l, r) = (if before(l, from) { from } else { l }, if before(to, r) { to } else { r });
            if before(l, r) {
                n = n.wrapping_add(r.wrapping_sub(l));
            }
        }
        n
    }

    /// The first stretch at or after `from` that the peer has not reported
    /// but has reported data beyond: presumed lost.
    fn next_hole(&self, from: u32) -> Option<(u32, u32)> {
        let mut pos = if before(from, self.snd_una) { self.snd_una } else { from };
        for &(l, r) in &self.scoreboard {
            if before(pos, l) {
                return Some((pos, l));
            }
            if before(pos, r) {
                pos = r;
            }
        }
        None
    }

    /// Bytes in the network, by RFC 6675's reckoning: what is above the
    /// highest reported byte, plus our retransmissions of holes below it.
    fn pipe(&self) -> u32 {
        let high = self.scoreboard.last().map_or(self.snd_una, |&(_, r)| r);
        let boundary = if before(high, self.rexmit_next) { self.rexmit_next } else { high };
        let retransmitted = self
            .rexmit_next
            .wrapping_sub(self.snd_una)
            .wrapping_sub(self.sacked_between(self.snd_una, self.rexmit_next));
        let retransmitted = if before(self.snd_una, self.rexmit_next) { retransmitted } else { 0 };
        self.snd_max.wrapping_sub(boundary).wrapping_add(retransmitted)
    }

    /// An ACK acknowledges new data up to `ack` (before `snd_una` moves).
    fn on_new_ack(&mut self, ack: u32) {
        let mss = self.snd_mss as u32;
        let acked = ack.wrapping_sub(self.snd_una);
        self.dup_acks = 0;
        if self.in_recovery {
            if before_eq(self.recover, ack) {
                self.in_recovery = false;
                self.cwnd = self.ssthresh;
                self.rexmit_one = None;
            } else if self.sack_ok {
                // The byte the ACK stops at was lost, though no block may say
                // so yet: resend it unless it has been resent.
                if before_eq(self.rexmit_next, ack) {
                    self.rexmit_next = ack;
                    self.rexmit_one = Some(ack);
                }
            } else {
                // NewReno partial ACK: retransmit the next hole, and deflate
                // by what was acknowledged (RFC 6582 3.2 step 5).
                self.rexmit_one = Some(ack);
                self.cwnd = self.cwnd.saturating_sub(acked).saturating_add(if acked >= mss { mss } else { 0 }).max(mss);
            }
        } else if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked.min(mss));
        } else {
            self.ca_acc = self.ca_acc.saturating_add(acked);
            if self.ca_acc >= self.cwnd {
                self.ca_acc -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(mss);
            }
        }
        // Reports below the new left edge are history.
        self.scoreboard.retain_mut(|(l, r)| {
            if before_eq(*r, ack) {
                return false;
            }
            if before(*l, ack) {
                *l = ack;
            }
            true
        });
    }

    fn on_dup_ack(&mut self) {
        self.dup_acks = self.dup_acks.saturating_add(1);
        let mss = self.snd_mss as u32;
        if self.in_recovery {
            if !self.sack_ok {
                self.cwnd = self.cwnd.saturating_add(mss);
            }
        } else if self.dup_acks == 3 && before_eq(self.recover, self.snd_una) {
            // Fast retransmit and fast recovery (RFC 5681 3.2, RFC 6582).
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            self.ssthresh = (flight / 2).max(2 * mss);
            self.recover = self.snd_max;
            self.in_recovery = true;
            self.rexmit_one = Some(self.snd_una);
            self.rexmit_next = self.snd_una;
            self.rtt_sample = None;
            self.cwnd = if self.sack_ok { self.ssthresh } else { self.ssthresh.saturating_add(3 * mss) };
        }
    }

    /// The retransmission timer fired with data outstanding (RFC 5681 3.1).
    fn on_timeout(&mut self) {
        let mss = self.snd_mss as u32;
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        self.ssthresh = (flight / 2).max(2 * mss);
        self.cwnd = mss;
        self.recover = self.snd_max;
        self.in_recovery = false;
        self.dup_acks = 0;
        self.ca_acc = 0;
        self.rexmit_one = None;
        self.scoreboard.clear();
    }

    /// Advances `snd_una` to `ack`, which acknowledges new data.
    fn ack_received(&mut self, ack: u32, now: Instant) {
        if let Some((seq, sent)) = self.rtt_sample
            && before_eq(seq, ack)
        {
            self.update_rtt(now - sent);
            self.rtt_sample = None;
        }
        // An ACK of new data ends any backoff (RFC 6298 5.7).
        if let Some((srtt, rttvar)) = self.srtt {
            self.rto = (srtt + rttvar * 4).clamp(MIN_RTO, MAX_RTO);
        }
        self.snd_una = ack;
        if before(self.snd_nxt, ack) {
            self.snd_nxt = ack;
        }
        let acked = (ack.wrapping_sub(self.tx_seq) as usize).min(self.tx.len());
        // `ack` can be iss + 1 (SYN only), below `tx_seq` in no case.
        if !before(ack, self.tx_seq) {
            self.tx.drain(..acked);
            self.tx_seq = self.tx_seq.wrapping_add(acked as u32);
        }
        self.retries = 0;
        self.timer = if self.snd_una == self.snd_max { None } else { Some(now + self.rto) };
    }

    pub(crate) fn poll_at(&self) -> Option<Instant> {
        match self.state {
            State::Closed => self.rst_pending.map(|_| Instant::ZERO),
            State::Listen => None,
            State::TimeWait => {
                if self.ack_pending {
                    Some(Instant::ZERO)
                } else {
                    self.timer
                }
            }
            State::SynSent | State::SynReceived => {
                if self.fresh || self.snd_nxt == self.iss || self.ack_pending {
                    Some(Instant::ZERO)
                } else {
                    self.timer
                }
            }
            _ => {
                let offset = self.snd_nxt.wrapping_sub(self.tx_seq) as usize;
                let data = offset < self.tx.len() && self.window_left() > 0;
                let fin = self.fin_queued && offset == self.tx.len();
                if self.ack_pending || data || fin || self.rexmit_ready() { Some(Instant::ZERO) } else { self.timer }
            }
        }
    }

    fn segment(&self, flags: u8) -> TcpHeader {
        self.segment_at(self.snd_nxt, flags)
    }

    fn segment_at(&self, seq: u32, flags: u8) -> TcpHeader {
        let mut h = TcpHeader {
            src_port: self.local.port(),
            dst_port: self.remote.port(),
            seq,
            ack: if flags & TCP_ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: (self.rx_window() >> self.rcv_shift).min(65535) as u16,
            ..TcpHeader::default()
        };
        if flags & (TCP_ACK | TCP_SYN) == TCP_ACK {
            self.fill_sack(&mut h);
        }
        if self.ts_ok && flags & TCP_RST == 0 {
            h.timestamps = Some((self.tsval(), self.ts_recent));
        }
        h
    }

    /// How many bytes from `snd_nxt` the peer's window and ours allow.
    fn window_left(&self) -> usize {
        let wnd = if self.probe { self.snd_wnd.max(1) } else { self.snd_wnd };
        let by_peer = self.snd_una.wrapping_add(wnd).wrapping_sub(self.snd_nxt) as i32;
        let by_cwnd = if self.in_recovery && self.sack_ok {
            i64::from(self.cwnd) - i64::from(self.pipe())
        } else {
            i64::from(self.snd_una.wrapping_add(self.cwnd.min(wnd)).wrapping_sub(self.snd_nxt) as i32)
        };
        i64::from(by_peer).min(by_cwnd).max(0) as usize
    }

    /// Returns true if recovery has a segment to retransmit.
    fn rexmit_ready(&self) -> bool {
        self.in_recovery
            && (self.rexmit_one.is_some()
                || (self.sack_ok && self.next_hole(self.rexmit_next).is_some() && self.pipe() < self.cwnd))
    }

    /// Retransmits up to `max` bytes from `seq`, which `snd_max` has passed,
    /// without moving `snd_nxt`. Returns how many sequence numbers it used.
    fn retransmit(&mut self, seq: u32, max: usize, out: &mut Vec<Packet>) -> u32 {
        let offset = seq.wrapping_sub(self.tx_seq) as usize;
        let sent = (self.snd_max.wrapping_sub(self.tx_seq) as usize).min(self.tx.len());
        if offset > self.tx.len() || !before(seq, self.snd_max) {
            return 0;
        }
        let len = sent.saturating_sub(offset).min(self.snd_mss).min(max);
        let fin = self.fin_queued
            && offset + len == self.tx.len()
            && before(self.tx_seq.wrapping_add(self.tx.len() as u32), self.snd_max);
        if len == 0 && !fin {
            return 0;
        }
        let flags = TCP_ACK | if fin { TCP_FIN } else { 0 };
        let payload: Vec<u8> = self.tx.range(offset..offset + len).copied().collect();
        let header = self.segment_at(seq, flags);
        self.emit(header, &payload, out);
        len as u32 + u32::from(fin)
    }

    fn emit(&mut self, header: TcpHeader, payload: &[u8], out: &mut Vec<Packet>) {
        let shift = if header.has(TCP_SYN) { 0 } else { self.rcv_shift };
        self.adv_wnd = u32::from(header.window) << shift;
        if header.has(TCP_ACK) {
            self.last_ack_sent = header.ack;
        }
        let segment = header.emit(self.local.ip(), self.remote.ip(), payload);
        out.push(Packet { src: self.local.ip(), dst: self.remote.ip(), protocol: PROTO_TCP, payload: segment });
    }

    pub(crate) fn dispatch(&mut self, cx: &mut Cx, out: &mut Vec<Packet>) {
        let now = cx.now;
        self.clock = now;
        match self.state {
            State::Closed => {
                if let Some(rst) = self.rst_pending.take() {
                    let segment = rst.emit(self.local.ip(), self.remote.ip(), &[]);
                    out.push(Packet {
                        src: self.local.ip(),
                        dst: self.remote.ip(),
                        protocol: PROTO_TCP,
                        payload: segment,
                    });
                }
                return;
            }
            State::Listen => return,
            State::TimeWait => {
                if self.timer.is_some_and(|t| now >= t) {
                    self.state = State::Closed;
                    self.timer = None;
                } else if self.ack_pending {
                    self.ack_pending = false;
                    self.emit(self.segment(TCP_ACK), &[], out);
                }
                return;
            }
            _ => {}
        }

        if self.fresh {
            let Some(addr) = cx.source_for(self.remote.ip()) else { return };
            self.local.set_ip(addr);
            if self.local.port() == 0 {
                self.local.set_port(cx.rng.ephemeral_port());
            }
            self.set_iss(cx.rng.isn(self.local, self.remote, now));
            self.ts_offset = cx.rng.next_u32();
            let mss = u32::from(cx.mss_for(&self.remote));
            self.cwnd = (10 * mss).min((2 * mss).max(14600));
            self.fresh = false;
        }

        if self.timer.is_some_and(|t| now >= t) {
            self.timer = None;
            self.retries += 1;
            if self.retries > MAX_RETRIES {
                // A half-open connection that never completed is no error
                // of the listener's.
                if self.state == State::SynReceived && self.passive {
                    self.relisten();
                } else {
                    self.fail(Error::TimedOut);
                }
                return;
            }
            self.rto = (self.rto * 2).min(MAX_RTO);
            // Karn's algorithm: never time a retransmitted segment.
            self.rtt_sample = None;
            if self.snd_una != self.snd_max && !matches!(self.state, State::SynSent | State::SynReceived) {
                self.on_timeout();
            }
            if self.snd_wnd == 0 && self.snd_una == self.snd_max {
                self.probe = true;
            }
            self.snd_nxt = self.snd_una;
        }

        if matches!(self.state, State::SynSent | State::SynReceived) {
            if self.snd_nxt == self.iss || self.ack_pending {
                self.snd_nxt = self.iss;
                let flags = if self.state == State::SynSent { TCP_SYN } else { TCP_SYN | TCP_ACK };
                let mut syn = self.segment(flags);
                // A SYN's window is never scaled.
                syn.window = self.rx_window().min(65535) as u16;
                syn.mss = Some(cx.mss_for(&self.remote));
                if self.state == State::SynSent {
                    syn.wscale = Some(self.ws_offer);
                    syn.sack_permitted = self.sack_enabled;
                    syn.timestamps = self.ts_enabled.then(|| (self.tsval(), 0));
                } else {
                    syn.wscale = self.ws_active.then_some(self.ws_offer);
                    syn.sack_permitted = self.sack_ok;
                }
                self.emit(syn, &[], out);
                self.snd_nxt = self.iss.wrapping_add(1);
                self.snd_max = self.snd_nxt;
                self.ack_pending = false;
                if self.retries == 0 && self.rtt_sample.is_none() {
                    self.rtt_sample = Some((self.snd_nxt, now));
                }
                self.timer.get_or_insert(now + self.rto);
            }
            return;
        }

        if self.in_recovery {
            if let Some(seq) = self.rexmit_one.take() {
                let n = self.retransmit(seq, self.snd_mss, out);
                if self.sack_ok && n > 0 && before(self.rexmit_next, seq.wrapping_add(n)) {
                    self.rexmit_next = seq.wrapping_add(n);
                }
                self.ack_pending = false;
            }
            for _ in 0..MAX_BURST {
                if !self.sack_ok || self.pipe() >= self.cwnd {
                    break;
                }
                let Some((start, end)) = self.next_hole(self.rexmit_next) else { break };
                let n = self.retransmit(start, end.wrapping_sub(start) as usize, out);
                if n == 0 {
                    break;
                }
                self.rexmit_next = start.wrapping_add(n);
                self.ack_pending = false;
            }
        }

        for _ in 0..MAX_BURST {
            let offset = self.snd_nxt.wrapping_sub(self.tx_seq) as usize;
            if offset > self.tx.len() {
                break; // the FIN is out
            }
            let unsent = self.tx.len() - offset;
            let len = unsent.min(self.window_left()).min(self.snd_mss);
            let fin = self.fin_queued && offset + len == self.tx.len();
            if len == 0 && !fin {
                break;
            }
            let mut flags = TCP_ACK;
            if len > 0 && offset + len == self.tx.len() {
                flags |= TCP_PSH;
            }
            if fin {
                flags |= TCP_FIN;
            }
            let payload: Vec<u8> = self.tx.range(offset..offset + len).copied().collect();
            let header = self.segment(flags);
            self.emit(header, &payload, out);
            let new_data = self.snd_nxt == self.snd_max;
            self.snd_nxt = self.snd_nxt.wrapping_add(len as u32 + u32::from(fin));
            if before(self.snd_max, self.snd_nxt) {
                self.snd_max = self.snd_nxt;
            }
            if new_data && self.retries == 0 && self.rtt_sample.is_none() {
                self.rtt_sample = Some((self.snd_nxt, now));
            }
            self.timer.get_or_insert(now + self.rto);
            self.ack_pending = false;
            self.probe = false;
            if fin {
                break;
            }
        }

        if self.ack_pending {
            self.ack_pending = false;
            self.emit(self.segment(TCP_ACK), &[], out);
        }

        // Persist timer: probe a zero window once it has been closed for a
        // retransmission timeout.
        let offset = self.snd_nxt.wrapping_sub(self.tx_seq) as usize;
        if self.snd_wnd == 0 && offset < self.tx.len() && self.timer.is_none() {
            self.timer = Some(now + self.rto);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::sa;
    use crate::testing::{B_IP, Fate, Host, pair, run};
    use crate::{SocketHandle, wire};

    fn tcp(h: &mut Host, s: SocketHandle) -> &mut TcpSocket {
        h.sockets.get_mut::<TcpSocket>(s)
    }

    /// A on an ephemeral port connected to B listening on 80.
    fn connected(rx: usize, tx: usize) -> (Host, Host, SocketHandle, SocketHandle, Instant) {
        let (mut a, mut b) = pair();
        let ca = a.sockets.add(TcpSocket::new(rx, tx));
        let cb = b.sockets.add(TcpSocket::new(rx, tx));
        tcp(&mut b, cb).listen(80).unwrap();
        tcp(&mut a, ca).connect(sa(B_IP, 80), 0).unwrap();
        let mut now = Instant::ZERO;
        assert!(run(&mut a, &mut b, &mut now, 1000, |a, b| {
            tcp(a, ca).state() == State::Established && tcp(b, cb).state() == State::Established
        }));
        assert_eq!(tcp(&mut b, cb).remote_endpoint(), tcp(&mut a, ca).local_endpoint());
        (a, b, ca, cb, now)
    }

    #[test]
    fn echo_and_close() {
        let (mut a, mut b, ca, cb, mut now) = connected(1024, 1024);
        assert_eq!(tcp(&mut a, ca).send(b"hello"), Ok(5));
        let mut buf = [0u8; 64];
        assert!(run(&mut a, &mut b, &mut now, 100, |_, b| tcp(b, cb).can_recv()));
        let n = tcp(&mut b, cb).recv(&mut buf).unwrap();
        tcp(&mut b, cb).send(&buf[..n]).unwrap();
        assert!(run(&mut a, &mut b, &mut now, 100, |a, _| tcp(a, ca).can_recv()));
        assert_eq!(tcp(&mut a, ca).recv(&mut buf), Ok(5));
        assert_eq!(&buf[..5], b"hello");

        tcp(&mut a, ca).close();
        assert!(run(&mut a, &mut b, &mut now, 100, |a, b| {
            tcp(b, cb).state() == State::CloseWait && tcp(a, ca).state() == State::FinWait2
        }));
        assert_eq!(tcp(&mut b, cb).recv(&mut buf), Ok(0), "end of stream");
        assert_eq!(tcp(&mut b, cb).send(b"late"), Ok(4), "B can still send");
        tcp(&mut b, cb).close();
        assert!(run(&mut a, &mut b, &mut now, 100, |a, b| tcp(b, cb).state() == State::Closed
            && tcp(a, ca).state() == State::TimeWait));
        assert_eq!(tcp(&mut a, ca).recv(&mut buf), Ok(4));
        assert_eq!(tcp(&mut a, ca).recv(&mut buf), Ok(0));
        assert!(run(&mut a, &mut b, &mut now, 11_000, |a, _| tcp(a, ca).state() == State::Closed), "TIME-WAIT ends");
        assert_eq!(tcp(&mut a, ca).error(), None);
    }

    /// Moves `len` bytes from A to B while `lossy` frames are dropped and B
    /// reads only every few milliseconds, so that the window closes.
    fn bulk(len: usize, rx: usize, lose: impl FnMut(u64, &[u8]) -> bool + Clone + 'static) -> Duration {
        let (mut a, mut b, ca, cb, mut now) = connected(rx, 8192);
        a.set_filter(lose.clone());
        b.set_filter(lose);
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + i / 251) as u8).collect();
        let mut sent = 0;
        let mut got = Vec::new();
        let mut buf = [0u8; 1000];
        let mut tick = 0u32;
        let start = now;
        let ok = run(&mut a, &mut b, &mut now, 120_000, |a, b| {
            if sent < data.len()
                && let Ok(n) = tcp(a, ca).send(&data[sent..])
            {
                sent += n;
                if sent == data.len() {
                    tcp(a, ca).close();
                }
            }
            // B drains in bursts, every third millisecond.
            tick += 1;
            if tick % 3 == 0 {
                while let Ok(n) = tcp(b, cb).recv(&mut buf) {
                    if n == 0 {
                        return true;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
            }
            false
        });
        if !ok {
            let x = tcp(&mut a, ca);
            std::println!(
                "A {:?} una {} nxt {} max {} tx_seq {} txlen {} wnd {} timer {:?} retries {} rto {:?}",
                x.state,
                x.snd_una,
                x.snd_nxt,
                x.snd_max,
                x.tx_seq,
                x.tx.len(),
                x.snd_wnd,
                x.timer,
                x.retries,
                x.rto
            );
            let z = tcp(&mut b, cb);
            std::println!(
                "B {:?} rcv_nxt {} rx {} adv {} got {} sent {}",
                z.state,
                z.rcv_nxt,
                z.rx.len(),
                z.adv_wnd,
                got.len(),
                sent
            );
            panic!("stalled");
        }
        assert!(got == data, "received {} of {} bytes intact", got.len(), data.len());
        assert_eq!(tcp(&mut b, cb).state(), State::CloseWait);
        std::println!("{len} bytes in {} ms", (now - start).as_millis());
        now - start
    }

    #[test]
    fn bulk_transfer() {
        bulk(200_000, 4096, |_, _| true);
    }

    #[test]
    fn bulk_transfer_with_loss() {
        // Drop every seventh frame each way, including SYNs, FINs and ACKs.
        // A small window recovers by timeout, a large one mostly by fast
        // retransmit.
        bulk(100_000, 4096, |n, _| n % 7 != 3);
        let slow = bulk(100_000, 32768, |n, _| n % 7 != 3);
        assert!(slow < Duration::from_secs(6), "fast retransmit: {slow:?}");
    }

    #[test]
    fn refused() {
        let (mut a, mut b) = pair();
        let ca = a.sockets.add(TcpSocket::new(64, 64));
        tcp(&mut a, ca).connect(sa(B_IP, 81), 5000).unwrap();
        let mut now = Instant::ZERO;
        assert!(run(&mut a, &mut b, &mut now, 100, |a, _| !tcp(a, ca).is_open()));
        assert_eq!(tcp(&mut a, ca).error(), Some(Error::ConnectionRefused));
        assert_eq!(tcp(&mut a, ca).recv(&mut [0; 4]), Err(Error::ConnectionRefused));
    }

    #[test]
    fn times_out_and_backs_off() {
        let (mut a, mut b, ca, _, mut now) = connected(64, 64);
        let start = now;
        a.set_filter(|_, _| false);
        tcp(&mut a, ca).send(b"lost").unwrap();
        assert!(run(&mut a, &mut b, &mut now, 600_000, |a, _| !tcp(a, ca).is_open()));
        assert_eq!(tcp(&mut a, ca).error(), Some(Error::TimedOut));
        // RTO starts near the 200 ms floor and doubles, capped at 60 s.
        let elapsed = (now - start).as_secs();
        assert!((60..=200).contains(&elapsed), "gave up after {elapsed} s");
    }

    #[test]
    fn abort_resets_the_peer() {
        let (mut a, mut b, ca, cb, mut now) = connected(64, 64);
        tcp(&mut a, ca).abort();
        assert!(run(&mut a, &mut b, &mut now, 100, |_, b| !tcp(b, cb).is_open()));
        assert_eq!(tcp(&mut b, cb).error(), Some(Error::ConnectionReset));
    }

    #[test]
    fn listener_ignores_stray_segments() {
        let mut rng = crate::rng::Rng::new(1);
        let mut s = TcpSocket::new(64, 64);
        s.listen(80).unwrap();
        let mut cx = Cx {
            now: Instant::ZERO,
            addr: Some(B_IP),
            mac: Default::default(),
            mss: 1460,
            mss6: 1440,
            addr6: None,
            link_local6: None,
            rng: &mut rng,
        };
        let dst = sa(B_IP, 80);
        let src = sa(Ipv4Addr::new(192, 168, 1, 9), 4000);
        let ack =
            TcpHeader { src_port: 4000, dst_port: 80, seq: 1, ack: 99, flags: wire::TCP_ACK, ..Default::default() };
        let rst = s.process(&mut cx, dst, src, &ack, &[]).unwrap();
        assert_eq!((rst.seq, rst.flags), (99, TCP_RST));
        assert_eq!(s.state(), State::Listen);
    }

    const PEER: SocketAddr = sa(Ipv4Addr::new(192, 168, 1, 9), 4000);

    fn syn(mss: Option<u16>) -> TcpHeader {
        TcpHeader { src_port: 4000, dst_port: 80, seq: 1000, flags: TCP_SYN, window: 1000, mss, ..Default::default() }
    }

    /// A listener on 80 that has taken `syn` from [`PEER`].
    fn half_open(rng: &mut crate::rng::Rng, syn: &TcpHeader) -> TcpSocket {
        let mut s = TcpSocket::new(64, 64);
        s.listen(80).unwrap();
        let mut cx = Cx {
            now: Instant::ZERO,
            addr: Some(B_IP),
            mac: Default::default(),
            mss: 1460,
            mss6: 1440,
            addr6: None,
            link_local6: None,
            rng,
        };
        assert!(s.process(&mut cx, sa(B_IP, 80), PEER, syn, &[]).is_none());
        s
    }

    #[test]
    fn listener_ignores_syns_from_no_one() {
        let mut rng = crate::rng::Rng::new(1);
        let mut s = TcpSocket::new(64, 64);
        s.listen(80).unwrap();
        let mut cx = Cx {
            now: Instant::ZERO,
            addr: Some(B_IP),
            mac: Default::default(),
            mss: 1460,
            mss6: 1440,
            addr6: None,
            link_local6: None,
            rng: &mut rng,
        };
        let dst = sa(B_IP, 80);
        for ip in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, Ipv4Addr::new(224, 0, 0, 1)] {
            assert!(s.process(&mut cx, dst, sa(ip, 4000), &syn(None), &[]).is_none());
            assert_eq!(s.state(), State::Listen, "SYN from {ip}");
        }
    }

    #[test]
    fn unanswered_syn_ack_returns_to_listen() {
        let mut rng = crate::rng::Rng::new(1);
        let mut s = half_open(&mut rng, &syn(None));
        assert_eq!(s.state(), State::SynReceived);
        let mut now = Instant::ZERO;
        let mut out = Vec::new();
        while s.state() == State::SynReceived && now.as_millis() < 600_000 {
            let mut cx = Cx {
                now,
                addr: Some(B_IP),
                mac: Default::default(),
                mss: 1460,
                mss6: 1440,
                addr6: None,
                link_local6: None,
                rng: &mut rng,
            };
            s.dispatch(&mut cx, &mut out);
            now = Instant::from_millis(now.as_millis() + 100);
        }
        assert_eq!(out.len(), usize::from(MAX_RETRIES) + 1, "the SYN-ACK and its retransmissions");
        assert_eq!((s.state(), s.error(), s.local_endpoint().port()), (State::Listen, None, 80));
    }

    #[test]
    fn tiny_peer_mss_is_raised() {
        let mut rng = crate::rng::Rng::new(1);
        assert_eq!(half_open(&mut rng, &syn(Some(0))).snd_mss, MIN_MSS);
        assert_eq!(half_open(&mut rng, &syn(Some(9000))).snd_mss, 1460, "never above our own");
    }

    #[test]
    fn time_wait_ignores_resets() {
        let mut rng = crate::rng::Rng::new(1);
        let mut s = half_open(&mut rng, &syn(None));
        s.state = State::TimeWait;
        s.timer = Some(Instant::from_millis(10_000));
        let mut cx = Cx {
            now: Instant::ZERO,
            addr: Some(B_IP),
            mac: Default::default(),
            mss: 1460,
            mss6: 1440,
            addr6: None,
            link_local6: None,
            rng: &mut rng,
        };
        let rst = TcpHeader { seq: s.rcv_nxt, flags: TCP_RST, ..syn(None) };
        s.process(&mut cx, sa(B_IP, 80), PEER, &rst, &[]);
        assert_eq!(s.state(), State::TimeWait);
    }

    #[test]
    fn duplicate_acks_saturate() {
        let mut rng = crate::rng::Rng::new(1);
        let mut s = half_open(&mut rng, &syn(None));
        let dst = sa(B_IP, 80);
        let mut out = Vec::new();
        let mut cx = Cx {
            now: Instant::ZERO,
            addr: Some(B_IP),
            mac: Default::default(),
            mss: 1460,
            mss6: 1440,
            addr6: None,
            link_local6: None,
            rng: &mut rng,
        };
        s.dispatch(&mut cx, &mut out);
        let ack = TcpHeader { seq: 1001, ack: s.iss.wrapping_add(1), flags: TCP_ACK, window: 1000, ..syn(None) };
        s.process(&mut cx, dst, PEER, &ack, &[]);
        assert_eq!(s.state(), State::Established);
        s.send(b"data").unwrap();
        s.dispatch(&mut cx, &mut out);
        for _ in 0..300 {
            s.process(&mut cx, dst, PEER, &ack, &[]);
        }
        assert_eq!(s.dup_acks, u8::MAX);
    }

    /// The sequence number and payload length of an Ethernet frame, if it
    /// carries a TCP segment.
    fn tcp_segment(frame: &[u8]) -> Option<(u32, usize)> {
        let (_, ip) = wire::EthernetHeader::parse(frame)?;
        let (h, payload) = wire::Ipv4Header::parse(ip)?;
        if h.protocol != PROTO_TCP {
            return None;
        }
        TcpHeader::parse(payload, h.src, h.dst).map(|(t, d)| (t.seq, d.len()))
    }

    /// What a transfer from A to B left behind.
    struct Transfer {
        elapsed: Duration,
        /// Data segments A sent that covered bytes it had sent before.
        resent: usize,
        max_cwnd: u32,
        recoveries: u32,
        timeouts: u32,
    }

    /// Sends `len` bytes from A to B, through `fate` on A's frames and
    /// `back` on B's, with the sockets adjusted by `setup`.
    fn transfer(
        len: usize,
        rx: usize,
        setup: impl Fn(&mut TcpSocket, &mut TcpSocket),
        fate: impl FnMut(u64, &[u8]) -> Fate + 'static,
        back: impl FnMut(u64, &[u8]) -> Fate + 'static,
    ) -> Transfer {
        let (mut a, mut b) = pair();
        let ca = a.sockets.add(TcpSocket::new(rx, len + 1));
        let cb = b.sockets.add(TcpSocket::new(rx, 1024));
        setup(tcp(&mut a, ca), tcp(&mut b, cb));
        tcp(&mut b, cb).listen(80).unwrap();
        tcp(&mut a, ca).connect(sa(B_IP, 80), 0).unwrap();
        let mut now = Instant::ZERO;
        assert!(run(&mut a, &mut b, &mut now, 1000, |a, b| {
            tcp(a, ca).state() == State::Established && tcp(b, cb).state() == State::Established
        }));
        let segments = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let counter = segments.clone();
        let mut fate = fate;
        let mut high = None::<u32>;
        a.set_shaper(move |n, f| {
            if let Some((seq, len @ 1..)) = tcp_segment(f) {
                let end = seq.wrapping_add(len as u32);
                match high {
                    Some(h) if before(seq, h) => counter.set(counter.get() + 1),
                    Some(h) if !before(h, end) => {}
                    _ => high = Some(end),
                }
            }
            fate(n, f)
        });
        b.set_shaper(back);
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + i / 251) as u8).collect();
        assert_eq!(tcp(&mut a, ca).send(&data), Ok(len));
        tcp(&mut a, ca).close();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        let start = now;
        let (mut max_cwnd, mut recoveries, mut timeouts) = (0, 0, 0);
        let (mut was_recovering, mut last_retries) = (false, 0);
        let ok = run(&mut a, &mut b, &mut now, 120_000, |a, b| {
            let x = tcp(a, ca);
            max_cwnd = max_cwnd.max(x.cwnd);
            recoveries += u32::from(x.in_recovery && !was_recovering);
            was_recovering = x.in_recovery;
            timeouts += u32::from(x.retries > 0 && last_retries == 0);
            last_retries = x.retries;
            while let Ok(n) = tcp(b, cb).recv(&mut buf) {
                if n == 0 {
                    return true;
                }
                got.extend_from_slice(&buf[..n]);
            }
            false
        });
        assert!(ok, "stalled after {} of {len} bytes", got.len());
        assert!(got == data, "received {} of {len} bytes intact", got.len());
        Transfer { elapsed: now - start, resent: segments.get(), max_cwnd, recoveries, timeouts }
    }

    fn clean(_: u64, _: &[u8]) -> Fate {
        Fate::Deliver
    }

    fn data_frame(f: &[u8]) -> bool {
        tcp_segment(f).is_some_and(|(_, l)| l > 0)
    }

    #[test]
    fn reordered_segments_are_reassembled_without_retransmission() {
        // Every fourth data segment arrives two segments late.
        let mut k = 0;
        let t = transfer(
            60_000,
            65535,
            |_, _| {},
            move |_, f| {
                if !data_frame(f) {
                    return Fate::Deliver;
                }
                k += 1;
                if k % 4 == 0 { Fate::Delay(2) } else { Fate::Deliver }
            },
            clean,
        );
        assert_eq!(t.resent, 0, "nothing was sent twice");
        assert_eq!(t.timeouts, 0);
    }

    #[test]
    fn one_lost_segment_is_the_only_one_resent() {
        let mut k = 0;
        let t = transfer(
            60_000,
            65535,
            |_, _| {},
            move |_, f| {
                if !data_frame(f) {
                    return Fate::Deliver;
                }
                k += 1;
                if k == 5 { Fate::Drop } else { Fate::Deliver }
            },
            clean,
        );
        assert_eq!(t.resent, 1, "only the hole is resent, not what followed it");
        assert_eq!(t.recoveries, 1);
        assert_eq!(t.timeouts, 0);
    }

    #[test]
    fn duplicated_frames_are_harmless() {
        let mut k = 0;
        let t = transfer(
            60_000,
            8192,
            |_, _| {},
            move |_, f| {
                k += 1;
                if data_frame(f) && k % 3 == 0 { Fate::Duplicate } else { Fate::Deliver }
            },
            |n, _| if n % 5 == 0 { Fate::Duplicate } else { Fate::Deliver },
        );
        assert_eq!(t.timeouts, 0);
        assert!(t.elapsed < Duration::from_secs(3), "{:?}", t.elapsed);
    }

    #[test]
    fn data_past_a_gap_is_held_and_delivered_in_order() {
        let (mut a, mut b, ca, cb, mut now) = connected(4096, 4096);
        // Drop the first data segment only.
        let mut first = true;
        a.set_shaper(move |_, f| if data_frame(f) && std::mem::take(&mut first) { Fate::Drop } else { Fate::Deliver });
        tcp(&mut a, ca).send(&[1; 100]).unwrap();
        run(&mut a, &mut b, &mut now, 10, |_, _| false);
        tcp(&mut a, ca).send(&[2; 100]).unwrap();
        run(&mut a, &mut b, &mut now, 10, |_, _| false);
        let rx = tcp(&mut b, cb);
        assert_eq!((rx.recv_queue(), rx.ooo.len()), (0, 1), "second segment is held");
        assert!(run(&mut a, &mut b, &mut now, 3000, |_, b| tcp(b, cb).recv_queue() == 200));
        let mut buf = [0u8; 200];
        assert_eq!(tcp(&mut b, cb).recv(&mut buf), Ok(200));
        assert!(buf[..100].iter().all(|&x| x == 1) && buf[100..].iter().all(|&x| x == 2));
        assert!(tcp(&mut b, cb).ooo.is_empty());
    }

    #[test]
    fn fin_ahead_of_data_waits_for_the_gap() {
        let (mut a, mut b, ca, cb, mut now) = connected(4096, 4096);
        let mut first = true;
        a.set_shaper(move |_, f| if data_frame(f) && std::mem::take(&mut first) { Fate::Drop } else { Fate::Deliver });
        tcp(&mut a, ca).send(&[1; 100]).unwrap();
        run(&mut a, &mut b, &mut now, 5, |_, _| false);
        tcp(&mut a, ca).send(&[2; 100]).unwrap();
        tcp(&mut a, ca).close();
        run(&mut a, &mut b, &mut now, 20, |_, _| false);
        assert_eq!(tcp(&mut b, cb).state(), State::Established, "the FIN is not taken before the data");
        assert!(run(&mut a, &mut b, &mut now, 3000, |_, b| tcp(b, cb).state() == State::CloseWait));
        let mut buf = [0u8; 300];
        assert_eq!(tcp(&mut b, cb).recv(&mut buf), Ok(200));
        assert_eq!(tcp(&mut b, cb).recv(&mut buf), Ok(0));
    }

    #[test]
    fn out_of_order_ranges_merge_and_are_bounded() {
        let mut s = TcpSocket::new(1000, 100);
        s.rcv_nxt = 100;
        s.ooo_insert(110, &[1; 10]);
        s.ooo_insert(130, &[3; 10]);
        s.ooo_insert(120, &[2; 10]);
        assert_eq!(s.ooo.len(), 1);
        assert_eq!((s.ooo[0].0, s.ooo[0].1.len()), (110, 30));
        s.ooo_insert(105, &[0; 10]);
        assert_eq!((s.ooo[0].0, s.ooo[0].1.len()), (105, 35));
        s.ooo_insert(1000, &[9; 1]);
        for i in 0..200u32 {
            s.ooo_insert(2000 + i * 2, &[0; 1]);
        }
        assert!(s.ooo.len() <= MAX_RANGES);
        s.rx.clear();
        s.ooo_insert(100, &[7; 5]);
        s.rcv_nxt = 100;
        s.ooo_drain();
        assert_eq!(s.rcv_nxt, 140, "the bytes before the gap and the merged range are taken");
    }

    #[test]
    fn slow_start_then_loss_halves_the_window() {
        let t = transfer(300_000, 65535, |_, _| {}, clean, clean);
        assert!(t.max_cwnd > 14600 * 2, "slow start opens the window: {}", t.max_cwnd);
        assert_eq!((t.recoveries, t.timeouts), (0, 0));

        let mut k = 0;
        let lossy = transfer(
            300_000,
            65535,
            |_, _| {},
            move |_, f| {
                if !data_frame(f) {
                    return Fate::Deliver;
                }
                k += 1;
                if k % 50 == 0 { Fate::Drop } else { Fate::Deliver }
            },
            clean,
        );
        assert!(lossy.recoveries >= 3, "{} recoveries", lossy.recoveries);
        assert_eq!(lossy.timeouts, 0, "fast recovery, not timeouts");
        assert!(lossy.max_cwnd < t.max_cwnd + 1, "loss caps the window");
    }

    #[test]
    fn congestion_window_state_machine() {
        let mut s = TcpSocket::new(65535, 100);
        s.snd_mss = 1000;
        s.snd_una = 5000;
        s.snd_max = 5000 + 20_000;
        s.snd_nxt = s.snd_max;
        s.cwnd = 3000;
        s.ssthresh = 5000;
        // Slow start: one MSS per ACK, however much it acknowledges.
        s.on_new_ack(5000 + 4000);
        s.snd_una += 4000;
        assert_eq!(s.cwnd, 4000);
        s.on_new_ack(s.snd_una + 1000);
        s.snd_una += 1000;
        assert_eq!(s.cwnd, 5000);
        // Congestion avoidance: one MSS per window acknowledged.
        for _ in 0..5 {
            s.on_new_ack(s.snd_una + 1000);
            s.snd_una += 1000;
        }
        assert_eq!(s.cwnd, 6000);
        // Three duplicate ACKs: ssthresh is half the flight, cwnd is that
        // plus the three segments that left the network.
        let flight = s.snd_max - s.snd_una;
        for _ in 0..3 {
            s.on_dup_ack();
        }
        assert!(s.in_recovery);
        assert_eq!((s.ssthresh, s.cwnd, s.rexmit_one), (flight / 2, flight / 2 + 3000, Some(s.snd_una)));
        s.on_dup_ack();
        assert_eq!(s.cwnd, flight / 2 + 4000, "inflated by each further duplicate");
        // A partial ACK stays in recovery and retransmits the next hole.
        s.on_new_ack(s.snd_una + 2000);
        s.snd_una += 2000;
        assert!(s.in_recovery && s.rexmit_one == Some(s.snd_una));
        // The full ACK deflates to ssthresh.
        s.on_new_ack(s.snd_max);
        assert!(!s.in_recovery);
        assert_eq!(s.cwnd, s.ssthresh);
        // A timeout starts over from one segment.
        s.snd_una = s.snd_max - 8000;
        s.on_timeout();
        assert_eq!((s.cwnd, s.ssthresh), (1000, 4000));
        // And a third duplicate ACK right after cannot start a recovery
        // for data sent before the timeout (RFC 6582).
        s.dup_acks = 2;
        s.on_dup_ack();
        assert!(!s.in_recovery);
    }

    #[test]
    fn window_scaling_opens_large_windows() {
        let (a, b, ca, cb, _) = connected(1 << 20, 4096);
        assert_eq!(tcp_ws(&a, ca), (true, 5, 5), "1 MiB needs a shift of 5");
        let _ = (b, cb);
        // A transfer that needs far more than 64 KiB in flight to be fast.
        let t = transfer(1_000_000, 1 << 20, |_, _| {}, clean, clean);
        assert!(t.max_cwnd > 65535, "window above 64 KiB used: {}", t.max_cwnd);
        assert!(t.elapsed < Duration::from_secs(5), "{:?}", t.elapsed);
    }

    fn tcp_ws(h: &Host, s: SocketHandle) -> (bool, u8, u8) {
        let s = h.sockets.get::<TcpSocket>(s);
        (s.ws_active, s.snd_shift, s.rcv_shift)
    }

    #[test]
    fn window_scaling_is_off_unless_both_ends_offer_it() {
        let mut rng = crate::rng::Rng::new(1);
        let mut s = half_open(&mut rng, &syn(None));
        assert_eq!((s.ws_active, s.snd_shift, s.rcv_shift, s.sack_ok), (false, 0, 0, false));
        let mut out = Vec::new();
        let mut cx = Cx {
            now: Instant::ZERO,
            addr: Some(B_IP),
            mac: Default::default(),
            mss: 1460,
            mss6: 1440,
            addr6: None,
            link_local6: None,
            rng: &mut rng,
        };
        s.dispatch(&mut cx, &mut out);
        let (h, _) = TcpHeader::parse(&out[0].payload, B_IP, PEER.ip()).unwrap();
        assert_eq!((h.wscale, h.sack_permitted), (None, false), "the SYN-ACK answers only what was offered");

        let offer = TcpHeader { wscale: Some(9), sack_permitted: true, ..syn(None) };
        let mut s = half_open(&mut rng, &offer);
        assert_eq!((s.ws_active, s.snd_shift, s.sack_ok), (true, 9, true));
        out.clear();
        let mut cx = Cx {
            now: Instant::ZERO,
            addr: Some(B_IP),
            mac: Default::default(),
            mss: 1460,
            mss6: 1440,
            addr6: None,
            link_local6: None,
            rng: &mut rng,
        };
        s.dispatch(&mut cx, &mut out);
        let (h, _) = TcpHeader::parse(&out[0].payload, B_IP, PEER.ip()).unwrap();
        assert_eq!((h.wscale, h.sack_permitted), (Some(0), true));
        let big = TcpHeader { wscale: Some(40), ..syn(None) };
        assert_eq!(half_open(&mut rng, &big).snd_shift, MAX_SHIFT, "shifts are capped");
    }

    #[test]
    fn large_buffers_without_scaling_advertise_65535() {
        let mut rng = crate::rng::Rng::new(1);
        let mut s = half_open(&mut rng, &syn(None));
        s.rx_cap = 1 << 20;
        assert_eq!(s.rx_window(), 65535);
        let seg = s.segment(TCP_ACK);
        assert_eq!(seg.window, 65535);
    }

    /// Frames of one flight lost together: SACK resends exactly those.
    fn burst_loss(sack: bool) -> Transfer {
        let mut k = 0;
        transfer(
            200_000,
            65535,
            move |a, b| {
                a.sack_enabled = sack;
                b.sack_enabled = sack;
            },
            move |_, f| {
                if !data_frame(f) {
                    return Fate::Deliver;
                }
                k += 1;
                // Segments 30, 32, 34 and 36 of the first pass.
                if matches!(k, 30 | 32 | 34 | 36) { Fate::Drop } else { Fate::Deliver }
            },
            clean,
        )
    }

    #[test]
    fn sack_recovers_several_holes_in_one_round_trip() {
        let with = burst_loss(true);
        assert_eq!(with.resent, 4, "exactly the four lost segments are resent");
        assert_eq!((with.recoveries, with.timeouts), (1, 0));
        let without = burst_loss(false);
        assert!(without.resent >= 4);
        assert!(with.elapsed <= without.elapsed, "{:?} vs {:?}", with.elapsed, without.elapsed);
    }

    #[test]
    fn sack_blocks_are_reported_and_scoreboard_tracks_them() {
        let (mut a, mut b, ca, cb, mut now) = connected(8192, 8192);
        assert!(tcp(&mut a, ca).sack_ok && tcp(&mut b, cb).sack_ok);
        let mut n = 0;
        a.set_shaper(move |_, f| {
            if !data_frame(f) {
                return Fate::Deliver;
            }
            n += 1;
            if n == 1 || n == 3 { Fate::Drop } else { Fate::Deliver }
        });
        tcp(&mut a, ca).send(&[7; 5 * 1460]).unwrap();
        run(&mut a, &mut b, &mut now, 30, |_, _| false);
        let sender = tcp(&mut a, ca);
        assert!(sender.in_recovery || sender.scoreboard.len() <= 2);
        let rcv_nxt_gap = tcp(&mut b, cb).ooo.len();
        assert!(rcv_nxt_gap <= 2);
        assert!(run(&mut a, &mut b, &mut now, 3000, |_, b| tcp(b, cb).recv_queue() == 5 * 1460));
    }

    #[test]
    fn timestamps_are_negotiated() {
        let (mut a, mut b, ca, cb, _) = connected(1024, 1024);
        assert!(tcp(&mut a, ca).has_timestamps() && tcp(&mut b, cb).has_timestamps());
        // 1500 less IP, TCP and the 12 bytes of option.
        assert_eq!(tcp(&mut a, ca).snd_mss, 1500 - 40 - 12);
        assert_eq!(tcp(&mut b, cb).snd_mss, 1500 - 40 - 12);

        // One side without them: neither uses them.
        let (mut a, mut b) = pair();
        let ca = a.sockets.add(TcpSocket::new(1024, 1024));
        let cb = b.sockets.add(TcpSocket::new(1024, 1024));
        tcp(&mut a, ca).ts_enabled = false;
        tcp(&mut b, cb).listen(80).unwrap();
        tcp(&mut a, ca).connect(sa(B_IP, 80), 0).unwrap();
        let mut now = Instant::ZERO;
        assert!(run(&mut a, &mut b, &mut now, 1000, |a, b| {
            tcp(a, ca).state() == State::Established && tcp(b, cb).state() == State::Established
        }));
        assert!(!tcp(&mut a, ca).has_timestamps() && !tcp(&mut b, cb).has_timestamps());
        assert_eq!(tcp(&mut b, cb).snd_mss, 1500 - 40);
        tcp(&mut a, ca).send(b"plain").unwrap();
        assert!(run(&mut a, &mut b, &mut now, 100, |_, b| tcp(b, cb).can_recv()));
    }

    #[test]
    fn paws_drops_old_segments() {
        let (mut a, mut b, ca, cb, mut now) = connected(1024, 1024);
        tcp(&mut a, ca).send(b"one").unwrap();
        assert!(run(&mut a, &mut b, &mut now, 100, |_, b| tcp(b, cb).can_recv()));
        let mut buf = [0u8; 16];
        assert_eq!(tcp(&mut b, cb).recv(&mut buf), Ok(3));

        let sock = tcp(&mut b, cb);
        let (local, remote) = (sock.local, sock.remote);
        let recent = sock.ts_recent;
        let mut rng = crate::rng::Rng::new(1);
        let mut segment = |sock: &mut TcpSocket, now: Instant, ts: Option<(u32, u32)>, data: &[u8]| {
            let seg = TcpHeader {
                src_port: remote.port(),
                dst_port: local.port(),
                seq: sock.rcv_nxt,
                ack: sock.snd_nxt,
                flags: TCP_ACK,
                window: 1000,
                timestamps: ts,
                ..TcpHeader::default()
            };
            let addr = match local.ip() {
                IpAddr::V4(a) => Some(a),
                IpAddr::V6(_) => None,
            };
            let mut cx = Cx {
                now,
                addr,
                mac: Default::default(),
                mss: 1460,
                mss6: 1440,
                addr6: None,
                link_local6: None,
                rng: &mut rng,
            };
            sock.process(&mut cx, local, remote, &seg, data);
            sock.recv_queue()
        };
        assert_eq!(segment(sock, now, Some((recent.wrapping_sub(1), 0)), b"old"), 0, "older than TS.Recent");
        assert_eq!(segment(sock, now, None, b"bare"), 0, "no timestamp on a timestamped connection");
        assert_eq!(segment(sock, now, Some((recent.wrapping_add(1), 0)), b"new"), 3);
        assert_eq!(sock.ts_recent, recent.wrapping_add(1));
        // After 24 days of silence TS.Recent is not trusted.
        let later = now + TS_RECENT_LIFE;
        assert_eq!(segment(sock, later, Some((recent.wrapping_sub(5), 0)), b"!"), 4);
    }

    #[test]
    fn timestamp_echo_samples_the_round_trip() {
        let mut s = TcpSocket::new(1024, 1024);
        s.clock = Instant::from_millis(1000);
        s.sample_echo(s.tsval().wrapping_sub(50));
        assert_eq!(s.srtt, Some((Duration::from_millis(50), Duration::from_millis(25))));
        // An echo from the future or from long ago is not a round trip.
        s.sample_echo(s.tsval().wrapping_add(5));
        s.sample_echo(s.tsval().wrapping_sub(MAX_TS_RTT + 1));
        assert_eq!(s.srtt, Some((Duration::from_millis(50), Duration::from_millis(25))));
    }

    #[test]
    fn timestamped_transfer_survives_loss() {
        let (mut a, mut b, ca, cb, mut now) = connected(8192, 8192);
        a.set_filter(|n, _| n % 7 != 3);
        let data: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
        let (mut sent, mut got) = (0, Vec::new());
        assert!(run(&mut a, &mut b, &mut now, 60_000, |a, b| {
            sent += tcp(a, ca).send(&data[sent..]).unwrap_or(0);
            let mut buf = [0u8; 2048];
            while let Ok(n @ 1..) = tcp(b, cb).recv(&mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
            got.len() == data.len()
        }));
        assert_eq!(got, data);
        assert!(tcp(&mut a, ca).srtt.is_some());
    }
}
