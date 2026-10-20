//! TCP connections (RFC 9293), with RFC 6298 retransmission timing.
//!
//! A listening socket takes a single connection: on a SYN it turns into
//! that connection. A server that wants several at once listens with
//! several sockets on the same port.
//!
//! Received data is accepted only in order; a segment past a gap is dropped
//! and re-acknowledged, and the peer's retransmission fills the gap. Lost
//! data of our own is resent go-back-N from the oldest unacknowledged byte,
//! on a timeout or after three duplicate ACKs. There is no congestion
//! control beyond that: the sender fills the peer's window.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::time::Duration;

use super::{Cx, Packet, binds};
use crate::wire::{PROTO_TCP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TcpHeader};
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
/// Segments sent per poll.
const MAX_BURST: usize = 16;

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
    local: SocketAddrV4,
    remote: SocketAddrV4,
    /// The SYN is still to be built: [`connect`](Self::connect) was called
    /// but the interface has not assigned the address, port and ISS yet.
    fresh: bool,
    /// The connection came from [`listen`](Self::listen); a reset in
    /// SYN-RECEIVED returns it to LISTEN.
    passive: bool,

    rx: VecDeque<u8>,
    rx_cap: usize,
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
}

impl TcpSocket {
    /// A closed socket with `rx_cap` and `tx_cap` bytes of buffering. The
    /// receive buffer bounds the advertised window, so at most 65535 of it
    /// is used.
    pub fn new(rx_cap: usize, tx_cap: usize) -> Self {
        Self {
            state: State::Closed,
            local: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            remote: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            fresh: false,
            passive: false,
            rx: VecDeque::new(),
            rx_cap: rx_cap.min(65535),
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
        }
    }

    fn reset(&mut self) {
        *self = Self::new(self.rx_cap, self.tx_cap);
    }

    /// Waits for a connection to `port` on any address of the interface.
    pub fn listen(&mut self, port: u16) -> Result<(), Error> {
        if port == 0 {
            return Err(Error::InvalidAddress);
        }
        if self.state != State::Closed {
            return Err(Error::InvalidState);
        }
        self.reset();
        self.local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        self.state = State::Listen;
        self.passive = true;
        Ok(())
    }

    /// Opens a connection to `remote` from `local_port`, or from an
    /// ephemeral port if it is 0. The SYN goes out on the next poll;
    /// [`state`](Self::state) reaches [`State::Established`] when the peer
    /// accepts, and [`error`](Self::error) says why if it does not.
    pub fn connect(&mut self, remote: SocketAddrV4, local_port: u16) -> Result<(), Error> {
        if remote.port() == 0 || remote.ip().is_unspecified() || remote.ip().is_broadcast() {
            return Err(Error::InvalidAddress);
        }
        if self.state != State::Closed {
            return Err(Error::InvalidState);
        }
        self.reset();
        self.local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port);
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

    /// Returns true while the connection is established in both directions
    /// or the peer has closed its side but ours is still open.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait)
    }

    /// Our end of the connection.
    pub fn local_endpoint(&self) -> SocketAddrV4 {
        self.local
    }

    /// The peer's end of the connection.
    pub fn remote_endpoint(&self) -> SocketAddrV4 {
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
        if self.adv_wnd < self.rx_cap as u32 / 2 && self.rx_window() >= self.rx_cap as u32 / 2 {
            self.ack_pending = true;
        }
        Ok(n)
    }

    fn rx_window(&self) -> u32 {
        (self.rx_cap - self.rx.len()) as u32
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
    pub(crate) fn accepts_exact(&self, dst: SocketAddrV4, src: SocketAddrV4) -> bool {
        !matches!(self.state, State::Closed | State::Listen) && self.local == dst && self.remote == src
    }

    /// Returns true if the socket listens for connections to `dst`.
    pub(crate) fn accepts_listen(&self, dst: SocketAddrV4) -> bool {
        self.state == State::Listen && binds(self.local, dst)
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
        dst: SocketAddrV4,
        src: SocketAddrV4,
        seg: &TcpHeader,
        payload: &[u8],
    ) -> Option<TcpHeader> {
        let now = cx.now;
        match self.state {
            State::Closed => return None,
            State::Listen => {
                if seg.has(TCP_RST) {
                    return None;
                }
                if seg.has(TCP_ACK) || !seg.has(TCP_SYN) {
                    return reset_for(seg, payload.len());
                }
                self.local = dst;
                self.remote = src;
                self.rcv_nxt = seg.seq.wrapping_add(1);
                self.iss = cx.rng.next_u32();
                self.set_iss(self.iss);
                self.snd_wnd = u32::from(seg.window);
                self.snd_wl1 = seg.seq;
                self.snd_mss = usize::from(seg.mss.unwrap_or(DEFAULT_MSS as u16)).min(usize::from(cx.mss));
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
                self.snd_mss = usize::from(seg.mss.unwrap_or(DEFAULT_MSS as u16)).min(usize::from(cx.mss));
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
                let port = self.local.port();
                self.reset();
                self.local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
                self.state = State::Listen;
                self.passive = true;
            } else if matches!(self.state, State::Closing | State::LastAck | State::TimeWait) {
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

        if !seg.has(TCP_ACK) {
            return None;
        }
        if self.state == State::SynReceived {
            if !(before(self.snd_una, seg.ack) && before_eq(seg.ack, self.snd_max)) {
                return reset_for(seg, payload.len());
            }
            self.state = State::Established;
            self.snd_wnd = u32::from(seg.window);
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
        }
        if before(self.snd_max, seg.ack) {
            // Acknowledges something never sent.
            self.ack_pending = true;
            return None;
        }
        if before(self.snd_una, seg.ack) {
            self.ack_received(seg.ack, now);
            self.dup_acks = 0;
        } else if seg.ack == self.snd_una
            && payload.is_empty()
            && !seg.has(TCP_FIN)
            && self.snd_una != self.snd_max
            && u32::from(seg.window) == self.snd_wnd
        {
            // Fast retransmit (RFC 5681 3.2): a third duplicate ACK means a
            // segment was lost, not merely delayed.
            self.dup_acks += 1;
            if self.dup_acks == 3 {
                self.snd_nxt = self.snd_una;
                self.rtt_sample = None;
            }
        }
        if before(self.snd_wl1, seg.seq) || (self.snd_wl1 == seg.seq && before_eq(self.snd_wl2, seg.ack)) {
            self.snd_wnd = u32::from(seg.window);
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
                // Skip what we already have, then take what fits.
                let skip = if before(seg.seq, self.rcv_nxt) { self.rcv_nxt.wrapping_sub(seg.seq) as usize } else { 0 };
                if seg.seq.wrapping_add(skip as u32) == self.rcv_nxt && skip <= payload.len() {
                    let data = &payload[skip..];
                    let take = data.len().min(self.rx_window() as usize);
                    self.rx.extend(&data[..take]);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
                    fin_ok = take == data.len();
                } else {
                    // Out of order: acknowledge at once, so that the sender
                    // sees one duplicate ACK per segment (RFC 5681 4.2).
                    self.adv_wnd = self.rx_window();
                    return Some(self.segment(TCP_ACK));
                }
            }
            self.ack_pending = true;
        }

        if seg.has(TCP_FIN) {
            let fin_seq = seg.seq.wrapping_add(payload.len() as u32);
            match self.state {
                State::Established | State::FinWait1 | State::FinWait2 if fin_ok && fin_seq == self.rcv_nxt => {
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
                State::TimeWait => self.enter_time_wait(now),
                _ => {}
            }
            self.ack_pending = true;
        }
        None
    }

    fn set_iss(&mut self, iss: u32) {
        self.iss = iss;
        self.tx_seq = iss.wrapping_add(1);
        self.snd_una = iss;
        self.snd_nxt = iss;
        self.snd_max = iss;
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
                let window_left = self.snd_una.wrapping_add(self.snd_wnd).wrapping_sub(self.snd_nxt) as i32 > 0;
                let data = offset < self.tx.len() && window_left;
                let fin = self.fin_queued && offset == self.tx.len();
                if self.ack_pending || data || fin { Some(Instant::ZERO) } else { self.timer }
            }
        }
    }

    fn segment(&self, flags: u8) -> TcpHeader {
        TcpHeader {
            src_port: self.local.port(),
            dst_port: self.remote.port(),
            seq: self.snd_nxt,
            ack: if flags & TCP_ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: self.rx_window().min(65535) as u16,
            mss: None,
        }
    }

    fn emit(&mut self, header: TcpHeader, payload: &[u8], out: &mut Vec<Packet>) {
        self.adv_wnd = u32::from(header.window);
        let segment = header.emit(*self.local.ip(), *self.remote.ip(), payload);
        out.push(Packet { src: *self.local.ip(), dst: *self.remote.ip(), protocol: PROTO_TCP, payload: segment });
    }

    pub(crate) fn dispatch(&mut self, cx: &mut Cx, out: &mut Vec<Packet>) {
        let now = cx.now;
        match self.state {
            State::Closed => {
                if let Some(rst) = self.rst_pending.take() {
                    let segment = rst.emit(*self.local.ip(), *self.remote.ip(), &[]);
                    out.push(Packet {
                        src: *self.local.ip(),
                        dst: *self.remote.ip(),
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
            let Some(addr) = cx.addr else { return };
            self.local.set_ip(addr);
            if self.local.port() == 0 {
                self.local.set_port(cx.rng.ephemeral_port());
            }
            self.set_iss(cx.rng.next_u32());
            self.fresh = false;
        }

        if self.timer.is_some_and(|t| now >= t) {
            self.timer = None;
            self.retries += 1;
            if self.retries > MAX_RETRIES {
                self.fail(Error::TimedOut);
                return;
            }
            self.rto = (self.rto * 2).min(MAX_RTO);
            // Karn's algorithm: never time a retransmitted segment.
            self.rtt_sample = None;
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
                syn.mss = Some(cx.mss);
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

        for _ in 0..MAX_BURST {
            let offset = self.snd_nxt.wrapping_sub(self.tx_seq) as usize;
            if offset > self.tx.len() {
                break; // the FIN is out
            }
            let unsent = self.tx.len() - offset;
            let wnd = if self.probe { self.snd_wnd.max(1) } else { self.snd_wnd };
            let window = (self.snd_una.wrapping_add(wnd).wrapping_sub(self.snd_nxt) as i32).max(0) as usize;
            let len = unsent.min(window).min(self.snd_mss);
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
    use crate::testing::{B_IP, Host, pair, run};
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
        tcp(&mut a, ca).connect(SocketAddrV4::new(B_IP, 80), 0).unwrap();
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
        assert!(slow < Duration::from_secs(2), "fast retransmit: {slow:?}");
    }

    #[test]
    fn refused() {
        let (mut a, mut b) = pair();
        let ca = a.sockets.add(TcpSocket::new(64, 64));
        tcp(&mut a, ca).connect(SocketAddrV4::new(B_IP, 81), 5000).unwrap();
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
        let mut cx = Cx { now: Instant::ZERO, addr: Some(B_IP), mac: Default::default(), mss: 1460, rng: &mut rng };
        let dst = SocketAddrV4::new(B_IP, 80);
        let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 9), 4000);
        let ack =
            TcpHeader { src_port: 4000, dst_port: 80, seq: 1, ack: 99, flags: wire::TCP_ACK, ..Default::default() };
        let rst = s.process(&mut cx, dst, src, &ack, &[]).unwrap();
        assert_eq!((rst.seq, rst.flags), (99, TCP_RST));
        assert_eq!(s.state(), State::Listen);
    }
}
