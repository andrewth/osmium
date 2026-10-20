//! An iSCSI session over one TCP connection: login, commands in the full
//! feature phase, and logout.
//!
//! The session runs at error recovery level 0 with one command
//! outstanding: it sends a command, then pumps the network until the
//! target's status arrives, answering R2Ts with Data-Out and target pings
//! (NOP-In) with NOP-Out along the way. Any protocol failure drops the
//! session; a SCSI error status does not.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddrV4;
use core::time::Duration;

use osmium_net::{Instant, SocketHandle, TcpSocket, TcpState};

use crate::chap::{self, Chap};
use crate::net::Net;
use crate::params::{Negotiator, Offer, Params};
use crate::pdu::{
    DataOut, LoginRequest, LogoutRequest, Message, NopOut, PduError, PduReader, RESERVED_TAG, ScsiCommand, TextRequest,
    lun_field, sn_lt, stage,
};
use crate::scsi::{Cdb, Sense, status};
use crate::{IscsiError, text};

/// Login Request/Response exchanges, continuations included, before giving
/// up on a target that never finishes.
const MAX_LOGIN_EXCHANGES: usize = 32;

/// Text Request/Response exchanges for one SendTargets.
const MAX_TEXT_EXCHANGES: usize = 32;

/// The most text accepted in one login stage or one SendTargets reply,
/// however many PDUs it is split across.
const MAX_TEXT: usize = 64 * 1024;

/// How long closing the TCP connection may take when a session ends.
const CLOSE_TIME: Duration = Duration::from_secs(1);

/// The longest data segment accepted during login, whatever was offered
/// (the login-phase default, RFC 7143 §13.12).
const LOGIN_DSL: usize = 8192;

/// How to log in.
#[derive(Clone, Debug)]
pub struct Options {
    /// Our iSCSI name, e.g. `iqn.2026-10.org.osmium:host`.
    pub initiator_name: String,
    /// The target to log in to, e.g. `iqn.2026-10.org.osmium:disk0`.
    /// Discovery ignores it.
    pub target_name: String,
    /// The logical unit to drive.
    pub lun: u16,
    /// The initiator session ID. Concurrent sessions from one initiator to
    /// one target need distinct values.
    pub isid: [u8; 6],
    /// How long each step may take: connecting, the whole login, one
    /// command (from issue to status, however the target paces its data),
    /// one SendTargets, one logout.
    pub timeout: Duration,
    /// The operational parameters to ask for.
    pub offer: Offer,
    /// CHAP credentials. With them, the login must authenticate (the target
    /// that offers no CHAP is refused); without, AuthMethod=None.
    pub chap: Option<Chap>,
    /// TCP receive buffer, in bytes (at most 65535 is used).
    pub rx_buffer: usize,
    /// TCP send buffer, in bytes.
    pub tx_buffer: usize,
}

impl Options {
    /// Options to reach `target_name`'s LUN 0 as `initiator_name`, with a
    /// ten-second timeout and the default [`Offer`].
    pub fn new(initiator_name: &str, target_name: &str) -> Self {
        Self {
            initiator_name: initiator_name.into(),
            target_name: target_name.into(),
            lun: 0,
            // Random format (type 10b), fixed bits: one session per target.
            isid: [0x80, 0x6f, 0x73, 0x6d, 0x00, 0x01],
            timeout: Duration::from_secs(10),
            offer: Offer::default(),
            chap: None,
            rx_buffer: 65535,
            tx_buffer: 65536,
        }
    }
}

/// The data stage of a SCSI command.
pub enum Data<'buf> {
    /// No data.
    None,
    /// The target sends data into this buffer.
    In(&'buf mut [u8]),
    /// The target receives this data.
    Out(&'buf [u8]),
}

/// The U and O flags and residual count of a command's status.
#[derive(Clone, Copy)]
struct Residual {
    underflow: bool,
    overflow: bool,
    count: u32,
}

/// Where a CHAP login stands.
#[derive(Clone, Copy)]
enum Auth {
    /// Waiting for the target to agree to CHAP.
    Method,
    /// Waiting for its challenge.
    Algorithm,
    /// Our answer is out; waiting for the target to accept it. Mutual CHAP
    /// holds the response we expect from the target.
    Response(Option<[u8; 16]>),
    /// Authenticated, or no authentication wanted.
    Done,
}

/// A TCP connection carrying PDUs. Dropping it closes the connection and
/// removes its socket.
struct Conn<N: Net> {
    net: N,
    socket: SocketHandle,
    reader: PduReader,
    timeout: Duration,
    /// CRC32C digests on the PDUs we send, once negotiated.
    header_digest: bool,
    data_digest: bool,
}

impl<N: Net> Conn<N> {
    /// Connects to `target` and waits until the connection is established.
    fn open(mut net: N, target: SocketAddrV4, opts: &Options) -> Result<Self, IscsiError> {
        let socket = net.with_sockets(|s| s.add(TcpSocket::new(opts.rx_buffer, opts.tx_buffer)));
        let mut c = Self {
            net,
            socket,
            reader: PduReader::new(LOGIN_DSL),
            timeout: opts.timeout,
            header_digest: false,
            data_digest: false,
        };
        c.tcp(|t| t.connect(target, 0))?;
        let deadline = c.deadline();
        loop {
            let (state, error) = c.tcp(|t| (t.state(), t.error()));
            match (state, error) {
                (TcpState::Established, _) => return Ok(c),
                (_, Some(e)) => return Err(e.into()),
                (TcpState::Closed, None) => return Err(IscsiError::Closed),
                _ => c.pump(deadline)?,
            }
        }
    }

    fn tcp<R>(&mut self, f: impl FnOnce(&mut TcpSocket) -> R) -> R {
        let h = self.socket;
        self.net.with_sockets(|s| f(s.get_mut::<TcpSocket>(h)))
    }

    /// When a wait starting now times out.
    fn deadline(&mut self) -> Instant {
        self.net.poll() + self.timeout
    }

    /// Polls the network once, failing if `deadline` has passed.
    fn pump(&mut self, deadline: Instant) -> Result<(), IscsiError> {
        if self.net.poll() >= deadline { Err(IscsiError::TimedOut) } else { Ok(()) }
    }

    /// Queues `m` on the connection, waiting until `deadline` for room in
    /// the send buffer.
    fn send(&mut self, m: Message, deadline: Instant) -> Result<(), IscsiError> {
        let bytes = m.encode().to_bytes_with(self.header_digest, self.data_digest);
        let mut sent = 0;
        while sent < bytes.len() {
            match self.tcp(|t| t.send(&bytes[sent..])) {
                Ok(n) => sent += n,
                Err(osmium_net::Error::WouldBlock) => self.pump(deadline)?,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// The next PDU from the target.
    fn recv(&mut self, deadline: Instant) -> Result<Message, IscsiError> {
        loop {
            let next = self.reader.next_pdu().map_err(|e| match e {
                PduError::Digest => IscsiError::Digest,
                _ => IscsiError::Protocol("data segment too long"),
            })?;
            if let Some(pdu) = next {
                return Message::decode(pdu).map_err(|_| IscsiError::Protocol("unexpected opcode"));
            }
            let mut buf = [0u8; 2048];
            match self.tcp(|t| t.recv(&mut buf)) {
                Ok(0) | Err(osmium_net::Error::InvalidState) => return Err(IscsiError::Closed),
                Ok(n) => self.reader.push(&buf[..n]),
                Err(osmium_net::Error::WouldBlock) => self.pump(deadline)?,
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl<N: Net> Drop for Conn<N> {
    fn drop(&mut self) {
        self.tcp(TcpSocket::close);
        // Give our FIN a moment to be acknowledged, then reset whatever is
        // left rather than linger in TIME-WAIT.
        let deadline = self.net.poll() + CLOSE_TIME.min(self.timeout);
        while !matches!(self.tcp(|t| t.state()), TcpState::Closed | TcpState::FinWait2 | TcpState::TimeWait)
            && self.net.poll() < deadline
        {}
        self.tcp(TcpSocket::abort);
        self.net.poll();
        let h = self.socket;
        self.net.with_sockets(|s| s.remove(h));
    }
}

/// A logged-in session. Dropping it logs out.
pub(crate) struct Session<N: Net> {
    conn: Conn<N>,
    params: Params,
    isid: [u8; 6],
    tsih: u16,
    lun: [u8; 8],
    /// The CmdSN of the next non-immediate command.
    cmd_sn: u32,
    exp_stat_sn: u32,
    /// The first Login Response has set `exp_stat_sn`.
    stat_sn_known: bool,
    /// The highest CmdSN the target accepts now.
    max_cmd_sn: u32,
    itt: u32,
    /// Logged in and in step with the target.
    open: bool,
}

impl<N: Net> Session<N> {
    /// Connects to `target` and logs in: to `opts.target_name` in a normal
    /// session, or to a discovery session if `discovery`.
    pub(crate) fn login(net: N, target: SocketAddrV4, opts: &Options, discovery: bool) -> Result<Self, IscsiError> {
        let mut s = Self {
            conn: Conn::open(net, target, opts)?,
            params: Params::default(),
            isid: opts.isid,
            tsih: 0,
            lun: lun_field(opts.lun),
            cmd_sn: 1,
            exp_stat_sn: 0,
            stat_sn_known: false,
            max_cmd_sn: 1,
            itt: 0,
            open: false,
        };
        s.negotiate(opts, discovery)?;
        // From now on the target's segments are bounded by what we declared.
        s.conn.reader.set_max_data(s.params.max_recv_data_segment_length as usize);
        // Digests start with the full feature phase.
        let p = &s.params;
        s.conn.header_digest = p.header_digest;
        s.conn.data_digest = p.data_digest;
        s.conn.reader.set_digests(p.header_digest, p.data_digest);
        s.open = true;
        Ok(s)
    }

    pub(crate) fn params(&self) -> &Params {
        &self.params
    }

    pub(crate) fn net(&mut self) -> &mut N {
        &mut self.conn.net
    }

    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    fn next_itt(&mut self) -> u32 {
        self.itt = self.itt.wrapping_add(1);
        if self.itt == RESERVED_TAG {
            self.itt = 0;
        }
        self.itt
    }

    /// The login exchange (RFC 7143 §6.3): SecurityNegotiation with
    /// AuthMethod=None (or CHAP, in three rounds, RFC 7143 §12.1), then LoginOperationalNegotiation, then the full
    /// feature phase. The target may hold us in a stage for more rounds,
    /// split its text across responses, or offer keys of its own.
    fn negotiate(&mut self, opts: &Options, discovery: bool) -> Result<(), IscsiError> {
        let deadline = self.conn.deadline();
        let mut neg = Negotiator::new(opts.offer.clone());
        let itt = self.next_itt();
        let target_name = (!discovery).then_some(opts.target_name.as_str());
        let mut keys = neg.security_keys(&opts.initiator_name, target_name, opts.chap.is_some());
        let mut auth = if opts.chap.is_some() { Auth::Method } else { Auth::Done };
        let mut current = stage::SECURITY;
        let mut operational_sent = false;
        let mut exchanges = 0;
        loop {
            let next = if current == stage::SECURITY { stage::OPERATIONAL } else { stage::FULL_FEATURE };
            // CHAP takes several rounds in SecurityNegotiation before we may
            // move on.
            let transit = current != stage::SECURITY || matches!(auth, Auth::Response(_) | Auth::Done);
            let mut req = LoginRequest {
                transit,
                cont: false,
                csg: current,
                nsg: next,
                isid: self.isid,
                tsih: 0,
                itt,
                cid: 0,
                cmd_sn: self.cmd_sn,
                exp_stat_sn: self.exp_stat_sn,
                data: core::mem::take(&mut keys),
            };
            let mut text = Vec::new();
            let resp = loop {
                // Continuations count too: a target that always has more
                // text must not keep us here.
                exchanges += 1;
                if exchanges > MAX_LOGIN_EXCHANGES {
                    return Err(IscsiError::Protocol("login did not finish"));
                }
                self.conn.send(Message::LoginRequest(req.clone()), deadline)?;
                let msg = self.conn.recv(deadline)?;
                self.absorb(&msg)?;
                let Message::LoginResponse(r) = msg else {
                    return Err(IscsiError::Protocol("expected a Login Response"));
                };
                if r.status_class != 0 {
                    return Err(IscsiError::Login { class: r.status_class, detail: r.status_detail });
                }
                if r.itt != itt || r.csg != current {
                    return Err(IscsiError::Protocol("Login Response out of step"));
                }
                if text.len() + r.data.len() > MAX_TEXT {
                    return Err(IscsiError::Protocol("login text too long"));
                }
                text.extend_from_slice(&r.data);
                if !r.cont {
                    break r;
                }
                // The target has more text: an empty request fetches it.
                req = LoginRequest {
                    transit: false,
                    data: Vec::new(),
                    cmd_sn: self.cmd_sn,
                    exp_stat_sn: self.exp_stat_sn,
                    ..req
                };
            };
            keys = neg.respond(&text)?;
            if current == stage::SECURITY
                && let Some(chap) = &opts.chap
            {
                let pairs = text::parse(&text).ok_or(IscsiError::Protocol("malformed login text"))?;
                match auth {
                    Auth::Method if !resp.transit => {
                        keys.extend_from_slice(&chap::start());
                        auth = Auth::Algorithm;
                    }
                    Auth::Algorithm if !resp.transit => {
                        let (answer, expected) = chap::answer(chap, &pairs)?;
                        keys.extend_from_slice(&answer);
                        auth = Auth::Response(expected);
                    }
                    Auth::Response(expected) if resp.transit => {
                        chap::verify(chap, expected, &pairs)?;
                        auth = Auth::Done;
                    }
                    Auth::Done => {}
                    _ => return Err(IscsiError::Protocol("CHAP exchange out of step")),
                }
            }
            if resp.transit {
                // The target moves on only when we asked to, and to no
                // later stage than we asked for (RFC 7143 §6.3): never
                // from SecurityNegotiation straight to the full feature
                // phase, skipping operational negotiation.
                if !req.transit || resp.nsg != next {
                    return Err(IscsiError::Protocol("Login Response with a bad next stage"));
                }
                match resp.nsg {
                    stage::FULL_FEATURE => {
                        neg.finish()?;
                        self.tsih = resp.tsih;
                        self.params = neg.params;
                        return Ok(());
                    }
                    stage::OPERATIONAL if current == stage::SECURITY => current = stage::OPERATIONAL,
                    _ => return Err(IscsiError::Protocol("Login Response with a bad next stage")),
                }
            }
            if current == stage::OPERATIONAL && !operational_sent {
                keys.extend_from_slice(&neg.operational_keys(discovery));
                operational_sent = true;
            }
        }
    }

    /// Tracks StatSN and the command window from a target PDU.
    fn absorb(&mut self, m: &Message) -> Result<(), IscsiError> {
        // Each PDU that advances StatSN must carry the one we expect: on
        // one in-order connection at error recovery level 0 a gap or a
        // repeat means we are out of step. The first Login Response sets
        // the starting value. R2T, Data-In without status and NOP-In
        // without an ITT carry the next StatSN without advancing it.
        if let Some(sn) = m.stat_sn() {
            if self.stat_sn_known && sn != self.exp_stat_sn {
                return Err(IscsiError::Protocol("StatSN out of sequence"));
            }
            self.stat_sn_known = true;
            self.exp_stat_sn = sn.wrapping_add(1);
        }
        // A window with MaxCmdSN = ExpCmdSN - 1 is closed; anything smaller
        // is invalid and ignored, as is a MaxCmdSN that went backwards.
        if let Some((exp, max)) = m.cmd_window()
            && !sn_lt(max, exp.wrapping_sub(1))
            && (matches!(m, Message::LoginResponse(_)) || !sn_lt(max, self.max_cmd_sn))
        {
            self.max_cmd_sn = max;
        }
        Ok(())
    }

    /// Reads one PDU and deals with what needs no caller: answers target
    /// pings, skips asynchronous events. Returns the rest.
    fn recv_one(&mut self, deadline: Instant) -> Result<Option<Message>, IscsiError> {
        let m = self.conn.recv(deadline)?;
        self.absorb(&m)?;
        match m {
            Message::NopIn(n) => {
                if n.ttt != RESERVED_TAG {
                    self.conn.send(
                        Message::NopOut(NopOut {
                            immediate: true,
                            lun: n.lun,
                            itt: RESERVED_TAG,
                            ttt: n.ttt,
                            cmd_sn: self.cmd_sn,
                            exp_stat_sn: self.exp_stat_sn,
                            data: n.data,
                        }),
                        deadline,
                    )?;
                }
                Ok(None)
            }
            // 2 and 3: the target is dropping the connection or session.
            Message::AsyncMessage(a) if matches!(a.event, 2 | 3) => Err(IscsiError::Closed),
            // A SCSI event, a logout request (we log out when dropped) or
            // a vendor event.
            Message::AsyncMessage(_) => Ok(None),
            Message::Reject(r) => Err(IscsiError::Reject(r.reason)),
            m => Ok(Some(m)),
        }
    }

    fn next(&mut self, deadline: Instant) -> Result<Message, IscsiError> {
        loop {
            if let Some(m) = self.recv_one(deadline)? {
                return Ok(m);
            }
        }
    }

    /// Waits until the target's window admits the next CmdSN.
    fn wait_window(&mut self, deadline: Instant) -> Result<(), IscsiError> {
        while sn_lt(self.max_cmd_sn, self.cmd_sn) {
            if self.recv_one(deadline)?.is_some() {
                return Err(IscsiError::Protocol("unexpected PDU while idle"));
            }
        }
        Ok(())
    }

    /// Runs `f` on an open session, dropping it if `f` failed in a way
    /// that leaves us out of step with the target.
    fn guarded<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R, IscsiError>) -> Result<R, IscsiError> {
        if !self.open {
            return Err(IscsiError::NoSession);
        }
        let r = f(self);
        if let Err(e) = &r
            && !matches!(e, IscsiError::Scsi { .. } | IscsiError::Response(_))
        {
            self.open = false;
        }
        r
    }

    /// Runs one SCSI command and returns the bytes of data it moved: what
    /// the target sent for [`Data::In`], or for [`Data::Out`] the length
    /// less any residual the target reported. Either may be short.
    pub(crate) fn command(&mut self, cdb: &Cdb, data: Data<'_>) -> Result<usize, IscsiError> {
        self.guarded(|s| s.run_command(cdb, data))
    }

    fn run_command(&mut self, cdb: &Cdb, mut data: Data<'_>) -> Result<usize, IscsiError> {
        // One deadline for the whole command: a target trickling data or
        // R2Ts cannot keep it alive past the timeout.
        let deadline = self.conn.deadline();
        self.wait_window(deadline)?;
        let itt = self.next_itt();
        let p = &self.params;
        let (read, write, expected) = match &data {
            Data::None => (false, false, 0),
            Data::In(b) => (true, false, b.len()),
            Data::Out(b) => (false, true, b.len()),
        };
        let max_burst = p.max_burst_length as usize;
        // Unsolicited data, up to FirstBurstLength: immediate data in the
        // command PDU if allowed, then Data-Out PDUs unless InitialR2T.
        let (immediate, unsolicited) = match &data {
            Data::Out(b) => {
                let burst = (p.first_burst_length as usize).min(b.len());
                let imm = if p.immediate_data { burst.min(p.max_xmit_data_segment_length as usize) } else { 0 };
                (imm, if p.initial_r2t { imm } else { burst })
            }
            _ => (0, 0),
        };
        let immediate_data = match &data {
            Data::Out(b) => b[..immediate].to_vec(),
            _ => Vec::new(),
        };
        self.conn.send(
            Message::ScsiCommand(ScsiCommand {
                final_pdu: unsolicited == immediate,
                read,
                write,
                attr: 1, // SIMPLE
                lun: self.lun,
                itt,
                expected_len: expected as u32,
                cmd_sn: self.cmd_sn,
                exp_stat_sn: self.exp_stat_sn,
                cdb: *cdb,
                data: immediate_data,
            }),
            deadline,
        )?;
        self.cmd_sn = self.cmd_sn.wrapping_add(1);
        if let Data::Out(b) = &data
            && unsolicited > immediate
        {
            self.data_out(itt, RESERVED_TAG, &b[immediate..unsolicited], immediate, deadline)?;
        }

        // DataPDUInOrder and DataSequenceInOrder are Yes, with one R2T at a
        // time: Data-In arrives in order with consecutive DataSNs, and
        // each R2T asks for the data after what we have sent.
        let mut received = 0;
        let mut data_sn = 0u32;
        let mut sent = unsolicited;
        let mut r2t_sn = 0u32;
        loop {
            match self.next(deadline)? {
                Message::DataIn(d) if d.itt == itt => {
                    let Data::In(buf) = &mut data else {
                        return Err(IscsiError::Protocol("Data-In for a command without input"));
                    };
                    if d.data_sn != data_sn || d.offset as usize != received {
                        return Err(IscsiError::Protocol("Data-In out of order"));
                    }
                    let end = received + d.data.len();
                    let dst = buf.get_mut(received..end).ok_or(IscsiError::Protocol("Data-In beyond the buffer"))?;
                    dst.copy_from_slice(&d.data);
                    received = end;
                    data_sn = data_sn.wrapping_add(1);
                    if let Some(st) = d.status {
                        let residual = Residual { underflow: d.underflow, overflow: d.overflow, count: d.residual };
                        return Self::status(0, st, &[], residual, expected, read, received);
                    }
                }
                Message::R2t(r) if r.itt == itt => {
                    let Data::Out(b) = &data else {
                        return Err(IscsiError::Protocol("R2T for a command without output"));
                    };
                    if r.ttt == RESERVED_TAG || r.r2t_sn != r2t_sn || r.offset as usize != sent {
                        return Err(IscsiError::Protocol("R2T out of step"));
                    }
                    let len = r.desired_len as usize;
                    if len == 0 || len > max_burst {
                        return Err(IscsiError::Protocol("R2T length outside 1..=MaxBurstLength"));
                    }
                    let chunk = b.get(sent..sent + len).ok_or(IscsiError::Protocol("R2T beyond the buffer"))?;
                    self.data_out(itt, r.ttt, chunk, sent, deadline)?;
                    sent += len;
                    r2t_sn = r2t_sn.wrapping_add(1);
                }
                Message::ScsiResponse(r) if r.itt == itt => {
                    let residual = Residual { underflow: r.underflow, overflow: r.overflow, count: r.residual };
                    let moved = if read { received } else { sent };
                    return Self::status(r.response, r.status, &r.data, residual, expected, read, moved);
                }
                _ => return Err(IscsiError::Protocol("unexpected PDU during a command")),
            }
        }
    }

    /// The outcome of a command from its response code, status and
    /// residual. `moved` is the data that crossed the wire: for a read the
    /// residual must account for exactly the bytes not received, and a
    /// write cannot have used data we never sent. Returns the bytes the
    /// target transferred, which is less than `expected` on an underflow.
    fn status(
        response: u8,
        st: u8,
        sense: &[u8],
        residual: Residual,
        expected: usize,
        read: bool,
        moved: usize,
    ) -> Result<usize, IscsiError> {
        match (response, st) {
            (0, status::GOOD | status::CONDITION_MET) => {}
            (0, status) => {
                return Err(IscsiError::Scsi {
                    status,
                    sense: if status == status::CHECK_CONDITION { Sense::from_response(sense) } else { None },
                });
            }
            (r, _) => return Err(IscsiError::Response(r)),
        }
        let transferred = match (residual.underflow, residual.overflow) {
            (true, true) => return Err(IscsiError::Protocol("both underflow and overflow")),
            (true, false) => expected
                .checked_sub(residual.count as usize)
                .ok_or(IscsiError::Protocol("residual beyond the expected length"))?,
            // An overflow leaves the whole expected length transferred.
            _ => expected,
        };
        if (read && transferred != moved) || (!read && transferred > moved) {
            return Err(IscsiError::Protocol("residual does not match the data moved"));
        }
        Ok(transferred)
    }

    /// Sends one data sequence, `data` at buffer offset `offset`, in
    /// Data-Out PDUs no larger than the target accepts.
    fn data_out(
        &mut self,
        itt: u32,
        ttt: u32,
        data: &[u8],
        offset: usize,
        deadline: Instant,
    ) -> Result<(), IscsiError> {
        let seg = (self.params.max_xmit_data_segment_length as usize).max(1);
        let count = data.len().div_ceil(seg);
        for (i, chunk) in data.chunks(seg).enumerate() {
            self.conn.send(
                Message::DataOut(DataOut {
                    final_pdu: i + 1 == count,
                    lun: self.lun,
                    itt,
                    ttt,
                    exp_stat_sn: self.exp_stat_sn,
                    data_sn: i as u32,
                    offset: (offset + i * seg) as u32,
                    data: chunk.to_vec(),
                }),
                deadline,
            )?;
        }
        Ok(())
    }

    /// Sends `SendTargets=All` and returns the target's text.
    pub(crate) fn send_targets(&mut self) -> Result<Vec<u8>, IscsiError> {
        self.guarded(|s| {
            let deadline = s.conn.deadline();
            let itt = s.next_itt();
            let mut ttt = RESERVED_TAG;
            let mut keys = Vec::new();
            text::push(&mut keys, "SendTargets", "All");
            let mut out = Vec::new();
            for _ in 0..MAX_TEXT_EXCHANGES {
                s.wait_window(deadline)?;
                s.conn.send(
                    Message::TextRequest(TextRequest {
                        immediate: false,
                        final_pdu: true,
                        cont: false,
                        lun: [0; 8],
                        itt,
                        ttt,
                        cmd_sn: s.cmd_sn,
                        exp_stat_sn: s.exp_stat_sn,
                        data: core::mem::take(&mut keys),
                    }),
                    deadline,
                )?;
                s.cmd_sn = s.cmd_sn.wrapping_add(1);
                let Message::TextResponse(r) = s.next(deadline)? else {
                    return Err(IscsiError::Protocol("expected a Text Response"));
                };
                if r.itt != itt {
                    return Err(IscsiError::Protocol("Text Response for another task"));
                }
                if out.len() + r.data.len() > MAX_TEXT {
                    return Err(IscsiError::Protocol("SendTargets text too long"));
                }
                out.extend_from_slice(&r.data);
                if r.final_pdu && !r.cont {
                    return Ok(out);
                }
                // More to come: an empty request with the target's tag.
                ttt = r.ttt;
            }
            Err(IscsiError::Protocol("SendTargets did not finish"))
        })
    }

    /// Logs out, closing the session. Later commands fail with
    /// [`IscsiError::NoSession`].
    pub(crate) fn logout(&mut self) -> Result<(), IscsiError> {
        let r = self.guarded(|s| {
            let deadline = s.conn.deadline();
            let itt = s.next_itt();
            s.conn.send(
                Message::LogoutRequest(LogoutRequest {
                    reason: 0, // close the session
                    itt,
                    cid: 0,
                    cmd_sn: s.cmd_sn,
                    exp_stat_sn: s.exp_stat_sn,
                }),
                deadline,
            )?;
            loop {
                match s.next(deadline)? {
                    Message::LogoutResponse(r) if r.itt == itt => {
                        return if r.response == 0 { Ok(()) } else { Err(IscsiError::Response(r.response)) };
                    }
                    // Anything still in flight from before.
                    _ => continue,
                }
            }
        });
        self.open = false;
        r
    }
}

impl<N: Net> Drop for Session<N> {
    fn drop(&mut self) {
        if self.open {
            let _ = self.logout();
        }
    }
}

/// A target a portal reported in discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredTarget {
    /// The target's iSCSI name.
    pub name: String,
    /// Its `TargetAddress` values, `host[:port],portal-group-tag`. Empty
    /// means the portal that was asked.
    pub addresses: Vec<String>,
}

impl DiscoveredTarget {
    /// The addresses that are IPv4 literals, with the default port 3260
    /// where none is given.
    pub fn portals(&self) -> impl Iterator<Item = SocketAddrV4> + '_ {
        self.addresses.iter().filter_map(|a| {
            let host_port = a.split(',').next()?;
            match host_port.rsplit_once(':') {
                Some((host, port)) => Some(SocketAddrV4::new(host.parse().ok()?, port.parse().ok()?)),
                None => Some(SocketAddrV4::new(host_port.parse().ok()?, 3260)),
            }
        })
    }
}

/// Asks the portal at `portal` which targets it offers (a discovery session
/// and `SendTargets=All`), as `opts.initiator_name`. The target name and
/// LUN in `opts` are not used.
pub fn discover<N: Net>(net: N, portal: SocketAddrV4, opts: &Options) -> Result<Vec<DiscoveredTarget>, IscsiError> {
    let mut s = Session::login(net, portal, opts, true)?;
    let reply = s.send_targets()?;
    let _ = s.logout();
    let mut targets: Vec<DiscoveredTarget> = Vec::new();
    for (key, value) in text::parse(&reply).ok_or(IscsiError::Protocol("malformed SendTargets text"))? {
        match key {
            "TargetName" => targets.push(DiscoveredTarget { name: value.into(), addresses: vec![] }),
            "TargetAddress" => match targets.last_mut() {
                Some(t) => t.addresses.push(value.into()),
                None => return Err(IscsiError::Protocol("TargetAddress before TargetName")),
            },
            _ => {}
        }
    }
    Ok(targets)
}
