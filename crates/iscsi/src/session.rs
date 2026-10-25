//! An iSCSI session: login (following redirections), commands in the full
//! feature phase over one or more TCP connections, error recovery, and
//! logout.
//!
//! Commands run as tasks. The session issues each job on a connection with
//! no task in flight, so with several connections (MC/S) the jobs of one
//! call proceed in parallel: CmdSN is session-wide and numbers them in the
//! order issued, while every connection keeps its own StatSN and ExpStatSN.
//! A task's PDUs must come back on the connection it was sent on.
//!
//! What a failure costs depends on the negotiated error recovery level.
//! At level 0 any protocol failure or lost connection drops the session.
//! Level 1 recovers inside a connection: a Data-In or status that went
//! missing or failed its data digest is asked for again with a SNACK, and a
//! command the target never saw is sent again. Level 2 also recovers a lost
//! connection: it logs in again with the same CID and reassigns each task
//! that was on it (or sends the command again if the target never saw it).
//! A SCSI error status never drops the session.

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
    BHS_LEN, DataOut, LoginRequest, LogoutRequest, Message, NopOut, PduError, PduReader, RESERVED_TAG, ScsiCommand,
    SnackRequest, TextRequest, TmfRequest, opcode, sn_lt, snack, stage, tmf,
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

/// Login redirections followed for one connection before giving up on a
/// target that keeps moving.
const MAX_REDIRECTS: usize = 8;

/// Connections recovered in one call before the session is given up on.
const MAX_RECOVERIES: usize = 8;

/// Times one command is sent again (or a quiet connection nudged with a
/// SNACK) before the target is declared dead.
const MAX_RETRIES: u32 = 8;

/// Network polls after which the clock is read again, however busy the
/// connections are.
const CLOCK_EVERY: u32 = 32;

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
    /// The operational parameters to ask for, among them how many
    /// connections and which error recovery level.
    pub offer: Offer,
    /// CHAP credentials. With them, the login must authenticate (the target
    /// that offers no CHAP is refused); without, AuthMethod=None.
    pub chap: Option<Chap>,
    /// TCP receive buffer, in bytes (at most 65535 is used).
    pub rx_buffer: usize,
    /// TCP send buffer, in bytes.
    pub tx_buffer: usize,
    /// How long a connection with a command outstanding may be silent
    /// before, at error recovery level 1 or more, the initiator asks the
    /// target to send again what it may have lost (or sends a command the
    /// target never acknowledged again).
    pub snack_timeout: Duration,
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
            snack_timeout: Duration::from_secs(1),
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

/// One SCSI command for [`Session::run`].
pub(crate) struct Job<'buf> {
    /// The 8-byte LUN field.
    pub(crate) lun: [u8; 8],
    pub(crate) cdb: Cdb,
    pub(crate) data: Data<'buf>,
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

/// The target moved the login elsewhere (status class 1).
struct Redirect {
    addr: SocketAddrV4,
    permanent: bool,
}

/// Which login a connection is making.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The first connection, which creates the session.
    Leading,
    /// Another connection of the session, or the replacement of a lost one.
    Additional,
}

/// `host[:port][,tag]` as an IPv4 socket address, port 3260 by default.
/// Addresses nobody can be reached at (unspecified, multicast, broadcast,
/// port 0) are refused.
pub(crate) fn parse_portal(addr: &str) -> Option<SocketAddrV4> {
    let host_port = addr.split(',').next()?;
    let a = match host_port.rsplit_once(':') {
        Some((host, port)) => SocketAddrV4::new(host.parse().ok()?, port.parse().ok()?),
        None => SocketAddrV4::new(host_port.parse().ok()?, 3260),
    };
    let ip = a.ip();
    (a.port() != 0 && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()).then_some(a)
}

/// What a connection has received.
enum Incoming {
    Pdu(Message),
    /// A PDU whose data digest failed (error recovery level 1 or more): its
    /// header.
    BadData([u8; BHS_LEN]),
}

/// A TCP connection carrying PDUs. It does not own the network: every
/// call is given the [`Net`] its socket lives in, and the session closes it.
struct Conn {
    socket: SocketHandle,
    reader: PduReader,
    cid: u16,
    portal: SocketAddrV4,
    /// CRC32C digests on the PDUs we send, once negotiated.
    header_digest: bool,
    data_digest: bool,
    /// The longest data segment the target takes on this connection.
    max_xmit: usize,
    /// The StatSN we expect next on this connection.
    exp_stat_sn: u32,
    /// The first Login Response has set `exp_stat_sn`.
    stat_sn_known: bool,
    /// When this connection last received a PDU, or was last nudged.
    quiet_since: Instant,
    /// Nudges since the last PDU.
    nudges: u32,
    /// A Status SNACK is out for this StatSN.
    status_snack: Option<u32>,
}

impl Conn {
    /// Connects to `target` and waits until the connection is established.
    fn open<N: Net>(net: &mut N, target: SocketAddrV4, opts: &Options) -> Result<Self, IscsiError> {
        let socket = net.with_sockets(|s| s.add(TcpSocket::new(opts.rx_buffer, opts.tx_buffer)));
        let mut c = Self {
            socket,
            reader: PduReader::new(LOGIN_DSL),
            cid: 0,
            portal: target,
            header_digest: false,
            data_digest: false,
            max_xmit: LOGIN_DSL,
            exp_stat_sn: 0,
            stat_sn_known: false,
            quiet_since: Instant::ZERO,
            nudges: 0,
            status_snack: None,
        };
        if let Err(e) = c.establish(net, target, opts.timeout) {
            c.close(net, opts.timeout);
            return Err(e);
        }
        Ok(c)
    }

    fn establish<N: Net>(&mut self, net: &mut N, target: SocketAddrV4, timeout: Duration) -> Result<(), IscsiError> {
        self.tcp(net, |t| t.connect(target, 0))?;
        let deadline = net.poll() + timeout;
        loop {
            let (state, error) = self.tcp(net, |t| (t.state(), t.error()));
            match (state, error) {
                (TcpState::Established, _) => return Ok(()),
                (_, Some(e)) => return Err(e.into()),
                (TcpState::Closed, None) => return Err(IscsiError::Closed),
                _ if net.poll() >= deadline => return Err(IscsiError::TimedOut),
                _ => {}
            }
        }
    }

    fn tcp<N: Net, R>(&self, net: &mut N, f: impl FnOnce(&mut TcpSocket) -> R) -> R {
        let h = self.socket;
        net.with_sockets(|s| f(s.get_mut::<TcpSocket>(h)))
    }

    /// Queues `m` on the connection, waiting until `deadline` for room in
    /// the send buffer.
    fn send<N: Net>(&mut self, net: &mut N, m: Message, deadline: Instant) -> Result<(), IscsiError> {
        let bytes = m.encode().to_bytes_with(self.header_digest, self.data_digest);
        let mut sent = 0;
        while sent < bytes.len() {
            match self.tcp(net, |t| t.send(bytes.get(sent..).unwrap_or_default())) {
                Ok(n) => sent += n,
                Err(osmium_net::Error::WouldBlock) => {
                    if net.poll() >= deadline {
                        return Err(IscsiError::TimedOut);
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// The next PDU the connection has, without waiting for the network.
    fn try_recv<N: Net>(&mut self, net: &mut N) -> Result<Option<Incoming>, IscsiError> {
        loop {
            match self.reader.next_pdu() {
                Ok(Some(pdu)) => {
                    let m = Message::decode(pdu).map_err(|_| IscsiError::Protocol("unexpected opcode"))?;
                    return Ok(Some(Incoming::Pdu(m)));
                }
                Ok(None) => {}
                Err(PduError::DataDigest(bhs)) => return Ok(Some(Incoming::BadData(bhs))),
                Err(PduError::Digest) => return Err(IscsiError::Digest),
                Err(_) => return Err(IscsiError::Protocol("data segment too long")),
            }
            let mut buf = [0u8; 2048];
            match self.tcp(net, |t| t.recv(&mut buf)) {
                Ok(0) | Err(osmium_net::Error::InvalidState) => return Err(IscsiError::Closed),
                Ok(n) => self.reader.push(buf.get(..n).unwrap_or_default()),
                Err(osmium_net::Error::WouldBlock) => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Closes the connection and removes its socket.
    fn close<N: Net>(self, net: &mut N, timeout: Duration) {
        self.tcp(net, TcpSocket::close);
        // Give our FIN a moment to be acknowledged, then reset whatever is
        // left rather than linger in TIME-WAIT.
        let deadline = net.poll() + CLOSE_TIME.min(timeout);
        while !matches!(self.tcp(net, |t| t.state()), TcpState::Closed | TcpState::FinWait2 | TcpState::TimeWait)
            && net.poll() < deadline
        {}
        self.tcp(net, TcpSocket::abort);
        net.poll();
        let h = self.socket;
        net.with_sockets(|s| s.remove(h));
    }
}

fn conn_mut(conns: &mut [Conn], ci: usize) -> Result<&mut Conn, IscsiError> {
    conns.get_mut(ci).ok_or(IscsiError::Protocol("no such connection"))
}

/// A failure while commands run.
enum Fail {
    /// Connection `.0` failed with `.1`; error recovery level 2 can repair it.
    Conn(usize, IscsiError),
    /// The session is out of step with the target.
    Session(IscsiError),
}

impl From<IscsiError> for Fail {
    fn from(e: IscsiError) -> Self {
        Fail::Session(e)
    }
}

/// What the connections have to say.
enum Polled {
    Pdu(usize, Message),
    BadData(usize, [u8; BHS_LEN]),
    Lost(usize, IscsiError),
    /// Nothing arrived; the network was polled at this time.
    Idle(Instant),
}

/// One command in flight.
struct Task {
    /// Index of the job in the run.
    job: usize,
    /// The connection the task is allegiant to.
    conn: usize,
    itt: u32,
    cmd_sn: u32,
    read: bool,
    write: bool,
    /// The data length the command declares.
    expected: usize,
    /// Bytes of the write in the command PDU, and in it plus the
    /// unsolicited Data-Out.
    immediate: usize,
    unsolicited: usize,
    /// The end of the write data sent so far.
    sent: usize,
    /// The R2TSN expected next.
    r2t_sn: u32,
    /// The next R2T sets `r2t_sn` (after a reassignment the target numbers
    /// its recovery R2Ts from where it was).
    adopt_r2t_sn: bool,
    /// Bytes of read data received, and the DataSN expected next.
    received: usize,
    data_sn: u32,
    /// A Data SNACK is out from this DataSN.
    snack_data: Option<u32>,
    /// An R2T SNACK is out from this R2TSN.
    snack_r2t: Option<u32>,
    /// The target has answered something for this task.
    seen: bool,
    /// A TASK REASSIGN with this tag is out.
    tmf: Option<u32>,
    /// Times the command was sent again.
    retries: u32,
    /// A NOP-Out is out to learn whether the target has the command.
    probed: bool,
}

/// The running of a batch of jobs.
struct Run<'run, 'buf> {
    jobs: &'run mut [Job<'buf>],
    tasks: Vec<Task>,
    results: Vec<Option<Result<usize, IscsiError>>>,
    done: usize,
    /// The next job to issue.
    next: usize,
    deadline: Instant,
    recoveries: usize,
}

impl Run<'_, '_> {
    fn find(&self, itt: u32) -> Option<usize> {
        self.tasks.iter().position(|t| t.itt == itt)
    }
}

/// A logged-in session. Dropping it logs out.
pub(crate) struct Session<N: Net> {
    net: N,
    conns: Vec<Conn>,
    params: Params,
    opts: Options,
    discovery: bool,
    isid: [u8; 6],
    tsih: u16,
    /// Where the leading connection logged in, after redirections.
    portal: SocketAddrV4,
    /// A redirection was permanent.
    moved: bool,
    /// The CmdSN of the next non-immediate command.
    cmd_sn: u32,
    /// The CmdSN the target expects next, as last reported.
    exp_cmd_sn: u32,
    /// The highest CmdSN the target accepts now.
    max_cmd_sn: u32,
    itt: u32,
    /// Logged in and in step with the target.
    open: bool,
    /// The connection to try first when choosing one for a job.
    next_conn: usize,
    /// The network time at the last poll.
    now: Instant,
    since_poll: u32,
    /// Do not log in again before this time (the target asked us to wait).
    reconnect_at: Option<Instant>,
}

impl<N: Net> Session<N> {
    /// Connects to `target` and logs in: to `opts.target_name` in a normal
    /// session, or to a discovery session if `discovery`. A normal session
    /// then opens more connections, up to what `opts.offer` and the target
    /// agreed.
    pub(crate) fn login(net: N, target: SocketAddrV4, opts: &Options, discovery: bool) -> Result<Self, IscsiError> {
        let mut s = Self {
            net,
            conns: Vec::new(),
            params: Params::default(),
            opts: opts.clone(),
            discovery,
            isid: opts.isid,
            tsih: 0,
            portal: target,
            moved: false,
            cmd_sn: 1,
            exp_cmd_sn: 0,
            max_cmd_sn: 1,
            itt: 0,
            open: false,
            next_conn: 0,
            now: Instant::ZERO,
            since_poll: 0,
            reconnect_at: None,
        };
        s.add_connection(target, 0, Kind::Leading, 0)?;
        s.open = true;
        if !discovery {
            let want = opts.offer.max_connections.min(s.params.max_connections);
            for cid in 1..want {
                // Fewer connections than asked for are still a session.
                if s.add_connection(s.portal, cid, Kind::Additional, 0).is_err() {
                    break;
                }
            }
        }
        Ok(s)
    }

    pub(crate) fn params(&self) -> &Params {
        &self.params
    }

    /// Runs `f` on the network stack.
    pub(crate) fn with_net<R>(&mut self, f: impl FnOnce(&mut N) -> R) -> R {
        f(&mut self.net)
    }

    #[cfg(test)]
    pub(crate) fn net_mut(&mut self) -> &mut N {
        &mut self.net
    }

    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    /// Connections in the session.
    pub(crate) fn connections(&self) -> usize {
        self.conns.len()
    }

    /// Where the leading connection is logged in, after any redirections.
    pub(crate) fn portal(&self) -> SocketAddrV4 {
        self.portal
    }

    /// Whether a redirection was permanent: the caller should use
    /// [`portal`](Self::portal) from now on.
    pub(crate) fn moved_permanently(&self) -> bool {
        self.moved
    }

    fn next_itt(&mut self) -> u32 {
        self.itt = self.itt.wrapping_add(1);
        if self.itt == RESERVED_TAG {
            self.itt = 0;
        }
        self.itt
    }

    fn exp_stat_sn(&self, ci: usize) -> u32 {
        self.conns.get(ci).map_or(0, |c| c.exp_stat_sn)
    }

    /// Polls the network once and returns the time.
    fn poll_net(&mut self) -> Instant {
        self.since_poll = 0;
        self.now = self.net.poll();
        self.now
    }

    fn deadline(&mut self) -> Instant {
        self.poll_net() + self.opts.timeout
    }

    /// Polls the network once, failing if `deadline` has passed.
    fn pump(&mut self, deadline: Instant) -> Result<(), IscsiError> {
        if self.poll_net() >= deadline { Err(IscsiError::TimedOut) } else { Ok(()) }
    }

    fn send_on(&mut self, ci: usize, m: Message, deadline: Instant) -> Result<(), Fail> {
        let c = conn_mut(&mut self.conns, ci)?;
        c.send(&mut self.net, m, deadline).map_err(|e| Fail::Conn(ci, e))
    }

    // ---- Login ----

    /// Logs in a connection with `cid` to `portal`, following redirections,
    /// and adds it to the session. Returns its index. `exp_stat_sn` is the
    /// StatSN a replacement connection expects next.
    fn add_connection(
        &mut self,
        portal: SocketAddrV4,
        cid: u16,
        kind: Kind,
        exp_stat_sn: u32,
    ) -> Result<usize, IscsiError> {
        let mut portal = portal;
        for _ in 0..=MAX_REDIRECTS {
            let mut conn = Conn::open(&mut self.net, portal, &self.opts)?;
            conn.cid = cid;
            conn.exp_stat_sn = exp_stat_sn;
            self.conns.push(conn);
            let ci = self.conns.len() - 1;
            match self.negotiate(ci, kind) {
                Ok(None) => {
                    if kind == Kind::Leading {
                        self.portal = portal;
                    }
                    return Ok(ci);
                }
                Ok(Some(r)) => {
                    self.drop_last();
                    self.moved |= r.permanent;
                    portal = r.addr;
                }
                Err(e) => {
                    self.drop_last();
                    return Err(e);
                }
            }
        }
        Err(IscsiError::Protocol("too many login redirections"))
    }

    fn drop_last(&mut self) {
        if let Some(c) = self.conns.pop() {
            c.close(&mut self.net, self.opts.timeout);
        }
    }

    /// Reads a login-phase PDU from connection `ci`.
    fn recv_login(&mut self, ci: usize, deadline: Instant) -> Result<Message, IscsiError> {
        loop {
            match conn_mut(&mut self.conns, ci)?.try_recv(&mut self.net)? {
                Some(Incoming::Pdu(m)) => return Ok(m),
                Some(Incoming::BadData(_)) => return Err(IscsiError::Digest),
                None => self.pump(deadline)?,
            }
        }
    }

    /// The login exchange (RFC 7143 §6.3): SecurityNegotiation with
    /// AuthMethod=None (or CHAP, in three rounds, RFC 7143 §12.1), then LoginOperationalNegotiation, then the full
    /// feature phase. The target may hold us in a stage for more rounds,
    /// split its text across responses, or offer keys of its own. For a
    /// leading login the result is the session's parameters; for another
    /// connection only its digests and segment length are negotiated. `None`
    /// means logged in; a redirection (status class 1) is returned.
    fn negotiate(&mut self, ci: usize, kind: Kind) -> Result<Option<Redirect>, IscsiError> {
        let deadline = self.deadline();
        let discovery = self.discovery;
        let opts = self.opts.clone();
        let mut neg = match kind {
            Kind::Leading => Negotiator::new(opts.offer.clone()),
            Kind::Additional => Negotiator::additional(opts.offer.clone(), self.params.clone()),
        };
        let itt = self.next_itt();
        let target_name = (!discovery).then_some(opts.target_name.as_str());
        let mut keys = neg.security_keys(&opts.initiator_name, target_name, opts.chap.is_some());
        let mut auth = if opts.chap.is_some() { Auth::Method } else { Auth::Done };
        let mut current = stage::SECURITY;
        let mut operational_sent = false;
        let mut exchanges = 0;
        let cid = conn_mut(&mut self.conns, ci)?.cid;
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
                tsih: if kind == Kind::Leading { 0 } else { self.tsih },
                itt,
                cid,
                cmd_sn: self.cmd_sn,
                exp_stat_sn: self.exp_stat_sn(ci),
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
                conn_mut(&mut self.conns, ci)?.send(&mut self.net, Message::LoginRequest(req.clone()), deadline)?;
                let msg = self.recv_login(ci, deadline)?;
                self.absorb_login(ci, &msg, kind)?;
                let Message::LoginResponse(r) = msg else {
                    return Err(IscsiError::Protocol("expected a Login Response"));
                };
                if r.status_class == 1 {
                    // Target Moved Temporarily (1) or Permanently (2): the
                    // address to try instead is in TargetAddress.
                    let addr = text::parse(&r.data).and_then(|pairs| {
                        pairs.into_iter().find(|(k, _)| *k == "TargetAddress").and_then(|(_, v)| parse_portal(v))
                    });
                    return match (addr, r.status_detail) {
                        (Some(addr), d @ (1 | 2)) => Ok(Some(Redirect { addr, permanent: d == 2 })),
                        _ => Err(IscsiError::Login { class: 1, detail: r.status_detail }),
                    };
                }
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
                    exp_stat_sn: self.exp_stat_sn(ci),
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
                        let p = &neg.params;
                        match kind {
                            Kind::Leading => {
                                self.tsih = resp.tsih;
                                self.params = p.clone();
                            }
                            Kind::Additional if resp.tsih != self.tsih => {
                                return Err(IscsiError::Protocol("Login Response for another session"));
                            }
                            Kind::Additional => {}
                        }
                        let erl = self.params.error_recovery_level;
                        let c = conn_mut(&mut self.conns, ci)?;
                        // From now on the target's segments are bounded by
                        // what we declared, and digests are on.
                        c.reader.set_max_data(p.max_recv_data_segment_length as usize);
                        c.header_digest = p.header_digest;
                        c.data_digest = p.data_digest;
                        c.reader.set_digests(p.header_digest, p.data_digest);
                        c.reader.set_recoverable(erl >= 1);
                        c.max_xmit = p.max_xmit_data_segment_length as usize;
                        c.quiet_since = self.now;
                        return Ok(None);
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

    /// Tracks StatSN and the command window from a Login Response.
    fn absorb_login(&mut self, ci: usize, m: &Message, kind: Kind) -> Result<(), IscsiError> {
        if let Some(sn) = m.stat_sn() {
            let c = conn_mut(&mut self.conns, ci)?;
            if c.stat_sn_known && sn != c.exp_stat_sn {
                return Err(IscsiError::Protocol("StatSN out of sequence"));
            }
            c.stat_sn_known = true;
            c.exp_stat_sn = sn.wrapping_add(1);
        }
        self.take_window(m.cmd_window(), kind == Kind::Leading);
        Ok(())
    }

    /// Takes the command window (ExpCmdSN, MaxCmdSN) from a target PDU.
    fn take_window(&mut self, window: Option<(u32, u32)>, first: bool) {
        let Some((exp, max)) = window else { return };
        // A window with MaxCmdSN = ExpCmdSN - 1 is closed; anything smaller
        // is invalid and ignored, as is a MaxCmdSN that went backwards.
        if !sn_lt(max, exp.wrapping_sub(1)) && (first || !sn_lt(max, self.max_cmd_sn)) {
            self.max_cmd_sn = max;
        }
        // The target cannot expect a command we have not sent.
        if !sn_lt(self.cmd_sn, exp) && (first || sn_lt(self.exp_cmd_sn, exp)) {
            self.exp_cmd_sn = exp;
        }
    }

    // ---- Receiving ----

    /// Looks at every connection for a PDU and, if none has one, polls the
    /// network once.
    fn poll_any(&mut self) -> Polled {
        let n = self.conns.len();
        for k in 0..n {
            let ci = (self.next_conn + k) % n;
            let Some(c) = self.conns.get_mut(ci) else { continue };
            match c.try_recv(&mut self.net) {
                Ok(Some(Incoming::Pdu(m))) => {
                    self.next_conn = ci + 1;
                    c.quiet_since = self.now;
                    self.since_poll += 1;
                    if self.since_poll >= CLOCK_EVERY {
                        self.poll_net();
                    }
                    return Polled::Pdu(ci, m);
                }
                Ok(Some(Incoming::BadData(bhs))) => {
                    c.quiet_since = self.now;
                    return Polled::BadData(ci, bhs);
                }
                Ok(None) => {}
                Err(e) => return Polled::Lost(ci, e),
            }
        }
        Polled::Idle(self.poll_net())
    }

    /// Answers a target ping (NOP-In) on connection `ci`.
    fn answer_ping(&mut self, ci: usize, n: crate::pdu::NopIn, deadline: Instant) -> Result<(), Fail> {
        if n.ttt != RESERVED_TAG {
            let m = Message::NopOut(NopOut {
                immediate: true,
                lun: n.lun,
                itt: RESERVED_TAG,
                ttt: n.ttt,
                cmd_sn: self.cmd_sn,
                exp_stat_sn: self.exp_stat_sn(ci),
                data: n.data,
            });
            self.send_on(ci, m, deadline)?;
        }
        Ok(())
    }

    /// Reads one PDU outside a command run and deals with what needs no
    /// caller: answers target pings, skips asynchronous events. StatSN
    /// must be in sequence. Returns `None` for a PDU it consumed.
    fn recv_plain_opt(&mut self, deadline: Instant) -> Result<Option<Message>, IscsiError> {
        let (ci, m) = loop {
            match self.poll_any() {
                Polled::Pdu(ci, m) => break (ci, m),
                Polled::BadData(..) => return Err(IscsiError::Digest),
                Polled::Lost(_, e) => return Err(e),
                Polled::Idle(now) if now >= deadline => return Err(IscsiError::TimedOut),
                Polled::Idle(_) => {}
            }
        };
        if let Some(sn) = m.stat_sn() {
            let c = conn_mut(&mut self.conns, ci)?;
            if sn != c.exp_stat_sn {
                return Err(IscsiError::Protocol("StatSN out of sequence"));
            }
            c.exp_stat_sn = sn.wrapping_add(1);
        }
        self.take_window(m.cmd_window(), false);
        match m {
            Message::NopIn(n) => match self.answer_ping(ci, n, deadline) {
                Ok(()) => Ok(None),
                Err(Fail::Conn(_, e) | Fail::Session(e)) => Err(e),
            },
            // 2 and 3: the target is dropping the connection or session.
            Message::AsyncMessage(a) if matches!(a.event, 2 | 3) => Err(IscsiError::Closed),
            // A SCSI event, a logout request (we log out when dropped) or
            // a vendor event.
            Message::AsyncMessage(_) => Ok(None),
            Message::Reject(r) => Err(IscsiError::Reject(r.reason)),
            m => Ok(Some(m)),
        }
    }

    /// The next PDU outside a command run that is not dealt with on the way.
    fn recv_plain(&mut self, deadline: Instant) -> Result<Message, IscsiError> {
        loop {
            if let Some(m) = self.recv_plain_opt(deadline)? {
                return Ok(m);
            }
        }
    }

    /// Waits until the target's window admits the next CmdSN.
    fn wait_window(&mut self, deadline: Instant) -> Result<(), IscsiError> {
        while sn_lt(self.max_cmd_sn, self.cmd_sn) {
            if self.recv_plain_opt(deadline)?.is_some() {
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

    // ---- Commands ----

    /// Runs one SCSI command at `lun` and returns the bytes of data it
    /// moved: what the target sent for [`Data::In`], or for [`Data::Out`]
    /// the length less any residual the target reported. Either may be
    /// short.
    pub(crate) fn command(&mut self, lun: [u8; 8], cdb: &Cdb, data: Data<'_>) -> Result<usize, IscsiError> {
        let mut jobs = [Job { lun, cdb: *cdb, data }];
        let mut results = self.run(&mut jobs)?;
        results.pop().unwrap_or(Err(IscsiError::Protocol("command lost")))
    }

    /// Runs `jobs`, in parallel over the session's connections, and returns
    /// each one's outcome. The outer error is a failure of the session.
    pub(crate) fn run(&mut self, jobs: &mut [Job<'_>]) -> Result<Vec<Result<usize, IscsiError>>, IscsiError> {
        self.guarded(|s| {
            // One deadline for the call, pushed back by each command that
            // finishes: a target trickling data or R2Ts cannot keep a
            // command alive past the timeout.
            let deadline = s.deadline();
            let mut run = Run {
                results: jobs.iter().map(|_| None).collect(),
                jobs,
                tasks: Vec::new(),
                done: 0,
                next: 0,
                deadline,
                recoveries: 0,
            };
            s.drive(&mut run)?;
            run.results
                .into_iter()
                .map(|r| r.ok_or(IscsiError::Protocol("command lost")))
                .collect::<Result<Vec<_>, _>>()
        })
    }

    fn drive(&mut self, run: &mut Run<'_, '_>) -> Result<(), IscsiError> {
        while run.done < run.jobs.len() {
            let step = self.issue(run).and_then(|()| match self.poll_any() {
                Polled::Pdu(ci, m) => self.on_pdu(ci, m, run),
                Polled::BadData(ci, bhs) => self.on_bad_data(ci, bhs, run),
                Polled::Lost(ci, e) => Err(Fail::Conn(ci, e)),
                Polled::Idle(now) if now >= run.deadline => Err(Fail::Session(IscsiError::TimedOut)),
                Polled::Idle(now) => self.on_idle(now, run),
            });
            match step {
                Ok(()) => {}
                Err(Fail::Session(e)) => return Err(e),
                Err(Fail::Conn(ci, e)) => self.recover(ci, e, run)?,
            }
        }
        Ok(())
    }

    /// A connection with no task, starting from the one after the last used.
    fn free_conn(&self, run: &Run<'_, '_>) -> Option<usize> {
        let n = self.conns.len();
        (0..n).map(|k| (self.next_conn + k) % n).find(|ci| !run.tasks.iter().any(|t| t.conn == *ci))
    }

    /// Starts as many jobs as the command window and the free connections
    /// allow.
    fn issue(&mut self, run: &mut Run<'_, '_>) -> Result<(), Fail> {
        while run.next < run.jobs.len() && !sn_lt(self.max_cmd_sn, self.cmd_sn) {
            let Some(ci) = self.free_conn(run) else { break };
            self.next_conn = ci + 1;
            let job = run.next;
            run.next += 1;
            let itt = self.next_itt();
            let cmd_sn = self.cmd_sn;
            self.cmd_sn = self.cmd_sn.wrapping_add(1);
            let mut task = Task {
                job,
                conn: ci,
                itt,
                cmd_sn,
                read: false,
                write: false,
                expected: 0,
                immediate: 0,
                unsolicited: 0,
                sent: 0,
                r2t_sn: 0,
                adopt_r2t_sn: false,
                received: 0,
                data_sn: 0,
                snack_data: None,
                snack_r2t: None,
                seen: false,
                tmf: None,
                retries: 0,
                probed: false,
            };
            self.plan(ci, run.jobs.get(job).ok_or(IscsiError::Protocol("no such job"))?, &mut task)?;
            run.tasks.push(task);
            self.send_command(run, run.tasks.len() - 1)?;
        }
        Ok(())
    }

    /// Works out how `job` moves its data on connection `ci`: whether the
    /// command carries immediate data and how much follows unsolicited.
    fn plan(&self, ci: usize, job: &Job<'_>, t: &mut Task) -> Result<(), IscsiError> {
        let p = &self.params;
        let (read, write, expected) = match &job.data {
            Data::None => (false, false, 0),
            Data::In(b) => (true, false, b.len()),
            Data::Out(b) => (false, true, b.len()),
        };
        u32::try_from(expected).map_err(|_| IscsiError::Protocol("transfer too large"))?;
        // Unsolicited data, up to FirstBurstLength: immediate data in the
        // command PDU if allowed, then Data-Out PDUs unless InitialR2T.
        let max_xmit = self.conns.get(ci).map_or(LOGIN_DSL, |c| c.max_xmit);
        let (immediate, unsolicited) = if write {
            let burst = (p.first_burst_length as usize).min(expected);
            let imm = if p.immediate_data { burst.min(max_xmit) } else { 0 };
            (imm, if p.initial_r2t { imm } else { burst })
        } else {
            (0, 0)
        };
        *t = Task {
            probed: false,
            read,
            write,
            expected,
            immediate,
            unsolicited,
            sent: unsolicited,
            received: 0,
            data_sn: 0,
            r2t_sn: 0,
            adopt_r2t_sn: false,
            snack_data: None,
            snack_r2t: None,
            seen: false,
            tmf: None,
            conn: ci,
            ..*t
        };
        Ok(())
    }

    /// Sends task `ti`'s command and its unsolicited data on its connection.
    fn send_command(&mut self, run: &mut Run<'_, '_>, ti: usize) -> Result<(), Fail> {
        let t = run.tasks.get(ti).ok_or(IscsiError::Protocol("no such task"))?;
        let job = run.jobs.get(t.job).ok_or(IscsiError::Protocol("no such job"))?;
        let ci = t.conn;
        let expected_len = u32::try_from(t.expected).map_err(|_| IscsiError::Protocol("transfer too large"))?;
        let immediate_data = match &job.data {
            Data::Out(b) => b.get(..t.immediate).unwrap_or_default().to_vec(),
            _ => Vec::new(),
        };
        let m = Message::ScsiCommand(ScsiCommand {
            final_pdu: t.unsolicited == t.immediate,
            read: t.read,
            write: t.write,
            attr: 1, // SIMPLE
            lun: job.lun,
            itt: t.itt,
            expected_len,
            cmd_sn: t.cmd_sn,
            exp_stat_sn: self.exp_stat_sn(ci),
            cdb: job.cdb,
            data: immediate_data,
        });
        self.send_on(ci, m, run.deadline)?;
        if let Data::Out(b) = &job.data
            && t.unsolicited > t.immediate
        {
            let burst =
                b.get(t.immediate..t.unsolicited).ok_or(IscsiError::Protocol("unsolicited data beyond the buffer"))?;
            self.data_out(ci, t.itt, RESERVED_TAG, job.lun, burst, t.immediate, run.deadline)?;
        }
        Ok(())
    }

    /// Sends the command of task `ti` again, as if for the first time.
    fn retry_command(&mut self, run: &mut Run<'_, '_>, ti: usize, ci: usize) -> Result<(), Fail> {
        let t = run.tasks.get_mut(ti).ok_or(IscsiError::Protocol("no such task"))?;
        t.retries += 1;
        if t.retries > MAX_RETRIES {
            return Err(IscsiError::TimedOut.into());
        }
        let mut fresh = Task { ..*t };
        let job = run.jobs.get(t.job).ok_or(IscsiError::Protocol("no such job"))?;
        self.plan(ci, job, &mut fresh)?;
        *run.tasks.get_mut(ti).ok_or(IscsiError::Protocol("no such task"))? = fresh;
        self.send_command(run, ti)
    }

    /// Sends one data sequence, `data` at buffer offset `offset`, in
    /// Data-Out PDUs no larger than the target accepts.
    #[allow(clippy::too_many_arguments)]
    fn data_out(
        &mut self,
        ci: usize,
        itt: u32,
        ttt: u32,
        lun: [u8; 8],
        data: &[u8],
        offset: usize,
        deadline: Instant,
    ) -> Result<(), Fail> {
        let seg = conn_mut(&mut self.conns, ci)?.max_xmit.max(1);
        let count = data.len().div_ceil(seg);
        for (i, chunk) in data.chunks(seg).enumerate() {
            let at = i
                .checked_mul(seg)
                .and_then(|d| offset.checked_add(d))
                .and_then(|o| u32::try_from(o).ok())
                .ok_or(IscsiError::Protocol("Data-Out offset beyond 4 GiB"))?;
            let m = Message::DataOut(DataOut {
                final_pdu: i + 1 == count,
                lun,
                itt,
                ttt,
                exp_stat_sn: self.exp_stat_sn(ci),
                data_sn: i as u32,
                offset: at,
                data: chunk.to_vec(),
            });
            self.send_on(ci, m, deadline)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn send_snack(
        &mut self,
        ci: usize,
        kind: u8,
        lun: [u8; 8],
        itt: u32,
        ttt: u32,
        beg_run: u32,
        run_length: u32,
        deadline: Instant,
    ) -> Result<(), Fail> {
        let m = Message::SnackRequest(SnackRequest {
            kind,
            lun,
            itt,
            ttt,
            exp_stat_sn: self.exp_stat_sn(ci),
            beg_run,
            run_length,
        });
        self.send_on(ci, m, deadline)
    }

    /// Asks for the statuses from the connection's ExpStatSN on, once per
    /// value of it.
    fn snack_status(&mut self, ci: usize, deadline: Instant) -> Result<(), Fail> {
        let c = conn_mut(&mut self.conns, ci)?;
        if c.status_snack == Some(c.exp_stat_sn) {
            return Ok(());
        }
        let sn = c.exp_stat_sn;
        c.status_snack = Some(sn);
        self.send_snack(ci, snack::STATUS, [0; 8], RESERVED_TAG, RESERVED_TAG, sn, 0, deadline)
    }

    /// Ends task `ti` with `r`. A SCSI or iSCSI failure of the command is
    /// its result; anything else fails the session.
    fn finish(&mut self, run: &mut Run<'_, '_>, ti: usize, r: Result<usize, IscsiError>) -> Result<(), Fail> {
        if ti >= run.tasks.len() {
            return Err(IscsiError::Protocol("no such task").into());
        }
        let t = run.tasks.swap_remove(ti);
        if let Err(e) = &r
            && !matches!(e, IscsiError::Scsi { .. } | IscsiError::Response(_))
        {
            return Err(Fail::Session(*e));
        }
        if let Some(slot) = run.results.get_mut(t.job) {
            *slot = Some(r);
        }
        run.done += 1;
        run.deadline = self.now + self.opts.timeout;
        Ok(())
    }

    /// Deals with a PDU from connection `ci` during a run.
    fn on_pdu(&mut self, ci: usize, m: Message, run: &mut Run<'_, '_>) -> Result<(), Fail> {
        let erl = self.params.error_recovery_level;
        let sn = m.stat_sn();
        let window = m.cmd_window();
        if let Some(sn) = sn {
            let c = conn_mut(&mut self.conns, ci)?;
            if sn != c.exp_stat_sn {
                if erl == 0 {
                    return Err(IscsiError::Protocol("StatSN out of sequence").into());
                }
                // Ahead: a status went missing, ask for it. Behind: a
                // duplicate, which says nothing new.
                if sn_lt(c.exp_stat_sn, sn) {
                    return self.snack_status(ci, run.deadline);
                }
                return Ok(());
            }
        }
        let progress =
            matches!(m, Message::DataIn(_) | Message::R2t(_) | Message::ScsiResponse(_) | Message::TmfResponse(_));
        let accepted = self.dispatch(ci, m, run)?;
        if accepted
            && progress
            && let Some(c) = self.conns.get_mut(ci)
        {
            c.nudges = 0;
        }
        if accepted {
            if let Some(sn) = sn
                && let Some(c) = self.conns.get_mut(ci)
            {
                c.exp_stat_sn = sn.wrapping_add(1);
                c.status_snack = None;
            }
            self.take_window(window, false);
        }
        Ok(())
    }

    /// Handles `m`; false if it was set aside (out of order, or a
    /// duplicate), in which case its StatSN is not consumed.
    fn dispatch(&mut self, ci: usize, m: Message, run: &mut Run<'_, '_>) -> Result<bool, Fail> {
        let erl = self.params.error_recovery_level;
        match m {
            Message::NopIn(n) => {
                self.answer_ping(ci, n, run.deadline)?;
                Ok(true)
            }
            Message::AsyncMessage(a) => match a.event {
                // The target is about to drop the connection: ask to be
                // let in again, after the time it names.
                2 if erl >= 2 => {
                    let wait = Duration::from_secs(a.params.get(1).copied().unwrap_or(0).into());
                    self.reconnect_at = Some(self.now + wait.min(self.opts.timeout));
                    if let Some(c) = self.conns.get_mut(ci) {
                        c.exp_stat_sn = a.stat_sn.wrapping_add(1);
                    }
                    Err(Fail::Conn(ci, IscsiError::Closed))
                }
                // 2 and 3: the target is dropping the connection or session.
                2 | 3 => Err(IscsiError::Closed.into()),
                // A SCSI event, a logout request (we log out when dropped)
                // or a vendor event.
                _ => Ok(true),
            },
            Message::Reject(r) => self.on_reject(ci, r, run),
            Message::DataIn(d) => self.on_data_in(ci, d, run),
            Message::R2t(r) => self.on_r2t(ci, r, run),
            Message::ScsiResponse(r) => self.on_response(ci, r, run),
            Message::TmfResponse(t) => {
                let Some(ti) = run.tasks.iter().position(|x| x.tmf == Some(t.itt)) else {
                    return Ok(true);
                };
                if t.response == 0 {
                    if let Some(task) = run.tasks.get_mut(ti) {
                        task.tmf = None;
                        task.seen = true;
                        task.adopt_r2t_sn = task.write;
                    }
                    Ok(true)
                } else {
                    // The target no longer has the task.
                    self.finish(run, ti, Err(IscsiError::Response(t.response)))?;
                    Ok(true)
                }
            }
            _ => Err(IscsiError::Protocol("unexpected PDU during a command").into()),
        }
    }

    /// The task a target PDU for `itt` on connection `ci` belongs to. A
    /// PDU for a finished task is a stale duplicate where recovery is on,
    /// and a protocol error where it is not.
    fn task_of(&self, ci: usize, itt: u32, run: &Run<'_, '_>) -> Result<Option<usize>, IscsiError> {
        match run.find(itt) {
            Some(ti) => match run.tasks.get(ti) {
                // A task's PDUs come on the connection it was sent on.
                Some(t) if t.conn == ci => Ok(Some(ti)),
                _ => Err(IscsiError::Protocol("PDU for a task on another connection")),
            },
            None if self.params.error_recovery_level >= 1 => Ok(None),
            None => Err(IscsiError::Protocol("unexpected PDU during a command")),
        }
    }

    fn on_data_in(&mut self, ci: usize, d: crate::pdu::DataIn, run: &mut Run<'_, '_>) -> Result<bool, Fail> {
        let erl = self.params.error_recovery_level;
        let Some(ti) = self.task_of(ci, d.itt, run)? else { return Ok(true) };
        let deadline = run.deadline;
        let t = run.tasks.get_mut(ti).ok_or(IscsiError::Protocol("no such task"))?;
        t.seen = true;
        let job = run.jobs.get_mut(t.job).ok_or(IscsiError::Protocol("no such job"))?;
        let Data::In(buf) = &mut job.data else {
            return Err(IscsiError::Protocol("Data-In for a command without input").into());
        };
        if erl >= 1 && d.data_sn != t.data_sn {
            if sn_lt(t.data_sn, d.data_sn) && t.snack_data != Some(t.data_sn) {
                // A PDU went missing: ask for everything from there.
                t.snack_data = Some(t.data_sn);
                let (lun, itt, from) = (job.lun, t.itt, t.data_sn);
                self.send_snack(ci, snack::DATA_R2T, lun, itt, RESERVED_TAG, from, 0, deadline)?;
            }
            return Ok(false);
        }
        if d.data_sn != t.data_sn || d.offset as usize != t.received {
            return Err(IscsiError::Protocol("Data-In out of order").into());
        }
        let end = t.received.checked_add(d.data.len()).ok_or(IscsiError::Protocol("Data-In beyond the buffer"))?;
        let dst = buf.get_mut(t.received..end).ok_or(IscsiError::Protocol("Data-In beyond the buffer"))?;
        dst.copy_from_slice(&d.data);
        t.received = end;
        t.data_sn = t.data_sn.wrapping_add(1);
        t.snack_data = None;
        let (lun, itt, next_sn, expected, read, received) = (job.lun, t.itt, t.data_sn, t.expected, t.read, t.received);
        if d.ack && erl >= 1 {
            // The target wants to know the data so far arrived.
            self.send_snack(ci, snack::DATA_ACK, lun, itt, d.ttt, next_sn, 0, deadline)?;
        }
        if let Some(st) = d.status {
            let residual = Residual { underflow: d.underflow, overflow: d.overflow, count: d.residual };
            let r = Self::status(0, st, &[], residual, expected, read, received);
            // The StatSN is consumed by the caller, once we return true.
            self.finish(run, ti, r)?;
        }
        Ok(true)
    }

    fn on_r2t(&mut self, ci: usize, r: crate::pdu::R2t, run: &mut Run<'_, '_>) -> Result<bool, Fail> {
        let erl = self.params.error_recovery_level;
        let Some(ti) = self.task_of(ci, r.itt, run)? else { return Ok(true) };
        let max_burst = self.params.max_burst_length as usize;
        let deadline = run.deadline;
        let t = run.tasks.get_mut(ti).ok_or(IscsiError::Protocol("no such task"))?;
        t.seen = true;
        let job = run.jobs.get(t.job).ok_or(IscsiError::Protocol("no such job"))?;
        let Data::Out(b) = &job.data else {
            return Err(IscsiError::Protocol("R2T for a command without output").into());
        };
        if r.ttt == RESERVED_TAG {
            return Err(IscsiError::Protocol("R2T out of step").into());
        }
        if erl >= 1 {
            if t.adopt_r2t_sn {
                t.adopt_r2t_sn = false;
                t.r2t_sn = r.r2t_sn;
            }
            if r.r2t_sn != t.r2t_sn {
                if sn_lt(t.r2t_sn, r.r2t_sn) && t.snack_r2t != Some(t.r2t_sn) {
                    t.snack_r2t = Some(t.r2t_sn);
                    let (lun, itt, from) = (job.lun, t.itt, t.r2t_sn);
                    self.send_snack(ci, snack::DATA_R2T, lun, itt, RESERVED_TAG, from, 0, deadline)?;
                }
                return Ok(false);
            }
        }
        // DataPDUInOrder and DataSequenceInOrder are Yes, with one R2T at a
        // time: each R2T asks for the data after what we have sent (or,
        // where recovery is on, again for what was lost).
        let offset = r.offset as usize;
        if r.r2t_sn != t.r2t_sn || (erl == 0 && offset != t.sent) {
            return Err(IscsiError::Protocol("R2T out of step").into());
        }
        let len = r.desired_len as usize;
        if len == 0 || len > max_burst {
            return Err(IscsiError::Protocol("R2T length outside 1..=MaxBurstLength").into());
        }
        let end = offset.checked_add(len).ok_or(IscsiError::Protocol("R2T beyond the buffer"))?;
        let chunk = b.get(offset..end).ok_or(IscsiError::Protocol("R2T beyond the buffer"))?;
        t.sent = t.sent.max(end);
        t.r2t_sn = t.r2t_sn.wrapping_add(1);
        t.snack_r2t = None;
        let (itt, lun) = (t.itt, job.lun);
        self.data_out(ci, itt, r.ttt, lun, chunk, offset, deadline)?;
        Ok(true)
    }

    fn on_response(&mut self, ci: usize, r: crate::pdu::ScsiResponse, run: &mut Run<'_, '_>) -> Result<bool, Fail> {
        let erl = self.params.error_recovery_level;
        let Some(ti) = self.task_of(ci, r.itt, run)? else { return Ok(true) };
        let deadline = run.deadline;
        let t = run.tasks.get_mut(ti).ok_or(IscsiError::Protocol("no such task"))?;
        t.seen = true;
        if erl >= 1 && t.read && sn_lt(t.data_sn, r.exp_data_sn) {
            // The status says more Data-In was sent than arrived: hold the
            // status back (it is sent again after the data) and ask.
            if t.snack_data == Some(t.data_sn) {
                return Err(IscsiError::Protocol("target did not resend Data-In").into());
            }
            t.snack_data = Some(t.data_sn);
            let lun = run.jobs.get(t.job).ok_or(IscsiError::Protocol("no such job"))?.lun;
            let (itt, from) = (t.itt, t.data_sn);
            self.send_snack(ci, snack::R_DATA, lun, itt, RESERVED_TAG, from, 0, deadline)?;
            return Ok(false);
        }
        let residual = Residual { underflow: r.underflow, overflow: r.overflow, count: r.residual };
        let moved = if t.read { t.received } else { t.sent };
        let res = Self::status(r.response, r.status, &r.data, residual, t.expected, t.read, moved);
        self.finish(run, ti, res)?;
        Ok(true)
    }

    fn on_reject(&mut self, ci: usize, r: crate::pdu::Reject, run: &mut Run<'_, '_>) -> Result<bool, Fail> {
        if self.params.error_recovery_level >= 1 {
            let op = r.data.first().map(|b| b & 0x3f);
            let itt = r.data.get(16..20).and_then(|b| <[u8; 4]>::try_from(b).ok()).map(u32::from_be_bytes);
            match (r.reason, op, itt) {
                // The target could not use a SNACK; the timer will ask again.
                (_, Some(opcode::SNACK_REQUEST), _) => return Ok(true),
                // Data digest error, resend: a command is sent again; the
                // target recovers lost Data-Out with a fresh R2T.
                (0x02, Some(opcode::SCSI_COMMAND), Some(itt)) => {
                    if let Some(ti) = run.find(itt) {
                        self.retry_command(run, ti, ci)?;
                    }
                    return Ok(true);
                }
                (0x02, Some(opcode::DATA_OUT), _) => return Ok(true),
                _ => {}
            }
        }
        Err(IscsiError::Reject(r.reason).into())
    }

    /// A PDU on connection `ci` failed its data digest (error recovery
    /// level 1 or more): ask for it again.
    fn on_bad_data(&mut self, ci: usize, bhs: [u8; BHS_LEN], run: &mut Run<'_, '_>) -> Result<(), Fail> {
        let itt = bhs.get(16..20).and_then(|b| <[u8; 4]>::try_from(b).ok()).map_or(RESERVED_TAG, u32::from_be_bytes);
        let deadline = run.deadline;
        if bhs.first().map(|b| b & 0x3f) == Some(opcode::DATA_IN)
            && let Some(ti) = run.find(itt)
            && let Some(t) = run.tasks.get_mut(ti)
            && t.conn == ci
            && t.read
        {
            if t.snack_data != Some(t.data_sn) {
                t.snack_data = Some(t.data_sn);
                let lun = run.jobs.get(t.job).map_or([0; 8], |j| j.lun);
                let (itt, from) = (t.itt, t.data_sn);
                self.send_snack(ci, snack::DATA_R2T, lun, itt, RESERVED_TAG, from, 0, deadline)?;
            }
            return Ok(());
        }
        // Anything else that carried data carried status.
        self.snack_status(ci, deadline)
    }

    /// Nothing has arrived: at error recovery level 1 or more, nudge
    /// connections that have been quiet too long.
    fn on_idle(&mut self, now: Instant, run: &mut Run<'_, '_>) -> Result<(), Fail> {
        if self.params.error_recovery_level == 0 {
            return Ok(());
        }
        for ci in 0..self.conns.len() {
            if !run.tasks.iter().any(|t| t.conn == ci) {
                continue;
            }
            let c = conn_mut(&mut self.conns, ci)?;
            if now < c.quiet_since + self.opts.snack_timeout {
                continue;
            }
            c.quiet_since = now;
            c.nudges += 1;
            if c.nudges > MAX_RETRIES {
                return Err(IscsiError::TimedOut.into());
            }
            let mut status_due = false;
            for ti in 0..run.tasks.len() {
                let Some(t) = run.tasks.get(ti) else { continue };
                if t.conn != ci || t.tmf.is_some() {
                    continue;
                }
                let lun = run.jobs.get(t.job).map_or([0; 8], |j| j.lun);
                let (itt, cmd_sn, read, write, data_sn, r2t_sn) =
                    (t.itt, t.cmd_sn, t.read, t.write, t.data_sn, t.r2t_sn);
                let probed = t.probed;
                if sn_lt(cmd_sn, self.exp_cmd_sn) {
                    // The target has the command. A read may be missing
                    // data, a write an R2T; a missing status is asked for
                    // below.
                    if read {
                        self.send_snack(ci, snack::DATA_R2T, lun, itt, RESERVED_TAG, data_sn, 0, run.deadline)?;
                        status_due = true;
                    } else if write && t.sent < t.expected {
                        self.send_snack(ci, snack::DATA_R2T, lun, itt, RESERVED_TAG, r2t_sn, 1, run.deadline)?;
                    } else {
                        status_due = true;
                    }
                } else if !probed {
                    // The target has not acknowledged the command: it may not
                    // have arrived, or its answer may be lost. A ping gets
                    // the target's ExpCmdSN, which tells the two apart; the
                    // command is sent again only if the next round still finds
                    // it unacknowledged.
                    let probe = Message::NopOut(NopOut {
                        immediate: true,
                        lun: [0; 8],
                        itt: self.next_itt(),
                        ttt: RESERVED_TAG,
                        cmd_sn: self.cmd_sn,
                        exp_stat_sn: self.exp_stat_sn(ci),
                        data: Vec::new(),
                    });
                    if let Some(t) = run.tasks.get_mut(ti) {
                        t.probed = true;
                    }
                    self.send_on(ci, probe, run.deadline)?;
                } else {
                    self.retry_command(run, ti, ci)?;
                }
            }
            if status_due {
                let sn = conn_mut(&mut self.conns, ci)?.exp_stat_sn;
                self.send_snack(ci, snack::STATUS, [0; 8], RESERVED_TAG, RESERVED_TAG, sn, 0, run.deadline)?;
            }
        }
        Ok(())
    }

    // ---- Connection recovery ----

    /// Connection `ci` failed with `e`. At error recovery level 2, logs in
    /// again with the same CID and moves its tasks across; otherwise the
    /// session fails.
    fn recover(&mut self, ci: usize, e: IscsiError, run: &mut Run<'_, '_>) -> Result<(), IscsiError> {
        let recoverable = matches!(e, IscsiError::Net(_) | IscsiError::Closed | IscsiError::Digest);
        if self.params.error_recovery_level < 2 || !recoverable || self.discovery {
            return Err(e);
        }
        run.recoveries += 1;
        if run.recoveries > MAX_RECOVERIES {
            return Err(e);
        }
        let (cid, portal, exp_stat_sn) = {
            let c = self.conns.get(ci).ok_or(e)?;
            (c.cid, c.portal, c.exp_stat_sn)
        };
        if let Some(at) = self.reconnect_at.take() {
            while self.poll_net() < at.min(run.deadline) {}
        }
        // The replacement logs in at the end, then takes the old one's place.
        self.add_connection(portal, cid, Kind::Additional, exp_stat_sn)?;
        let Some(fresh) = self.conns.pop() else { return Err(e) };
        let old = core::mem::replace(self.conns.get_mut(ci).ok_or(e)?, fresh);
        old.close(&mut self.net, self.opts.timeout);
        run.deadline = self.now + self.opts.timeout;
        // Each task that was on the connection: the target has the command
        // if its CmdSN is below the ExpCmdSN it reported at this login, and
        // then the task is reassigned; otherwise the command is sent again.
        for ti in 0..run.tasks.len() {
            let Some(t) = run.tasks.get(ti) else { continue };
            if t.conn != ci {
                continue;
            }
            let r = if sn_lt(t.cmd_sn, self.exp_cmd_sn) {
                self.reassign(run, ti, ci)
            } else {
                self.retry_command(run, ti, ci)
            };
            match r {
                Ok(()) => {}
                Err(Fail::Session(e)) => return Err(e),
                // The new connection failed at once.
                Err(Fail::Conn(_, e)) => return Err(e),
            }
        }
        Ok(())
    }

    /// Asks the target to move task `ti` to connection `ci` (TASK REASSIGN).
    fn reassign(&mut self, run: &mut Run<'_, '_>, ti: usize, ci: usize) -> Result<(), Fail> {
        let tag = self.next_itt();
        let t = run.tasks.get_mut(ti).ok_or(IscsiError::Protocol("no such task"))?;
        t.conn = ci;
        t.tmf = Some(tag);
        let lun = run.jobs.get(t.job).map_or([0; 8], |j| j.lun);
        let m = Message::TmfRequest(TmfRequest {
            immediate: true,
            function: tmf::TASK_REASSIGN,
            lun,
            itt: tag,
            ref_task_tag: t.itt,
            cmd_sn: self.cmd_sn,
            exp_stat_sn: self.exp_stat_sn(ci),
            ref_cmd_sn: t.cmd_sn,
            exp_data_sn: if t.read { t.data_sn } else { 0 },
        });
        self.send_on(ci, m, run.deadline)
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

    // ---- Text and logout ----

    /// Sends `SendTargets=All` and returns the target's text.
    pub(crate) fn send_targets(&mut self) -> Result<Vec<u8>, IscsiError> {
        self.guarded(|s| {
            let deadline = s.deadline();
            let itt = s.next_itt();
            let mut ttt = RESERVED_TAG;
            let mut keys = Vec::new();
            text::push(&mut keys, "SendTargets", "All");
            let mut out = Vec::new();
            for _ in 0..MAX_TEXT_EXCHANGES {
                s.wait_window(deadline)?;
                let m = Message::TextRequest(TextRequest {
                    immediate: false,
                    final_pdu: true,
                    cont: false,
                    lun: [0; 8],
                    itt,
                    ttt,
                    cmd_sn: s.cmd_sn,
                    exp_stat_sn: s.exp_stat_sn(0),
                    data: core::mem::take(&mut keys),
                });
                conn_mut(&mut s.conns, 0)?.send(&mut s.net, m, deadline)?;
                s.cmd_sn = s.cmd_sn.wrapping_add(1);
                let Message::TextResponse(r) = s.recv_plain(deadline)? else {
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
            let deadline = s.deadline();
            let itt = s.next_itt();
            let cid = conn_mut(&mut s.conns, 0)?.cid;
            let m = Message::LogoutRequest(LogoutRequest {
                reason: 0, // close the session
                itt,
                cid,
                cmd_sn: s.cmd_sn,
                exp_stat_sn: s.exp_stat_sn(0),
            });
            conn_mut(&mut s.conns, 0)?.send(&mut s.net, m, deadline)?;
            loop {
                match s.recv_plain(deadline)? {
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
        for c in core::mem::take(&mut self.conns) {
            c.close(&mut self.net, self.opts.timeout);
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
        self.addresses.iter().filter_map(|a| parse_portal(a))
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
