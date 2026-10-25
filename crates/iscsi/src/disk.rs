//! Logical units of an iSCSI target as [`BlockDevice`]s.

use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::net::SocketAddrV4;

use osmium_hal::block::{BlockDevice, BlockError};

use crate::IscsiError;
use crate::net::Net;
use crate::params::Params;
use crate::pdu::lun_field;
use crate::scsi::{self, Capacity, Cdb, Inquiry, sense_key};
use crate::session::{Data, Job, Options, Session};

/// TEST UNIT READY attempts while the unit reports UNIT ATTENTION or NOT
/// READY after login.
const READY_TRIES: usize = 10;

/// Attempts at a command that fails with UNIT ATTENTION (a reset or a
/// capacity change reported once to each initiator).
const ATTENTION_TRIES: usize = 3;

/// The block sizes accepted: powers of two in this range.
const MIN_BLOCK_SIZE: u32 = 512;
const MAX_BLOCK_SIZE: u32 = 64 * 1024;

/// The most bytes of REPORT LUNS data asked for (8 per unit, so 8191 units).
const MAX_LUN_LIST: usize = 64 * 1024;

type Shared<N> = Rc<RefCell<Session<N>>>;

/// Runs `f` on the session, unless something has it borrowed.
fn with<N: Net, R>(
    session: &Shared<N>,
    f: impl FnOnce(&mut Session<N>) -> Result<R, IscsiError>,
) -> Result<R, IscsiError> {
    f(&mut *session.try_borrow_mut().map_err(|_| IscsiError::Busy)?)
}

/// Runs `jobs`, running again the ones the unit failed with UNIT ATTENTION.
/// Returns the bytes each moved.
fn run_retried<N: Net>(session: &Shared<N>, jobs: Vec<Job<'_>>) -> Result<Vec<usize>, IscsiError> {
    let mut moved: Vec<usize> = vec![0; jobs.len()];
    let mut pending: Vec<(usize, Job<'_>)> = jobs.into_iter().enumerate().collect();
    for attempt in 0..ATTENTION_TRIES {
        let (index, mut batch): (Vec<usize>, Vec<Job<'_>>) = pending.into_iter().unzip();
        let results = with(session, |s| s.run(&mut batch))?;
        pending = Vec::new();
        for ((i, job), r) in index.into_iter().zip(batch).zip(results) {
            match r {
                Ok(n) => {
                    if let Some(slot) = moved.get_mut(i) {
                        *slot = n;
                    }
                }
                Err(e) if e.sense_key() == Some(sense_key::UNIT_ATTENTION) && attempt + 1 < ATTENTION_TRIES => {
                    pending.push((i, job));
                }
                Err(e) => return Err(e),
            }
        }
        if pending.is_empty() {
            break;
        }
    }
    Ok(moved)
}

/// A session with a target: one or more TCP connections, shared by the
/// block devices of the target's logical units.
///
/// [`connect`](Self::connect) logs in and asks the target which units it has
/// (REPORT LUNS); [`disk`](Self::disk) opens one as an [`IscsiDisk`]. The
/// disks share the session, and so its connections and its command
/// numbering; the session logs out when the last of them (and this handle)
/// is dropped.
pub struct IscsiSession<N: Net> {
    session: Shared<N>,
    luns: Vec<u16>,
}

impl<N: Net> IscsiSession<N> {
    /// Connects to the portal at `target`, logs in to `opts.target_name` and
    /// reports the target's logical units. A target that does not know
    /// REPORT LUNS is taken to have just `opts.lun`.
    pub fn connect(net: N, target: SocketAddrV4, opts: &Options) -> Result<Self, IscsiError> {
        let session = Session::login(net, target, opts, false)?;
        let mut s = Self { session: Rc::new(RefCell::new(session)), luns: Vec::new() };
        s.luns = match s.report_luns() {
            Ok(l) => l,
            Err(e) if e.sense_key() == Some(sense_key::ILLEGAL_REQUEST) => vec![opts.lun],
            Err(e) => return Err(e),
        };
        Ok(s)
    }

    /// The logical units the target reported at login.
    pub fn luns(&self) -> &[u16] {
        &self.luns
    }

    /// Asks the target for its logical units again.
    pub fn report_luns(&mut self) -> Result<Vec<u16>, IscsiError> {
        let mut len = 512;
        loop {
            let mut d = vec![0u8; len];
            let jobs = vec![Job { lun: lun_field(0), cdb: scsi::report_luns(len as u32), data: Data::In(&mut d) }];
            let n = run_retried(&self.session, jobs)?.first().copied().unwrap_or(0);
            let (luns, needed) = scsi::parse_report_luns(d.get(..n).unwrap_or_default())
                .ok_or(IscsiError::Protocol("short REPORT LUNS"))?;
            // The list was cut short: ask again with room for all of it.
            if needed > len && len < MAX_LUN_LIST {
                len = needed.min(MAX_LUN_LIST);
                continue;
            }
            return Ok(luns);
        }
    }

    /// Opens logical unit `lun`: waits for it to become ready and reads its
    /// identification and capacity.
    pub fn disk(&self, lun: u16) -> Result<IscsiDisk<N>, IscsiError> {
        IscsiDisk::open(self.session.clone(), lun)
    }

    /// The connections the session has open.
    pub fn connections(&self) -> usize {
        self.session.try_borrow().map_or(0, |s| s.connections())
    }

    /// The operational parameters negotiated at login.
    pub fn params(&self) -> Result<Params, IscsiError> {
        Ok(self.session.try_borrow().map_err(|_| IscsiError::Busy)?.params().clone())
    }

    /// Runs `f` on the network stack, e.g. to serve other sockets between
    /// operations.
    pub fn with_net<R>(&mut self, f: impl FnOnce(&mut N) -> R) -> Result<R, IscsiError> {
        with(&self.session, |s| Ok(s.with_net(f)))
    }

    /// Logs out of the session. Every disk of it then fails with
    /// [`IscsiError::NoSession`].
    pub fn logout(&mut self) -> Result<(), IscsiError> {
        with(&self.session, |s| s.logout())
    }
}

/// A logical unit of an iSCSI target: commands on the session it was opened
/// from, over whichever of its connections are free.
///
/// Every operation blocks, pumping the network until the target answers or
/// a command has taken [`Options::timeout`]. Reads and writes are split into
/// commands of at most `MaxBurstLength` bytes, which run in parallel on a
/// session with several connections; one the target moves only part of (an
/// underflow) fails. Dropping the last handle on the session logs out and
/// closes its connections, which also pumps the network.
pub struct IscsiDisk<N: Net> {
    session: Shared<N>,
    lun: u16,
    inquiry: Inquiry,
    capacity: Capacity,
    params: Params,
}

impl<N: Net> IscsiDisk<N> {
    /// Connects to the portal at `target`, logs in to `opts.target_name`,
    /// waits for LUN `opts.lun` to become ready, and reads its
    /// identification and capacity.
    pub fn connect(net: N, target: SocketAddrV4, opts: &Options) -> Result<Self, IscsiError> {
        let session = Session::login(net, target, opts, false)?;
        Self::open(Rc::new(RefCell::new(session)), opts.lun)
    }

    fn open(session: Shared<N>, lun: u16) -> Result<Self, IscsiError> {
        let field = lun_field(lun);
        let command = |cdb: Cdb, data: Data<'_>| with(&session, |s| s.command(field, &cdb, data));
        // The first command after login usually reports UNIT ATTENTION
        // (power on or reset), and a unit may be NOT READY for a while.
        let mut tries = 0;
        loop {
            match command(scsi::test_unit_ready(), Data::None) {
                Ok(_) => break,
                Err(e)
                    if tries + 1 < READY_TRIES
                        && matches!(e.sense_key(), Some(sense_key::UNIT_ATTENTION | sense_key::NOT_READY)) =>
                {
                    tries += 1
                }
                Err(e) => return Err(e),
            }
        }
        let mut d = [0u8; 96];
        let n = command(scsi::inquiry(d.len() as u16), Data::In(&mut d))?;
        let inquiry = Inquiry::parse(d.get(..n).ok_or(IscsiError::Protocol("short INQUIRY data"))?)
            .ok_or(IscsiError::Protocol("short INQUIRY data"))?;
        // A target answers INQUIRY for a unit it does not have with
        // peripheral qualifier 3 (not supported).
        if inquiry.peripheral >> 5 == 3 {
            return Err(IscsiError::Protocol("no such logical unit"));
        }

        let mut d = [0u8; 32];
        let n = command(scsi::read_capacity_10(), Data::In(d.get_mut(..8).unwrap_or_default()))?;
        let mut capacity = Capacity::parse_10(d.get(..n).unwrap_or_default())
            .ok_or(IscsiError::Protocol("short READ CAPACITY data"))?;
        if capacity.last_lba == u32::MAX as u64 {
            let n = command(scsi::read_capacity_16(), Data::In(&mut d))?;
            capacity = Capacity::parse_16(d.get(..n).unwrap_or_default())
                .ok_or(IscsiError::Protocol("short READ CAPACITY data"))?;
        }
        let bs = capacity.block_size;
        if !bs.is_power_of_two() || !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&bs) || capacity.last_lba == u64::MAX {
            return Err(IscsiError::Protocol("unusable capacity"));
        }
        let params = with(&session, |s| Ok(s.params().clone()))?;
        Ok(Self { session, lun, inquiry, capacity, params })
    }

    /// The unit's identification.
    pub fn inquiry(&self) -> &Inquiry {
        &self.inquiry
    }

    /// The unit's size.
    pub fn capacity(&self) -> Capacity {
        self.capacity
    }

    /// The logical unit number.
    pub fn lun(&self) -> u16 {
        self.lun
    }

    /// The operational parameters negotiated at login.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// The connections the session has open.
    pub fn connections(&self) -> usize {
        self.session.try_borrow().map_or(0, |s| s.connections())
    }

    /// Where the session's first connection is logged in: the portal given
    /// to `connect`, or where a login redirection sent it.
    pub fn portal(&self) -> Option<SocketAddrV4> {
        self.session.try_borrow().ok().map(|s| s.portal())
    }

    /// Whether the target moved the login permanently: use
    /// [`portal`](Self::portal) from now on.
    pub fn moved_permanently(&self) -> bool {
        self.session.try_borrow().is_ok_and(|s| s.moved_permanently())
    }

    /// Runs `f` on the network stack, e.g. to serve other sockets between
    /// operations. Fails if the session is in use.
    pub fn with_net<R>(&mut self, f: impl FnOnce(&mut N) -> R) -> Result<R, IscsiError> {
        with(&self.session, |s| Ok(s.with_net(f)))
    }

    /// True until the session logs out or fails.
    pub fn is_logged_in(&self) -> bool {
        self.session.try_borrow().is_ok_and(|s| s.is_open())
    }

    /// Runs any SCSI command on the unit and returns the bytes moved. A
    /// status other than GOOD is [`IscsiError::Scsi`].
    pub fn execute(&mut self, cdb: &Cdb, data: Data<'_>) -> Result<usize, IscsiError> {
        let lun = lun_field(self.lun);
        with(&self.session, |s| s.command(lun, cdb, data))
    }

    /// Runs a command, retrying it while the unit reports UNIT ATTENTION.
    fn retried(&mut self, cdb: &Cdb, data: Data<'_>) -> Result<usize, IscsiError> {
        let job = Job { lun: lun_field(self.lun), cdb: *cdb, data };
        Ok(run_retried(&self.session, vec![job])?.first().copied().unwrap_or(0))
    }

    /// Logs out of the session (all of its units). Later operations fail;
    /// dropping the disk then only closes the connections.
    pub fn logout(&mut self) -> Result<(), IscsiError> {
        with(&self.session, |s| s.logout())
    }

    /// Blocks per command: what fits in `MaxBurstLength`.
    fn chunk_blocks(&self) -> usize {
        let bs = self.capacity.block_size as usize;
        (self.params.max_burst_length as usize / bs).clamp(1, scsi::MAX_BLOCKS_10 as usize)
    }
}

impl<N: Net> BlockDevice for IscsiDisk<N> {
    fn block_size(&self) -> usize {
        self.capacity.block_size as usize
    }

    fn num_blocks(&self) -> u64 {
        self.capacity.blocks()
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let (bs, step) = (self.block_size(), self.chunk_blocks());
        let lun = lun_field(self.lun);
        let jobs: Vec<Job<'_>> = buf
            .chunks_mut(step * bs)
            .enumerate()
            .map(|(i, chunk)| Job {
                lun,
                cdb: scsi::read(lba + (i * step) as u64, (chunk.len() / bs) as u32),
                data: Data::In(chunk),
            })
            .collect();
        let lens: Vec<usize> = jobs
            .iter()
            .map(|j| match &j.data {
                Data::In(b) => b.len(),
                _ => 0,
            })
            .collect();
        let moved = run_retried(&self.session, jobs)?;
        if moved != lens {
            return Err(BlockError::Io); // the target sent less
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let (bs, step) = (self.block_size(), self.chunk_blocks());
        let lun = lun_field(self.lun);
        let jobs: Vec<Job<'_>> = buf
            .chunks(step * bs)
            .enumerate()
            .map(|(i, chunk)| Job {
                lun,
                cdb: scsi::write(lba + (i * step) as u64, (chunk.len() / bs) as u32),
                data: Data::Out(chunk),
            })
            .collect();
        let lens: Vec<usize> = buf.chunks(step * bs).map(<[u8]>::len).collect();
        let moved = run_retried(&self.session, jobs)?;
        if moved != lens {
            return Err(BlockError::Io); // the target took less
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        match self.retried(&scsi::synchronize_cache_10(), Data::None) {
            // A unit without a write cache may not know the command.
            Err(e) if e.sense_key() == Some(sense_key::ILLEGAL_REQUEST) => Ok(()),
            r => r.map(drop).map_err(BlockError::from),
        }
    }
}

#[cfg(test)]
impl<N: Net> IscsiDisk<N> {
    /// The network stack, for tests that play the other end of it. Works
    /// while the disk is the only handle on its session.
    pub(crate) fn net_mut(&mut self) -> &mut N {
        let cell = Rc::get_mut(&mut self.session).expect("the disk is the only handle on its session");
        cell.get_mut().net_mut()
    }
}
