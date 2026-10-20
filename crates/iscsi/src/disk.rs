//! A logical unit of an iSCSI target as a [`BlockDevice`].

use core::net::SocketAddrV4;

use osmium_hal::block::{BlockDevice, BlockError};

use crate::IscsiError;
use crate::net::Net;
use crate::params::Params;
use crate::scsi::{self, Capacity, Cdb, Inquiry, sense_key};
use crate::session::{Data, Options, Session};

/// TEST UNIT READY attempts while the unit reports UNIT ATTENTION or NOT
/// READY after login.
const READY_TRIES: usize = 10;

/// Attempts at a command that fails with UNIT ATTENTION (a reset or a
/// capacity change reported once to each initiator).
const ATTENTION_TRIES: usize = 3;

/// The largest block size accepted.
const MAX_BLOCK_SIZE: u32 = 64 * 1024;

/// A disk on an iSCSI target: one session to one logical unit, driving its
/// TCP connection through a [`Net`].
///
/// Every operation blocks, pumping the network until the target answers or
/// [`Options::timeout`] passes without progress. Reads and writes are split
/// into commands of at most `MaxBurstLength` bytes. Dropping the disk logs
/// out and closes the connection, which also pumps the network.
pub struct IscsiDisk<N: Net> {
    session: Session<N>,
    inquiry: Inquiry,
    capacity: Capacity,
}

impl<N: Net> IscsiDisk<N> {
    /// Connects to the portal at `target`, logs in to `opts.target_name`,
    /// waits for LUN `opts.lun` to become ready, and reads its
    /// identification and capacity.
    pub fn connect(net: N, target: SocketAddrV4, opts: &Options) -> Result<Self, IscsiError> {
        let mut session = Session::login(net, target, opts, false)?;
        // The first command after login usually reports UNIT ATTENTION
        // (power on or reset), and a unit may be NOT READY for a while.
        let mut tries = 0;
        loop {
            match session.command(&scsi::test_unit_ready(), Data::None) {
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
        let n = session.command(&scsi::inquiry(d.len() as u16), Data::In(&mut d))?;
        let inquiry = Inquiry::parse(&d[..n]).ok_or(IscsiError::Protocol("short INQUIRY data"))?;

        let mut d = [0u8; 32];
        let n = session.command(&scsi::read_capacity_10(), Data::In(&mut d[..8]))?;
        let mut capacity = Capacity::parse_10(&d[..n]).ok_or(IscsiError::Protocol("short READ CAPACITY data"))?;
        if capacity.last_lba == u32::MAX as u64 {
            let n = session.command(&scsi::read_capacity_16(), Data::In(&mut d))?;
            capacity = Capacity::parse_16(&d[..n]).ok_or(IscsiError::Protocol("short READ CAPACITY data"))?;
        }
        if capacity.block_size == 0 || capacity.block_size > MAX_BLOCK_SIZE || capacity.last_lba == u64::MAX {
            return Err(IscsiError::Protocol("unusable capacity"));
        }
        Ok(Self { session, inquiry, capacity })
    }

    /// The unit's identification.
    pub fn inquiry(&self) -> &Inquiry {
        &self.inquiry
    }

    /// The unit's size.
    pub fn capacity(&self) -> Capacity {
        self.capacity
    }

    /// The operational parameters negotiated at login.
    pub fn params(&self) -> &Params {
        self.session.params()
    }

    /// The network stack, e.g. to serve other sockets between operations.
    pub fn net_mut(&mut self) -> &mut N {
        self.session.net()
    }

    /// True until the session logs out or fails.
    pub fn is_logged_in(&self) -> bool {
        self.session.is_open()
    }

    /// Runs any SCSI command on the unit and returns the bytes moved. A
    /// status other than GOOD is [`IscsiError::Scsi`].
    pub fn execute(&mut self, cdb: &Cdb, data: Data<'_>) -> Result<usize, IscsiError> {
        self.session.command(cdb, data)
    }

    /// Runs a command, retrying it while the unit reports UNIT ATTENTION.
    fn retried(&mut self, cdb: &Cdb, mut data: Data<'_>) -> Result<usize, IscsiError> {
        let mut tries = 0;
        loop {
            let d = match &mut data {
                Data::None => Data::None,
                Data::In(b) => Data::In(b),
                Data::Out(b) => Data::Out(b),
            };
            match self.session.command(cdb, d) {
                Err(e) if e.sense_key() == Some(sense_key::UNIT_ATTENTION) && tries + 1 < ATTENTION_TRIES => tries += 1,
                r => return r,
            }
        }
    }

    /// Logs out. Later operations fail; dropping the disk then only closes
    /// the connection.
    pub fn logout(&mut self) -> Result<(), IscsiError> {
        self.session.logout()
    }

    /// Blocks per command: what fits in `MaxBurstLength`.
    fn chunk_blocks(&self) -> usize {
        let bs = self.capacity.block_size as usize;
        (self.params().max_burst_length as usize / bs).clamp(1, scsi::MAX_BLOCKS_10 as usize)
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
        for (i, chunk) in buf.chunks_mut(step * bs).enumerate() {
            let cdb = scsi::read(lba + (i * step) as u64, (chunk.len() / bs) as u32);
            let len = chunk.len();
            if self.retried(&cdb, Data::In(chunk))? != len {
                return Err(BlockError::Io); // the target sent less
            }
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let (bs, step) = (self.block_size(), self.chunk_blocks());
        for (i, chunk) in buf.chunks(step * bs).enumerate() {
            let cdb = scsi::write(lba + (i * step) as u64, (chunk.len() / bs) as u32);
            self.retried(&cdb, Data::Out(chunk))?;
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
