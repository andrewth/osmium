//! Transfer Request Blocks (xHCI 1.2 §6.4): the 16-byte entries of every
//! command, transfer and event ring.

use osmium_hal::usb::SetupPacket;

/// A TRB: a 64-bit parameter, a status word and a control word whose bit 0
/// is the cycle bit and bits 10–15 the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Trb {
    /// Parameter (a pointer, or immediate data).
    pub param: u64,
    /// Status (lengths, completion code).
    pub status: u32,
    /// Control (cycle bit, flags, type, slot and endpoint IDs).
    pub control: u32,
}

/// TRB type codes.
pub mod kind {
    #![allow(missing_docs)]
    pub const NORMAL: u32 = 1;
    pub const ISOCH: u32 = 5;
    pub const SETUP_STAGE: u32 = 2;
    pub const DATA_STAGE: u32 = 3;
    pub const STATUS_STAGE: u32 = 4;
    pub const LINK: u32 = 6;
    pub const ENABLE_SLOT: u32 = 9;
    pub const DISABLE_SLOT: u32 = 10;
    pub const ADDRESS_DEVICE: u32 = 11;
    pub const CONFIGURE_ENDPOINT: u32 = 12;
    pub const EVALUATE_CONTEXT: u32 = 13;
    pub const RESET_ENDPOINT: u32 = 14;
    pub const STOP_ENDPOINT: u32 = 15;
    pub const SET_TR_DEQUEUE: u32 = 16;
    pub const NO_OP_COMMAND: u32 = 23;
    pub const TRANSFER_EVENT: u32 = 32;
    pub const COMMAND_COMPLETION: u32 = 33;
    pub const PORT_STATUS_CHANGE: u32 = 34;
    pub const HOST_CONTROLLER: u32 = 37;
}

/// Completion codes (§6.4.5).
pub mod completion {
    #![allow(missing_docs)]
    pub const SUCCESS: u8 = 1;
    pub const DATA_BUFFER: u8 = 2;
    pub const BABBLE: u8 = 3;
    pub const USB_TRANSACTION: u8 = 4;
    pub const TRB: u8 = 5;
    pub const STALL: u8 = 6;
    pub const RESOURCE: u8 = 7;
    pub const BANDWIDTH_OVERRUN: u8 = 8;
    pub const NO_SLOTS: u8 = 9;
    pub const SLOT_NOT_ENABLED: u8 = 11;
    pub const ENDPOINT_NOT_ENABLED: u8 = 12;
    pub const SHORT_PACKET: u8 = 13;
    pub const RING_UNDERRUN: u8 = 14;
    pub const RING_OVERRUN: u8 = 15;
    pub const PARAMETER: u8 = 17;
    pub const CONTEXT_STATE: u8 = 19;
    pub const MISSED_SERVICE: u8 = 23;
    pub const COMMAND_RING_STOPPED: u8 = 24;
    pub const COMMAND_ABORTED: u8 = 25;
    pub const ISOCH_BUFFER_OVERRUN: u8 = 31;
}

/// Control-word bits.
pub mod flag {
    #![allow(missing_docs)]
    pub const CYCLE: u32 = 1 << 0;
    /// Link TRB: toggle the cycle state when following this link.
    pub const TOGGLE_CYCLE: u32 = 1 << 1;
    /// Interrupt on short packet: generate an event if a transfer ends short.
    pub const ISP: u32 = 1 << 2;
    pub const CHAIN: u32 = 1 << 4;
    /// Interrupt on completion: generate an event when this TRB completes.
    pub const IOC: u32 = 1 << 5;
    /// Immediate data: the parameter holds data, not a pointer.
    pub const IDT: u32 = 1 << 6;
    /// Data/Status Stage direction: IN.
    pub const DIR_IN: u32 = 1 << 16;
    /// Isoch TRB: start as soon as possible instead of in a given frame.
    pub const SIA: u32 = 1 << 31;
}

/// Setup Stage transfer type (TRT).
const TRT_NO_DATA: u32 = 0;
const TRT_OUT: u32 = 2;
const TRT_IN: u32 = 3;

impl Trb {
    const fn new(kind: u32, param: u64, status: u32, control: u32) -> Self {
        Self { param, status, control: control | kind << 10 }
    }

    /// The TRB type.
    pub const fn kind(&self) -> u32 {
        self.control >> 10 & 0x3f
    }

    /// The cycle bit.
    pub const fn cycle(&self) -> bool {
        self.control & flag::CYCLE != 0
    }

    /// Completion code of an event TRB.
    pub const fn completion_code(&self) -> u8 {
        (self.status >> 24) as u8
    }

    /// Slot ID of an event or command TRB.
    pub const fn slot_id(&self) -> u8 {
        (self.control >> 24) as u8
    }

    /// Endpoint ID (DCI) of a Transfer Event.
    pub const fn endpoint_id(&self) -> u8 {
        (self.control >> 16 & 0x1f) as u8
    }

    /// Bytes not transferred, from a Transfer Event.
    pub const fn residual(&self) -> u32 {
        self.status & 0xff_ffff
    }

    /// Port ID of a Port Status Change Event.
    pub const fn port_id(&self) -> u8 {
        (self.param >> 24) as u8
    }

    /// Link TRB pointing at `segment`, toggling the cycle state.
    pub const fn link(segment: u64) -> Self {
        Self::new(kind::LINK, segment, 0, flag::TOGGLE_CYCLE)
    }

    /// No Op Command.
    pub const fn no_op_command() -> Self {
        Self::new(kind::NO_OP_COMMAND, 0, 0, 0)
    }

    /// Enable Slot Command.
    pub const fn enable_slot() -> Self {
        Self::new(kind::ENABLE_SLOT, 0, 0, 0)
    }

    /// Disable Slot Command.
    pub const fn disable_slot(slot: u8) -> Self {
        Self::new(kind::DISABLE_SLOT, 0, 0, (slot as u32) << 24)
    }

    /// Address Device Command with the input context at `input`.
    pub const fn address_device(slot: u8, input: u64) -> Self {
        Self::new(kind::ADDRESS_DEVICE, input, 0, (slot as u32) << 24)
    }

    /// Configure Endpoint Command with the input context at `input`.
    pub const fn configure_endpoint(slot: u8, input: u64) -> Self {
        Self::new(kind::CONFIGURE_ENDPOINT, input, 0, (slot as u32) << 24)
    }

    /// Evaluate Context Command with the input context at `input`.
    pub const fn evaluate_context(slot: u8, input: u64) -> Self {
        Self::new(kind::EVALUATE_CONTEXT, input, 0, (slot as u32) << 24)
    }

    /// Reset Endpoint Command (recovers a halted endpoint).
    pub const fn reset_endpoint(slot: u8, dci: u8) -> Self {
        Self::new(kind::RESET_ENDPOINT, 0, 0, (slot as u32) << 24 | (dci as u32) << 16)
    }

    /// Stop Endpoint Command (halts a running endpoint so its ring can be
    /// moved).
    pub const fn stop_endpoint(slot: u8, dci: u8) -> Self {
        Self::new(kind::STOP_ENDPOINT, 0, 0, (slot as u32) << 24 | (dci as u32) << 16)
    }

    /// Set TR Dequeue Pointer Command: the endpoint resumes at `dequeue`
    /// with cycle state `cycle`.
    pub const fn set_tr_dequeue(slot: u8, dci: u8, dequeue: u64, cycle: bool) -> Self {
        Self::new(kind::SET_TR_DEQUEUE, dequeue | cycle as u64, 0, (slot as u32) << 24 | (dci as u32) << 16)
    }

    /// Setup Stage with the request inline. The transfer type follows the
    /// request: no data stage if `wLength` is 0, else one in its direction.
    pub const fn setup_stage(setup: &SetupPacket) -> Self {
        let trt = if setup.length == 0 {
            TRT_NO_DATA
        } else if setup.request_type & 0x80 != 0 {
            TRT_IN
        } else {
            TRT_OUT
        };
        Self::new(kind::SETUP_STAGE, setup.to_u64(), 8, flag::IDT | trt << 16)
    }

    /// Data Stage of `len` bytes at `buf`.
    pub const fn data_stage(buf: u64, len: u32, dir_in: bool) -> Self {
        let dir = if dir_in { flag::DIR_IN } else { 0 };
        Self::new(kind::DATA_STAGE, buf, len, dir | flag::ISP | flag::IOC)
    }

    /// Status Stage, which runs opposite to the data stage (IN if there was
    /// none).
    pub const fn status_stage(dir_in: bool) -> Self {
        let dir = if dir_in { flag::DIR_IN } else { 0 };
        Self::new(kind::STATUS_STAGE, 0, 0, dir | flag::IOC)
    }

    /// Isochronous TRB moving `len` bytes at `buf` in one service interval
    /// (a whole TD in one TRB). `packets` is the number of max-size packets
    /// the TD spans; `burst` the endpoint's Max Burst Size; `ss` whether the
    /// device is SuperSpeed (which counts bursts; high speed puts the
    /// transactions of the microframe in TLBPC). `frame` is the 11-bit frame
    /// to send it in, or `None` for as soon as possible. Interrupts on
    /// completion.
    pub const fn isoch(
        buf: u64,
        len: u32,
        packets: u32,
        burst: u32,
        ss: bool,
        frame: Option<u16>,
        dir_in: bool,
    ) -> Self {
        let packets = if packets == 0 { 1 } else { packets };
        let (tbc, tlbpc) =
            if ss { ((packets - 1) / (burst + 1), (packets - 1) % (burst + 1)) } else { (0, packets - 1) };
        let when = match frame {
            Some(f) => (f as u32 & 0x7ff) << 20,
            None => flag::SIA,
        };
        let isp = if dir_in { flag::ISP } else { 0 };
        Self::new(kind::ISOCH, buf, len & 0x1_ffff, isp | flag::IOC | tbc << 7 | tlbpc << 16 | when)
    }

    /// Normal TRB for a bulk or interrupt transfer of `len` bytes at `buf`.
    pub const fn normal(buf: u64, len: u32) -> Self {
        Self::new(kind::NORMAL, buf, len, flag::ISP | flag::IOC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        let s = SetupPacket::get_descriptor(1, 0, 18);
        let t = Trb::setup_stage(&s);
        assert_eq!(t.kind(), kind::SETUP_STAGE);
        assert_eq!(t.status, 8);
        assert_eq!(t.control >> 16 & 3, TRT_IN);
        assert_eq!(t.param, 0x0012_0000_0100_0680);
        assert_eq!(Trb::setup_stage(&SetupPacket::set_configuration(1)).control >> 16 & 3, TRT_NO_DATA);

        let ev = Trb { param: 0x1000, status: (13 << 24) | 5, control: (3 << 24) | (2 << 16) | (32 << 10) | 1 };
        assert_eq!((ev.kind(), ev.completion_code(), ev.residual()), (kind::TRANSFER_EVENT, 13, 5));
        assert_eq!((ev.slot_id(), ev.endpoint_id(), ev.cycle()), (3, 2, true));

        assert_eq!(Trb::set_tr_dequeue(1, 3, 0x2000, true).param, 0x2001);
        // A high-speed 3-packet TD in frame 5, and a SuperSpeed 7-packet one (burst 3) as soon as possible.
        let hs = Trb::isoch(0x1000, 3072, 3, 2, false, Some(5), false);
        assert_eq!((hs.kind(), hs.param, hs.status), (kind::ISOCH, 0x1000, 3072));
        assert_eq!((hs.control >> 16 & 0xf, hs.control >> 7 & 3, hs.control >> 20 & 0x7ff), (2, 0, 5));
        assert_eq!(hs.control & (flag::SIA | flag::IOC | flag::ISP), flag::IOC);
        let ss = Trb::isoch(0x1000, 7000, 7, 3, true, None, true);
        assert_eq!((ss.control >> 7 & 3, ss.control >> 16 & 0xf), (1, 2));
        assert_eq!(ss.control & (flag::SIA | flag::IOC | flag::ISP), flag::SIA | flag::IOC | flag::ISP);

        assert_eq!(Trb::link(0x3000).control, (kind::LINK << 10) | flag::TOGGLE_CYCLE);
    }
}
