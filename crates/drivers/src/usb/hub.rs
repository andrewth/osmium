//! USB hubs (class 09, USB 2.0 chapter 11 and USB 3.x chapter 10).
//!
//! [`Hub`] drives one hub that is already enumerated and configured: it
//! reads the hub descriptor, tells the host controller about the hub
//! ([`UsbHost::configure_hub`], which sets the slot context's hub, port-count,
//! think-time and multi-TT fields), powers the ports, and turns the hub's
//! status-change endpoint into connect and disconnect events.
//! [`Hub::poll_events`] resets a port that got a device and addresses the
//! device through [`UsbHost::attach_hub_port`], so the controller can build
//! its route string and transaction-translator fields. The caller then
//! enumerates the new device as it would one on a root port, and may find that
//! it is a hub too (hubs nest five deep).
//!
//! Nothing here waits on a clock: the driver has no timer, so the caller
//! sleeps [`Hub::power_on_delay_ms`] after [`Hub::power_ports`], and port
//! resets are polled with a bounded number of status reads.

use osmium_hal::usb::{
    DeviceId, Direction, Recipient, RequestKind, SetupPacket, Speed, TransferType, UsbError, UsbHost, descriptor_type,
    find_interface,
};

/// Most ports a hub may have for this driver (the change bitmap and the
/// child table are sized for it).
pub const MAX_HUB_PORTS: u8 = 31;

/// Hub class request codes.
mod req {
    pub const GET_STATUS: u8 = 0;
    pub const CLEAR_FEATURE: u8 = 1;
    pub const SET_FEATURE: u8 = 3;
    pub const GET_DESCRIPTOR: u8 = 6;
    pub const SET_HUB_DEPTH: u8 = 12;
}

/// Port feature selectors.
mod feature {
    pub const PORT_RESET: u16 = 4;
    pub const PORT_POWER: u16 = 8;
    pub const C_PORT_CONNECTION: u16 = 16;
    pub const C_PORT_ENABLE: u16 = 17;
    pub const C_PORT_SUSPEND: u16 = 18;
    pub const C_PORT_OVER_CURRENT: u16 = 19;
    pub const C_PORT_RESET: u16 = 20;
}

/// `wPortStatus` / `wPortChange` bits common to both speeds.
const CONNECTION: u16 = 1 << 0;
const ENABLE: u16 = 1 << 1;
const OVER_CURRENT: u16 = 1 << 3;
const RESET: u16 = 1 << 4;
/// USB 2 only.
const POWER_2: u16 = 1 << 8;
const LOW_SPEED: u16 = 1 << 9;
const HIGH_SPEED: u16 = 1 << 10;
/// USB 3 only.
const POWER_3: u16 = 1 << 9;

/// How many times a port's status is read while waiting for its reset.
const RESET_POLLS: u32 = 2000;

/// A hub port's status and change bits (`GET_STATUS` on a port).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortState {
    /// `wPortStatus`.
    pub status: u16,
    /// `wPortChange`.
    pub change: u16,
    /// The hub is a SuperSpeed one, which lays out the speed and power bits
    /// differently.
    pub super_speed: bool,
}

impl PortState {
    /// A device is attached.
    pub fn connected(&self) -> bool {
        self.status & CONNECTION != 0
    }

    /// The port is enabled (its reset completed).
    pub fn enabled(&self) -> bool {
        self.status & ENABLE != 0
    }

    /// The port has power.
    pub fn powered(&self) -> bool {
        self.status & if self.super_speed { POWER_3 } else { POWER_2 } != 0
    }

    /// The device draws too much current.
    pub fn over_current(&self) -> bool {
        self.status & OVER_CURRENT != 0
    }

    /// A device connected or disconnected since the change was cleared.
    pub fn connect_changed(&self) -> bool {
        self.change & CONNECTION != 0
    }

    /// Speed of the attached device.
    pub fn speed(&self) -> Option<Speed> {
        if !self.connected() {
            None
        } else if self.super_speed {
            Some(Speed::Super)
        } else if self.status & LOW_SPEED != 0 {
            Some(Speed::Low)
        } else if self.status & HIGH_SPEED != 0 {
            Some(Speed::High)
        } else {
            Some(Speed::Full)
        }
    }
}

/// What happened on a hub port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortEvent {
    /// A device was plugged in, reset and addressed. It is not yet
    /// configured: run [`enumerate`-style bring-up](osmium_hal::usb::set_configuration)
    /// on it.
    Connected {
        /// The hub port (from 1).
        port: u8,
        /// The addressed device.
        device: DeviceId,
        /// Its speed.
        speed: Speed,
    },
    /// The device on `port` was unplugged and its resources released.
    Disconnected {
        /// The hub port.
        port: u8,
        /// The device that was there.
        device: Option<DeviceId>,
    },
    /// A device is on `port` but could not be reset or addressed.
    Failed {
        /// The hub port.
        port: u8,
        /// Why.
        error: UsbError,
    },
}

/// A set of ports (bit `n` is port `n`; bit 0 is the hub itself) from the
/// status-change endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PortSet(u32);

impl PortSet {
    fn take_lowest(&mut self) -> Option<u8> {
        if self.0 == 0 {
            return None;
        }
        let p = self.0.trailing_zeros() as u8;
        self.0 &= self.0 - 1;
        Some(p)
    }
}

/// A hub class driver.
pub struct Hub<H: UsbHost> {
    host: H,
    dev: DeviceId,
    ports: u8,
    super_speed: bool,
    power_on_ms: u32,
    status_ep: u8,
    /// A status-change transfer is outstanding.
    armed: bool,
    /// Ports still to examine from the last status-change report.
    pending: PortSet,
    /// The device on each port, index 0 being port 1.
    children: [Option<DeviceId>; MAX_HUB_PORTS as usize],
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

impl<H: UsbHost> Hub<H> {
    /// Takes over the hub `dev`, whose configuration descriptor set is
    /// `config` and which is already configured. `ss_depth` is `Some(tier)`
    /// for a SuperSpeed hub (0 for one plugged into a root port), which must
    /// be told its depth. Fails with `BadDescriptor` if `config` has no hub
    /// interface or the hub descriptor is malformed, and `Unsupported` for
    /// more than [`MAX_HUB_PORTS`] ports.
    pub fn new(mut host: H, dev: DeviceId, config: &[u8], ss_depth: Option<u8>) -> Result<Self, UsbError> {
        let iface = find_interface(config, |i| i.class == 9).ok_or(UsbError::BadDescriptor)?;
        let status_ep = iface.endpoint(TransferType::Interrupt, Direction::In).ok_or(UsbError::BadDescriptor)?.address;
        let super_speed = ss_depth.is_some();
        if let Some(depth) = ss_depth {
            let setup = SetupPacket::new(
                Direction::Out,
                RequestKind::Class,
                Recipient::Device,
                req::SET_HUB_DEPTH,
                depth as u16,
                0,
                0,
            );
            host.control_out(dev, setup, &[])?;
        }
        let ty = if super_speed { descriptor_type::SS_HUB } else { descriptor_type::HUB };
        let setup = SetupPacket::new(
            Direction::In,
            RequestKind::Class,
            Recipient::Device,
            req::GET_DESCRIPTOR,
            (ty as u16) << 8,
            0,
            16,
        );
        let mut d = [0u8; 16];
        let n = host.control_in(dev, setup, &mut d)?;
        let min = if super_speed { 10 } else { 7 };
        if n < min || (d[0] as usize) < min || d[1] != ty {
            return Err(UsbError::BadDescriptor);
        }
        let ports = d[2];
        if ports == 0 {
            return Err(UsbError::BadDescriptor);
        }
        if ports > MAX_HUB_PORTS {
            return Err(UsbError::Unsupported);
        }
        // wHubCharacteristics bits 5-6: TT think time (USB 2 only).
        let think_time = if super_speed { 0 } else { (le16(&d, 3) >> 5 & 3) as u8 };
        // A multi-TT hub (interface protocol 2) gives each port its own
        // translator once alternate setting 1 is selected.
        let multi_tt = !super_speed && iface.descriptor.protocol == 2;
        if multi_tt {
            host.control_out(dev, SetupPacket::set_interface(iface.descriptor.number, 1), &[])?;
        }
        host.configure_hub(dev, ports, think_time, multi_tt)?;
        Ok(Self {
            host,
            dev,
            ports,
            super_speed,
            power_on_ms: d[5] as u32 * 2,
            status_ep,
            armed: false,
            pending: PortSet(0),
            children: [None; MAX_HUB_PORTS as usize],
        })
    }

    /// The hub's device handle.
    pub fn device(&self) -> DeviceId {
        self.dev
    }

    /// Number of downstream ports.
    pub fn num_ports(&self) -> u8 {
        self.ports
    }

    /// The host controller, for talking to the devices behind the hub.
    pub fn host(&mut self) -> &mut H {
        &mut self.host
    }

    /// Gives the host back, leaving the devices behind the hub attached.
    pub fn into_host(self) -> H {
        self.host
    }

    /// Milliseconds a port needs after power-on before its status is valid
    /// (`bPwrOn2PwrGood` x 2).
    pub fn power_on_delay_ms(&self) -> u32 {
        self.power_on_ms
    }

    /// The device on `port` (from 1), if [`poll_events`](Self::poll_events)
    /// attached one.
    pub fn child(&self, port: u8) -> Option<DeviceId> {
        self.children.get((port as usize).wrapping_sub(1)).copied().flatten()
    }

    fn check_port(&self, port: u8) -> Result<(), UsbError> {
        if port == 0 || port > self.ports { Err(UsbError::NoDevice) } else { Ok(()) }
    }

    fn port_request(&mut self, request: u8, feature: u16, port: u8) -> Result<(), UsbError> {
        self.check_port(port)?;
        let setup =
            SetupPacket::new(Direction::Out, RequestKind::Class, Recipient::Other, request, feature, port as u16, 0);
        self.host.control_out(self.dev, setup, &[])
    }

    /// Turns on power to every port. Wait
    /// [`power_on_delay_ms`](Self::power_on_delay_ms) before reading status.
    pub fn power_ports(&mut self) -> Result<(), UsbError> {
        for port in 1..=self.ports {
            self.port_request(req::SET_FEATURE, feature::PORT_POWER, port)?;
        }
        Ok(())
    }

    /// Reads a port's status and change bits.
    pub fn port_state(&mut self, port: u8) -> Result<PortState, UsbError> {
        self.check_port(port)?;
        let setup =
            SetupPacket::new(Direction::In, RequestKind::Class, Recipient::Other, req::GET_STATUS, 0, port as u16, 4);
        let mut b = [0u8; 4];
        if self.host.control_in(self.dev, setup, &mut b)? < 4 {
            return Err(UsbError::BadDescriptor);
        }
        Ok(PortState { status: le16(&b, 0), change: le16(&b, 2), super_speed: self.super_speed })
    }

    /// Acknowledges every change `state` reports on `port`.
    fn clear_changes(&mut self, port: u8, state: PortState) -> Result<(), UsbError> {
        const CHANGES: [(u16, u16); 5] = [
            (CONNECTION, feature::C_PORT_CONNECTION),
            (ENABLE, feature::C_PORT_ENABLE),
            (1 << 2, feature::C_PORT_SUSPEND),
            (OVER_CURRENT, feature::C_PORT_OVER_CURRENT),
            (RESET, feature::C_PORT_RESET),
        ];
        for (bit, selector) in CHANGES {
            if state.change & bit != 0 {
                self.port_request(req::CLEAR_FEATURE, selector, port)?;
            }
        }
        Ok(())
    }

    /// Resets `port` and returns the speed of the device on it. Fails with
    /// `NoDevice` if nothing is connected and `Transaction` if the port did
    /// not come out of reset enabled.
    pub fn reset_port(&mut self, port: u8) -> Result<Speed, UsbError> {
        if !self.port_state(port)?.connected() {
            return Err(UsbError::NoDevice);
        }
        self.port_request(req::SET_FEATURE, feature::PORT_RESET, port)?;
        for _ in 0..RESET_POLLS {
            let state = self.port_state(port)?;
            if state.change & RESET != 0 {
                self.clear_changes(port, state)?;
                return match state.speed() {
                    Some(speed) if state.enabled() => Ok(speed),
                    _ => Err(UsbError::Transaction),
                };
            }
            if !state.connected() {
                return Err(UsbError::NoDevice);
            }
        }
        Err(UsbError::Timeout)
    }

    /// Resets `port` and addresses the device on it.
    pub fn attach_port(&mut self, port: u8) -> Result<(DeviceId, Speed), UsbError> {
        let speed = self.reset_port(port)?;
        Ok((self.host.attach_hub_port(self.dev, port, speed)?, speed))
    }

    /// Queues every port for examination, to pick up devices that were
    /// plugged in before the hub was powered (their connect change may have
    /// been missed). Call after [`power_ports`](Self::power_ports) and the
    /// power-on delay, then drain [`poll_events`](Self::poll_events).
    pub fn scan(&mut self) {
        self.pending = PortSet(((1u64 << (self.ports + 1)) - 2) as u32);
    }

    /// Returns the next port event, or `None` when there is nothing to do
    /// (the status-change endpoint reports no change). Call repeatedly, from
    /// a poll loop or after an interrupt, until it returns `None`.
    pub fn poll_events(&mut self) -> Result<Option<PortEvent>, UsbError> {
        loop {
            while let Some(port) = self.pending.take_lowest() {
                if port == 0 || port > self.ports {
                    continue; // the hub's own status, or a bit past the last port
                }
                if let Some(event) = self.service_port(port)? {
                    return Ok(Some(event));
                }
            }
            if !self.armed {
                let len = (self.ports as usize + 1).div_ceil(8);
                self.host.submit_in(self.dev, self.status_ep, len)?;
                self.armed = true;
            }
            let mut buf = [0u8; 4];
            match self.host.poll_in(self.dev, self.status_ep, &mut buf) {
                None => return Ok(None),
                Some(result) => {
                    self.armed = false;
                    result?;
                    // The device wrote as many bytes as it has ports to report.
                    self.pending = PortSet(u32::from_le_bytes(buf));
                }
            }
        }
    }

    /// Brings the host's view of `port` in line with the hub's.
    fn service_port(&mut self, port: u8) -> Result<Option<PortEvent>, UsbError> {
        let state = self.port_state(port)?;
        self.clear_changes(port, state)?;
        let slot = port as usize - 1;
        let had = self.children[slot];
        if state.connected() && had.is_some() && !state.connect_changed() {
            return Ok(None);
        }
        // Gone, or gone and back: the old device's resources are released.
        if let Some(old) = self.children[slot].take() {
            self.host.detach(old);
            if state.connected() {
                // Re-attach below; report the departure on the next round.
                self.pending.0 |= 1 << port;
                return Ok(Some(PortEvent::Disconnected { port, device: Some(old) }));
            }
            return Ok(Some(PortEvent::Disconnected { port, device: Some(old) }));
        }
        if !state.connected() {
            return Ok(None);
        }
        Ok(Some(match self.attach_port(port) {
            Ok((device, speed)) => {
                self.children[slot] = Some(device);
                PortEvent::Connected { port, device, speed }
            }
            Err(error) => PortEvent::Failed { port, error },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmium_hal::usb::{EndpointDescriptor, PortStatus};
    use std::vec::Vec;

    /// A USB 2 hub with three ports plus the host calls it triggers.
    #[derive(Default)]
    struct FakeHub {
        /// Per port: status, change.
        ports: [(u16, u16); 3],
        /// The class and interface requests the hub received.
        requests: Vec<(u8, u16, u16)>,
        /// Hub configuration seen by the controller.
        configured: Option<(u8, u8, bool)>,
        attached: Vec<(u8, Speed)>,
        detached: Vec<DeviceId>,
        armed: bool,
        super_speed: bool,
        /// Resets complete only after this many status reads.
        reset_delay: u32,
        resetting: Option<(usize, u32)>,
    }

    impl FakeHub {
        fn plug(&mut self, port: usize, extra: u16) {
            self.ports[port - 1] = (CONNECTION | POWER_2 | extra, CONNECTION);
        }
    }

    impl UsbHost for FakeHub {
        fn num_ports(&self) -> u8 {
            1
        }
        fn port_status(&self, _: u8) -> PortStatus {
            unimplemented!()
        }
        fn attach(&mut self, _: u8) -> Result<DeviceId, UsbError> {
            unimplemented!()
        }
        fn detach(&mut self, dev: DeviceId) {
            self.detached.push(dev);
        }
        fn configure_endpoints(&mut self, _: DeviceId, _: &[EndpointDescriptor]) -> Result<(), UsbError> {
            Ok(())
        }
        fn control_in(&mut self, _: DeviceId, s: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
            match s.request {
                req::GET_DESCRIPTOR => {
                    let ty = (s.value >> 8) as u8;
                    assert_eq!(ty, if self.super_speed { 0x2a } else { 0x29 });
                    // Think time 2 (24 FS bit times), power-good 50 ms.
                    let d = [9, ty, 3, 2 << 5, 0, 25, 100, 0, 0xff];
                    buf[..9].copy_from_slice(&d);
                    Ok(9)
                }
                req::GET_STATUS => {
                    let i = s.index as usize - 1;
                    if let Some((p, left)) = self.resetting
                        && p == i
                    {
                        if left > 0 {
                            self.resetting = Some((p, left - 1));
                        } else {
                            let speed = self.ports[i].0 & (LOW_SPEED | HIGH_SPEED);
                            self.ports[i] = (CONNECTION | ENABLE | POWER_2 | speed, self.ports[i].1 | RESET);
                            self.resetting = None;
                        }
                    }
                    let (st, ch) = self.ports[i];
                    buf[..2].copy_from_slice(&st.to_le_bytes());
                    buf[2..4].copy_from_slice(&ch.to_le_bytes());
                    Ok(4)
                }
                _ => Err(UsbError::Stall),
            }
        }
        fn control_out(&mut self, _: DeviceId, s: SetupPacket, _: &[u8]) -> Result<(), UsbError> {
            self.requests.push((s.request, s.value, s.index));
            match (s.request, s.value) {
                (req::SET_FEATURE, feature::PORT_RESET) => {
                    self.resetting = Some((s.index as usize - 1, self.reset_delay));
                }
                (req::CLEAR_FEATURE, f) => {
                    let bit = match f {
                        feature::C_PORT_CONNECTION => CONNECTION,
                        feature::C_PORT_ENABLE => ENABLE,
                        feature::C_PORT_RESET => RESET,
                        _ => 0,
                    };
                    self.ports[s.index as usize - 1].1 &= !bit;
                }
                _ => {}
            }
            Ok(())
        }
        fn transfer_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Result<usize, UsbError> {
            unimplemented!()
        }
        fn transfer_out(&mut self, _: DeviceId, _: u8, _: &[u8]) -> Result<(), UsbError> {
            unimplemented!()
        }
        fn submit_in(&mut self, _: DeviceId, ep: u8, len: usize) -> Result<(), UsbError> {
            assert_eq!((ep, len), (0x81, 1));
            assert!(!self.armed);
            self.armed = true;
            Ok(())
        }
        fn poll_in(&mut self, _: DeviceId, _: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
            assert!(self.armed);
            let bitmap = self.ports.iter().enumerate().fold(0u8, |m, (i, p)| if p.1 != 0 { m | 2 << i } else { m });
            if bitmap == 0 {
                return None;
            }
            self.armed = false;
            buf[0] = bitmap;
            Some(Ok(1))
        }
        fn attach_hub_port(&mut self, _: DeviceId, port: u8, speed: Speed) -> Result<DeviceId, UsbError> {
            self.attached.push((port, speed));
            Ok(DeviceId(10 + port))
        }
        fn configure_hub(&mut self, _: DeviceId, ports: u8, tt: u8, multi: bool) -> Result<(), UsbError> {
            self.configured = Some((ports, tt, multi));
            Ok(())
        }
    }

    const CONFIG: [u8; 25] = [
        9, 2, 25, 0, 1, 1, 0, 0xe0, 50, //
        9, 4, 0, 0, 1, 9, 0, 1, 0, // hub, single TT
        7, 5, 0x81, 3, 1, 0, 12, // status change endpoint
    ];

    fn hub(fake: &mut FakeHub) -> Hub<&mut FakeHub> {
        Hub::new(fake, DeviceId(1), &CONFIG, None).unwrap()
    }

    #[test]
    fn reads_the_descriptor_and_configures_the_controller() {
        let mut fake = FakeHub::default();
        let mut h = hub(&mut fake);
        assert_eq!((h.num_ports(), h.power_on_delay_ms()), (3, 50));
        h.power_ports().unwrap();
        assert_eq!(fake.configured, Some((3, 2, false)));
        let powered: Vec<_> = fake.requests.iter().filter(|r| r.1 == feature::PORT_POWER).map(|r| r.2).collect();
        assert_eq!(powered, [1, 2, 3]);
    }

    #[test]
    fn multi_tt_hub_selects_alternate_setting() {
        let mut config = CONFIG;
        config[16] = 2; // bInterfaceProtocol
        let mut fake = FakeHub::default();
        Hub::new(&mut fake, DeviceId(1), &config, None).unwrap();
        assert_eq!(fake.configured.map(|c| c.2), Some(true));
        assert!(fake.requests.contains(&(11, 1, 0)), "SET_INTERFACE alternate 1");
    }

    #[test]
    fn superspeed_hub_gets_its_depth() {
        let mut fake = FakeHub { super_speed: true, ..Default::default() };
        // The fake's descriptor is the 9-byte USB 2 shape, too short for a SuperSpeed hub.
        assert_eq!(Hub::new(&mut fake, DeviceId(1), &CONFIG, Some(1)).err(), Some(UsbError::BadDescriptor));
        assert_eq!(fake.requests[0], (req::SET_HUB_DEPTH, 1, 0));
    }

    #[test]
    fn rejects_non_hubs() {
        let mut config = CONFIG;
        config[14] = 3; // HID
        assert_eq!(Hub::new(&mut FakeHub::default(), DeviceId(1), &config, None).err(), Some(UsbError::BadDescriptor));
    }

    #[test]
    fn connect_resets_and_addresses_the_device() {
        let mut fake = FakeHub { reset_delay: 3, ..Default::default() };
        let mut h = hub(&mut fake);
        assert_eq!(h.poll_events(), Ok(None));
        h.host().plug(2, LOW_SPEED);
        assert_eq!(
            h.poll_events(),
            Ok(Some(PortEvent::Connected { port: 2, device: DeviceId(12), speed: Speed::Low }))
        );
        assert_eq!(h.child(2), Some(DeviceId(12)));
        assert_eq!(h.poll_events(), Ok(None), "all changes were acknowledged");
        assert_eq!(fake.attached, [(2, Speed::Low)]);
    }

    #[test]
    fn disconnect_releases_the_device() {
        let mut fake = FakeHub::default();
        let mut h = hub(&mut fake);
        h.host().plug(1, HIGH_SPEED);
        assert!(matches!(h.poll_events(), Ok(Some(PortEvent::Connected { speed: Speed::High, .. }))));
        h.host().ports[0] = (POWER_2, CONNECTION);
        assert_eq!(h.poll_events(), Ok(Some(PortEvent::Disconnected { port: 1, device: Some(DeviceId(11)) })));
        assert_eq!(h.child(1), None);
        assert_eq!(fake.detached, [DeviceId(11)]);
    }

    #[test]
    fn replugging_between_polls_detaches_then_attaches() {
        let mut fake = FakeHub::default();
        let mut h = hub(&mut fake);
        h.host().plug(3, 0);
        assert!(matches!(h.poll_events(), Ok(Some(PortEvent::Connected { port: 3, .. }))));
        h.host().plug(3, HIGH_SPEED);
        assert!(matches!(h.poll_events(), Ok(Some(PortEvent::Disconnected { port: 3, .. }))));
        assert!(matches!(h.poll_events(), Ok(Some(PortEvent::Connected { port: 3, speed: Speed::High, .. }))));
        assert_eq!(fake.detached.len(), 1);
    }

    #[test]
    fn scan_finds_devices_already_present() {
        let mut fake = FakeHub::default();
        fake.ports[1] = (CONNECTION | POWER_2, 0); // no change bit
        let mut h = hub(&mut fake);
        assert_eq!(h.poll_events(), Ok(None));
        h.scan();
        assert!(matches!(h.poll_events(), Ok(Some(PortEvent::Connected { port: 2, speed: Speed::Full, .. }))));
        assert_eq!(h.poll_events(), Ok(None));
    }

    #[test]
    fn reset_that_never_completes_times_out() {
        let mut fake = FakeHub { reset_delay: u32::MAX, ..Default::default() };
        let mut h = hub(&mut fake);
        h.host().plug(1, 0);
        assert_eq!(h.reset_port(1), Err(UsbError::Timeout));
        assert_eq!(h.reset_port(0), Err(UsbError::NoDevice));
        assert_eq!(h.reset_port(4), Err(UsbError::NoDevice));
    }

    #[test]
    fn port_state_decodes_speed_and_power() {
        let s = |status, super_speed| PortState { status, change: 0, super_speed };
        assert_eq!(s(CONNECTION | HIGH_SPEED, false).speed(), Some(Speed::High));
        assert_eq!(s(CONNECTION | LOW_SPEED, false).speed(), Some(Speed::Low));
        assert_eq!(s(CONNECTION, true).speed(), Some(Speed::Super));
        assert_eq!(s(HIGH_SPEED, false).speed(), None);
        assert!(s(POWER_2, false).powered() && !s(POWER_2, true).powered() && s(POWER_3, true).powered());
    }
}
