//! USB HID keyboards, through the boot protocol (class 03/01/01).
//!
//! The boot protocol fixes the report format, so no report descriptor
//! parsing is needed: 8 bytes of modifier bits, a reserved byte and up to six
//! pressed keys' usage IDs (HID 1.11 appendix B.1). [`BootKeyboard::poll`]
//! keeps one interrupt IN transfer outstanding and turns each new report
//! into key press and release events by comparing it with the last.

use osmium_hal::usb::find_interface;
use osmium_hal::usb::{DeviceId, Direction, Recipient, RequestKind, SetupPacket, TransferType, UsbError, UsbHost};

const SET_IDLE: u8 = 0x0a;
const SET_PROTOCOL: u8 = 0x0b;
const BOOT_PROTOCOL: u16 = 0;

/// A boot-protocol keyboard report.
pub type Report = [u8; 8];

/// Modifier bits (byte 0 of a report).
pub mod modifier {
    #![allow(missing_docs)]
    pub const LEFT_CTRL: u8 = 1 << 0;
    pub const LEFT_SHIFT: u8 = 1 << 1;
    pub const LEFT_ALT: u8 = 1 << 2;
    pub const LEFT_GUI: u8 = 1 << 3;
    pub const RIGHT_CTRL: u8 = 1 << 4;
    pub const RIGHT_SHIFT: u8 = 1 << 5;
    pub const RIGHT_ALT: u8 = 1 << 6;
    pub const RIGHT_GUI: u8 = 1 << 7;
    pub const SHIFT: u8 = LEFT_SHIFT | RIGHT_SHIFT;
    pub const CTRL: u8 = LEFT_CTRL | RIGHT_CTRL;
}

/// A key going down or up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    /// HID usage ID (page 7): 0x04 is A, 0x28 Enter, 0x29 Escape.
    pub usage: u8,
    /// True for a press, false for a release.
    pub pressed: bool,
    /// Modifier bits in effect.
    pub modifiers: u8,
}

impl KeyEvent {
    /// The character a press produces on a US layout, if any.
    pub fn to_ascii(&self) -> Option<char> {
        if !self.pressed {
            return None;
        }
        usage_to_ascii(self.usage, self.modifiers & modifier::SHIFT != 0, self.modifiers & modifier::CTRL != 0)
    }
}

/// Translates a usage ID on a US layout. Ctrl with a letter gives the
/// control character (Ctrl-C is 0x03).
pub fn usage_to_ascii(usage: u8, shift: bool, ctrl: bool) -> Option<char> {
    const PLAIN: &[u8; 0x39 - 0x1e] = b"1234567890\n\x1b\x08\t -=[]\\#;'`,./";
    const SHIFTED: &[u8; 0x39 - 0x1e] = b"!@#$%^&*()\n\x1b\x08\t _+{}|~:\"~<>?";
    let c = match usage {
        0x04..=0x1d => {
            let letter = b'a' + (usage - 0x04);
            if ctrl {
                letter - b'a' + 1
            } else if shift {
                letter.to_ascii_uppercase()
            } else {
                letter
            }
        }
        0x1e..=0x38 => {
            let i = (usage - 0x1e) as usize;
            if shift { SHIFTED[i] } else { PLAIN[i] }
        }
        _ => return None,
    };
    Some(c as char)
}

/// Appends to `out` the events that turn report `prev` into `cur`:
/// releases first, then presses. Returns how many were written (at most 12;
/// `out` should hold that many). Reports signalling rollover (every key
/// slot 0x01) produce nothing.
pub fn diff(prev: &Report, cur: &Report, out: &mut [KeyEvent]) -> usize {
    if cur[2..].iter().all(|&k| k == 1) {
        return 0;
    }
    let mut n = 0;
    let mut push = |usage, pressed, modifiers| {
        if n < out.len() {
            out[n] = KeyEvent { usage, pressed, modifiers };
            n += 1;
        }
    };
    for &k in &prev[2..] {
        if k > 1 && !cur[2..].contains(&k) {
            push(k, false, cur[0]);
        }
    }
    for &k in &cur[2..] {
        if k > 1 && !prev[2..].contains(&k) {
            push(k, true, cur[0]);
        }
    }
    n
}

/// A keyboard driven through the boot protocol.
pub struct BootKeyboard<H: UsbHost> {
    host: H,
    dev: DeviceId,
    endpoint: u8,
    max_packet: usize,
    last: Report,
    submitted: bool,
    queue: [KeyEvent; 12],
    queued: usize,
    head: usize,
}

impl<H: UsbHost> BootKeyboard<H> {
    /// Drives the boot keyboard interface of the enumerated device `dev`,
    /// whose configuration descriptor set is `config`, switching it to the
    /// boot protocol and to reporting only on change.
    pub fn new(mut host: H, dev: DeviceId, config: &[u8]) -> Result<Self, UsbError> {
        let iface = find_interface(config, |i| i.class == 3 && i.subclass == 1 && i.protocol == 1)
            .ok_or(UsbError::BadDescriptor)?;
        let ep = iface.endpoint(TransferType::Interrupt, Direction::In).ok_or(UsbError::BadDescriptor)?;
        let number = iface.descriptor.number as u16;
        let class = |request, value| {
            SetupPacket::new(Direction::Out, RequestKind::Class, Recipient::Interface, request, value, number, 0)
        };
        host.control_out(dev, class(SET_PROTOCOL, BOOT_PROTOCOL), &[])?;
        // Optional: report only on change. Some keyboards stall it.
        let _ = host.control_out(dev, class(SET_IDLE, 0), &[]);
        let empty = KeyEvent { usage: 0, pressed: false, modifiers: 0 };
        Ok(Self {
            host,
            dev,
            endpoint: ep.address,
            max_packet: (ep.max_packet_size() as usize).clamp(8, 64),
            last: [0; 8],
            submitted: false,
            queue: [empty; 12],
            queued: 0,
            head: 0,
        })
    }

    /// The device handle.
    pub fn device(&self) -> DeviceId {
        self.dev
    }

    /// Checks for a new report without waiting; returns it if one arrived.
    pub fn poll_report(&mut self) -> Result<Option<Report>, UsbError> {
        if !self.submitted {
            self.host.submit_in(self.dev, self.endpoint, self.max_packet)?;
            self.submitted = true;
        }
        let mut buf = [0u8; 64];
        let got = match self.host.poll_in(self.dev, self.endpoint, &mut buf) {
            None => return Ok(None),
            Some(r) => r,
        };
        self.submitted = false;
        // A boot report is 8 bytes; anything shorter is ignored, not padded.
        if got? < 8 {
            return Ok(None);
        }
        Ok(Some(buf[..8].try_into().expect("fixed-width slice")))
    }

    /// The next key event, if any, without waiting.
    pub fn poll(&mut self) -> Result<Option<KeyEvent>, UsbError> {
        if self.queued == 0
            && let Some(report) = self.poll_report()?
        {
            self.queued = diff(&self.last, &report, &mut self.queue);
            self.head = 0;
            if !report[2..].iter().all(|&k| k == 1) {
                self.last = report;
            }
        }
        if self.queued == 0 {
            return Ok(None);
        }
        self.queued -= 1;
        self.head += 1;
        Ok(Some(self.queue[self.head - 1]))
    }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their borrow of the fake device.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use osmium_hal::usb::{EndpointDescriptor, PortStatus};
    use std::collections::VecDeque;
    use std::vec::Vec;

    #[test]
    fn ascii() {
        assert_eq!(usage_to_ascii(0x04, false, false), Some('a'));
        assert_eq!(usage_to_ascii(0x1d, true, false), Some('Z'));
        assert_eq!(usage_to_ascii(0x06, false, true), Some('\x03'), "Ctrl-C");
        assert_eq!(usage_to_ascii(0x1e, false, false), Some('1'));
        assert_eq!(usage_to_ascii(0x1f, true, false), Some('@'));
        assert_eq!(usage_to_ascii(0x28, false, false), Some('\n'));
        assert_eq!(usage_to_ascii(0x2c, true, false), Some(' '));
        assert_eq!(usage_to_ascii(0x38, true, false), Some('?'));
        assert_eq!(usage_to_ascii(0x3a, false, false), None, "F1");
    }

    #[test]
    fn report_diffs() {
        let mut out = [KeyEvent { usage: 0, pressed: false, modifiers: 0 }; 12];
        let a = [0, 0, 0x04, 0, 0, 0, 0, 0];
        let ab = [modifier::LEFT_SHIFT, 0, 0x04, 0x05, 0, 0, 0, 0];
        let b = [0, 0, 0x05, 0, 0, 0, 0, 0];
        assert_eq!(diff(&[0; 8], &a, &mut out), 1);
        assert_eq!(out[0], KeyEvent { usage: 0x04, pressed: true, modifiers: 0 });
        assert_eq!(diff(&a, &ab, &mut out), 1);
        assert_eq!(out[0].to_ascii(), Some('B'));
        assert_eq!(diff(&ab, &b, &mut out), 1);
        assert_eq!((out[0].usage, out[0].pressed), (0x04, false));
        assert_eq!(diff(&b, &[0, 0, 1, 1, 1, 1, 1, 1], &mut out), 0, "rollover");
    }

    /// A keyboard whose reports arrive one per completed submission.
    #[derive(Default)]
    struct FakeKeyboard {
        /// Reports, or shorter transfers.
        reports: VecDeque<Vec<u8>>,
        outstanding: bool,
        requests: Vec<(u8, u16)>,
    }

    impl UsbHost for FakeKeyboard {
        fn num_ports(&self) -> u8 {
            1
        }
        fn port_status(&self, _: u8) -> PortStatus {
            unimplemented!()
        }
        fn attach(&mut self, _: u8) -> Result<DeviceId, UsbError> {
            unimplemented!()
        }
        fn detach(&mut self, _: DeviceId) {}
        fn configure_endpoints(&mut self, _: DeviceId, _: &[EndpointDescriptor]) -> Result<(), UsbError> {
            Ok(())
        }
        fn control_in(&mut self, _: DeviceId, _: SetupPacket, _: &mut [u8]) -> Result<usize, UsbError> {
            unimplemented!()
        }
        fn control_out(&mut self, _: DeviceId, s: SetupPacket, _: &[u8]) -> Result<(), UsbError> {
            self.requests.push((s.request, s.value));
            Ok(())
        }
        fn transfer_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Result<usize, UsbError> {
            unimplemented!()
        }
        fn transfer_out(&mut self, _: DeviceId, _: u8, _: &[u8]) -> Result<(), UsbError> {
            unimplemented!()
        }
        fn submit_in(&mut self, _: DeviceId, ep: u8, len: usize) -> Result<(), UsbError> {
            assert_eq!((ep, len), (0x81, 8));
            assert!(!self.outstanding, "one transfer at a time");
            self.outstanding = true;
            Ok(())
        }
        fn poll_in(&mut self, _: DeviceId, _: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
            assert!(self.outstanding);
            let r = self.reports.pop_front()?;
            self.outstanding = false;
            buf[..r.len()].copy_from_slice(&r);
            Some(Ok(r.len()))
        }
    }

    const CONFIG: [u8; 34] = [
        9, 2, 34, 0, 1, 1, 0, 0xa0, 50, //
        9, 4, 0, 0, 1, 3, 1, 1, 0, //
        9, 0x21, 0x11, 1, 0, 1, 0x22, 63, 0, // HID descriptor
        7, 5, 0x81, 3, 8, 0, 10,
    ];

    #[test]
    fn typing() {
        let mut fake = FakeKeyboard::default();
        let mut kb = BootKeyboard::new(&mut fake, DeviceId(2), &CONFIG).unwrap();
        assert_eq!(kb.poll(), Ok(None));
        // "Hi" then everything released.
        for r in [[0x02, 0, 0x0b, 0, 0, 0, 0, 0], [0; 8], [0, 0, 0x0c, 0, 0, 0, 0, 0], [0; 8]] {
            kb.host.reports.push_back(r.to_vec());
        }
        let mut typed = std::string::String::new();
        while let Some(ev) = kb.poll().unwrap() {
            typed.extend(ev.to_ascii());
        }
        assert_eq!(typed, "Hi");
        assert!(kb.host.outstanding, "a new transfer is always waiting");
        drop(kb);
        assert_eq!(fake.requests, [(SET_PROTOCOL, 0), (SET_IDLE, 0)]);
    }

    #[test]
    fn short_reports_are_ignored() {
        let mut fake = FakeKeyboard::default();
        let mut kb = BootKeyboard::new(&mut fake, DeviceId(2), &CONFIG).unwrap();
        // Read as a full report, this would release nothing and press 'a'.
        kb.host.reports.push_back(std::vec![0, 0, 0x04]);
        assert_eq!(kb.poll(), Ok(None));
        assert_eq!(kb.last, [0; 8]);
        kb.host.reports.push_back(std::vec![0, 0, 0x05, 0, 0, 0, 0, 0]);
        assert_eq!(kb.poll().unwrap().map(|e| (e.usage, e.pressed)), Some((0x05, true)));
        assert_eq!(kb.poll(), Ok(None));
    }
}
