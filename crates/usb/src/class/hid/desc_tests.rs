//! Tests of report descriptor parsing, report decoding and the descriptor-driven devices.

// Tests drop drivers explicitly to end their borrow of the fake device.
#![allow(clippy::drop_non_drop)]

use super::descriptor::*;
use super::device::*;
use super::report::Item;
use super::*;
use osmium_hal::usb::{EndpointDescriptor, PortStatus};
use std::collections::VecDeque;
use std::vec::Vec;

/// HID 1.11 appendix E.6: the boot keyboard.
const KEYBOARD: &[u8] = &[
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95,
    0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05,
    0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19,
    0x00, 0x29, 0x65, 0x81, 0x00, 0xc0,
];

/// A three-button wheel mouse (relative X, Y and wheel).
const MOUSE: &[u8] = &[
    0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25,
    0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x03, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31,
    0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, 0xc0, 0xc0,
];

/// A gamepad: four 8-bit axes, a hat switch with a null state, twelve buttons.
const GAMEPAD: &[u8] = &[
    0x05, 0x01, 0x09, 0x05, 0xa1, 0x01, 0xa1, 0x00, 0x09, 0x30, 0x09, 0x31, 0x09, 0x32, 0x09, 0x35, 0x15, 0x81, 0x25,
    0x7f, 0x75, 0x08, 0x95, 0x04, 0x81, 0x02, 0xc0, 0x09, 0x39, 0x15, 0x01, 0x25, 0x08, 0x35, 0x00, 0x46, 0x3b, 0x01,
    0x65, 0x14, 0x75, 0x04, 0x95, 0x01, 0x81, 0x42, 0x75, 0x04, 0x95, 0x01, 0x81, 0x03, 0x05, 0x09, 0x19, 0x01, 0x29,
    0x0c, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x0c, 0x81, 0x02, 0x75, 0x04, 0x95, 0x01, 0x81, 0x03, 0xc0,
];

/// An NKRO keyboard with report IDs: report 1 has modifiers and a 128-bit key bitmap, report 2 consumer keys.
const NKRO: &[u8] = &[
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75,
    0x01, 0x95, 0x08, 0x81, 0x02, 0x19, 0x00, 0x29, 0x7f, 0x95, 0x80, 0x81, 0x02, 0xc0, 0x05, 0x0c, 0x09, 0x01, 0xa1,
    0x01, 0x85, 0x02, 0x09, 0xe9, 0x09, 0xea, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x02, 0x81, 0x02, 0x75, 0x06,
    0x95, 0x01, 0x81, 0x03, 0xc0,
];

#[test]
fn boot_keyboard() {
    let d = ReportDescriptor::parse(KEYBOARD).unwrap();
    assert_eq!(d.applications(), [usages::KEYBOARD]);
    assert!(!d.uses_report_ids());
    // Modifiers, five LEDs and the key array (the padding is not kept).
    assert_eq!(d.fields().len(), 3);
    let mods = d.fields()[0];
    assert_eq!((mods.kind, mods.bit_offset, mods.report_size, mods.report_count), (ReportKind::Input, 0, 1, 8));
    assert!(mods.flags.is_variable() && !mods.flags.is_array());
    assert_eq!(mods.usages, Usages::Range { min: usages::key(0xe0), max: usages::key(0xe7) });
    assert_eq!(mods.application, usages::KEYBOARD);
    let keys = d.fields()[2];
    assert_eq!((keys.bit_offset, keys.report_size, keys.report_count), (16, 8, 6));
    assert!(keys.flags.is_array());
    assert_eq!((keys.logical_min, keys.logical_max), (0, 0x65));
    assert_eq!(d.array_usage(&keys, 4), Some(usages::key(4)));
    assert_eq!(d.array_usage(&keys, 0x66), None);
    assert_eq!(d.array_value_for(&keys, usages::key(5)), Some(5));
    assert_eq!(d.report_len(ReportKind::Input, 0), Some(8));
    assert_eq!(d.report_len(ReportKind::Output, 0), Some(1));
    assert_eq!(d.report_len(ReportKind::Feature, 0), None);
    assert_eq!(d.max_input_len(), 8);
    let leds = d.fields()[1];
    assert_eq!((leds.kind, leds.report_count), (ReportKind::Output, 5));
    assert_eq!(d.fields()[2].report_id, 0);
}

#[test]
fn keyboard_decoding_matches_the_boot_diff() {
    let d = ReportDescriptor::parse(KEYBOARD).unwrap();
    let mut dec = KeyboardDecoder::new();
    let mut out = [KeyEvent { usage: 0, pressed: false, modifiers: 0 }; 64];
    let mut typed = std::string::String::new();
    for r in [[0x02, 0, 0x0b, 0, 0, 0, 0, 0], [0; 8], [0, 0, 0x0c, 0, 0, 0, 0, 0], [0; 8]] {
        let n = dec.update(&d, &r, &mut out);
        typed.extend(out[..n].iter().flat_map(|e| e.to_ascii()));
    }
    assert_eq!(typed, "Hi");
    // Two keys, then one released and one pressed in the same report.
    assert_eq!(dec.update(&d, &[0, 0, 4, 5, 0, 0, 0, 0], &mut out), 2);
    let n = dec.update(&d, &[0, 0, 5, 6, 0, 0, 0, 0], &mut out);
    let got: Vec<_> = out[..n].iter().map(|e| (e.usage, e.pressed)).collect();
    assert_eq!(got, [(4, false), (6, true)]);
    // Rollover error: nothing, and the state is kept.
    assert_eq!(dec.update(&d, &[0, 0, 1, 1, 1, 1, 1, 1], &mut out), 0);
    assert_eq!(dec.update(&d, &[0, 0, 5, 6, 0, 0, 0, 0], &mut out), 0);
    // A report shorter than the descriptor says is not a report: no keys released.
    assert_eq!(dec.update(&d, &[0, 0, 5], &mut out), 0);
    assert_eq!(dec.update(&d, &[0, 0, 5, 6, 0, 0, 0, 0], &mut out), 0);
    assert_eq!(dec.update(&d, &[], &mut out), 0);
}

#[test]
fn mouse() {
    let d = ReportDescriptor::parse(MOUSE).unwrap();
    assert_eq!(d.applications(), [usages::MOUSE]);
    assert_eq!(d.fields().len(), 2);
    let axes = d.fields()[1];
    assert_eq!((axes.logical_min, axes.logical_max, axes.report_count), (-127, 127, 3));
    assert!(axes.flags.is_relative());
    assert_eq!(axes.collection, usages::POINTER);
    assert_eq!(axes.application, usages::MOUSE);
    assert_eq!(d.logical_range(usages::Y), Some((-127, 127)));
    let ev = decode_pointer(&d, &[0b101, 0x10, 0xf0, 0x01]).unwrap();
    assert_eq!(ev, PointerEvent { dx: 16, dy: -16, wheel: 1, buttons: 0b101, ..Default::default() });
    // A truncated report is not a report.
    assert_eq!(decode_pointer(&d, &[0b001, 0x05]), None);
}

#[test]
fn gamepad() {
    let d = ReportDescriptor::parse(GAMEPAD).unwrap();
    assert_eq!(d.applications(), [usages::GAMEPAD]);
    let report = [0x80, 0x7f, 0x00, 0x81, 0x35, 0x0a, 0x00];
    let r = d.input_report(&report).unwrap();
    let mut items = Vec::new();
    r.for_each(|i| items.push(i));
    let axis = |u| items.iter().find(|i| i.usage == u).map(|i| i.value);
    assert_eq!(axis(usages::X), Some(-128));
    assert_eq!(axis(usages::Y), Some(127));
    assert_eq!(axis(usages::Z), Some(0));
    assert_eq!(axis(usages::RZ), Some(-127));
    // Hat value 5 with the low nibble: 0x35 is hat 5 and padding 3.
    assert_eq!(axis(usages::HAT_SWITCH), Some(5));
    assert_eq!(r.value(usages::button(2)), Some(1));
    assert_eq!(r.value(usages::button(4)), Some(1));
    assert_eq!(r.value(usages::button(1)), Some(0));
    assert_eq!(r.value(usages::button(13)), None);
    let hat = d.fields().iter().find(|f| f.usages == Usages::List { start: 4, len: 1 }).unwrap();
    assert!(hat.flags.has_null_state());
    assert_eq!(hat.physical(1), Some(0));
    assert_eq!(hat.physical(5), Some(180));
    assert_eq!(hat.unit, 0x14);
    // Hat released: the null state value 0 is out of range and skipped.
    let mut seen = false;
    d.input_report(&[0, 0, 0, 0, 0, 0, 0]).unwrap().for_each(|i| seen |= i.usage == usages::HAT_SWITCH);
    assert!(!seen);
}

#[test]
fn nkro_keyboard_with_report_ids() {
    let d = ReportDescriptor::parse(NKRO).unwrap();
    assert!(d.uses_report_ids());
    assert_eq!(d.applications(), [usages::KEYBOARD, usage(0x0c, 1)]);
    assert_eq!(d.report_len(ReportKind::Input, 1), Some(1 + 1 + 16));
    assert_eq!(d.report_len(ReportKind::Input, 2), Some(2));
    let mut dec = KeyboardDecoder::new();
    let mut out = [KeyEvent { usage: 0, pressed: false, modifiers: 0 }; 64];
    let mut r = [0u8; 18];
    r[0] = 1;
    r[1] = 0x20; // right shift
    r[2 + 1] = 0x01 << 4; // usage 0x0c ('i')
    r[2 + 16 - 1] = 0x80; // usage 0x7f
    let n = dec.update(&d, &r, &mut out);
    let got: Vec<_> = out[..n].iter().map(|e| (e.usage, e.pressed, e.modifiers)).collect();
    assert_eq!(got, [(0x0c, true, 0x20), (0x7f, true, 0x20)]);
    // A consumer report neither presses nor releases keys.
    assert_eq!(dec.update(&d, &[2, 3], &mut out), 0);
    assert_eq!(dec.modifiers(), 0x20);
    assert_eq!(d.input_report(&[2, 3]).unwrap().value(usage(0x0c, 0xea)), Some(1));
    // An unknown report ID is not a report.
    assert!(d.input_report(&[9, 0]).is_none());
    r[0] = 1;
    r[2 + 1] = 0;
    r[2 + 15] = 0;
    r[1] = 0;
    assert_eq!(dec.update(&d, &r, &mut out), 2);
}

#[test]
fn field_read_write() {
    let f = Field {
        kind: ReportKind::Output,
        report_id: 0,
        flags: FieldFlags(2),
        bit_offset: 3,
        report_size: 10,
        report_count: 2,
        logical_min: -512,
        logical_max: 511,
        physical_min: -512,
        physical_max: 511,
        unit: 0,
        unit_exponent: 0,
        usages: Usages::None,
        application: 0,
        collection: 0,
    };
    let mut data = [0u8; 4];
    assert_eq!(f.write(&mut data, 0, -3), Some(()));
    assert_eq!(f.write(&mut data, 1, 511), Some(()));
    assert_eq!(f.read(&data, 0), Some(-3));
    assert_eq!(f.read(&data, 1), Some(511));
    assert_eq!(f.write(&mut data, 0, 512), None, "does not fit");
    assert_eq!(f.write(&mut data, 2, 0), None, "no such element");
    assert_eq!(f.read(&data[..2], 1), None, "report too short");
    assert_eq!(f.write(&mut data[..2], 1, 0), None);
    assert_eq!(f.read(&data, 0), Some(-3), "failed writes change nothing");
}

#[test]
fn global_stack_delimiters_and_long_items() {
    let d = ReportDescriptor::parse(&[
        0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, // mouse
        0xa4, // push
        0x05, 0x09, 0x19, 0x01, 0x29, 0x02, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x02, 0x81, 0x02, //
        0xb4, // pop: usage page, sizes and range go back
        0xfe, 0x02, 0x10, 0xaa, 0xbb, // a long item, skipped
        0xa9, 0x01, 0x09, 0x30, 0x09, 0x31, 0xa9, 0x00, // a delimited set: only X counts
        0x75, 0x08, 0x95, 0x01, 0x15, 0x81, 0x25, 0x7f, 0x81, 0x06, //
        0xc0,
    ])
    .unwrap();
    assert_eq!(d.fields().len(), 2);
    assert_eq!(d.fields()[1].usages, Usages::List { start: 0, len: 1 });
    assert_eq!(d.field_usage(&d.fields()[1], 0), Some(usages::X));
    assert_eq!(d.fields()[0].usage_page(&d), Some(usages::PAGE_BUTTON));
}

#[test]
fn malformed_descriptors_are_errors() {
    use ParseError::*;
    let cases: &[(&[u8], ParseError)] = &[
        (&[0x05], Truncated),
        (&[0x06, 0x01], Truncated),
        (&[0x07, 1, 2, 3], Truncated),
        (&[0xfe, 5, 0, 1], Truncated),
        (&[0xfe], Truncated),
        (&[0xc0], UnbalancedCollection),
        (&[0xa1, 0x01], UnbalancedCollection),
        (&[0xb4], BadPushPop),
        (&[0xa4, 0xa4, 0xa4, 0xa4, 0xa4], BadPushPop),
        (&[0x85, 0x00], BadReportId),
        (&[0x86, 0x00, 0x01], BadReportId),
        // Input with report size 0, then 33.
        (&[0x95, 0x01, 0x81, 0x02], BadReportSize),
        (&[0x75, 0x21, 0x95, 0x01, 0x81, 0x02], BadReportSize),
        // 32-bit size times a huge count.
        (&[0x75, 0x20, 0x97, 0xff, 0xff, 0xff, 0xff, 0x81, 0x02], ReportTooLong),
        (&[0x75, 0x08, 0x96, 0xff, 0xff, 0x81, 0x02], ReportTooLong),
        // Minimum above maximum.
        (&[0x75, 0x08, 0x95, 0x01, 0x15, 0x05, 0x25, 0x01, 0x81, 0x02], BadLogicalRange),
        // Usage minimum without maximum, and reversed.
        (&[0x75, 0x08, 0x95, 0x01, 0x25, 0x01, 0x19, 0x01, 0x81, 0x02], BadUsageRange),
        (&[0x75, 0x08, 0x95, 0x01, 0x25, 0x01, 0x19, 0x05, 0x29, 0x01, 0x81, 0x02], BadUsageRange),
    ];
    for (bytes, want) in cases {
        assert_eq!(ReportDescriptor::parse(bytes).unwrap_err(), *want, "{bytes:02x?}");
    }
    // Too deep.
    let deep = [0xa1u8, 0x01].repeat(MAX_DEPTH_FOR_TEST + 1);
    assert_eq!(ReportDescriptor::parse(&deep).unwrap_err(), TooDeep);
    // Too many usages for one item, and too many in all.
    let many = [0x09u8, 0x01].repeat(33);
    assert_eq!(ReportDescriptor::parse(&many).unwrap_err(), TooManyUsages);
    let mut pool = std::vec![0x75, 0x01, 0x95, 0x20, 0x15, 0x00, 0x25, 0x01];
    for _ in 0..9 {
        for _ in 0..32 {
            pool.extend([0x09, 0x01]);
        }
        pool.extend([0x81, 0x02]);
    }
    assert_eq!(ReportDescriptor::parse(&pool).unwrap_err(), TooManyUsages);
    // Too many fields.
    let mut fields = std::vec![0x75, 0x01, 0x95, 0x01, 0x15, 0x00, 0x25, 0x01];
    for _ in 0..=MAX_FIELDS {
        fields.extend([0x81, 0x02]);
    }
    assert_eq!(ReportDescriptor::parse(&fields).unwrap_err(), TooManyFields);
    // Too many reports.
    let mut ids = std::vec::Vec::new();
    for id in 1..=(MAX_REPORTS as u8 + 1) {
        ids.extend([0x85, id, 0x75, 0x00, 0x95, 0x01, 0x81, 0x01]);
    }
    assert_eq!(ReportDescriptor::parse(&ids).unwrap_err(), TooManyReports);
}

const MAX_DEPTH_FOR_TEST: usize = 16;

#[test]
fn trailing_padding_and_empty_descriptors_parse() {
    let mut padded = KEYBOARD.to_vec();
    padded.extend([0, 0, 0]);
    assert_eq!(ReportDescriptor::parse(&padded).unwrap().fields().len(), 3);
    let empty = ReportDescriptor::parse(&[]).unwrap();
    assert!(empty.fields().is_empty() && empty.applications().is_empty());
    assert!(empty.input_report(&[1, 2]).is_none());
}

/// A small deterministic generator (xorshift64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Parses `bytes`; if that works, decodes reports of every length from the descriptor.
fn exercise(bytes: &[u8], rng: &mut Rng) {
    let Ok(d) = ReportDescriptor::parse(bytes) else { return };
    let mut dec = KeyboardDecoder::new();
    let mut out = [KeyEvent { usage: 0, pressed: false, modifiers: 0 }; 8];
    let mut report = [0u8; 40];
    for len in [0, 1, 2, 5, 9, 17, 40] {
        for b in report.iter_mut() {
            *b = rng.next() as u8;
        }
        let r = &report[..len];
        let _ = dec.update(&d, r, &mut out);
        let _ = decode_pointer(&d, r);
        if let Some(rep) = d.input_report(r) {
            rep.for_each(|_| {});
            let _ = rep.value(usages::X);
            let _ = rep.has_page(7);
        }
    }
    for f in d.fields() {
        let _ = f.physical(rng.next() as i64);
        let _ = f.read(&report, rng.next() as u32 % 70000);
        let _ = f.write(&mut report, rng.next() as u32 % 70000, rng.next() as i64);
        let _ = d.field_usage(f, rng.next() as u32);
        let _ = d.array_usage(f, rng.next() as i64);
        let _ = d.array_value_for(f, rng.next() as u32);
    }
    let _ = d.logical_range(usages::X);
    let _ = d.max_input_len();
}

#[test]
fn fuzz_random_and_mutated_descriptors() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    // Pure noise, biased toward item prefixes.
    for _ in 0..4000 {
        let len = rng.next() as usize % 64;
        let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        exercise(&bytes, &mut rng);
    }
    // Real descriptors with bytes flipped, cut and extended.
    for base in [KEYBOARD, MOUSE, GAMEPAD, NKRO] {
        for _ in 0..3000 {
            let mut bytes = base.to_vec();
            for _ in 0..1 + rng.next() % 4 {
                let at = rng.next() as usize % bytes.len();
                match rng.next() % 4 {
                    0 => bytes[at] = rng.next() as u8,
                    1 => bytes[at] ^= 1 << (rng.next() % 8),
                    2 => bytes.truncate(at),
                    _ => bytes.insert(at, rng.next() as u8),
                }
                if bytes.is_empty() {
                    break;
                }
            }
            exercise(&bytes, &mut rng);
        }
    }
}

#[test]
fn unaligned_and_wide_fields() {
    // Two 12-bit axes and a signed 32-bit value.
    let d = ReportDescriptor::parse(&[
        0x05, 0x01, 0x09, 0x04, 0xa1, 0x01, 0x09, 0x30, 0x09, 0x31, 0x16, 0x00, 0xf8, 0x26, 0xff, 0x07, 0x75, 0x0c,
        0x95, 0x02, 0x81, 0x02, 0x09, 0x32, 0x17, 0x00, 0x00, 0x00, 0x80, 0x27, 0xff, 0xff, 0xff, 0x7f, 0x75, 0x20,
        0x95, 0x01, 0x81, 0x02, 0xc0,
    ])
    .unwrap();
    assert_eq!(d.report_len(ReportKind::Input, 0), Some(7));
    let report = [0x01, 0xf8, 0x7f, 0x00, 0x00, 0x00, 0x80];
    let mut got = Vec::new();
    d.input_report(&report).unwrap().for_each(|i: Item| got.push((i.usage, i.value)));
    assert_eq!(got, [(usages::X, -2047), (usages::Y, 2047), (usages::Z, i32::MIN as i64)]);
}

/// A HID device whose reports arrive one per completed submission.
#[derive(Default)]
struct FakeHid {
    descriptor: Vec<u8>,
    reports: VecDeque<Vec<u8>>,
    outstanding: bool,
    out: Vec<(u8, u16, Vec<u8>)>,
}

impl UsbHost for FakeHid {
    fn num_ports(&self) -> u8 {
        1
    }
    fn port_status(&self, _: u8) -> PortStatus {
        panic!("not used by this test")
    }
    fn attach(&mut self, _: u8) -> Result<DeviceId, UsbError> {
        panic!("not used by this test")
    }
    fn detach(&mut self, _: DeviceId) {}
    fn configure_endpoints(&mut self, _: DeviceId, _: &[EndpointDescriptor]) -> Result<(), UsbError> {
        Ok(())
    }
    fn control_in(&mut self, _: DeviceId, s: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
        assert_eq!((s.request, s.value), (6, 0x2200), "GET_DESCRIPTOR(report)");
        assert_eq!(s.index, 1, "the second interface");
        let n = self.descriptor.len().min(buf.len());
        buf[..n].copy_from_slice(&self.descriptor[..n]);
        Ok(n)
    }
    fn control_out(&mut self, _: DeviceId, s: SetupPacket, data: &[u8]) -> Result<(), UsbError> {
        self.out.push((s.request, s.value, data.to_vec()));
        Ok(())
    }
    fn transfer_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Result<usize, UsbError> {
        panic!("not used by this test")
    }
    fn transfer_out(&mut self, _: DeviceId, _: u8, _: &[u8]) -> Result<(), UsbError> {
        panic!("not used by this test")
    }
    fn submit_in(&mut self, _: DeviceId, ep: u8, _: usize) -> Result<(), UsbError> {
        assert_eq!(ep, 0x82);
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

/// Interface 0 is a vendor interface, interface 1 the HID one (a boot-subclass keyboard) with the report descriptor `len` bytes long.
fn config(len: usize) -> Vec<u8> {
    let mut c = std::vec![9, 2, 0, 0, 2, 1, 0, 0xa0, 50];
    c.extend([9, 4, 0, 0, 0, 0xff, 0, 0, 0]);
    c.extend([9, 4, 1, 0, 1, 3, 1, 1, 0]);
    c.extend([9, 0x21, 0x11, 1, 0, 1, 0x22, len as u8, (len >> 8) as u8]);
    c.extend([7, 5, 0x82, 3, 8, 0, 10]);
    let total = c.len();
    c[2] = total as u8;
    c
}

/// Drivers hold a descriptor and are moved by value on kernel stacks.
#[test]
fn the_descriptor_table_stays_small() {
    assert!(core::mem::size_of::<ReportDescriptor>() <= 3072);
}

#[test]
fn class_descriptor_lookup() {
    let c = config(63);
    assert_eq!(report_descriptor_len(&c, 1), Some(63));
    assert_eq!(report_descriptor_len(&c, 0), None);
    assert_eq!(report_descriptor_len(&c, 2), None);
    assert_eq!(hid_interfaces(&c).collect::<Vec<_>>(), [1]);
    // A HID descriptor that announces none, or more than it holds (only what is there counts).
    let mut short = c.clone();
    short[27 + 5] = 9;
    assert_eq!(report_descriptor_len(&short, 1), Some(63));
    short[27 + 5] = 0;
    assert_eq!(report_descriptor_len(&short, 1), None);
    // Truncated at every length: never panics.
    for n in 0..c.len() {
        let _ = report_descriptor_len(&c[..n], 1);
        let _ = hid_interfaces(&c[..n]).count();
    }
}

#[test]
fn keyboard_through_its_descriptor() {
    let mut fake = FakeHid { descriptor: KEYBOARD.to_vec(), ..Default::default() };
    let c = config(KEYBOARD.len());
    let mut kb = HidKeyboard::new(&mut fake, DeviceId(2), &c).unwrap();
    assert_eq!(kb.device().interface(), 1);
    assert_eq!(kb.poll(), Ok(None));
    kb.device.host.reports.extend([[0x02, 0, 0x0b, 0, 0, 0, 0, 0].to_vec(), [0; 8].to_vec()]);
    let mut typed = std::string::String::new();
    while let Some(ev) = kb.poll().unwrap() {
        typed.extend(ev.to_ascii());
    }
    assert_eq!(typed, "H");
    kb.set_leds(true, false, true).unwrap();
    drop(kb);
    assert_eq!(fake.out[0], (SET_PROTOCOL, 1, std::vec![]));
    assert_eq!(fake.out[1].0, SET_IDLE);
    // SET_REPORT(output): Num Lock is bit 0, Scroll Lock bit 2.
    assert_eq!(fake.out[2], (0x09, 0x0200, std::vec![0b101]));
}

#[test]
fn mouse_through_its_descriptor() {
    let mut fake = FakeHid { descriptor: MOUSE.to_vec(), ..Default::default() };
    let c = config(MOUSE.len());
    assert!(HidKeyboard::new(&mut fake, DeviceId(2), &c).is_err(), "not a keyboard");
    let mut m = HidMouse::new(&mut fake, DeviceId(2), &c).unwrap();
    assert_eq!(m.range(), Some(((-127, 127), (-127, 127))));
    m.device.host.reports.push_back(std::vec![1, 3, 0xfd, 0]);
    let ev = m.poll().unwrap().unwrap();
    assert_eq!((ev.buttons, ev.dx, ev.dy, ev.absolute), (1, 3, -3, false));
    assert_eq!(m.poll(), Ok(None));
}

#[test]
fn bad_descriptors_from_devices_are_errors() {
    let c = config(10);
    // The device returns garbage, or less than it announced.
    for desc in [std::vec![0xa1, 0x01], std::vec![], std::vec![0xff; 10]] {
        let mut fake = FakeHid { descriptor: desc, ..Default::default() };
        assert!(HidDevice::new(&mut fake, DeviceId(2), &c, 1).is_err());
    }
    // A huge announced length is refused before any transfer.
    let mut fake = FakeHid::default();
    assert!(HidDevice::new(&mut fake, DeviceId(2), &config(60000), 1).is_err());
    assert!(HidDevice::new(&mut fake, DeviceId(2), &config(0), 1).is_err());
}
