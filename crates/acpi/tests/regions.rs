//! Operation regions and fields: layout, access widths, update rules, index and bank fields, PCI
//! addressing, and `_REG`.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::Access::*;
use common::*;
use osmium_acpi::aml::{AmlError, Interpreter, PciAddress, Value};

const TABLE: &[u8] = include_bytes!("asl/regions.aml");

fn setup() -> Interpreter<TestHost> {
    load(TABLE)
}

/// Runs `path` and returns what the host saw while it ran.
fn run(aml: &mut Interpreter<TestHost>, path: &str) -> (Result<Value, AmlError>, Vec<common::Access>) {
    aml.host_mut().clear_log();
    let r = aml.evaluate(path, &[]);
    (r, aml.host().log.clone())
}

#[test]
fn byte_fields_across_units() {
    let mut aml = setup();
    let (r, log) = run(&mut aml, "\\W001");
    assert!(r.is_ok(), "{r:?}");
    // Every unit is wholly covered, so nothing is read first.
    assert_eq!(
        log,
        [
            MemW(0x1000, 8, 0xAB),
            MemW(0x1001, 8, 0x34),
            MemW(0x1002, 8, 0x12),
            MemW(0x1004, 8, 0xEF),
            MemW(0x1005, 8, 0xBE),
            MemW(0x1006, 8, 0xAD),
            MemW(0x1007, 8, 0xDE),
        ]
    );
    assert_eq!(aml.host().peek(0x1000, 8), [0xAB, 0x34, 0x12, 0, 0xEF, 0xBE, 0xAD, 0xDE]);
    aml.host_mut().poke(0x1004, &[0x78, 0x56, 0x34, 0x12]);
    assert_eq!(run(&mut aml, "\\G001").0, Ok(Value::Integer(0x1234_5678)));
    assert_eq!(run(&mut aml, "\\G002").0, Ok(Value::Integer(0x1234)));
}

#[test]
fn write_as_zeros_and_ones_fill_the_rest_of_the_unit() {
    let mut aml = setup();
    aml.host_mut().poke(0x1010, &[0xFF; 4]);
    let (r, log) = run(&mut aml, "\\W002");
    assert!(r.is_ok());
    assert_eq!(log, [MemW(0x1010, 32, 0x50)]);
    let (_, log) = run(&mut aml, "\\W003");
    assert_eq!(log, [MemW(0x1010, 32, 0x03)]);
    assert_eq!(aml.host().peek(0x1010, 4), [3, 0, 0, 0]);
    let (_, log) = run(&mut aml, "\\W004");
    assert_eq!(log, [MemW(0x1018, 32, 0xFFFF_FFF0)]);
}

#[test]
fn preserve_reads_modifies_and_writes() {
    let mut aml = setup();
    aml.host_mut().poke(0x101C, &[0xA5]);
    let (_, log) = run(&mut aml, "\\W005");
    assert_eq!(log, [MemR(0x101C, 32), MemW(0x101C, 32, 0xF5)]);
    aml.host_mut().poke(0x1030, &[0xF8]);
    let (_, log) = run(&mut aml, "\\W007");
    assert_eq!(log, [MemR(0x1030, 8), MemW(0x1030, 8, 0xF9)]);
}

#[test]
fn qword_and_any_access() {
    let mut aml = setup();
    let (_, log) = run(&mut aml, "\\W006");
    assert_eq!(log, [MemW(0x1020, 64, 0x1122_3344_5566_7788)]);
    assert_eq!(run(&mut aml, "\\G006").0, Ok(Value::Integer(0x1122_3344_5566_7788)));
    // AnyAcc: the narrowest aligned unit that holds the whole field.
    aml.host_mut().poke(0x1030, &[0xFF, 0x78, 0x56, 0x34, 0x12]);
    let (r, log) = run(&mut aml, "\\G007");
    assert_eq!((r, log), (Ok(Value::Integer(7)), vec![MemR(0x1030, 8)]));
    let (r, log) = run(&mut aml, "\\G008");
    assert_eq!((r, log), (Ok(Value::Integer(0x1234_5678)), vec![MemR(0x1030, 64)]));
}

#[test]
fn wide_fields_are_buffers() {
    let mut aml = setup();
    let data: Vec<u8> = (1..=16).collect();
    aml.host_mut().poke(0x1040, &data);
    assert_eq!(run(&mut aml, "\\G009").0, Ok(Value::Buffer(data.clone())));
    aml.host_mut().poke(0x1040, &[0; 16]);
    assert!(run(&mut aml, "\\W008").0.is_ok());
    assert_eq!(aml.host().peek(0x1040, 16), data);
}

#[test]
fn fields_that_do_not_fit_whole_units() {
    let mut aml = setup();
    aml.host_mut().poke(0x1051, &[0xF0]);
    assert!(run(&mut aml, "\\W009").0.is_ok());
    assert_eq!(aml.host().peek(0x1050, 2), [0xBC, 0xFA]);
    assert_eq!(run(&mut aml, "\\G010").0, Ok(Value::Integer(0xABC)));
    aml.host_mut().poke(0x1062, &[0x00, 0xA0]);
    assert!(run(&mut aml, "\\W010").0.is_ok());
    assert_eq!(aml.host().peek(0x1060, 4), [0xFF, 0xFF, 0x0F, 0xA0]);
}

#[test]
fn accesses_stay_inside_the_region() {
    let mut aml = setup();
    aml.host_mut().poke(0x10FE, &[0x34, 0x12]);
    assert_eq!(run(&mut aml, "\\G011").0, Ok(Value::Integer(0x1234)));
    // The region is 4 bytes long (a runtime value, so the compiler cannot check it); the field is not.
    assert_eq!(run(&mut aml, "\\G012").0, Err(AmlError::OutOfBounds));
}

#[test]
fn port_io() {
    let mut aml = setup();
    assert_eq!(run(&mut aml, "\\W011").1, [IoW(0x60, 8, 0x5A)]);
    aml.host_mut().io.insert(0x61, 0x42);
    let (r, log) = run(&mut aml, "\\G013");
    assert_eq!((r, log), (Ok(Value::Integer(0x42)), vec![IoR(0x61, 8)]));
    assert_eq!(run(&mut aml, "\\W012").1, [IoW(0x64, 32, 0x1122_3344)]);
    // There are no 64-bit port accesses: they become two 32-bit ones.
    assert_eq!(run(&mut aml, "\\W013").1, [IoW(0x100, 32, 0x5566_7788), IoW(0x104, 32, 0x1122_3344)]);
    let (r, log) = run(&mut aml, "\\G014");
    assert_eq!(r, Ok(Value::Integer(0x1122_3344_5566_7788)));
    assert_eq!(log, [IoR(0x104, 32), IoR(0x100, 32)]);
}

#[test]
fn index_fields_go_through_the_index_and_data_registers() {
    let mut aml = setup();
    assert_eq!(run(&mut aml, "\\W014").1, [IoW(0x70, 8, 1), IoW(0x71, 8, 0x99)]);
    assert_eq!(aml.host().indexed.get(&1), Some(&0x99));
    let (r, log) = run(&mut aml, "\\G015");
    assert_eq!((r, log), (Ok(Value::Integer(0x99)), vec![IoW(0x70, 8, 1), IoR(0x71, 8)]));
    aml.host_mut().indexed.insert(2, 0xA5);
    let (_, log) = run(&mut aml, "\\W015");
    assert_eq!(log, [IoW(0x70, 8, 2), IoR(0x71, 8), IoW(0x70, 8, 2), IoW(0x71, 8, 0xA6)]);
}

#[test]
fn bank_fields_select_the_bank_first() {
    let mut aml = setup();
    assert_eq!(run(&mut aml, "\\W016").1, [MemW(0x2000, 8, 2), MemW(0x2011, 8, 7)]);
    aml.host_mut().poke(0x2010, &[0x5E]);
    let (r, log) = run(&mut aml, "\\G016");
    assert_eq!((r, log), (Ok(Value::Integer(0x5E)), vec![MemW(0x2000, 8, 1), MemR(0x2010, 8)]));
}

#[test]
fn pci_config_regions_find_their_device_through_bridges() {
    let mut aml = setup();
    let root = PciAddress { segment: 1, bus: 3, device: 0, function: 0 };
    let dev1 = PciAddress { segment: 1, bus: 3, device: 1, function: 2 };
    let child = PciAddress { segment: 1, bus: 9, device: 3, function: 1 };
    for (i, b) in [0x86, 0x80, 0x34, 0x12].into_iter().enumerate() {
        aml.host_mut().pci.insert((root, i as u16), b);
    }
    // The device is on the root bridge's bus (_BBN) in its segment (_SEG).
    let (r, log) = run(&mut aml, "\\PCI0.G017");
    assert_eq!((r, log), (Ok(Value::Integer(0x8086)), vec![PciR(root, 0, 32)]));
    aml.host_mut().pci.insert((dev1, 0x41), 0x66);
    let (r, log) = run(&mut aml, "\\PCI0.DEV1.G018");
    assert_eq!((r, log), (Ok(Value::Integer(0x66)), vec![PciR(dev1, 0x41, 8)]));
    // Behind the bridge DEV1: its secondary bus number, register 0x19, says which bus CHLD is on.
    aml.host_mut().pci.insert((dev1, 0x19), 9);
    aml.host_mut().pci.insert((child, 0), 0x78);
    let (r, log) = run(&mut aml, "\\PCI0.DEV1.CHLD.G019");
    assert_eq!(r, Ok(Value::Integer(0x78)));
    assert_eq!(log, [PciR(dev1, 0x19, 8), PciR(child, 0, 32)]);
    // The address is remembered.
    let (_, log) = run(&mut aml, "\\PCI0.DEV1.CHLD.G019");
    assert_eq!(log, [PciR(child, 0, 32)]);
}

#[test]
fn other_address_spaces_go_to_the_host() {
    let mut aml = setup();
    assert_eq!(run(&mut aml, "\\W017").1, [RegionW(3, 0x11, 8, 0x77)]);
    let (_, log) = run(&mut aml, "\\G020");
    assert_eq!(log, [RegionR(3, 0x10, 8)]);
}

#[test]
fn reg_runs_for_each_space_the_host_serves() {
    let mut aml = setup();
    let report = aml.initialize();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    // The root scope has memory and I/O regions (and an embedded controller one, which the host does not serve).
    assert_eq!(aml.evaluate("\\RGM_", &[]), Ok(Value::Integer(0b011)));
    assert_eq!(aml.evaluate("\\PCI0.RGP_", &[]), Ok(Value::Integer(0b100)));
    assert_eq!(report.reg_run, 3);

    let host = TestHost { extra_spaces: vec![3], ..TestHost::default() };
    let mut aml = load_with(host, TABLE);
    aml.initialize();
    assert_eq!(aml.evaluate("\\RGM_", &[]), Ok(Value::Integer(0b1011)));
}
