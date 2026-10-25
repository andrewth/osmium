//! Devices, initialization order, resources, PCI interrupt routing and loading from a table chain.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use osmium_acpi::aml::{AmlError, Config, Interpreter, Value};
use osmium_acpi::pci::{IrqRoute, PrtEntry, PrtSource};
use osmium_acpi::resource::{AddressKind, Resource};
use osmium_boot::acpi::Acpi;

const DEVICES: &[u8] = include_bytes!("asl/devices.aml");
const SSDT: &[u8] = include_bytes!("asl/ssdt.aml");

fn machine() -> Interpreter<TestHost> {
    load(DEVICES)
}

#[test]
fn initialization_runs_ini_in_declaration_order_and_skips_absent_devices() {
    let mut aml = machine();
    let report = aml.initialize();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    // \_SB._INI, then PCI0, then (GONE and its child are skipped; FUNC is only functioning, so its own
    // _INI does not run but its child's does).
    assert_eq!(aml.evaluate("\\ILOG", &[]), Ok(Value::Integer(0x123)));
    assert_eq!(report.ini_run, 3);
    // PCI0, LNKA, LNKB, FUNC, KID1, PWRB, LID0.
    assert_eq!(report.devices, 7);
}

#[test]
fn devices_are_listed_with_their_identity() {
    let mut aml = machine();
    let devs = aml.devices();
    let find = |path: &str| devs.iter().find(|d| d.path == path).unwrap_or_else(|| panic!("no {path}"));
    let pci0 = find("\\_SB_.PCI0");
    assert_eq!(
        (pci0.hid.as_deref(), pci0.uid.as_deref(), pci0.adr, pci0.status),
        (Some("PNP0A08"), Some("0"), Some(0), 0xf)
    );
    assert_eq!(find("\\_SB_.LNKA").hid.as_deref(), Some("PNP0C0F"));
    assert_eq!(find("\\_SB_.GONE").status, 0);
    assert_eq!(find("\\_SB_.GONE").hid.as_deref(), Some("OSM0001"));
    // A compatible id counts as a match too.
    let by_cid = aml.find_devices("PNP0A03");
    assert_eq!(by_cid.len(), 1);
    assert_eq!(aml.namespace().path(by_cid[0]), "\\_SB_.PCI0");
    assert_eq!(aml.find_devices("PNP0C0F").len(), 2);
    assert!(aml.find_devices("NOPE0000").is_empty());
}

#[test]
fn host_bridge_resources() {
    let mut aml = machine();
    let pci0 = aml.namespace().find("\\_SB.PCI0").unwrap();
    let res = aml.current_resources(pci0).unwrap();
    assert_eq!(res.len(), 5, "{res:#?}");
    let Resource::Address(bus) = &res[0] else { panic!("{:?}", res[0]) };
    assert_eq!(
        (bus.kind, bus.width, bus.producer, bus.min, bus.max, bus.length),
        (AddressKind::BusNumber, 16, true, 0, 0xFF, 0x100)
    );
    assert!(bus.min_fixed && bus.max_fixed);
    assert_eq!(res[1], Resource::Io { decode16: true, min: 0xCF8, max: 0xCF8, align: 1, length: 8 });
    let Resource::Address(low) = &res[2] else { panic!("{:?}", res[2]) };
    assert_eq!(
        (low.kind, low.width, low.min, low.max, low.length),
        (AddressKind::Memory, 32, 0xE000_0000, 0xFEBF_FFFF, 0x1EC0_0000)
    );
    let Resource::Address(high) = &res[3] else { panic!("{:?}", res[3]) };
    assert_eq!((high.kind, high.width, high.min, high.length), (AddressKind::Memory, 64, 0x8_0000_0000, 0x8_0000_0000));
    assert_eq!(res[4], Resource::FixedMemory32 { writable: false, base: 0xFED0_0000, length: 0x1000 });
}

#[test]
fn routing_table_resolves_names_declared_later() {
    let mut aml = machine();
    let pci0 = aml.namespace().find("\\_SB.PCI0").unwrap();
    let lnka = aml.namespace().find("\\_SB.LNKA").unwrap();
    let lnkb = aml.namespace().find("\\_SB.LNKB").unwrap();
    let prt = aml.pci_routing_table(pci0).unwrap();
    let link = |node, index| PrtSource::Link { node, index };
    assert_eq!(
        prt,
        [
            PrtEntry { device: 1, function: None, pin: 0, source: link(lnka, 0) },
            PrtEntry { device: 1, function: None, pin: 1, source: link(lnkb, 0) },
            PrtEntry { device: 2, function: None, pin: 0, source: PrtSource::Gsi(16) },
            PrtEntry { device: 3, function: None, pin: 3, source: PrtSource::Gsi(19) },
            PrtEntry { device: 4, function: None, pin: 0, source: link(lnka, 0) },
            PrtEntry { device: 4, function: Some(2), pin: 1, source: link(lnkb, 0) },
        ]
    );
}

#[test]
fn interrupts_route_through_links_and_directly() {
    let mut aml = machine();
    let pci0 = aml.namespace().find("\\_SB.PCI0").unwrap();
    let r = |aml: &mut Interpreter<TestHost>, d, f, p| aml.route_pci_irq(pci0, d, f, p).unwrap();
    // Through LNKA, whose _CRS says IRQ 10 (level, active low, shared).
    assert_eq!(r(&mut aml, 1, 0, 0), Some(IrqRoute { gsi: 10, level_triggered: true, active_low: true, shared: true }));
    // Through LNKB, whose _CRS is an extended interrupt.
    assert_eq!(r(&mut aml, 1, 0, 1), Some(IrqRoute { gsi: 11, level_triggered: true, active_low: true, shared: true }));
    // Wired straight to a GSI.
    assert_eq!(r(&mut aml, 2, 0, 0), Some(IrqRoute { gsi: 16, level_triggered: true, active_low: true, shared: true }));
    // A row for function 2 only.
    assert_eq!(r(&mut aml, 4, 2, 1).map(|x| x.gsi), Some(11));
    assert_eq!(r(&mut aml, 4, 0, 1), None);
    // No row at all.
    assert_eq!(r(&mut aml, 9, 0, 0), None);
}

#[test]
fn links_are_configured_with_srs() {
    let mut aml = machine();
    let lnka = aml.namespace().find("\\_SB.LNKA").unwrap();
    let possible = aml.possible_resources(lnka).unwrap();
    assert_eq!(
        possible,
        [Resource::Irq { mask: 1 << 5 | 1 << 10 | 1 << 11, edge: false, active_low: true, shared: true, wake: false }]
    );
    let mut chosen = possible;
    if let Some(Resource::Irq { mask, .. }) = chosen.first_mut() {
        *mask = 1 << 5;
    }
    aml.set_resources(lnka, &chosen).unwrap();
    let pci0 = aml.namespace().find("\\_SB.PCI0").unwrap();
    assert_eq!(aml.route_pci_irq(pci0, 1, 0, 0).unwrap().map(|x| x.gsi), Some(5));
}

#[test]
fn osi_asks_the_host() {
    let mut aml = machine();
    let osi = |aml: &mut Interpreter<TestHost>, s: &str| aml.evaluate("\\OSIT", &[Value::from(s)]);
    assert_eq!(osi(&mut aml, "Module Device"), Ok(Value::Integer(u64::MAX)));
    assert_eq!(osi(&mut aml, "Windows 2015"), Ok(Value::Integer(0)));
    aml.host_mut().interfaces.push("Windows 2015".into());
    assert_eq!(osi(&mut aml, "Windows 2015"), Ok(Value::Integer(u64::MAX)));
    assert_eq!(aml.evaluate("\\OSNM", &[]), Ok(Value::from("Microsoft Windows NT")));
    assert_eq!(aml.evaluate("\\REVN", &[]), Ok(Value::Integer(2)));
    let config = Config { os_name: "Osmium".into(), revision: 5, ..Config::default() };
    let mut custom = Interpreter::new(TestHost::default(), config);
    custom.load_table(DEVICES).unwrap();
    assert_eq!(custom.evaluate("\\OSNM", &[]), Ok(Value::from("Osmium")));
    assert_eq!(custom.evaluate("\\REVN", &[]), Ok(Value::Integer(5)));
}

#[test]
fn tables_load_through_the_fadt_and_root_table() {
    let mem = machine_memory(DEVICES, &[SSDT]);
    let acpi = Acpi::new(0, reader(&mem)).unwrap();
    let mut aml = Interpreter::new(TestHost::default(), Config::default());
    let report = aml.load_tables(&acpi).unwrap();
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    let sigs: Vec<_> = report.loaded.iter().map(|t| t.signature).collect();
    assert_eq!(sigs, [*b"DSDT", *b"SSDT"]);
    assert_eq!(aml.evaluate("\\SSDV", &[]), Ok(Value::Integer(0x55)));
    // The SSDT's device sits under the DSDT's bridge.
    let ext = aml.namespace().find("\\_SB.PCI0.EXT0").unwrap();
    assert_eq!(
        aml.evaluate_node(aml.namespace().child(ext, osmium_acpi::aml::NameSeg(*b"_UID")).unwrap(), &[]),
        Ok(Value::Integer(7))
    );
    // Its second LOG_ is skipped: the first declaration stands, and the repeat is noted.
    assert_eq!(aml.evaluate("\\LOG_", &[]), Ok(Value::Integer(0)));
    assert!(aml.warnings().iter().any(|w| w.contains("LOG_")), "{:?}", aml.warnings());
}

#[test]
fn a_missing_dsdt_is_an_error() {
    let mut mem = machine_memory(DEVICES, &[]);
    mem[0x1000..0x1004].copy_from_slice(b"XXXX");
    let acpi = Acpi::new(0, reader(&mem)).unwrap();
    let mut aml = Interpreter::new(TestHost::default(), Config::default());
    assert_eq!(aml.load_tables(&acpi).err(), Some(AmlError::InvalidTable));
}

#[test]
fn bad_tables_are_rejected_before_they_run() {
    let mut aml = Interpreter::new(TestHost::default(), Config::default());
    assert_eq!(aml.load_table(&[]).err(), Some(AmlError::InvalidTable));
    let mut bad = DEVICES.to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(aml.load_table(&bad).err(), Some(AmlError::InvalidTable));
    let mut wrong_sig = DEVICES.to_vec();
    wrong_sig[..4].copy_from_slice(b"FACP");
    assert_eq!(aml.load_table(&seal(wrong_sig)).err(), Some(AmlError::InvalidTable));
    // Nothing was declared.
    assert!(aml.namespace().find("\\_SB.PCI0").is_none());
}
