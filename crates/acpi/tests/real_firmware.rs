//! Real firmware: loads a machine's own tables and runs everything in them.
//!
//! Skipped unless `ACPI_TABLES_DIR` names a directory holding a `DSDT` and any number of `SSDT*` files, as
//! Linux exposes them (root only), for example:
//!
//! ```sh
//! mkdir /tmp/tables && sudo cp /sys/firmware/acpi/tables/{DSDT,SSDT*} /tmp/tables && sudo chmod a+r /tmp/tables/*
//! ACPI_TABLES_DIR=/tmp/tables cargo test --release -p osmium-acpi --test real_firmware -- --nocapture
//! ```
//!
//! Every table must load and every method that takes no arguments is run. Methods are expected to fail
//! here when they need hardware that is not there (an embedded controller that never answers makes a
//! busy-wait loop time out), so failures are reported, not asserted; what is asserted is that nothing
//! panics, hangs or fails to load.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use common::*;
use osmium_acpi::aml::{Config, Interpreter, ObjectKind, ROOT};

#[test]
fn load_and_run_a_real_machines_tables() {
    let Ok(dir) = std::env::var("ACPI_TABLES_DIR") else {
        println!("ACPI_TABLES_DIR not set: skipping");
        return;
    };
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n == "DSDT" || n.starts_with("SSDT")))
        .collect();
    // The DSDT first, then the SSDTs in name order (SSDT2 before SSDT10 is not guaranteed; real firmware
    // lists them in the RSDT, which Linux numbers in order).
    files.sort_by_key(|p| {
        let n = p.file_name().unwrap().to_string_lossy().into_owned();
        (n != "DSDT", n.trim_start_matches("SSDT").parse::<u32>().unwrap_or(0), n)
    });
    assert!(files.first().is_some_and(|p| p.ends_with("DSDT")), "no DSDT in {dir}");

    let config = Config { max_steps: 300_000, ..Config::default() };
    let mut aml = Interpreter::new(TestHost::default(), config);
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        let info = aml.load_table(&bytes).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        println!("loaded {} ({} bytes, revision {})", f.display(), info.length, info.revision);
    }
    let objects = aml.namespace().descendants(ROOT).len();
    println!(
        "{objects} objects; {} warnings: {:?}",
        aml.warnings().len(),
        aml.warnings().iter().take(10).collect::<Vec<_>>()
    );

    let init = aml.initialize();
    println!(
        "initialize: _REG {}, _INI {}, {} devices, {} errors",
        init.reg_run,
        init.ini_run,
        init.devices,
        init.errors.len()
    );
    for (p, e) in init.errors.iter().take(20) {
        println!("  {p}: {e}");
    }

    let (mut ran, mut failed) = (0, 0);
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for id in aml.namespace().descendants(ROOT) {
        if !matches!(aml.namespace().kind(id), Some(ObjectKind::Method | ObjectKind::Data)) {
            continue;
        }
        match aml.evaluate_node(id, &[]) {
            Ok(_) => ran += 1,
            Err(osmium_acpi::aml::AmlError::WrongArgCount) => {}
            Err(e) => {
                failed += 1;
                *kinds.entry(e.to_string()).or_default() += 1;
            }
        }
    }
    println!("evaluated {ran} objects, {failed} failed: {kinds:#?}");
    println!("deepest nesting {}", aml.peak_depth());

    let devices = aml.devices();
    println!("{} devices", devices.len());
    for d in devices.iter().filter(|d| d.hid.as_deref().is_some_and(|h| h == "PNP0A08" || h == "PNP0A03")) {
        let res = aml.current_resources(d.node).map(|r| r.len());
        let prt = aml.pci_routing_table(d.node).map(|r| r.len());
        println!(
            "host bridge {}: {} resources, _PRT rows {:?}",
            d.path,
            res.map_or_else(|e| e.to_string(), |n| n.to_string()),
            prt
        );
    }
}
