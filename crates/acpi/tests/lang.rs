//! The AML language: arithmetic, strings, buffers, packages, references, methods, control flow.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use osmium_acpi::aml::Value;

#[test]
fn language_tests() {
    let mut aml = load(include_bytes!("asl/lang.aml"));
    assert!(run_numbered_tests(&mut aml) >= 15);
}

#[test]
fn concatenated_resource_templates_drop_the_first_end_tag() {
    let mut aml = load(include_bytes!("asl/lang.aml"));
    let want = [0x47, 1, 0x60, 0, 0x60, 0, 1, 1, 0x23, 0x10, 0, 1, 0x79, 0];
    assert_eq!(aml.evaluate("\\RES1", &[]), Ok(Value::Buffer(want.to_vec())));
}

#[test]
fn evaluate_reads_names_and_runs_methods() {
    let mut aml = load(include_bytes!("asl/lang.aml"));
    assert_eq!(aml.evaluate("\\N001", &[]), Ok(Value::Integer(0x1234)));
    assert_eq!(aml.evaluate("N001", &[]), Ok(Value::Integer(0x1234)));
    assert_eq!(aml.evaluate("\\S001", &[]), Ok(Value::from("hello")));
    assert_eq!(aml.evaluate("\\B001", &[]), Ok(Value::Buffer(vec![1, 2, 3, 4])));
    assert_eq!(aml.evaluate("\\ADD3", &[1u64.into(), 2u64.into(), 3u64.into()]), Ok(Value::Integer(6)));
    assert_eq!(aml.evaluate("\\FIB", &[10u64.into()]), Ok(Value::Integer(55)));
    assert_eq!(aml.evaluate("\\NOPE", &[]), Err(osmium_acpi::aml::AmlError::NotFound));
    assert_eq!(aml.evaluate("\\FIB", &[]), Err(osmium_acpi::aml::AmlError::WrongArgCount));
}
