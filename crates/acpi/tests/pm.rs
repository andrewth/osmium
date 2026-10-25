//! The FADT, ACPI mode, sleep states, reset, and the SCI with fixed events and GPEs.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::Access::*;
use common::*;
use osmium_acpi::aml::{Interpreter, Value};
use osmium_acpi::fadt::{Fadt, Gas};
use osmium_acpi::pm::{Pm, PmError, fixed};
use osmium_boot::acpi::Table;

const DEVICES: &[u8] = include_bytes!("asl/devices.aml");

fn pm() -> Pm {
    let f = fadt(0x1000);
    Pm::new(Fadt::parse(Table { data: &f }).unwrap())
}

fn host() -> TestHost {
    TestHost {
        // PM1a status and GPE status registers clear by writing ones.
        w1c: vec![0x600, 0x601, 0x680, 0x681, 0x682, 0x683],
        smi: Some((0xB2, 0xF1, 0x604)),
        wake_on_sleep: Some((0x604, 0x600)),
        ..TestHost::default()
    }
}

fn machine() -> Interpreter<TestHost> {
    load_with(host(), DEVICES)
}

#[test]
fn fadt_fields() {
    let f = fadt(0x1000);
    let fadt = Fadt::parse(Table { data: &f }).unwrap();
    assert_eq!(fadt.revision, 6);
    assert_eq!(fadt.dsdt_address(), 0x1000);
    assert_eq!(fadt.sci_int, 9);
    assert_eq!((fadt.smi_cmd, fadt.acpi_enable, fadt.acpi_disable), (0xB2, 0xF1, 0xF0));
    assert_eq!(fadt.pm1a_evt, Gas::io(0x600, 4).unwrap());
    assert_eq!(fadt.pm1a_cnt.address, 0x604);
    assert!(fadt.pm1b_cnt.is_empty());
    assert_eq!(fadt.pm_tmr.address, 0x608);
    assert_eq!((fadt.gpe0.address, fadt.gpe0_len), (0x680, 8));
    assert_eq!((fadt.reset_reg.address, fadt.reset_value), (0xCF9, 6));
    assert!(!fadt.hw_reduced());
    // Not a FADT, or too short to be one.
    assert!(Fadt::parse(Table { data: &table(b"APIC", 1, &[0; 8]) }).is_none());
    assert!(Fadt::parse(Table { data: &table(b"FACP", 1, &[0; 8]) }).is_none());
}

#[test]
fn the_extended_dsdt_address_wins() {
    let mut f = fadt(0x1000);
    f[140..148].copy_from_slice(&0x1_2345_6000u64.to_le_bytes());
    let fadt = Fadt::parse(Table { data: &seal(f) }).unwrap();
    assert_eq!(fadt.dsdt_address(), 0x1_2345_6000);
}

#[test]
fn enabling_acpi_mode() {
    let pm = pm();
    let mut h = host();
    assert_eq!(pm.acpi_enabled(&mut h), Ok(false));
    pm.enable(&mut h).unwrap();
    assert_eq!(h.log, [IoR(0x604, 16), IoR(0x604, 16), IoW(0xB2, 8, 0xF1), IoR(0x604, 16)]);
    assert_eq!(pm.acpi_enabled(&mut h), Ok(true));
    // Already enabled: no second SMI.
    h.clear_log();
    pm.enable(&mut h).unwrap();
    assert!(!h.log.iter().any(|a| matches!(a, IoW(0xB2, ..))));
    // Firmware that never sets SCI_EN is reported, not waited for forever.
    let mut dead = TestHost::default();
    assert_eq!(pm.enable(&mut dead), Err(PmError::Timeout));
}

#[test]
fn power_off_writes_the_sleep_type_then_enable() {
    let pm = pm();
    let mut aml = machine();
    aml.host_mut().clear_log();
    pm.power_off(&mut aml).unwrap();
    // _PTS(5) ran first.
    assert_eq!(aml.evaluate("\\PTSL", &[]), Ok(Value::Integer(5)));
    let writes: Vec<_> =
        aml.host().log.iter().filter(|a| matches!(a, IoW(0x604, ..) | IoW(0x600, ..))).cloned().collect();
    // WAK_STS is cleared, then S5's SLP_TYP (7) is set, then SLP_EN.
    assert_eq!(writes, [IoW(0x600, 16, 0x8000), IoW(0x604, 16, 7 << 10), IoW(0x604, 16, 7 << 10 | 1 << 13)]);
}

#[test]
fn a_sleep_state_the_firmware_lacks() {
    let pm = pm();
    let mut aml = machine();
    assert_eq!(pm.enter_sleep_state(&mut aml, 4), Err(PmError::NoSuchState(4)));
    assert_eq!(pm.enter_sleep_state(&mut aml, 0), Err(PmError::NoSuchState(0)));
    assert_eq!(pm.enter_sleep_state(&mut aml, 6), Err(PmError::NoSuchState(6)));
    assert_eq!(pm.sleep_types(&mut aml, 3), Ok((5, 5)));
    assert_eq!(pm.sleep_types(&mut aml, 5), Ok((7, 7)));
    assert!(!aml.host().log.iter().any(|a| matches!(a, IoW(0x604, ..))));
}

#[test]
fn suspend_waits_for_the_wake_and_runs_wak() {
    let pm = pm();
    let mut aml = machine();
    pm.enter_sleep_state(&mut aml, 3).unwrap();
    assert_eq!(aml.evaluate("\\PTSL", &[]), Ok(Value::Integer(3)));
    assert_eq!(aml.evaluate("\\WAKL", &[]), Ok(Value::Integer(3)));
    // WAK_STS was cleared after the wake.
    assert_eq!(aml.host().io.get(&0x601).copied().unwrap_or(0) & 0x80, 0);
    // A machine that never wakes times out instead of hanging.
    let mut stuck = load_with(TestHost { w1c: vec![0x600, 0x601], ..TestHost::default() }, DEVICES);
    assert_eq!(pm.enter_sleep_state(&mut stuck, 3), Err(PmError::Timeout));
}

#[test]
fn reset_writes_the_reset_register() {
    let pm = pm();
    let mut h = host();
    pm.reset(&mut h).unwrap();
    assert_eq!(h.log, [IoW(0xCF9, 8, 6)]);
    let mut f = fadt(0x1000);
    f[112..116].copy_from_slice(&0u32.to_le_bytes());
    let no_reset = Pm::new(Fadt::parse(Table { data: &seal(f) }).unwrap());
    assert_eq!(no_reset.reset(&mut h), Err(PmError::Unsupported("reset register")));
}

#[test]
fn the_pm_timer_is_24_bits_unless_the_fadt_says_32() {
    let pm = pm();
    let mut h = host();
    h.io.extend([(0x608, 0x78), (0x609, 0x56), (0x60A, 0x34), (0x60B, 0x12)]);
    assert_eq!(pm.timer(&mut h), Ok(0x0034_5678));
    let mut f = fadt(0x1000);
    f[112..116].copy_from_slice(&(1u32 << 10 | 1 << 8).to_le_bytes());
    let wide = Pm::new(Fadt::parse(Table { data: &seal(f) }).unwrap());
    assert_eq!(wide.timer(&mut h), Ok(0x1234_5678));
}

#[test]
fn fixed_events_need_to_be_pending_and_enabled() {
    let pm = pm();
    let mut aml = machine();
    // Power button pending, but not enabled: nothing to report.
    aml.host_mut().io.insert(0x601, 0x01);
    assert_eq!(pm.handle_sci(&mut aml).unwrap().fixed, 0);
    pm.enable_fixed_events(aml.host_mut(), fixed::POWER_BUTTON | fixed::RTC_ALARM).unwrap();
    assert_eq!(aml.host().io.get(&0x602), Some(&0));
    assert_eq!(aml.host().io.get(&0x603), Some(&0x05));
    let ev = pm.handle_sci(&mut aml).unwrap();
    assert_eq!(ev.fixed, fixed::POWER_BUTTON);
    // The event was cleared.
    assert_eq!(aml.host().io.get(&0x601).copied().unwrap_or(0) & 0x01, 0);
    assert_eq!(pm.handle_sci(&mut aml).unwrap().fixed, 0);
    pm.disable_fixed_events(aml.host_mut(), fixed::POWER_BUTTON).unwrap();
    assert_eq!(aml.host().io.get(&0x603), Some(&0x04));
}

#[test]
fn gpes_run_their_methods() {
    let pm = pm();
    let mut aml = machine();
    // Enable what the firmware has handlers for: _E05, _E07 and _L0A.
    assert_eq!(pm.enable_gpes(&mut aml).unwrap(), [5, 7, 10]);
    assert_eq!(aml.host().io.get(&0x684), Some(&0xA0));
    assert_eq!(aml.host().io.get(&0x685), Some(&0x04));
    // Nothing pending.
    assert!(pm.handle_sci(&mut aml).unwrap().gpes.is_empty());
    // GPE 5 (edge) and 10 (level) fire, and so does 3, which has no handler.
    aml.host_mut().io.insert(0x680, 0x20 | 0x08);
    aml.host_mut().io.insert(0x681, 0x04);
    pm.enable_gpe(aml.host_mut(), 3).unwrap();
    aml.host_mut().io.insert(0x680, 0x20 | 0x08);
    aml.host_mut().notifications.clear();
    let ev = pm.handle_sci(&mut aml).unwrap();
    assert_eq!(ev.gpes, [5, 10]);
    assert_eq!(ev.unhandled, [3]);
    assert!(ev.errors.is_empty(), "{:?}", ev.errors);
    assert_eq!(aml.evaluate("\\_GPE.E05C", &[]), Ok(Value::Integer(1)));
    assert_eq!(aml.evaluate("\\_GPE.L0AC", &[]), Ok(Value::Integer(1)));
    assert_eq!(aml.host().notifications, [("\\_SB_.PWRB".to_string(), 0x80), ("\\_SB_.LID0".to_string(), 0x80)]);
    // All three are cleared. The level GPE is enabled again; the one without a handler is not.
    assert_eq!(aml.host().io.get(&0x680).copied().unwrap_or(0), 0);
    assert_eq!(aml.host().io.get(&0x681).copied().unwrap_or(0), 0);
    assert_eq!(aml.host().io.get(&0x684), Some(&0xA0));
    assert_eq!(aml.host().io.get(&0x685), Some(&0x04));
    assert!(pm.enable_gpe(aml.host_mut(), 200).is_err());
}

#[test]
fn a_failing_gpe_method_is_reported_not_fatal() {
    let pm = pm();
    let mut aml = machine();
    // _E07 divides by zero. It is reported, and the GPE that follows it still runs.
    pm.enable_gpe(aml.host_mut(), 7).unwrap();
    pm.enable_gpe(aml.host_mut(), 10).unwrap();
    aml.host_mut().io.insert(0x680, 0x80);
    aml.host_mut().io.insert(0x681, 0x04);
    let ev = pm.handle_sci(&mut aml).unwrap();
    assert_eq!(ev.gpes, [7, 10]);
    assert_eq!(ev.errors, [("\\_GPE._E07".to_string(), osmium_acpi::aml::AmlError::DivideByZero)]);
    assert_eq!(aml.evaluate("\\_GPE.L0AC", &[]), Ok(Value::Integer(1)));
}
