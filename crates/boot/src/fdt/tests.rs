use super::*;
use alloc::vec::Vec;

/// A tree shaped like QEMU's RISC-V `virt` machine.
fn qemu_like() -> Vec<u8> {
    let mut w = FdtWriter::new();
    w.reserve_memory(0x8000_0000, 0x8_0000);
    w.begin_node("");
    w.property_u32("#address-cells", 2);
    w.property_u32("#size-cells", 2);
    w.property_string("compatible", "riscv-virtio");
    w.begin_node("chosen");
    w.property_string("bootargs", "console=ttyS0 quiet");
    w.property_u64("linux,initrd-start", 0x8400_0000);
    w.property_u32("linux,initrd-end", 0x8410_0000);
    w.end_node();
    w.begin_node("memory@80000000");
    w.property_string("device_type", "memory");
    w.property_cells("reg", &[0, 0x8000_0000, 0, 0x800_0000]);
    w.end_node();
    w.begin_node("reserved-memory");
    w.property_u32("#address-cells", 2);
    w.property_u32("#size-cells", 2);
    w.begin_node("mmode_resv0@80000000");
    w.property_cells("reg", &[0, 0x8000_0000, 0, 0x4_0000]);
    w.end_node();
    w.end_node();
    w.begin_node("soc");
    w.property_u32("#address-cells", 2);
    w.property_u32("#size-cells", 2);
    w.begin_node("serial@10000000");
    w.property_cells("interrupts", &[10]);
    w.property_cells("reg", &[0, 0x1000_0000, 0, 0x100]);
    w.property_string_list("compatible", &["ns16550a", "ns16550"]);
    w.end_node();
    w.begin_node("bus@20000000");
    w.property_u32("#address-cells", 1);
    w.property_u32("#size-cells", 0);
    w.begin_node("dev@3");
    w.property_cells("reg", &[3]);
    w.end_node();
    w.end_node();
    w.end_node();
    w.end_node();
    w.finish(0)
}

#[test]
fn header_errors() {
    assert_eq!(Fdt::new(&[0; 8]).err(), Some(FdtError::BadMagic));
    let blob = qemu_like();
    assert_eq!(Fdt::new(&blob[..blob.len() - 1]).err(), Some(FdtError::Truncated));
}

#[test]
fn navigation_and_properties() {
    let blob = qemu_like();
    let fdt = Fdt::new(&blob).unwrap();
    assert_eq!(fdt.bootargs(), Some("console=ttyS0 quiet"));
    assert_eq!(
        fdt.root().children().map(|n| n.name()).collect::<Vec<_>>(),
        ["chosen", "memory@80000000", "reserved-memory", "soc"]
    );

    let uart = fdt.find_compatible(&["ns16550a"]).unwrap();
    assert_eq!(uart.name(), "serial@10000000");
    assert!(uart.is_compatible("ns16550"));
    assert_eq!(uart.reg().collect::<Vec<_>>(), [(0x1000_0000, Some(0x100))]);
    assert_eq!(uart.interrupts().collect::<Vec<_>>(), [10]);
    assert_eq!(fdt.find_node("/soc/serial").unwrap().name(), "serial@10000000");

    let dev = fdt.find_node("/soc/bus@20000000/dev@3").unwrap();
    assert_eq!(dev.reg().collect::<Vec<_>>(), [(3, None)], "1 address cell, 0 size cells");
    assert_eq!(fdt.all_nodes().count(), 9);
    assert_eq!(fdt.all_nodes().find(|n| n.name() == "dev@3").unwrap().reg().next(), Some((3, None)));
    assert!(fdt.find_node("/soc/nothing").is_none());
}

#[test]
fn memory_map() {
    let blob = qemu_like();
    let fdt = Fdt::new(&blob).unwrap();
    assert_eq!(fdt.memory().collect::<Vec<_>>(), [(0x8000_0000, 0x800_0000)]);
    assert_eq!(fdt.reservations().collect::<Vec<_>>(), [(0x8000_0000, 0x8_0000)]);
    assert_eq!(fdt.initrd(), Some((0x8400_0000, 0x8410_0000)));
    let mut map = MemoryMap::<16>::new();
    assert_eq!(fdt.fill_memory_map(&mut map, Some(PhysAddr::new(0x8700_0000))), Ok(0));
    assert_eq!(map.total(RegionKind::Reserved), 0x8_0000);
    assert_eq!(map.total(RegionKind::Bootloader), 0x10_0000 + blob.len() as u64, "initrd and blob");
    assert_eq!(map.total(RegionKind::Usable), 0x800_0000 - 0x8_0000 - 0x10_0000 - blob.len() as u64);

    // Too many regions for the map: RAM is given up, never a reservation.
    let mut map = MemoryMap::<3>::new();
    let lost = fdt.fill_memory_map(&mut map, Some(PhysAddr::new(0x8700_0000))).unwrap();
    assert!(lost > 0);
    assert_eq!(map.total(RegionKind::Bootloader), 0x10_0000 + blob.len() as u64);
    assert!(map.usable().all(|r| r.start >= PhysAddr::new(0x8008_0000)));
}

#[test]
fn version_16_has_no_struct_size() {
    let mut blob = qemu_like();
    let nodes = Fdt::new(&blob).unwrap().all_nodes().count();
    // Version 16, last compatible 16; the word that would be
    // `size_dt_struct` is garbage.
    blob[20..24].copy_from_slice(&16u32.to_be_bytes());
    blob[24..28].copy_from_slice(&16u32.to_be_bytes());
    blob[36..40].copy_from_slice(&8u32.to_be_bytes());
    let fdt = Fdt::new(&blob).unwrap();
    assert_eq!(fdt.all_nodes().count(), nodes);
    assert_eq!(fdt.bootargs(), Some("console=ttyS0 quiet"));
    blob[20..24].copy_from_slice(&15u32.to_be_bytes());
    assert_eq!(Fdt::new(&blob).err(), Some(FdtError::BadVersion));
}

#[test]
fn string_table_dedup() {
    let mut w = FdtWriter::new();
    w.begin_node("");
    w.property_u32("reg", 1);
    w.begin_node("a");
    w.property_u32("reg", 2);
    w.end_node();
    w.end_node();
    let blob = w.finish(0);
    let fdt = Fdt::new(&blob).unwrap();
    assert_eq!(fdt.strings.len(), 4, "\"reg\\0\" stored once");
}

#[test]
fn hostile_cell_counts_yield_no_regs() {
    let mut w = FdtWriter::new();
    w.begin_node("");
    w.property_u32("#address-cells", 0xffff_ffff);
    w.property_u32("#size-cells", 3);
    w.begin_node("dev@0");
    w.property_cells("reg", &[1, 2, 3, 4]);
    w.end_node();
    w.end_node();
    let blob = w.finish(0);
    let fdt = Fdt::new(&blob).unwrap();
    assert_eq!(fdt.find_node("/dev").unwrap().reg().count(), 0);
}
