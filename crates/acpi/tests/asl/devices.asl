/*
 * A small machine: a host bridge with resources and an interrupt routing table, interrupt links,
 * devices that are absent or only functioning, sleep states and general-purpose events.
 * tests/devices.rs and tests/pm.rs use it. Compile with tests/asl/build.sh.
 */
DefinitionBlock ("", "DSDT", 2, "OSMIUM", "DEVS", 1)
{
    // _INI methods append their digit here, so the log is the order they ran in.
    Name (LOG_, 0)
    Method (LGW, 1) { Store (Or (ShiftLeft (LOG_, 4), Arg0), LOG_) }

    Name (_S0_, Package () { 0, 0, 0, 0 })
    Name (_S1_, Package () { 1, 1, 0, 0 })
    Name (_S3_, Package () { 5, 5, 0, 0 })
    Name (_S5_, Package () { 7, 7, 0, 0 })
    Name (PTSL, 0xFF)
    Name (WAKL, 0xFF)
    Method (_PTS, 1) { Store (Arg0, PTSL) }
    Method (_WAK, 1)
    {
        Store (Arg0, WAKL)
        Return (Package () { 0, 0 })
    }

    Method (OSIT, 1) { Return (_OSI (Arg0)) }
    Method (OSNM) { Return (_OS_) }
    Method (REVN) { Return (_REV) }

    Scope (_SB)
    {
        Method (_INI) { LGW (1) }

        Device (PCI0)
        {
            Name (_HID, EisaId ("PNP0A08"))
            Name (_CID, EisaId ("PNP0A03"))
            Name (_UID, 0)
            Name (_ADR, 0)
            Method (_INI) { LGW (2) }
            Name (_CRS, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode, 0x0000, 0x0000, 0x00FF, 0x0000, 0x0100)
                IO (Decode16, 0x0CF8, 0x0CF8, 0x01, 0x08)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                    0x00000000, 0xE0000000, 0xFEBFFFFF, 0x00000000, 0x1EC00000)
                QWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
                    0x0000000000000000, 0x0000000800000000, 0x0000000FFFFFFFFF, 0x0000000000000000, 0x0000000800000000)
                Memory32Fixed (ReadOnly, 0xFED00000, 0x00001000)
            })
            // The links are declared further down: the table must resolve the names when it is read.
            Name (_PRT, Package ()
            {
                Package () { 0x0001FFFF, 0, \_SB.LNKA, 0 },
                Package () { 0x0001FFFF, 1, \_SB.LNKB, 0 },
                Package () { 0x0002FFFF, 0, 0, 16 },
                Package () { 0x0003FFFF, 3, 0, 19 },
                Package () { 0x0004FFFF, 0, \_SB.LNKA, 0 },
                Package () { 0x00040002, 1, \_SB.LNKB, 0 },
            })
        }

        // An interrupt link with a legacy IRQ descriptor, configured through _SRS.
        Device (LNKA)
        {
            Name (_HID, EisaId ("PNP0C0F"))
            Name (_UID, 1)
            Name (_PRS, ResourceTemplate () { IRQ (Level, ActiveLow, Shared) {5, 10, 11} })
            Name (BUFA, ResourceTemplate () { IRQ (Level, ActiveLow, Shared) {10} })
            Method (_CRS) { Return (BUFA) }
            Method (_SRS, 1)
            {
                CreateWordField (Arg0, 1, IRQS)
                CreateWordField (BUFA, 1, IRQM)
                Store (IRQS, IRQM)
            }
        }

        // An interrupt link with an extended interrupt descriptor.
        Device (LNKB)
        {
            Name (_HID, EisaId ("PNP0C0F"))
            Name (_UID, 2)
            Name (_CRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveLow, Shared, , , ) { 11 }
            })
        }

        // Neither present nor functioning: it and everything below are skipped.
        Device (GONE)
        {
            Name (_HID, "OSM0001")
            Method (_STA) { Return (0) }
            Method (_INI) { LGW (9) }
            Device (KID0) { Name (_ADR, 1) Method (_INI) { LGW (8) } }
        }

        // Functioning but not present: not initialized itself, but its children are.
        Device (FUNC)
        {
            Name (_HID, "OSM0002")
            Method (_STA) { Return (0x08) }
            Method (_INI) { LGW (7) }
            Device (KID1) { Name (_ADR, 1) Method (_INI) { LGW (3) } }
        }

        Device (PWRB) { Name (_HID, EisaId ("PNP0C0C")) }
        Device (LID0)
        {
            Name (_HID, EisaId ("PNP0C0D"))
            Method (_STA) { Return (0x0F) }
        }
    }

    Scope (_GPE)
    {
        Name (E05C, 0)
        Name (L0AC, 0)
        Method (_E05) { Add (E05C, 1, E05C) Notify (\_SB.PWRB, 0x80) }
        Method (_L0A) { Add (L0AC, 1, L0AC) Notify (\_SB.LID0, 0x80) }
        // Fails at run time: a division by a value the compiler cannot see is zero.
        Method (_E07)
        {
            Store (0, Local0)
            Divide (1, Local0, Local1, Local2)
        }
    }

    Method (ILOG) { Return (LOG_) }
}
