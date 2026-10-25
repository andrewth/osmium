/*
 * A secondary table loaded after devices.asl: it adds a device under the host bridge and a name, and
 * repeats a name the DSDT already declared (which the loader must skip, not fail on).
 */
DefinitionBlock ("", "SSDT", 2, "OSMIUM", "EXTRA", 1)
{
    External (_SB.PCI0, DeviceObj)

    Name (SSDV, 0x55)
    Name (LOG_, 0x77)

    Scope (\_SB.PCI0)
    {
        Device (EXT0)
        {
            Name (_HID, "OSM0003")
            Name (_UID, 7)
        }
    }
}
