/*
 * Operation regions and fields. tests/regions.rs calls the methods here and checks what reached the
 * host. Compile with tests/asl/build.sh.
 */
DefinitionBlock ("", "DSDT", 2, "OSMIUM", "REGS", 1)
{
    OperationRegion (RAM0, SystemMemory, 0x1000, 0x100)
    Field (RAM0, ByteAcc, NoLock, Preserve)
    {
        R008, 8,
        R016, 16,
        , 8,
        R032, 32,
    }
    Field (RAM0, DWordAcc, NoLock, WriteAsZeros)
    {
        Offset (0x10),
        D000, 4,
        D004, 4,
        D008, 24,
        D032, 32,
    }
    Field (RAM0, DWordAcc, NoLock, WriteAsOnes)
    {
        Offset (0x18),
        O000, 4,
        O004, 28,
    }
    Field (RAM0, DWordAcc, NoLock, Preserve)
    {
        Offset (0x1C),
        P000, 4,
        P004, 4,
    }
    Field (RAM0, QWordAcc, NoLock, Preserve)
    {
        Offset (0x20),
        Q000, 64,
    }
    Field (RAM0, AnyAcc, NoLock, Preserve)
    {
        Offset (0x30),
        A003, 3,
        A005, 5,
        A008, 32,
        A040, 24,
    }
    Field (RAM0, ByteAcc, NoLock, Preserve)
    {
        Offset (0x40),
        BIG, 128,
    }
    Field (RAM0, ByteAcc, NoLock, Preserve)
    {
        Offset (0x50),
        UNA, 12,
    }
    Field (RAM0, WordAcc, NoLock, Preserve)
    {
        Offset (0x60),
        W000, 20,
    }
    Field (RAM0, ByteAcc, NoLock, Preserve)
    {
        Offset (0xFE),
        EDG0, 16,
    }
    Name (SHLN, 4)
    OperationRegion (SHRT, SystemMemory, 0x3000, SHLN)
    Field (SHRT, ByteAcc, NoLock, Preserve)
    {
        Offset (2),
        OVER, 32,
    }

    OperationRegion (IO00, SystemIO, 0x60, 8)
    Field (IO00, ByteAcc, NoLock, Preserve)
    {
        IOA, 8,
        IOB, 8,
    }
    Field (IO00, DWordAcc, NoLock, Preserve)
    {
        Offset (4),
        IOD, 32,
    }
    OperationRegion (IO64, SystemIO, 0x100, 8)
    Field (IO64, QWordAcc, NoLock, Preserve)
    {
        IOQ, 64,
    }

    OperationRegion (IDXR, SystemIO, 0x70, 2)
    Field (IDXR, ByteAcc, NoLock, Preserve)
    {
        IDX, 8,
        DAT, 8,
    }
    IndexField (IDX, DAT, ByteAcc, NoLock, Preserve)
    {
        IF00, 8,
        IF01, 8,
        IF02, 4,
        IF03, 4,
    }

    OperationRegion (BNKR, SystemMemory, 0x2000, 0x10)
    Field (BNKR, ByteAcc, NoLock, Preserve)
    {
        BANK, 8,
    }
    OperationRegion (BREG, SystemMemory, 0x2010, 0x10)
    BankField (BREG, BANK, 1, ByteAcc, NoLock, Preserve)
    {
        B1A, 8,
        B1B, 8,
    }
    BankField (BREG, BANK, 2, ByteAcc, NoLock, Preserve)
    {
        B2A, 8,
        B2B, 8,
    }

    OperationRegion (ECR, EmbeddedControl, 0, 0xFF)
    Field (ECR, ByteAcc, NoLock, Preserve)
    {
        Offset (0x10),
        EC10, 8,
        EC11, 8,
    }

    Name (RGM_, 0)
    Method (_REG, 2)
    {
        If (Arg1) { Or (RGM_, ShiftLeft (1, Arg0), RGM_) }
    }

    Device (PCI0)
    {
        Name (_HID, EisaId ("PNP0A03"))
        Name (_ADR, 0)
        Name (_BBN, 3)
        Name (_SEG, 1)
        Name (RGP_, 0)
        Method (_REG, 2)
        {
            If (Arg1) { Or (RGP_, ShiftLeft (1, Arg0), RGP_) }
        }
        OperationRegion (PCFG, PCI_Config, 0, 0x100)
        Field (PCFG, DWordAcc, NoLock, Preserve)
        {
            VID, 16,
            DID, 16,
        }
        Method (G017) { Return (VID) }
        Device (DEV1)
        {
            Name (_ADR, 0x00010002)
            OperationRegion (CFG, PCI_Config, 0x40, 0x10)
            Field (CFG, ByteAcc, NoLock, Preserve)
            {
                R40, 8,
                R41, 8,
            }
            Method (G018) { Return (R41) }
            Device (CHLD)
            {
                Name (_ADR, 0x00030001)
                OperationRegion (CFG, PCI_Config, 0, 0x10)
                Field (CFG, DWordAcc, NoLock, Preserve)
                {
                    C000, 32,
                }
                Method (G019) { Return (C000) }
            }
        }
    }

    Method (W001)
    {
        Store (0xAB, R008)
        Store (0x1234, R016)
        Store (0xDEADBEEF, R032)
    }
    Method (G001) { Return (R032) }
    Method (G002) { Return (R016) }
    Method (W002) { Store (0x5, D004) }
    Method (W003) { Store (0x3, D000) }
    Method (W004) { Store (0x0, O000) }
    Method (W005) { Store (0xF, P004) }
    Method (W006) { Store (0x1122334455667788, Q000) }
    Method (G006) { Return (Q000) }
    Method (G007) { Return (A003) }
    Method (G008) { Return (A008) }
    Method (W007) { Store (0x1, A003) }
    Method (G009) { Return (BIG) }
    Method (W008) { Store (Buffer () { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, BIG) }
    Method (W009) { Store (0xABC, UNA) }
    Method (G010) { Return (UNA) }
    Method (W010) { Store (0xFFFFF, W000) }
    Method (G011) { Return (EDG0) }
    Method (G012) { Return (OVER) }
    Method (W011) { Store (0x5A, IOA) }
    Method (G013) { Return (IOB) }
    Method (W012) { Store (0x11223344, IOD) }
    Method (W013) { Store (0x1122334455667788, IOQ) }
    Method (G014) { Return (IOQ) }
    Method (W014) { Store (0x99, IF01) }
    Method (G015) { Return (IF01) }
    Method (W015) { Store (0x6, IF02) }
    Method (W016) { Store (7, B2B) }
    Method (G016) { Return (B1A) }
    Method (W017) { Store (0x77, EC11) }
    Method (G020) { Return (EC10) }
}
