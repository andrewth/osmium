/*
 * Language tests. Every method named Tnnn returns 0 when it passes and the number of the failing step
 * otherwise; tests/lang.rs runs them all. Compile with tests/asl/build.sh.
 */
DefinitionBlock ("", "DSDT", 2, "OSMIUM", "LANG", 1)
{
    Name (N001, 0x1234)
    Name (S001, "hello")
    Name (B001, Buffer () { 1, 2, 3, 4 })
    Name (P001, Package () { 1, "two", Buffer () { 3 }, Package () { 4, 5 } })
    Name (INT1, 0)
    Name (STR1, "abc")
    Name (BUF1, Buffer (4) {})
    Alias (N001, AL01)
    Mutex (MTX0, 0)
    Event (EVT0)

    Method (T000)
    {
        Store (Add (3, 4), Local0)
        If (LNotEqual (Local0, 7)) { Return (1) }
        If (LNotEqual (Subtract (10, 4), 6)) { Return (2) }
        If (LNotEqual (Multiply (6, 7), 42)) { Return (3) }
        Divide (17, 5, Local1, Local2)
        If (LNotEqual (Local1, 2)) { Return (4) }
        If (LNotEqual (Local2, 3)) { Return (5) }
        If (LNotEqual (Mod (17, 5), 2)) { Return (6) }
        If (LNotEqual (ShiftLeft (1, 40), 0x10000000000)) { Return (7) }
        If (LNotEqual (ShiftRight (0x100, 4), 0x10)) { Return (8) }
        If (LNotEqual (And (0xFF0, 0x0FF), 0x0F0)) { Return (9) }
        If (LNotEqual (Or (0xF0, 0x0F), 0xFF)) { Return (10) }
        If (LNotEqual (Xor (0xFF, 0x0F), 0xF0)) { Return (11) }
        If (LNotEqual (Nand (0xFF, 0x0F), 0xFFFFFFFFFFFFFFF0)) { Return (12) }
        If (LNotEqual (Nor (0, 0), Ones)) { Return (13) }
        If (LNotEqual (Not (0), Ones)) { Return (14) }
        If (LNotEqual (FindSetLeftBit (0x80), 8)) { Return (15) }
        If (LNotEqual (FindSetRightBit (0x80), 8)) { Return (16) }
        If (LNotEqual (FindSetLeftBit (0), 0)) { Return (17) }
        If (LNotEqual (FindSetRightBit (0x8001), 1)) { Return (18) }
        Store (5, Local3)
        Increment (Local3)
        Increment (Local3)
        Decrement (Local3)
        If (LNotEqual (Local3, 6)) { Return (19) }
        If (LNotEqual (Add (Ones, 1), 0)) { Return (20) }
        If (LNotEqual (ShiftLeft (1, 64), 0)) { Return (21) }
        Return (0)
    }

    Method (T001)
    {
        If (LAnd (1, 0)) { Return (1) }
        If (LNot (LOr (1, 0))) { Return (2) }
        If (LNotEqual (LAnd (1, 1), Ones)) { Return (3) }
        If (LEqual (LGreater (1, 2), Ones)) { Return (4) }
        If (LNot (LLess (1, 2))) { Return (5) }
        If (LNot (LGreaterEqual (2, 2))) { Return (6) }
        If (LNot (LLessEqual (2, 2))) { Return (7) }
        If (LEqual (1, 2)) { Return (8) }
        If (LNot (LEqual ("abc", "abc"))) { Return (9) }
        If (LNot (LLess ("abc", "abd"))) { Return (10) }
        If (LNot (LGreater ("abcd", "abc"))) { Return (11) }
        If (LNot (LEqual (Buffer () { 1, 2 }, Buffer () { 1, 2 }))) { Return (12) }
        If (LNot (LLess (Buffer () { 1, 2 }, Buffer () { 1, 3 }))) { Return (13) }
        If (LNot (LEqual (0x10, "10"))) { Return (14) }
        Return (0)
    }

    Method (T002)
    {
        If (LNotEqual (SizeOf (S001), 5)) { Return (1) }
        If (LNotEqual (Concatenate ("ab", "cd"), "abcd")) { Return (2) }
        If (LNotEqual (Mid ("hello", 1, 3), "ell")) { Return (3) }
        Store (Mid ("hello", 3, 99), Local7)
        If (LNotEqual (SizeOf (Local7), 2)) { Return (4) }
        Store (Mid ("hello", 9, 2), Local7)
        If (LNotEqual (SizeOf (Local7), 0)) { Return (5) }
        If (LNotEqual (ToInteger ("123"), 123)) { Return (6) }
        If (LNotEqual (ToInteger ("0x10"), 16)) { Return (7) }
        If (LNotEqual (ToDecimalString (255), "255")) { Return (8) }
        If (LNotEqual (ToString (Buffer () { 0x61, 0x62, 0 }), "ab")) { Return (9) }
        If (LNotEqual (ToString (Buffer () { 0x61, 0x62, 0x63 }, 2), "ab")) { Return (10) }
        Store (ToBuffer ("ab"), Local7)
        If (LNotEqual (SizeOf (Local7), 2)) { Return (11) }
        Store (ToBuffer (0x1122), Local7)
        If (LNotEqual (SizeOf (Local7), 8)) { Return (12) }
        Store (Concatenate (1, 2), Local7)
        If (LNotEqual (SizeOf (Local7), 16)) { Return (13) }
        Store (Concatenate ("a", 0x1F), Local7)
        If (LNotEqual (SizeOf (Local7), 17)) { Return (14) }
        Store (Concatenate (Buffer () { 1 }, Buffer () { 2, 3 }), Local7)
        If (LNotEqual (SizeOf (Local7), 3)) { Return (15) }
        If (LNotEqual (ToInteger (Buffer () { 0x34, 0x12 }), 0x1234)) { Return (16) }
        If (LNotEqual (FromBCD (0x1234), 1234)) { Return (17) }
        If (LNotEqual (ToBCD (1234), 0x1234)) { Return (18) }
        Return (0)
    }

    Method (T003)
    {
        Store (Buffer (8) {}, Local0)
        CreateDWordField (Local0, 0, DW0)
        CreateByteField (Local0, 3, BY3)
        CreateWordField (Local0, 4, WD4)
        CreateBitField (Local0, 1, BIT1)
        CreateQWordField (Local0, 0, QW0)
        CreateField (Local0, 36, 12, FLD)
        Store (0x11223344, DW0)
        If (LNotEqual (BY3, 0x11)) { Return (1) }
        If (LNotEqual (DerefOf (Index (Local0, 0)), 0x44)) { Return (2) }
        If (LNotEqual (BIT1, 0)) { Return (3) }
        Store (1, BIT1)
        If (LNotEqual (DerefOf (Index (Local0, 0)), 0x46)) { Return (4) }
        Store (0xBEEF, WD4)
        If (LNotEqual (DerefOf (Index (Local0, 5)), 0xBE)) { Return (5) }
        Store (0xABC, FLD)
        If (LNotEqual (FLD, 0xABC)) { Return (6) }
        If (LNotEqual (WD4, 0xABCF)) { Return (7) }
        If (LNotEqual (QW0, 0xABCF11223346)) { Return (8) }
        Store (0x55, Index (Local0, 7))
        If (LNotEqual (QW0, 0x5500ABCF11223346)) { Return (9) }
        Return (0)
    }

    Method (T004)
    {
        If (LNotEqual (SizeOf (P001), 4)) { Return (1) }
        If (LNotEqual (DerefOf (Index (P001, 0)), 1)) { Return (2) }
        If (LNotEqual (DerefOf (Index (P001, 1)), "two")) { Return (3) }
        If (LNotEqual (DerefOf (Index (DerefOf (Index (P001, 3)), 1)), 5)) { Return (4) }
        Store (99, Index (P001, 0))
        If (LNotEqual (DerefOf (Index (P001, 0)), 99)) { Return (5) }
        Store (1, Index (P001, 0))
        Store (Package (3) { 7, 8 }, Local0)
        If (LNotEqual (SizeOf (Local0), 3)) { Return (6) }
        If (LNotEqual (ObjectType (DerefOf (Index (Local0, 2))), 0)) { Return (7) }
        Store (9, Index (Local0, 2))
        If (LNotEqual (DerefOf (Index (Local0, 2)), 9)) { Return (8) }
        Store (Index (B001, 2), Local1)
        If (LNotEqual (DerefOf (Local1), 3)) { Return (9) }
        Store (0x77, Index (B001, 2))
        If (LNotEqual (DerefOf (Index (B001, 2)), 0x77)) { Return (10) }
        Store (3, Index (B001, 2))
        Return (0)
    }

    Method (T005)
    {
        If (LNotEqual (ObjectType (N001), 1)) { Return (1) }
        If (LNotEqual (ObjectType (S001), 2)) { Return (2) }
        If (LNotEqual (ObjectType (B001), 3)) { Return (3) }
        If (LNotEqual (ObjectType (P001), 4)) { Return (4) }
        If (LNotEqual (ObjectType (T000), 8)) { Return (5) }
        If (LNotEqual (ObjectType (MTX0), 9)) { Return (6) }
        If (LNotEqual (ObjectType (EVT0), 7)) { Return (7) }
        If (LNotEqual (ObjectType (Local5), 0)) { Return (8) }
        If (LNotEqual (ObjectType (Debug), 16)) { Return (9) }
        If (LNotEqual (AL01, 0x1234)) { Return (10) }
        If (LNotEqual (ObjectType (AL01), 1)) { Return (11) }
        Return (0)
    }

    Method (FIB, 1)
    {
        If (LLess (Arg0, 2)) { Return (Arg0) }
        Return (Add (FIB (Subtract (Arg0, 1)), FIB (Subtract (Arg0, 2))))
    }

    Method (SETR, 1) { Store (42, Arg0) }
    Method (ADD3, 3) { Return (Add (Arg0, Add (Arg1, Arg2))) }
    Method (NOVL) { Store (1, Local0) }

    Method (T006)
    {
        If (LNotEqual (FIB (15), 610)) { Return (1) }
        If (LNotEqual (ADD3 (1, 2, 3), 6)) { Return (2) }
        Store (0, Local0)
        SETR (RefOf (Local0))
        If (LNotEqual (Local0, 42)) { Return (3) }
        Store (RefOf (N001), Local1)
        If (LNotEqual (DerefOf (Local1), 0x1234)) { Return (4) }
        Store (0, Local2)
        Store (RefOf (Local2), Local3)
        Store (5, Local2)
        If (LNotEqual (DerefOf (Local3), 5)) { Return (5) }
        If (LNot (CondRefOf (N001, Local4))) { Return (6) }
        If (LNotEqual (DerefOf (Local4), 0x1234)) { Return (7) }
        Return (0)
    }

    Method (T007)
    {
        Store (0, Local0)
        Store (0, Local1)
        While (LLess (Local0, 10))
        {
            Increment (Local0)
            If (LEqual (Local0, 3)) { Continue }
            If (LEqual (Local0, 8)) { Break }
            Add (Local1, Local0, Local1)
        }
        If (LNotEqual (Local1, 25)) { Return (1) }
        Store (0, Local2)
        While (One)
        {
            While (One)
            {
                Increment (Local2)
                If (LGreater (Local2, 4)) { Break }
            }
            If (LGreater (Local2, 4)) { Break }
        }
        If (LNotEqual (Local2, 5)) { Return (2) }
        Store (0, Local3)
        While (One)
        {
            Increment (Local3)
            If (LEqual (Local3, 7)) { Return (0) }
        }
        Return (3)
    }

    Method (SWT, 1)
    {
        Switch (ToInteger (Arg0))
        {
            Case (1) { Return (10) }
            Case (2) { Return (20) }
            Case (Package () { 3, 4 }) { Return (30) }
            Default { Return (99) }
        }
    }

    Method (T008)
    {
        If (LNotEqual (SWT (1), 10)) { Return (1) }
        If (LNotEqual (SWT (2), 20)) { Return (2) }
        If (LNotEqual (SWT (4), 30)) { Return (3) }
        If (LNotEqual (SWT (7), 99)) { Return (4) }
        Return (0)
    }

    Method (LOCN, 0)
    {
        Name (LOC1, 5)
        Store (Add (LOC1, 1), LOC1)
        Return (LOC1)
    }

    Method (T009)
    {
        // A named object a method creates is gone when it returns, so a second call can create it again.
        If (LNotEqual (LOCN (), 6)) { Return (1) }
        If (LNotEqual (LOCN (), 6)) { Return (2) }
        If (CondRefOf (\LOC1)) { Return (3) }
        Return (0)
    }

    Method (T010)
    {
        Store (7, INT1)
        If (LNotEqual (INT1, 7)) { Return (1) }
        Store ("10", INT1)
        If (LNotEqual (INT1, 16)) { Return (2) }
        Store (Buffer () { 1, 2 }, INT1)
        If (LNotEqual (INT1, 0x0201)) { Return (3) }
        Store (0x1F, STR1)
        If (LNotEqual (SizeOf (STR1), 16)) { Return (4) }
        Store ("abc", STR1)
        Store (Buffer () { 1, 2 }, BUF1)
        If (LNotEqual (SizeOf (BUF1), 4)) { Return (5) }
        If (LNotEqual (DerefOf (Index (BUF1, 1)), 2)) { Return (6) }
        If (LNotEqual (DerefOf (Index (BUF1, 2)), 0)) { Return (7) }
        Store (Buffer () { 1, 2, 3, 4, 5, 6 }, BUF1)
        If (LNotEqual (SizeOf (BUF1), 4)) { Return (8) }
        Store (0, INT1)
        // CopyObject replaces the object, whatever its type.
        CopyObject ("now a string", INT1)
        If (LNotEqual (ObjectType (INT1), 2)) { Return (9) }
        CopyObject (0, INT1)
        Return (0)
    }

    Method (T011)
    {
        If (Acquire (MTX0, 0xFFFF)) { Return (1) }
        Release (MTX0)
        Signal (EVT0)
        If (Wait (EVT0, 0)) { Return (2) }
        If (LEqual (Wait (EVT0, 0), 0)) { Return (3) }
        Signal (EVT0)
        Reset (EVT0)
        If (LEqual (Wait (EVT0, 0), 0)) { Return (4) }
        Return (0)
    }

    Method (T012)
    {
        Store (Package () { 5, 10, 15, 20 }, Local0)
        If (LNotEqual (Match (Local0, MEQ, 15, MTR, 0, 0), 2)) { Return (1) }
        If (LNotEqual (Match (Local0, MGT, 7, MTR, 0, 0), 1)) { Return (2) }
        If (LNotEqual (Match (Local0, MLE, 5, MTR, 0, 0), 0)) { Return (3) }
        If (LNotEqual (Match (Local0, MEQ, 99, MTR, 0, 0), Ones)) { Return (4) }
        If (LNotEqual (Match (Local0, MGE, 10, MLT, 20, 0), 1)) { Return (5) }
        If (LNotEqual (Match (Local0, MEQ, 5, MTR, 0, 1), Ones)) { Return (6) }
        Return (0)
    }

    Method (T013)
    {
        // Arguments are copies: a method that changes its argument does not change the caller's value.
        Store (5, Local0)
        BUMP (Local0)
        If (LNotEqual (Local0, 5)) { Return (1) }
        Return (0)
    }

    Method (BUMP, 1) { Increment (Arg0) }

    Method (RES1)
    {
        Return (ConcatenateResTemplate (ResourceTemplate () { IO (Decode16, 0x60, 0x60, 1, 1) },
            ResourceTemplate () { IRQ (Edge, ActiveHigh, Exclusive) { 4 } }))
    }

    Method (T014)
    {
        Store (Buffer () { 1, 2, 3 }, Local0)
        Store (SizeOf (Local0), Local1)
        If (LNotEqual (Local1, 3)) { Return (1) }
        Store (ConcatenateResTemplate (ResourceTemplate () { IO (Decode16, 0x60, 0x60, 1, 1) },
            ResourceTemplate () { IRQ (Edge, ActiveHigh, Exclusive) { 4 } }), Local2)
        // 8 byte IO + 4 byte IRQ + 2 byte end tag.
        If (LNotEqual (SizeOf (Local2), 14)) { Return (2) }
        Return (0)
    }
}
