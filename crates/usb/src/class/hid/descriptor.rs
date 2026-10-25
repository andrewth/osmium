//! HID report descriptor parsing (HID 1.11 section 6.2.2).
//!
//! A report descriptor is a stream of short items. *Global* items set state
//! that sticks (usage page, logical range, report size/count/ID), *local*
//! items set state for the next main item only (usages), and *main* items
//! (Input, Output, Feature, Collection) consume that state. [`ReportDescriptor::parse`]
//! runs this state machine and keeps the result as a flat table of
//! [`Field`]s, each with its position in its report, so a report can be
//! decoded without looking at the descriptor again (see [`super::report`]).
//!
//! The descriptor is untrusted device input. Parsing never panics and never
//! allocates: every table has a fixed capacity and overflowing one is a
//! [`ParseError`], as are truncated items, unbalanced collections and
//! impossible sizes. Constant (padding) fields take up bits in their report
//! but are not kept in the table.

/// Capacity of the field table.
pub const MAX_FIELDS: usize = 64;
/// Capacity of the pool of explicitly listed usages.
pub const MAX_USAGES: usize = 256;
/// Capacity of the table of distinct (kind, report ID) pairs.
pub const MAX_REPORTS: usize = 32;
/// Capacity of the list of top-level collections.
pub const MAX_APPLICATIONS: usize = 8;
/// The longest report accepted, in bits (4096 bytes).
pub const MAX_REPORT_BITS: u32 = 4096 * 8;
/// Most usages one main item may list.
const MAX_LOCAL_USAGES: usize = 32;
/// Deepest collection nesting.
const MAX_DEPTH: usize = 16;
/// Deepest `Push` nesting.
const MAX_PUSH: usize = 4;

/// Why a report descriptor was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// An item runs past the end of the descriptor.
    Truncated,
    /// An `End Collection` without a `Collection`, or a `Collection` never ended.
    UnbalancedCollection,
    /// Collections nested too deeply.
    TooDeep,
    /// `Pop` without `Push`, or `Push` nested too deeply.
    BadPushPop,
    /// More than [`MAX_FIELDS`] data fields.
    TooManyFields,
    /// More usages listed than the tables hold.
    TooManyUsages,
    /// More than [`MAX_REPORTS`] distinct reports.
    TooManyReports,
    /// A data field whose report size is 0 or over 32 bits.
    BadReportSize,
    /// A report longer than [`MAX_REPORT_BITS`].
    ReportTooLong,
    /// Report ID 0 or over 255, which are not allowed.
    BadReportId,
    /// A data field whose logical minimum exceeds its maximum.
    BadLogicalRange,
    /// A usage minimum above its maximum, or only one of the two.
    BadUsageRange,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

/// Which direction a report travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportKind {
    /// Device to host, on the interrupt IN endpoint.
    Input,
    /// Host to device (LEDs, rumble).
    Output,
    /// Configuration, read or written with control requests.
    Feature,
}

/// The data bits of an Input, Output or Feature item (HID 1.11 section 6.2.2.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FieldFlags(pub u16);

impl FieldFlags {
    /// The field holds fixed data, not a value (padding).
    pub const fn is_constant(self) -> bool {
        self.0 & 1 != 0
    }
    /// Each element is its own variable. Otherwise the field is an array of
    /// indices into the field's usages.
    pub const fn is_variable(self) -> bool {
        self.0 & 2 != 0
    }
    /// An array field (the opposite of [`is_variable`](Self::is_variable)).
    pub const fn is_array(self) -> bool {
        !self.is_variable()
    }
    /// Values are changes since the last report (a mouse's motion).
    pub const fn is_relative(self) -> bool {
        self.0 & 4 != 0
    }
    /// Values wrap around at the limits.
    pub const fn wraps(self) -> bool {
        self.0 & 8 != 0
    }
    /// The relation between value and measurement is not linear.
    pub const fn is_nonlinear(self) -> bool {
        self.0 & 0x10 != 0
    }
    /// Values outside the logical range mean "no data" (a hat switch at rest).
    pub const fn has_null_state(self) -> bool {
        self.0 & 0x40 != 0
    }
}

/// A usage is `page << 16 | id`.
pub const fn usage(page: u16, id: u16) -> u32 {
    (page as u32) << 16 | id as u32
}

/// The usage page of a usage.
pub const fn page_of(usage: u32) -> u16 {
    (usage >> 16) as u16
}

/// The usage ID of a usage.
pub const fn id_of(usage: u32) -> u16 {
    usage as u16
}

/// Usage pages and usages the class drivers care about.
pub mod usages {
    use super::usage;
    /// Generic Desktop page.
    pub const PAGE_GENERIC_DESKTOP: u16 = 0x01;
    /// Keyboard/Keypad page.
    pub const PAGE_KEYBOARD: u16 = 0x07;
    /// LED page.
    pub const PAGE_LED: u16 = 0x08;
    /// Button page.
    pub const PAGE_BUTTON: u16 = 0x09;
    /// Consumer page.
    pub const PAGE_CONSUMER: u16 = 0x0c;
    /// Generic Desktop: Pointer.
    pub const POINTER: u32 = usage(0x01, 0x01);
    /// Generic Desktop: Mouse.
    pub const MOUSE: u32 = usage(0x01, 0x02);
    /// Generic Desktop: Joystick.
    pub const JOYSTICK: u32 = usage(0x01, 0x04);
    /// Generic Desktop: Game Pad.
    pub const GAMEPAD: u32 = usage(0x01, 0x05);
    /// Generic Desktop: Keyboard.
    pub const KEYBOARD: u32 = usage(0x01, 0x06);
    /// Generic Desktop: Keypad.
    pub const KEYPAD: u32 = usage(0x01, 0x07);
    /// Generic Desktop: X.
    pub const X: u32 = usage(0x01, 0x30);
    /// Generic Desktop: Y.
    pub const Y: u32 = usage(0x01, 0x31);
    /// Generic Desktop: Z.
    pub const Z: u32 = usage(0x01, 0x32);
    /// Generic Desktop: Rx.
    pub const RX: u32 = usage(0x01, 0x33);
    /// Generic Desktop: Ry.
    pub const RY: u32 = usage(0x01, 0x34);
    /// Generic Desktop: Rz.
    pub const RZ: u32 = usage(0x01, 0x35);
    /// Generic Desktop: Wheel.
    pub const WHEEL: u32 = usage(0x01, 0x38);
    /// Generic Desktop: Hat Switch.
    pub const HAT_SWITCH: u32 = usage(0x01, 0x39);
    /// Consumer: AC Pan (horizontal wheel).
    pub const AC_PAN: u32 = usage(0x0c, 0x238);
    /// LED page: Num Lock.
    pub const LED_NUM_LOCK: u32 = usage(0x08, 0x01);
    /// LED page: Caps Lock.
    pub const LED_CAPS_LOCK: u32 = usage(0x08, 0x02);
    /// LED page: Scroll Lock.
    pub const LED_SCROLL_LOCK: u32 = usage(0x08, 0x03);
    /// Button page: button `n` (1-based).
    pub const fn button(n: u16) -> u32 {
        usage(0x09, n)
    }
    /// Keyboard page: key with usage ID `id`.
    pub const fn key(id: u16) -> u32 {
        usage(0x07, id)
    }
}

/// The usages a field's elements stand for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usages {
    /// None given: every element has usage 0.
    None,
    /// `min..=max`: element `i` of a variable field is `min + i`; value `v`
    /// of an array field is `min + (v - logical_min)`.
    Range {
        /// First usage.
        min: u32,
        /// Last usage.
        max: u32,
    },
    /// `len` usages starting at `start` in the descriptor's pool
    /// ([`ReportDescriptor::field_usage`] reads them).
    List {
        /// Index of the first usage in the pool.
        start: u16,
        /// How many there are.
        len: u16,
    },
}

/// One data field of a report: `report_count` elements of `report_size` bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    /// Input, output or feature.
    pub kind: ReportKind,
    /// Report ID, or 0 when the descriptor uses none.
    pub report_id: u8,
    /// The main item's data bits.
    pub flags: FieldFlags,
    /// Where the first element starts, in bits from the start of the report
    /// data (after the report ID byte, if any).
    pub bit_offset: u16,
    /// Bits per element, 1 to 32.
    pub report_size: u8,
    /// Number of elements.
    pub report_count: u16,
    /// Smallest value an element can hold. Fields whose minimum is negative
    /// are signed, the rest unsigned.
    pub logical_min: i64,
    /// Largest value an element can hold.
    pub logical_max: i64,
    /// What `logical_min` means in `unit`s (equal to the logical range if the
    /// descriptor gave none).
    pub physical_min: i64,
    /// What `logical_max` means in `unit`s.
    pub physical_max: i64,
    /// The unit, as the descriptor's nibble-encoded word.
    pub unit: u32,
    /// Power of ten the physical range is scaled by, -8 to 7.
    pub unit_exponent: i8,
    /// What the elements mean.
    pub usages: Usages,
    /// Usage of the outermost collection this field is in (0 if none), such
    /// as [`usages::MOUSE`].
    pub application: u32,
    /// Usage of the innermost collection this field is in (0 if none).
    pub collection: u32,
}

impl Field {
    const EMPTY: Self = Self {
        kind: ReportKind::Input,
        report_id: 0,
        flags: FieldFlags(0),
        bit_offset: 0,
        report_size: 0,
        report_count: 0,
        logical_min: 0,
        logical_max: 0,
        physical_min: 0,
        physical_max: 0,
        unit: 0,
        unit_exponent: 0,
        usages: Usages::None,
        application: 0,
        collection: 0,
    };

    /// The usage page of the field's first usage, if it has any.
    pub fn usage_page(&self, desc: &ReportDescriptor) -> Option<u16> {
        match self.usages {
            Usages::None => None,
            Usages::Range { min, .. } => Some(page_of(min)),
            Usages::List { .. } => desc.field_usage(self, 0).map(page_of),
        }
    }
}

/// The size of one (kind, report ID) report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReportInfo {
    kind: ReportKind,
    id: u8,
    bits: u32,
}

/// A parsed report descriptor.
#[derive(Clone, Debug)]
pub struct ReportDescriptor {
    fields: [Field; MAX_FIELDS],
    n_fields: usize,
    pool: [u32; MAX_USAGES],
    n_pool: usize,
    reports: [ReportInfo; MAX_REPORTS],
    n_reports: usize,
    apps: [u32; MAX_APPLICATIONS],
    n_apps: usize,
    uses_ids: bool,
}

#[derive(Clone, Copy)]
struct Global {
    usage_page: u16,
    logical_min: i64,
    logical_max: (u32, usize),
    physical_min: i64,
    physical_max: (u32, usize),
    unit_exponent: i8,
    unit: u32,
    report_size: u32,
    report_count: u32,
    report_id: u8,
}

impl Global {
    const INIT: Self = Self {
        usage_page: 0,
        logical_min: 0,
        logical_max: (0, 0),
        physical_min: 0,
        physical_max: (0, 0),
        unit_exponent: 0,
        unit: 0,
        report_size: 0,
        report_count: 0,
        report_id: 0,
    };
}

struct Local {
    usages: [u32; MAX_LOCAL_USAGES],
    n: usize,
    min: Option<u32>,
    max: Option<u32>,
    in_delimiter: bool,
    delimiter_taken: bool,
}

impl Local {
    const INIT: Self =
        Self { usages: [0; MAX_LOCAL_USAGES], n: 0, min: None, max: None, in_delimiter: false, delimiter_taken: false };
}

/// Sign-extends the low `size` bytes of `v`.
fn sign_extend(v: u32, size: usize) -> i64 {
    match size {
        0 => 0,
        1 => v as u8 as i8 as i64,
        2 => v as u16 as i16 as i64,
        _ => v as i32 as i64,
    }
}

/// A maximum is unsigned unless the minimum is negative.
fn resolve_max(raw: (u32, usize), min: i64) -> i64 {
    if min < 0 { sign_extend(raw.0, raw.1) } else { raw.0 as i64 }
}

fn extended_usage(raw: u32, size: usize, page: u16) -> u32 {
    if size == 4 { raw } else { usage(page, raw as u16) }
}

/// The unit exponent nibble (4-bit two's complement).
fn unit_exponent(raw: u32) -> i8 {
    let n = (raw & 0xf) as i8;
    if n > 7 { n - 16 } else { n }
}

impl ReportDescriptor {
    const EMPTY: Self = Self {
        fields: [Field::EMPTY; MAX_FIELDS],
        n_fields: 0,
        pool: [0; MAX_USAGES],
        n_pool: 0,
        reports: [ReportInfo { kind: ReportKind::Input, id: 0, bits: 0 }; MAX_REPORTS],
        n_reports: 0,
        apps: [0; MAX_APPLICATIONS],
        n_apps: 0,
        uses_ids: false,
    };

    /// Parses a report descriptor.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut d = Self::EMPTY;
        d.run(bytes)?;
        Ok(d)
    }

    fn run(&mut self, bytes: &[u8]) -> Result<(), ParseError> {
        let mut global = Global::INIT;
        let mut pushed = [Global::INIT; MAX_PUSH];
        let mut n_pushed = 0;
        let mut local = Local::INIT;
        let mut stack = [0u32; MAX_DEPTH];
        let mut depth = 0usize;
        let mut rest = bytes;
        while let Some((&prefix, tail)) = rest.split_first() {
            if prefix == 0xfe {
                // Long item: size, tag, data. None are defined; skip it.
                let (&len, tail) = tail.split_first().ok_or(ParseError::Truncated)?;
                let tail = tail.get(1..).ok_or(ParseError::Truncated)?;
                rest = tail.get(len as usize..).ok_or(ParseError::Truncated)?;
                continue;
            }
            let size = match prefix & 3 {
                0 => 0,
                1 => 1,
                2 => 2,
                _ => 4,
            };
            let (data, after) = tail.split_at_checked(size).ok_or(ParseError::Truncated)?;
            rest = after;
            let raw = data.iter().rev().fold(0u32, |a, &b| a << 8 | b as u32);
            let tag = prefix >> 4;
            match (prefix >> 2) & 3 {
                // Main.
                0 => {
                    match tag {
                        0x8 | 0x9 | 0xb => {
                            let kind = match tag {
                                0x8 => ReportKind::Input,
                                0x9 => ReportKind::Output,
                                _ => ReportKind::Feature,
                            };
                            let app = if depth > 0 { stack.first().copied().unwrap_or(0) } else { 0 };
                            let inner = depth.checked_sub(1).and_then(|i| stack.get(i)).copied().unwrap_or(0);
                            self.data_item(kind, FieldFlags(raw as u16), &global, &local, app, inner)?;
                        }
                        0xa => {
                            let u = if local.n > 0 { local.usages.first().copied().unwrap_or(0) } else { 0 };
                            *stack.get_mut(depth).ok_or(ParseError::TooDeep)? = u;
                            // Collection type 1 is Application.
                            if depth == 0
                                && raw == 1
                                && let Some(slot) = self.apps.get_mut(self.n_apps)
                            {
                                *slot = u;
                                self.n_apps += 1;
                            }
                            depth += 1;
                        }
                        0xc => depth = depth.checked_sub(1).ok_or(ParseError::UnbalancedCollection)?,
                        _ => {}
                    }
                    local = Local::INIT;
                }
                // Global.
                1 => match tag {
                    0x0 => global.usage_page = raw as u16,
                    0x1 => global.logical_min = sign_extend(raw, size),
                    0x2 => global.logical_max = (raw, size),
                    0x3 => global.physical_min = sign_extend(raw, size),
                    0x4 => global.physical_max = (raw, size),
                    0x5 => global.unit_exponent = unit_exponent(raw),
                    0x6 => global.unit = raw,
                    0x7 => global.report_size = raw,
                    0x8 => {
                        if raw == 0 || raw > 255 {
                            return Err(ParseError::BadReportId);
                        }
                        global.report_id = raw as u8;
                        self.uses_ids = true;
                    }
                    0x9 => global.report_count = raw,
                    0xa => {
                        *pushed.get_mut(n_pushed).ok_or(ParseError::BadPushPop)? = global;
                        n_pushed += 1;
                    }
                    0xb => {
                        n_pushed = n_pushed.checked_sub(1).ok_or(ParseError::BadPushPop)?;
                        global = pushed.get(n_pushed).copied().ok_or(ParseError::BadPushPop)?;
                    }
                    _ => {}
                },
                // Local.
                2 => match tag {
                    0x0 => {
                        if !(local.in_delimiter && local.delimiter_taken) {
                            let u = extended_usage(raw, size, global.usage_page);
                            *local.usages.get_mut(local.n).ok_or(ParseError::TooManyUsages)? = u;
                            local.n += 1;
                            local.delimiter_taken = local.in_delimiter;
                        }
                    }
                    0x1 => local.min = Some(extended_usage(raw, size, global.usage_page)),
                    0x2 => local.max = Some(extended_usage(raw, size, global.usage_page)),
                    0xa => {
                        local.in_delimiter = raw == 1;
                        local.delimiter_taken = false;
                    }
                    _ => {}
                },
                // Reserved.
                _ => {}
            }
        }
        if depth != 0 {
            return Err(ParseError::UnbalancedCollection);
        }
        Ok(())
    }

    fn data_item(
        &mut self,
        kind: ReportKind,
        flags: FieldFlags,
        g: &Global,
        local: &Local,
        application: u32,
        collection: u32,
    ) -> Result<(), ParseError> {
        let bits = (g.report_size as u64).checked_mul(g.report_count as u64).ok_or(ParseError::ReportTooLong)?;
        let existing = self.reports.iter().take(self.n_reports).position(|r| r.kind == kind && r.id == g.report_id);
        let slot = match existing {
            Some(i) => i,
            None => {
                let i = self.n_reports;
                *self.reports.get_mut(i).ok_or(ParseError::TooManyReports)? =
                    ReportInfo { kind, id: g.report_id, bits: 0 };
                self.n_reports += 1;
                i
            }
        };
        let info = self.reports.get_mut(slot).ok_or(ParseError::TooManyReports)?;
        let offset = info.bits;
        let end = u32::try_from(bits)
            .ok()
            .and_then(|b| offset.checked_add(b))
            .filter(|&e| e <= MAX_REPORT_BITS)
            .ok_or(ParseError::ReportTooLong)?;
        info.bits = end;
        if flags.is_constant() || g.report_count == 0 {
            return Ok(());
        }
        if g.report_size == 0 || g.report_size > 32 {
            return Err(ParseError::BadReportSize);
        }
        let logical_max = resolve_max(g.logical_max, g.logical_min);
        if g.logical_min > logical_max {
            return Err(ParseError::BadLogicalRange);
        }
        let (physical_min, physical_max) = if g.physical_min == 0 && g.physical_max.0 == 0 {
            (g.logical_min, logical_max)
        } else {
            (g.physical_min, resolve_max(g.physical_max, g.physical_min))
        };
        let usages = match (local.min, local.max) {
            (Some(min), Some(max)) if min <= max => Usages::Range { min, max },
            (None, None) if local.n == 0 => Usages::None,
            (None, None) => {
                let start = self.n_pool;
                let end = start.checked_add(local.n).ok_or(ParseError::TooManyUsages)?;
                let list = local.usages.get(..local.n).ok_or(ParseError::TooManyUsages)?;
                self.pool.get_mut(start..end).ok_or(ParseError::TooManyUsages)?.copy_from_slice(list);
                self.n_pool = end;
                Usages::List { start: start as u16, len: local.n as u16 }
            }
            _ => return Err(ParseError::BadUsageRange),
        };
        let field = Field {
            kind,
            report_id: g.report_id,
            flags,
            // Bounded by MAX_REPORT_BITS above.
            bit_offset: offset as u16,
            report_size: g.report_size as u8,
            report_count: g.report_count.min(u16::MAX as u32) as u16,
            logical_min: g.logical_min,
            logical_max,
            physical_min,
            physical_max,
            unit: g.unit,
            unit_exponent: g.unit_exponent,
            usages,
            application,
            collection,
        };
        *self.fields.get_mut(self.n_fields).ok_or(ParseError::TooManyFields)? = field;
        self.n_fields += 1;
        Ok(())
    }

    /// Every data field, in descriptor order.
    pub fn fields(&self) -> &[Field] {
        self.fields.get(..self.n_fields).unwrap_or(&[])
    }

    /// The fields of one kind of report with ID `id`.
    pub fn fields_of(&self, kind: ReportKind, id: u8) -> impl Iterator<Item = &Field> + '_ {
        self.fields().iter().filter(move |f| f.kind == kind && f.report_id == id)
    }

    /// Usages of the top-level application collections, such as
    /// [`usages::KEYBOARD`] and [`usages::MOUSE`].
    pub fn applications(&self) -> &[u32] {
        self.apps.get(..self.n_apps).unwrap_or(&[])
    }

    /// Whether the descriptor has a top-level collection with `usage`.
    pub fn has_application(&self, usage: u32) -> bool {
        self.applications().contains(&usage)
    }

    /// Whether reports begin with a report ID byte.
    pub fn uses_report_ids(&self) -> bool {
        self.uses_ids
    }

    /// The size of report `id` of `kind` in bytes, including the ID byte if
    /// the descriptor uses report IDs.
    pub fn report_len(&self, kind: ReportKind, id: u8) -> Option<usize> {
        let info = self.reports.iter().take(self.n_reports).find(|r| r.kind == kind && r.id == id)?;
        Some(info.bits.div_ceil(8) as usize + usize::from(self.uses_ids))
    }

    /// The length of the longest input report, in bytes.
    pub fn max_input_len(&self) -> usize {
        let lens = self.reports.iter().take(self.n_reports).filter(|r| r.kind == ReportKind::Input);
        lens.map(|r| r.bits.div_ceil(8) as usize + usize::from(self.uses_ids)).max().unwrap_or(0)
    }

    /// The usage of element `index` of `field`. A variable field with fewer
    /// listed usages than elements repeats the last. A usage range stops at
    /// its end.
    pub fn field_usage(&self, field: &Field, index: u32) -> Option<u32> {
        match field.usages {
            Usages::None => Some(0),
            Usages::Range { min, max } => min.checked_add(index).filter(|&u| u <= max),
            Usages::List { start, len } => {
                let i = index.min((len as u32).checked_sub(1)?) as usize;
                self.pool.get((start as usize).checked_add(i)?).copied()
            }
        }
    }

    /// The usage array value `value` selects in an array `field`.
    pub fn array_usage(&self, field: &Field, value: i64) -> Option<u32> {
        let index = u32::try_from(value.checked_sub(field.logical_min)?).ok()?;
        match field.usages {
            Usages::List { len, .. } if index >= len as u32 => None,
            _ => self.field_usage(field, index),
        }
    }

    /// The value an array `field` holds when it selects `usage`, the inverse
    /// of [`array_usage`](Self::array_usage).
    pub fn array_value_for(&self, field: &Field, usage: u32) -> Option<i64> {
        let index = match field.usages {
            Usages::None => return None,
            Usages::Range { min, max } => {
                if !(min..=max).contains(&usage) {
                    return None;
                }
                usage - min
            }
            Usages::List { start, len } => {
                let list = self.pool.get(start as usize..(start as usize).checked_add(len as usize)?)?;
                list.iter().position(|&u| u == usage)? as u32
            }
        };
        field.logical_min.checked_add(i64::from(index))
    }

    /// The logical range of the first input field that has `usage`.
    pub fn logical_range(&self, usage: u32) -> Option<(i64, i64)> {
        self.fields()
            .iter()
            .filter(|f| f.kind == ReportKind::Input && f.flags.is_variable())
            .find(|f| (0..f.report_count as u32).any(|i| self.field_usage(f, i) == Some(usage)))
            .map(|f| (f.logical_min, f.logical_max))
    }
}
