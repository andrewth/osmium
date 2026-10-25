//! Extracting values from, and packing values into, HID reports using a
//! parsed [`ReportDescriptor`].
//!
//! Reports come from the device and are as untrusted as the descriptor: [`ReportDescriptor::input_report`]
//! rejects a report shorter than its descriptor says, and [`Field::read`] and
//! [`Field::write`] check every bit position against the slice they are given.

use super::descriptor::{Field, ReportDescriptor, ReportKind};

impl Field {
    /// The bit position of element `index`, if it lies within the field.
    fn bit_position(&self, index: u32) -> Option<u32> {
        if index >= self.report_count as u32 {
            return None;
        }
        index.checked_mul(self.report_size as u32)?.checked_add(self.bit_offset as u32)
    }

    /// Reads element `index` of this field from report `data` (without the
    /// report ID byte). The value is sign-extended if the field's logical
    /// minimum is negative. `None` if `index` is out of range or the report
    /// is too short.
    pub fn read(&self, data: &[u8], index: u32) -> Option<i64> {
        let start = self.bit_position(index)?;
        let size = self.report_size as u32;
        let mut v = 0u64;
        for i in 0..size {
            let bit = start.checked_add(i)?;
            let byte = *data.get((bit / 8) as usize)?;
            v |= u64::from(byte >> (bit % 8) & 1) << i;
        }
        if self.logical_min < 0 && size > 0 && v >> (size - 1) & 1 != 0 {
            Some((v | !0u64 << size) as i64)
        } else {
            Some(v as i64)
        }
    }

    /// Writes `value` to element `index` of this field in report `data`
    /// (without the report ID byte). Returns `None`, writing nothing, if the
    /// report is too short, `index` is out of range or `value` does not fit
    /// in the field's size.
    pub fn write(&self, data: &mut [u8], index: u32, value: i64) -> Option<()> {
        let start = self.bit_position(index)?;
        let size = self.report_size as u32;
        if size == 0 {
            return None;
        }
        let fits = if self.logical_min < 0 {
            let half = 1i64 << (size - 1);
            (-half..half).contains(&value)
        } else {
            (0..1i64 << size).contains(&value)
        };
        if !fits {
            return None;
        }
        let last = start.checked_add(size.checked_sub(1)?)?;
        data.get((last / 8) as usize)?;
        for i in 0..size {
            let bit = start + i;
            let byte = data.get_mut((bit / 8) as usize)?;
            let mask = 1u8 << (bit % 8);
            if value >> i & 1 != 0 {
                *byte |= mask;
            } else {
                *byte &= !mask;
            }
        }
        Some(())
    }

    /// Whether `value` is inside the logical range.
    pub fn in_range(&self, value: i64) -> bool {
        (i64::from(self.logical_min)..=i64::from(self.logical_max)).contains(&value)
    }

    /// Maps a logical `value` to the physical range, as
    /// `physical_min + (value - logical_min) * (physical_max - physical_min) / (logical_max - logical_min)`.
    /// The result is in units of `10^unit_exponent` times [`unit`](Self::unit).
    pub fn physical(&self, value: i64) -> Option<i64> {
        let l = i128::from(self.logical_max) - i128::from(self.logical_min);
        if l == 0 {
            return Some(i64::from(self.physical_min));
        }
        let p = i128::from(self.physical_max) - i128::from(self.physical_min);
        let scaled = (i128::from(value) - i128::from(self.logical_min)).checked_mul(p)? / l;
        i64::try_from(scaled.checked_add(i128::from(self.physical_min))?).ok()
    }
}

/// One value found in a report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    /// The usage (`page << 16 | id`; see [`usage`](super::descriptor::usage)).
    pub usage: u32,
    /// The value. For an array field's element this is 1: the usage is
    /// active.
    pub value: i64,
    /// Whether the value is a change since the last report.
    pub relative: bool,
}

/// An input report, matched to the descriptor that describes it.
#[derive(Clone, Copy, Debug)]
pub struct InputReport<'desc, 'data> {
    desc: &'desc ReportDescriptor,
    id: u8,
    data: &'data [u8],
}

impl ReportDescriptor {
    /// Splits the report ID off `report` if the descriptor uses report IDs
    /// and wraps the rest. `None` for an empty report or an ID no input
    /// report has.
    pub fn input_report<'desc, 'data>(&'desc self, report: &'data [u8]) -> Option<InputReport<'desc, 'data>> {
        let (id, data) = if self.uses_report_ids() {
            let (&id, data) = report.split_first()?;
            (id, data)
        } else {
            (0, report)
        };
        // A report shorter than the descriptor says is malformed, not partial.
        (report.len() >= self.report_len(ReportKind::Input, id)?).then_some(())?;
        Some(InputReport { desc: self, id, data })
    }
}

impl<'desc, 'data> InputReport<'desc, 'data> {
    /// The report ID (0 if the descriptor uses none).
    pub fn id(&self) -> u8 {
        self.id
    }

    /// The report's fields.
    pub fn fields(&self) -> impl Iterator<Item = &'desc Field> + use<'desc, 'data> {
        self.desc.fields_of(ReportKind::Input, self.id)
    }

    /// Whether any of the report's fields has a usage on `page`.
    pub fn has_page(&self, page: u16) -> bool {
        self.fields().any(|f| f.usage_page(self.desc) == Some(page))
    }

    /// Calls `f` for each value the report carries: every element of a
    /// variable field (except those outside the range of a field with a null
    /// state), and each nonzero-usage element of an array field that selects
    /// a usage (value 1). Elements the report is too short to hold are
    /// skipped.
    pub fn for_each(&self, mut f: impl FnMut(Item)) {
        for field in self.fields() {
            for i in 0..field.report_count as u32 {
                let Some(value) = field.read(self.data, i) else { continue };
                if field.flags.is_variable() {
                    if field.flags.has_null_state() && !field.in_range(value) {
                        continue;
                    }
                    if let Some(usage) = self.desc.field_usage(field, i) {
                        f(Item { usage, value, relative: field.flags.is_relative() });
                    }
                } else if field.in_range(value)
                    && let Some(usage) = self.desc.array_usage(field, value).filter(|&u| u as u16 != 0)
                {
                    f(Item { usage, value: 1, relative: false });
                }
            }
        }
    }

    /// The value of `usage`: the element of a variable field with that
    /// usage, or 1 or 0 for a usage an array field can select, depending on
    /// whether it is currently selected. `None` if the report has no such
    /// field.
    pub fn value(&self, usage: u32) -> Option<i64> {
        let mut found = None;
        for field in self.fields() {
            if field.flags.is_variable() {
                for i in 0..field.report_count as u32 {
                    if self.desc.field_usage(field, i) == Some(usage) {
                        found = field.read(self.data, i).or(found);
                    }
                }
            } else if let Some(want) = self.desc.array_value_for(field, usage) {
                let on = (0..field.report_count as u32).filter_map(|i| field.read(self.data, i)).any(|v| v == want);
                found = Some(i64::from(on)).max(found);
            }
        }
        found
    }
}
