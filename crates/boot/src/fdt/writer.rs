use alloc::vec::Vec;

use super::{BEGIN_NODE, END, END_NODE, MAGIC, PROP};

/// Builds a device tree blob (version 17).
///
/// ```
/// use osmium_boot::fdt::{Fdt, FdtWriter};
///
/// let mut w = FdtWriter::new();
/// w.begin_node("");
/// w.property_u32("#address-cells", 2);
/// w.property_u32("#size-cells", 2);
/// w.begin_node("memory@80000000");
/// w.property_string("device_type", "memory");
/// w.property_cells("reg", &[0, 0x8000_0000, 0, 0x1000_0000]);
/// w.end_node();
/// w.end_node();
/// let blob = w.finish(0);
///
/// let fdt = Fdt::new(&blob).unwrap();
/// assert_eq!(fdt.memory().next(), Some((0x8000_0000, 0x1000_0000)));
/// ```
#[derive(Debug, Default)]
pub struct FdtWriter {
    structs: Vec<u8>,
    strings: Vec<u8>,
    reservations: Vec<(u64, u64)>,
    depth: usize,
}

impl FdtWriter {
    /// Starts an empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry to the memory reservation block.
    pub fn reserve_memory(&mut self, addr: u64, size: u64) {
        self.reservations.push((addr, size));
    }

    /// Opens a node; the first one must be the root, named `""`.
    pub fn begin_node(&mut self, name: &str) {
        self.u32(BEGIN_NODE);
        self.structs.extend_from_slice(name.as_bytes());
        self.structs.push(0);
        self.pad();
        self.depth += 1;
    }

    /// Closes the innermost open node.
    ///
    /// # Panics
    ///
    /// If no node is open.
    pub fn end_node(&mut self) {
        assert!(self.depth > 0, "end_node without begin_node");
        self.u32(END_NODE);
        self.depth -= 1;
    }

    /// Adds a property with a raw value.
    ///
    /// # Panics
    ///
    /// If called outside a node.
    pub fn property(&mut self, name: &str, value: &[u8]) {
        assert!(self.depth > 0, "property outside a node");
        let nameoff = self.string_offset(name);
        self.u32(PROP);
        self.u32(value.len() as u32);
        self.u32(nameoff);
        self.structs.extend_from_slice(value);
        self.pad();
    }

    /// Adds an empty (boolean) property.
    pub fn property_empty(&mut self, name: &str) {
        self.property(name, &[]);
    }

    /// Adds a one-cell property.
    pub fn property_u32(&mut self, name: &str, v: u32) {
        self.property(name, &v.to_be_bytes());
    }

    /// Adds a two-cell property.
    pub fn property_u64(&mut self, name: &str, v: u64) {
        self.property(name, &v.to_be_bytes());
    }

    /// Adds a multi-cell property (`reg`, `interrupts`, `ranges`, ...).
    pub fn property_cells(&mut self, name: &str, cells: &[u32]) {
        let bytes: Vec<u8> = cells.iter().flat_map(|c| c.to_be_bytes()).collect();
        self.property(name, &bytes);
    }

    /// Adds a string property.
    pub fn property_string(&mut self, name: &str, s: &str) {
        self.property_string_list(name, &[s]);
    }

    /// Adds a string-list property (`compatible`).
    pub fn property_string_list(&mut self, name: &str, list: &[&str]) {
        let mut bytes = Vec::with_capacity(list.iter().map(|s| s.len() + 1).sum());
        for s in list {
            bytes.extend_from_slice(s.as_bytes());
            bytes.push(0);
        }
        self.property(name, &bytes);
    }

    /// Finishes the tree and returns the blob.
    ///
    /// # Panics
    ///
    /// If any node is still open.
    pub fn finish(mut self, boot_cpu: u32) -> Vec<u8> {
        assert_eq!(self.depth, 0, "unclosed nodes");
        self.u32(END);
        let header_len = 40;
        let rsv_off = header_len;
        let rsv_len = (self.reservations.len() + 1) * 16;
        let struct_off = rsv_off + rsv_len;
        let strings_off = struct_off + self.structs.len();
        let total = strings_off + self.strings.len();

        let mut out = Vec::with_capacity(total);
        for v in [
            MAGIC,
            total as u32,
            struct_off as u32,
            strings_off as u32,
            rsv_off as u32,
            17,
            16,
            boot_cpu,
            self.strings.len() as u32,
            self.structs.len() as u32,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        for (a, s) in self.reservations.iter().chain(&[(0, 0)]) {
            out.extend_from_slice(&a.to_be_bytes());
            out.extend_from_slice(&s.to_be_bytes());
        }
        out.extend_from_slice(&self.structs);
        out.extend_from_slice(&self.strings);
        out
    }

    fn u32(&mut self, v: u32) {
        self.structs.extend_from_slice(&v.to_be_bytes());
    }

    fn pad(&mut self) {
        while self.structs.len() % 4 != 0 {
            self.structs.push(0);
        }
    }

    fn string_offset(&mut self, name: &str) -> u32 {
        // Reuse an existing copy (a suffix match also works, as in dtc).
        let needle: Vec<u8> = name.bytes().chain([0]).collect();
        if let Some(pos) = self.strings.windows(needle.len()).position(|w| w == needle.as_slice())
            && (pos == 0 || pos.checked_sub(1).and_then(|p| self.strings.get(p)) == Some(&0) || name.is_empty())
        {
            return pos as u32;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(&needle);
        off
    }
}
