//! EDID (VESA Enhanced EDID 1.4) base-block parser.
//!
//! An EDID comes from the monitor, or from a virtual one such as
//! virtio-gpu's `GET_EDID`, so it is untrusted: [`Edid::parse`] checks the
//! header and checksum, and every read is bounds-checked. It exposes what a
//! display driver needs to pick a mode: the preferred detailed timing, the
//! physical size and the identification strings. Extension blocks (CEA,
//! DisplayID) are counted but not parsed.

/// Bytes of one EDID block.
pub const BLOCK_LEN: usize = 128;

/// The fixed first eight bytes of an EDID.
const HEADER: [u8; 8] = [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0];

/// Offset of the first of four 18-byte descriptors.
const DESCRIPTORS: usize = 54;
const DESCRIPTOR_LEN: usize = 18;

/// Why an EDID was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdidError {
    /// Shorter than one 128-byte block.
    TooShort,
    /// The fixed header is wrong.
    BadHeader,
    /// The block's bytes do not sum to zero.
    BadChecksum,
}

/// A detailed timing descriptor: one video mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetailedTiming {
    /// Pixel clock in kHz.
    pub pixel_clock_khz: u32,
    /// Visible width in pixels.
    pub width: u32,
    /// Visible height in lines.
    pub height: u32,
    /// Horizontal blanking in pixels.
    pub h_blank: u32,
    /// Vertical blanking in lines.
    pub v_blank: u32,
    /// Image width in millimetres (0 if unknown).
    pub width_mm: u32,
    /// Image height in millimetres (0 if unknown).
    pub height_mm: u32,
    /// True for an interlaced mode.
    pub interlaced: bool,
}

impl DetailedTiming {
    /// The refresh rate in millihertz (60 Hz is 60000), or 0 if the timing
    /// has no total size. An interlaced mode counts fields, as written.
    pub fn refresh_mhz(&self) -> u32 {
        let total =
            u64::from(self.width.saturating_add(self.h_blank)) * u64::from(self.height.saturating_add(self.v_blank));
        let clock = u64::from(self.pixel_clock_khz) * 1_000_000;
        u32::try_from(clock.checked_div(total).unwrap_or(0)).unwrap_or(u32::MAX)
    }

    fn parse(d: &[u8]) -> Option<Self> {
        let b = |i: usize| d.get(i).copied().map(u32::from);
        let clock = b(0)? | b(1)? << 8;
        if clock == 0 {
            return None;
        }
        Some(Self {
            pixel_clock_khz: clock * 10,
            width: b(2)? | (b(4)? >> 4) << 8,
            h_blank: b(3)? | (b(4)? & 15) << 8,
            height: b(5)? | (b(7)? >> 4) << 8,
            v_blank: b(6)? | (b(7)? & 15) << 8,
            width_mm: b(12)? | (b(14)? >> 4) << 8,
            height_mm: b(13)? | (b(14)? & 15) << 8,
            interlaced: b(17)? & 0x80 != 0,
        })
    }
}

/// A parsed EDID base block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edid {
    manufacturer: [u8; 3],
    /// The manufacturer's product code.
    pub product: u16,
    /// The serial number (0 if unset).
    pub serial: u32,
    /// Week of manufacture (0 if unspecified).
    pub week: u8,
    /// Year of manufacture, e.g. 2024.
    pub year: u16,
    /// EDID version and revision, e.g. `(1, 4)`.
    pub version: (u8, u8),
    /// Image size in centimetres, if the base block gives one.
    pub size_cm: Option<(u8, u8)>,
    /// Number of extension blocks that follow the base block.
    pub extensions: u8,
    timings: [Option<DetailedTiming>; 4],
    name: [u8; 13],
    name_len: usize,
}

impl Edid {
    /// Parses the first block of `data`, checking the header and checksum.
    pub fn parse(data: &[u8]) -> Result<Self, EdidError> {
        let block = data.get(..BLOCK_LEN).ok_or(EdidError::TooShort)?;
        if block.get(..8) != Some(&HEADER[..]) {
            return Err(EdidError::BadHeader);
        }
        if block.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
            return Err(EdidError::BadChecksum);
        }
        let b = |i: usize| block.get(i).copied().unwrap_or(0);
        // Three 5-bit letters, 1 = 'A'.
        let m = u16::from_be_bytes([b(8), b(9)]);
        let letter = |shift: u32| b'@'.wrapping_add(((m >> shift) & 31) as u8);
        let mut edid = Self {
            manufacturer: [letter(10), letter(5), letter(0)],
            product: u16::from_le_bytes([b(10), b(11)]),
            serial: u32::from_le_bytes([b(12), b(13), b(14), b(15)]),
            week: b(16),
            year: 1990 + u16::from(b(17)),
            version: (b(18), b(19)),
            size_cm: (b(21) != 0 && b(22) != 0).then_some((b(21), b(22))),
            extensions: b(126),
            timings: [None; 4],
            name: [0; 13],
            name_len: 0,
        };
        for i in 0..4 {
            let at = DESCRIPTORS + i * DESCRIPTOR_LEN;
            let Some(d) = block.get(at..at + DESCRIPTOR_LEN) else { continue };
            if let Some(t) = DetailedTiming::parse(d) {
                if let Some(slot) = edid.timings.get_mut(i) {
                    *slot = Some(t);
                }
            } else if d.get(..3) == Some(&[0, 0, 0][..]) && d.get(3) == Some(&0xfc) {
                // Monitor name: up to 13 characters, ended by a newline.
                let text = d.get(5..).unwrap_or(&[]);
                let len = text.iter().position(|&c| c == b'\n').unwrap_or(text.len()).min(13);
                for (dst, &c) in edid.name.iter_mut().zip(text.iter().take(len)) {
                    *dst = if (0x20..0x7f).contains(&c) { c } else { b'?' };
                }
                edid.name_len = len;
            }
        }
        Ok(edid)
    }

    /// The three-letter manufacturer ID (PnP vendor), e.g. `"RHT"`.
    pub fn manufacturer(&self) -> &str {
        core::str::from_utf8(&self.manufacturer).unwrap_or("???")
    }

    /// The monitor name from its descriptor, if it has one.
    pub fn name(&self) -> Option<&str> {
        let text = self.name.get(..self.name_len)?;
        (!text.is_empty()).then(|| core::str::from_utf8(text).unwrap_or(""))
    }

    /// The preferred mode: the first descriptor, if it is a detailed timing
    /// (EDID 1.4 requires it to be).
    pub fn preferred_mode(&self) -> Option<&DetailedTiming> {
        self.timings.first()?.as_ref()
    }

    /// The preferred mode's size in pixels as `(width, height)`.
    pub fn preferred_size(&self) -> Option<(u32, u32)> {
        self.preferred_mode().map(|t| (t.width, t.height))
    }

    /// The physical image size in millimetres: the preferred timing's if it
    /// gives one, else the base block's centimetres.
    pub fn size_mm(&self) -> Option<(u32, u32)> {
        match self.preferred_mode() {
            Some(t) if t.width_mm != 0 && t.height_mm != 0 => Some((t.width_mm, t.height_mm)),
            _ => self.size_cm.map(|(w, h)| (u32::from(w) * 10, u32::from(h) * 10)),
        }
    }

    /// The detailed timings present, in descriptor order.
    pub fn detailed_timings(&self) -> impl Iterator<Item = &DetailedTiming> {
        self.timings.iter().flatten()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A valid 128-byte EDID: manufacturer "RHT", 1920x1080 at 60 Hz
    /// (148.5 MHz, 2200x1125 total), 527x296 mm, named "Test".
    pub fn sample() -> [u8; BLOCK_LEN] {
        let mut e = [0u8; BLOCK_LEN];
        e[..8].copy_from_slice(&HEADER);
        // R=18, H=8, T=20.
        let m: u16 = 18 << 10 | 8 << 5 | 20;
        e[8..10].copy_from_slice(&m.to_be_bytes());
        e[10..12].copy_from_slice(&0x1234u16.to_le_bytes());
        e[12..16].copy_from_slice(&7u32.to_le_bytes());
        e[16] = 12;
        e[17] = 34;
        e[18] = 1;
        e[19] = 4;
        e[21] = 53;
        e[22] = 30;
        let d = &mut e[54..72];
        d[..2].copy_from_slice(&14850u16.to_le_bytes());
        d[2] = (1920 & 0xff) as u8;
        d[3] = (280 & 0xff) as u8;
        d[4] = ((1920 >> 8) << 4 | (280 >> 8)) as u8;
        d[5] = (1080 & 0xff) as u8;
        d[6] = 45;
        d[7] = ((1080 >> 8) << 4) as u8;
        d[12] = (527 & 0xff) as u8;
        d[13] = (296 & 0xff) as u8;
        d[14] = ((527 >> 8) << 4 | (296 >> 8)) as u8;
        e[75] = 0xfc;
        e[77..82].copy_from_slice(b"Test\n");
        e[82..90].fill(b' ');
        fix(&mut e);
        e
    }

    pub fn fix(e: &mut [u8; BLOCK_LEN]) {
        e[127] = 0;
        e[127] = 0u8.wrapping_sub(e[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b)));
    }

    #[test]
    fn parses_the_sample() {
        let e = Edid::parse(&sample()).unwrap();
        assert_eq!(e.manufacturer(), "RHT");
        assert_eq!((e.product, e.serial, e.week, e.year, e.version), (0x1234, 7, 12, 2024, (1, 4)));
        assert_eq!(e.preferred_size(), Some((1920, 1080)));
        let t = e.preferred_mode().unwrap();
        assert_eq!((t.h_blank, t.v_blank, t.pixel_clock_khz), (280, 45, 148_500));
        assert_eq!(t.refresh_mhz(), 60_000);
        assert!(!t.interlaced);
        assert_eq!(e.size_mm(), Some((527, 296)));
        assert_eq!(e.size_cm, Some((53, 30)));
        assert_eq!(e.name(), Some("Test"));
        assert_eq!(e.detailed_timings().count(), 1);
        assert_eq!(e.extensions, 0);
    }

    #[test]
    fn rejects_bad_blocks() {
        let good = sample();
        assert_eq!(Edid::parse(&good[..127]), Err(EdidError::TooShort));
        let mut bad = good;
        bad[3] = 0;
        assert_eq!(Edid::parse(&bad), Err(EdidError::BadHeader));
        let mut bad = good;
        bad[30] ^= 1;
        assert_eq!(Edid::parse(&bad), Err(EdidError::BadChecksum));
    }

    #[test]
    fn missing_pieces_are_none() {
        let mut e = sample();
        e[54..72].fill(0);
        e[75] = 0;
        e[21] = 0;
        fix(&mut e);
        let e = Edid::parse(&e).unwrap();
        assert_eq!((e.preferred_size(), e.size_mm(), e.name()), (None, None, None));
    }

    #[test]
    fn hostile_timings_do_not_overflow() {
        let mut e = sample();
        e[54..72].fill(0xff);
        e[77..90].fill(0xff);
        fix(&mut e);
        let e = Edid::parse(&e).unwrap();
        let t = e.preferred_mode().unwrap();
        assert!(t.refresh_mhz() > 0);
        let mut zero = *t;
        zero.width = 0;
        zero.h_blank = 0;
        assert_eq!(zero.refresh_mhz(), 0);
    }
}
