//! A text console on a linear framebuffer.
//!
//! [`FbConsole`] draws characters from a built-in 8x8 bitmap font onto a
//! [`Framebuffer`], so a kernel with only a GOP, VBE or virtio-gpu screen can
//! use `println!`. It handles a cursor, wrapping, scrolling and the usual
//! control characters, and the common ANSI escape sequences (see
//! [`FbText::write_str`]). It works on any pixel format the [`Framebuffer`]
//! does, including 32-bit RGB and BGR.
//!
//! The font covers printable ASCII (0x20 to 0x7e). It is a 5x7 design drawn
//! for this crate (no third-party font data), placed in an 8x8 cell. Any
//! other character is drawn as `?`. An integer scale factor enlarges the cell
//! for high-resolution screens.
//!
//! For a display whose memory must be told to update (virtio-gpu), call
//! [`Display::flush`](crate::display::Display::flush) after writing; the
//! console itself only writes the framebuffer.

use core::fmt;

use osmium_sync::{IrqDisabled, IrqSpinLock, SpinLockGuard};

use crate::console::Console;
use crate::display::{DisplayError, Framebuffer, Rect, Rgb};

/// Width and height of a character cell at scale 1, in pixels.
pub const CELL: u32 = 8;

/// 5x7 glyphs for 0x20..=0x7e, one byte per row with the leftmost pixel in
/// bit 4. Original work for this crate, released under the crate's licence.
#[rustfmt::skip]
const FONT: [[u8; 7]; 95] = [
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00], [0x04,0x04,0x04,0x04,0x04,0x00,0x04], [0x0A,0x0A,0x0A,0x00,0x00,0x00,0x00],
    [0x0A,0x0A,0x1F,0x0A,0x1F,0x0A,0x0A], [0x04,0x0F,0x14,0x0E,0x05,0x1E,0x04], [0x18,0x19,0x02,0x04,0x08,0x13,0x03],
    [0x0C,0x12,0x14,0x08,0x15,0x12,0x0D], [0x0C,0x04,0x08,0x00,0x00,0x00,0x00], [0x02,0x04,0x08,0x08,0x08,0x04,0x02],
    [0x08,0x04,0x02,0x02,0x02,0x04,0x08], [0x00,0x04,0x15,0x0E,0x15,0x04,0x00], [0x00,0x04,0x04,0x1F,0x04,0x04,0x00],
    [0x00,0x00,0x00,0x00,0x0C,0x04,0x08], [0x00,0x00,0x00,0x1F,0x00,0x00,0x00], [0x00,0x00,0x00,0x00,0x00,0x0C,0x0C],
    [0x00,0x01,0x02,0x04,0x08,0x10,0x00], [0x0E,0x11,0x13,0x15,0x19,0x11,0x0E], [0x04,0x0C,0x04,0x04,0x04,0x04,0x0E],
    [0x0E,0x11,0x01,0x02,0x04,0x08,0x1F], [0x1F,0x02,0x04,0x02,0x01,0x11,0x0E], [0x02,0x06,0x0A,0x12,0x1F,0x02,0x02],
    [0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E], [0x06,0x08,0x10,0x1E,0x11,0x11,0x0E], [0x1F,0x01,0x02,0x04,0x08,0x08,0x08],
    [0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E], [0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C], [0x00,0x0C,0x0C,0x00,0x0C,0x0C,0x00],
    [0x00,0x0C,0x0C,0x00,0x0C,0x04,0x08], [0x02,0x04,0x08,0x10,0x08,0x04,0x02], [0x00,0x00,0x1F,0x00,0x1F,0x00,0x00],
    [0x08,0x04,0x02,0x01,0x02,0x04,0x08], [0x0E,0x11,0x01,0x02,0x04,0x00,0x04], [0x0E,0x11,0x17,0x15,0x17,0x10,0x0E],
    [0x0E,0x11,0x11,0x1F,0x11,0x11,0x11], [0x1E,0x11,0x11,0x1E,0x11,0x11,0x1E], [0x0E,0x11,0x10,0x10,0x10,0x11,0x0E],
    [0x1C,0x12,0x11,0x11,0x11,0x12,0x1C], [0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F], [0x1F,0x10,0x10,0x1E,0x10,0x10,0x10],
    [0x0E,0x11,0x10,0x17,0x11,0x11,0x0F], [0x11,0x11,0x11,0x1F,0x11,0x11,0x11], [0x0E,0x04,0x04,0x04,0x04,0x04,0x0E],
    [0x07,0x02,0x02,0x02,0x02,0x12,0x0C], [0x11,0x12,0x14,0x18,0x14,0x12,0x11], [0x10,0x10,0x10,0x10,0x10,0x10,0x1F],
    [0x11,0x1B,0x15,0x15,0x11,0x11,0x11], [0x11,0x11,0x19,0x15,0x13,0x11,0x11], [0x0E,0x11,0x11,0x11,0x11,0x11,0x0E],
    [0x1E,0x11,0x11,0x1E,0x10,0x10,0x10], [0x0E,0x11,0x11,0x11,0x15,0x12,0x0D], [0x1E,0x11,0x11,0x1E,0x14,0x12,0x11],
    [0x0F,0x10,0x10,0x0E,0x01,0x01,0x1E], [0x1F,0x04,0x04,0x04,0x04,0x04,0x04], [0x11,0x11,0x11,0x11,0x11,0x11,0x0E],
    [0x11,0x11,0x11,0x11,0x11,0x0A,0x04], [0x11,0x11,0x11,0x15,0x15,0x15,0x0A], [0x11,0x11,0x0A,0x04,0x0A,0x11,0x11],
    [0x11,0x11,0x11,0x0A,0x04,0x04,0x04], [0x1F,0x01,0x02,0x04,0x08,0x10,0x1F], [0x0E,0x08,0x08,0x08,0x08,0x08,0x0E],
    [0x00,0x10,0x08,0x04,0x02,0x01,0x00], [0x0E,0x02,0x02,0x02,0x02,0x02,0x0E], [0x04,0x0A,0x11,0x00,0x00,0x00,0x00],
    [0x00,0x00,0x00,0x00,0x00,0x00,0x1F], [0x08,0x04,0x02,0x00,0x00,0x00,0x00], [0x00,0x00,0x0E,0x01,0x0F,0x11,0x0F],
    [0x10,0x10,0x16,0x19,0x11,0x11,0x1E], [0x00,0x00,0x0E,0x10,0x10,0x11,0x0E], [0x01,0x01,0x0D,0x13,0x11,0x11,0x0F],
    [0x00,0x00,0x0E,0x11,0x1F,0x10,0x0E], [0x06,0x09,0x08,0x1C,0x08,0x08,0x08], [0x00,0x0F,0x11,0x11,0x0F,0x01,0x0E],
    [0x10,0x10,0x16,0x19,0x11,0x11,0x11], [0x04,0x00,0x0C,0x04,0x04,0x04,0x0E], [0x02,0x00,0x06,0x02,0x02,0x12,0x0C],
    [0x10,0x10,0x12,0x14,0x18,0x14,0x12], [0x0C,0x04,0x04,0x04,0x04,0x04,0x0E], [0x00,0x00,0x1A,0x15,0x15,0x11,0x11],
    [0x00,0x00,0x16,0x19,0x11,0x11,0x11], [0x00,0x00,0x0E,0x11,0x11,0x11,0x0E], [0x00,0x00,0x1E,0x11,0x1E,0x10,0x10],
    [0x00,0x00,0x0D,0x13,0x0F,0x01,0x01], [0x00,0x00,0x16,0x19,0x10,0x10,0x10], [0x00,0x00,0x0E,0x10,0x0E,0x01,0x1E],
    [0x08,0x08,0x1C,0x08,0x08,0x09,0x06], [0x00,0x00,0x11,0x11,0x11,0x13,0x0D], [0x00,0x00,0x11,0x11,0x11,0x0A,0x04],
    [0x00,0x00,0x11,0x11,0x15,0x15,0x0A], [0x00,0x00,0x11,0x0A,0x04,0x0A,0x11], [0x00,0x00,0x11,0x11,0x0F,0x01,0x0E],
    [0x00,0x00,0x1F,0x02,0x04,0x08,0x1F], [0x02,0x04,0x04,0x08,0x04,0x04,0x02], [0x04,0x04,0x04,0x04,0x04,0x04,0x04],
    [0x08,0x04,0x04,0x02,0x04,0x04,0x08], [0x00,0x00,0x08,0x15,0x02,0x00,0x00],
];

/// The 8x8 bitmap of `c` (one byte per row, leftmost pixel in bit 7), with
/// `?` for anything outside printable ASCII.
pub fn glyph(c: char) -> [u8; 8] {
    let c = if (' '..='~').contains(&c) { c } else { '?' };
    let rows = FONT.get(c as usize - 0x20).copied().unwrap_or([0; 7]);
    let mut out = [0u8; 8];
    for (o, r) in out.iter_mut().zip(rows) {
        *o = r << 2; // one blank column on the left, two on the right
    }
    out
}

/// The 16 ANSI colours: black, red, green, yellow (brown), blue, magenta,
/// cyan and white, then their bright forms (the VGA palette).
pub const PALETTE: [Rgb; 16] = [
    Rgb::new(0x00, 0x00, 0x00),
    Rgb::new(0xaa, 0x00, 0x00),
    Rgb::new(0x00, 0xaa, 0x00),
    Rgb::new(0xaa, 0x55, 0x00),
    Rgb::new(0x00, 0x00, 0xaa),
    Rgb::new(0xaa, 0x00, 0xaa),
    Rgb::new(0x00, 0xaa, 0xaa),
    Rgb::new(0xaa, 0xaa, 0xaa),
    Rgb::new(0x55, 0x55, 0x55),
    Rgb::new(0xff, 0x55, 0x55),
    Rgb::new(0x55, 0xff, 0x55),
    Rgb::new(0xff, 0xff, 0x55),
    Rgb::new(0x55, 0x55, 0xff),
    Rgb::new(0xff, 0x55, 0xff),
    Rgb::new(0x55, 0xff, 0xff),
    Rgb::new(0xff, 0xff, 0xff),
];

const MAX_PARAMS: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Esc {
    Ground,
    /// After ESC.
    Escape,
    /// Inside `ESC [`, collecting parameters.
    Csi,
}

/// The console's state and drawing, without a lock. [`FbConsole`] wraps it
/// for use as a global [`Console`]; use this directly when you own the
/// console exclusively.
pub struct FbText {
    fb: Framebuffer,
    scale: u32,
    cols: u32,
    rows: u32,
    col: u32,
    row: u32,
    /// Palette indices of the current colours (before `reverse`).
    fg: u8,
    bg: u8,
    bold: bool,
    reverse: bool,
    cursor_enabled: bool,
    cursor_drawn: bool,
    esc: Esc,
    params: [u16; MAX_PARAMS],
    nparams: usize,
    saved: (u32, u32),
}

impl FbText {
    /// A console filling `fb` with cells of `8 * scale` pixels square, white
    /// on black, cleared, with the cursor at the top left.
    ///
    /// Fails with [`DisplayError::BadGeometry`] if `scale` is zero or not
    /// even one cell fits.
    pub fn new(fb: Framebuffer, scale: u32) -> Result<Self, DisplayError> {
        let cell = CELL.checked_mul(scale).filter(|&c| c > 0).ok_or(DisplayError::BadGeometry)?;
        let info = fb.info();
        let (cols, rows) = (info.width / cell, info.height / cell);
        if cols == 0 || rows == 0 {
            return Err(DisplayError::BadGeometry);
        }
        let mut t = Self {
            fb,
            scale,
            cols,
            rows,
            col: 0,
            row: 0,
            fg: 7,
            bg: 0,
            bold: false,
            reverse: false,
            cursor_enabled: true,
            cursor_drawn: false,
            esc: Esc::Ground,
            params: [0; MAX_PARAMS],
            nparams: 0,
            saved: (0, 0),
        };
        t.clear_screen();
        t.draw_cursor();
        Ok(t)
    }

    /// The framebuffer being drawn on.
    pub fn framebuffer(&self) -> &Framebuffer {
        &self.fb
    }

    /// Character columns and rows.
    pub fn size(&self) -> (u32, u32) {
        (self.cols, self.rows)
    }

    /// The cursor position as `(column, row)`, zero-based. The column equals
    /// the number of columns after a character is written in the last one.
    pub fn cursor(&self) -> (u32, u32) {
        (self.col, self.row)
    }

    /// Shows or hides the cursor (an inverted underline).
    pub fn set_cursor_visible(&mut self, visible: bool) {
        self.erase_cursor();
        self.cursor_enabled = visible;
        self.draw_cursor();
    }

    /// Writes `s`, interpreting:
    ///
    /// - `\n` moves to the start of the next line (scrolling at the bottom),
    ///   `\r` to the start of the line, `\x08` back one column (without
    ///   erasing), `\t` to the next multiple of 8 columns;
    /// - `ESC [ n A/B/C/D` cursor up/down/forward/back, `n G` to column,
    ///   `r ; c H` or `f` to a position (one-based), `s`/`u` save and
    ///   restore the cursor;
    /// - `ESC [ n J` and `K` erase in the screen and line (0 to the end, 1
    ///   from the start, 2 all; `J` with 2 does not move the cursor);
    /// - `ESC [ ... m` colours: `0` reset, `1` bold (bright foreground),
    ///   `7` reverse, `22`, `27`, `30`-`37`, `40`-`47`, `90`-`97`,
    ///   `100`-`107`, `39`, `49`.
    ///
    /// Other sequences are swallowed, and characters other than printable
    /// ASCII are drawn as `?`.
    pub fn write_str(&mut self, s: &str) {
        self.erase_cursor();
        for c in s.chars() {
            self.put(c);
        }
        self.draw_cursor();
    }

    fn colors(&self) -> (Rgb, Rgb) {
        let fg = if self.bold && self.fg < 8 { self.fg + 8 } else { self.fg };
        let (fg, bg) = (self.palette(fg), self.palette(self.bg));
        if self.reverse { (bg, fg) } else { (fg, bg) }
    }

    fn palette(&self, i: u8) -> Rgb {
        PALETTE.get(i as usize).copied().unwrap_or(Rgb::WHITE)
    }

    fn cell_px(&self) -> u32 {
        CELL * self.scale // checked in `new`
    }

    fn put(&mut self, c: char) {
        match self.esc {
            Esc::Ground => self.ground(c),
            Esc::Escape => {
                if c == '[' {
                    self.params = [0; MAX_PARAMS];
                    self.nparams = 0;
                    self.esc = Esc::Csi;
                } else {
                    self.esc = Esc::Ground;
                }
            }
            Esc::Csi => match c {
                '0'..='9' => {
                    self.nparams = self.nparams.max(1);
                    if let Some(p) = self.params.get_mut(self.nparams - 1) {
                        *p = p.saturating_mul(10).saturating_add(c as u16 - '0' as u16);
                    }
                }
                ';' => self.nparams = (self.nparams.max(1) + 1).min(MAX_PARAMS),
                '\x40'..='\x7e' => {
                    self.esc = Esc::Ground;
                    self.csi(c);
                }
                '\x20'..='\x3f' => {} // private markers and intermediates
                _ => self.esc = Esc::Ground,
            },
        }
    }

    fn ground(&mut self, c: char) {
        match c {
            '\x1b' => self.esc = Esc::Escape,
            '\n' => {
                self.col = 0;
                self.line_feed();
            }
            '\r' => self.col = 0,
            '\x08' => self.col = self.col.saturating_sub(1),
            '\t' => {
                let next = (self.col / 8 + 1) * 8;
                self.col = next.min(self.cols - 1);
            }
            c if c.is_control() => {}
            c => {
                if self.col >= self.cols {
                    self.col = 0;
                    self.line_feed();
                }
                self.draw_char(self.col, self.row, c);
                self.col += 1; // may equal `cols`: wraps before the next character
            }
        }
    }

    fn line_feed(&mut self) {
        if self.row + 1 < self.rows {
            self.row += 1;
        } else {
            let (_, bg) = self.colors();
            self.fb.scroll_up(self.cell_px(), bg);
        }
    }

    /// Parameter `i`, or `default` if absent or zero.
    fn param(&self, i: usize, default: u32) -> u32 {
        match self.params.get(i) {
            Some(&p) if i < self.nparams && p != 0 => p as u32,
            _ => default,
        }
    }

    fn csi(&mut self, fin: char) {
        let n = self.param(0, 1);
        // A cursor sitting past the last column (after a full line) counts as the last column.
        let col = self.col.min(self.cols - 1);
        match fin {
            'A' => self.row = self.row.saturating_sub(n),
            'B' => self.row = self.row.saturating_add(n).min(self.rows - 1),
            'C' => self.col = col.saturating_add(n).min(self.cols - 1),
            'D' => self.col = col.saturating_sub(n),
            'G' => self.col = (n - 1).min(self.cols - 1),
            'H' | 'f' => {
                self.row = (n - 1).min(self.rows - 1);
                self.col = (self.param(1, 1) - 1).min(self.cols - 1);
            }
            'J' => match self.param(0, 0) {
                0 => {
                    self.erase_cells(col, self.row, self.cols);
                    for r in self.row + 1..self.rows {
                        self.erase_cells(0, r, self.cols);
                    }
                }
                1 => {
                    for r in 0..self.row {
                        self.erase_cells(0, r, self.cols);
                    }
                    self.erase_cells(0, self.row, col + 1);
                }
                2 => self.clear_screen(),
                _ => {}
            },
            'K' => match self.param(0, 0) {
                0 => self.erase_cells(col, self.row, self.cols),
                1 => self.erase_cells(0, self.row, col + 1),
                2 => self.erase_cells(0, self.row, self.cols),
                _ => {}
            },
            's' => self.saved = (self.col, self.row),
            'u' => (self.col, self.row) = (self.saved.0.min(self.cols - 1), self.saved.1.min(self.rows - 1)),
            'm' => self.sgr(),
            _ => {}
        }
    }

    fn sgr(&mut self) {
        for i in 0..self.nparams.max(1) {
            match self.params.get(i).copied().unwrap_or(0) {
                0 => (self.fg, self.bg, self.bold, self.reverse) = (7, 0, false, false),
                1 => self.bold = true,
                7 => self.reverse = true,
                22 => self.bold = false,
                27 => self.reverse = false,
                p @ 30..=37 => self.fg = (p - 30) as u8,
                39 => self.fg = 7,
                p @ 40..=47 => self.bg = (p - 40) as u8,
                49 => self.bg = 0,
                p @ 90..=97 => self.fg = (p - 90) as u8 + 8,
                p @ 100..=107 => self.bg = (p - 100) as u8 + 8,
                _ => {}
            }
        }
    }

    fn cell_rect(&self, col: u32, row: u32) -> Rect {
        let cell = self.cell_px();
        // `col` and `row` are within the grid, which fits in the framebuffer's 32-bit dimensions.
        Rect::new(col * cell, row * cell, cell, cell)
    }

    fn draw_char(&mut self, col: u32, row: u32, c: char) {
        let (fg, bg) = self.colors();
        let rows = glyph(c);
        let rect = self.cell_rect(col, row);
        let scale = self.scale;
        self.fb.draw(rect, |x, y| {
            let (gx, gy) = ((x - rect.x) / scale, (y - rect.y) / scale);
            let set = rows.get(gy as usize).is_some_and(|b| b & (0x80 >> gx) != 0);
            if set { fg } else { bg }
        });
    }

    /// Fills cells `from..to` of `row` with the background.
    fn erase_cells(&mut self, from: u32, row: u32, to: u32) {
        if from >= to {
            return;
        }
        let (_, bg) = self.colors();
        let (a, b) = (self.cell_rect(from, row), self.cell_rect(to - 1, row));
        self.fb.fill_rect(Rect::new(a.x, a.y, b.x + b.width - a.x, a.height), bg);
    }

    fn clear_screen(&mut self) {
        let (_, bg) = self.colors();
        self.fb.clear(bg);
    }

    fn toggle_cursor(&mut self) {
        let r = self.cell_rect(self.col.min(self.cols - 1), self.row);
        for y in r.y + r.height - self.scale..r.y + r.height {
            for x in r.x..r.x + r.width {
                if let Some(p) = self.fb.pixel(x, y) {
                    self.fb.set_pixel(x, y, Rgb::new(!p.r, !p.g, !p.b));
                }
            }
        }
        self.cursor_drawn = !self.cursor_drawn;
    }

    fn erase_cursor(&mut self) {
        if self.cursor_drawn {
            self.toggle_cursor();
        }
    }

    fn draw_cursor(&mut self) {
        if self.cursor_enabled && !self.cursor_drawn {
            self.toggle_cursor();
        }
    }
}

impl fmt::Write for FbText {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        FbText::write_str(self, s);
        Ok(())
    }
}

/// A [`Console`] drawing on a framebuffer: [`FbText`] behind an IRQ-safe
/// lock.
pub struct FbConsole {
    text: IrqSpinLock<FbText>,
}

impl FbConsole {
    /// See [`FbText::new`].
    pub fn new(fb: Framebuffer, scale: u32) -> Result<Self, DisplayError> {
        Ok(Self { text: IrqSpinLock::new(FbText::new(fb, scale)?) })
    }

    /// Locks the console for direct use.
    pub fn text(&self) -> SpinLockGuard<'_, FbText, IrqDisabled> {
        self.text.lock()
    }
}

impl Console for FbConsole {
    fn write_str(&self, s: &str) {
        self.text.lock().write_str(s);
    }

    fn write_fmt(&self, args: fmt::Arguments<'_>) {
        let _ = fmt::Write::write_fmt(&mut *self.text.lock(), args);
    }
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use crate::display::{FramebufferInfo, PixelFormat};
    use crate::mmio::IoMem;
    use std::vec;
    use std::vec::Vec;

    fn console(mem: &mut Vec<u32>, w: u32, h: u32, format: PixelFormat, scale: u32) -> FbText {
        // SAFETY: the window covers a local buffer that outlives the test.
        let io = unsafe { IoMem::new(mem.as_mut_ptr().cast(), mem.len() * 4) };
        FbText::new(Framebuffer::new(io, FramebufferInfo::packed(w, h, format)).unwrap(), scale).unwrap()
    }

    fn lit(t: &FbText, col: u32, row: u32) -> usize {
        let r = t.cell_rect(col, row);
        let mut n = 0;
        for y in r.y..r.y + r.height {
            for x in r.x..r.x + r.width {
                n += (t.fb.pixel(x, y) != Some(Rgb::BLACK)) as usize;
            }
        }
        n
    }

    fn ink(c: char) -> usize {
        glyph(c).iter().map(|b| b.count_ones() as usize).sum()
    }

    #[test]
    fn draws_glyph_pixels() {
        let mut mem = vec![0u32; 32 * 16];
        let mut t = console(&mut mem, 32, 16, PixelFormat::XRGB8888, 1);
        assert_eq!(t.size(), (4, 2));
        t.set_cursor_visible(false);
        t.write_str("I");
        // 'I' is 0x0E,0x04,..,0x0E: columns 1..=5 of the cell, with the top bar in columns 2..=4.
        let on = |t: &FbText, x, y| t.fb.pixel(x, y) == Some(Rgb::new(0xaa, 0xaa, 0xaa));
        assert!(on(&t, 2, 0) && on(&t, 3, 0) && on(&t, 4, 0) && !on(&t, 1, 0) && !on(&t, 5, 0));
        assert!(on(&t, 3, 3) && !on(&t, 2, 3));
        assert!(!on(&t, 3, 7), "last row is blank");
        assert_eq!(t.cursor(), (1, 0));
        drop(t);
        assert_eq!(mem[3], 0x00aa_aaaa, "XRGB8888 in memory");
    }

    #[test]
    fn every_printable_glyph_has_ink() {
        for c in '!'..='~' {
            assert!(ink(c) >= 3, "{c}");
        }
        assert_eq!(ink(' '), 0);
        assert_eq!(glyph('\u{e9}'), glyph('?'));
    }

    #[test]
    fn bgr_format_and_colours() {
        let mut mem = vec![0u32; 16 * 8];
        let mut t = console(&mut mem, 16, 8, PixelFormat::XBGR8888, 1);
        t.write_str("\x1b[31;44m-\x1b[0m");
        // '-' is a horizontal bar on row 3, red on blue.
        assert_eq!(t.fb.pixel(3, 3), Some(Rgb::new(0xaa, 0, 0)));
        assert_eq!(t.fb.pixel(0, 0), Some(Rgb::new(0, 0, 0xaa)));
        drop(t);
        assert_eq!(mem[3 * 16 + 3], 0x0000_00aa, "red in the low byte for BGR");
    }

    #[test]
    fn newline_backspace_tab_wrap() {
        let mut mem = vec![0u32; 80 * 24];
        let mut t = console(&mut mem, 80, 24, PixelFormat::XRGB8888, 1);
        assert_eq!(t.size(), (10, 3));
        t.write_str("ab\n");
        assert_eq!(t.cursor(), (0, 1));
        t.write_str("abc\x08");
        assert_eq!(t.cursor(), (2, 1));
        t.write_str("\r\t");
        assert_eq!(t.cursor(), (8, 1));
        t.write_str("\tx"); // clamps to the last column
        assert_eq!(t.cursor(), (10, 1));
        t.write_str("y"); // wraps
        assert_eq!(t.cursor(), (1, 2));
        t.write_str("\u{e9}"); // non-ASCII draws '?'
        assert_eq!(lit(&t, 1, 2), ink('?'));
    }

    #[test]
    fn scrolls_at_the_bottom() {
        let mut mem = vec![0u32; 16 * 16];
        let mut t = console(&mut mem, 16, 16, PixelFormat::XRGB8888, 1);
        t.set_cursor_visible(false);
        t.write_str("A\nB\nC");
        // Two rows: A scrolled off, B on row 0, C on row 1.
        assert_eq!(t.cursor(), (1, 1));
        assert_eq!(lit(&t, 0, 0), ink('B'));
        assert_eq!(lit(&t, 0, 1), ink('C'));
    }

    #[test]
    fn ansi_cursor_and_erase() {
        let mut mem = vec![0u32; 80 * 40];
        let mut t = console(&mut mem, 80, 40, PixelFormat::XRGB8888, 1);
        t.set_cursor_visible(false);
        t.write_str("\x1b[3;5Hx");
        assert_eq!(t.cursor(), (5, 2));
        assert!(lit(&t, 4, 2) > 0);
        t.write_str("\x1b[2A\x1b[3D");
        assert_eq!(t.cursor(), (2, 0));
        t.write_str("\x1b[99B\x1b[99C");
        assert_eq!(t.cursor(), (9, 4));
        t.write_str("\x1b[3;1H\x1b[2K");
        assert_eq!(lit(&t, 4, 2), 0, "line erased");
        t.write_str("\x1b[1;1Hq\x1b[5;1Hq\x1b[3;1H\x1b[J");
        assert!(lit(&t, 0, 0) > 0, "above is kept");
        assert_eq!(lit(&t, 0, 4), 0, "below is erased");
        t.write_str("\x1b[2J");
        assert_eq!(lit(&t, 0, 0), 0);
        t.write_str("\x1b[?25l\x1b[9999;9999;1;2;3;4;5;6;7;8;9Hz"); // junk is tolerated
        assert_eq!(t.cursor(), (10, 4));
    }

    #[test]
    fn cursor_is_drawn_and_erased() {
        let mut mem = vec![0u32; 16 * 8];
        let mut t = console(&mut mem, 16, 8, PixelFormat::XRGB8888, 1);
        assert_eq!(t.fb.pixel(0, 7), Some(Rgb::WHITE), "inverted black underline");
        t.write_str("a");
        assert_eq!(t.fb.pixel(0, 7), Some(Rgb::BLACK), "erased where it was");
        assert_eq!(t.fb.pixel(8, 7), Some(Rgb::WHITE));
        t.set_cursor_visible(false);
        assert_eq!(t.fb.pixel(8, 7), Some(Rgb::BLACK));
    }

    #[test]
    fn scaled_cells_and_bad_geometry() {
        let mut mem = vec![0u32; 32 * 32];
        let mut t = console(&mut mem, 32, 32, PixelFormat::XRGB8888, 2);
        assert_eq!(t.size(), (2, 2));
        t.set_cursor_visible(false);
        t.write_str("-"); // bar at glyph row 3 -> pixel rows 6 and 7
        assert_ne!(t.fb.pixel(6, 6), Some(Rgb::BLACK));
        assert_ne!(t.fb.pixel(7, 7), Some(Rgb::BLACK));
        assert_eq!(t.fb.pixel(6, 8), Some(Rgb::BLACK));
        let mut small = vec![0u32; 4 * 4];
        // SAFETY: the window covers a local buffer that outlives the test.
        let io = unsafe { IoMem::new(small.as_mut_ptr().cast(), 64) };
        let f = Framebuffer::new(io, FramebufferInfo::packed(4, 4, PixelFormat::XRGB8888)).unwrap();
        assert!(FbText::new(f, 1).is_err());
    }

    #[test]
    fn console_trait_and_reverse() {
        let mut mem = vec![0u32; 16 * 8];
        // SAFETY: the window covers a local buffer that outlives the test.
        let io = unsafe { IoMem::new(mem.as_mut_ptr().cast(), 16 * 8 * 4) };
        let fb = Framebuffer::new(io, FramebufferInfo::packed(16, 8, PixelFormat::XRGB8888)).unwrap();
        let con = FbConsole::new(fb, 1).unwrap();
        con.text().set_cursor_visible(false);
        Console::write_fmt(&con, format_args!("\x1b[7m{}\x1b[27m", 'A'));
        assert_eq!(con.text().framebuffer().pixel(0, 0), Some(Rgb::new(0xaa, 0xaa, 0xaa)), "reverse video");
    }
}
