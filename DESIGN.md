# Osmium Design

Visual identity for **osmium**, a Rust library of operating-system code. This file is the source of truth for the logo, color, type and usage. The rendered reference is the published "Osmium Mark" page.

## Concept

Osmium is the densest natural element (Z 76, symbol Os, 22.59 g/cm³), which suits low-level code that should feel solid. Os is also the obvious abbreviation for "operating system".

The mark combines three ideas:

| Idea | Source | What it contributes |
| --- | --- | --- |
| Hexagon | Osmium's hexagonal close-packed crystal lattice | The body of the mark |
| Four bonds | OsO₄, the oxide osmium forms (osmium's version of rust) | Three visible atoms on bonds, plus a fourth set back at half opacity |
| Prompt | Terminal `>_` | A chevron and cursor inside the hexagon, where the OS hands control to the user |

The mark is drawn entirely as shapes, with no lettering.

## Logo

### Geometry

The mark is built in a 200×200 box. The unit **x** is the diameter of one oxygen atom (32).

| Element | Value |
| --- | --- |
| Hexagon | Pointy-top, centre (100,104), circumradius 46 (about 2.9x). Points: `100,58 139.8,81 139.8,127 100,150 60.2,127 60.2,81` |
| Bonds | Stroke 7, round caps, from the centre (100,104) to each atom |
| Atoms | Radius 16 at (100,24), (32,150) and (168,150) |
| Fourth atom | Radius 10 at (150,52), 50% opacity, with its bond at 50% opacity |
| Chevron | Polyline `80,90 98,104 80,118`, stroke 8, round caps and joins |
| Cursor | Rect x 104, y 111, 20×8, radius 1.5 |

Draw order, back to front: bonds, fourth atom, hexagon, chevron and cursor, atoms.

### Simplified core

Below 40px, use the core: the hexagon and prompt only, no atoms or bonds. It is drawn in a 100×100 box with a heavier chevron (stroke 11). Points: `50,2 91.6,26 91.6,74 50,98 8.4,74 8.4,26`. Chevron `29,35 48,50 29,65`. Cursor rect x 54, y 59, 22×10.

### Lockups

- **Horizontal** (default): mark on the left, wordmark `osmium` to its right, vertically centred. Viewbox 540×200, wordmark at x 214, baseline y 132, size 84.
- **Stacked**: mark above the wordmark, centred. For square spaces such as avatars, stickers and title slides.
- The wordmark is JetBrains Mono Bold, lowercase, letter-spacing about -0.04em. Convert it to outlines before print or vendor use.

### Variants

| Variant | Use |
| --- | --- |
| Full color | Primary, on Paper or white |
| Reversed | On Ink or other dark grounds |
| One color, dark (Slate) | Single-ink print, embossing, fax-quality contexts |
| One color, light (white) | Knockout on solid color grounds, such as Oxide |

In the one-color versions the hexagon becomes an outline (stroke 8). The bonds are masked out around it, which leaves a small gap, and the prompt, atoms and faded fourth atom are solid. The simplified core uses the same outline treatment.

### Clear space and size

- Clear space: at least 1x on every side, measured from the outermost atoms.
- Minimum size: full mark 40px or 10mm wide. Simplified core 16px or 5mm.

### Don't

- Rotate or skew the mark.
- Recolor atoms individually.
- Add a stroke around the hexagon in the full-color version.
- Replace the chevron with typed text.
- Use the full mark below 40px.

## Color

| Token | Hex | Role |
| --- | --- | --- |
| Slate | `#2B3D51` | Hexagon and wordmark on light |
| Metal | `#4E6984` | Hexagon on dark, UI accents on light |
| Lustre | `#8FA7BF` | Bonds |
| Lustre Light | `#C0D1E1` | Chevron on Slate |
| Frost | `#E6EEF6` | Chevron and wordmark on dark |
| Oxide | `#B4552D` | Atoms on light |
| Oxide Bright | `#E07B4B` | Cursor, atoms on dark |
| Ink | `#121A23` | Dark ground |
| Paper | `#F4F6F8` | Light ground |

Oxide and Oxide Bright are the only warm colors. Keep them for atoms, the cursor and small emphasis. Don't use them as backgrounds except for the white knockout variant.

### Theme tokens (web)

Light (`:root`): bg `#EDF0F3`, surface `#FFFFFF`, text `#17202A`, muted `#5A6674`, line `#D4DBE2`, metal `#4E6984`, metal-hi `#8FA7BF`, metal-lo `#2B3D51`, oxide `#B4552D`.

Dark: bg `#0E1319`, surface `#161D25`, text `#E5EBF1`, muted `#92A0AF`, line `#25303B`, metal `#89A4BF`, metal-hi `#C0D1E1`, metal-lo `#4B6683`, oxide `#E07B4B`.

## Typography

| Role | Face | Notes |
| --- | --- | --- |
| Wordmark, code, labels, data | JetBrains Mono | Wordmark in Bold (700). Labels in 500, uppercase, letter-spacing about 0.08em |
| Display headings | Archivo | Weight 700–800, width axis 110–125, tight tracking |
| Body | IBM Plex Sans | 400/500/600, line-height 1.55, about 65 characters per line |

Google Fonts: `family=Archivo:wdth,wght@62..125,300..900`, `family=JetBrains+Mono:wght@400;500;600;700`, `family=IBM+Plex+Sans:wght@400;500;600`. Fallbacks: Helvetica Neue and Arial for Archivo, ui-monospace and Menlo for JetBrains Mono, system-ui for Plex Sans.

## Usage

- **README / crates.io header:** horizontal reversed lockup on Ink, followed by `cargo add osmium` and badges (`no_std`, supported architectures, license).
- **Favicon, docs.rs sidebar, app icon:** simplified core in full color. For an app icon, put the reversed core on an Ink rounded square.
- **Social avatar:** stacked lockup, or the full mark alone on Ink.
- **Voice:** plain and technical. Name things by what they do. Write the crate name in lowercase, `osmium`, in code and in running text.

## Provenance

Chosen from ten studies. Picks: No. 02 Close-Packed, No. 06 Tetroxide, No. 07 Boot Prompt. The others were Element Tile, Ingot, Cog, Ring Zero, Six Shells, Lustre and Page Table.
