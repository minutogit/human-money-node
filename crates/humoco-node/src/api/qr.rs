//! Minimal, zero-dependency QR Code Generator (ISO/IEC 18004 compliant).
//! Supports dynamic QR versions (V3, V4, V5, V6) in Error Correction Level L with Byte encoding.
//! Correctly implements Galois Field GF(2^8) Reed-Solomon error correction and codeword interleaving.

const GF_POLY: u16 = 0x11D; // x^8 + x^4 + x^3 + x^2 + 1

struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x = 1u16;
        for i in 0..255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x >= 256 {
                x ^= GF_POLY;
            }
        }
        Self { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let idx = (self.log[a as usize] as usize + self.log[b as usize] as usize) % 255;
            self.exp[idx]
        }
    }
}

fn rs_generator_poly(ec_count: usize, gf: &Gf256) -> Vec<u8> {
    let mut g = vec![1u8];
    for i in 0..ec_count {
        let alpha = gf.exp[i];
        let mut next = vec![0u8; g.len() + 1];
        for (j, &c) in g.iter().enumerate() {
            next[j] ^= c;
            next[j + 1] ^= gf.mul(c, alpha);
        }
        g = next;
    }
    g
}

fn rs_encode(data: &[u8], ec_count: usize, gf: &Gf256) -> Vec<u8> {
    let gen = rs_generator_poly(ec_count, gf);
    let mut remainder = vec![0u8; ec_count];
    for &byte in data {
        let factor = byte ^ remainder[0];
        remainder.copy_within(1..ec_count, 0);
        remainder[ec_count - 1] = 0;
        if factor != 0 {
            for (r, &g) in remainder.iter_mut().zip(&gen[1..]) {
                *r ^= gf.mul(g, factor);
            }
        }
    }
    remainder
}

fn compute_format_bits() -> u16 {
    // Level L = 01, Mask 0 = 000 -> 01000_2 = 8
    let data = 8u16;
    let mut rem = data << 10;
    for i in (0..5).rev() {
        if (rem & (1 << (i + 10))) != 0 {
            rem ^= 0x537 << i;
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct QrVersionSpec {
    version: usize,
    size: usize,
    alignment_center: usize,
    total_codewords: usize,
    data_codewords: usize,
    ec_codewords_per_block: usize,
    blocks: usize,
    remainder_bits: usize,
}

impl QrVersionSpec {
    fn for_text_len(len: usize) -> Self {
        // Mode (4 bits) + Count (8 bits) = 12 bits -> 2 codewords overhead.
        // Payload capacity = data_codewords - 2
        if len <= 53 {
            // Version 3-L (29x29): 55 data, 15 EC (1 block), total 70
            Self {
                version: 3,
                size: 29,
                alignment_center: 22,
                total_codewords: 70,
                data_codewords: 55,
                ec_codewords_per_block: 15,
                blocks: 1,
                remainder_bits: 0,
            }
        } else if len <= 78 {
            // Version 4-L (33x33): 80 data, 20 EC (1 block), total 100
            Self {
                version: 4,
                size: 33,
                alignment_center: 26,
                total_codewords: 100,
                data_codewords: 80,
                ec_codewords_per_block: 20,
                blocks: 1,
                remainder_bits: 0,
            }
        } else if len <= 106 {
            // Version 5-L (37x37): 108 data, 26 EC (1 block), total 134
            Self {
                version: 5,
                size: 37,
                alignment_center: 30,
                total_codewords: 134,
                data_codewords: 108,
                ec_codewords_per_block: 26,
                blocks: 1,
                remainder_bits: 0,
            }
        } else {
            // Version 6-L (41x41): 136 data (2 blocks of 68), 36 EC (2 blocks of 18), total 172
            Self {
                version: 6,
                size: 41,
                alignment_center: 34,
                total_codewords: 172,
                data_codewords: 136,
                ec_codewords_per_block: 18,
                blocks: 2,
                remainder_bits: 7,
            }
        }
    }
}

/// Represents a generated QR module matrix.
pub struct QrMatrix {
    pub size: usize,
    pub modules: Vec<Vec<bool>>,
}

/// Generates the raw boolean module matrix for `text`.
/// `true` = dark module (black), `false` = light module (white).
#[allow(clippy::needless_range_loop)]
pub fn generate_qr_matrix(text: &str) -> QrMatrix {
    let bytes = text.as_bytes();
    let spec = QrVersionSpec::for_text_len(bytes.len());
    let max_payload = spec.data_codewords - 2;
    let len = bytes.len().min(max_payload);

    let mut bit_buf = Vec::with_capacity(spec.data_codewords * 8);

    // Mode: Byte (0100)
    push_bits(&mut bit_buf, 0b0100, 4);
    // Count indicator: 8 bits for Version 1..9 in Byte mode
    push_bits(&mut bit_buf, len as u16, 8);
    // Data bytes
    for &b in &bytes[..len] {
        push_bits(&mut bit_buf, b as u16, 8);
    }

    // Terminator: up to 4 bits
    let total_data_bits = spec.data_codewords * 8;
    let term_len = 4.min(total_data_bits.saturating_sub(bit_buf.len()));
    push_bits(&mut bit_buf, 0, term_len);

    // Byte boundary padding
    while bit_buf.len() % 8 != 0 {
        bit_buf.push(false);
    }

    // Codewords
    let mut data_codewords = Vec::with_capacity(spec.data_codewords);
    for chunk in bit_buf.chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | (bit as u8);
        }
        data_codewords.push(byte);
    }

    // Pad codewords: alternate 0xEC, 0x11
    let pad = [0xEC, 0x11];
    let mut pad_idx = 0;
    while data_codewords.len() < spec.data_codewords {
        data_codewords.push(pad[pad_idx]);
        pad_idx = 1 - pad_idx;
    }

    // Reed-Solomon Error Correction per block
    let gf = Gf256::new();
    let data_per_block = spec.data_codewords / spec.blocks;
    let mut ec_blocks = Vec::with_capacity(spec.blocks);
    let mut data_blocks = Vec::with_capacity(spec.blocks);

    for b in 0..spec.blocks {
        let slice = &data_codewords[b * data_per_block..(b + 1) * data_per_block];
        data_blocks.push(slice);
        let ec = rs_encode(slice, spec.ec_codewords_per_block, &gf);
        ec_blocks.push(ec);
    }

    // Interleave data codewords across blocks
    let mut interleaved = Vec::with_capacity(spec.total_codewords);
    for i in 0..data_per_block {
        for b in 0..spec.blocks {
            interleaved.push(data_blocks[b][i]);
        }
    }
    // Interleave error correction codewords across blocks
    for i in 0..spec.ec_codewords_per_block {
        for b in 0..spec.blocks {
            interleaved.push(ec_blocks[b][i]);
        }
    }

    // Flatten to bitstream
    let mut all_bits = Vec::with_capacity(spec.total_codewords * 8 + spec.remainder_bits);
    for byte in interleaved {
        for i in (0..8).rev() {
            all_bits.push(((byte >> i) & 1) == 1);
        }
    }
    // Remainder bits
    all_bits.resize(all_bits.len() + spec.remainder_bits, false);

    // Matrix allocation
    let size = spec.size;
    let mut modules = vec![vec![false; size]; size];
    let mut is_func = vec![vec![false; size]; size];

    // Finders & separators
    place_finder(&mut modules, &mut is_func, 0, 0);
    place_finder(&mut modules, &mut is_func, 0, size - 7);
    place_finder(&mut modules, &mut is_func, size - 7, 0);

    // Separators around finders
    for i in 0..8 {
        mark_func(&mut is_func, size, 7, i);
        mark_func(&mut is_func, size, i, 7);
        mark_func(&mut is_func, size, 7, size - 1 - i);
        mark_func(&mut is_func, size, i, size - 8);
        mark_func(&mut is_func, size, size - 8, i);
        mark_func(&mut is_func, size, size - 1 - i, 7);
    }

    // Alignment pattern
    if spec.alignment_center > 0 {
        place_alignment(
            &mut modules,
            &mut is_func,
            spec.alignment_center,
            spec.alignment_center,
        );
    }

    // Timing patterns
    for i in 8..(size - 8) {
        let is_black = i % 2 == 0;
        modules[6][i] = is_black;
        is_func[6][i] = true;
        modules[i][6] = is_black;
        is_func[i][6] = true;
    }

    // Dark module at (SIZE - 8, 8)
    modules[size - 8][8] = true;
    is_func[size - 8][8] = true;

    // Reserve format bits
    for i in 0..9 {
        is_func[8][i] = true;
        is_func[i][8] = true;
    }
    for i in 0..8 {
        is_func[8][size - 1 - i] = true;
        is_func[size - 1 - i][8] = true;
    }

    // Data traversal (zig-zag from right to left in 2-column tracks)
    let mut bit_idx = 0;
    let mut col = size as isize - 1;
    let mut upward = true;

    while col > 0 {
        if col == 6 {
            col -= 1; // Skip vertical timing column
        }
        let rows: Vec<usize> = if upward {
            (0..size).rev().collect()
        } else {
            (0..size).collect()
        };

        for r in rows {
            for c in [col as usize, (col - 1) as usize] {
                if !is_func[r][c] {
                    let bit = if bit_idx < all_bits.len() {
                        all_bits[bit_idx]
                    } else {
                        false
                    };
                    bit_idx += 1;

                    // Mask 0: (row + col) % 2 == 0
                    let mask = (r + c) % 2 == 0;
                    modules[r][c] = bit ^ mask;
                }
            }
        }
        upward = !upward;
        col -= 2;
    }

    // Write format bits (15 bits, Level L, Mask 0)
    let format_val = compute_format_bits();
    for i in 0..15 {
        let bit = ((format_val >> i) & 1) == 1;

        // Top-left
        let (r1, c1) = match i {
            0..=5 => (8, i as usize),
            6 => (8, 7),
            7 => (8, 8),
            8 => (7, 8),
            9..=14 => ((14 - i) as usize, 8),
            _ => unreachable!(),
        };
        modules[r1][c1] = bit;

        // Bottom-left & Top-right
        let (r2, c2) = if i < 7 {
            (size - 1 - (i as usize), 8)
        } else {
            (8, size - 8 + (i as usize - 7))
        };
        modules[r2][c2] = bit;
    }

    QrMatrix { size, modules }
}

/// Generates an inline SVG QR code representing `text`.
pub fn generate_qr_svg(text: &str) -> String {
    let qr = generate_qr_matrix(text);
    let size = qr.size;

    // Render SVG with 4-module quiet zone for robust camera edge detection
    let quiet = 4;
    let total_size = size + quiet * 2;
    let mut path_d = String::new();

    for r in 0..size {
        let mut c = 0;
        while c < size {
            if qr.modules[r][c] {
                let start_c = c;
                while c < size && qr.modules[r][c] {
                    c += 1;
                }
                let w = c - start_c;
                let x = start_c + quiet;
                let y = r + quiet;
                if w == 1 {
                    path_d.push_str(&format!("M{} {}h1v1h-1z ", x, y));
                } else {
                    path_d.push_str(&format!("M{} {}h{}v1h-{}z ", x, y, w, w));
                }
            } else {
                c += 1;
            }
        }
    }

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="crispEdges" class="qr-svg"><rect width="{total}" height="{total}" fill="#ffffff"/><path fill="#111827" d="{d}"/></svg>"##,
        total = total_size,
        d = path_d.trim_end()
    )
}

/// Generates a compact ANSI/Unicode QR code for direct terminal rendering.
/// Uses half-block characters (▀, ▄, █, space) to fit 2 QR rows per terminal line.
pub fn generate_qr_ansi(text: &str) -> String {
    let qr = generate_qr_matrix(text);
    let size = qr.size;
    let quiet = 2;
    let total_size = size + quiet * 2;
    let mut output = String::new();

    let get_module = |y: usize, x: usize| -> bool {
        if y < quiet || y >= quiet + size || x < quiet || x >= quiet + size {
            false // Light / white in quiet zone
        } else {
            qr.modules[y - quiet][x - quiet]
        }
    };

    let mut y = 0;
    while y < total_size {
        for x in 0..total_size {
            let top_dark = get_module(y, x);
            let bot_dark = if y + 1 < total_size {
                get_module(y + 1, x)
            } else {
                false
            };

            // Terminal rendering (light on dark):
            // false (light module) -> rendered as solid light
            // true (dark module) -> rendered as dark space
            let ch = match (!top_dark, !bot_dark) {
                (true, true) => '█',   // Both light
                (true, false) => '▀',  // Top light, bottom dark
                (false, true) => '▄',  // Top dark, bottom light
                (false, false) => ' ', // Both dark
            };
            output.push(ch);
        }
        output.push('\n');
        y += 2;
    }

    output
}

fn push_bits(buf: &mut Vec<bool>, val: u16, len: usize) {
    for i in (0..len).rev() {
        buf.push(((val >> i) & 1) == 1);
    }
}

fn place_finder(modules: &mut [Vec<bool>], is_func: &mut [Vec<bool>], r: usize, c: usize) {
    for dr in 0..7 {
        for dc in 0..7 {
            let is_black = dr == 0 || dr == 6 || dc == 0 || dc == 6 || ((2..=4).contains(&dr) && (2..=4).contains(&dc));
            modules[r + dr][c + dc] = is_black;
            is_func[r + dr][c + dc] = true;
        }
    }
}

fn place_alignment(modules: &mut [Vec<bool>], is_func: &mut [Vec<bool>], center_r: usize, center_c: usize) {
    for dr in 0..5 {
        for dc in 0..5 {
            let r = center_r - 2 + dr;
            let c = center_c - 2 + dc;
            let is_black = dr == 0 || dr == 4 || dc == 0 || dc == 4 || (dr == 2 && dc == 2);
            modules[r][c] = is_black;
            is_func[r][c] = true;
        }
    }
}

fn mark_func(is_func: &mut [Vec<bool>], size: usize, r: usize, c: usize) {
    if r < size && c < size {
        is_func[r][c] = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bits_computation() {
        let f = compute_format_bits();
        // Standard ISO/IEC 18004 Table C.1: Level L, Mask 0 = 0x77C4 (111011111000100)
        assert_eq!(f, 0x77C4);
    }

    #[test]
    fn test_qr_versions_selection() {
        // V3 (<= 53 B)
        let v3 = QrVersionSpec::for_text_len(40);
        assert_eq!(v3.version, 3);
        assert_eq!(v3.size, 29);
        assert_eq!(v3.blocks, 1);

        // V4 (<= 78 B)
        let v4 = QrVersionSpec::for_text_len(60);
        assert_eq!(v4.version, 4);
        assert_eq!(v4.size, 33);
        assert_eq!(v4.blocks, 1);

        // V5 (<= 106 B)
        let v5 = QrVersionSpec::for_text_len(90);
        assert_eq!(v5.version, 5);
        assert_eq!(v5.size, 37);
        assert_eq!(v5.blocks, 1);

        // V6 (<= 134 B)
        let v6 = QrVersionSpec::for_text_len(120);
        assert_eq!(v6.version, 6);
        assert_eq!(v6.size, 41);
        assert_eq!(v6.blocks, 2);
    }

    #[test]
    fn test_qr_svg_generation() {
        let peering = "9ZNTfG4NyQgxy2SWjSiQoUyBPEvXT2xq7f2U6bK8d5wH@127.0.0.1:9090";
        let svg = generate_qr_svg(peering);
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains("class=\"qr-svg\""));
        // Version 4 (33x33) + quiet (4*2) = 41x41 viewBox
        assert!(svg.contains("viewBox=\"0 0 41 41\""));
    }

    #[test]
    fn test_qr_ansi_generation() {
        let text = "9ZNTfG4NyQgxy2SWjSiQoUyBPEvXT2xq7f2U6bK8d5wH@127.0.0.1:9090";
        let ansi = generate_qr_ansi(text);
        let lines: Vec<&str> = ansi.lines().collect();
        // Version 4: 33 + quiet(2*2) = 37 modules tall with 2 rows per character = 19 lines
        assert_eq!(lines.len(), 19);
        for line in lines {
            assert_eq!(line.chars().count(), 37);
        }
    }
}

