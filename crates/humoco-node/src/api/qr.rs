//! Minimal, zero-dependency QR Code SVG Generator (ISO/IEC 18004 compliant).
//! Generates a valid Version 6 (41x41) QR Code in Error Correction Level L with Byte encoding.
//! Designed for peering strings (`<pubkey>@<ip>:9090`) up to 134 bytes.

const SIZE: usize = 41; // 4 * 6 + 17
const TOTAL_CODEWORDS: usize = 172;
const EC_CODEWORDS: usize = 36;
const DATA_CODEWORDS: usize = 136;
const GF_POLY: u16 = 0x11D;

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

#[allow(clippy::needless_range_loop)]
/// Generates an inline SVG QR code representing `text`.
pub fn generate_qr_svg(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut bit_buf = Vec::new();

    // Mode: Byte (0100)
    push_bits(&mut bit_buf, 0b0100, 4);
    // Count indicator: 8 bits for Version 1..9 in Byte mode
    let len = bytes.len().min(DATA_CODEWORDS - 2);
    push_bits(&mut bit_buf, len as u16, 8);
    // Data bytes
    for &b in &bytes[..len] {
        push_bits(&mut bit_buf, b as u16, 8);
    }
    // Terminator: up to 4 bits
    let total_data_bits = DATA_CODEWORDS * 8;
    let term_len = 4.min(total_data_bits.saturating_sub(bit_buf.len()));
    push_bits(&mut bit_buf, 0, term_len);
    // Byte boundary padding
    while bit_buf.len() % 8 != 0 {
        bit_buf.push(false);
    }
    // Codewords
    let mut data_codewords = Vec::with_capacity(DATA_CODEWORDS);
    for chunk in bit_buf.chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | (bit as u8);
        }
        data_codewords.push(byte);
    }
    // Pad codewords: 0xEC, 0x11
    let pad = [0xEC, 0x11];
    let mut pad_idx = 0;
    while data_codewords.len() < DATA_CODEWORDS {
        data_codewords.push(pad[pad_idx]);
        pad_idx = 1 - pad_idx;
    }

    // Reed-Solomon Error Correction
    let gf = Gf256::new();
    let ec_codewords = rs_encode(&data_codewords, EC_CODEWORDS, &gf);

    let mut all_codewords = data_codewords;
    all_codewords.extend_from_slice(&ec_codewords);

    // Flatten to bitstream
    let mut all_bits = Vec::with_capacity(TOTAL_CODEWORDS * 8 + 7);
    for byte in all_codewords {
        for i in (0..8).rev() {
            all_bits.push(((byte >> i) & 1) == 1);
        }
    }
    // 7 remainder bits for Version 6
    all_bits.resize(all_bits.len() + 7, false);

    // Grid placement
    let mut modules = [[false; SIZE]; SIZE];
    let mut is_func = [[false; SIZE]; SIZE];

    // Finders & separators
    place_finder(&mut modules, &mut is_func, 0, 0);
    place_finder(&mut modules, &mut is_func, 0, SIZE - 7);
    place_finder(&mut modules, &mut is_func, SIZE - 7, 0);

    // Separators
    for i in 0..8 {
        mark_func(&mut is_func, 7, i);
        mark_func(&mut is_func, i, 7);
        mark_func(&mut is_func, 7, SIZE - 1 - i);
        mark_func(&mut is_func, i, SIZE - 8);
        mark_func(&mut is_func, SIZE - 8, i);
        mark_func(&mut is_func, SIZE - 1 - i, 7);
    }

    // Alignment pattern at (34, 34) for Version 6
    place_alignment(&mut modules, &mut is_func, 34, 34);

    // Timing patterns
    for i in 8..(SIZE - 8) {
        let is_black = i % 2 == 0;
        modules[6][i] = is_black;
        is_func[6][i] = true;
        modules[i][6] = is_black;
        is_func[i][6] = true;
    }

    // Dark module at (SIZE - 8, 8) = (33, 8)
    modules[SIZE - 8][8] = true;
    is_func[SIZE - 8][8] = true;

    // Reserve format bits
    for i in 0..9 {
        is_func[8][i] = true;
        is_func[i][8] = true;
    }
    for i in 0..8 {
        is_func[8][SIZE - 1 - i] = true;
        is_func[SIZE - 1 - i][8] = true;
    }

    // Data traversal (zig-zag from right to left)
    let mut bit_idx = 0;
    let mut col = SIZE as isize - 1;
    let mut upward = true;

    while col > 0 {
        if col == 6 {
            col -= 1; // Skip vertical timing column
        }
        let rows: Vec<usize> = if upward {
            (0..SIZE).rev().collect()
        } else {
            (0..SIZE).collect()
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

    // Write format bits
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
            (SIZE - 1 - (i as usize), 8)
        } else {
            (8, SIZE - 8 + (i as usize - 7))
        };
        modules[r2][c2] = bit;
    }

    // Render SVG with horizontal run-length compression
    let quiet = 2;
    let total_size = SIZE + quiet * 2;
    let mut path_d = String::new();

    for r in 0..SIZE {
        let mut c = 0;
        while c < SIZE {
            if modules[r][c] {
                let start_c = c;
                while c < SIZE && modules[r][c] {
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
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="crispEdges" class="qr-svg"><rect width="{total}" height="{total}" fill="#ffffff" rx="2"/><path fill="#111827" d="{d}"/></svg>"##,
        total = total_size,
        d = path_d.trim_end()
    )
}

fn push_bits(buf: &mut Vec<bool>, val: u16, len: usize) {
    for i in (0..len).rev() {
        buf.push(((val >> i) & 1) == 1);
    }
}

fn place_finder(modules: &mut [[bool; SIZE]; SIZE], is_func: &mut [[bool; SIZE]; SIZE], r: usize, c: usize) {
    for dr in 0..7 {
        for dc in 0..7 {
            let is_black = dr == 0 || dr == 6 || dc == 0 || dc == 6 || ((2..=4).contains(&dr) && (2..=4).contains(&dc));
            modules[r + dr][c + dc] = is_black;
            is_func[r + dr][c + dc] = true;
        }
    }
}

fn place_alignment(modules: &mut [[bool; SIZE]; SIZE], is_func: &mut [[bool; SIZE]; SIZE], center_r: usize, center_c: usize) {
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

fn mark_func(is_func: &mut [[bool; SIZE]; SIZE], r: usize, c: usize) {
    if r < SIZE && c < SIZE {
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
    fn test_qr_svg_generation() {
        let svg = generate_qr_svg("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a@127.0.0.1:9090");
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains("class=\"qr-svg\""));
        assert!(svg.contains("viewBox=\"0 0 45 45\""));
    }
}
