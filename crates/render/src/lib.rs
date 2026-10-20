//! Deterministic renderer, version 0. Bit-exact port of the Python reference
//! (`render/treegen.py`). Integer-only; no floating point anywhere.
//!
//! Output: a 64x64 matrix of palette indexes (row-major) and the trait roll.
//! The canonical image hash is SHA-256 of the matrix bytes.

use sha2::{Digest, Sha256};

mod sin_table;
pub use sin_table::SIN;

/// Fixed palette; index = colour id used in the matrix.
pub const PALETTE: [(u8, u8, u8); 33] = [
    (0, 0, 0), (222, 236, 240), (245, 200, 160), (28, 32, 52), (12, 10, 22),
    (110, 150, 80), (120, 110, 70), (50, 60, 70), (30, 28, 45), (240, 244, 250),
    (105, 75, 45), (120, 85, 50), (85, 55, 60), (150, 158, 175),
    (96, 178, 64), (140, 205, 90), (60, 140, 50),
    (225, 150, 45), (240, 195, 70), (190, 110, 40),
    (205, 70, 115), (240, 150, 175), (160, 50, 90),
    (120, 200, 235), (200, 240, 255), (80, 150, 200),
    (250, 200, 215), (200, 80, 40), (245, 200, 40), (180, 240, 255), (70, 50, 40), (20, 20, 24), (140, 140, 150),
];

pub const W: usize = 64;
pub const H: usize = 64;
const GROUND_Y: i64 = 52;

// ---------------------------------------------------------------- PRNG

fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// xoshiro256** seeded from 8 bytes via splitmix64.
pub struct Xoshiro {
    s: [u64; 4],
}

impl Xoshiro {
    pub fn new(seed8: [u8; 8]) -> Self {
        let mut x = u64::from_le_bytes(seed8);
        let mut s = [0u64; 4];
        for v in s.iter_mut() {
            *v = splitmix64(&mut x);
        }
        Self { s }
    }
    pub fn next_u64(&mut self) -> u64 {
        let s = &mut self.s;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    pub fn chance(&mut self, num: u64) -> bool {
        self.below(1000) < num
    }
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + self.below((hi - lo + 1) as u64) as i64
    }
}

pub fn stream(seed: &[u8; 32], tag: &[u8]) -> Xoshiro {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(tag);
    let d = h.finalize();
    Xoshiro::new(d[..8].try_into().unwrap())
}

// ---------------------------------------------------------------- trig / raster

fn sin_q(a: i64) -> i64 {
    SIN[(a & 1023) as usize] as i64
}
fn cos_q(a: i64) -> i64 {
    SIN[((a + 256) & 1023) as usize] as i64
}

/// Q8 -> pixel (floor of (v + 128) / 256, arithmetic shift as in Python).
fn px(v: i64) -> i64 {
    (v + 128) >> 8
}

pub type Grid = [[u8; W]; H];

fn put(g: &mut Grid, x: i64, y: i64, c: u8) {
    if (0..W as i64).contains(&x) && (0..H as i64).contains(&y) {
        g[y as usize][x as usize] = c;
    }
}

fn line(g: &mut Grid, mut x0: i64, mut y0: i64, x1: i64, y1: i64, c: u8, width: i64) {
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    loop {
        put(g, x0, y0, c);
        if width >= 2 {
            put(g, x0 + 1, y0, c);
        }
        if width >= 3 {
            put(g, x0 - 1, y0, c);
        }
        if x0 == x1 && y0 == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
    }
}

// ---------------------------------------------------------------- traits

pub const SPECIES: [&str; 4] = ["Sprout", "Sapling", "Orchard", "Ironwood"];
const SPECIES_W: [u64; 4] = [500, 320, 150, 30];
pub const SEASONS: [&str; 4] = ["Canopy", "Blossom", "Heartwood", "Overwinter"];
const SEASONS_W: [u64; 4] = [450, 250, 200, 100];
pub const SKIES: [&str; 4] = ["Day", "Dusk", "Night", "Shielded"];
const SKIES_W: [u64; 4] = [500, 250, 200, 50];
pub const FORMS: [&str; 4] = ["Upright", "Leaning", "Weeping", "Wide"];
const FORMS_W: [u64; 4] = [450, 250, 150, 150];

fn pick(r: &mut Xoshiro, weights: &[u64; 4]) -> usize {
    let x = r.below(weights.iter().sum());
    let mut acc = 0;
    for (i, w) in weights.iter().enumerate() {
        acc += w;
        if x < acc {
            return i;
        }
    }
    3
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Traits {
    pub species: String,
    pub season: String,
    pub sky: String,
    pub form: String,
    pub generations: u32,
    pub anchor: bool,
    pub fruit: bool,
    pub easter: String,
}

struct Roll {
    species: usize,
    season: usize,
    sky: usize,
    form: usize,
    generations: u32,
    anchor: bool,
    fruit: bool,
    easter: u8, // 0 none, 1 zeal, 2 grafted, 3 turnstile
}

fn roll_traits(seed: &[u8; 32]) -> Roll {
    let mut r = stream(seed, b"traits");
    let species = pick(&mut r, &SPECIES_W);
    let season = pick(&mut r, &SEASONS_W);
    let sky = pick(&mut r, &SKIES_W);
    let form = pick(&mut r, &FORMS_W);
    let generations = [6u32, 6, 7, 7, 7, 8, 8, 9][r.below(8) as usize];
    let anchor = r.chance(80);
    let fruit_roll = r.chance(100);
    let fruit = fruit_roll && species != 3;
    let egg = r.below(1000);
    let easter = if egg < 20 { 1 } else if egg < 30 { 2 } else if egg < 40 { 3 } else { 0 };
    Roll { species, season, sky, form, generations, anchor, fruit, easter }
}

impl Roll {
    fn traits(&self) -> Traits {
        Traits {
            species: SPECIES[self.species].into(),
            season: SEASONS[self.season].into(),
            sky: SKIES[self.sky].into(),
            form: FORMS[self.form].into(),
            generations: self.generations,
            anchor: self.anchor,
            fruit: self.fruit,
            easter: ["None", "Zeal", "Grafted", "Turnstile"][self.easter as usize].into(),
        }
    }
}

// ---------------------------------------------------------------- growth

#[allow(clippy::too_many_arguments)]
fn grow(g: &mut Grid, r: &mut Xoshiro, x: i64, y: i64, ang: i64, ln: i64, depth: u32, trunk_c: u8, tips: &mut Vec<(i64, i64)>, form: usize) {
    if depth == 0 || ln < (3 << 8) / 2 {
        tips.push((px(x), px(y)));
        return;
    }
    let x2 = x + ((ln * cos_q(ang)) >> 12);
    let mut y2 = y - ((ln * sin_q(ang)) >> 12);
    if form == 2 && depth <= 3 {
        y2 += ln >> 2;
    }
    let width = if depth >= 7 { 3 } else if depth >= 4 { 2 } else { 1 };
    line(g, px(x), px(y), px(x2), px(y2), trunk_c, width);
    let n = if r.chance(300) { 3 } else { 2 };
    let (lo, hi) = if form != 3 { (40, 90) } else { (70, 130) };
    for i in 0..n {
        let mut spread = r.range(lo, hi) * if i % 2 == 0 { 1 } else { -1 };
        if n == 3 && i == 2 {
            spread = r.range(-20, 20);
        }
        if form == 1 {
            spread += 18;
        }
        let shrink = r.range(600, 780);
        grow(g, r, x2, y2, ang + spread, (ln * shrink) / 1000, depth - 1, trunk_c, tips, form);
    }
}

// ---------------------------------------------------------------- render

pub fn render(seed: &[u8; 32]) -> (Grid, Traits) {
    let t = roll_traits(seed);
    let sp = t.species;
    let sk = t.sky;
    let mut g: Grid = [[1 + sk as u8; W]; H];
    let ground_c = [5u8, 6, 7, 8][sk];
    for row in g.iter_mut().skip(GROUND_Y as usize) {
        *row = [ground_c; W];
    }
    if sk >= 2 {
        let mut rs = stream(seed, b"stars");
        for _ in 0..18 {
            let x = rs.below(W as u64) as i64;
            let y = rs.below((GROUND_Y - 8) as u64) as i64;
            put(&mut g, x, y, 9);
        }
    }
    if t.season == 3 {
        for x in 0..W {
            g[GROUND_Y as usize][x] = 9;
        }
    }

    let mut rt = stream(seed, b"tree");
    let mut tips: Vec<(i64, i64)> = vec![];
    let trunk_c = 10 + sp as u8;
    let base_ang = 256 + rt.range(-12, 12) + if t.form == 1 { -40 } else { 0 };
    let ln = rt.range(11 << 8, 14 << 8);
    grow(&mut g, &mut rt, 32 << 8, GROUND_Y << 8, base_ang, ln, t.generations, trunk_c, &mut tips, t.form);
    if t.anchor {
        let mut rr = stream(seed, b"roots");
        let mut rtips = vec![];
        grow(&mut g, &mut rr, 32 << 8, GROUND_Y << 8, 768, 6 << 8, 4, 30, &mut rtips, 0);
    }

    // foliage
    let mut rl = stream(seed, b"leaves");
    let leaf_c = [14 + 3 * sp as u8, 15 + 3 * sp as u8, 16 + 3 * sp as u8];
    let keep = [1000u64, 900, 600, 150][t.season];
    for &(x, y) in &tips {
        if !rl.chance(keep) {
            continue;
        }
        let mut c = leaf_c[rl.below(3) as usize];
        if t.season == 2 && rl.chance(500) {
            c = 27;
        }
        if t.season == 1 && rl.chance(350) {
            c = 26;
        }
        if t.season == 3 {
            c = 9;
        }
        for (dx, dy) in [(0, 0), (1, 0), (0, 1), (-1, 0), (0, -1)] {
            if rl.chance(700) {
                put(&mut g, x + dx, y + dy, c);
            }
        }
    }
    if t.fruit && !tips.is_empty() {
        let mut rf = stream(seed, b"fruit");
        let n = rf.range(2, 4);
        for _ in 0..n {
            let (x, y) = tips[rf.below(tips.len() as u64) as usize];
            put(&mut g, x, y + 1, 28);
            put(&mut g, x, y + 2, 28);
        }
    }
    if sk == 3 && !tips.is_empty() {
        let mut rg = stream(seed, b"glow");
        for _ in 0..6 {
            let (x, y) = tips[rg.below(tips.len() as u64) as usize];
            put(&mut g, x, y, 29);
        }
    }
    match t.easter {
        1 => {
            for bx in [8i64, 14, 46] {
                for dx in 0..5i64 {
                    put(&mut g, bx + dx, GROUND_Y - 2, if dx % 2 == 0 { 31 } else { 9 });
                    put(&mut g, bx + dx, GROUND_Y - 1, if dx % 2 == 1 { 31 } else { 9 });
                }
                put(&mut g, bx + 4, GROUND_Y - 3, 31);
            }
        }
        2 if !tips.is_empty() => {
            let mut rg = stream(seed, b"graft");
            let other = ((sp + 1) % 4) as u8;
            for _ in 0..tips.len().min(6) {
                let (x, y) = tips[rg.below(tips.len() as u64) as usize];
                put(&mut g, x, y, 14 + 3 * other);
                put(&mut g, x + 1, y, 15 + 3 * other);
            }
        }
        3 => {
            for dy in 0..4i64 {
                put(&mut g, 48, GROUND_Y - 1 - dy, 32);
                put(&mut g, 54, GROUND_Y - 1 - dy, 32);
            }
            for dx in 0..7i64 {
                put(&mut g, 48 + dx, GROUND_Y - 3, 32);
            }
        }
        _ => {}
    }
    (g, t.traits())
}

pub fn grid_hash(g: &Grid) -> String {
    let mut h = Sha256::new();
    for row in g {
        h.update(row);
    }
    hex::encode(h.finalize())
}

pub fn sin_table_sha256() -> String {
    let joined = SIN.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",");
    hex::encode(Sha256::digest(joined.as_bytes()))
}
