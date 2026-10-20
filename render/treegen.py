#!/usr/bin/env python3
"""Reference renderer v0 — deterministic fractal trees (64x64, fixed palette).

Design rules (see spec): integer-only arithmetic, fixed-point Q8 positions,
1024-step sine table, xoshiro256** PRNG seeded through splitmix64 from
SHA-256(seed || stream_tag). No floats touch the output. The canonical
artifact of a render is the 64x64 palette-index matrix; PNG is presentation.
"""
import hashlib, math, os, sys, json, io

W = H = 64
GROUND_Y = 52
MASK64 = (1 << 64) - 1

# ---------------------------------------------------------------- PRNG
def splitmix64(x):
    x = (x + 0x9E3779B97F4A7C15) & MASK64
    z = x
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return z ^ (z >> 31), x

def rotl(x, k):
    return ((x << k) | (x >> (64 - k))) & MASK64

class Xoshiro:
    """xoshiro256** seeded from 8 bytes via splitmix64 (as in the reference paper)."""
    def __init__(self, seed8):
        x = int.from_bytes(seed8, "little")
        s = []
        for _ in range(4):
            v, x = splitmix64(x); s.append(v)
        self.s = s
    def next_u64(self):
        s = self.s
        result = (rotl((s[1] * 5) & MASK64, 7) * 9) & MASK64
        t = (s[1] << 17) & MASK64
        s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]
        s[2] ^= t; s[3] = rotl(s[3], 45)
        return result
    def below(self, n):            # uniform in [0, n) via 64-bit modulo (n << 2^32, bias negligible; spec'd as-is)
        return self.next_u64() % n
    def chance(self, num, den=1000):  # true with probability num/den
        return self.below(den) < num
    def range(self, lo, hi):        # inclusive integer range
        return lo + self.below(hi - lo + 1)

def stream(seed32, tag):
    return Xoshiro(hashlib.sha256(seed32 + tag).digest()[:8])

# ---------------------------------------------------------------- trig (frozen table)
SIN = [round(math.sin(2 * math.pi * i / 1024) * 4096) for i in range(1024)]  # frozen constants in spec
SIN_TABLE_SHA256 = hashlib.sha256(",".join(map(str, SIN)).encode()).hexdigest()
def sin_q(a): return SIN[a & 1023]
def cos_q(a): return SIN[(a + 256) & 1023]

# ---------------------------------------------------------------- palette (fixed, index = color id)
PALETTE = [
    (0, 0, 0),           # 0 unused
    (222, 236, 240),     # 1 sky day
    (245, 200, 160),     # 2 sky dusk
    (28, 32, 52),        # 3 sky night
    (12, 10, 22),        # 4 sky shielded
    (110, 150, 80),      # 5 ground grass
    (120, 110, 70),      # 6 ground soil
    (50, 60, 70),        # 7 ground night
    (30, 28, 45),        # 8 ground shielded
    (240, 244, 250),     # 9 snow / star
    (105, 75, 45),       # 10 trunk sprout
    (120, 85, 50),       # 11 trunk sapling
    (85, 55, 60),        # 12 trunk orchard
    (150, 158, 175),     # 13 trunk ironwood
    (96, 178, 64), (140, 205, 90), (60, 140, 50),        # 14-16 leaves sprout
    (225, 150, 45), (240, 195, 70), (190, 110, 40),      # 17-19 leaves sapling
    (205, 70, 115), (240, 150, 175), (160, 50, 90),      # 20-22 leaves orchard
    (120, 200, 235), (200, 240, 255), (80, 150, 200),    # 23-25 leaves ironwood
    (250, 200, 215),     # 26 blossom
    (200, 80, 40),       # 27 heartwood red
    (245, 200, 40),      # 28 fruit gold
    (180, 240, 255),     # 29 shielded glow
    (70, 50, 40),        # 30 roots
    (20, 20, 24),        # 31 silhouette black
    (140, 140, 150),     # 32 stone / turnstile
]

SPECIES = ["Sprout", "Sapling", "Orchard", "Ironwood"]
SPECIES_W = [500, 320, 150, 30]                     # per mille
SEASONS = ["Canopy", "Blossom", "Heartwood", "Overwinter"]
SEASONS_W = [450, 250, 200, 100]
SKIES = ["Day", "Dusk", "Night", "Shielded"]
SKIES_W = [500, 250, 200, 50]
FORMS = ["Upright", "Leaning", "Weeping", "Wide"]
FORMS_W = [450, 250, 150, 150]

def pick(r, names, weights):
    x = r.below(sum(weights)); acc = 0
    for n, w in zip(names, weights):
        acc += w
        if x < acc: return n
    return names[-1]

# ---------------------------------------------------------------- raster helpers (integer)
def px(v):  # Q8 -> pixel
    return (v + 128) >> 8

def put(grid, x, y, c):
    if 0 <= x < W and 0 <= y < H: grid[y][x] = c

def line(grid, x0, y0, x1, y1, c, width):
    dx, dy = abs(x1 - x0), -abs(y1 - y0)
    sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
    err = dx + dy
    while True:
        put(grid, x0, y0, c)
        if width >= 2: put(grid, x0 + 1, y0, c)
        if width >= 3: put(grid, x0 - 1, y0, c)
        if x0 == x1 and y0 == y1: break
        e2 = 2 * err
        if e2 >= dy: err += dy; x0 += sx
        if e2 <= dx: err += dx; y0 += sy

# ---------------------------------------------------------------- tree growth
def grow(grid, r, x, y, ang, ln, depth, trunk_c, tips, form):
    """x,y,ln in Q8; ang in 1/1024 turn. Recursive branching with integer math."""
    if depth == 0 or ln < (3 << 8) // 2:
        tips.append((px(x), px(y))); return
    x2 = x + ((ln * cos_q(ang)) >> 12)
    y2 = y - ((ln * sin_q(ang)) >> 12)
    if form == "Weeping" and depth <= 3:
        y2 += ln >> 2                       # droop the outer branches
    line(grid, px(x), px(y), px(x2), px(y2), trunk_c, 3 if depth >= 7 else (2 if depth >= 4 else 1))
    n = 3 if r.chance(300) else 2
    spread_lo, spread_hi = (40, 90) if form != "Wide" else (70, 130)
    for i in range(n):
        spread = r.range(spread_lo, spread_hi) * (1 if i % 2 == 0 else -1)
        if n == 3 and i == 2: spread = r.range(-20, 20)
        if form == "Leaning": spread += 18
        shrink = r.range(600, 780)          # per mille
        grow(grid, r, x2, y2, ang + spread, (ln * shrink) // 1000, depth - 1, trunk_c, tips, form)

# ---------------------------------------------------------------- main render
def roll_traits(seed):
    r = stream(seed, b"traits")
    t = {
        "species": pick(r, SPECIES, SPECIES_W),
        "season": pick(r, SEASONS, SEASONS_W),
        "sky": pick(r, SKIES, SKIES_W),
        "form": pick(r, FORMS, FORMS_W),
        "generations": [6, 6, 7, 7, 7, 8, 8, 9][r.below(8)],
    }
    t["anchor"] = r.chance(80)
    t["fruit"] = r.chance(100) and t["species"] != "Ironwood"
    egg = r.below(1000)
    t["easter"] = "Zeal" if egg < 20 else ("Grafted" if egg < 30 else ("Turnstile" if egg < 40 else "None"))
    return t

def render(seed):
    t = roll_traits(seed)
    sp = SPECIES.index(t["species"]); sk = SKIES.index(t["sky"])
    grid = [[1 + sk] * W for _ in range(H)]
    ground_c = [5, 6, 7, 8][sk]
    for y in range(GROUND_Y, H):
        for x in range(W): grid[y][x] = ground_c
    if sk >= 2:
        rs = stream(seed, b"stars")
        for _ in range(18): put(grid, rs.below(W), rs.below(GROUND_Y - 8), 9)
    if t["season"] == "Overwinter":
        for x in range(W): grid[GROUND_Y][x] = 9

    rt = stream(seed, b"tree")
    tips = []
    trunk_c = 10 + sp
    base_ang = 256 + rt.range(-12, 12) + (-40 if t["form"] == "Leaning" else 0)
    grow(grid, rt, 32 << 8, GROUND_Y << 8, base_ang, rt.range(11 << 8, 14 << 8), t["generations"], trunk_c, tips, t["form"])
    if t["anchor"]:
        rr = stream(seed, b"roots"); rtips = []
        grow(grid, rr, 32 << 8, GROUND_Y << 8, 768, 6 << 8, 4, 30, rtips, "Upright")

    # foliage
    rl = stream(seed, b"leaves")
    leaf_c = [14 + 3 * sp, 15 + 3 * sp, 16 + 3 * sp]
    keep = {"Canopy": 1000, "Blossom": 900, "Heartwood": 600, "Overwinter": 150}[t["season"]]
    for (x, y) in tips:
        if not rl.chance(keep): continue
        c = leaf_c[rl.below(3)]
        if t["season"] == "Heartwood" and rl.chance(500): c = 27
        if t["season"] == "Blossom" and rl.chance(350): c = 26
        if t["season"] == "Overwinter": c = 9
        for dx, dy in ((0, 0), (1, 0), (0, 1), (-1, 0), (0, -1)):
            if rl.chance(700): put(grid, x + dx, y + dy, c)
    if t["fruit"] and tips:
        rf = stream(seed, b"fruit")
        for _ in range(rf.range(2, 4)):
            x, y = tips[rf.below(len(tips))]
            put(grid, x, y + 1, 28); put(grid, x, y + 2, 28)
    if t["sky"] == "Shielded" and tips:
        rg = stream(seed, b"glow")
        for _ in range(6):
            x, y = tips[rg.below(len(tips))]; put(grid, x, y, 29)
    # easter eggs
    if t["easter"] == "Zeal":
        for bx in (8, 14, 46):
            for dx in range(5):
                put(grid, bx + dx, GROUND_Y - 2, 31 if dx % 2 == 0 else 9)
                put(grid, bx + dx, GROUND_Y - 1, 31 if dx % 2 == 1 else 9)
            put(grid, bx + 4, GROUND_Y - 3, 31)
    elif t["easter"] == "Grafted" and tips:
        rg = stream(seed, b"graft"); other = (sp + 1) % 4
        for _ in range(min(6, len(tips))):
            x, y = tips[rg.below(len(tips))]
            put(grid, x, y, 14 + 3 * other); put(grid, x + 1, y, 15 + 3 * other)
    elif t["easter"] == "Turnstile":
        for dy in range(4):
            put(grid, 48, GROUND_Y - 1 - dy, 32); put(grid, 54, GROUND_Y - 1 - dy, 32)
        for dx in range(7): put(grid, 48 + dx, GROUND_Y - 3, 32)
    return grid, t

def grid_hash(grid):
    return hashlib.sha256(bytes(c for row in grid for c in row)).hexdigest()

def to_png(grid, scale=1):
    from PIL import Image
    im = Image.new("P", (W, H))
    flat = [c for rgb in PALETTE for c in rgb]
    im.putpalette(flat + [0] * (768 - len(flat)))
    im.putdata([c for row in grid for c in row])
    if scale > 1: im = im.resize((W * scale, H * scale), Image.NEAREST)
    return im

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"); os.makedirs(out, exist_ok=True)
    if len(sys.argv) > 2 and sys.argv[1] == "seed":
        # render one tree from a 32-byte hex seed (as recorded by the indexer)
        seed = bytes.fromhex(sys.argv[2])
        g, t = render(seed)
        path = os.path.join(out, f"seed_{sys.argv[2][:16]}.png")
        to_png(g, scale=4).save(path)
        print(json.dumps({"seed": sys.argv[2], "traits": t, "matrix_sha256": grid_hash(g), "png": path}))
        raise SystemExit(0)
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 64
    from PIL import Image
    tiles, traits = [], []
    for i in range(n):
        seed = hashlib.sha256(f"sample-{i}".encode()).digest()
        g, t = render(seed)
        g2, _ = render(seed)
        assert grid_hash(g) == grid_hash(g2), "non-deterministic!"
        t["hash"] = grid_hash(g)[:16]; traits.append(t); tiles.append(to_png(g))
    S, PAD, cols = 4, 6, 8
    rows = (n + cols - 1) // cols
    sheet = Image.new("RGB", (cols * (W * S + PAD) + PAD, rows * (H * S + PAD) + PAD), (250, 250, 248))
    for i, im in enumerate(tiles):
        sheet.paste(im.convert("RGB").resize((W * S, H * S), Image.NEAREST),
                    (PAD + (i % cols) * (W * S + PAD), PAD + (i // cols) * (H * S + PAD)))
    sheet.save(os.path.join(out, f"sheet_{n}.png"))
    json.dump(traits, open(os.path.join(out, f"traits_{n}.json"), "w"), indent=1)
    # rarity over 10k rolls (traits only, no raster)
    from collections import Counter
    cnt = {k: Counter() for k in ("species", "season", "sky", "form", "generations", "anchor", "fruit", "easter")}
    N = 10000
    for i in range(N):
        t = roll_traits(hashlib.sha256(f"rarity-{i}".encode()).digest())
        for k in cnt: cnt[k][t[k]] += 1
    print("SIN table sha256:", SIN_TABLE_SHA256)
    for k, c in cnt.items():
        print(f"{k:12s}", {kk: f"{v / N * 100:.1f}%" for kk, v in sorted(c.items(), key=lambda kv: -kv[1])})
    sizes = []
    for im in tiles[:16]:
        b = io.BytesIO(); im.save(b, "PNG", optimize=True); sizes.append(len(b.getvalue()))
    print("png bytes (first 16):", sizes, "avg", sum(sizes) // len(sizes))
    print("wrote", os.path.join(out, f"sheet_{n}.png"))
