"""
ui.py -- palette, fonts and small drawing helpers shared by every screen.

Everything is drawn with Pillow primitives so nothing depends on glyph
coverage in the device's font (arrows, warning signs, etc. are drawn).
"""

import os
import zlib

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
W, H = 320, 170

BG = (13, 13, 16)
PANEL = (29, 29, 34)
PANEL2 = (37, 37, 43)
LINE = (56, 56, 64)
TEXT = (236, 236, 236)
DIM = (136, 136, 148)
FAINT = (84, 84, 94)
AMBER = (255, 172, 28)
RED = (232, 64, 52)
GREEN = (72, 208, 104)
BLUE = (88, 170, 255)
DKGREEN = (24, 70, 38)
DKRED = (70, 22, 20)
DKAMBER = (72, 50, 10)

# ---------------------------------------------------------------------------
# Fonts: DejaVu from fonts-dejavu-core on the device; anything Vera-shaped
# off-device; Pillow's built-in scalable font as the last resort.
# ---------------------------------------------------------------------------

_FONT_DIRS = [os.path.join(HERE, "fonts"), "/usr/share/fonts/truetype/dejavu",
              "/usr/share/fonts/TTF", "/usr/share/fonts/dejavu", "/usr/share/fonts"]
_FONT_NAMES = {
    "sans": ["DejaVuSans.ttf", "BitstromWeraNerdFont-Regular.ttf"],
    "bold": ["DejaVuSans-Bold.ttf", "BitstromWeraNerdFont-Bold.ttf"],
    "mono": ["DejaVuSansMono.ttf", "BitstromWeraNerdFontMono-Regular.ttf"],
    "monob": ["DejaVuSansMono-Bold.ttf", "BitstromWeraNerdFontMono-Bold.ttf"],
}
_font_cache = {}


def font(kind, size):
    key = (kind, size)
    if key not in _font_cache:
        f = None
        for d in _FONT_DIRS:
            for n in _FONT_NAMES[kind]:
                p = os.path.join(d, n)
                if os.path.exists(p):
                    f = ImageFont.truetype(p, size)
                    break
            if f:
                break
        if f is None:
            try:
                f = ImageFont.load_default(size)   # Pillow >= 10.1
            except TypeError:
                f = ImageFont.load_default()
        _font_cache[key] = f
    return _font_cache[key]


_fit_cache = {}


def fit(d, text, fnt, width):
    """Truncate `text` with an ellipsis to fit `width` pixels (memoized:
    text measurement dominates frame time on the CM0)."""
    key = (str(text), id(fnt), width)
    hit = _fit_cache.get(key)
    if hit is not None:
        return hit
    text = str(text)
    if d.textlength(text, font=fnt) > width:
        while text and d.textlength(text + "…", font=fnt) > width:
            text = text[:-1]
        text += "…"
    if len(_fit_cache) > 3000:
        _fit_cache.clear()
    _fit_cache[key] = text
    return text


# ---------------------------------------------------------------------------
# Render scale. Screens are laid out in 320x170 units. On the Cardputer they
# are drawn 1:1; a bigger display (the uConsole window) sets SCALE so every
# shape and glyph is drawn at full resolution instead of upscaling pixels.
# ---------------------------------------------------------------------------

SCALE = 1


def set_scale(s):
    global SCALE
    SCALE = max(1, int(s))


def canvas():
    """A fresh frame and something to draw on it in 320x170 units."""
    img = Image.new("RGB", (W * SCALE, H * SCALE), BG)
    d = ImageDraw.Draw(img)
    return img, (d if SCALE == 1 else ScaledDraw(d, SCALE))


_paste_cache = {}


def paste_asset(img, name, size, xy):
    """Paste assets/<name> at `size` (320x170 units), resampled from the
    source file at the current scale so it stays sharp."""
    key = (name, size, SCALE)
    if key not in _paste_cache:
        _paste_cache[key] = asset(name, (size[0] * SCALE, size[1] * SCALE))
    im = _paste_cache[key]
    if im is not None:
        img.paste(im, (xy[0] * SCALE, xy[1] * SCALE))


def _flat(xy):
    out = []
    for v in xy:
        if isinstance(v, (tuple, list)):
            out.extend(v)
        else:
            out.append(v)
    return out


class ScaledDraw:
    """ImageDraw stand-in: takes 320x170 coordinates, sizes and fonts, and
    draws them `s` times bigger. Text is re-rasterized from the TrueType
    font at s x size, so it's crisp rather than blocky. textlength() answers
    in 320x170 units (measured on the big font) so layout code is unchanged."""

    def __init__(self, d, s):
        self.d, self.s = d, s
        self._fonts = {}

    def _font(self, f):
        if f is None:
            return None
        key = id(f)
        if key not in self._fonts:
            try:
                self._fonts[key] = ImageFont.truetype(f.path, round(f.size * self.s))
            except (AttributeError, OSError):
                try:
                    self._fonts[key] = f.font_variant(size=round(f.size * self.s))
                except Exception:
                    self._fonts[key] = f
        return self._fonts[key]

    def _box(self, xy):
        x0, y0, x1, y1 = _flat(xy)
        s = self.s
        return (round(x0 * s), round(y0 * s), round(x1 * s) + s - 1, round(y1 * s) + s - 1)

    def _pts(self, xy):
        v, s, c = _flat(xy), self.s, (self.s - 1) / 2
        return [(v[i] * s + c, v[i + 1] * s + c) for i in range(0, len(v) - 1, 2)]

    def _w(self, width):
        return max(1, width or 1) * self.s

    def rectangle(self, xy, fill=None, outline=None, width=1):
        self.d.rectangle(self._box(xy), fill=fill, outline=outline, width=self._w(width))

    def rounded_rectangle(self, xy, radius=0, fill=None, outline=None, width=1, **kw):
        self.d.rounded_rectangle(self._box(xy), radius=radius * self.s, fill=fill,
                                 outline=outline, width=self._w(width), **kw)

    def ellipse(self, xy, fill=None, outline=None, width=1):
        self.d.ellipse(self._box(xy), fill=fill, outline=outline, width=self._w(width))

    def line(self, xy, fill=None, width=0, joint=None):
        self.d.line(self._pts(xy), fill=fill, width=self._w(width), joint=joint)

    def polygon(self, xy, fill=None, outline=None, width=1):
        self.d.polygon(self._pts(xy), fill=fill, outline=outline, width=self._w(width))

    def point(self, xy, fill=None):
        v, s = _flat(xy), self.s
        for i in range(0, len(v) - 1, 2):
            x, y = round(v[i] * s), round(v[i + 1] * s)
            self.d.rectangle((x, y, x + s - 1, y + s - 1), fill=fill)

    def text(self, xy, text, fill=None, font=None, anchor=None, **kw):
        x, y = _flat(xy)[:2]
        for k in ("spacing", "stroke_width"):
            if k in kw:
                kw[k] = kw[k] * self.s
        self.d.text((x * self.s, y * self.s), text, fill=fill, font=self._font(font),
                    anchor=anchor, **kw)

    def textlength(self, text, font=None, **kw):
        return self.d.textlength(text, font=self._font(font), **kw) / self.s


def asset(name, size=None):
    try:
        im = Image.open(os.path.join(HERE, "assets", name)).convert("RGB")
        return im.resize(size, Image.LANCZOS) if size else im
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Drawn icons and widgets
# ---------------------------------------------------------------------------

def tri(d, x, y, direction, size=3, fill=DIM):
    if direction == "l":
        pts = [(x + size, y - size), (x + size, y + size), (x, y)]
    elif direction == "r":
        pts = [(x, y - size), (x, y + size), (x + size, y)]
    elif direction == "u":
        pts = [(x - size, y + size), (x + size, y + size), (x, y)]
    else:
        pts = [(x - size, y), (x + size, y), (x, y + size)]
    d.polygon(pts, fill=fill)


def warn_icon(d, x, y, col=AMBER, size=10):
    """A filled warning triangle with a '!' cut out; (x, y) = top-left."""
    d.polygon([(x + size // 2, y), (x + size, y + size), (x, y + size)], fill=col)
    cx = x + size // 2
    d.line([cx, y + 3, cx, y + size - 4], fill=BG, width=1)
    d.point((cx, y + size - 2), fill=BG)


def keycap(d, x, y, label, action):
    """Footer hint: [key] action. Returns the x after it."""
    f, fa = font("bold", 8), font("sans", 9)
    w = 18 if label in ("lr", "ud") else int(d.textlength(label, font=f)) + 8
    d.rounded_rectangle([x, y, x + w, y + 11], radius=3, fill=PANEL2, outline=LINE)
    if label == "lr":
        tri(d, x + 3, y + 5, "l", 3, TEXT)
        tri(d, x + 11, y + 5, "r", 3, TEXT)
    elif label == "ud":
        tri(d, x + 5, y + 3, "u", 3, TEXT)
        tri(d, x + 13, y + 4, "d", 3, TEXT)
    else:
        d.text((x + 4, y + 1), label, font=f, fill=TEXT)
    x += w + 4
    d.text((x, y), action, font=fa, fill=DIM)
    return x + int(d.textlength(action, font=fa)) + 9


def rj45(d, x, y, w, h, col):
    """An RJ45 jack outline, used for the 'plug me in' state."""
    d.rounded_rectangle([x, y, x + w, y + h], radius=3, outline=col, width=2)
    pw = w // 9
    for i in range(8):
        px = x + 6 + i * ((w - 12) // 8)
        d.rectangle([px, y + 5, px + pw - 1, y + 5 + h // 4], fill=col)
    notch = w // 3
    d.rectangle([x + notch, y + h - 2, x + w - notch, y + h + 5], outline=col, width=2)


def badge(d, x_right, y, text, fill, fg, size=9):
    """Right-aligned rounded badge; returns its left x."""
    f = font("bold", size)
    w = int(d.textlength(text, font=f)) + 10
    d.rounded_rectangle([x_right - w, y, x_right, y + size + 4], radius=(size + 4) // 2, fill=fill)
    d.text((x_right - w // 2, y + 1), text, font=f, fill=fg, anchor="ma")
    return x_right - w


def tag(d, x, y, text, fill, fg=BG, size=8):
    """Left-aligned square-ish tag; returns the x after it."""
    f = font("bold", size)
    w = int(d.textlength(text, font=f)) + 8
    d.rounded_rectangle([x, y, x + w, y + size + 2], radius=3, fill=fill)
    d.text((x + 4, y + 1), text, font=f, fill=fg)
    return x + w + 4


def scrollbar(d, top, rows, total, start, lh):
    if total <= rows:
        return
    track = rows * lh
    bar = max(8, track * rows // total)
    pos = top + (track - bar) * start // max(1, total - rows)
    d.rectangle([W - 4, pos, W - 2, pos + bar], fill=LINE)


def empty(d, title, lines, warn=None, top=50):
    d.text((W // 2, top), title, font=font("bold", 12), fill=TEXT, anchor="ma")
    y = top + 19
    for line in lines:
        d.text((W // 2, y), line, font=font("sans", 10), fill=DIM, anchor="ma")
        y += 14
    if warn:
        d.text((W // 2, y + 4), warn, font=font("bold", 9), fill=AMBER, anchor="ma")


def vendor_color(name):
    if not name:
        return FAINT
    return [AMBER, BLUE, GREEN, (232, 96, 200), (120, 220, 220), RED][zlib.crc32(name.encode()) % 6]


def nice(v):
    """Round a graph ceiling up to 1/2/5 x 10^n."""
    if v <= 0:
        return 1.0
    p = 10 ** int(f"{v:e}".split("e")[1])
    for m in (1, 2, 5, 10):
        if v <= m * p:
            return m * p
    return 10 * p


def ms(v, prec=None):
    if prec is None:
        prec = 2 if v < 1 else (1 if v < 10 else 0)
    return f"{v:.{prec}f}ms" if prec else f"{v:.0f}ms"


def ago(seconds):
    if seconds is None:
        return "—"
    s = int(seconds)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    return f"{s // 3600}h ago"


def duration(seconds):
    s = int(seconds)
    if s % 86400 == 0 and s:
        return f"{s // 86400}d"
    if s % 3600 == 0 and s:
        return f"{s // 3600}h"
    if s >= 3600:
        return f"{s / 3600:.1f}h"
    return f"{s // 60}m" if s >= 60 else f"{s}s"
