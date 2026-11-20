"""
ui.py -- palette, fonts and small drawing helpers shared by every screen.

Everything is drawn with Pillow primitives so nothing depends on glyph
coverage in the device's font (arrows, warning signs, etc. are drawn).
"""

import os
import zlib

from PIL import Image, ImageFont

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
