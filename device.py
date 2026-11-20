"""
device.py -- CardputerZero screen + keyboard, with no compiled deps.

Display: mmap the ST7789V framebuffer. Per the APPLaunch contract we never
hard-code /dev/fb0 (fb0 may be HDMI): honour APPLAUNCH_LINUX_FBDEV_DEVICE /
LV_LINUX_FBDEV_DEVICE, else find the LCD in /proc/fb (`panel-mipi-dbid` on
the current Debian 13 image, `fb_st7789v` on older ones).

Keyboard: read struct input_event straight off /dev/input/eventN, so the
app doesn't need python3-evdev. Emits (keycode, value) with value
1=press, 0=release, 2=autorepeat.
"""

import fcntl
import glob
import mmap
import os
import select
import struct

try:
    import numpy as np
except ImportError:          # works without numpy, just slower per frame
    np = None

FBIOGET_VSCREENINFO = 0x4600
FBIOGET_FSCREENINFO = 0x4602
FIX_FMT = "16sL" + "I" * 6 + "HHHI"


def find_fb():
    for var in ("APPLAUNCH_LINUX_FBDEV_DEVICE", "LV_LINUX_FBDEV_DEVICE", "LANDEVIL_FB"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        with open("/proc/fb") as f:
            for line in f:
                num, _, name = line.strip().partition(" ")
                # Stock image: "panel-mipi-dbid" (DRM mipi-dbi); older: "fb_st7789v"
                if any(k in name.lower() for k in ("st7789", "mipi-dbi")):
                    return f"/dev/fb{num}"
    except OSError:
        pass
    return "/dev/fb0"


class Framebuffer:
    def __init__(self, path=None):
        self.path = path or find_fb()
        self.fd = os.open(self.path, os.O_RDWR)
        vbuf = bytearray(160)
        fcntl.ioctl(self.fd, FBIOGET_VSCREENINFO, vbuf)
        self.w, self.h, _, _, _, _, self.bpp = struct.unpack_from("7I", vbuf, 0)
        fbuf = bytearray(struct.calcsize(FIX_FMT))
        fcntl.ioctl(self.fd, FBIOGET_FSCREENINFO, fbuf)
        fields = struct.unpack(FIX_FMT, fbuf)
        self.smem_len, self.line_length = fields[2], fields[8]
        if self.bpp not in (16, 32):
            raise RuntimeError(f"{self.path}: unsupported {self.bpp} bpp")
        self.mm = mmap.mmap(self.fd, self.smem_len, mmap.MAP_SHARED,
                            mmap.PROT_READ | mmap.PROT_WRITE)

    def show(self, img):
        if img.size != (self.w, self.h):
            img = img.resize((self.w, self.h))
        data = to_rgb565(img) if self.bpp == 16 else img.convert("RGBX").tobytes("raw", "BGRX")
        row = self.w * (self.bpp // 8)
        if self.line_length == row:
            self.mm.seek(0)
            self.mm.write(data)
        else:
            for y in range(self.h):
                self.mm.seek(y * self.line_length)
                self.mm.write(data[y * row:(y + 1) * row])

    def close(self):
        try:
            self.mm.close()
        finally:
            os.close(self.fd)


def to_rgb565(img):
    img = img.convert("RGB")
    if np is not None:
        a = np.asarray(img, dtype=np.uint16)
        v = ((a[..., 0] >> 3) << 11) | ((a[..., 1] >> 2) << 5) | (a[..., 2] >> 3)
        return v.astype("<u2").tobytes()
    out = bytearray()
    for r, g, b in img.getdata():
        v = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        out += bytes((v & 0xFF, v >> 8))
    return bytes(out)


# ---------------------------------------------------------------------------
# Keyboard
# ---------------------------------------------------------------------------

EV_KEY = 1
EVENT_FMT = "llHHi"                       # struct input_event on 64-bit Linux
EVENT_SIZE = struct.calcsize(EVENT_FMT)
CARDPUTER_KBD = "/dev/input/by-path/platform-3f804000.i2c-event"


def _keyboard_paths():
    if os.path.exists(CARDPUTER_KBD):
        return [CARDPUTER_KBD]
    # Fall back to anything the kernel tags as a keyboard (USB keyboards too).
    paths, block = [], {}
    try:
        with open("/proc/bus/input/devices") as f:
            for line in f.read().split("\n") + [""]:
                if line.startswith("H: Handlers="):
                    block["h"] = line.split("=", 1)[1].split()
                elif line.startswith("B: EV="):
                    block["ev"] = int(line.split("=", 1)[1], 16)
                elif not line.strip():
                    if block.get("ev", 0) & (1 << EV_KEY) and "kbd" in block.get("h", []):
                        paths += [f"/dev/input/{h}" for h in block["h"] if h.startswith("event")]
                    block = {}
    except OSError:
        pass
    return paths or sorted(glob.glob("/dev/input/event*"))


class Keyboard:
    def __init__(self):
        self.fds = []
        for p in _keyboard_paths():
            try:
                self.fds.append(os.open(p, os.O_RDONLY | os.O_NONBLOCK))
            except OSError:
                pass

    def poll(self, timeout):
        """Return a list of (code, value) key events, waiting up to `timeout`."""
        if not self.fds:
            select.select([], [], [], timeout)
            return []
        r, _, _ = select.select(self.fds, [], [], timeout)
        events = []
        for fd in r:
            while True:
                try:
                    data = os.read(fd, EVENT_SIZE * 32)
                except BlockingIOError:
                    break
                except OSError:
                    break
                if not data:
                    break
                for off in range(0, len(data) - EVENT_SIZE + 1, EVENT_SIZE):
                    _, _, typ, code, value = struct.unpack_from(EVENT_FMT, data, off)
                    if typ == EV_KEY:
                        events.append((code, value))
        return events

    def close(self):
        for fd in self.fds:
            os.close(fd)


# Linux input keycodes -> characters (unshifted, shifted). Only what a
# hostname / IP field needs, plus a few symbols.
KEY = dict(ESC=1, BACKSPACE=14, TAB=15, ENTER=28, LEFTSHIFT=42, RIGHTSHIFT=54,
           SPACE=57, UP=103, DOWN=108, LEFT=105, RIGHT=106, PAGEUP=104,
           PAGEDOWN=109, HOME=102, END=107, DELETE=111, KPENTER=96,
           LEFTCTRL=29, LEFTALT=56, FN=0x1d0)

_ROWS = {2: "1234567890-=", 16: "qwertyuiop[]", 30: "asdfghjkl;'`", 44: "zxcvbnm,./"}
_SHIFT = dict(zip("1234567890-=[];'`,./", "!@#$%^&*()_+{}:\"~<>?"))
CHARS = {}
for start, row in _ROWS.items():
    for i, c in enumerate(row):
        CHARS[start + i] = c
CHARS[43] = "\\"
CHARS[57] = " "


def keychar(code, shift):
    c = CHARS.get(code)
    if c is None:
        return None
    if shift:
        return c.upper() if c.isalpha() else _SHIFT.get(c, c)
    return c
