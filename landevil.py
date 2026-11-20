#!/usr/bin/env python3
"""
LAN Devil for CardputerZero.

Plug the Cardputer's Ethernet port into a switch: the home screen shows
link speed, your DHCP lease, and what you're plugged into (switch name,
port, VLAN, mgmt IP) from LLDP/CDP. Ping (with a live RTT graph), ARP
sweep and a TCP port grid are one key away. Same tool as the Pi and S31
builds; here the keyboard and screen are the control plane, so there's
no BLE or Wi-Fi AP.

Keys:  Left/Right or Tab  switch screen    Up/Down  scroll
       Enter              run              Esc      cancel / back
       hold Esc           exit to launcher

  landevil.py                 run on the device (APPLaunch starts it as root)
  landevil.py --preview DIR   render store screenshots with demo data (no device)
"""

import argparse
import os
import signal
import sys
import threading
import time
import zlib

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import netdiag  # noqa: E402
from device import KEY, keychar  # noqa: E402

VERSION = "0.1.0"
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
DKGREEN = (24, 70, 38)

SCREENS = ["STAT", "PING", "ARP", "PORT"]
LONG_PRESS = 0.8

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
    if len(_fit_cache) > 2000:
        _fit_cache.clear()
    _fit_cache[key] = text
    return text


def _asset(name, size=None):
    try:
        im = Image.open(os.path.join(HERE, "assets", name)).convert("RGB")
        return im.resize(size, Image.LANCZOS) if size else im
    except OSError:
        return None


LOGO_SMALL = _asset("logo120.png", (15, 15))
LOGO_BIG = _asset("logo120.png", (112, 112))


# ---------------------------------------------------------------------------
# Little drawn icons (no glyph-coverage worries on the device font)
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


def keycap(d, x, y, label, action):
    """Footer hint: [key] action. Returns the x after it."""
    f, fa = font("bold", 8), font("sans", 9)
    if label in ("lr", "ud"):
        w = 18
    else:
        w = int(d.textlength(label, font=f)) + 8
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
    return x + int(d.textlength(action, font=fa)) + 10


def rj45(d, x, y, w, h, col):
    """An RJ45 jack outline, used for the 'plug me in' state."""
    d.rounded_rectangle([x, y, x + w, y + h], radius=3, outline=col, width=2)
    pw = w // 9
    for i in range(8):
        px = x + 6 + i * ((w - 12) // 8)
        d.rectangle([px, y + 5, px + pw - 1, y + 5 + h // 4], fill=col)
    notch = w // 3
    d.rectangle([x + notch, y + h - 2, x + w - notch, y + h + 5], outline=col, width=2)


def vendor_color(name):
    if not name:
        return FAINT
    hue = zlib.crc32(name.encode()) % 6
    return [(255, 172, 28), (88, 170, 255), (72, 208, 104),
            (232, 96, 200), (120, 220, 220), (232, 64, 52)][hue]


# ---------------------------------------------------------------------------
# Jobs: one active probe per screen, Esc cancels.
# ---------------------------------------------------------------------------

class Job:
    def __init__(self, fn, *args):
        self.lines = []
        self.data = {}
        self.stop = threading.Event()
        self.running = True
        self.started = time.monotonic()
        self._lock = threading.Lock()
        threading.Thread(target=self._run, args=(fn, args), daemon=True).start()

    def emit(self, line):
        with self._lock:
            self.lines.append(line)
            del self.lines[:-300]

    def _run(self, fn, args):
        try:
            fn(self, *args)
        except Exception as e:  # a probe must never take the UI down
            self.emit(f"error: {e}")
        finally:
            self.running = False

    def last(self):
        with self._lock:
            return self.lines[-1] if self.lines else ""


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

class App:
    def __init__(self, demo=None):
        self.demo = demo
        self.iface = demo["iface"] if demo else netdiag.pick_interface()
        self.screen = 0
        self.jobs = {}
        self.scroll = {s: 0 for s in SCREENS}
        self.fields = {"PING": "", "PORT": ""}
        self.shift = False
        self.esc_down = None
        self.hint_until = 0
        self.quit = False
        self.started = time.monotonic()
        self.facts = {}
        self.facts_at = 0
        self.listener = None
        if not demo:
            self.listener = netdiag.NeighborListener(self.iface)
            self.listener.start()

    # ---- data -----------------------------------------------------------

    def refresh(self):
        if self.demo:
            self.facts = self.demo["facts"]
            return
        now = time.monotonic()
        link = netdiag.link_info(self.iface)
        if now - self.facts_at > 2 or link["up"] != self.facts.get("link", {}).get("up"):
            ip, prefix = netdiag.iface_ipv4(self.iface)
            self.facts = {"ip": ip, "prefix": prefix,
                          "gw": netdiag.default_gateway(self.iface, only=True),
                          "dns": netdiag.dns_servers()}
            self.facts_at = now
            gw = self.facts["gw"] or netdiag.default_gateway(self.iface)
            for k in ("PING", "PORT"):       # prefill targets with the gateway
                if not self.fields[k] and gw:
                    self.fields[k] = gw
        self.facts["link"] = link

    def neighbor(self):
        if self.demo:
            return self.demo.get("neighbor")
        return self.listener.latest()

    # ---- input ----------------------------------------------------------

    def on_key(self, code, value):
        if code in (KEY["LEFTSHIFT"], KEY["RIGHTSHIFT"]):
            self.shift = value != 0
            return
        if code == KEY["ESC"]:
            if value == 1:
                self.esc_down = time.monotonic()
            elif value == 0 and self.esc_down is not None:
                held = time.monotonic() - self.esc_down
                self.esc_down = None
                if held < LONG_PRESS:
                    self.back()
            return
        if value == 0:
            return
        name = SCREENS[self.screen]
        job = self.jobs.get(name)
        running = job is not None and job.running
        if code == KEY["RIGHT"] or (code == KEY["TAB"] and not self.shift):
            self.screen = (self.screen + 1) % len(SCREENS)
        elif code == KEY["LEFT"] or (code == KEY["TAB"] and self.shift):
            self.screen = (self.screen - 1) % len(SCREENS)
        elif code in (KEY["UP"], KEY["PAGEUP"]):
            self.scroll[name] = max(0, self.scroll[name] - (1 if code == KEY["UP"] else 6))
        elif code in (KEY["DOWN"], KEY["PAGEDOWN"]):
            self.scroll[name] += 1 if code == KEY["DOWN"] else 6
        elif code in (KEY["ENTER"], KEY["KPENTER"]):
            if not running:
                self.start(name)
        elif name in self.fields and not running:
            if code == KEY["BACKSPACE"]:
                self.fields[name] = self.fields[name][:-1]
            else:
                c = keychar(code, self.shift)
                if c and c not in " \\" and len(self.fields[name]) < 63:
                    self.fields[name] += c

    def back(self):
        job = self.jobs.get(SCREENS[self.screen])
        if job and job.running:
            job.stop.set()
        elif self.screen != 0:
            self.screen = 0
        else:
            self.hint_until = time.monotonic() + 2.5

    def start(self, name):
        self.scroll[name] = 0
        if name == "PING" and self.fields["PING"]:
            self.jobs[name] = Job(netdiag.ping, self.fields["PING"], self.iface)
        elif name == "ARP":
            self.jobs[name] = Job(netdiag.arp_sweep, self.iface)
        elif name == "PORT" and self.fields["PORT"]:
            self.jobs[name] = Job(netdiag.port_scan, self.fields["PORT"], self.iface)

    def tick(self):
        """Long-press Esc detection that works even without key repeat."""
        if self.esc_down is not None and time.monotonic() - self.esc_down >= LONG_PRESS:
            self.quit = True

    def shutdown(self):
        for j in self.jobs.values():
            j.stop.set()
        if self.listener:
            self.listener.stop()

    # ---- frame ----------------------------------------------------------

    def render(self):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        self.draw_header(img, d)
        getattr(self, "draw_" + SCREENS[self.screen].lower())(d)
        self.draw_footer(d)
        if self.esc_down is not None:            # long-press progress
            frac = min(1.0, (time.monotonic() - self.esc_down) / LONG_PRESS)
            d.rectangle([0, H - 2, int(W * frac), H], fill=RED)
        return img

    def draw_header(self, img, d):
        d.rectangle([0, 0, W, 18], fill=PANEL)
        x = 4
        if LOGO_SMALL:
            img.paste(LOGO_SMALL, (3, 2))
            x = 22
        d.text((x, 2), "LAN", font=font("bold", 12), fill=TEXT)
        d.text((x + d.textlength("LAN ", font=font("bold", 12)), 2), "DEVIL",
               font=font("bold", 12), fill=RED)
        f = font("bold", 9)
        x = W - 4
        for i in reversed(range(len(SCREENS))):
            label = SCREENS[i]
            w = int(d.textlength(label, font=f)) + 10
            x -= w
            job = self.jobs.get(label)
            if i == self.screen:
                d.rounded_rectangle([x, 3, x + w - 2, 15], radius=3, fill=AMBER)
                d.text((x + 4, 4), label, font=f, fill=BG)
            else:
                d.text((x + 4, 4), label, font=f, fill=DIM)
            if job and job.running:                  # busy dot
                d.ellipse([x + w - 5, 2, x + w - 1, 6], fill=GREEN if i != self.screen else BG)
            x -= 2
        d.line([0, 18, W, 18], fill=LINE)

    def draw_footer(self, d):
        y = H - 13
        d.line([0, H - 16, W, H - 16], fill=LINE)
        name = SCREENS[self.screen]
        job = self.jobs.get(name)
        if time.monotonic() < self.hint_until:
            d.text((5, y), "Hold Esc to exit LAN Devil", font=font("bold", 9), fill=AMBER)
            return
        x = 5
        if job and job.running:
            x = keycap(d, x, y, "Esc", "stop")
        else:
            x = keycap(d, x, y, "lr", "screens")
            if name != "STAT":
                x = keycap(d, x, y, "Enter", "run")
        if name == "ARP":
            keycap(d, x, y, "ud", "scroll")
        elif name == "STAT":
            keycap(d, x, y, "Esc", "hold to exit")

    # ---- STATUS ---------------------------------------------------------

    def draw_stat(self, d):
        f = self.facts
        link = f.get("link", {})
        up = link.get("up")

        # link pill + speed ladder
        y = 23
        pill = "LINK UP" if up else ("NO LINK" if link.get("present", True) else "NO PORT")
        pw = int(d.textlength(pill, font=font("bold", 10))) + 16
        d.rounded_rectangle([5, y, 5 + pw, y + 15], radius=7, fill=DKGREEN if up else (70, 22, 20))
        d.ellipse([9, y + 5, 14, y + 10], fill=GREEN if up else RED)
        d.text((17, y + 2), pill, font=font("bold", 10), fill=GREEN if up else RED)
        sx = 12 + pw
        speed = link.get("speed") or 0
        for label, val in (("10", 10), ("100", 100), ("1G", 1000)):
            lw = int(d.textlength(label, font=font("bold", 8))) + 8
            lit = up and speed >= val
            d.rounded_rectangle([sx, y + 2, sx + lw, y + 13], radius=2,
                                fill=AMBER if lit else PANEL, outline=None if lit else LINE)
            d.text((sx + 4, y + 3), label, font=font("bold", 8), fill=BG if lit else FAINT)
            sx += lw + 3
        if up and link.get("duplex"):
            d.text((sx + 3, y + 3), link["duplex"].upper(), font=font("bold", 8), fill=DIM)
        d.text((W - 6, y + 2), self.iface, font=font("monob", 11), fill=DIM, anchor="ra")

        # address block
        y = 42
        if f.get("ip"):
            ip = f["ip"]
            d.text((6, y), ip, font=font("monob", 15), fill=TEXT)
            d.text((8 + d.textlength(ip, font=font("monob", 15)), y + 4), f"/{f['prefix']}",
                   font=font("mono", 10), fill=DIM)
        else:
            msg = "waiting for DHCP…" if up else "no address"
            d.text((6, y + 2), msg, font=font("bold", 12), fill=AMBER if up else FAINT)
        rx = 196
        self.kv(d, rx, y - 1, "GW", f.get("gw") or "—", W - rx - 4)
        dns = f.get("dns") or []
        self.kv(d, rx, y + 10, "DNS", dns[0] if dns else "—", W - rx - 4)

        # neighbor card
        top, bot = 66, H - 19
        n = self.neighbor()
        accent = AMBER if n else (LINE if not up else (120, 90, 30))
        d.rounded_rectangle([4, top, W - 5, bot], radius=6, fill=PANEL, outline=LINE)
        d.rounded_rectangle([4, top, 8, bot], radius=2, fill=accent)
        if n:
            self.draw_neighbor(d, n, top)
        else:
            self.draw_listening(d, top, bot, up)

    def draw_neighbor(self, d, n, top):
        tag = n["proto"]
        tw = int(d.textlength(tag, font=font("bold", 8))) + 8
        d.rounded_rectangle([14, top + 5, 14 + tw, top + 15], radius=3, fill=AMBER)
        d.text((18, top + 6), tag, font=font("bold", 8), fill=BG)
        age = n.get("age")
        when = "cached" if age is None else ("just now" if age < 2 else f"{int(age)}s ago")
        d.text((W - 12, top + 5), when, font=font("sans", 9), fill=DIM, anchor="ra")
        d.text((14, top + 18), fit(d, n.get("name") or "unknown", font("bold", 15), W - 30),
               font=font("bold", 15), fill=TEXT)
        # three chips: PORT / VLAN / MGMT
        cy = top + 39
        port = n.get("port") or "?"
        chips = [("PORT", port, 110), ("VLAN", str(n["vlan"]) if n.get("vlan") else "—", 54),
                 ("MGMT", n.get("mgmt_ip") or "—", W - 20 - 110 - 54 - 8)]
        cx = 14
        for label, val, cw in chips:
            d.rounded_rectangle([cx, cy, cx + cw - 4, cy + 25], radius=4, fill=PANEL2)
            d.text((cx + 5, cy + 2), label, font=font("bold", 7), fill=DIM)
            d.text((cx + 5, cy + 11), fit(d, val, font("monob", 11), cw - 13),
                   font=font("monob", 11), fill=AMBER if label == "VLAN" and val != "—" else TEXT)
            cx += cw
        sub = n.get("platform") or n.get("port_descr")
        if sub:
            d.text((14, cy + 28), fit(d, sub, font("sans", 9), W - 30), font=font("sans", 9), fill=DIM)

    def draw_listening(self, d, top, bot, up):
        err = None if self.demo else self.listener.error
        cx, cy = 40, (top + bot) // 2
        if not up:
            rj45(d, cx - 18, cy - 15, 36, 24, FAINT)
            d.text((74, top + 14), "Plug into a switch port", font=font("bold", 13), fill=TEXT)
            d.text((74, top + 34), "Switch, port, VLAN & mgmt IP", font=font("sans", 10), fill=DIM)
            d.text((74, top + 48), "appear here from LLDP / CDP.", font=font("sans", 10), fill=DIM)
            return
        if err:
            d.text((20, top + 12), "Neighbor capture unavailable", font=font("bold", 12), fill=RED)
            d.text((20, top + 32), fit(d, err, font("mono", 10), W - 40), font=font("mono", 10), fill=DIM)
            return
        # radar pulse
        t = time.monotonic()
        for k in range(3):
            ph = ((t * 0.8) + k / 3) % 1.0
            r = 4 + ph * 22
            c = tuple(int(a * (1 - ph) + b * ph) for a, b in zip(AMBER, PANEL))
            d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=c, width=2)
        d.ellipse([cx - 4, cy - 4, cx + 4, cy + 4], fill=AMBER)
        since = self.listener.listen_since if self.listener else self.started
        waited = time.monotonic() - since
        d.text((74, top + 12), "Listening for LLDP / CDP", font=font("bold", 13), fill=AMBER)
        d.text((74, top + 32), "Switches announce every 30-60s.", font=font("sans", 10), fill=DIM)
        # 60 s progress bar
        bx0, bx1, by = 74, W - 14, top + 52
        d.rounded_rectangle([bx0, by, bx1, by + 6], radius=3, fill=PANEL2)
        frac = min(1.0, waited / 60)
        if frac > 0.02:
            d.rounded_rectangle([bx0, by, bx0 + int((bx1 - bx0) * frac), by + 6], radius=3,
                                fill=AMBER if waited < 60 else FAINT)
        msg = f"{int(waited)}s" if waited < 60 else f"{int(waited)}s · unmanaged switch?"
        d.text((74, by + 9), msg, font=font("sans", 9), fill=DIM)

    def kv(self, d, x, y, k, v, width):
        d.text((x, y + 2), k, font=font("bold", 7), fill=DIM)
        d.text((x + 22, y), fit(d, v, font("mono", 10), width - 22), font=font("mono", 10), fill=TEXT)

    # ---- shared: target field ------------------------------------------

    def draw_field(self, d, name, label, right_w=0):
        job = self.jobs.get(name)
        running = job is not None and job.running
        d.text((6, 25), label, font=font("bold", 10), fill=DIM)
        x0 = 8 + int(d.textlength(label, font=font("bold", 10))) + 4
        x1 = W - 6 - right_w
        d.rounded_rectangle([x0, 22, x1, 39], radius=4, fill=PANEL,
                            outline=LINE if running else AMBER)
        txt = fit(d, self.fields[name], font("monob", 12), x1 - x0 - 14)
        d.text((x0 + 5, 24), txt, font=font("monob", 12), fill=TEXT)
        if not running and int(time.monotonic() * 2) % 2 == 0:
            cx = x0 + 6 + d.textlength(txt, font=font("monob", 12))
            d.rectangle([cx, 25, cx + 1, 36], fill=AMBER)

    def empty(self, d, title, lines, warn=None, top=50):
        d.text((W // 2, top), title, font=font("bold", 12), fill=TEXT, anchor="ma")
        y = top + 19
        for line in lines:
            d.text((W // 2, y), line, font=font("sans", 10), fill=DIM, anchor="ma")
            y += 14
        if warn:
            d.text((W // 2, y + 4), warn, font=font("bold", 9), fill=AMBER, anchor="ma")

    # ---- PING -----------------------------------------------------------

    def draw_ping(self, d):
        self.draw_field(d, "PING", "PING")
        job = self.jobs.get("PING")
        if not job:
            self.empty(d, "Live latency graph",
                       [f"Pings the target once a second over {self.iface},",
                        "up to 60 times.  Hostnames use DHCP's DNS."])
            return
        data = job.data
        rtts = data.get("rtts") or []
        got = [r for r in rtts if r is not None]
        sent = data.get("sent", 0)

        # graph
        gx0, gy0, gx1, gy1 = 6, 44, W - 6, 112
        d.rounded_rectangle([gx0, gy0, gx1, gy1], radius=4, fill=PANEL)
        if not rtts:
            msg = job.last() if not job.running else f"pinging {data.get('ip') or data.get('target')}…"
            d.text(((gx0 + gx1) // 2, (gy0 + gy1) // 2 - 6), fit(d, msg, font("sans", 10), gx1 - gx0 - 10),
                   font=font("sans", 10), fill=RED if not job.running else DIM, anchor="ma")
        else:
            top = max(got) if got else 1.0
            scale = _nice(top * 1.15)
            for frac in (0.5, 1.0):
                yy = gy1 - 4 - int((gy1 - gy0 - 12) * frac)
                for xx in range(gx0 + 4, gx1 - 30, 4):
                    d.point((xx, yy), fill=LINE)
                d.text((gx1 - 4, yy - 5), _ms(scale * frac), font=font("sans", 8), fill=FAINT, anchor="ra")
            bw, gap = 5, 2
            maxbars = (gx1 - gx0 - 40) // (bw + gap)
            shown = rtts[-maxbars:]
            avg = sum(got) / len(got) if got else 0
            for i, r in enumerate(shown):
                bx = gx0 + 5 + i * (bw + gap)
                if r is None:
                    d.line([bx, gy1 - 10, bx + bw - 1, gy1 - 4], fill=RED, width=2)
                    d.line([bx, gy1 - 4, bx + bw - 1, gy1 - 10], fill=RED, width=2)
                    continue
                h = max(2, int((gy1 - gy0 - 12) * min(1.0, r / scale)))
                col = GREEN if r <= avg * 1.5 or r < 2 else AMBER
                d.rectangle([bx, gy1 - 4 - h, bx + bw - 1, gy1 - 4], fill=col)

        # stat tiles
        loss = 100 * (sent - len(got)) / sent if sent else 0
        tiles = [("TARGET", data.get("ip") or data.get("target") or "—", TEXT),
                 ("RECV", f"{len(got)}/{sent}", TEXT),
                 ("LOSS", f"{loss:.0f}%", GREEN if loss == 0 else (AMBER if loss < 20 else RED)),
                 ("AVG", _ms(sum(got) / len(got)) if got else "—", TEXT),
                 ("MIN/MAX ms", f"{min(got):.1f}/{max(got):.1f}" if got else "—", TEXT)]
        widths = [84, 54, 42, 56, 72]
        x, y = 6, 116
        for (label, val, col), tw in zip(tiles, widths):
            d.rounded_rectangle([x, y, x + tw - 3, y + 34], radius=4, fill=PANEL)
            d.text((x + 5, y + 4), label, font=font("bold", 7), fill=DIM)
            d.text((x + 5, y + 16), fit(d, val, font("monob", 11), tw - 12), font=font("monob", 11), fill=col)
            x += tw

    # ---- ARP ------------------------------------------------------------

    def draw_arp(self, d):
        job = self.jobs.get("ARP")
        if not job:
            self.empty(d, "ARP sweep",
                       ["One ARP request to every address in your",
                        "subnet (capped at a /24), then lists who answered",
                        "with MAC and vendor."],
                       warn="Active scan · authorized networks only", top=34)
            return
        data = job.data
        hosts = data.get("hosts") or []
        d.text((6, 23), "ARP", font=font("bold", 11), fill=TEXT)
        d.text((32, 24), data.get("net") or "", font=font("mono", 10), fill=DIM)
        badge = f"{len(hosts)} hosts"
        bw = int(d.textlength(badge, font=font("bold", 9))) + 10
        d.rounded_rectangle([W - 6 - bw, 22, W - 6, 35], radius=6, fill=AMBER if hosts else PANEL2)
        d.text((W - 6 - bw // 2, 24), badge, font=font("bold", 9), fill=BG if hosts else DIM, anchor="ma")

        y = 39
        if job.running:
            total, sent = data.get("total") or 1, data.get("sent", 0)
            d.rounded_rectangle([6, y, W - 6, y + 4], radius=2, fill=PANEL2)
            d.rounded_rectangle([6, y, 6 + int((W - 12) * sent / total), y + 4], radius=2, fill=AMBER)
        y += 7
        if not hosts:
            msg = "listening for replies…" if job.running else (job.last() or "no replies")
            d.text((W // 2, y + 36), msg, font=font("sans", 10), fill=DIM, anchor="ma")
            return
        # column header
        d.text((16, y), "IP", font=font("bold", 7), fill=FAINT)
        d.text((104, y), "MAC", font=font("bold", 7), fill=FAINT)
        d.text((214, y), "VENDOR", font=font("bold", 7), fill=FAINT)
        y += 10
        lh, rows = 11, (H - 18 - y) // 11
        self.scroll["ARP"] = min(self.scroll["ARP"], max(0, len(hosts) - rows))
        start = self.scroll["ARP"]
        f = font("mono", 9)
        for i, (ip, mac, ven) in enumerate(hosts[start:start + rows]):
            ry = y + i * lh
            if (start + i) % 2 == 0:
                d.rectangle([4, ry - 1, W - 6, ry + lh - 2], fill=PANEL)
            d.ellipse([7, ry + 2, 11, ry + 6], fill=vendor_color(ven))
            d.text((16, ry), ip, font=f, fill=TEXT)
            d.text((104, ry), mac, font=f, fill=DIM)
            d.text((214, ry), fit(d, ven or "unknown", font("sans", 9), W - 222), font=font("sans", 9),
                   fill=TEXT if ven else FAINT)
        if len(hosts) > rows:
            track = rows * lh
            bar = max(8, track * rows // len(hosts))
            pos = y + (track - bar) * start // max(1, len(hosts) - rows)
            d.rectangle([W - 4, pos, W - 2, pos + bar], fill=LINE)

    # ---- PORTS ----------------------------------------------------------

    def draw_port(self, d):
        job = self.jobs.get("PORT")
        state = job.data.get("state", {}) if job else {}
        n_open = sum(1 for v in state.values() if v == "open")
        done = sum(1 for v in state.values() if v in ("open", "closed"))
        self.draw_field(d, "PORT", "SCAN", right_w=66 if job else 0)
        if job:
            lab = f"{n_open} open" if not job.running else f"{done}/{len(netdiag.COMMON_PORTS)}"
            d.rounded_rectangle([W - 66, 22, W - 6, 39], radius=4,
                                fill=DKGREEN if n_open and not job.running else PANEL)
            d.text((W - 36, 25), lab, font=font("bold", 10),
                   fill=GREEN if n_open else DIM, anchor="ma")
        if job and not state and not job.running:
            d.text((W // 2, 90), job.last() or "failed", font=font("sans", 10), fill=RED, anchor="ma")
            return
        cols, tw, th = 7, 44, 26
        x0, y0 = 6, 44
        for i, (port, svc) in enumerate(netdiag.COMMON_PORTS):
            x = x0 + (i % cols) * tw
            y = y0 + (i // cols) * (th + 1)
            st = state.get(port)
            if st == "open":
                fill, fg, sub, outline = GREEN, BG, (16, 60, 28), None
            elif st == "scanning":
                fill, fg, sub, outline = PANEL, AMBER, DIM, AMBER
            elif st == "closed":
                fill, fg, sub, outline = PANEL, FAINT, FAINT, None
            else:
                fill, fg, sub, outline = BG, DIM, FAINT, LINE
            d.rounded_rectangle([x, y, x + tw - 3, y + th - 1], radius=4, fill=fill, outline=outline)
            d.text((x + (tw - 3) // 2, y + 3), str(port), font=font("monob", 10), fill=fg, anchor="ma")
            d.text((x + (tw - 3) // 2, y + 15), fit(d, svc, font("sans", 7), tw - 6),
                   font=font("sans", 7), fill=sub, anchor="ma")
        if not job:
            d.text((W // 2, y0 + 4 * (th + 1) + 1), "TCP connect scan · authorized targets only",
                   font=font("bold", 8), fill=AMBER, anchor="ma")


def _nice(v):
    """Round a graph ceiling up to 1/2/5 x 10^n."""
    if v <= 0:
        return 1.0
    p = 10 ** int(f"{v:e}".split("e")[1])
    for m in (1, 2, 5, 10):
        if v <= m * p:
            return m * p
    return 10 * p


def _ms(v, prec=None):
    if prec is None:
        prec = 2 if v < 1 else (1 if v < 10 else 0)
    return f"{v:.{prec}f}ms" if prec else f"{v:.0f}ms"


# ---------------------------------------------------------------------------
# Splash
# ---------------------------------------------------------------------------

def splash():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if LOGO_BIG:
        img.paste(LOGO_BIG, (14, (H - 112) // 2))
    x = 140
    d.text((x, 44), "LAN", font=font("bold", 30), fill=TEXT)
    d.text((x, 76), "DEVIL", font=font("bold", 30), fill=RED)
    d.text((x + 2, 116), f"pocket network ID · v{VERSION}", font=font("sans", 9), fill=DIM)
    return img


# ---------------------------------------------------------------------------
# Preview: deterministic store screenshots with demo data
# ---------------------------------------------------------------------------

def demo_data():
    return {
        "iface": "eth0",
        "facts": {"ip": "10.20.0.57", "prefix": 24, "gw": "10.20.0.1",
                  "dns": ["10.20.0.1", "1.1.1.1"],
                  "link": {"present": True, "up": True, "speed": 100,
                           "duplex": "full", "mac": "b8:27:eb:4c:11:2e"}},
        "neighbor": {"proto": "LLDP", "name": "sw-closet-3.example.lan",
                     "port": "Gi1/0/24", "port_descr": None, "vlan": 20,
                     "mgmt_ip": "10.20.0.2", "age": 14,
                     "platform": "Cisco IOS Software, C2960X Software, Version 15.2(7)E8"},
    }


class _Done(Job):
    def __init__(self, data, lines=(), running=False):
        self.lines, self.data, self.running = list(lines), data, running
        self.stop = threading.Event()
        self._lock = threading.Lock()


def preview(out_dir):
    import random
    random.seed(7)
    os.makedirs(out_dir, exist_ok=True)
    app = App(demo=demo_data())
    app.refresh()
    app.fields = {"PING": "10.20.0.1", "PORT": "10.20.0.40"}
    shots = [("splash", splash())]

    app.screen = 0
    shots.append(("status", app.render()))

    app.screen = 1
    rtts = [round(random.uniform(0.45, 0.75), 3) for _ in range(38)]
    rtts[17], rtts[29] = 2.9, None
    rtts[30] = 1.4
    app.jobs["PING"] = _Done({"target": "10.20.0.1", "ip": "10.20.0.1",
                              "rtts": rtts, "sent": len(rtts)}, running=True)
    shots.append(("ping", app.render()))

    app.screen = 2
    hosts = [("10.20.0.1", "00:1a:2b:3c:4d:01", "Ubiquiti Inc"),
             ("10.20.0.2", "00:25:84:aa:10:3f", "Cisco Systems, Inc"),
             ("10.20.0.11", "3c:52:82:19:7e:c0", "Hewlett Packard"),
             ("10.20.0.23", "dc:a6:32:08:5b:91", "Raspberry Pi Trading Ltd"),
             ("10.20.0.40", "00:11:32:9f:02:aa", "Synology Incorporated"),
             ("10.20.0.88", "f0:9f:c2:71:4e:13", "Ubiquiti Inc"),
             ("10.20.0.102", "a4:83:e7:2d:19:6c", "Apple, Inc."),
             ("10.20.0.131", "00:80:92:5e:22:07", "Silex Technology"),
             ("10.20.0.200", "b8:27:eb:90:aa:01", "Raspberry Pi Foundation")]
    app.jobs["ARP"] = _Done({"net": "10.20.0.0/24", "total": 253, "sent": 253, "hosts": hosts})
    shots.append(("arp", app.render()))

    app.screen = 3
    opened = {22, 80, 139, 443, 445, 5000}
    state = {p: ("open" if p in opened else "closed") for p, _ in netdiag.COMMON_PORTS}
    app.jobs["PORT"] = _Done({"target": "10.20.0.40", "ip": "10.20.0.40", "state": state})
    shots.append(("ports", app.render()))

    for name, img in shots:
        p = os.path.join(out_dir, f"{name}.png")
        img.save(p)
        print(p)


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="LAN Devil for CardputerZero")
    ap.add_argument("--preview", metavar="DIR", help="render demo screenshots and exit")
    args = ap.parse_args()
    if args.preview:
        preview(args.preview)
        return 0

    from device import Framebuffer, Keyboard
    try:
        fb = Framebuffer()
    except (OSError, RuntimeError) as e:
        print(f"landevil: framebuffer: {e}", file=sys.stderr)
        return 1
    fb.show(splash())
    shown_at = time.monotonic()
    kbd = Keyboard()
    app = App()

    def on_signal(*_):
        app.quit = True
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        app.refresh()
        time.sleep(max(0, 1.2 - (time.monotonic() - shown_at)))
        kbd.poll(0)                         # drop the launcher's Enter keypress
        while not app.quit:
            app.refresh()
            fb.show(app.render())
            radar = (app.screen == 0 and app.facts.get("link", {}).get("up")
                     and not app.neighbor())
            busy = (any(j.running for j in app.jobs.values()) or app.esc_down is not None
                    or radar)
            for code, value in kbd.poll(0.08 if busy else 0.25):
                app.on_key(code, value)
            app.tick()
    finally:
        app.shutdown()
        try:
            fb.show(Image.new("RGB", (fb.w, fb.h), (0, 0, 0)))
        finally:
            fb.close()
            kbd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
