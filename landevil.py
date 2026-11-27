#!/usr/bin/env python3
"""
LAN Devil for CardputerZero.

Plug the Cardputer's Ethernet port into a switch: the home screen shows
link speed, flaps, your DHCP lease, and what you're plugged into (switch,
port, VLAN, voice VLAN, PoE, mgmt IP) from LLDP/CDP. Tabs for a DHCP
rogue-server probe, trunk VLAN discovery + join, ping with a live RTT
graph, DNS / internet / traceroute checks, ARP sweep, a TCP port grid, and
a CSV log of every port you visit. 802.1X ports are flagged on STAT.

Keys:  Left/Right or Tab  switch screen    Up/Down  scroll / select
       Enter              run              Esc      cancel / back
       Ctrl+S or Print    save a screenshot to ~/landevil/screenshots/
       hold Esc           exit to launcher

  landevil.py                 run on the device (APPLaunch starts it via sudo)
  landevil.py --window        run fullscreen in a desktop window (uConsole)
  landevil.py --windowed      same, in a normal window (F11 toggles fullscreen)
  landevil.py --preview DIR   render screenshots with demo data (no device)
"""

import argparse
import os
import signal
import sys
import threading
import time

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import dhcp  # noqa: E402
import netdiag  # noqa: E402
import portlog  # noqa: E402
import vlan  # noqa: E402
from device import KEY, keychar  # noqa: E402
from portlog import PortLog  # noqa: E402
from ui import (AMBER, BG, BLUE, DIM, DKAMBER, DKGREEN, DKRED, FAINT, GREEN, H,  # noqa: E402
                LINE, PANEL, PANEL2, RED, TEXT, W, ago, badge, canvas, duration, empty,
                fit, font, keycap, ms, nice, paste_asset, rj45, scrollbar, set_scale, tag,
                vendor_color, warn_icon)

VERSION = "0.3.1"
SCREENS = ["STAT", "DHCP", "VLAN", "PING", "NET", "ARP", "PORT", "LOG"]
LONG_PRESS = 0.8
KEY_S, KEY_X = 31, 45
KEY_RIGHTCTRL, KEY_SYSRQ = 97, 99           # SysRq = the Print key


HOST_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:")
FIELD_RULES = {                       # screen -> (allowed(c), max length)
    "PING": (lambda c: c in HOST_CHARS, 63),
    "PORT": (lambda c: c in HOST_CHARS, 63),
    "NET": (lambda c: c in HOST_CHARS, 63),
    "VLAN": (lambda c: c.isdigit(), 4),
    "LOG": (lambda c: c.isprintable(), 40),
}


# ---------------------------------------------------------------------------
# Jobs: background probes, streamed into job.data, Esc cancels.
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
        self.vjoin = None                  # VLAN join Job
        self.scroll = {s: 0 for s in SCREENS}
        self.fields = {k: "" for k in FIELD_RULES}
        self.shift = False
        self.ctrl = False
        self.esc_down = None
        self.hint_until = 0
        self.flash = None                  # (text, colour, until)
        self.quit = False
        self.started = time.monotonic()
        self.facts = {}
        self.facts_at = 0
        self.fields["NET"] = "example.com"
        self._dns = (None, 0, [])          # (ip, when, servers): per-port DNS cache
        self.listener = None
        self.cc_base = None
        self.link_changed_at = None
        self._was_up = None
        self.pending_auto = None           # (key, first_seen)
        self.log = PortLog(demo.get("log_path")) if demo else PortLog()
        if not demo:
            self.cc_base = netdiag.carrier_changes(self.iface)
            self.listener = netdiag.NeighborListener(self.iface)
            self.listener.start()

    # ---- data -----------------------------------------------------------

    @property
    def joined(self):
        j = self.vjoin
        return j.data if j and j.data.get("state") == "up" else None

    @property
    def test_iface(self):
        """Where active probes run: the joined VLAN, else the physical port."""
        return self.joined["iface"] if self.joined else self.iface

    def flaps(self):
        if self.demo:
            return self.demo.get("flaps", 0)
        cc = netdiag.carrier_changes(self.iface)
        if cc is None or self.cc_base is None:
            return 0
        return max(0, cc - self.cc_base) // 2

    def refresh(self):
        if self.demo:
            self.facts = self.demo["facts"]
            return
        now = time.monotonic()
        link = netdiag.link_info(self.iface)
        if self._was_up is not None and link["up"] != self._was_up:
            self.link_changed_at = now
        self._was_up = link["up"]
        if now - self.facts_at > 2 or link["up"] != self.facts.get("link", {}).get("up"):
            ip, prefix = netdiag.iface_ipv4(self.iface)
            self.facts = {"ip": ip, "prefix": prefix,
                          "gw": netdiag.default_gateway(self.iface, only=True),
                          "dns": self.port_dns(ip, now)}
            self.facts_at = now
            gw = self.facts["gw"] or netdiag.default_gateway(self.iface)
            for k in ("PING", "PORT"):       # prefill targets with the gateway
                if not self.fields[k] and gw:
                    self.fields[k] = gw
        self.facts["link"] = link
        self.auto_log(now)

    def port_dns(self, ip, now):
        """DNS servers this port got from DHCP (cached; it shells out). Falls
        back to resolv.conf, which a VPN such as Tailscale may have taken over."""
        cip, when, servers = self._dns
        if ip != cip or now - when > 20:
            servers = (netdiag.iface_dns(self.iface) if ip else []) or netdiag.dns_servers()
            self._dns = (ip, now, servers)
        return servers

    def net_dns(self):
        """Resolvers the NET check should use for the port probes run on."""
        if self.joined:
            return list(self.joined["ack"].get("dns") or []) or self.facts.get("dns") or []
        servers = list(self.facts.get("dns") or [])
        job = self.jobs.get("DHCP")             # what the DHCP probe was offered, as backup
        for o in (job.data.get("offers") or []) if job else []:
            servers += [a for a in o.get("dns") or [] if a not in servers]
        return [a for a in servers if ":" not in a]

    def neighbor(self):
        if self.demo:
            return self.demo.get("neighbor")
        return self.listener.latest()

    def auth(self):
        """802.1X state heard on the port (see NeighborListener.auth_state)."""
        if self.demo:
            return self.demo.get("auth")
        return self.listener.auth_state() if self.listener else None

    def snapshot_row(self):
        """What the port log records about where we're plugged in now."""
        f, n = self.facts, self.neighbor() or {}
        link = f.get("link", {})
        offers = (self.jobs.get("DHCP").data.get("offers") if self.jobs.get("DHCP") else None) or []
        return {
            "switch": n.get("name"), "port": n.get("port"), "port_descr": n.get("port_descr"),
            "vlan": n.get("vlan"), "voice_vlan": n.get("voice_vlan"), "mgmt_ip": n.get("mgmt_ip"),
            "proto": n.get("proto"),
            "link": netdiag.mau_text((link.get("speed"), link.get("duplex")))
            if link.get("up") and link.get("speed") else ("up" if link.get("up") else "down"),
            "switch_link": netdiag.mau_text(n.get("mau")),
            "poe": netdiag.poe_text(n.get("poe")),
            "ip": f"{f['ip']}/{f['prefix']}" if f.get("ip") else None,
            "gateway": f.get("gw"),
            "dhcp_server": " ".join(sorted({o["server"] for o in offers})) or None,
            "flaps": self.flaps(), "platform": n.get("platform"),
        }

    def auto_log(self, now):
        n = self.neighbor()
        if not n or not self.facts.get("link", {}).get("up"):
            self.pending_auto = None
            return
        key = (n.get("name"), n.get("port"))
        if not self.pending_auto or self.pending_auto[0] != key:
            self.pending_auto = (key, now)
            return
        # Give DHCP a moment so the row carries our IP, but don't wait forever.
        if self.facts.get("ip") or now - self.pending_auto[1] > 15:
            if self.log.maybe_auto(self.snapshot_row()):
                self.say(f"logged {key[0]} {key[1]}", GREEN)

    def say(self, text, col=GREEN, secs=2.5):
        self.flash = (text, col, time.monotonic() + secs)

    def alerts(self):
        """Port-health problems worth shouting about on STAT, worst first."""
        link = self.facts.get("link", {})
        if not link.get("up"):
            return []
        out = []
        a = self.auth()
        if a and a["age"] < 180:
            if a.get("result") == "Failure":
                out.append((RED, "802.1X: authentication failed on this port"))
            elif a.get("result") != "Success":
                if not self.facts.get("ip"):
                    out.append((RED, "802.1X port: needs login, no DHCP until then"))
                else:
                    out.append((AMBER, "802.1X port: in via MAB or a guest VLAN?"))
        n = self.neighbor() or {}
        ours = (link.get("speed"), link.get("duplex"))
        theirs = n.get("mau")
        if not theirs and n.get("cdp_duplex") and ours[0]:
            theirs = (ours[0], n["cdp_duplex"])
        if theirs and ours[0] and (theirs[0] != ours[0] or theirs[1] != ours[1]):
            out.append((RED, f"Mismatch: switch {netdiag.mau_text(theirs)}, "
                             f"us {netdiag.mau_text(ours)}"))
        elif ours[1] == "half":
            out.append((RED, "Half duplex: check autonegotiation"))
        if ours[0] == 10:
            out.append((AMBER, "Link negotiated 10M: cable or port fault?"))
        if self.link_changed_at and time.monotonic() - self.link_changed_at < 90 and self.flaps():
            out.append((AMBER, f"Link flapped {ago(time.monotonic() - self.link_changed_at)}"))
        return out

    # ---- input ----------------------------------------------------------

    def on_key(self, code, value):
        if code in (KEY["LEFTSHIFT"], KEY["RIGHTSHIFT"]):
            self.shift = value != 0
            return
        if code in (KEY["LEFTCTRL"], KEY_RIGHTCTRL):
            self.ctrl = value != 0
            return
        if code == KEY_SYSRQ or (self.ctrl and code == KEY_S):
            if value == 1:
                self.screenshot()
            return
        if self.ctrl:                      # no other Ctrl shortcuts; don't type them
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
            if name == "VLAN":
                self.vlan_enter()
            elif not running:
                self.start(name)
        elif name == "VLAN" and code == KEY_S and not self.fields["VLAN"]:
            self.start("VLAN")
        elif name == "VLAN" and code == KEY_X:
            self.vlan_leave()
        elif name in self.fields and not (running and name != "VLAN"):
            if code == KEY["BACKSPACE"]:
                self.fields[name] = self.fields[name][:-1]
            else:
                c = keychar(code, self.shift)
                ok, maxlen = FIELD_RULES[name]
                if c and ok(c) and len(self.fields[name]) < maxlen:
                    self.fields[name] += c

    def back(self):
        name = SCREENS[self.screen]
        job = self.jobs.get(name)
        if name == "VLAN" and self.vjoin and self.vjoin.running:
            self.vjoin.stop.set()
        elif job and job.running:
            job.stop.set()
        elif name in ("VLAN", "LOG") and self.fields[name]:
            self.fields[name] = ""
        elif self.screen != 0:
            self.screen = 0
        else:
            self.hint_until = time.monotonic() + 2.5

    def start(self, name):
        self.scroll[name] = 0
        ti = self.test_iface
        if name == "PING" and self.fields["PING"]:
            self.jobs[name] = Job(netdiag.ping, self.fields["PING"], ti)
        elif name == "ARP":
            self.jobs[name] = Job(netdiag.arp_sweep, ti)
        elif name == "PORT" and self.fields["PORT"]:
            self.jobs[name] = Job(netdiag.port_scan, self.fields["PORT"], ti)
        elif name == "NET" and self.fields["NET"]:
            self.jobs[name] = Job(netdiag.netcheck, self.fields["NET"], ti, self.net_dns())
        elif name == "DHCP":
            self.jobs[name] = Job(dhcp.probe, ti)
        elif name == "VLAN":
            old = self.jobs.get("VLAN")
            if old and old.running:
                old.stop.set()
            self.jobs[name] = Job(vlan.sniff, self.iface)
        elif name == "LOG":
            row = self.snapshot_row()
            row["label"] = self.fields["LOG"].strip() or "manual"
            if self.log.append(row):
                self.fields["LOG"] = ""
                self.say("logged" + (f" {row['switch']} {row['port']}" if row["switch"] else ""))

    def screenshot(self):
        """Save the current screen (without any message overlay) as a PNG
        in the desktop user's ~/landevil/screenshots/."""
        img = self.render()
        home, uid, gid = portlog._owner()
        folder = os.path.join(home, "landevil", "screenshots")
        name = f"landevil-{time.strftime('%Y%m%d-%H%M%S')}-{SCREENS[self.screen].lower()}.png"
        try:
            for d in (os.path.dirname(folder), folder):
                if not os.path.isdir(d):
                    os.makedirs(d, exist_ok=True)
                    if uid is not None:
                        os.chown(d, uid, gid)
            path = os.path.join(folder, name)
            img.save(path)
            if uid is not None:
                os.chown(path, uid, gid)
            self.say(f"saved ~/landevil/screenshots/{name}")
        except OSError as e:
            self.say(f"screenshot failed: {e.strerror or e}", RED)

    def vlan_rows(self):
        """Merge what we've *seen* tagged with what the switch *advertises*."""
        job = self.jobs.get("VLAN")
        seen = dict(job.data.get("vlans") or {}) if job else {}
        n = self.neighbor() or {}
        adv = {}
        for vid, nm in (n.get("vlan_names") or {}).items():
            adv.setdefault(vid, []).append(nm or "named")
        if n.get("vlan"):
            adv.setdefault(n["vlan"], []).append("native")
        if n.get("voice_vlan"):
            adv.setdefault(n["voice_vlan"], []).append("voice")
        rows = []
        for vid in sorted(set(seen) | set(adv)):
            s = seen.get(vid)
            rows.append({"vid": vid, "seen": s, "adv": adv.get(vid, [])})
        return rows

    def vlan_enter(self):
        if self.vjoin and self.vjoin.running:
            return
        txt = self.fields["VLAN"]
        if txt:
            vid = int(txt)
        else:
            rows = self.vlan_rows()
            if not rows:
                self.start("VLAN")
                return
            vid = rows[min(self.scroll["VLAN"], len(rows) - 1)]["vid"]
        if not 1 <= vid <= 4094:
            self.say("VLAN ID must be 1-4094", RED)
            return
        if self.joined and self.joined["vid"] == vid:
            return
        self.vlan_leave(quiet=True)
        self.fields["VLAN"] = ""
        self.vjoin = Job(vlan.join, self.iface, vid)

    def vlan_leave(self, quiet=False):
        j = self.joined
        if self.vjoin and self.vjoin.running:
            self.vjoin.stop.set()
        if j:
            vlan.leave(j["iface"], j.get("ack"))
            if not quiet:
                self.say(f"left VLAN {j['vid']}", AMBER)
            gw = self.facts.get("gw")
            for k in ("PING", "PORT"):
                if gw:
                    self.fields[k] = gw
        self.vjoin = None

    def on_joined(self):
        """Point Ping/Port at the VLAN's gateway once a join completes."""
        j = self.joined
        if j and not j.get("_announced"):
            j["_announced"] = True
            router = (j["ack"].get("router") or [None])[0]
            for k in ("PING", "PORT"):
                self.fields[k] = router or j["ack"]["yiaddr"]
            self.say(f"on VLAN {j['vid']}: {j['ack']['yiaddr']}")

    def tick(self):
        """Long-press Esc detection that works even without key repeat."""
        if self.esc_down is not None and time.monotonic() - self.esc_down >= LONG_PRESS:
            self.quit = True
        self.on_joined()

    def shutdown(self):
        for j in self.jobs.values():
            j.stop.set()
        self.vlan_leave(quiet=True)       # never leave an eth0.N behind
        if self.listener:
            self.listener.stop()

    # ---- frame ----------------------------------------------------------

    def render(self):
        img, d = canvas()
        self.draw_header(img, d)
        getattr(self, "draw_" + SCREENS[self.screen].lower())(d)
        self.draw_footer(d)
        if self.esc_down is not None:            # long-press progress
            frac = min(1.0, (time.monotonic() - self.esc_down) / LONG_PRESS)
            d.rectangle([0, H - 2, int(W * frac), H], fill=RED)
        return img

    def draw_header(self, img, d):
        d.rectangle([0, 0, W, 18], fill=PANEL)
        paste_asset(img, "logo120.png", (15, 15), (3, 2))
        f = font("bold", 9)
        x = W - 3
        for i in reversed(range(len(SCREENS))):
            label = SCREENS[i]
            if label == "VLAN" and self.joined:
                label = f"V{self.joined['vid']}"
            w = int(d.textlength(label, font=f)) + 9
            x -= w
            job = self.jobs.get(SCREENS[i])
            busy = (job and job.running) or (SCREENS[i] == "VLAN" and self.vjoin and self.vjoin.running)
            if i == self.screen:
                d.rounded_rectangle([x, 3, x + w - 2, 15], radius=3, fill=AMBER)
                d.text((x + 4, 4), label, font=f, fill=BG)
            else:
                col = GREEN if label.startswith("V") and self.joined and label != "VLAN" else DIM
                d.text((x + 4, 4), label, font=f, fill=col)
            if busy:
                d.ellipse([x + w - 5, 2, x + w - 1, 6], fill=GREEN if i != self.screen else BG)
            x -= 1
        tf = font("bold", 10)
        if 22 + d.textlength("LAN DEVIL", font=tf) + 4 <= x:   # wordmark only if the tabs leave room
            d.text((22, 3), "LAN", font=tf, fill=TEXT)
            d.text((22 + d.textlength("LAN ", font=tf), 3), "DEVIL", font=tf, fill=RED)
        d.line([0, 18, W, 18], fill=LINE)

    def draw_footer(self, d):
        y = H - 13
        d.line([0, H - 16, W, H - 16], fill=LINE)
        name = SCREENS[self.screen]
        job = self.jobs.get(name)
        now = time.monotonic()
        if now < self.hint_until:
            d.text((5, y), "Hold Esc to exit LAN Devil", font=font("bold", 9), fill=AMBER)
            return
        if self.flash and now < self.flash[2]:
            d.text((5, y), fit(d, self.flash[0], font("bold", 9), W - 10), font=font("bold", 9),
                   fill=self.flash[1])
            return
        x = 5
        if name == "VLAN":
            if (job and job.running) or (self.vjoin and self.vjoin.running):
                x = keycap(d, x, y, "Esc", "stop")
            else:
                x = keycap(d, x, y, "S", "watch")
            x = keycap(d, x, y, "Enter", "join")
            if self.joined:
                keycap(d, x, y, "X", "leave")
            else:
                keycap(d, x, y, "ud", "select")
            return
        if job and job.running:
            x = keycap(d, x, y, "Esc", "stop")
        else:
            x = keycap(d, x, y, "lr", "screens")
            if name == "LOG":
                x = keycap(d, x, y, "Enter", "log port")
            elif name != "STAT":
                x = keycap(d, x, y, "Enter", "probe" if name == "DHCP" else "run")
        if name in ("ARP", "DHCP", "LOG", "NET"):
            keycap(d, x, y, "ud", "scroll")
        elif name == "STAT":
            keycap(d, x, y, "Esc", "hold to exit")

    # ---- STATUS ---------------------------------------------------------

    def draw_stat(self, d):
        f = self.facts
        link = f.get("link", {})
        up = link.get("up")

        # link pill + speed ladder + duplex
        y = 23
        pill = "LINK UP" if up else ("NO LINK" if link.get("present", True) else "NO PORT")
        pw = int(d.textlength(pill, font=font("bold", 10))) + 16
        d.rounded_rectangle([5, y, 5 + pw, y + 15], radius=7, fill=DKGREEN if up else DKRED)
        d.ellipse([9, y + 5, 14, y + 10], fill=GREEN if up else RED)
        d.text((17, y + 2), pill, font=font("bold", 10), fill=GREEN if up else RED)
        sx = 12 + pw
        speed = link.get("speed") or 0
        for label, val in (("10", 10), ("100", 100), ("1G", 1000)):
            lw = int(d.textlength(label, font=font("bold", 8))) + 8
            lit = up and speed >= val
            fill = (RED if speed == 10 else AMBER) if lit else PANEL
            d.rounded_rectangle([sx, y + 2, sx + lw, y + 13], radius=2, fill=fill,
                                outline=None if lit else LINE)
            d.text((sx + 4, y + 3), label, font=font("bold", 8), fill=BG if lit else FAINT)
            sx += lw + 3
        if up and link.get("duplex"):
            half = link["duplex"] == "half"
            d.text((sx + 2, y + 3), "HALF" if half else "FULL", font=font("bold", 8),
                   fill=RED if half else DIM)
        rx = W - 6
        d.text((rx, y + 2), self.iface, font=font("monob", 11), fill=DIM, anchor="ra")
        rx -= int(d.textlength(self.iface, font=font("monob", 11))) + 6
        fl = self.flaps()
        if fl or up:
            col = (RED if fl >= 3 else AMBER) if fl else FAINT
            d.text((rx, y + 3), f"{fl} flap{'s' if fl != 1 else ''}", font=font("bold", 8),
                   fill=col, anchor="ra")

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
        alerts = self.alerts()
        accent = (alerts[0][0] if alerts else AMBER) if n else (LINE if not up else (120, 90, 30))
        d.rounded_rectangle([4, top, W - 5, bot], radius=6, fill=PANEL, outline=LINE)
        d.rounded_rectangle([4, top, 8, bot], radius=2, fill=accent)
        if n:
            self.draw_neighbor(d, n, top, alerts)
        else:
            self.draw_listening(d, top, bot, up, alerts)

    def draw_neighbor(self, d, n, top, alerts):
        x = tag(d, 14, top + 5, n["proto"], AMBER)
        a = self.auth()
        tags = []
        if a and a["age"] < 180:
            tags.append(("802.1X", GREEN if a.get("result") == "Success" else RED))
        poe = netdiag.poe_text(n.get("poe"))
        if poe:
            tags.append((poe, BLUE))
        if n.get("voice_vlan"):
            tags.append((f"VOICE {n['voice_vlan']}", (232, 96, 200)))
        for text, col in tags:
            if x + d.textlength(text, font=font("bold", 8)) + 8 > W - 58:
                break
            x = tag(d, x, top + 5, text, col)
        age = n.get("age")
        when = "cached" if age is None else ("just now" if age < 2 else f"{int(age)}s ago")
        d.text((W - 12, top + 5), when, font=font("sans", 9), fill=DIM, anchor="ra")
        d.text((14, top + 18), fit(d, n.get("name") or "unknown", font("bold", 15), W - 30),
               font=font("bold", 15), fill=TEXT)
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
        if alerts:
            col, msg = alerts[0]
            warn_icon(d, 14, cy + 29, col, 9)
            d.text((27, cy + 28), fit(d, msg, font("bold", 9), W - 42), font=font("bold", 9), fill=col)
        else:
            sub = n.get("platform") or n.get("port_descr")
            if n.get("mau"):
                sub = f"switch {netdiag.mau_text(n['mau'])}" + (f" · {sub}" if sub else "")
            if sub:
                d.text((14, cy + 28), fit(d, sub, font("sans", 9), W - 30), font=font("sans", 9), fill=DIM)

    def draw_listening(self, d, top, bot, up, alerts):
        err = None if self.demo else self.listener.error
        cx, cy = 40, (top + bot) // 2
        if not up:
            rj45(d, cx - 18, cy - 15, 36, 24, FAINT)
            d.text((74, top + 14), "Plug into a switch port", font=font("bold", 13), fill=TEXT)
            d.text((74, top + 34), "Switch, port, VLAN, PoE & mgmt IP", font=font("sans", 10), fill=DIM)
            d.text((74, top + 48), "appear here from LLDP / CDP.", font=font("sans", 10), fill=DIM)
            return
        if err:
            d.text((20, top + 12), "Neighbor capture unavailable", font=font("bold", 12), fill=RED)
            d.text((20, top + 32), fit(d, err, font("mono", 10), W - 40), font=font("mono", 10), fill=DIM)
            return
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
        if alerts:
            col, msg = alerts[0]
            d.text((74, top + 32), fit(d, msg, font("bold", 9), W - 88), font=font("bold", 9), fill=col)
        else:
            d.text((74, top + 32), "Switches announce every 30-60s.", font=font("sans", 10), fill=DIM)
        bx0, bx1, by = 74, W - 14, top + 52
        d.rounded_rectangle([bx0, by, bx1, by + 6], radius=3, fill=PANEL2)
        frac = min(1.0, waited / 60)
        if frac > 0.02:
            d.rounded_rectangle([bx0, by, bx0 + int((bx1 - bx0) * frac), by + 6], radius=3,
                                fill=AMBER if waited < 60 else FAINT)
        msg = f"{int(waited)}s" if waited < 60 else f"{int(waited)}s · unmanaged switch?"
        d.text((74, by + 9), msg, font=font("sans", 9), fill=DIM)

    def kv(self, d, x, y, k, v, width, kw=22):
        d.text((x, y + 2), k, font=font("bold", 7), fill=DIM)
        d.text((x + kw, y), fit(d, v, font("mono", 10), width - kw), font=font("mono", 10), fill=TEXT)

    # ---- shared: target field ------------------------------------------

    def draw_field(self, d, name, label, right_w=0, x_left=6, locked=None):
        job = self.jobs.get(name)
        running = (job is not None and job.running) if locked is None else locked
        d.text((x_left, 25), label, font=font("bold", 10), fill=DIM)
        x0 = x_left + 2 + int(d.textlength(label, font=font("bold", 10))) + 4
        x1 = W - 6 - right_w
        d.rounded_rectangle([x0, 22, x1, 39], radius=4, fill=PANEL,
                            outline=LINE if running else AMBER)
        txt = fit(d, self.fields[name], font("monob", 12), x1 - x0 - 14)
        d.text((x0 + 5, 24), txt, font=font("monob", 12), fill=TEXT)
        if not running and int(time.monotonic() * 2) % 2 == 0:
            cx = x0 + 6 + d.textlength(txt, font=font("monob", 12))
            d.rectangle([cx, 25, cx + 1, 36], fill=AMBER)

    def iface_note(self, d, y=25):
        """Small right-aligned 'on eth0.20' when probes run on a joined VLAN."""
        if self.joined:
            badge(d, W - 6, y, f"on VLAN {self.joined['vid']}", DKGREEN, GREEN, 8)

    # ---- DHCP -----------------------------------------------------------

    def draw_dhcp(self, d):
        job = self.jobs.get("DHCP")
        d.text((6, 23), "DHCP servers", font=font("bold", 11), fill=TEXT)
        d.text((92, 25), f"on {job.data.get('iface') if job else self.test_iface}",
               font=font("mono", 9), fill=DIM)
        if not job:
            empty(d, "Who answers DHCP here?",
                  ["Broadcasts a DHCP discover and lists every",
                   "server that offers an address. Two or more",
                   "servers = a rogue or misconfigured relay."],
                  warn="Sends one discover · no lease is taken", top=44)
            return
        offers = job.data.get("offers") or []
        servers = sorted({o["server"] for o in offers})
        if job.running:
            el = time.monotonic() - job.data.get("started", job.started)
            d.rounded_rectangle([6, 39, W - 6, 43], radius=2, fill=PANEL2)
            d.rounded_rectangle([6, 39, 6 + int((W - 12) * min(1, el / 4)), 43], radius=2, fill=AMBER)
            badge(d, W - 6, 22, f"{len(servers)} found", PANEL2, DIM)
        elif not offers:
            badge(d, W - 6, 22, "none", DKRED, RED)
            msg = job.last() or "No DHCP server answered."
            d.text((W // 2, 82), fit(d, msg, font("bold", 11), W - 20), font=font("bold", 11),
                   fill=RED, anchor="ma")
            d.text((W // 2, 100), "Static-only network, or DHCP blocked on this VLAN.",
                   font=font("sans", 9), fill=DIM, anchor="ma")
            return
        elif len(servers) == 1:
            badge(d, W - 6, 22, "1 server", DKGREEN, GREEN)
        else:
            badge(d, W - 6, 22, f"{len(servers)} SERVERS", RED, BG)
        if not offers:
            d.text((W // 2, 80), "listening for offers…", font=font("sans", 10), fill=DIM, anchor="ma")
            return
        rows = []
        rogue = len(servers) > 1
        for i, o in enumerate(offers):
            rows.append(("head", i, o))
            rows.append(("kv", [("OFFER", f"{o['yiaddr']}/{o['prefix'] or '?'}"),
                                ("GW", ", ".join(o["router"]) or "—")]))
            rows.append(("kv", [("DNS", ", ".join(o["dns"][:2]) or "—"),
                                ("LEASE", duration(o["lease"]) if o.get("lease") else "—")]))
            extra = []
            if o.get("domain"):
                extra.append(("DOMAIN", o["domain"]))
            if o.get("tftp") or o.get("bootfile"):
                extra.append(("BOOT", " ".join(x for x in (o.get("tftp"), o.get("bootfile")) if x)))
            if o.get("giaddr") and o["giaddr"] != "0.0.0.0":
                extra.append(("RELAY", o["giaddr"]))
            for k in range(0, len(extra), 2):
                rows.append(("kv", extra[k:k + 2]))
        top = 46 if rogue else 44
        if rogue:
            d.rounded_rectangle([4, 40, W - 5, 54], radius=4, fill=DKRED)
            warn_icon(d, 9, 42, RED, 10)
            d.text((24, 41), "More than one DHCP server: possible rogue", font=font("bold", 9), fill=RED)
            top = 58
        lh = 12
        nrows = (H - 18 - top) // lh
        self.scroll["DHCP"] = min(self.scroll["DHCP"], max(0, len(rows) - nrows))
        start = self.scroll["DHCP"]
        for i, row in enumerate(rows[start:start + nrows]):
            y = top + i * lh
            if row[0] == "head":
                _, idx, o = row
                col = (RED if rogue and idx > 0 else AMBER) if rogue else GREEN
                x = tag(d, 6, y + 1, f"#{idx + 1}", col)
                d.text((x, y), o["server"], font=font("monob", 10), fill=TEXT)
                d.text((x + 6 + d.textlength(o["server"], font=font("monob", 10)), y + 1),
                       o["src_mac"], font=font("mono", 9), fill=DIM)
            else:
                xs = [14, 168]
                for (k, v), x in zip(row[1], xs):
                    self.kv(d, x, y, k, v, (W - 20 - x) if x == 168 or len(row[1]) == 1 else 150, kw=34)
        scrollbar(d, top, nrows, len(rows), start, lh)

    # ---- VLAN -----------------------------------------------------------

    def draw_vlan(self, d):
        job = self.jobs.get("VLAN")
        self.draw_field(d, "VLAN", "JOIN VID", right_w=W - 132, locked=False)
        if job:
            el = time.monotonic() - job.data.get("started", job.started)
            txt = (f"watching {int(el)}s · {job.data.get('frames', 0)} tagged" if job.running
                   else f"{job.data.get('frames', 0)} tagged frames")
            d.text((W - 6, 26), txt, font=font("sans", 9), fill=GREEN if job.running else DIM, anchor="ra")
        else:
            d.text((W - 6, 26), "or S to watch tags", font=font("sans", 9), fill=FAINT, anchor="ra")
        y = 42
        jd = self.vjoin.data if self.vjoin else None
        if jd:
            st = jd.get("state")
            if st == "up":
                ack = jd["ack"]
                fill, col = DKGREEN, GREEN
                msg = (f"On VLAN {jd['vid']} · {ack['yiaddr']}/{ack['prefix']} · gw "
                       f"{(ack.get('router') or ['—'])[0]}")
            elif st == "failed":
                fill, col, msg = DKRED, RED, f"VLAN {jd['vid']}: {jd.get('error')}"
            else:
                fill, col = DKAMBER, AMBER
                msg = f"Joining VLAN {jd['vid']}… " + ("DHCP" if st == "dhcp" else "creating link")
            d.rounded_rectangle([4, y, W - 5, y + 13], radius=4, fill=fill)
            d.text((10, y + 1), fit(d, msg, font("bold", 9), W - 20), font=font("bold", 9), fill=col)
            y += 16
        rows = self.vlan_rows()
        if not rows:
            if job and job.running:
                empty(d, "Watching for tagged frames…",
                      ["Nothing yet. Tags only appear on trunk ports;",
                       "an access port will stay empty."], top=y + 10)
            else:
                empty(d, "Find the VLANs on this port",
                      ["S watches for 802.1Q-tagged frames (passive).",
                       "Enter joins a VLAN: eth0.N + DHCP, then",
                       "Ping / ARP / Port / DHCP run on it."], top=y + 6)
            return
        cols = [(8, "VID"), (44, "FRAMES"), (92, "HOSTS"), (130, "SUBNET / SWITCH SAYS"), (W - 34, "SEEN")]
        for x, lab in cols:
            d.text((x, y), lab, font=font("bold", 7), fill=FAINT)
        y += 10
        lh = 12
        nrows = (H - 18 - y) // lh
        cur = min(self.scroll["VLAN"], len(rows) - 1)
        self.scroll["VLAN"] = cur
        start = max(0, min(cur - nrows + 1, len(rows) - nrows)) if cur >= nrows else 0
        joined_vid = self.joined["vid"] if self.joined else None
        for i, r in enumerate(rows[start:start + nrows]):
            ry = y + i * lh
            sel = start + i == cur
            if sel:
                d.rounded_rectangle([4, ry - 1, W - 6, ry + lh - 2], radius=3, fill=PANEL2, outline=AMBER)
            elif (start + i) % 2 == 0:
                d.rectangle([4, ry - 1, W - 6, ry + lh - 2], fill=PANEL)
            s = r["seen"]
            vcol = GREEN if r["vid"] == joined_vid else (AMBER if s else DIM)
            d.text((8, ry), str(r["vid"]), font=font("monob", 10), fill=vcol)
            if s:
                d.text((44, ry), _k(s["frames"]), font=font("mono", 9), fill=TEXT)
                d.text((92, ry), str(len(s["macs"])), font=font("mono", 9), fill=TEXT)
                sub = vlan.subnet_guess(s["ips"]) or ""
                d.text((W - 34, ry), ago(time.monotonic() - s["last"]).replace(" ago", ""),
                       font=font("mono", 9), fill=DIM)
            else:
                d.text((44, ry), "—", font=font("mono", 9), fill=FAINT)
                d.text((92, ry), "—", font=font("mono", 9), fill=FAINT)
                sub = ""
            adv = ", ".join(r["adv"])
            text = " · ".join(x for x in (sub, adv) if x) or ", ".join(sorted(s["kinds"])) if s else adv
            d.text((130, ry), fit(d, text or "", font("sans", 9), W - 34 - 136), font=font("sans", 9),
                   fill=TEXT if sub else DIM)
        scrollbar(d, y, nrows, len(rows), start, lh)

    # ---- PING -----------------------------------------------------------

    def draw_ping(self, d):
        self.draw_field(d, "PING", "PING", right_w=70 if self.joined else 0)
        self.iface_note(d)
        job = self.jobs.get("PING")
        if not job:
            empty(d, "Live latency graph",
                  [f"Pings the target once a second over {self.test_iface},",
                   "up to 60 times.  Hostnames use DHCP's DNS."])
            return
        data = job.data
        rtts = data.get("rtts") or []
        got = [r for r in rtts if r is not None]
        sent = data.get("sent", 0)

        gx0, gy0, gx1, gy1 = 6, 44, W - 6, 112
        d.rounded_rectangle([gx0, gy0, gx1, gy1], radius=4, fill=PANEL)
        if not rtts:
            msg = job.last() if not job.running else f"pinging {data.get('ip') or data.get('target')}…"
            d.text(((gx0 + gx1) // 2, (gy0 + gy1) // 2 - 6), fit(d, msg, font("sans", 10), gx1 - gx0 - 10),
                   font=font("sans", 10), fill=RED if not job.running else DIM, anchor="ma")
        else:
            top = max(got) if got else 1.0
            scale = nice(top * 1.15)
            for frac in (0.5, 1.0):
                yy = gy1 - 4 - int((gy1 - gy0 - 12) * frac)
                for xx in range(gx0 + 4, gx1 - 30, 4):
                    d.point((xx, yy), fill=LINE)
                d.text((gx1 - 4, yy - 5), ms(scale * frac), font=font("sans", 8), fill=FAINT, anchor="ra")
            bw, gap = 5, 2
            maxbars = (gx1 - gx0 - 40) // (bw + gap)
            avg = sum(got) / len(got) if got else 0
            for i, r in enumerate(rtts[-maxbars:]):
                bx = gx0 + 5 + i * (bw + gap)
                if r is None:
                    d.line([bx, gy1 - 10, bx + bw - 1, gy1 - 4], fill=RED, width=2)
                    d.line([bx, gy1 - 4, bx + bw - 1, gy1 - 10], fill=RED, width=2)
                    continue
                h = max(2, int((gy1 - gy0 - 12) * min(1.0, r / scale)))
                col = GREEN if r <= avg * 1.5 or r < 2 else AMBER
                d.rectangle([bx, gy1 - 4 - h, bx + bw - 1, gy1 - 4], fill=col)

        loss = 100 * (sent - len(got)) / sent if sent else 0
        tiles = [("TARGET", data.get("ip") or data.get("target") or "—", TEXT),
                 ("RECV", f"{len(got)}/{sent}", TEXT),
                 ("LOSS", f"{loss:.0f}%", GREEN if loss == 0 else (AMBER if loss < 20 else RED)),
                 ("AVG", ms(sum(got) / len(got)) if got else "—", TEXT),
                 ("MIN/MAX ms", f"{min(got):.1f}/{max(got):.1f}" if got else "—", TEXT)]
        widths = [84, 54, 42, 56, 72]
        x, y = 6, 116
        for (label, val, col), tw in zip(tiles, widths):
            d.rounded_rectangle([x, y, x + tw - 3, y + 34], radius=4, fill=PANEL)
            d.text((x + 5, y + 4), label, font=font("bold", 7), fill=DIM)
            d.text((x + 5, y + 16), fit(d, val, font("monob", 11), tw - 12), font=font("monob", 11), fill=col)
            x += tw

    # ---- ARP ------------------------------------------------------------

    # ---- NET ------------------------------------------------------------

    def draw_net(self, d):
        job = self.jobs.get("NET")
        self.draw_field(d, "NET", "HOST")
        if not job:
            empty(d, "Can this port reach the internet?",
                  ["Looks the host up on this port's DNS, checks",
                   "for internet or a captive portal, then traces",
                   "the route hop by hop."],
                  warn="Sends DNS queries, one HTTP request, UDP probes", top=46)
            return
        data, phase = job.data, job.data.get("phase")
        dns, web, hops = data.get("dns") or [], data.get("web"), data.get("hops") or []

        # three summary cards
        cards = []
        ok = [r for r in dns if r["ips"]]
        if not dns and data.get("ip") and phase != "dns":
            cards.append(("DNS", "IP given", DIM))
        elif phase == "dns" and job.running:
            cards.append(("DNS", "asking…", DIM))
        elif ok:
            cards.append(("DNS", "OK" + (f" {ok[0]['ms']:.0f}ms" if ok[0]["ms"] else ""),
                          GREEN if len(ok) == len(dns) else AMBER))
        else:
            cards.append(("DNS", (dns[0]["err"] if dns else "none") or "fail", RED))
        if web:
            st = web["state"]
            cards.append(("INTERNET", {"online": "ONLINE", "portal": "PORTAL"}.get(st, "NO"),
                          {"online": GREEN, "portal": AMBER}.get(st, RED)))
        else:
            cards.append(("INTERNET", "checking…" if job.running and phase in ("dns", "web") else "—", DIM))
        end = hops[-1]["end"] if hops else None
        if end == "reached":
            cards.append(("TRACE", f"{len(hops)} hops", GREEN))
        elif hops and job.running:
            cards.append(("TRACE", f"hop {len(hops)}…", DIM))
        elif end:
            cards.append(("TRACE", end, RED))
        elif hops:
            cards.append(("TRACE", f"{len(hops)}, no end", AMBER))
        else:
            cards.append(("TRACE", "—" if not job.running else "waiting", DIM))
        cw, cx, cy = (W - 12) // 3, 6, 43
        for label, val, col in cards:
            d.rounded_rectangle([cx, cy, cx + cw - 4, cy + 24], radius=4, fill=PANEL)
            d.text((cx + 5, cy + 2), label, font=font("bold", 7), fill=DIM)
            d.text((cx + 5, cy + 10), fit(d, val, font("bold", 11), cw - 13), font=font("bold", 11), fill=col)
            cx += cw

        # detail list: DNS servers, internet detail, then hops
        rows = []
        for r in dns:
            res = ", ".join(r["ips"][:2]) if r["ips"] else r["err"] or "?"
            rows.append(("DNS", r["server"], res, r["ms"], GREEN if r["ips"] else RED))
        if web:
            rows.append(("WEB", web["detail"], "", web["ms"],
                         {"online": GREEN, "portal": AMBER}.get(web["state"], RED)))
        for h in hops:
            col = GREEN if h["end"] == "reached" else (RED if h["end"] else TEXT)
            rows.append((str(h["ttl"]), h["ip"] or "*", h["end"] if h["end"] not in (None, "reached") else "",
                         h["ms"], col if h["ip"] else FAINT))
        top, lh = 71, 12
        nrows = (H - 18 - top) // lh
        self.scroll["NET"] = min(self.scroll["NET"], max(0, len(rows) - nrows))
        start = self.scroll["NET"]
        for i, (k, a, b, ms_, col) in enumerate(rows[start:start + nrows]):
            y = top + i * lh
            kcol = PANEL2 if k.isdigit() else (DKAMBER if k == "WEB" else PANEL2)
            d.rounded_rectangle([6, y + 1, 30, y + 10], radius=2, fill=kcol)
            d.text((18, y + 1), k, font=font("bold", 7), fill=DIM, anchor="ma")
            d.text((36, y), fit(d, a, font("monob", 10), 128), font=font("monob", 10), fill=col)
            if b:
                d.text((168, y + 1), fit(d, b, font("mono", 9), 100), font=font("mono", 9), fill=DIM)
            if ms_ is not None:
                d.text((W - 8, y + 1), ms(ms_), font=font("sans", 9), fill=DIM, anchor="ra")
        scrollbar(d, top, nrows, len(rows), start, lh)

    def draw_arp(self, d):
        job = self.jobs.get("ARP")
        if not job:
            empty(d, "ARP sweep",
                  ["One ARP request to every address in your",
                   "subnet (capped at a /24), paced at 12/s to stay",
                   "under switch ARP-inspection limits (about 20 s).",
                   f"Lists who answered, with vendor. On {self.test_iface}."],
                  warn="Active scan · authorized networks only", top=34)
            return
        data = job.data
        hosts = data.get("hosts") or []
        d.text((6, 23), "ARP", font=font("bold", 11), fill=TEXT)
        d.text((32, 24), data.get("net") or "", font=font("mono", 10), fill=DIM)
        badge(d, W - 6, 22, f"{len(hosts)} hosts", AMBER if hosts else PANEL2, BG if hosts else DIM)
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
        scrollbar(d, y, rows, len(hosts), start, lh)

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
            d.text((W - 36, 25), lab, font=font("bold", 10), fill=GREEN if n_open else DIM, anchor="ma")
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

    # ---- LOG ------------------------------------------------------------

    def draw_log(self, d):
        self.draw_field(d, "LOG", "NOTE", locked=False)
        if not self.fields["LOG"]:
            d.text((80, 25), "e.g. Rm 214 jack B, then Enter", font=font("sans", 9), fill=FAINT)
        rows = self.log.rows
        y = 43
        if self.log.error:
            d.text((6, y), fit(d, self.log.error, font("bold", 9), W - 12), font=font("bold", 9), fill=RED)
        else:
            d.text((6, y), f"{len(rows)} rows · {self.log.display_path()} · auto-log on",
                   font=font("sans", 9), fill=DIM)
        y += 14
        if not rows:
            empty(d, "No ports logged yet",
                  ["Each new switch + port you plug into is logged",
                   "automatically. Add a note above to label it.",
                   "Open the CSV in any spreadsheet."], top=y + 6)
            return
        lh = 12
        nrows = (H - 18 - y) // lh
        newest = rows[::-1]
        self.scroll["LOG"] = min(self.scroll["LOG"], max(0, len(newest) - nrows))
        start = self.scroll["LOG"]
        for i, r in enumerate(newest[start:start + nrows]):
            ry = y + i * lh
            if (start + i) % 2 == 0:
                d.rectangle([4, ry - 1, W - 6, ry + lh - 2], fill=PANEL)
            t = (r.get("time") or "")[11:16]
            d.text((8, ry), t, font=font("mono", 9), fill=DIM)
            lab = r.get("label") or ""
            x = 42
            if lab == "auto":
                x = tag(d, x, ry + 1, "AUTO", PANEL2, DIM, 7)
            elif lab:
                x = tag(d, x, ry + 1, fit(d, lab, font("bold", 7), 90), AMBER, BG, 7)
            where = " ".join(v for v in (r.get("switch"), r.get("port")) if v) or "(no neighbor)"
            vl = f"v{r['vlan']}" if r.get("vlan") else ""
            d.text((W - 10, ry), vl, font=font("monob", 9), fill=AMBER, anchor="ra")
            d.text((x, ry), fit(d, where, font("sans", 9), W - 14 - x - 30), font=font("sans", 9), fill=TEXT)
        scrollbar(d, y, nrows, len(newest), start, lh)


def _k(n):
    return f"{n / 1000:.1f}k" if n >= 1000 else str(n)


# ---------------------------------------------------------------------------
# Splash
# ---------------------------------------------------------------------------

def splash():
    img, d = canvas()
    paste_asset(img, "logo120.png", (112, 112), (14, (H - 112) // 2))
    x = 140
    d.text((x, 44), "LAN", font=font("bold", 30), fill=TEXT)
    d.text((x, 76), "DEVIL", font=font("bold", 30), fill=RED)
    d.text((x + 2, 116), f"pocket network ID · v{VERSION}", font=font("sans", 9), fill=DIM)
    return img


# ---------------------------------------------------------------------------
# Preview: deterministic screenshots with demo data
# ---------------------------------------------------------------------------

def demo_data(log_path):
    return {
        "iface": "eth0", "flaps": 1, "log_path": log_path,
        "facts": {"ip": "10.20.0.57", "prefix": 24, "gw": "10.20.0.1",
                  "dns": ["10.20.0.1", "1.1.1.1"],
                  "link": {"present": True, "up": True, "speed": 100,
                           "duplex": "full", "mac": "00:e0:a1:05:7b:9f"}},
        "neighbor": {"proto": "LLDP", "name": "sw-closet-3.example.lan",
                     "port": "Gi1/0/24", "port_descr": "desk 12", "vlan": 20, "voice_vlan": 30,
                     "mgmt_ip": "10.20.0.2", "age": 14, "mau": (100, "full"),
                     "poe": {"supported": True, "class": 4, "type": 2, "allocated_w": 25.5},
                     "vlan_names": {20: "DATA", 30: "VOICE", 99: "MGMT"},
                     "platform": "Cisco IOS Software, C2960X Software, Version 15.2(7)E8"},
    }


class _Done(Job):
    def __init__(self, data, lines=(), running=False):
        self.lines, self.data, self.running = list(lines), data, running
        self.stop = threading.Event()
        self.started = time.monotonic()
        self._lock = threading.Lock()


def preview(out_dir):
    import random
    import tempfile
    random.seed(7)
    os.makedirs(out_dir, exist_ok=True)
    tmp = tempfile.mkdtemp()
    app = App(demo=demo_data(os.path.join(tmp, "ports.csv")))
    app.log.display_path = lambda: "~/landevil/ports.csv"   # not the temp dir
    app.refresh()
    app.fields.update(PING="10.20.0.1", PORT="10.20.0.40")
    now = time.monotonic()
    shots = [("splash", splash())]

    app.screen = SCREENS.index("STAT")
    shots.append(("status", app.render()))
    app.demo = dict(app.demo, auth={"count": 3, "age": 12, "last": "Request", "method": None,
                                    "prompt": None, "src": "00:25:84:aa:10:3f", "result": None})
    app.facts = dict(app.facts, ip=None, prefix=None, gw=None)
    shots.append(("dot1x", app.render()))
    app.demo = dict(app.demo, auth=None)
    app.refresh()

    app.screen = SCREENS.index("DHCP")
    o1 = {"server": "10.20.0.1", "src_mac": "00:1a:2b:3c:4d:01", "yiaddr": "10.20.0.58", "prefix": 24,
          "router": ["10.20.0.1"], "dns": ["10.20.0.1", "1.1.1.1"], "lease": 86400,
          "domain": "example.lan", "tftp": None, "bootfile": None, "giaddr": "0.0.0.0"}
    o2 = {"server": "192.168.1.1", "src_mac": "74:da:38:5e:aa:10", "yiaddr": "192.168.1.104",
          "prefix": 24, "router": ["192.168.1.1"], "dns": ["192.168.1.1"], "lease": 7200,
          "domain": None, "tftp": None, "bootfile": None, "giaddr": "0.0.0.0"}
    app.jobs["DHCP"] = _Done({"iface": "eth0", "offers": [o1, o2], "started": now - 5})
    shots.append(("dhcp", app.render()))

    app.screen = SCREENS.index("VLAN")
    def v(frames, macs, ips, last, kinds):
        return {"frames": frames, "macs": set(range(macs)), "ips": set(ips),
                "kinds": kinds, "first": now - 40, "last": now - last}
    app.jobs["VLAN"] = _Done({"started": now - 42, "frames": 2918, "vlans": {
        1: v(311, 3, [], 4, {"STP": 300, "CDP": 11}),
        20: v(1840, 37, ["10.20.0.1", "10.20.0.11", "10.20.0.23"], 0, {"ARP": 400, "IPv4": 1440}),
        30: v(512, 12, ["10.30.0.1", "10.30.0.20"], 1, {"ARP": 90, "IPv4": 422}),
        99: v(155, 4, ["10.99.0.2", "10.99.0.3"], 9, {"ARP": 30, "IPv4": 125}),
        140: v(100, 2, ["172.16.40.9"], 22, {"ARP": 100})}}, running=True)
    app.vjoin = _Done({"vid": 30, "iface": "eth0.30", "state": "up",
                       "ack": {"yiaddr": "10.30.0.57", "prefix": 24, "router": ["10.30.0.1"]}})
    app.scroll["VLAN"] = 2
    shots.append(("vlan", app.render()))
    app.vjoin = None

    app.screen = SCREENS.index("PING")
    rtts = [round(random.uniform(0.45, 0.75), 3) for _ in range(38)]
    rtts[17], rtts[29] = 2.9, None
    rtts[30] = 1.4
    app.jobs["PING"] = _Done({"target": "10.20.0.1", "ip": "10.20.0.1",
                              "rtts": rtts, "sent": len(rtts)}, running=True)
    shots.append(("ping", app.render()))

    app.screen = SCREENS.index("NET")
    trace = ["10.20.0.1", "10.0.0.1", "96.120.88.13", "68.85.220.185", "24.124.155.129",
             "96.110.33.114", None, "172.68.32.28", "1.1.1.1"]
    app.jobs["NET"] = _Done({
        "target": "one.one.one.one", "ip": "1.1.1.1", "phase": "done",
        "dns": [{"server": "10.20.0.1", "ms": 3.1, "ips": ["1.1.1.1", "1.0.0.1"], "err": None},
                {"server": "1.1.1.1", "ms": 14.2, "ips": ["1.1.1.1", "1.0.0.1"], "err": None}],
        "web": {"state": "online", "detail": "HTTP 204", "ms": 66.0},
        "hops": [{"ttl": i + 1, "ip": ip, "ms": None if ip is None else 0.6 + i * 1.7,
                  "end": "reached" if ip == "1.1.1.1" else None} for i, ip in enumerate(trace)]})
    app.fields["NET"] = "one.one.one.one"
    shots.append(("net", app.render()))

    app.screen = SCREENS.index("ARP")
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

    app.screen = SCREENS.index("PORT")
    opened = {22, 80, 139, 443, 445, 5000}
    state = {p: ("open" if p in opened else "closed") for p, _ in netdiag.COMMON_PORTS}
    app.jobs["PORT"] = _Done({"target": "10.20.0.40", "ip": "10.20.0.40", "state": state})
    shots.append(("ports", app.render()))

    app.screen = SCREENS.index("LOG")
    base = {"vlan": 20, "proto": "LLDP", "link": "100M FD"}
    for t, lab, sw, port, vl in [("09:12", "auto", "sw-closet-3", "Gi1/0/12", 20),
                                 ("09:14", "Rm 210 jack A", "sw-closet-3", "Gi1/0/14", 20),
                                 ("09:17", "auto", "sw-closet-3", "Gi1/0/17", 30),
                                 ("09:21", "Rm 212 printer", "sw-closet-3", "Gi1/0/21", 99),
                                 ("09:26", "auto", "sw-closet-4", "Gi2/0/3", 20),
                                 ("09:31", "Rm 214 jack B", "sw-closet-3", "Gi1/0/24", 20)]:
        app.log.rows.append(dict(base, time=f"2026-11-20 {t}:00", label=lab, switch=sw, port=port, vlan=vl))
    app.fields["LOG"] = "Rm 216 jack A"
    shots.append(("log", app.render()))

    for name, img in shots:
        p = os.path.join(out_dir, f"{name}.png")
        img.save(p)
        print(p)


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="LAN Devil for CardputerZero")
    ap.add_argument("--preview", metavar="DIR", help="render demo screenshots and exit")
    ap.add_argument("--window", action="store_true",
                    help="run in a fullscreen desktop window (uConsole) instead of the LCD")
    ap.add_argument("--windowed", action="store_true",
                    help="like --window, but a normal-sized window (F11 toggles fullscreen)")
    ap.add_argument("--scale", type=int, help="window scale factor (default: fit the screen)")
    args = ap.parse_args()
    if args.preview:
        preview(args.preview)
        return 0

    if args.window or args.windowed:
        try:
            from window import Window
            fb = kbd = Window(W, H, fullscreen=not args.windowed, scale=args.scale)
            set_scale(fb.scale)           # draw at full resolution, not upscaled
        except Exception as e:             # no display, no tkinter, no ImageTk
            print(f"landevil: window: {e}", file=sys.stderr)
            return 1
    else:
        from device import Framebuffer, Keyboard
        try:
            fb = Framebuffer()
        except (OSError, RuntimeError) as e:
            print(f"landevil: framebuffer: {e}", file=sys.stderr)
            return 1
        kbd = None
    fb.show(splash())
    shown_at = time.monotonic()
    if kbd is None:
        kbd = Keyboard()
    app = App()

    def on_signal(*_):
        app.quit = True
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_signal)

    try:
        app.refresh()
        time.sleep(max(0, 1.2 - (time.monotonic() - shown_at)))
        kbd.poll(0)                         # drop the launcher's Enter keypress
        while not app.quit:
            if getattr(kbd, "closed", False):     # desktop window closed
                break
            app.refresh()
            fb.show(app.render())
            radar = (app.screen == 0 and app.facts.get("link", {}).get("up")
                     and not app.neighbor())
            busy = (any(j.running for j in app.jobs.values()) or app.esc_down is not None
                    or radar or (app.vjoin and app.vjoin.running))
            for code, value in kbd.poll(0.08 if busy else 0.25):
                app.on_key(code, value)
            app.tick()
    finally:
        app.shutdown()
        try:
            fb.show(Image.new("RGB", (fb.w, fb.h), (0, 0, 0)))
        finally:
            fb.close()
            if kbd is not fb:
                kbd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
