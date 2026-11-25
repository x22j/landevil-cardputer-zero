"""
netdiag.py -- network layer for LAN Devil on CardputerZero.

Port of the Pi build's diag.py, with one big difference: there is no
lldpd here. The CardputerZero OS doesn't ship it and the store can't
assume it, so LLDP/CDP frames are captured on raw AF_PACKET sockets and
parsed in Python -- the same TLV walk as the S31 firmware's lldp_cdp.c,
plus the mgmt-address and 802.1 port-VLAN TLVs that build skipped.

Raw sockets need root (CAP_NET_RAW). APPLaunch runs as root and its
children inherit that, so launched from the launcher everything works;
run by hand as `pi` the passive capture and ARP sweep report that they
need root instead of failing silently.

Everything active (ping, ARP sweep, port scan) is explicit-call only.
"""

import ipaddress
import json
import os
import select
import socket
import struct
import subprocess
import threading
import time

ETH_P_ARP = 0x0806
ETH_P_LLDP = 0x88CC
ETH_P_802_2 = 0x0004          # 802.3 length-framed LLC frames (CDP rides on these)
ETH_P_PAE = 0x888E            # 802.1X EAPOL
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
SO_BINDTODEVICE = 25

LLDP_MCAST = bytes.fromhex("0180c200000e")
CDP_MCAST = bytes.fromhex("01000ccccccc")
PAE_MCAST = bytes.fromhex("0180c2000003")    # 802.1X port access entity group


def is_root():
    return os.geteuid() == 0


# ---------------------------------------------------------------------------
# Interface facts (all cheap; poll freely)
# ---------------------------------------------------------------------------

def list_wired_interfaces():
    """Wired candidates, eth* first. Excludes lo, wlan, and virtual ifaces."""
    out = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name == "lo" or name.startswith(("wlan", "wl", "p2p", "usb")):
                continue
            if os.path.exists(f"/sys/class/net/{name}/wireless"):
                continue
            if os.path.exists(f"/sys/class/net/{name}/device"):
                out.append(name)
    except OSError:
        pass
    out.sort(key=lambda n: (not n.startswith(("eth", "en")), n))
    return out


def pick_interface():
    env = os.environ.get("LANDEVIL_IFACE")
    if env:
        return env
    wired = list_wired_interfaces()
    return wired[0] if wired else "eth0"


def _sysfs(iface, attr):
    try:
        with open(f"/sys/class/net/{iface}/{attr}") as f:
            return f.read().strip()
    except OSError:
        return None


def link_info(iface):
    """{'present', 'up', 'speed', 'duplex', 'mac'}"""
    carrier = _sysfs(iface, "carrier")
    speed = _sysfs(iface, "speed") if carrier == "1" else None
    try:
        speed = int(speed) if speed and int(speed) > 0 else None
    except ValueError:
        speed = None
    return {
        "present": os.path.exists(f"/sys/class/net/{iface}"),
        "up": carrier == "1",
        "speed": speed,
        "duplex": _sysfs(iface, "duplex") if carrier == "1" else None,
        "mac": _sysfs(iface, "address"),
    }


def iface_ipv4(iface):
    """(ip, prefixlen) or (None, None)."""
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=3).stdout
        for entry in json.loads(out or "[]"):
            for a in entry.get("addr_info", []):
                if a.get("family") == "inet":
                    return a.get("local"), int(a.get("prefixlen", 24))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return None, None


def default_gateway(iface=None, only=False):
    """Default IPv4 gateway from /proc/net/route, preferring `iface`
    (or requiring it, with only=True)."""
    best = None
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) < 8 or p[1] != "00000000" or not int(p[3], 16) & 2:
                    continue
                if only and p[0] != iface:
                    continue
                gw = socket.inet_ntoa(struct.pack("<I", int(p[2], 16)))
                metric = int(p[6])
                score = (p[0] != iface, metric)
                if best is None or score < best[0]:
                    best = (score, gw)
    except (OSError, ValueError, StopIteration):
        pass
    return best[1] if best else None


def dns_servers():
    out = []
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            with open(path) as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 2 and p[0] == "nameserver" and p[1] not in out:
                        if not p[1].startswith("127."):
                            out.append(p[1])
        except OSError:
            continue
        if out:
            break
    out.sort(key=lambda a: ":" in a)        # IPv4 first; v6 link-local is noise here
    return out


# ---------------------------------------------------------------------------
# LLDP / CDP parsing (pure functions; unit-testable off-device)
# ---------------------------------------------------------------------------

def _txt(b):
    return b.decode("utf-8", "replace").strip("\x00 \r\n\t")


def _first_line(s, limit=120):
    s = s.replace("\r", "\n")
    for line in s.split("\n"):
        if line.strip():
            return line.strip()[:limit]
    return ""


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _blank(proto, frame):
    return {"proto": proto, "name": None, "port": None, "port_descr": None,
            "vlan": None, "mgmt_ip": None, "platform": None, "chassis": None,
            "src_mac": _mac(frame[6:12]), "poe": None, "mau": None,
            "voice_vlan": None, "vlan_names": {}}


# IEEE 802.3 MAU types (RFC 4836) -> (Mb/s, duplex) for the copper/fibre
# types a switch port will realistically report.
MAU_TYPES = {10: (10, "half"), 11: (10, "full"), 12: (10, "half"), 13: (10, "full"),
             15: (100, "half"), 16: (100, "full"), 17: (100, "half"), 18: (100, "full"),
             19: (100, "half"), 20: (100, "full"), 21: (1000, "half"), 22: (1000, "full"),
             23: (1000, "half"), 24: (1000, "full"), 25: (1000, "half"), 26: (1000, "full"),
             27: (1000, "half"), 28: (1000, "full"), 29: (1000, "half"), 30: (1000, "full")}


def mau_text(mau):
    """MAU tuple -> '100 FD' style text."""
    if not mau:
        return None
    sp, dup = mau
    return f"{sp // 1000}G {'FD' if dup == 'full' else 'HD'}" if sp >= 1000 else \
        f"{sp}M {'FD' if dup == 'full' else 'HD'}"


def parse_lldp(frame):
    """Parse an Ethernet frame carrying an LLDPDU. Returns dict or None."""
    if len(frame) < 16 or frame[12:14] != b"\x88\xcc":
        return None
    r = _blank("LLDP", frame)
    pos = 14
    n = len(frame)
    while pos + 2 <= n:
        hdr = (frame[pos] << 8) | frame[pos + 1]
        t, ln = hdr >> 9, hdr & 0x1FF
        pos += 2
        if t == 0:
            break
        if pos + ln > n:
            return None                      # malformed: TLV runs off the frame
        v = frame[pos:pos + ln]
        if t == 1 and ln > 1:                # Chassis ID
            r["chassis"] = _mac(v[1:7]) if v[0] == 4 and ln == 7 else _txt(v[1:])
        elif t == 2 and ln > 1:              # Port ID
            r["port"] = _mac(v[1:7]) if v[0] == 3 and ln == 7 else _txt(v[1:])
        elif t == 4:                         # Port Description
            r["port_descr"] = _txt(v)
        elif t == 5:                         # System Name
            r["name"] = _txt(v)
        elif t == 6:                         # System Description
            r["platform"] = _first_line(_txt(v))
        elif t == 8 and ln >= 2:             # Management Address
            alen, sub = v[0], v[1]
            if sub == 1 and alen == 5 and ln >= 6 and not r["mgmt_ip"]:
                r["mgmt_ip"] = socket.inet_ntoa(v[2:6])
        elif t == 127 and ln >= 4:
            _lldp_org(r, v[0:3], v[3], v[4:])
        pos += ln
    r["name"] = r["name"] or r["chassis"]
    if not any(r[k] for k in ("name", "port", "mgmt_ip")):
        return None
    return r


def _lldp_org(r, oui, sub, v):
    """Organizationally-specific TLVs: 802.1, 802.3 and LLDP-MED."""
    if oui == b"\x00\x80\xc2":                       # IEEE 802.1
        if sub == 1 and len(v) >= 2:
            r["vlan"] = (v[0] << 8) | v[1]                 # Port VLAN ID (native)
        elif sub == 3 and len(v) >= 3:                     # VLAN Name
            vid, n = (v[0] << 8) | v[1], v[2]
            r["vlan_names"][vid] = _txt(v[3:3 + n])
    elif oui == b"\x00\x12\x0f":                     # IEEE 802.3
        if sub == 1 and len(v) >= 5:                       # MAC/PHY config/status
            r["mau"] = MAU_TYPES.get((v[3] << 8) | v[4])
        elif sub == 2 and len(v) >= 3:                     # Power via MDI
            poe = r["poe"] or {}
            poe["supported"] = bool(v[0] & 0x02)
            poe["enabled"] = bool(v[0] & 0x04)
            poe["pse"] = bool(v[0] & 0x01)
            if v[2]:
                poe["class"] = v[2] - 1
            if len(v) >= 8:                                 # 802.3at extension
                poe["type"] = 1 if v[3] & 0x80 else 2
                poe["requested_w"] = ((v[4] << 8) | v[5]) / 10
                poe["allocated_w"] = ((v[6] << 8) | v[7]) / 10
            r["poe"] = poe
    elif oui == b"\x00\x12\xbb":                     # LLDP-MED
        if sub == 2 and len(v) >= 4 and v[0] == 1:         # Network Policy: voice
            bits = (v[1] << 16) | (v[2] << 8) | v[3]
            if not bits & 0x800000:                         # U (unknown) flag clear
                r["voice_vlan"] = (bits >> 9) & 0xFFF
        elif sub == 4 and len(v) >= 3:                     # Extended Power-via-MDI
            poe = r["poe"] or {}
            poe.setdefault("allocated_w", ((v[1] << 8) | v[2]) / 10)
            poe["supported"] = True
            r["poe"] = poe


def poe_text(poe):
    """Short PoE summary, or None if the switch didn't advertise power."""
    if not poe or not (poe.get("supported") or poe.get("class") is not None
                       or poe.get("allocated_w") or poe.get("cdp_mw")):
        return None
    parts = ["PoE"]
    if poe.get("type"):
        parts.append("802.3at" if poe["type"] == 2 else "802.3af")
    if poe.get("class") is not None:
        parts.append(f"class {poe['class']}")
    w = poe.get("allocated_w") or (poe.get("cdp_mw") or poe.get("available_mw") or 0) / 1000
    if w:
        parts.append(f"{w:.1f}W")
    if poe.get("enabled") is False and not w:
        parts.append("off")
    return " ".join(parts)


def is_cdp(frame):
    return (len(frame) >= 26 and (frame[12] << 8 | frame[13]) < 0x0600
            and frame[14:22] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00")


def parse_cdp(frame):
    if not is_cdp(frame):
        return None
    r = _blank("CDP", frame)
    # 802.3 length field bounds the payload; trailing padding is ignored.
    end = min(len(frame), 14 + (frame[12] << 8 | frame[13]))
    pos = 14 + 8 + 4                          # eth + LLC/SNAP + ver/ttl/cksum
    sw_version = None
    while pos + 4 <= end:
        t = (frame[pos] << 8) | frame[pos + 1]
        ln = (frame[pos + 2] << 8) | frame[pos + 3]
        if ln < 4 or pos + ln > end:
            break
        v = frame[pos + 4:pos + ln]
        if t == 0x0001:
            r["name"] = _txt(v)
        elif t == 0x0003:
            r["port"] = _txt(v)
        elif t == 0x0005:
            sw_version = _first_line(_txt(v))
        elif t == 0x0006:
            r["platform"] = _txt(v)
        elif t == 0x000A and len(v) == 2:
            r["vlan"] = (v[0] << 8) | v[1]
        elif t in (0x0002, 0x0016) and not r["mgmt_ip"]:
            r["mgmt_ip"] = _cdp_first_ipv4(v)
        elif t == 0x000B and len(v) == 1:                   # Duplex
            r["cdp_duplex"] = "full" if v[0] else "half"
        elif t == 0x000E and len(v) >= 3:                   # Appliance (voice) VLAN
            r["voice_vlan"] = (v[1] << 8) | v[2]
        elif t == 0x0010 and len(v) == 2:                   # Power consumption, mW
            r["poe"] = dict(r["poe"] or {}, cdp_mw=(v[0] << 8) | v[1], supported=True)
        elif t == 0x001A and len(v) >= 8:                   # Power available, mW
            r["poe"] = dict(r["poe"] or {}, available_mw=struct.unpack(">I", v[4:8])[0],
                            supported=True)
        pos += ln
    if sw_version and not r["platform"]:
        r["platform"] = sw_version
    elif sw_version:
        r["platform"] = f"{r['platform']} / {sw_version}"
    if not any(r[k] for k in ("name", "port", "mgmt_ip")):
        return None
    return r


def _cdp_first_ipv4(v):
    """CDP Addresses TLV: count(4) then [ptype(1) plen(1) proto(plen) alen(2) addr]."""
    if len(v) < 4:
        return None
    count = struct.unpack(">I", v[:4])[0]
    p = 4
    for _ in range(min(count, 8)):
        if p + 2 > len(v):
            return None
        ptype, plen = v[p], v[p + 1]
        proto = v[p + 2:p + 2 + plen]
        p += 2 + plen
        if p + 2 > len(v):
            return None
        alen = struct.unpack(">H", v[p:p + 2])[0]
        addr = v[p + 2:p + 2 + alen]
        p += 2 + alen
        if ptype == 1 and proto == b"\xcc" and alen == 4:
            return socket.inet_ntoa(addr)
    return None


# ---------------------------------------------------------------------------
# 802.1X (EAPOL). An authenticator -- the switch -- on an 802.1X port sends
# EAP-Request/Identity to the PAE group address every ~30 s until a
# supplicant answers. Hearing one means "this port wants you to log in":
# the usual reason a port shows link but hands out no DHCP.
# ---------------------------------------------------------------------------

EAP_CODES = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
EAP_METHODS = {1: "Identity", 4: "MD5", 6: "GTC", 13: "TLS", 17: "LEAP", 21: "TTLS",
               25: "PEAP", 26: "MSCHAPv2", 43: "FAST", 55: "TEAP"}
EAPOL_TYPES = {0: "EAP", 1: "Start", 2: "Logoff", 3: "Key"}


def parse_eapol(frame):
    """{'src', 'eapol', 'code', 'method', 'prompt'} for an EAPOL frame, or None."""
    if len(frame) < 18 or frame[12:14] != b"\x88\x8e":
        return None
    r = {"src": _mac(frame[6:12]), "eapol": EAPOL_TYPES.get(frame[15], str(frame[15])),
         "code": None, "method": None, "prompt": None}
    if frame[15] == 0 and len(frame) >= 22:
        code, elen = frame[18], int.from_bytes(frame[20:22], "big")
        r["code"] = EAP_CODES.get(code, str(code))
        if code in (1, 2) and len(frame) >= 23 and elen >= 5:
            t = frame[22]
            r["method"] = EAP_METHODS.get(t, f"type {t}")
            if t == 1:                     # Request/Identity may carry a prompt
                r["prompt"] = _txt(frame[23:18 + elen]) or None
    return r


# ---------------------------------------------------------------------------
# Passive neighbor listener
# ---------------------------------------------------------------------------

class NeighborListener(threading.Thread):
    """Listens for LLDP and CDP on `iface` and keeps the latest of each.

    Survives the interface disappearing/reappearing (USB-Ethernet replug)
    and clears what it heard whenever link drops, so the screen never shows
    the previous switch after you move the cable.
    """

    def __init__(self, iface):
        super().__init__(daemon=True)
        self.iface = iface
        self.lock = threading.Lock()
        self.lldp = None
        self.cdp = None
        self.lldpd = None
        self.lldpd_at = 0
        self.heard_at = None
        self.auth = None                   # 802.1X: what we've heard, see auth_state()
        self.listen_since = time.monotonic()
        self.error = None
        self._stop = threading.Event()
        self._was_up = False
        self._mac = None

    def stop(self):
        self._stop.set()

    def latest(self):
        with self.lock:
            # Prefer LLDP (vendor neutral) but fill gaps from CDP: CDP carries
            # the native VLAN far more often than switches send 802.1 TLVs.
            a, b = self.lldp, self.cdp
            if not a and not b:
                # Nothing heard on the wire yet: if lldpd is installed it has
                # usually cached the neighbor already, so show that at once.
                if self.lldpd:
                    return dict(self.lldpd, age=None)
                return None
            best = dict(a or b)
            other = b if a else None
            if other:
                for k in ("vlan", "mgmt_ip", "platform", "poe", "mau", "voice_vlan"):
                    if not best.get(k) and other.get(k):
                        best[k] = other[k]
                best["vlan_names"] = dict(other.get("vlan_names") or {}, **(best.get("vlan_names") or {}))
                best["proto"] = "LLDP+CDP"
            best["age"] = time.monotonic() - self.heard_at if self.heard_at else None
            return best

    def auth_state(self):
        """802.1X on this port: {'count', 'age', 'last', 'method', 'prompt',
        'src', 'result'} once an authenticator has been heard, else None."""
        with self.lock:
            if not self.auth:
                return None
            return dict(self.auth, age=time.monotonic() - self.auth["last_at"])

    def _on_eapol(self, frame):
        e = parse_eapol(frame)
        if not e or e["src"] == self._mac or e["code"] == "Response" or e["eapol"] != "EAP":
            return                         # only what the authenticator sends us
        now = time.monotonic()
        with self.lock:
            a = self.auth or {"count": 0, "first_at": now, "method": None, "prompt": None,
                              "result": None}
            a.update(count=a["count"] + 1, last_at=now, src=e["src"], last=e["code"])
            if e["code"] in ("Success", "Failure"):
                a["result"] = e["code"]
            if e["method"] and e["method"] != "Identity":
                a["method"] = e["method"]
            if e["prompt"]:
                a["prompt"] = e["prompt"]
            self.auth = a

    def reset(self):
        with self.lock:
            self.lldp = self.cdp = self.lldpd = self.heard_at = None
            self.auth = None
            self.lldpd_at = 0
            self.listen_since = time.monotonic()

    def _open(self):
        socks = []
        ifindex = socket.if_nametoindex(self.iface)
        self._mac = link_info(self.iface).get("mac")
        for proto, mcast in ((ETH_P_LLDP, LLDP_MCAST), (ETH_P_802_2, CDP_MCAST),
                             (ETH_P_PAE, PAE_MCAST)):
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
            s.bind((self.iface, 0))
            mreq = struct.pack("iHH8s", ifindex, PACKET_MR_MULTICAST, 6, mcast)
            s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            socks.append(s)
        return socks

    def _poll_lldpd(self, up):
        now = time.monotonic()
        if up and now - self.lldpd_at > 5:
            self.lldpd_at = now
            n = lldpctl_neighbor(self.iface)
            with self.lock:
                self.lldpd = n

    def run(self):
        socks = []
        while not self._stop.is_set():
            up = link_info(self.iface)["up"]
            if up != self._was_up:
                self._was_up = up
                self.reset()
            self._poll_lldpd(up)
            if not is_root():
                if not self.lldpd:
                    self.error = "raw capture needs root; lldpd has no neighbor yet"
                else:
                    self.error = None
                self._stop.wait(2)
                continue
            if not socks:
                try:
                    socks = self._open()
                    self.error = None
                except OSError as e:
                    self.error = f"{self.iface}: {e.strerror or e}"
                    self._stop.wait(2)
                    continue
            try:
                r, _, _ = select.select(socks, [], [], 1.0)
                for s in r:
                    frame = s.recv(2048)
                    if frame[12:14] == b"\x88\xcc":
                        n = parse_lldp(frame)
                        if n:
                            with self.lock:
                                self.lldp, self.heard_at = n, time.monotonic()
                    elif frame[12:14] == b"\x88\x8e":
                        self._on_eapol(frame)
                    elif is_cdp(frame):
                        n = parse_cdp(frame)
                        if n:
                            with self.lock:
                                self.cdp, self.heard_at = n, time.monotonic()
            except OSError:
                for s in socks:
                    s.close()
                socks = []
                self._stop.wait(1)
        for s in socks:
            s.close()




# ---------------------------------------------------------------------------
# lldpd, when present (optional -- the store build can't assume it)
# ---------------------------------------------------------------------------

def lldpctl_neighbor(iface):
    """Neighbor from a running lldpd via `lldpcli -f json`, or None."""
    # Absolute paths: lldpcli lives in /usr/sbin, which isn't on a desktop
    # user's PATH when the app runs unprivileged.
    for cmd in (["/usr/sbin/lldpcli", "-f", "json", "show", "neighbors", "details", "ports", iface],
                ["/usr/sbin/lldpctl", "-f", "json", iface],
                ["lldpcli", "-f", "json", "show", "neighbors", "details", "ports", iface]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=4).stdout
            data = json.loads(out) if out.strip() else None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            continue
        if data:
            n = _normalize_lldpd(data, iface)
            if n:
                return n
    return None


def _first_value(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            return v
    if isinstance(obj, list) and obj:
        return obj[0]
    return None


def _t(v):
    if isinstance(v, dict):
        return _t(v.get("value"))
    if isinstance(v, list):
        return _t(v[0]) if v else None
    return None if v is None else str(v)


def _normalize_lldpd(data, iface):
    """lldpd's JSON shape varies by version (dict vs list-of-dicts and
    keyed-by-sysname chassis); every accessor here is defensive. Ported
    from the Pi build's diag.py."""
    lldp = data.get("lldp", data)
    if isinstance(lldp, list):
        lldp = lldp[0] if lldp else {}
    ifs = lldp.get("interface")
    block = None
    if isinstance(ifs, dict):
        block = ifs.get(iface) or _first_value(ifs)
    elif isinstance(ifs, list):
        for e in ifs:
            if isinstance(e, dict) and iface in e:
                block = e[iface]
                break
        else:
            block = _first_value(ifs[0]) if ifs else None
    if not isinstance(block, dict):
        return None
    proto = (block.get("via") or "LLDP").upper()
    r = _blank(f"{proto} (lldpd)", b"\x00" * 12)
    r["src_mac"] = None
    ch = block.get("chassis")
    if isinstance(ch, list):
        ch = ch[0] if ch else None
    body = None
    if isinstance(ch, dict):
        fv = _first_value(ch)
        if isinstance(fv, dict) and "id" not in ch and "name" not in ch:
            r["name"] = next(iter(ch.keys()))
            body = fv
        else:
            body = ch
    if isinstance(body, dict):
        r["name"] = _t(body.get("name")) or r["name"]
        descr = _t(body.get("descr"))
        r["platform"] = _first_line(descr) if descr else None
        mg = body.get("mgmt-ip")
        if isinstance(mg, list):
            mg = next((m for m in map(_t, mg) if m and "." in m), None)
        else:
            mg = _t(mg)
        r["mgmt_ip"] = mg
        cid = body.get("id")
        r["chassis"] = _t(cid)
    port = block.get("port")
    if isinstance(port, list):
        port = port[0] if port else None
    if isinstance(port, dict):
        r["port"] = _t(port.get("id"))
        r["port_descr"] = _t(port.get("descr"))
        an = port.get("auto-negotiation")
        if isinstance(an, list):
            an = an[0] if an else None
        if isinstance(an, dict):
            r["mau"] = _mau_from_text(_t(an.get("current")))
        pw = port.get("power")
        if isinstance(pw, list):
            pw = pw[0] if pw else None
        if isinstance(pw, dict):
            r["poe"] = _lldpd_power(pw)
    r["voice_vlan"] = _find_voice_vlan(block.get("lldp-med"))
    vlan = block.get("vlan")
    if isinstance(vlan, list):
        for v in vlan:
            if isinstance(v, dict) and v.get("vlan-id") is not None:
                try:
                    vid = int(_t(v.get("vlan-id")) if isinstance(v.get("vlan-id"), (dict, list))
                              else v.get("vlan-id"))
                except (TypeError, ValueError):
                    continue
                name = v.get("value")
                if isinstance(name, str) and name:
                    r["vlan_names"][vid] = name
                if v.get("pvid") in (True, "yes", "true"):
                    r["vlan"] = vid
        vlan = vlan[0] if vlan and r["vlan"] is None else None
    if isinstance(vlan, dict):
        vid = vlan.get("vlan-id") or _t(vlan)
        if vid is None:
            inner = _first_value(vlan)
            vid = inner.get("vlan-id") if isinstance(inner, dict) else None
        try:
            r["vlan"] = int(_t(vid) if isinstance(vid, (dict, list)) else vid)
        except (TypeError, ValueError):
            pass
    r["name"] = r["name"] or r["chassis"]
    if not any(r[k] for k in ("name", "port", "mgmt_ip")):
        return None
    return r


def _mau_from_text(s):
    """'100BaseTXFD - 2 pair ...' / '1000BaseTFD' -> (speed, duplex)."""
    import re
    m = re.match(r"\s*(\d+)(G?)Base\w*?(FD|HD)", s or "")
    if not m:
        return None
    sp = int(m.group(1)) * (1000 if m.group(2) else 1)
    return (sp, "full" if m.group(3) == "FD" else "half")


def _num(v):
    try:
        return float(str(_t(v) if isinstance(v, (dict, list)) else v).split()[0])
    except (TypeError, ValueError, IndexError):
        return None


def _lldpd_power(pw):
    poe = {"supported": pw.get("supported") in (True, "yes"),
           "enabled": pw.get("enabled") in (True, "yes"),
           "pse": "PSE" in str(_t(pw.get("device-type")) or "")}
    cls = _t(pw.get("class"))
    if cls:
        digits = "".join(c for c in cls if c.isdigit())
        if digits:
            poe["class"] = int(digits)
    pt = _t(pw.get("power-type"))
    if pt and pt.strip()[:1] in "12":
        poe["type"] = int(pt.strip()[0])
    alloc = _num(pw.get("allocated"))
    if alloc:
        poe["allocated_w"] = alloc / 1000 if alloc > 100 else alloc   # lldpd reports mW
    req = _num(pw.get("requested"))
    if req:
        poe["requested_w"] = req / 1000 if req > 100 else req
    return poe


def _find_voice_vlan(obj):
    """Dig an LLDP-MED voice policy VLAN out of lldpd's JSON, any shape."""
    if isinstance(obj, list):
        for x in obj:
            v = _find_voice_vlan(x)
            if v:
                return v
    elif isinstance(obj, dict):
        app = str(_t(obj.get("apptype")) or obj.get("apptype") or "")
        if "voice" in app.lower() and "signal" not in app.lower():
            vl = obj.get("vlan")
            vid = vl.get("vid") if isinstance(vl, dict) else vl
            n = _num(vid)
            if n:
                return int(n)
        for x in obj.values():
            v = _find_voice_vlan(x)
            if v:
                return v
    return None


def carrier_changes(iface):
    """Kernel count of carrier transitions since boot (catches flaps that
    happen between our polls)."""
    v = _sysfs(iface, "carrier_changes")
    return int(v) if v and v.isdigit() else None


# ---------------------------------------------------------------------------
# Active probes. Each takes a Job (see landevil.py): job.emit(line) streams
# text, job.stop is an Event the UI sets on Esc, and job.data carries the
# structured results the graphics are drawn from.
# ---------------------------------------------------------------------------

def resolve(host):
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except (socket.gaierror, IndexError, UnicodeError):
        return None


PING_COUNT = 60


def ping(job, host, iface):
    """Ping (up to PING_COUNT, 1/s) streaming per-reply RTTs.

    job.data: {"target", "rtts": [ms or None per seq], "sent"}
    """
    ip = resolve(host)
    d = job.data
    d.update(target=host, ip=ip, rtts=[], sent=0)
    if not ip:
        job.emit(f"can't resolve {host}")
        return
    args = ["ping", "-n", "-O", "-c", str(PING_COUNT), "-W", "1"]
    if link_info(iface)["up"]:
        args += ["-I", iface]              # test the wired port, not Wi-Fi
    args.append(ip)
    try:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
    except OSError as e:
        job.emit(f"ping: {e}")
        return
    stopper = threading.Thread(target=lambda: (job.stop.wait(), p.poll() is None and p.terminate()),
                               daemon=True)
    stopper.start()
    try:
        for line in p.stdout:
            line = line.rstrip()
            if not line:
                continue
            job.emit(line)
            seq = _field(line, "icmp_seq=")
            if seq is None:
                continue
            seq = int(seq)
            while len(d["rtts"]) < seq:
                d["rtts"].append(None)       # gap = lost
            if "time=" in line:
                d["rtts"][seq - 1] = float(_field(line, "time="))
            elif "no answer" in line or "Unreachable" in line:
                d["rtts"][seq - 1] = None
            d["sent"] = max(d["sent"], seq)
    finally:
        job.stop.set()
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()


def _field(line, key):
    i = line.find(key)
    if i < 0:
        return None
    v = line[i + len(key):].split()[0]
    return v.rstrip(",")


_OUI = None
_OUI_PATHS = ("/usr/share/arp-scan/ieee-oui.txt", "/usr/share/ieee-data/oui.txt",
              "/usr/share/nmap/nmap-mac-prefixes", "/usr/share/hwdata/oui.txt")


def vendor(mac):
    """Best-effort OUI vendor lookup from whatever database the OS has."""
    global _OUI
    if _OUI is None:
        _OUI = {}
        for path in _OUI_PATHS:
            try:
                with open(path, errors="replace") as f:
                    for line in f:
                        _oui_line(line)
            except OSError:
                continue
            if _OUI:
                break
    return _OUI.get(mac.replace(":", "").upper()[:6], "")


def _oui_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return
    key = line[:8].replace("-", "").replace(":", "").upper()[:6]
    if len(key) < 6 or any(c not in "0123456789ABCDEF" for c in key):
        return
    if "(hex)" in line:
        name = line.split("(hex)", 1)[1]
    elif "\t" in line:
        name = line.split("\t", 1)[1]
    elif " " in line:
        name = line.split(" ", 1)[1]
    else:
        return
    if "(base 16)" in line:
        return
    _OUI.setdefault(key, name.strip())


def arp_sweep(job, iface):
    """ARP every address in the local subnet (capped to the /24 around us).

    Same shape as the S31 firmware: paced bursts, then a 2.5 s collection
    window. job.data: {"net", "total", "sent", "hosts": [(ip, mac, vendor)]}
    """
    d = job.data
    d.update(total=0, sent=0, hosts=[])
    ip, prefix = iface_ipv4(iface)
    mac = link_info(iface)["mac"]
    if not ip or not mac:
        job.emit(f"{iface} has no IPv4 address yet")
        return
    net = ipaddress.IPv4Network(f"{ip}/{max(prefix, 24)}", strict=False)
    targets = [str(h) for h in net.hosts() if str(h) != ip]
    target_set = set(targets)
    d.update(net=str(net), total=len(targets))
    if not is_root():
        return _arp_sweep_kernel(job, iface, targets)
    my_mac = bytes.fromhex(mac.replace(":", ""))
    my_ip = socket.inet_aton(ip)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    s.bind((iface, ETH_P_ARP))
    s.setblocking(False)
    seen = {}

    def drain():
        while True:
            try:
                f = s.recv(128)
            except BlockingIOError:
                return
            if len(f) >= 42 and f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02":
                sip = socket.inet_ntoa(f[28:32])
                if sip not in seen and sip in target_set:
                    m = _mac(f[22:28])
                    seen[sip] = m
                    d["hosts"] = sorted(((k, v, vendor(v)) for k, v in seen.items()),
                                        key=lambda r: ipaddress.IPv4Address(r[0]))

    try:
        for i, t in enumerate(targets):
            if job.stop.is_set():
                return
            s.send(b"\xff" * 6 + my_mac + b"\x08\x06" +
                   b"\x00\x01\x08\x00\x06\x04\x00\x01" + my_mac + my_ip +
                   b"\x00" * 6 + socket.inet_aton(t))
            d["sent"] = i + 1
            if i % 16 == 15:
                time.sleep(0.03)
                drain()
        deadline = time.monotonic() + 2.5
        while time.monotonic() < deadline and not job.stop.is_set():
            select.select([s], [], [], 0.1)
            drain()
    finally:
        s.close()


def _arp_sweep_kernel(job, iface, targets):
    """Unprivileged fallback: poke each address with a UDP datagram so the
    kernel ARPs for it, then read the answers out of /proc/net/arp."""
    d = job.data
    target_set = set(targets)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
    except OSError:
        pass                                  # on-link routes still use iface
    s.setblocking(False)

    def collect():
        try:
            with open("/proc/net/arp") as f:
                next(f)
                rows = [l.split() for l in f]
        except (OSError, StopIteration):
            return
        found = {r[0]: r[3] for r in rows
                 if len(r) >= 6 and r[5] == iface and r[0] in target_set
                 and int(r[2], 16) & 0x2 and r[3] != "00:00:00:00:00:00"}
        d["hosts"] = sorted(((k, v, vendor(v)) for k, v in found.items()),
                            key=lambda r: ipaddress.IPv4Address(r[0]))

    try:
        for i, t in enumerate(targets):
            if job.stop.is_set():
                return
            try:
                s.sendto(b"\0", (t, 9))       # discard port; reply irrelevant
            except OSError:
                pass
            d["sent"] = i + 1
            if i % 16 == 15:
                time.sleep(0.03)
                collect()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not job.stop.is_set():
            time.sleep(0.25)
            collect()
    finally:
        s.close()


COMMON_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (80, "http"), (88, "kerberos"), (110, "pop3"), (135, "msrpc"),
    (139, "netbios"), (143, "imap"), (389, "ldap"), (443, "https"),
    (445, "smb"), (502, "modbus"), (515, "lpd"), (554, "rtsp"),
    (631, "ipp"), (1883, "mqtt"), (3306, "mysql"), (3389, "rdp"),
    (5000, "upnp"), (5432, "postgres"), (5900, "vnc"), (8000, "http-alt"),
    (8080, "http-alt"), (8443, "https-alt"), (9100, "jetdirect"),
]


def port_scan(job, host, iface, timeout=0.8):
    """TCP connect scan of COMMON_PORTS.

    job.data: {"target", "ip", "state": {port: "open"|"closed"|"scanning"}}
    """
    d = job.data
    d.update(target=host, ip=None, state={})
    ip = resolve(host)
    if not ip:
        job.emit(f"can't resolve {host}")
        return
    d["ip"] = ip
    bind = is_root() and link_info(iface)["up"]
    lock = threading.Lock()
    queue = list(COMMON_PORTS)

    def worker():
        while not job.stop.is_set():
            with lock:
                if not queue:
                    return
                port, _ = queue.pop(0)
                d["state"][port] = "scanning"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            res = "closed"
            try:
                if bind:
                    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
                if s.connect_ex((ip, port)) == 0:
                    res = "open"
            except OSError:
                pass
            finally:
                s.close()
            d["state"][port] = res

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ---------------------------------------------------------------------------
# NET: DNS lookup, internet / captive-portal check, traceroute. Everything
# is pinned to the wired port (SO_BINDTODEVICE when root), so the answers
# describe *this* port -- not Wi-Fi, not a VPN's resolver.
# ---------------------------------------------------------------------------

IP_RECVERR = 11
NET_CHECK_HOST = "connectivitycheck.gstatic.com"     # answers 204 when online
TRACE_MAX_HOPS = 20


def _bind(sock, iface):
    if is_root() and link_info(iface)["up"]:
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
        except OSError:
            pass


def _ipv4s(items):
    out = []
    for a in items:
        a = a.strip()
        try:
            if ipaddress.IPv4Address(a) and a not in out and not a.startswith("127."):
                out.append(a)
        except ValueError:
            pass
    return out


def iface_dns(iface):
    """IPv4 DNS servers handed to `iface` (DHCP), not whatever a VPN put in
    /etc/resolv.conf. Tries NetworkManager, then systemd-resolved; [] if
    neither knows the interface."""
    for cmd in (["nmcli", "-g", "IP4.DNS", "device", "show", iface],
                ["resolvectl", "dns", iface]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        if cmd[0] == "resolvectl":
            out = out.split(":", 1)[1] if ":" in out else ""
        found = _ipv4s(out.replace("|", " ").split())
        if found:
            return found
    return []


def _dns_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("idna")
        if not 0 < len(b) < 64:
            raise ValueError(f"bad name: {name}")
        out += bytes([len(b)]) + b
    return out + b"\0"


def _skip_name(msg, i):
    while i < len(msg):
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1
    raise ValueError("truncated name")


DNS_RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns_build_query(qid, name):
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack(">HH", 1, 1)


def dns_parse_reply(msg, qid):
    """(ips, error) from a DNS reply to query `qid`; error is None, an rcode
    name, or 'no A record'."""
    if len(msg) < 12:
        raise ValueError("short reply")
    rid, flags, qd, an = struct.unpack(">HHHH", msg[:8])
    if rid != qid:
        raise ValueError("wrong id")
    if flags & 0xF:
        return [], DNS_RCODES.get(flags & 0xF, f"rcode {flags & 0xF}")
    i = 12
    for _ in range(qd):
        i = _skip_name(msg, i) + 4
    ips = []
    for _ in range(an):
        i = _skip_name(msg, i)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(msg[i:i + 4]))
        i += rdlen
    return ips, None if ips else "no A record"


def dns_query(server, name, iface, timeout=2.0):
    """Ask one server for `name` A records: {'server','ms','ips','err'}."""
    r = {"server": server, "ms": None, "ips": [], "err": None}
    qid = int.from_bytes(os.urandom(2), "big")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        _bind(s, iface)
        t0 = time.monotonic()
        s.sendto(dns_build_query(qid, name), (server, 53))
        end = t0 + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0 or not select.select([s], [], [], left)[0]:
                r["err"] = "timeout"
                break
            msg, src = s.recvfrom(1500)
            try:
                r["ips"], r["err"] = dns_parse_reply(msg, qid)
            except (ValueError, struct.error):
                continue                   # not ours / garbled: keep waiting
            r["ms"] = (time.monotonic() - t0) * 1000
            break
    except (OSError, ValueError) as e:
        r["err"] = getattr(e, "strerror", None) or str(e)
    finally:
        s.close()
    return r


def http_check(ip, iface, timeout=4.0):
    """GET /generate_204 from `ip` (Host: NET_CHECK_HOST).
    {'state': 'online'|'portal'|'blocked', 'detail', 'ms'}"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        _bind(s, iface)
        t0 = time.monotonic()
        s.connect((ip, 80))
        s.sendall(f"GET /generate_204 HTTP/1.1\r\nHost: {NET_CHECK_HOST}\r\n"
                  "User-Agent: LAN-Devil\r\nConnection: close\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 8192:
            chunk = s.recv(2048)
            if not chunk:
                break
            head += chunk
        ms = (time.monotonic() - t0) * 1000
    except OSError as e:
        return {"state": "blocked", "detail": e.strerror or str(e), "ms": None}
    finally:
        s.close()
    lines = head.decode("latin-1", "replace").split("\r\n")
    parts = lines[0].split()
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    if code == 204:
        return {"state": "online", "detail": "HTTP 204", "ms": ms}
    where = next((ln.split(":", 1)[1].strip() for ln in lines[1:]
                  if ln.lower().startswith("location:")), None)
    if where:
        where = where.split("//", 1)[-1].split("/", 1)[0]
    return {"state": "portal", "detail": f"HTTP {code or '?'}" + (f" → {where}" if where else ""),
            "ms": ms}


def parse_recverr(cdata):
    """(icmp_type, icmp_code, offender_ip) from an IP_RECVERR control
    message (struct sock_extended_err + sockaddr_in), or None if it isn't
    an ICMP error."""
    if len(cdata) < 24:
        return None
    _, origin, etype, code = struct.unpack("=IBBB", cdata[:7])
    if origin != 2:                        # SO_EE_ORIGIN_ICMP
        return None
    return etype, code, socket.inet_ntoa(cdata[20:24])


def trace_hop(ip, ttl, iface, timeout=1.5):
    """One UDP probe at `ttl`. {'ttl','ip','ms','end'} where end is None,
    'reached', or an unreachable marker. Uses IP_RECVERR, so no root needed."""
    hop = {"ttl": ttl, "ip": None, "ms": None, "end": None}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setblocking(False)
        s.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        _bind(s, iface)
        t0 = time.monotonic()
        s.sendto(b"LAN Devil trace", (ip, 33434 + ttl))
        end = t0 + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0 or not select.select([s], [], [], left)[0]:
                return hop
            try:
                _, anc, _, _ = s.recvmsg(512, 512, socket.MSG_ERRQUEUE)
            except BlockingIOError:
                try:
                    s.recv(512)            # a real UDP answer: the target itself
                    hop.update(ip=ip, ms=(time.monotonic() - t0) * 1000, end="reached")
                    return hop
                except OSError:
                    continue
            for level, kind, cdata in anc:
                if level != socket.IPPROTO_IP or kind != IP_RECVERR:
                    continue
                err = parse_recverr(cdata)
                if not err:
                    continue
                etype, code, src = err
                hop.update(ip=src, ms=(time.monotonic() - t0) * 1000)
                if etype == 3:             # destination unreachable
                    hop["end"] = "reached" if code == 3 else {0: "!N", 1: "!H", 13: "!X"}.get(code, f"!{code}")
                return hop
    except OSError as e:
        hop["end"] = f"error: {e.strerror or e}"
        return hop
    finally:
        s.close()


def netcheck(job, host, iface, dns):
    """DNS, then internet/captive-portal, then traceroute -- one job.

    job.data: {'target', 'ip', 'phase', 'dns': [dns_query results],
               'web': http_check result, 'hops': [trace_hop results]}
    """
    d = job.data
    d.update(target=host, ip=None, phase="dns", dns=[], web=None, hops=[], servers=dns[:3])
    try:
        ipaddress.IPv4Address(host)
        d["ip"] = host
    except ValueError:
        for server in dns[:3]:
            if job.stop.is_set():
                return
            r = dns_query(server, host, iface)
            d["dns"].append(r)
            if r["ips"] and not d["ip"]:
                d["ip"] = r["ips"][0]
        if not dns:
            d["ip"] = resolve(host)        # no per-port DNS known: system resolver
            d["dns"].append({"server": "system", "ms": None, "ips": [d["ip"]] if d["ip"] else [],
                             "err": None if d["ip"] else "can't resolve"})

    d["phase"] = "web"
    if job.stop.is_set():
        return
    check_ip = None
    for server in dns[:3]:
        r = dns_query(server, NET_CHECK_HOST, iface)
        if r["ips"]:
            check_ip = r["ips"][0]
            break
    if not check_ip:
        check_ip = resolve(NET_CHECK_HOST)
    d["web"] = http_check(check_ip, iface) if check_ip else \
        {"state": "blocked", "detail": "DNS failed", "ms": None}

    d["phase"] = "trace"
    if not d["ip"]:
        job.emit(f"can't resolve {host}")
        d["phase"] = "done"
        return
    silent = 0
    for ttl in range(1, TRACE_MAX_HOPS + 1):
        if job.stop.is_set():
            break
        hop = trace_hop(d["ip"], ttl, iface)
        d["hops"].append(hop)
        silent = silent + 1 if hop["ip"] is None else 0
        if hop["end"] or silent >= 5:
            break
    d["phase"] = "done"
