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
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
SO_BINDTODEVICE = 25

LLDP_MCAST = bytes.fromhex("0180c200000e")
CDP_MCAST = bytes.fromhex("01000ccccccc")


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


def parse_lldp(frame):
    """Parse an Ethernet frame carrying an LLDPDU. Returns dict or None."""
    if len(frame) < 16 or frame[12:14] != b"\x88\xcc":
        return None
    r = {"proto": "LLDP", "name": None, "port": None, "port_descr": None,
         "vlan": None, "mgmt_ip": None, "platform": None, "chassis": None,
         "src_mac": _mac(frame[6:12])}
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
        elif t == 127 and ln >= 6 and v[0:3] == b"\x00\x80\xc2" and v[3] == 1:
            r["vlan"] = (v[4] << 8) | v[5]   # IEEE 802.1 Port VLAN ID
        pos += ln
    r["name"] = r["name"] or r["chassis"]
    if not any(r[k] for k in ("name", "port", "mgmt_ip")):
        return None
    return r


def is_cdp(frame):
    return (len(frame) >= 26 and (frame[12] << 8 | frame[13]) < 0x0600
            and frame[14:22] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00")


def parse_cdp(frame):
    if not is_cdp(frame):
        return None
    r = {"proto": "CDP", "name": None, "port": None, "port_descr": None,
         "vlan": None, "mgmt_ip": None, "platform": None, "chassis": None,
         "src_mac": _mac(frame[6:12])}
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
        self.listen_since = time.monotonic()
        self.error = None
        self._stop = threading.Event()
        self._was_up = False

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
                for k in ("vlan", "mgmt_ip", "platform"):
                    if not best.get(k) and other.get(k):
                        best[k] = other[k]
                best["proto"] = "LLDP+CDP"
            best["age"] = time.monotonic() - self.heard_at if self.heard_at else None
            return best

    def reset(self):
        with self.lock:
            self.lldp = self.cdp = self.lldpd = self.heard_at = None
            self.lldpd_at = 0
            self.listen_since = time.monotonic()

    def _open(self):
        socks = []
        ifindex = socket.if_nametoindex(self.iface)
        for proto, mcast in ((ETH_P_LLDP, LLDP_MCAST), (ETH_P_802_2, CDP_MCAST)):
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
    for cmd in (["lldpcli", "-f", "json", "show", "neighbors", "ports", iface],
                ["lldpctl", "-f", "json", iface]):
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
    r = {"proto": f"{proto} (lldpd)", "name": None, "port": None, "port_descr": None,
         "vlan": None, "mgmt_ip": None, "platform": None, "chassis": None, "src_mac": None}
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
    vlan = block.get("vlan")
    if isinstance(vlan, list):
        vlan = vlan[0] if vlan else None
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
