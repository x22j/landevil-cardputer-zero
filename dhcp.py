"""
dhcp.py -- DHCP on raw sockets: a rogue-server probe and a one-shot lease.

probe():  broadcast DHCPDISCOVER and collect *every* OFFER for a few
          seconds. More than one distinct server = a second DHCP server on
          the segment (rogue, or a misconfigured relay). Discover only:
          nothing is requested, so no lease is taken.
lease():  full DISCOVER/OFFER/REQUEST/ACK, used when joining a VLAN.
release(): DHCPRELEASE, so we hand the address back when leaving.

Raw AF_PACKET (root) rather than a UDP socket on :68, because
NetworkManager's client already owns port 68 on this image.
"""

import os
import random
import select
import socket
import struct
import time

ETH_P_IP = 0x0800
MAGIC = b"\x63\x82\x53\x63"
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE = 1, 2, 3, 4, 5, 6, 7
PARAMS = bytes([1, 3, 6, 15, 51, 54, 42, 66, 67, 43, 119, 121, 150, 252])


def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _frame(src_mac, dst_mac, src_ip, dst_ip, payload):
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0x10, 20 + len(udp), random.getrandbits(16),
                     0, 64, 17, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + udp


def _bootp(mac, xid, opts, ciaddr=b"\0" * 4, broadcast=True):
    body = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0,
                       0x8000 if broadcast else 0, ciaddr, b"\0" * 4, b"\0" * 4,
                       b"\0" * 4, mac + b"\0" * 10, b"", b"")
    msg = body + MAGIC + opts + b"\xff"
    return msg + b"\0" * max(0, 300 - len(msg))


def _opt(code, data):
    return bytes([code, len(data)]) + data


def _hostname():
    try:
        return socket.gethostname().encode()[:32]
    except OSError:
        return b"landevil"


def parse(frame):
    """Parse an Ethernet/IPv4/UDP 67->68 BOOTP reply; dict or None."""
    if len(frame) < 14 + 20 + 8 + 240 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != 17:
        return None
    u = 14 + ihl
    sport, dport = struct.unpack("!HH", frame[u:u + 4])
    if sport != 67 or dport != 68:
        return None
    b = frame[u + 8:]
    if len(b) < 240 or b[0] != 2 or b[236:240] != MAGIC:
        return None
    r = {"xid": struct.unpack("!I", b[4:8])[0], "yiaddr": socket.inet_ntoa(b[16:20]),
         "siaddr": socket.inet_ntoa(b[20:24]), "giaddr": socket.inet_ntoa(b[24:28]),
         "src_ip": socket.inet_ntoa(frame[26:30]),
         "src_mac": ":".join(f"{x:02x}" for x in frame[6:12]),
         "sname": b[44:108].split(b"\0")[0].decode("ascii", "replace"),
         "file": b[108:236].split(b"\0")[0].decode("ascii", "replace"), "opts": {}}
    p = 240
    while p < len(b):
        code = b[p]
        if code == 255:
            break
        if code == 0:
            p += 1
            continue
        if p + 2 > len(b):
            break
        ln = b[p + 1]
        r["opts"][code] = b[p + 2:p + 2 + ln]
        p += 2 + ln
    o = r["opts"]
    r["type"] = o.get(53, b"\0")[0]
    ips = lambda v: [socket.inet_ntoa(v[i:i + 4]) for i in range(0, len(v) - 3, 4)]
    r["server"] = socket.inet_ntoa(o[54]) if len(o.get(54, b"")) == 4 else r["src_ip"]
    r["mask"] = socket.inet_ntoa(o[1]) if len(o.get(1, b"")) == 4 else None
    r["prefix"] = bin(struct.unpack("!I", o[1])[0]).count("1") if r["mask"] else None
    r["router"] = ips(o.get(3, b""))
    r["dns"] = ips(o.get(6, b""))
    r["ntp"] = ips(o.get(42, b""))
    r["domain"] = o.get(15, b"").decode("ascii", "replace").strip("\0") or None
    r["lease"] = struct.unpack("!I", o[51])[0] if len(o.get(51, b"")) == 4 else None
    tftp = o.get(66, b"").decode("ascii", "replace").strip("\0")
    if len(o.get(150, b"")) >= 4:
        tftp = tftp or ", ".join(ips(o[150]))
    r["tftp"] = tftp or (r["siaddr"] if r["siaddr"] != "0.0.0.0" and r["file"] else None)
    r["bootfile"] = o.get(67, b"").decode("ascii", "replace").strip("\0") or r["file"] or None
    r["wpad"] = o.get(252, b"").decode("ascii", "replace").strip("\0") or None
    r["vendor_len"] = len(o[43]) if 43 in o else 0
    return r


class _Raw:
    def __init__(self, iface, mac):
        self.iface = iface
        self.mac = bytes.fromhex(mac.replace(":", ""))
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        self.s.bind((iface, ETH_P_IP))

    def send(self, payload, dst_mac=b"\xff" * 6, src_ip=b"\0" * 4, dst_ip=b"\xff" * 4):
        self.s.send(_frame(self.mac, dst_mac, src_ip, dst_ip, payload))

    def recv_until(self, deadline, xid):
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            r, _, _ = select.select([self.s], [], [], min(left, 0.2))
            if r:
                d = parse(self.s.recv(2048))
                if d and d["xid"] == xid:
                    yield d
            else:
                yield None              # lets callers check cancellation

    def close(self):
        self.s.close()


def _mac_of(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except OSError:
        return None


def probe(job, iface, listen=4.0):
    """Collect all OFFERs. job.data: {"iface", "offers": [...], "done"}"""
    d = job.data
    d.update(iface=iface, offers=[], started=time.monotonic())
    if os.geteuid() != 0:
        job.emit("DHCP probe needs root (passwordless sudo)")
        return
    mac = _mac_of(iface)
    if not mac:
        job.emit(f"no interface {iface}")
        return
    raw = _Raw(iface, mac)
    xid = random.getrandbits(32)
    disc = _bootp(raw.mac, xid, _opt(53, bytes([DISCOVER])) + _opt(55, PARAMS) +
                  _opt(12, _hostname()) + _opt(57, struct.pack("!H", 1500)))
    seen = {}
    try:
        raw.send(disc)
        resent = False
        deadline = time.monotonic() + listen
        for r in raw.recv_until(deadline, xid):
            if job.stop.is_set():
                return
            if not resent and time.monotonic() > deadline - listen / 2:
                raw.send(disc)          # once more, in case the first was lost
                resent = True
            if r and r["type"] == OFFER:
                key = (r["server"], r["src_mac"])
                if key not in seen:
                    seen[key] = r
                    d["offers"] = list(seen.values())
    finally:
        raw.close()


def lease(iface, timeout=6.0, stop=None):
    """DORA on `iface`. Returns the ACK dict (with 'server', 'yiaddr', ...)
    or raises RuntimeError with a short reason."""
    mac = _mac_of(iface)
    if not mac:
        raise RuntimeError(f"no interface {iface}")
    raw = _Raw(iface, mac)
    xid = random.getrandbits(32)
    common = _opt(55, PARAMS) + _opt(12, _hostname())
    try:
        offer = None
        for attempt in range(2):
            raw.send(_bootp(raw.mac, xid, _opt(53, bytes([DISCOVER])) + common))
            for r in raw.recv_until(time.monotonic() + timeout / 2, xid):
                if stop is not None and stop.is_set():
                    raise RuntimeError("cancelled")
                if r and r["type"] == OFFER:
                    offer = r
                    break
            if offer:
                break
        if not offer:
            raise RuntimeError("no DHCP offer on this VLAN")
        req = _bootp(raw.mac, xid, _opt(53, bytes([REQUEST])) +
                     _opt(50, socket.inet_aton(offer["yiaddr"])) +
                     _opt(54, socket.inet_aton(offer["server"])) + common)
        raw.send(req)
        for r in raw.recv_until(time.monotonic() + timeout / 2, xid):
            if stop is not None and stop.is_set():
                raise RuntimeError("cancelled")
            if r and r["type"] == ACK:
                r["server_mac"] = offer["src_mac"]
                return r
            if r and r["type"] == NAK:
                raise RuntimeError(f"server {r['server']} refused (NAK)")
        raise RuntimeError("no DHCP ACK")
    finally:
        raw.close()


def release(iface, ack):
    """Hand the address back. Best effort; never raises."""
    try:
        mac = _mac_of(iface)
        raw = _Raw(iface, mac)
        ci = socket.inet_aton(ack["yiaddr"])
        msg = _bootp(raw.mac, random.getrandbits(32),
                     _opt(53, bytes([RELEASE])) + _opt(54, socket.inet_aton(ack["server"])),
                     ciaddr=ci, broadcast=False)
        dst_mac = bytes.fromhex(ack.get("server_mac", "ff:ff:ff:ff:ff:ff").replace(":", ""))
        raw.send(msg, dst_mac=dst_mac, src_ip=ci, dst_ip=socket.inet_aton(ack["server"]))
        raw.close()
    except Exception:
        pass
