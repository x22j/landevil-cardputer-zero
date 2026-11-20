"""
vlan.py -- find the VLANs on a trunk port, and hop onto one.

sniff():  watch 802.1Q-tagged frames on the parent interface. Linux strips
          the tag before packet taps see the frame (always in software, and
          the r8152 USB NIC also does it in hardware), so the VLAN ID comes
          from PACKET_AUXDATA, with the in-frame tag as a fallback. A
          kernel BPF filter keeps untagged traffic out of Python entirely.
          Passive: nothing is transmitted (the port goes promiscuous while
          the screen is watching, so it sees unicast as well as broadcast).
join():   ip link add eth0.N, a DHCP lease on it, address assigned (no
          default route, so Wi-Fi/SSH keep working). LAN Devil's probes then
          run on eth0.N.
leave():  DHCPRELEASE + delete the interface.

Tags only appear on trunk ports; on an access port this sees nothing,
which is itself the answer.
"""

import ctypes
import ipaddress
import select
import socket
import struct
import subprocess
import time

import dhcp

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
SO_ATTACH_FILTER = 26
SKF_AD_VLAN_TAG_PRESENT = 0xFFFFF000 + 48     # SKF_AD_OFF + 48

# Accept (first 96 bytes of) frames that are tagged, by metadata or in-frame.
_BPF = [
    (0x20, 0, 0, SKF_AD_VLAN_TAG_PRESENT),   # ld  vlan_avail
    (0x15, 1, 0, 0),                         # jeq #0 -> check frame, else accept
    (0x06, 0, 0, 96),                        # ret #96
    (0x28, 0, 0, 12),                        # ldh [12]
    (0x15, 2, 0, 0x8100),                    # jeq 802.1Q -> accept
    (0x15, 1, 0, 0x88A8),                    # jeq 802.1ad -> accept
    (0x06, 0, 0, 0),                         # ret #0 (drop)
    (0x06, 0, 0, 96),                        # ret #96
]


def _attach_bpf(s):
    prog = b"".join(struct.pack("HBBI", *ins) for ins in _BPF)
    buf = ctypes.create_string_buffer(prog)
    fprog = struct.pack("HL", len(_BPF), ctypes.addressof(buf))
    s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
    return buf        # keep alive while attached (the kernel copies it, but be safe)


_KINDS = {0x0806: "ARP", 0x0800: "IPv4", 0x86DD: "IPv6", 0x88CC: "LLDP", 0x8100: "QinQ"}


def _kind(inner_type, payload):
    if inner_type in _KINDS:
        return _KINDS[inner_type]
    if inner_type < 0x0600:
        if payload[:2] == b"\x42\x42":
            return "STP"
        if payload[:8] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
            return "CDP"
        return "LLC"
    return f"0x{inner_type:04x}"


def sniff(job, iface):
    """job.data: {"vlans": {vid: {...}}, "frames": n}. Runs until Esc."""
    d = job.data
    d.update(vlans={}, frames=0, started=time.monotonic())
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        s.bind((iface, 0))
        s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        ifindex = socket.if_nametoindex(iface)
        s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                     struct.pack("iHH8s", ifindex, PACKET_MR_PROMISC, 0, b""))
        try:
            keep = _attach_bpf(s)  # noqa: F841
        except OSError:
            keep = None            # noqa: F841 -- filter in Python instead
        cmsg_len = socket.CMSG_SPACE(20)
        while not job.stop.is_set():
            r, _, _ = select.select([s], [], [], 0.25)
            if not r:
                continue
            for _ in range(64):            # drain a burst per wakeup
                try:
                    f, anc, _, _ = s.recvmsg(256, cmsg_len, socket.MSG_DONTWAIT)
                except BlockingIOError:
                    break
                vid = None
                for level, typ, data in anc:
                    if level == SOL_PACKET and typ == PACKET_AUXDATA and len(data) >= 20:
                        status, _, _, _, _, tci, _ = struct.unpack("IIIHHHH", data[:20])
                        if status & TP_STATUS_VLAN_VALID:
                            vid = tci & 0xFFF
                off = 12
                if vid is None and len(f) >= 18 and f[12:14] in (b"\x81\x00", b"\x88\xa8"):
                    vid = ((f[14] << 8) | f[15]) & 0xFFF
                    off = 16
                if vid is None or len(f) < off + 2:
                    continue
                inner = (f[off] << 8) | f[off + 1]
                payload = f[off + 2:]
                _account(d, vid, f, inner, payload)
    finally:
        s.close()


def _account(d, vid, f, inner, payload):
    d["frames"] += 1
    v = d["vlans"].get(vid)
    if v is None:
        v = d["vlans"][vid] = {"frames": 0, "macs": set(), "ips": set(), "kinds": {},
                               "first": time.monotonic(), "last": 0}
    v["frames"] += 1
    v["last"] = time.monotonic()
    if len(v["macs"]) < 4096:
        v["macs"].add(bytes(f[6:12]))
    k = _kind(inner, payload)
    v["kinds"][k] = v["kinds"].get(k, 0) + 1
    if inner == 0x0806 and len(payload) >= 28 and len(v["ips"]) < 1024:
        sip = payload[14:18]
        if sip != b"\0\0\0\0":
            v["ips"].add(socket.inet_ntoa(sip))
    elif inner == 0x0800 and len(payload) >= 20 and len(v["ips"]) < 1024:
        src = payload[12:16]
        if src[0] not in (0, 127, 169, 224, 255) and src[0] < 224:
            v["ips"].add(socket.inet_ntoa(src))


def subnet_guess(ips):
    """Most common /24 among private source addresses seen on the VLAN."""
    counts = {}
    for ip in ips:
        try:
            a = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if not a.is_private:
            continue
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        counts[net] = counts.get(net, 0) + 1
    if not counts:
        return None
    return str(max(counts, key=counts.get))


# ---------------------------------------------------------------------------
# join / leave
# ---------------------------------------------------------------------------

def _ip(*args):
    p = subprocess.run(["ip", *args], capture_output=True, text=True, timeout=5)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip().splitlines()[-1] if
                           (p.stderr or p.stdout).strip() else f"ip {' '.join(args)} failed")
    return p.stdout


def vlan_ifname(parent, vid):
    name = f"{parent}.{vid}"
    return name if len(name) <= 15 else f"ldv.{vid}"


def join(job, parent, vid):
    """job.data: {"vid", "iface", "state", "ack", "error"}"""
    d = job.data
    name = vlan_ifname(parent, vid)
    d.update(vid=vid, iface=name, state="creating", ack=None, error=None)
    created = False
    try:
        try:
            _ip("link", "add", "link", parent, "name", name, "type", "vlan", "id", str(vid))
            created = True
        except RuntimeError as e:
            if "exists" not in str(e):
                raise
        # Keep NetworkManager's hands off it; we manage the address ourselves.
        subprocess.run(["nmcli", "device", "set", name, "managed", "no"],
                       capture_output=True, timeout=5)
        _ip("link", "set", name, "up")
        time.sleep(0.5)
        d["state"] = "dhcp"
        ack = dhcp.lease(name, stop=job.stop)
        _ip("addr", "add", f"{ack['yiaddr']}/{ack['prefix'] or 24}", "dev", name)
        d.update(ack=ack, state="up", created=created)
    except Exception as e:
        d.update(state="failed", error=str(e))
        if created:
            try:
                _ip("link", "del", name)
            except Exception:
                pass


def leave(name, ack=None):
    if ack:
        dhcp.release(name, ack)
    try:
        _ip("link", "del", name)
    except Exception:
        pass
