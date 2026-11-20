"""Off-device tests for the v0.2 features."""
import os
import socket
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import dhcp  # noqa: E402
import netdiag  # noqa: E402
import vlan  # noqa: E402
from portlog import PortLog  # noqa: E402
from test_netdiag import SRC, cdp_tlv, lldp_tlv  # noqa: E402


def lldp(*tlvs):
    return netdiag.LLDP_MCAST + SRC + b"\x88\xcc" + b"".join(tlvs) + lldp_tlv(0, b"")


BASE = [lldp_tlv(1, b"\x04" + SRC), lldp_tlv(2, b"\x05Gi1/0/24"), lldp_tlv(5, b"sw1")]


class LldpExtras(unittest.TestCase):
    def test_poe_at_mau_voice_vlan_names(self):
        f = lldp(*BASE,
                 lldp_tlv(127, b"\x00\x12\x0f\x01" + b"\x03\x6c\x01\x00\x10"),       # MAU 16 = 100FD
                 lldp_tlv(127, b"\x00\x12\x0f\x02" + b"\x0f\x01\x05" + b"\x51\x00\xff\x00\xff"),
                 lldp_tlv(127, b"\x00\x12\xbb\x02" + b"\x01" + ((30 << 9) | (5 << 6) | 46).to_bytes(3, "big")),
                 lldp_tlv(127, b"\x00\x80\xc2\x03" + b"\x00\x14\x04DATA"),
                 lldp_tlv(127, b"\x00\x80\xc2\x01" + b"\x00\x14"))
        r = netdiag.parse_lldp(f)
        self.assertEqual(r["mau"], (100, "full"))
        self.assertEqual(r["poe"]["class"], 4)
        self.assertEqual(r["poe"]["type"], 2)
        self.assertAlmostEqual(r["poe"]["allocated_w"], 25.5)
        self.assertEqual(r["voice_vlan"], 30)
        self.assertEqual(r["vlan_names"], {20: "DATA"})
        self.assertEqual(r["vlan"], 20)
        self.assertEqual(netdiag.poe_text(r["poe"]), "PoE 802.3at class 4 25.5W")
        self.assertEqual(netdiag.mau_text(r["mau"]), "100M FD")

    def test_med_unknown_policy_ignored(self):
        f = lldp(*BASE, lldp_tlv(127, b"\x00\x12\xbb\x02\x01" + (0x800000 | (30 << 9)).to_bytes(3, "big")))
        self.assertIsNone(netdiag.parse_lldp(f)["voice_vlan"])

    def test_cdp_power_voice_duplex(self):
        payload = (b"\x02\xb4\x00\x00" + cdp_tlv(1, b"sw1") + cdp_tlv(3, b"Fa0/1") +
                   cdp_tlv(0x0B, b"\x00") + cdp_tlv(0x0E, b"\x01\x00\x1e") + cdp_tlv(0x10, b"\x1b\x58"))
        llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + payload
        r = netdiag.parse_cdp(netdiag.CDP_MCAST + SRC + struct.pack(">H", len(llc)) + llc)
        self.assertEqual(r["voice_vlan"], 30)
        self.assertEqual(r["cdp_duplex"], "half")
        self.assertEqual(r["poe"]["cdp_mw"], 7000)
        self.assertEqual(netdiag.poe_text(r["poe"]), "PoE 7.0W")

    def test_lldpd_power_autoneg_med(self):
        data = {"lldp": {"interface": {"eth0": {"via": "LLDP",
            "chassis": {"sw1": {"id": {"type": "mac", "value": "aa"}}},
            "port": {"id": {"value": "Gi1/0/3"},
                     "auto-negotiation": {"supported": True, "enabled": True,
                                          "current": "1000BaseTFD - Four-pair Category 5 UTP, full duplex mode"},
                     "power": {"supported": True, "enabled": True, "device-type": "PSE",
                               "class": "class 4", "power-type": "2", "allocated": "25500"}},
            "vlan": [{"vlan-id": "20", "pvid": True, "value": "DATA"}, {"vlan-id": "30", "value": "VOICE"}],
            "lldp-med": {"policy": [{"apptype": "Voice", "vlan": {"vid": 30}}]}}}}}
        r = netdiag._normalize_lldpd(data, "eth0")
        self.assertEqual(r["mau"], (1000, "full"))
        self.assertEqual(r["poe"]["class"], 4)
        self.assertAlmostEqual(r["poe"]["allocated_w"], 25.5)
        self.assertEqual(r["voice_vlan"], 30)
        self.assertEqual(r["vlan"], 20)
        self.assertEqual(r["vlan_names"], {20: "DATA", 30: "VOICE"})


def offer_frame(server="10.0.0.1", yi="10.0.0.50", xid=0x1234):
    opts = (b"\x35\x01\x02" + b"\x36\x04" + socket.inet_aton(server) +
            b"\x01\x04" + socket.inet_aton("255.255.255.0") + b"\x03\x04" + socket.inet_aton(server) +
            b"\x06\x08" + socket.inet_aton("1.1.1.1") + socket.inet_aton("8.8.8.8") +
            b"\x33\x04\x00\x01\x51\x80" + b"\x0f\x07example" + b"\x42\x08tftp.lan" + b"\xff")
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4,
                        socket.inet_aton(yi), b"\0" * 4, b"\0" * 4, b"\x11" * 6 + b"\0" * 10,
                        b"", b"") + dhcp.MAGIC + opts
    return dhcp._frame(b"\xaa" * 6, b"\xff" * 6, socket.inet_aton(server), b"\xff" * 4, bootp)


class Dhcp(unittest.TestCase):
    def test_offer_parse(self):
        # _frame builds 68->67 (client side); flip ports to make a server reply.
        f = bytearray(offer_frame())
        f[34:38] = struct.pack("!HH", 67, 68)
        r = dhcp.parse(bytes(f))
        self.assertEqual((r["type"], r["server"], r["yiaddr"], r["prefix"]), (dhcp.OFFER, "10.0.0.1", "10.0.0.50", 24))
        self.assertEqual(r["dns"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual((r["lease"], r["domain"], r["tftp"]), (86400, "example", "tftp.lan"))
        self.assertEqual(r["xid"], 0x1234)

    def test_discover_is_valid_ip(self):
        f = dhcp._frame(b"\xaa" * 6, b"\xff" * 6, b"\0" * 4, b"\xff" * 4, dhcp._bootp(b"\xaa" * 6, 1, b""))
        self.assertEqual(dhcp._csum(f[14:34]), 0)            # IP header checksum verifies
        self.assertGreaterEqual(len(f) - 42, 300)            # BOOTP min size


class Vlan(unittest.TestCase):
    def test_account_and_guess(self):
        d = {"vlans": {}, "frames": 0}
        arp = b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x22" * 6 + socket.inet_aton("10.20.0.9") + b"\0" * 10
        f = b"\xff" * 6 + b"\x22" * 6 + b"\x08\x06" + arp
        vlan._account(d, 20, f, 0x0806, arp)
        vlan._account(d, 20, f, 0x0806, arp)
        v = d["vlans"][20]
        self.assertEqual((v["frames"], len(v["macs"]), v["kinds"]["ARP"]), (2, 1, 2))
        self.assertEqual(vlan.subnet_guess(v["ips"]), "10.20.0.0/24")
        self.assertIsNone(vlan.subnet_guess({"8.8.8.8"}))

    def test_ifname_limit(self):
        self.assertEqual(vlan.vlan_ifname("eth0", 20), "eth0.20")
        self.assertEqual(vlan.vlan_ifname("enx00e0a1057b9f", 20), "ldv.20")


class Log(unittest.TestCase):
    def test_auto_dedupe_and_reload(self):
        p = os.path.join(tempfile.mkdtemp(), "sub", "ports.csv")
        log = PortLog(p)
        row = {"switch": "sw1", "port": "Gi1/0/1", "vlan": 20}
        self.assertTrue(log.maybe_auto(row))
        self.assertFalse(log.maybe_auto(row))               # same port: no dup
        self.assertTrue(log.append(dict(row, label="Rm 1")))
        self.assertFalse(log.maybe_auto({"switch": None, "port": None}))
        again = PortLog(p)
        self.assertEqual([r["label"] for r in again.rows], ["auto", "Rm 1"])
        self.assertEqual(again.rows[0]["vlan"], "20")


if __name__ == "__main__":
    unittest.main()
