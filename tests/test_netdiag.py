"""Off-device tests: LLDP/CDP frame parsing and lldpd JSON normalizing."""
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netdiag  # noqa: E402

SRC = bytes.fromhex("00258 4aa103f".replace(" ", ""))


def lldp_tlv(t, v):
    return struct.pack(">H", (t << 9) | len(v)) + v


def lldp_frame():
    body = (lldp_tlv(1, b"\x04" + SRC) +
            lldp_tlv(2, b"\x05Gi1/0/24") +
            lldp_tlv(3, b"\x00\x78") +
            lldp_tlv(4, b"uplink to desk 12") +
            lldp_tlv(5, b"sw-closet-3") +
            lldp_tlv(6, b"Cisco IOS Software, C2960X\nTechnical Support: ...") +
            lldp_tlv(8, b"\x05\x01" + socket.inet_aton("10.20.0.2") + b"\x02\x00\x00\x00\x01\x00") +
            lldp_tlv(127, b"\x00\x80\xc2\x01\x00\x14") +
            lldp_tlv(0, b""))
    return netdiag.LLDP_MCAST + SRC + b"\x88\xcc" + body


def cdp_tlv(t, v):
    return struct.pack(">HH", t, len(v) + 4) + v


def cdp_frame():
    addr = struct.pack(">I", 1) + b"\x01\x01\xcc" + struct.pack(">H", 4) + socket.inet_aton("10.20.0.2")
    payload = (b"\x02\xb4\x00\x00" +
               cdp_tlv(1, b"sw-closet-3") + cdp_tlv(2, addr) + cdp_tlv(3, b"GigabitEthernet1/0/24") +
               cdp_tlv(5, b"Cisco IOS Software, Version 15.2(7)E8\nCopyright") +
               cdp_tlv(6, b"cisco WS-C2960X-48FPD-L") + cdp_tlv(0x0A, b"\x00\x14"))
    llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + payload
    frame = netdiag.CDP_MCAST + SRC + struct.pack(">H", len(llc)) + llc
    return frame + b"\x00" * 8          # Ethernet padding must be ignored


class Parse(unittest.TestCase):
    def test_lldp(self):
        r = netdiag.parse_lldp(lldp_frame())
        self.assertEqual(r["name"], "sw-closet-3")
        self.assertEqual(r["port"], "Gi1/0/24")
        self.assertEqual(r["port_descr"], "uplink to desk 12")
        self.assertEqual(r["vlan"], 20)
        self.assertEqual(r["mgmt_ip"], "10.20.0.2")
        self.assertEqual(r["platform"], "Cisco IOS Software, C2960X")

    def test_lldp_truncated_is_rejected(self):
        self.assertIsNone(netdiag.parse_lldp(lldp_frame()[:40]))

    def test_cdp(self):
        f = cdp_frame()
        self.assertTrue(netdiag.is_cdp(f))
        r = netdiag.parse_cdp(f)
        self.assertEqual(r["name"], "sw-closet-3")
        self.assertEqual(r["port"], "GigabitEthernet1/0/24")
        self.assertEqual(r["vlan"], 20)
        self.assertEqual(r["mgmt_ip"], "10.20.0.2")
        self.assertIn("WS-C2960X", r["platform"])

    def test_lldpd_json(self):
        data = {"lldp": {"interface": {"eth0": {
            "via": "LLDP", "rid": "1", "age": "0 day, 00:01:12",
            "chassis": {"sw-closet-3": {"id": {"type": "mac", "value": "00:25:84:aa:10:3f"},
                                        "descr": "Cisco IOS Software\nmore",
                                        "mgmt-ip": ["10.20.0.2", "fe80::1"]}},
            "port": {"id": {"type": "ifname", "value": "Gi1/0/24"}, "descr": "desk 12"},
            "vlan": {"vlan-id": "20", "pvid": True}}}}}
        r = netdiag._normalize_lldpd(data, "eth0")
        self.assertEqual((r["name"], r["port"], r["vlan"], r["mgmt_ip"]),
                         ("sw-closet-3", "Gi1/0/24", 20, "10.20.0.2"))
        self.assertEqual(r["proto"], "LLDP (lldpd)")

    def test_lldpd_list_form(self):
        data = {"lldp": [{"interface": [{"eth0": {"via": "CDPv2",
            "chassis": [{"name": [{"value": "core-sw"}], "mgmt-ip": [{"value": "10.0.0.1"}]}],
            "port": [{"id": [{"value": "Te1/1"}]}]}}]}]}
        r = netdiag._normalize_lldpd(data, "eth0")
        self.assertEqual((r["name"], r["port"], r["mgmt_ip"]), ("core-sw", "Te1/1", "10.0.0.1"))

    def test_lldpd_empty(self):
        self.assertIsNone(netdiag._normalize_lldpd({"lldp": {}}, "eth0"))


if __name__ == "__main__":
    unittest.main()
