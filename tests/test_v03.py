"""Off-device tests for the v0.3 features: 802.1X, DNS, traceroute parsing."""
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netdiag  # noqa: E402

SWITCH = bytes.fromhex("0025 84aa 103f".replace(" ", ""))
US = bytes.fromhex("88a29e761853")


def eapol(code, eap_type=None, data=b"", src=SWITCH, ptype=0):
    eap = bytes([code, 7])
    body = (bytes([eap_type]) + data) if eap_type is not None else b""
    eap += struct.pack(">H", 4 + len(body)) + body
    return (netdiag.PAE_MCAST + src + b"\x88\x8e" + bytes([2, ptype])
            + struct.pack(">H", len(eap)) + eap)


class Eapol(unittest.TestCase):
    def test_request_identity_with_prompt(self):
        e = netdiag.parse_eapol(eapol(1, 1, b"Hello, who are you?"))
        self.assertEqual((e["code"], e["method"], e["prompt"]), ("Request", "Identity", "Hello, who are you?"))
        self.assertEqual(e["src"], "00:25:84:aa:10:3f")

    def test_success_failure_and_method(self):
        self.assertEqual(netdiag.parse_eapol(eapol(4))["code"], "Failure")
        self.assertEqual(netdiag.parse_eapol(eapol(1, 25))["method"], "PEAP")

    def test_not_eapol(self):
        self.assertIsNone(netdiag.parse_eapol(b"\x00" * 12 + b"\x88\xcc" + b"\x00" * 10))

    def test_listener_tracks_authenticator_only(self):
        lst = netdiag.NeighborListener("eth0")
        lst._mac = "88:a2:9e:76:18:53"
        lst._on_eapol(eapol(2, 1, b"user", src=US))          # our own response: ignored
        self.assertIsNone(lst.auth_state())
        lst._on_eapol(eapol(1, 1))
        lst._on_eapol(eapol(1, 13))
        a = lst.auth_state()
        self.assertEqual((a["count"], a["method"], a["result"]), (2, "TLS", None))
        lst._on_eapol(eapol(3))
        self.assertEqual(lst.auth_state()["result"], "Success")
        lst.reset()
        self.assertIsNone(lst.auth_state())


def dns_reply(qid, name, ips, rcode=0, cname=None):
    q = netdiag._dns_name(name) + struct.pack(">HH", 1, 1)
    answers, n = b"", 0
    if cname:
        target = netdiag._dns_name(cname)
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(target)) + target
        n += 1
    for ip in ips:
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        n += 1
    return struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, n, 0, 0) + q + answers


class Dns(unittest.TestCase):
    def test_query_layout(self):
        q = netdiag.dns_build_query(0x1234, "example.com")
        self.assertEqual(q[:4], b"\x12\x34\x01\x00")
        self.assertIn(b"\x07example\x03com\x00\x00\x01\x00\x01", q)

    def test_parse_a_records_after_cname(self):
        msg = dns_reply(9, "www.example.com", ["93.184.215.14", "93.184.215.15"], cname="example.com")
        self.assertEqual(netdiag.dns_parse_reply(msg, 9), (["93.184.215.14", "93.184.215.15"], None))

    def test_nxdomain_and_wrong_id(self):
        self.assertEqual(netdiag.dns_parse_reply(dns_reply(5, "nope.invalid", [], rcode=3), 5),
                         ([], "NXDOMAIN"))
        with self.assertRaises(ValueError):
            netdiag.dns_parse_reply(dns_reply(5, "a.b", ["1.2.3.4"]), 6)

    def test_bad_names(self):
        with self.assertRaises(ValueError):
            netdiag.dns_build_query(1, "a" * 64 + ".com")

    def test_ipv4s_filter(self):
        self.assertEqual(netdiag._ipv4s(["10.0.1.1", "fd7a::53", "127.0.0.53", "10.0.1.1", "x"]),
                         ["10.0.1.1"])


class Trace(unittest.TestCase):
    def recverr(self, origin, etype, code, ip):
        return (struct.pack("=IBBBBII", 113, origin, etype, code, 0, 0, 0)
                + struct.pack("=HH", socket.AF_INET, 0) + socket.inet_aton(ip) + b"\0" * 8)

    def test_time_exceeded_and_port_unreachable(self):
        self.assertEqual(netdiag.parse_recverr(self.recverr(2, 11, 0, "10.0.0.1")), (11, 0, "10.0.0.1"))
        self.assertEqual(netdiag.parse_recverr(self.recverr(2, 3, 3, "1.1.1.1")), (3, 3, "1.1.1.1"))

    def test_local_errors_ignored(self):
        self.assertIsNone(netdiag.parse_recverr(self.recverr(1, 0, 0, "0.0.0.0")))
        self.assertIsNone(netdiag.parse_recverr(b"\0" * 10))


if __name__ == "__main__":
    unittest.main()
