"""Off-device tests for the first-launch permissions pop-up."""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import firstrun  # noqa: E402
import landevil  # noqa: E402
from device import KEY  # noqa: E402


def app(perms):
    tmp = tempfile.mkdtemp()
    a = landevil.App(demo=dict(landevil.demo_data(os.path.join(tmp, "p.csv")), perms=perms),
                     welcome=True)
    a.refresh()
    return a


def press(a, code):
    a.on_key(code, 1)
    a.on_key(code, 0)


class Welcome(unittest.TestCase):
    def test_esc_closes_and_blocks_other_keys(self):
        a = app((False, False, False))
        press(a, KEY["RIGHT"])
        self.assertEqual(a.screen, 0)          # tabs don't move under the pop-up
        a.render()
        press(a, KEY["ESC"])
        self.assertFalse(a.welcome)
        self.assertIsNone(a.install)

    def test_enter_installs_when_possible(self):
        a = app((False, False, True))
        with mock.patch.object(firstrun, "install_lldpd", lambda job: job.data.update(ok=True)):
            press(a, KEY["ENTER"])
            self.assertIsNotNone(a.install)
            for _ in range(50):
                if not a.install.running:
                    break
                time.sleep(0.01)
        self.assertTrue(a.welcome)             # stays up to show the result
        a.render()
        press(a, KEY["ENTER"])
        self.assertFalse(a.welcome)

    def test_enter_without_sudo_just_closes(self):
        a = app((False, False, False))
        press(a, KEY["ENTER"])
        self.assertIsNone(a.install)
        self.assertFalse(a.welcome)

    def test_hidden_install_announces_result(self):
        a = app((False, False, True))
        a.install = landevil._Done({"ok": False}, ["E: Could not get lock"])
        press(a, KEY["ESC"])
        a.tick()
        self.assertIn("failed", a.flash[0])


class Hint(unittest.TestCase):
    def stat(self, perms, waited, neighbor=False):
        a = app(perms)
        a.welcome = a.welcome_first = False
        if not neighbor:
            a.demo["neighbor"] = None
        a.demo["listen_since"] = time.monotonic() - waited
        return a

    def test_hint_after_silence_opens_popup(self):
        a = self.stat((True, False, True), 45)
        self.assertTrue(a.lldpd_hint())
        a.render()
        press(a, landevil.KEY_I)
        self.assertTrue(a.welcome)
        self.assertFalse(a.welcome_first)

    def test_no_hint_too_early_or_with_neighbor_or_lldpd(self):
        self.assertFalse(self.stat((True, False, True), 5).lldpd_hint())
        self.assertFalse(self.stat((True, False, True), 45, neighbor=True).lldpd_hint())
        self.assertFalse(self.stat((True, True, True), 45).lldpd_hint())
        a = self.stat((True, False, True), 5)
        press(a, landevil.KEY_I)
        self.assertFalse(a.welcome)


class Marker(unittest.TestCase):
    def test_seen_round_trip(self):
        with tempfile.TemporaryDirectory() as home, \
                mock.patch.object(firstrun.portlog, "_owner", lambda: (home, None, None)):
            self.assertFalse(firstrun.seen())
            firstrun.mark_seen()
            self.assertTrue(firstrun.seen())


if __name__ == "__main__":
    unittest.main()
