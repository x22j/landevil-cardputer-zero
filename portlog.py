"""
portlog.py -- a CSV of every switch port LAN Devil has been plugged into.

Walk a floor, plug into each jack, and the log fills itself: one row per
new switch+port seen (auto), plus labelled rows you add by typing a note
on the LOG screen ("Rm 214 jack B"). The file opens in any spreadsheet.

Location: ~/landevil/ports.csv of the *desktop* user. The app may run
under sudo, so SUDO_USER's home is used and the file is chowned back,
keeping it easy to scp off as that user.
"""

import csv
import os
import pwd
import time

FIELDS = ["time", "label", "switch", "port", "port_descr", "vlan", "voice_vlan",
          "mgmt_ip", "proto", "link", "switch_link", "poe", "ip", "gateway",
          "dhcp_server", "flaps", "platform"]


def _owner():
    if os.geteuid() == 0:
        try:
            if os.environ.get("SUDO_USER"):
                pw = pwd.getpwnam(os.environ["SUDO_USER"])
            elif os.environ.get("PKEXEC_UID"):          # launched via pkexec
                pw = pwd.getpwuid(int(os.environ["PKEXEC_UID"]))
            else:
                pw = None
            if pw:
                return pw.pw_dir, pw.pw_uid, pw.pw_gid
        except (KeyError, ValueError):
            pass
    return os.path.expanduser("~"), None, None


class PortLog:
    def __init__(self, path=None):
        home, self.uid, self.gid = _owner()
        self.path = path or os.environ.get("LANDEVIL_LOG") or os.path.join(home, "landevil", "ports.csv")
        self.rows = []
        self.error = None
        self._last_auto = None
        self._load()

    def display_path(self):
        home = _owner()[0]
        return "~" + self.path[len(home):] if self.path.startswith(home) else self.path

    def _load(self):
        try:
            with open(self.path, newline="") as f:
                self.rows = list(csv.DictReader(f))
        except OSError:
            self.rows = []
        except csv.Error as e:
            self.error = f"unreadable log: {e}"

    def _chown(self, p):
        if self.uid is not None:
            try:
                os.chown(p, self.uid, self.gid)
            except OSError:
                pass

    def append(self, row):
        row = {k: ("" if row.get(k) is None else row.get(k)) for k in FIELDS}
        row["time"] = row["time"] or time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            d = os.path.dirname(self.path)
            if not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
                self._chown(d)
            new = not os.path.exists(self.path) or os.path.getsize(self.path) == 0
            with open(self.path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=FIELDS)
                if new:
                    w.writeheader()
                w.writerow(row)
            if new:
                self._chown(self.path)
            self.rows.append(row)
            self.error = None
            return True
        except OSError as e:
            self.error = f"can't write {self.display_path()}: {e.strerror}"
            return False

    def maybe_auto(self, row):
        """Append an 'auto' row the first time this switch+port is seen in
        a session (and not if it's identical to the last row on file)."""
        key = (row.get("switch"), row.get("port"))
        if not all(key) or key == self._last_auto:
            return False
        self._last_auto = key
        if self.rows:
            last = self.rows[-1]
            if (last.get("switch"), last.get("port")) == key and last.get("label") == "auto":
                return False
        row = dict(row, label="auto")
        return self.append(row)
