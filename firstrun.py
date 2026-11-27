"""
firstrun.py -- the one-time welcome pop-up: what this launch can do with
the permissions it got, and an offer to install lldpd.

APPLaunch starts apps as the desktop user. The wrapper re-runs LAN Devil as
root when sudo needs no password (stock images); otherwise it runs
unprivileged and raw LLDP/CDP capture, the DHCP probe and VLAN join are off.
lldpd fills part of that gap: it runs as a system service, so the app can
read its neighbor table without root.

The pop-up is shown once per desktop user; a marker in ~/landevil/ records
that it was seen. `landevil.py --welcome` shows it again.
"""

import os
import subprocess

import portlog

LLDPCLI = ("/usr/sbin/lldpcli", "/usr/sbin/lldpctl", "/usr/bin/lldpcli")


def marker_path():
    return os.path.join(portlog._owner()[0], "landevil", ".welcome-seen")


def seen():
    return os.path.exists(marker_path())


def mark_seen():
    home, uid, gid = portlog._owner()
    folder = os.path.join(home, "landevil")
    path = os.path.join(folder, ".welcome-seen")
    try:
        if not os.path.isdir(folder):
            os.makedirs(folder, exist_ok=True)
            if uid is not None:
                os.chown(folder, uid, gid)
        with open(path, "w") as f:
            f.write("1\n")
        if uid is not None:
            os.chown(path, uid, gid)
    except OSError:
        pass                       # read-only home: the pop-up just shows again


def is_root():
    return os.geteuid() == 0


def lldpd_installed():
    return any(os.path.exists(p) for p in LLDPCLI)


def _sudo_prefix():
    """Command prefix that runs apt as root without asking for a password,
    or None when this launch has no way to do that."""
    if is_root():
        return []
    try:
        if subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5).returncode == 0:
            return ["sudo", "-n"]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def can_install():
    return _sudo_prefix() is not None


def _apt(job, prefix, args):
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", LC_ALL="C")
    p = subprocess.Popen(prefix + ["apt-get", "-y", "-q"] + args, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, env=env)
    out = []
    for line in p.stdout:
        line = line.strip()
        if line:
            out.append(line)
            job.emit(line)
    return p.wait(), out


def install_lldpd(job):
    """Job body: apt-get install lldpd (refreshing the package lists first
    if apt doesn't know the package). Sets job.data['ok']."""
    job.data["ok"] = False
    prefix = _sudo_prefix()
    if prefix is None:
        job.emit("needs root: run  sudo apt install lldpd")
        return
    job.emit("installing lldpd...")
    rc, out = _apt(job, prefix, ["install", "lldpd"])
    if rc != 0 and any("Unable to locate" in l or "has no installation candidate" in l for l in out):
        job.emit("updating package lists...")
        _apt(job, prefix, ["update"])
        rc, out = _apt(job, prefix, ["install", "lldpd"])
    job.data["ok"] = rc == 0 and lldpd_installed()
    if job.data["ok"]:
        job.emit("lldpd installed")
    elif rc == 0:
        job.emit("apt finished but lldpcli is missing")
    else:
        errs = [l for l in out if l.startswith(("E:", "W:"))]
        job.emit((errs[-1] if errs else f"apt-get failed ({rc})")[:120])
