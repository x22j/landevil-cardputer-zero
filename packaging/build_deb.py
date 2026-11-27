#!/usr/bin/env python3
"""
Build the LAN Devil .deb for CardputerZero's APPLaunch, or for the uConsole.

Works without dpkg-deb (writes the ar/tar container itself), so it runs
on any machine with Python 3; if dpkg-deb is present it is used instead.
The package is Architecture: all -- it's pure Python.

  python3 packaging/build_deb.py [--maintainer "Name <email>"] [--out build]   (default: LAN Devil <dev@landevil.com>)
  python3 packaging/build_deb.py --target uconsole      # landevil-uconsole_<ver>_all.deb

The uConsole package is an ordinary desktop app: code in /usr/share/landevil,
`landevil` on PATH, a menu entry and icon. It runs fullscreen (`--window`).
"""

import argparse
import gzip
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PREFIX = "usr/share/APPLaunch"
APP_FILES = ["landevil.py", "netdiag.py", "device.py", "ui.py", "dhcp.py", "vlan.py", "firstrun.py",
             "portlog.py", "assets/logo120.png"]
DEPENDS = "python3 (>= 3.9), python3-pil, python3-numpy, fonts-dejavu-core, iputils-ping, iproute2"

WRAPPER = """#!/bin/sh
# APPLaunch runs Exec without arguments or a shell; this wrapper is the Exec.
# APPLaunch runs as the desktop user, but passive LLDP/CDP capture and the
# raw ARP sweep need CAP_NET_RAW. Use passwordless sudo when the image has
# it (stock images do); otherwise run unprivileged -- the app then falls
# back to lldpd for neighbors and the kernel ARP table for the sweep.
APP=/usr/share/APPLaunch/apps/landevil/landevil.py
if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    exec sudo -n python3 "$APP" "$@"
fi
exec python3 "$APP" "$@"
"""


UCONSOLE_FILES = APP_FILES + ["window.py"]
UCONSOLE_DEPENDS = DEPENDS + ", python3-tk, python3-pil.imagetk"
UCONSOLE_WRAPPER = """#!/bin/sh
# LAN Devil on the uConsole: a fullscreen window on the desktop.
# Passive LLDP/CDP capture, the DHCP probe and the raw ARP sweep need
# CAP_NET_RAW, so re-run as root -- passwordless sudo when the image has it,
# else a pkexec password prompt -- passing the X display through. If neither
# works (or LANDEVIL_NO_ROOT is set) it runs unprivileged and falls back to
# lldpd for neighbors and the kernel ARP table for the sweep.
APP=/usr/share/landevil/landevil.py
if [ "$(id -u)" != 0 ] && [ -z "${LANDEVIL_NO_ROOT:-}" ]; then
    XA=${XAUTHORITY:-$HOME/.Xauthority}
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        exec sudo -n env DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$XA" \\
            LANDEVIL_IFACE="${LANDEVIL_IFACE:-}" python3 "$APP" --window "$@"
    fi
    if command -v pkexec >/dev/null 2>&1; then
        pkexec env DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$XA" \\
            LANDEVIL_IFACE="${LANDEVIL_IFACE:-}" python3 "$APP" --window "$@"
        rc=$?
        # 126/127: prompt dismissed or not authorized -> run without root
        [ "$rc" -ne 126 ] && [ "$rc" -ne 127 ] && exit "$rc"
    fi
fi
exec python3 "$APP" --window "$@"
"""


def stage_uconsole(staging, meta):
    name = meta["bin_name"]
    app_dir = os.path.join(staging, "usr", "share", "landevil")
    for f in UCONSOLE_FILES:
        dst = os.path.join(app_dir, f)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, f), dst)
    bin_dir = os.path.join(staging, "usr", "bin")
    os.makedirs(bin_dir, exist_ok=True)
    with open(os.path.join(bin_dir, name), "w") as f:
        f.write(UCONSOLE_WRAPPER)
    os.chmod(os.path.join(bin_dir, name), 0o755)
    icons = os.path.join(staging, "usr", "share", "icons", "hicolor", "256x256", "apps")
    os.makedirs(icons, exist_ok=True)
    shutil.copy2(os.path.join(ROOT, meta["store"]["icon"]), os.path.join(icons, f"{name}.png"))
    apps = os.path.join(staging, "usr", "share", "applications")
    os.makedirs(apps, exist_ok=True)
    with open(os.path.join(apps, f"{name}.desktop"), "w") as f:
        f.write("[Desktop Entry]\n"
                "Type=Application\n"
                f"Name={meta['app_name']}\n"
                f"Comment={meta['store']['summary']}\n"
                f"Exec={name}\n"
                f"Icon={name}\n"
                "Terminal=false\n"
                "Categories=Network;System;\n"
                "Keywords=LLDP;CDP;VLAN;DHCP;switch;ethernet;\n")


def stage(staging, meta):
    pkg = meta["package_name"]
    app_dir = os.path.join(staging, PREFIX, "apps", pkg)
    for f in APP_FILES:
        dst = os.path.join(app_dir, f)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, f), dst)
    bin_dir = os.path.join(staging, PREFIX, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    with open(os.path.join(bin_dir, meta["bin_name"]), "w") as f:
        f.write(WRAPPER)
    img_dir = os.path.join(staging, PREFIX, "share", "images")
    os.makedirs(img_dir, exist_ok=True)
    shutil.copy2(os.path.join(ROOT, meta["store"]["icon"]), os.path.join(img_dir, f"{pkg}.png"))
    apps = os.path.join(staging, PREFIX, "applications")
    os.makedirs(apps, exist_ok=True)
    with open(os.path.join(apps, f"{pkg}.desktop"), "w") as f:
        f.write("[Desktop Entry]\n"
                f"Name={meta['app_name']}\n"
                f"Exec=bin/{meta['bin_name']}\n"
                "Terminal=false\n"
                f"Icon=share/images/{pkg}.png\n"
                "Type=Application\n")


def control(meta, maintainer, staging, target="cardputer"):
    size_kb = sum(os.path.getsize(os.path.join(dp, f))
                  for dp, _, fs in os.walk(staging) for f in fs) // 1024 + 1
    uc = target == "uconsole"
    return (f"Package: {meta['package_name']}{'-uconsole' if uc else ''}\n"
            f"Version: {meta['version']}\n"
            "Architecture: all\n"
            f"Maintainer: {maintainer}\n"
            f"Installed-Size: {size_kb}\n"
            f"Depends: {UCONSOLE_DEPENDS if uc else DEPENDS}\n"
            f"Section: {'net' if uc else 'APPLaunch'}\n"
            "Priority: optional\n"
            f"Homepage: {meta['store'].get('source_repo') or 'https://landevil.com'}\n"
            f"Description: {meta['description']}\n"
            " Plug into a switch port and see the switch name, port, VLAN and\n"
            " management IP from LLDP/CDP, plus ping, ARP sweep and port scan.\n")


def _tar(add):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
            add(tf)
    return buf.getvalue()


def _clean(ti):
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    ti.mtime = int(time.time())
    if ti.isdir() or ti.name.endswith(("/bin/landevil",)) or ti.name.startswith("./postinst"):
        ti.mode = 0o755
    elif ti.isfile():
        ti.mode = 0o644
    return ti


def write_deb(staging, ctrl, out):
    def data(tf):
        for dp, dns, fs in os.walk(staging):
            dns.sort()
            rel = os.path.relpath(dp, staging)
            if rel.startswith("DEBIAN"):
                continue
            arc = "./" if rel == "." else f"./{rel}/"
            tf.add(dp, arcname=arc, recursive=False, filter=_clean)
            for f in sorted(fs):
                tf.add(os.path.join(dp, f), arcname=arc + f, filter=_clean)

    def ctl(tf):
        b = ctrl.encode()
        ti = tarfile.TarInfo("./control")
        ti.size, ti.mode, ti.mtime = len(b), 0o644, int(time.time())
        tf.addfile(ti, io.BytesIO(b))

    members = [("debian-binary", b"2.0\n"), ("control.tar.gz", _tar(ctl)),
               ("data.tar.gz", _tar(data))]
    with open(out, "wb") as f:
        f.write(b"!<arch>\n")
        for name, body in members:
            hdr = f"{name:<16}{int(time.time()):<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n"
            f.write(hdr.encode())
            f.write(body)
            if len(body) % 2:
                f.write(b"\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--maintainer", default=os.environ.get("LANDEVIL_MAINTAINER", "LAN Devil <dev@landevil.com>"))
    ap.add_argument("--out", default=os.path.join(ROOT, "build"))
    ap.add_argument("--target", choices=["cardputer", "uconsole"], default="cardputer",
                    help="cardputer: APPLaunch app (default); uconsole: desktop app")
    args = ap.parse_args()
    with open(os.path.join(ROOT, "app-builder.json")) as f:
        meta = json.load(f)
    if not args.maintainer:
        ap.error("set --maintainer 'Name <email>' (or LANDEVIL_MAINTAINER); "
                 "the store rejects template/placeholder maintainers")
    os.makedirs(args.out, exist_ok=True)
    uc = args.target == "uconsole"
    pkg = meta["package_name"] + ("-uconsole" if uc else "")
    deb = os.path.join(args.out, f"{pkg}_{meta['version']}_all.deb")
    with tempfile.TemporaryDirectory() as staging:
        os.chmod(staging, 0o755)              # becomes ./ in the package
        if uc:
            stage_uconsole(staging, meta)
        else:
            stage(staging, meta)
            os.chmod(os.path.join(staging, PREFIX, "bin", meta["bin_name"]), 0o755)
        ctrl = control(meta, args.maintainer, staging, args.target)
        if shutil.which("dpkg-deb"):
            os.makedirs(os.path.join(staging, "DEBIAN"))
            with open(os.path.join(staging, "DEBIAN", "control"), "w") as f:
                f.write(ctrl)
            subprocess.run(["dpkg-deb", "--root-owner-group", "-b", staging, deb], check=True)
        else:
            write_deb(staging, ctrl, deb)
    print(deb)


if __name__ == "__main__":
    main()
