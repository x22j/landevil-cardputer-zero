#!/usr/bin/env python3
"""
Build the LAN Devil .deb for CardputerZero's APPLaunch.

Works without dpkg-deb (writes the ar/tar container itself), so it runs
on any machine with Python 3; if dpkg-deb is present it is used instead.
The package is Architecture: all -- it's pure Python.

  python3 packaging/build_deb.py [--maintainer "Name <email>"] [--out build]
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
APP_FILES = ["landevil.py", "netdiag.py", "device.py", "assets/logo120.png"]
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


def control(meta, maintainer, staging):
    size_kb = sum(os.path.getsize(os.path.join(dp, f))
                  for dp, _, fs in os.walk(staging) for f in fs) // 1024 + 1
    return (f"Package: {meta['package_name']}\n"
            f"Version: {meta['version']}\n"
            "Architecture: all\n"
            f"Maintainer: {maintainer}\n"
            f"Installed-Size: {size_kb}\n"
            f"Depends: {DEPENDS}\n"
            "Section: APPLaunch\n"
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
    ap.add_argument("--maintainer", default=os.environ.get("LANDEVIL_MAINTAINER", ""))
    ap.add_argument("--out", default=os.path.join(ROOT, "build"))
    args = ap.parse_args()
    with open(os.path.join(ROOT, "app-builder.json")) as f:
        meta = json.load(f)
    if not args.maintainer:
        ap.error("set --maintainer 'Name <email>' (or LANDEVIL_MAINTAINER); "
                 "the store rejects template/placeholder maintainers")
    os.makedirs(args.out, exist_ok=True)
    deb = os.path.join(args.out, f"{meta['package_name']}_{meta['version']}_all.deb")
    with tempfile.TemporaryDirectory() as staging:
        stage(staging, meta)
        ctrl = control(meta, args.maintainer, staging)
        os.chmod(os.path.join(staging, PREFIX, "bin", meta["bin_name"]), 0o755)
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
