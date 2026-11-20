#!/bin/sh
# Copy LAN Devil to a CardputerZero over SSH and install it into APPLaunch,
# without going through the store. Usage: ./deploy.sh [user@cardputer-host]
set -eu
HOST=${1:-pi@cardputerzero.local}
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEB=$(python3 "$DIR/packaging/build_deb.py" --maintainer "${LANDEVIL_MAINTAINER:-LAN Devil <dev@landevil.com>}")
scp "$DEB" "$HOST:/tmp/landevil.deb"
# apt resolves the Depends (python3-pil, numpy, fonts) from the device's repos.
ssh -t "$HOST" 'sudo apt-get install -y /tmp/landevil.deb'
echo "Installed. LAN Devil should now be in the launcher."
