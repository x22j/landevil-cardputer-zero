# LAN Devil -- CardputerZero build

The LAN Devil pocket network-ID tool as a CardputerZero APPLaunch app.
Plug the Cardputer's Ethernet port into a switch port and the home screen
shows link speed, your DHCP lease, and what you're plugged into -- switch
name, port, VLAN, management IP -- from LLDP/CDP. Ping (live latency
graph), ARP sweep (with MAC vendors) and a TCP port grid are one key away.

Lineage: the Pi build (`~/Documents/ld`, Python + lldpd + e-paper) is the
direct ancestor; the LLDP/CDP TLV parsing is ported from the S31 firmware
(`landevil-s31/main/lldp_cdp.c`), extended with mgmt-address and 802.1
port-VLAN TLVs. Here the keyboard and screen are the control plane, so the
BLE / Wi-Fi AP control page isn't needed.

![status](store/screenshots/status.png) ![dhcp](store/screenshots/dhcp.png)
![vlan](store/screenshots/vlan.png) ![log](store/screenshots/log.png)
![ping](store/screenshots/ping.png) ![arp](store/screenshots/arp.png)
![ports](store/screenshots/ports.png)

## Screens

| Tab | What it does |
|---|---|
| **STAT** | Link + speed ladder + duplex, flap counter (kernel `carrier_changes`), IP/GW/DNS. Neighbor card: switch, port, native VLAN, mgmt IP, **PoE** (802.3af/at class + watts, LLDP-MED, CDP), **voice VLAN** (LLDP-MED / CDP), and the switch's own speed/duplex. Alerts on **speed/duplex mismatch**, half duplex, 10M links and recent flaps. |
| **DHCP** | Broadcasts one DHCPDISCOVER (no lease taken) and lists **every** server that offers: offered IP, gateway, DNS, lease, domain, TFTP/boot, relay. Two or more servers -> red **possible rogue** banner. |
| **VLAN** | `S` watches 802.1Q-tagged frames on a trunk (passive): per VLAN frames, hosts, guessed subnet, merged with what the switch advertises (native / voice / named VLANs). `Enter` **joins** the selected (or typed) VLAN: creates `eth0.N`, gets a DHCP lease, and DHCP/Ping/ARP/Port then run on that VLAN (header shows `V30`). `X` leaves (DHCPRELEASE + link removed); exiting the app always cleans up. No default route is added, so Wi-Fi/SSH are unaffected. |
| **PING** | Live RTT bar graph (lost = red X) + recv/loss/avg/min-max tiles. |
| **ARP** | Subnet sweep (capped /24) with MAC vendors. |
| **PORT** | TCP connect grid of 28 common services. |
| **LOG** | Every new switch+port is **auto-logged**; type a note ("Rm 214 jack B") + Enter to add a labelled row. CSV at `~/landevil/ports.csv` (owned by the desktop user even though the app runs under sudo). |

## Neighbor discovery: raw capture *and* lldpd

The store can't assume lldpd is installed, so the app captures LLDP
(EtherType 0x88CC) and CDP (802.3/SNAP) itself on AF_PACKET sockets.
Switches announce every 30-60 s, so on a fresh plug-in you wait up to a
minute (the status card shows a radar + 60 s bar while listening).

If lldpd **is** installed (it is on your unit), the app also polls
`lldpcli -f json show neighbors` every 5 s and shows that neighbor
immediately, tagged `LLDP (lldpd)` / `cached`, until a fresh frame is seen
on the wire. Both coexist fine: packet sockets get their own copy of each
frame.

Raw capture, the DHCP probe, VLAN watch/join and the raw ARP sweep need
root. APPLaunch runs as the desktop user (`jstn` on this unit), so the
launcher wrapper re-execs under passwordless `sudo` when the image allows
it (stock images do). Without it: neighbors come from lldpd, the ARP sweep
uses the kernel ARP table, and DHCP/VLAN say they need root.

## Files

| File | What |
|---|---|
| `landevil.py` | UI: screens, input, rendering (Pillow), `--preview` |
| `netdiag.py` | link/IP/gateway/DNS, LLDP/CDP parser (incl. 802.3 PoE/MAU, LLDP-MED, 802.1 VLAN names) + listener, lldpd reader, ping, ARP sweep, port scan |
| `dhcp.py` | raw-socket DHCP: rogue probe, one-shot lease (DORA), release |
| `vlan.py` | tagged-frame watcher (BPF + PACKET_AUXDATA), VLAN join/leave |
| `portlog.py` | the CSV port log |
| `ui.py` | palette, fonts, drawn icons/widgets |
| `device.py` | framebuffer (finds `fb_st7789v`, never assumes fb0) and raw evdev keyboard -- no python3-evdev needed |
| `assets/logo120.png`, `packaging/icon.png` | tinted from `branding/landevil-logo-concept-edited.jpeg` |
| `packaging/build_deb.py` | builds the `.deb` (uses dpkg-deb if present, otherwise writes it in pure Python) |
| `deploy.sh` | build, scp, `apt install` on the device, restart APPLaunch |
| `app-builder.json` | package + App Store listing metadata |
| `tests/` | parser/DHCP/VLAN/log tests with synthetic frames and lldpd JSON |

## Try it on your Cardputer (no store needed)

```bash
./deploy.sh pi@<cardputer-ip>
```

Or by hand on the device: copy the folder over and run
`sudo python3 landevil.py` (needs `python3-pil python3-numpy fonts-dejavu-core`).

## Develop off-device

```bash
python3 landevil.py --preview /tmp/ld      # renders splash + 4 store screenshots
cd tests && python3 -m unittest test_netdiag test_v02
```

## Package / publish

```bash
python3 packaging/build_deb.py --maintainer "Your Name <you@example.com>"
# -> build/landevil_0.2.0_all.deb   (Architecture: all -- pure Python)
```

Publishing goes through `czdev publish` (CardputerZero AppBuilder) or the
web portal at dev.cardputer.cc. See `PUBLISH.md` for what's still to fill
in. First release of a new app needs a short video of it running on a real
device posted on the publish PR.

## Responsible use

DHCP probe, VLAN join, ARP sweep and port scan send traffic and are
labelled as such on screen. Get an OK before running them on a network you
don't administer. STAT and VLAN watch are passive (VLAN watch puts the port
in promiscuous mode while it runs).
