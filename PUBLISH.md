# Publish record -- LAN Devil (CardputerZero App Store)

| Field | Value |
|---|---|
| Package | `landevil` |
| Version | 0.1.0 |
| Architecture | all |
| .deb path | `build/landevil_0.1.0_all.deb` (after `packaging/build_deb.py`) |
| App name (store title) | LAN Devil |
| Summary | Plug into a switch port: see switch, port, VLAN and mgmt IP |
| Categories | System Tools, Security |
| Icon | `packaging/icon.png` (256x256) |
| Screenshots | `store/screenshots/{status,ping,arp,ports}.png` (4 x 320x170) |
| License | MIT |
| Share code | LDVL (must be unique store-wide; change if taken) |
| Permissions | network only |

## TODO before submitting

- [ ] **Maintainer** for the .deb: `--maintainer "Name <email>"`
- [ ] **author.github** and **author.display_name** in `app-builder.json`
- [ ] **source_repo** (recommended): push this folder to a public repo
- [ ] Test on the real device: launch from APPLaunch, LLDP from a real switch, hold-Esc exit
- [ ] Record the short on-device video the first-release review asks for
- [ ] `czdev login` then `czdev publish --deb build/landevil_0.1.0_all.deb`
- [ ] Consider replacing demo screenshots with real captures

## Submission result

_Not submitted yet._
