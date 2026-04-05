![Architecture](https://img.shields.io/badge/Architecture-Linux-darkgreen)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)
![License](https://img.shields.io/badge/License-TBD-lightgrey)
![Sponsored](https://img.shields.io/badge/Sponsored-STN_Labz-blue)

# sentinel-daemon
The Sentinel Daemon for Ground, Space and Interstellar Security

**Version**: 0.5.7

This project is intended for real-world stress conditions, including Low Earth Orbit (LEO) environments, high-latency satellite links (Starlink/StarShield), and terrestrial adversarial scenarios.

Its sole purpose is **Host Security**.

> *State is disposable. Enforcement is not.*

---

## Sentinel Guarantees
- Operates under corrupted state
- Rebuilds state automatically
- Atomic filesystem operations (no partial writes)
- Service-safe execution (systemd hardened)
- Minimal footprint, no external dependencies

---

## Build
 - `cd sentinel-daemon`
 - `gcc -Wall -Wextra -O2 -o sentinel sentinel.c`
 
## Install
 - `sudo mv sentinel /usr/local/bin/sentinel`
 - Copy `etc/sentinel.conf` to `/etc/`
 - Copy `/etc/systemd/system/sentinel.service` to `/etc/systemd/system/`
 - Setup `/var/lib/sentinel`
 - Setup `var/log/sentinel/` + `/var/log/sentinel/quarantine`

*Directories are intentionally not auto-created. Explicit control is required.*
 
## Update
Please see the [Changelog](/changelog.md)
