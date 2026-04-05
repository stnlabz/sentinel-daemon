![Architecture](https://img.shields.io/badge/Architecture-Linux-darkgreen)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)
![License](https://img.shields.io/badge/License-TBD-lightgrey)
![Sponsored](https://img.shields.io/badge/Sponsored-STN_Labz-blue)
# sentinel-daemon
The Sentinel Daemon for Ground, Space and Inter Terrestrial Security

## About
This project is bound for Space, literally up to Low Earth Orbit (LEO) in order to test in 0g, -1c @ 17,000 MPH while hooked to StarLink and stress tested from the Home office.
I built this with Starlink, StarShield, the ISS, Lunar Artemis and beyond in mind. Its sole purpose is Host Security.

*State is disposable. Enforcement is not.*

## Sentinel Guarantees
 - Operates under corrupted state
 - Rebuilds state automatically
 - Atomic filesystem operations (no partial writes)
 - Service-safe execution (systemd hardened)
 - Minimal footprint, no external dependencies

## Get Source
 - `git clone https://github.com/stnlabz/sentinel-daemon.git`

## Build
 - `cd sentinel-daemon`
 - `gcc -Wall -Wextra -O2 -o sentinel sentinel.c`
 
## Install
 - `sudo mv sentinel /usr/local/bin/sentinel`
 - Copy `sentinel.conf` to `/etc`
 - Setup '/var/lib/sentinel`
 - Setup 'var/log/sentinel` + `/var/log/sentinel/quarantine`

*No I did not set this application up to auto-create these files or directories, quit being so lazy!*
 
## Update
Please see the [Changelog](/changelog.md)
