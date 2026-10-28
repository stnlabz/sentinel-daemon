![Architecture](https://img.shields.io/badge/Architecture-Linux-darkgreen)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)
![License](https://img.shields.io/badge/License-TBD-lightgrey)
![Sponsored](https://img.shields.io/badge/Sponsored-STN_Labz-blue)

# Sentinel Daemon
The Sentinel Daemon for Ground, Space and Interstellar Security

**Version**: 0.6.0

This project is intended for real-world stress conditions, including Low Earth Orbit (LEO) environments, high-latency satellite links (Starlink/StarShield), and terrestrial adversarial scenarios.

Its sole purpose is **Host Security**.

> *State is disposable. Enforcement is not.*

---

## Runtime behavior

- Host-wide observation is enabled by default.
- Each restart rebuilds the in-memory host baseline.
- The heartbeat is replaced atomically after each completed scan.
- The systemd service starts at boot and restarts on failure.
- The runtime uses libc and Linux interfaces without third-party libraries.

---

## Build
 - `cd sentinel-daemon`
 - `make`
 
## Install or update

Build and install from the repository root on Linux:

    make
    sudo make install
    sudo make install-config
    sudo make install-service
    sudo systemctl daemon-reload
    sudo systemctl enable --now sentinel
    sudo systemctl restart sentinel

For an existing installation, preserve a copy of the current binary,
/etc/sentinel.conf and /etc/systemd/system/sentinel.service before replacing them.
The install-config target replaces the installed configuration with the repository
host-mode defaults. Carry forward any custom runtime paths or scan interval.

Systemd creates /var/log/sentinel and /var/lib/sentinel. Sentinel creates its
quarantine directory and validates the runtime directories at startup. Custom
runtime paths must also be permitted by the service's ReadWritePaths setting.

Check operation with:

    systemctl status sentinel --no-pager
    tail -n 20 /var/log/sentinel/sentinel.log

Look for MONITOR_MODE HOST, HOST_BASELINE_COMPLETE and HOST_SCAN_COMPLETE.
A nonzero coverage_errors value identifies an incomplete scan; the preceding
HOST_COVERAGE_ERROR records show up to ten affected paths per scan. The heartbeat
is /var/lib/sentinel/heartbeat and contains the last completed heartbeat's Unix time.

See [Changelog](changelog.md) for release history.

## STN-Labz
STN-Labz is founded and operated by a 🏳️‍⚧️ transgender woman, retired soldier, space enthusiast, and developer.

It operates at the intersection of cybersecurity and space development—focused on building resilient systems for environments where failure is not an option.

## Host-wide observation (default)

monitor_mode=host recursively snapshots filesystem metadata starting at /,
including nested and hidden paths and mounted filesystems visible to the service.
It also snapshots all visible processes through /proc, using PID, process start
time and executable path to detect starts, exits, PID reuse and exec replacement.
No watch_dir allowlist applies in host mode. Host mode always observes; it never
quarantines files or terminates processes.

The first scan establishes an in-memory baseline; later scans log creates,
metadata changes, removals and process changes. Restarting creates a fresh baseline.
Tracking uses full paths and a dynamically allocated hash table rather than the
legacy 2,048-file limit. Memory scales with the number of entries. File contents,
command-line arguments and network traffic are not inspected.

This is polling, not a kernel audit stream: short-lived processes and changes
between scans can be missed. loop_interval is the delay after each complete
scan, so actual detection latency also includes scan time. Summary records report
entry count, process count, duration and coverage errors. Incomplete scans suppress
removal reports to avoid interpreting inaccessible paths as deletions.

The /proc and /sys trees are not recursively walked. Processes are handled separately.
Device trees are skipped except /dev/shm; symlinks are recorded but not followed.
Sentinel's log, state, heartbeat parent directories and quarantine are excluded to
avoid monitoring its own writes. Inaccessible paths, excessive depth, allocation
failures and oversized paths produce coverage errors rather than silent success.
Mount namespaces not visible to the service are outside its coverage.

The service uses the real /tmp, read-only home access, and only
CAP_DAC_READ_SEARCH / CAP_SYS_PTRACE to inspect protected host metadata.
Filesystem writes remain confined to Sentinel's log and state directories.
Logs rotate at log_max_size to one .1 backup (default 5 MiB each).

monitor_mode=directories retains the previous directory-rule behavior.
An explicit configuration may be selected with sentinel --config PATH.

## Validation

Run on Linux with privileges to inspect all processes:

    gcc -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -o test-host-monitor test_host_monitor.c
    sudo ./test-host-monitor
    make CFLAGS='-Wall -Wextra -Werror -O2'

The test covers more than 2,048 paths, duplicate basenames, nested/hidden files,
symlink cycles, metadata changes, removal handling, incomplete coverage, PID reuse,
live process creation/exit and log escaping. Test fixtures remain in a uniquely
named .host-test-* directory for inspection.
