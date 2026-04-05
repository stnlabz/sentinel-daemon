# Changelog

**Date/Time**: 2026-04-05T2052Z

**Version**: 0.5.6

**Core Fixes**
 - Fixed systemd service startup failure (`status=226/NAMESPACE`)
 - Corrected service containment issues while preserving required runtime access
 - Ensured proper execution under root context for enforcement operations
 - Restored full functionality when running as a service vs manual execution

**Filesystem & Runtime Stability**
 - Enforced creation of required runtime paths:
   - `/var/log/sentinel`
   - `/var/log/sentinel/quarantine`
   - `/var/lib/sentinel`
 - Fixed issue where log and quarantine directories were not created automatically
 - Resolved quarantine failures due to insufficient permissions

**State Engine Hardening**
 - Implemented strict state validation
   - Invalid or malformed DB now triggers automatic rebuild
   - Replaced delete/recreate logic with atomic state rebuild
   - Uses `.tmp` file + `rename()` swap
 - Eliminates partial writes and race conditions
 - Ensured deterministic recovery from corruption
 
**Bit-Flip & Corruption Resilience**
 - **Tested direct corruption via**:
   - Partial overwrite (`dd`)
   - Single-byte flip
   - Multi-byte injection
 - **Confirmed**:
   - Sentinel continues operating under corrupted state
   - Detection loop remains functional
   - State is treated as non-authoritative
 - **Added logic**:
   - Rebuild state when invalid
   - Maintain enforcement continuity post-corruption

**Execution & Enforcement**
 - **Verified real-time detection**:
   - `RULE_VIOLATION`
   - `THREAT_DETECTED`
 - **Confirmed consistent**:
   - `QUARANTINE_SUCCESS`
 - Recovery after failure scenarios
 - Execution monitoring remains stable under repeated events

**Heartbeat & Runtime Awareness**
 - Implemented atomic heartbeat writes
   - Prevents partial or stale heartbeat data
 - Ensures reliable daemon activity tracking
 
**Service Reliability**
 - **Fixed mismatch between**:
   - manual execution ✔
   - `systemd` execution ❌ → ✔
 - **Ensured consistent behavior across**:
   - reboot cycles
   - service restarts
 - Confirmed **persistent operation after reboot**
 
**Validation Summary**
 - ✔ Service starts cleanly under systemd
 - ✔ Logs write consistently
 - ✔ Quarantine operates correctly
 - ✔ Survives DB corruption
 - ✔ Recovers state automatically
 - ✔ Maintains enforcement loop integrity
 - ✔ Stable across reboot
 
***Notes***
 - State database is now **disposable by design**
 - Sentinel operates on **live observation, not historical dependency**
 - System remains **minimal, deterministic, and low-overhead**
