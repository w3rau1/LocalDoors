# LocalDoors

A Linux vulnerability scanner with an optional local-LLM explanation layer. Single Python file, standard library only, designed to run on weak or fully offline machines (including bare VMs with no GPU and no internet).

## Design principles

- **Facts and severity are decided by plain code, not by AI.** The optional local model (via llama.cpp, planned) can only rephrase and prioritize findings the checks already produced - it cannot invent or hide anything.
- **The HTML report is always generated**, with or without the AI layer, using fixed human-readable templates per finding.
- **No heavy dependencies.** Only the Python standard library and common Linux CLI tools (`find`, `ss`/`netstat`, `apt`, `ufw`/`iptables`, `getent`) that ship on virtually any Debian/Ubuntu system.

## Checks

1. Open ports and listening services
2. SSH hardening (`PermitRootLogin`, `PasswordAuthentication`, including `Include`-resolved configs)
3. Pending security updates (`apt`)
4. Firewall status and rules (`ufw` / `iptables`)
5. Users with root/sudo access (stray UID 0 accounts, sudo/wheel membership)
6. Empty passwords in `/etc/shadow`
7. Suspicious SUID files (allowlist-based)
8. World-writable files in system directories (excluding sticky-bit dirs and symlinks)
9. `/etc/shadow` permissions and ownership
10. Brute-force attempts in `/var/log/auth.log`

## Usage

```bash
python3 LocalDoors.py -o report.html
```

Each check runs independently and can never crash the whole scan - if a check can't run (missing permissions, missing tool, unsupported distro), it reports `failed-to-run` instead of a false result.

## Status

Core checks implemented and tested on Ubuntu (WSL2). Local LLM explanation layer is planned but not yet implemented - the deterministic, no-AI report generation is the required baseline and already works standalone.
