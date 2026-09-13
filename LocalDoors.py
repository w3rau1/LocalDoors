#!/usr/bin/env python3
"""
Linux vulnerability scanner with an optional local-LLM explanation layer.

Design rules (why the file is built this way):
- Only the plain Python checks below decide FACTS and SEVERITY. The LLM (if enabled)
  is only allowed to rephrase/prioritize what the checks already found. This keeps
  the tool trustworthy even if the model hallucinates - worst case it explains badly,
  it can never invent or hide a finding.
- The HTML report must always be produced, with or without AI, using fixed
  human-readable templates per finding. AI is a nice-to-have layer on top.
- Pure standard library, single file, so it can be copied onto a target machine
  (including an offline VM) with nothing to install.
"""

import argparse
import datetime
import glob
import html
import os
import platform
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """IntEnum so findings sort by severity for free (higher number = worse)."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    check_id: str          # short machine id, e.g. "open-ports"
    title: str             # human title, e.g. "Открытые порты и сервисы"
    severity: Severity
    description: str       # deterministic, plain-language fact - always present
    evidence: str = ""      # raw data backing the claim (command output, file line, ...)
    recommendation: str = ""


@dataclass
class CheckResult:
    check_id: str
    title: str
    ok: bool                # False if the check itself could not run (e.g. no permission)
    findings: list = field(default_factory=list)
    error: str = ""


# Each check is a plain function: () -> CheckResult.
# Wrapping every check in run_check() means one crashing check (missing binary,
# permission denied, weird system) never takes down the whole scan.
def run_check(check_id, title, func):
    try:
        findings = func()
        return CheckResult(check_id=check_id, title=title, ok=True, findings=findings)
    except Exception as exc:  # noqa: BLE001 - a scanner must never crash on one bad host
        return CheckResult(check_id=check_id, title=title, ok=False, error=str(exc))


def _run(cmd):
    """Run a shell command, return its stdout, or None if it could not be run
    (missing binary, no permission, timed out). Callers must NOT treat None the
    same as "" - "" means the command ran fine and simply printed nothing, which
    for checks like world-writable or pending-updates is itself a valid, common
    passing result and must not be confused with a failed/timed-out scan."""
    try:
        result = subprocess.run(
            cmd, shell=False, capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception:
        return None


def _run_first(*cmds):
    """Try each command in turn, return the stdout of the first one that actually
    ran (even if empty) - None only if every command failed or is missing."""
    for cmd in cmds:
        output = _run(cmd)
        if output is not None:
            return output
    return None


# --- Check 1: open ports and listening services -----------------------------
# Risky = plaintext / historically exploited protocols on well-known ports.
# This list is intentionally small and explicit: the scanner should only flag
# what it can justify in one sentence, not guess.
RISKY_PORTS = {
    21: ("FTP", "передаёт логин/пароль в открытом виде"),
    23: ("Telnet", "передаёт всё, включая пароли, в открытом виде"),
    111: ("rpcbind", "часто используется для разведки и амплификации DDoS"),
    512: ("rexec", "устаревший протокол удалённого выполнения без шифрования"),
    513: ("rlogin", "устаревший протокол удалённого входа без шифрования"),
    514: ("rsh", "удалённое выполнение команд без аутентификации по паролю"),
    2049: ("NFS", "нередко доступен без аутентификации при плохой настройке"),
    5900: ("VNC", "часто используется с пустым или слабым паролем"),
}


def check_open_ports():
    findings = []
    output = _run_first(["ss", "-tulnH"], ["netstat", "-tulnH"])
    if output is None:
        findings.append(Finding(
            check_id="open-ports",
            title="Открытые порты и сервисы",
            severity=Severity.INFO,
            description="failed-to-run: не удалось получить список слушающих портов "
                         "(нет ss/netstat или недостаточно прав).",
        ))
        return findings

    seen_ports = set()
    for line in output.splitlines():
        # ss/netstat columns: proto, recv-q, send-q, local-address:port, peer, ...
        match = re.search(r":(\d+)\s+\S+\s*(\S*)$", line)
        if not match:
            continue
        port = int(match.group(1))
        if port in seen_ports:
            continue
        seen_ports.add(port)

        if port in RISKY_PORTS:
            name, reason = RISKY_PORTS[port]
            findings.append(Finding(
                check_id="open-ports",
                title="Открытые порты и сервисы",
                severity=Severity.HIGH,
                description=f"failed: порт {port} ({name}) слушает и {reason}.",
                evidence=line.strip(),
                recommendation=f"Отключить {name}, если сервис не нужен, "
                                f"или заменить защищённым аналогом (например, SSH/SFTP).",
            ))

    if not any(f.severity >= Severity.LOW for f in findings):
        findings.append(Finding(
            check_id="open-ports",
            title="Открытые порты и сервисы",
            severity=Severity.INFO,
            description=f"passed: найдено {len(seen_ports)} слушающих портов, "
                         f"известных рискованных сервисов среди них нет.",
            evidence=", ".join(str(p) for p in sorted(seen_ports)) or "-",
        ))
    return findings


# --- Check 2: SSH hardening --------------------------------------------------
def _parse_sshd_config(paths):
    """Recursively resolve Include directives - Ubuntu 22.04+ ships a near-empty
    sshd_config that just does `Include /etc/ssh/sshd_config.d/*.conf`, so reading
    only the main file would silently miss the real settings."""
    settings = {}
    for path in paths:
        try:
            with open(path, "r") as f:
                lines = f.readlines()
        except (FileNotFoundError, PermissionError):
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0].lower(), parts[1].strip()
            if key == "include":
                for included in sorted(glob.glob(value)):
                    for k, v in _parse_sshd_config([included]).items():
                        settings.setdefault(k, v)
                continue
            # sshd uses the FIRST value seen for a given directive, unlike most configs
            settings.setdefault(key, value)
    return settings


def check_ssh_config():
    findings = []
    main_config = "/etc/ssh/sshd_config"
    if not os.path.exists(main_config):
        findings.append(Finding(
            check_id="ssh-config",
            title="Настройки SSH (root, пароль)",
            severity=Severity.INFO,
            description="failed-to-run: /etc/ssh/sshd_config не найден - похоже, sshd не установлен.",
        ))
        return findings

    settings = _parse_sshd_config([main_config])
    root_login = settings.get("permitrootlogin", "prohibit-password").lower()
    password_auth = settings.get("passwordauthentication", "yes").lower()

    if root_login == "yes":
        findings.append(Finding(
            check_id="ssh-config",
            title="PermitRootLogin",
            severity=Severity.CRITICAL,
            description=f"failed: PermitRootLogin {root_login} - вход под root по SSH "
                         f"разрешён полностью, включая по паролю.",
            evidence=f"PermitRootLogin {root_login}",
            recommendation="Установить PermitRootLogin no.",
        ))
    elif root_login in ("without-password", "prohibit-password"):
        findings.append(Finding(
            check_id="ssh-config",
            title="PermitRootLogin",
            severity=Severity.MEDIUM,
            description=f"passed-with-caveat: PermitRootLogin {root_login} - root может "
                         f"логиниться только по ключу, но вход под root в принципе разрешён.",
            evidence=f"PermitRootLogin {root_login}",
            recommendation="Для максимальной защиты установить PermitRootLogin no.",
        ))
    else:
        findings.append(Finding(
            check_id="ssh-config",
            title="PermitRootLogin",
            severity=Severity.INFO,
            description=f"passed: PermitRootLogin {root_login}",
        ))

    if password_auth == "yes":
        findings.append(Finding(
            check_id="ssh-config",
            title="PasswordAuthentication",
            severity=Severity.HIGH,
            description="failed: PasswordAuthentication yes - возможен подбор пароля по SSH.",
            evidence="PasswordAuthentication yes",
            recommendation="Отключить вход по паролю, использовать только ключи.",
        ))
    else:
        findings.append(Finding(
            check_id="ssh-config",
            title="PasswordAuthentication",
            severity=Severity.INFO,
            description=f"passed: PasswordAuthentication {password_auth}",
        ))

    return findings


# --- Check 3: pending security updates --------------------------------------
def check_pending_updates():
    findings = []
    if shutil.which("apt") is None and shutil.which("apt-get") is None:
        findings.append(Finding(
            check_id="pending-updates",
            title="Доступные обновления безопасности",
            severity=Severity.INFO,
            description="failed-to-run: apt/apt-get не найден - проверка поддерживает "
                         "только Debian/Ubuntu.",
        ))
        return findings

    # Deliberately NOT running "apt update" here: a scanner shouldn't mutate system
    # state or need network/sudo just to report. Result reflects the last apt update.
    output = _run(["apt", "list", "--upgradable"])
    if output is None:
        findings.append(Finding(
            check_id="pending-updates",
            title="Доступные обновления безопасности",
            severity=Severity.INFO,
            description="failed-to-run: не удалось выполнить apt list --upgradable.",
        ))
        return findings

    lines = [l for l in output.splitlines() if "/" in l and not l.startswith("Listing")]
    security_updates = [l for l in lines if "-security" in l]

    if security_updates:
        findings.append(Finding(
            check_id="pending-updates",
            title="Доступные обновления безопасности",
            severity=Severity.HIGH,
            description=f"failed: доступно {len(security_updates)} обновлений безопасности.",
            evidence="\n".join(security_updates[:20]),
            recommendation="Выполнить: sudo apt update && sudo apt upgrade.",
        ))
    elif lines:
        findings.append(Finding(
            check_id="pending-updates",
            title="Доступные обновления безопасности",
            severity=Severity.LOW,
            description=f"passed-with-caveat: обновлений безопасности не найдено, "
                         f"но есть {len(lines)} обычных обновлений.",
            evidence="\n".join(lines[:20]),
        ))
    else:
        findings.append(Finding(
            check_id="pending-updates",
            title="Доступные обновления безопасности",
            severity=Severity.INFO,
            description="passed: обновлений нет по данным локального кеша apt "
                         "(выполните apt update перед сканом, если кеш давно не обновлялся).",
        ))
    return findings


# --- Check 4: firewall status ------------------------------------------------
def check_firewall():
    findings = []
    if shutil.which("ufw"):
        output = _run(["ufw", "status"])
        if output is None:
            findings.append(Finding(
                check_id="firewall",
                title="Статус и правила файрвола",
                severity=Severity.INFO,
                description="failed-to-run: не удалось выполнить ufw status.",
            ))
            return findings
        if "Status: active" in output:
            rule_lines = [l for l in output.splitlines() if re.search(r"(ALLOW|DENY|REJECT)", l)]
            findings.append(Finding(
                check_id="firewall",
                title="Статус и правила файрвола",
                severity=Severity.INFO,
                description=f"passed: ufw активен, правил: {len(rule_lines)}.",
                evidence=output.strip(),
            ))
        else:
            findings.append(Finding(
                check_id="firewall",
                title="Статус и правила файрвола",
                severity=Severity.HIGH,
                description="failed: ufw установлен, но неактивен.",
                evidence=output.strip(),
                recommendation="Включить: sudo ufw enable.",
            ))
        return findings

    output = _run(["iptables", "-S"])
    if not output:
        findings.append(Finding(
            check_id="firewall",
            title="Статус и правила файрвола",
            severity=Severity.INFO,
            description="failed-to-run: не найден ни ufw, ни iptables (или нет прав их прочитать).",
        ))
        return findings

    rule_count = len([l for l in output.splitlines() if l.startswith("-A")])
    default_accept = "-P INPUT ACCEPT" in output

    if rule_count == 0 and default_accept:
        findings.append(Finding(
            check_id="firewall",
            title="Статус и правила файрвола",
            severity=Severity.HIGH,
            description="failed: iptables без явных правил, политика по умолчанию ACCEPT - "
                         "фактически файрвола нет.",
            evidence=output.strip(),
            recommendation="Настроить ufw, либо задать правила iptables с политикой DROP по умолчанию.",
        ))
    else:
        findings.append(Finding(
            check_id="firewall",
            title="Статус и правила файрвола",
            severity=Severity.INFO,
            description=f"passed: найдено {rule_count} правил iptables.",
            evidence=output.strip(),
        ))
    return findings


# --- Check 5: users with root/sudo access ------------------------------------
def check_privileged_users():
    findings = []
    try:
        with open("/etc/passwd") as f:
            passwd_lines = f.readlines()
    except (FileNotFoundError, PermissionError) as exc:
        findings.append(Finding(
            check_id="privileged-users",
            title="Пользователи с root и sudo",
            severity=Severity.INFO,
            description=f"failed-to-run: не удалось прочитать /etc/passwd ({exc}).",
        ))
        return findings

    uid0_users = []
    for line in passwd_lines:
        parts = line.strip().split(":")
        if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
            uid0_users.append(parts[0])

    if uid0_users:
        findings.append(Finding(
            check_id="privileged-users",
            title="Пользователи с UID 0",
            severity=Severity.CRITICAL,
            description=f"failed: помимо root, есть пользователи с UID 0: {', '.join(uid0_users)}.",
            evidence=", ".join(uid0_users),
            recommendation="Убрать UID 0 у всех аккаунтов, кроме root.",
        ))
    else:
        findings.append(Finding(
            check_id="privileged-users",
            title="Пользователи с UID 0",
            severity=Severity.INFO,
            description="passed: кроме root, UID 0 ни у кого нет.",
        ))

    members = []
    for group_name in ("sudo", "wheel"):
        group_line = (_run(["getent", "group", group_name]) or "").strip()
        fields = group_line.split(":")
        if len(fields) == 4 and fields[3]:
            members.extend(m for m in fields[3].split(",") if m)

    if members:
        findings.append(Finding(
            check_id="privileged-users",
            title="Члены группы sudo/wheel",
            severity=Severity.LOW,
            description=f"info: в sudo/wheel состоят: {', '.join(members)}.",
            evidence=", ".join(members),
            recommendation="Проверить, что в sudo/wheel только те, кому это реально нужно.",
        ))

    return findings


# --- Check 6: empty passwords -------------------------------------------------
def check_empty_passwords():
    findings = []
    try:
        with open("/etc/shadow") as f:
            shadow_lines = f.readlines()
    except PermissionError:
        findings.append(Finding(
            check_id="empty-passwords",
            title="Пустые пароли",
            severity=Severity.INFO,
            description="failed-to-run: нет прав на чтение /etc/shadow (нужен root).",
        ))
        return findings
    except FileNotFoundError:
        findings.append(Finding(
            check_id="empty-passwords",
            title="Пустые пароли",
            severity=Severity.INFO,
            description="failed-to-run: /etc/shadow не найден.",
        ))
        return findings

    empty_accounts = []
    for line in shadow_lines:
        parts = line.strip().split(":")
        if len(parts) >= 2 and parts[1] == "":
            empty_accounts.append(parts[0])

    if empty_accounts:
        findings.append(Finding(
            check_id="empty-passwords",
            title="Пустые пароли",
            severity=Severity.CRITICAL,
            description=f"failed: аккаунты без пароля: {', '.join(empty_accounts)}.",
            evidence=", ".join(empty_accounts),
            recommendation="Установить пароль (passwd <user>) или заблокировать аккаунт (passwd -l <user>).",
        ))
    else:
        findings.append(Finding(
            check_id="empty-passwords",
            title="Пустые пароли",
            severity=Severity.INFO,
            description="passed: аккаунтов с пустым паролем нет.",
        ))
    return findings


# --- Check 7: suspicious SUID files -------------------------------------------
# Small, explicit allowlist of binaries that legitimately need SUID. Anything
# outside it is worth a human look, not automatically malicious.
KNOWN_SUID_BINARIES = {
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/ping", "/usr/bin/gpasswd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/pkexec", "/usr/bin/fusermount",
    "/usr/bin/fusermount3", "/usr/lib/openssh/ssh-keysign", "/usr/bin/at",
    "/usr/bin/crontab", "/usr/sbin/pppd",
    "/bin/passwd", "/bin/su", "/bin/mount", "/bin/umount", "/bin/ping",
    "/usr/lib/snapd/snap-confine", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/landscape/apt-update", "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
}


def check_suid_files():
    findings = []
    # -xdev keeps the search on the root filesystem only - fast, and skips
    # /proc, network mounts, and any attached USB drives.
    output = _run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"])
    if not output:
        findings.append(Finding(
            check_id="suid-files",
            title="Подозрительные SUID-файлы",
            severity=Severity.INFO,
            description="failed-to-run: find не вернул результат (нет прав или недоступен).",
        ))
        return findings

    suid_files = [line.strip() for line in output.splitlines() if line.strip()]
    suspicious = [f for f in suid_files if f not in KNOWN_SUID_BINARIES]

    if suspicious:
        findings.append(Finding(
            check_id="suid-files",
            title="Подозрительные SUID-файлы",
            severity=Severity.HIGH,
            description=f"failed: найдено {len(suspicious)} SUID-файлов вне списка известных.",
            evidence="\n".join(suspicious[:30]),
            recommendation="Проверить каждый файл; снять SUID-бит (chmod u-s), если он не нужен.",
        ))
    else:
        findings.append(Finding(
            check_id="suid-files",
            title="Подозрительные SUID-файлы",
            severity=Severity.INFO,
            description=f"passed: все {len(suid_files)} SUID-файлов входят в список известных.",
        ))
    return findings


# --- Check 8: world-writable files in system directories ---------------------
SENSITIVE_DIRS = ["/etc", "/usr", "/bin", "/sbin", "/lib", "/boot"]


def check_world_writable():
    findings = []
    existing_dirs = [d for d in SENSITIVE_DIRS if os.path.isdir(d)]
    if not existing_dirs:
        findings.append(Finding(
            check_id="world-writable",
            title="World-writable в системных каталогах",
            severity=Severity.INFO,
            description="failed-to-run: ни один из проверяемых каталогов не найден.",
        ))
        return findings

    # "! -perm -1000" excludes directories with the sticky bit (like /tmp) -
    # those are meant to be world-writable and are not a problem.
    # "! -type l" is required too: a symlink's own permission bits are ignored
    # by Linux and always read back as 777 (lrwxrwxrwx), so without this every
    # symlink under the target dirs would falsely show up as world-writable.
    output = _run(["find", *existing_dirs, "-xdev", "!", "-type", "l",
                   "-perm", "-0002", "!", "-perm", "-1000"])
    if output is None:
        findings.append(Finding(
            check_id="world-writable",
            title="World-writable в системных каталогах",
            severity=Severity.INFO,
            description="failed-to-run: find не удалось выполнить (нет прав или таймаут).",
        ))
        return findings

    writable = [line.strip() for line in output.splitlines() if line.strip()]

    if writable:
        findings.append(Finding(
            check_id="world-writable",
            title="World-writable в системных каталогах",
            severity=Severity.HIGH,
            description=f"failed: найдено {len(writable)} объектов, доступных на запись "
                         f"всем, без sticky bit.",
            evidence="\n".join(writable[:30]),
            recommendation="Убрать world-write право (chmod o-w) или включить sticky bit (chmod +t).",
        ))
    else:
        findings.append(Finding(
            check_id="world-writable",
            title="World-writable в системных каталогах",
            severity=Severity.INFO,
            description="passed: world-writable объектов без sticky bit не найдено.",
        ))
    return findings


# --- Check 9: /etc/shadow permissions -----------------------------------------
def check_shadow_permissions():
    findings = []
    path = "/etc/shadow"
    try:
        st = os.stat(path)
    except FileNotFoundError:
        findings.append(Finding(
            check_id="shadow-permissions",
            title="Права на /etc/shadow",
            severity=Severity.INFO,
            description="failed-to-run: /etc/shadow не найден.",
        ))
        return findings
    except PermissionError:
        findings.append(Finding(
            check_id="shadow-permissions",
            title="Права на /etc/shadow",
            severity=Severity.INFO,
            description="failed-to-run: нет прав даже на stat /etc/shadow.",
        ))
        return findings

    mode = stat.S_IMODE(st.st_mode)
    problems = []
    if mode & stat.S_IROTH:
        problems.append("доступен на чтение всем (world-readable)")
    if mode & stat.S_IWOTH:
        problems.append("доступен на запись всем (world-writable)")
    if mode & stat.S_IWGRP:
        problems.append("доступен на запись группе")
    if st.st_uid != 0:
        problems.append(f"владелец не root (uid={st.st_uid})")

    evidence = f"mode={oct(mode)}, uid={st.st_uid}, gid={st.st_gid}"
    if problems:
        findings.append(Finding(
            check_id="shadow-permissions",
            title="Права на /etc/shadow",
            severity=Severity.CRITICAL,
            description=f"failed: {', '.join(problems)}.",
            evidence=evidence,
            recommendation="chmod 640 /etc/shadow && chown root:shadow /etc/shadow.",
        ))
    else:
        findings.append(Finding(
            check_id="shadow-permissions",
            title="Права на /etc/shadow",
            severity=Severity.INFO,
            description=f"passed: права {oct(mode)}, владелец root.",
            evidence=evidence,
        ))
    return findings


# --- Check 10: brute-force attempts in auth.log -------------------------------
def check_bruteforce_auth_log():
    findings = []
    log_path = "/var/log/auth.log"
    try:
        with open(log_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        findings.append(Finding(
            check_id="bruteforce-auth-log",
            title="Перебор паролей в auth.log",
            severity=Severity.INFO,
            description="failed-to-run: /var/log/auth.log не найден "
                         "(на RHEL/CentOS путь другой - /var/log/secure, пока не поддержан).",
        ))
        return findings
    except PermissionError:
        findings.append(Finding(
            check_id="bruteforce-auth-log",
            title="Перебор паролей в auth.log",
            severity=Severity.INFO,
            description="failed-to-run: нет прав на чтение /var/log/auth.log.",
        ))
        return findings

    ip_counts = {}
    for line in lines:
        if "Failed password" not in line:
            continue
        match = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)
        if match:
            ip = match.group(1)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    threshold = 10
    offenders = {ip: c for ip, c in ip_counts.items() if c >= threshold}

    if offenders:
        top = sorted(offenders.items(), key=lambda x: -x[1])[:20]
        findings.append(Finding(
            check_id="bruteforce-auth-log",
            title="Перебор паролей в auth.log",
            severity=Severity.HIGH,
            description=f"failed: {len(offenders)} IP-адресов с {threshold}+ неудачных попыток входа.",
            evidence="\n".join(f"{ip}: {c} попыток" for ip, c in top),
            recommendation="Настроить fail2ban или ограничить доступ по SSH через файрвол/VPN.",
        ))
    else:
        findings.append(Finding(
            check_id="bruteforce-auth-log",
            title="Перебор паролей в auth.log",
            severity=Severity.INFO,
            description=f"passed: серий из {threshold}+ неудачных попыток с одного IP не найдено.",
        ))
    return findings


CHECKS = [
    ("open-ports", "Открытые порты и сервисы", check_open_ports),
    ("ssh-config", "Настройки SSH (root, пароль)", check_ssh_config),
    ("pending-updates", "Доступные обновления безопасности", check_pending_updates),
    ("firewall", "Статус и правила файрвола", check_firewall),
    ("privileged-users", "Пользователи с root и sudo", check_privileged_users),
    ("empty-passwords", "Пустые пароли", check_empty_passwords),
    ("suid-files", "Подозрительные SUID-файлы", check_suid_files),
    ("world-writable", "World-writable в системных каталогах", check_world_writable),
    ("shadow-permissions", "Права на /etc/shadow", check_shadow_permissions),
    ("bruteforce-auth-log", "Перебор паролей в auth.log", check_bruteforce_auth_log),
]


SEVERITY_COLOR = {
    Severity.CRITICAL: "#7a1224",
    Severity.HIGH: "#b3261e",
    Severity.MEDIUM: "#b26a00",
    Severity.LOW: "#4a6b8a",
    Severity.INFO: "#5a5a5a",
}


def render_report(results, host_info):
    """Build the HTML report from already-computed findings.

    No templating library on purpose - the structure is simple enough that a
    plain f-string is easier to read and debug than adding a Jinja dependency.
    html.escape() is used on every value that came from the target system,
    since command output ends up inside an HTML page.
    """
    all_findings = [f for r in results for f in r.findings]
    counts = {sev: 0 for sev in Severity}
    for f in all_findings:
        counts[f.severity] += 1

    rows = []
    for result in results:
        if not result.ok:
            rows.append(
                f'<div class="check-error"><strong>{html.escape(result.title)}</strong>: '
                f'проверка не выполнена ({html.escape(result.error)})</div>'
            )
            continue
        for f in sorted(result.findings, key=lambda x: -x.severity):
            color = SEVERITY_COLOR[f.severity]
            evidence_html = (
                f'<pre class="evidence">{html.escape(f.evidence)}</pre>' if f.evidence else ""
            )
            recommendation_html = (
                f'<div class="recommendation">Рекомендация: {html.escape(f.recommendation)}</div>'
                if f.recommendation else ""
            )
            rows.append(f'''
            <div class="finding" style="border-left-color: {color}">
                <div class="finding-header">
                    <span class="severity" style="background:{color}">{f.severity.name}</span>
                    <strong>{html.escape(f.title)}</strong>
                </div>
                <p>{html.escape(f.description)}</p>
                {evidence_html}
                {recommendation_html}
            </div>''')

    summary = " · ".join(
        f'{sev.name}: {counts[sev]}' for sev in reversed(list(Severity)) if counts[sev]
    )

    return f'''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Отчёт сканера уязвимостей</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #666; margin-bottom: 1.5rem; }}
  .summary {{ font-weight: 600; margin-bottom: 1.5rem; }}
  .finding {{ border-left: 4px solid #999; background: #f7f7f7; padding: 0.75rem 1rem; margin-bottom: 0.75rem; border-radius: 4px; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.3rem; }}
  .severity {{ color: white; font-size: 0.75rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 3px; }}
  .evidence {{ background: #1e1e1e; color: #ddd; padding: 0.5rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }}
  .recommendation {{ font-size: 0.9rem; color: #333; margin-top: 0.3rem; }}
  .check-error {{ color: #888; font-style: italic; margin-bottom: 0.5rem; }}
</style>
</head>
<body>
  <h1>Отчёт сканера уязвимостей</h1>
  <div class="meta">Хост: {html.escape(host_info)} · Сгенерирован: {datetime.datetime.now().isoformat(timespec="seconds")}</div>
  <div class="summary">{summary or "Находок нет"}</div>
  {"".join(rows)}
</body>
</html>'''


def main():
    parser = argparse.ArgumentParser(description="Сканер уязвимостей Linux")
    parser.add_argument("-o", "--output", default="report.html", help="путь к HTML-отчёту")
    args = parser.parse_args()

    host_info = f"{platform.node()} ({platform.system()} {platform.release()})"

    results = [run_check(cid, title, func) for cid, title, func in CHECKS]

    report_html = render_report(results, host_info)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report_html)

    total_findings = sum(len(r.findings) for r in results)
    print(f"Готово: {total_findings} находок(и). Отчёт: {args.output}")


if __name__ == "__main__":
    main()
