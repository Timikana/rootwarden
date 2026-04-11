"""
cyber_audit.py — Helpers pour l'audit de securite cyber des serveurs Linux.

Fonctions pures : prennent un client Paramiko + root_password
et executent des commandes d'analyse via execute_as_root().

Checks :
    1. Comptes Linux (UID 0, sans password, jamais connectes, expires)
    2. Sudoers (NOPASSWD, ALL, fichiers dans sudoers.d)
    3. Ports ouverts (services exposes sur 0.0.0.0)
    4. Binaires SUID/SGID suspects
    5. MAJ securite en attente
    6. Permissions fichiers sensibles
"""

import re
import logging
from ssh_utils import execute_as_root

_log = logging.getLogger(__name__)

# ── Severite et scoring ──────────────────────────────────────────────────────

SEVERITY_POINTS = {'critical': 25, 'high': 15, 'medium': 10, 'low': 5, 'info': 0}

# SUID binaires connus et safe (ne pas alerter dessus)
KNOWN_SUID = {
    '/usr/bin/passwd', '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/newgrp',
    '/usr/bin/gpasswd', '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/mount',
    '/usr/bin/umount', '/usr/bin/crontab', '/usr/bin/at', '/usr/bin/fusermount',
    '/usr/bin/fusermount3', '/usr/bin/pkexec', '/usr/bin/ssh-agent',
    '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    '/usr/lib/openssh/ssh-keysign',
    '/usr/lib/policykit-1/polkit-agent-helper-1',
    '/usr/libexec/polkit-agent-helper-1',
    '/usr/sbin/unix_chkpwd',
    '/usr/bin/wall', '/usr/bin/expiry',
    '/usr/bin/bsd-write', '/usr/bin/write',
}

# Ports connus et attendus
SAFE_PORTS = {22, 80, 443}

# Fichiers sensibles et permissions attendues
SENSITIVE_FILES = {
    '/etc/shadow': '640',
    '/etc/gshadow': '640',
    '/etc/passwd': '644',
    '/etc/ssh/sshd_config': '644',
    '/etc/sudoers': '440',
}


# ── Check 1 : Comptes Linux ─────────────────────────────────────────────────

def check_accounts(client, root_pass):
    """Analyse les comptes Linux pour les anomalies de securite."""
    findings = []

    # Comptes avec UID 0 (autre que root)
    out, _, _ = execute_as_root(client, "awk -F: '$3==0 && $1!=\"root\" {print $1}' /etc/passwd", root_pass, timeout=10)
    for line in out.strip().splitlines():
        name = line.strip()
        if name:
            findings.append({
                'check': 'account_uid0',
                'severity': 'critical',
                'detail': f'Compte avec UID 0 : {name}',
            })

    # Comptes sans password (champ vide dans /etc/shadow)
    out, _, _ = execute_as_root(client,
        "awk -F: '($2==\"\" || $2==\"!\") && $1!=\"root\" {print $1\":\"$2}' /etc/shadow 2>/dev/null",
        root_pass, timeout=10)
    for line in out.strip().splitlines():
        parts = line.strip().split(':')
        if parts and parts[0]:
            is_locked = len(parts) > 1 and parts[1] == '!'
            if not is_locked:
                findings.append({
                    'check': 'account_no_password',
                    'severity': 'high',
                    'detail': f'Compte sans mot de passe : {parts[0]}',
                })

    # Comptes systeme avec shell de login (hors root, daemon connus)
    out, _, _ = execute_as_root(client,
        "awk -F: '$3>=1000 && $7!~/nologin/ && $7!~/false/ {print $1\":\"$7}' /etc/passwd",
        root_pass, timeout=10)
    login_accounts = []
    for line in out.strip().splitlines():
        parts = line.strip().split(':')
        if parts and parts[0]:
            login_accounts.append(parts[0])

    # Password expires (plus de 90 jours sans changement)
    out, _, _ = execute_as_root(client,
        "awk -F: '$3!=\"\" && $3!=\"0\" {print $1\":\"$3}' /etc/shadow 2>/dev/null",
        root_pass, timeout=10)
    import time
    today = int(time.time() / 86400)
    for line in out.strip().splitlines():
        parts = line.strip().split(':')
        if len(parts) >= 2 and parts[0] in login_accounts:
            try:
                last_change = int(parts[1])
                if last_change > 0 and (today - last_change) > 90:
                    days = today - last_change
                    findings.append({
                        'check': 'account_password_age',
                        'severity': 'medium',
                        'detail': f'Password de {parts[0]} non change depuis {days} jours',
                    })
            except (ValueError, IndexError):
                pass

    return findings


# ── Check 2 : Sudoers ───────────────────────────────────────────────────────

def check_sudoers(client, root_pass):
    """Analyse la configuration sudoers."""
    findings = []

    # Lire sudoers principal + sudoers.d
    out, _, _ = execute_as_root(client,
        "cat /etc/sudoers 2>/dev/null; echo '---SPLIT---'; cat /etc/sudoers.d/* 2>/dev/null || true",
        root_pass, timeout=10)

    for line in out.splitlines():
        line = line.strip()
        if line.startswith('#') or line.startswith('---SPLIT---') or not line:
            continue
        if 'Defaults' in line:
            continue

        # NOPASSWD detecte
        if 'NOPASSWD' in line:
            # rootwarden est attendu (service account)
            if 'rootwarden' in line:
                findings.append({
                    'check': 'sudoers_nopasswd_service',
                    'severity': 'info',
                    'detail': f'Service account rootwarden avec NOPASSWD (attendu)',
                })
            else:
                findings.append({
                    'check': 'sudoers_nopasswd',
                    'severity': 'high',
                    'detail': f'NOPASSWD detecte : {line[:100]}',
                })

        # ALL=(ALL) ALL sans NOPASSWD
        elif re.match(r'^\S+\s+ALL\s*=\s*\(ALL', line) and 'NOPASSWD' not in line:
            findings.append({
                'check': 'sudoers_all',
                'severity': 'medium',
                'detail': f'Privilege sudo large : {line[:100]}',
            })

    return findings


# ── Check 3 : Ports ouverts ─────────────────────────────────────────────────

def check_open_ports(client, root_pass):
    """Detecte les ports ouverts sur toutes les interfaces."""
    findings = []

    out, _, _ = execute_as_root(client,
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
        root_pass, timeout=10)

    port_re = re.compile(r'([\d.*:]+):(\d+)\s')
    for line in out.splitlines():
        if 'LISTEN' not in line:
            continue
        m = port_re.search(line)
        if not m:
            continue
        addr, port_str = m.group(1), m.group(2)
        port = int(port_str)

        # Detecter les services sur 0.0.0.0 ou *
        is_exposed = addr in ('0.0.0.0', '*', '::') or addr.endswith(':0.0.0.0')

        if is_exposed and port not in SAFE_PORTS:
            # Extraire le nom du process si disponible
            proc_match = re.search(r'users:\(\("([^"]+)"', line)
            proc_name = proc_match.group(1) if proc_match else 'inconnu'

            severity = 'critical' if port in (3306, 5432, 6379, 27017, 9200) else 'high'
            findings.append({
                'check': 'port_exposed',
                'severity': severity,
                'detail': f'Port {port} expose sur {addr} ({proc_name})',
            })

    return findings


# ── Check 4 : Binaires SUID/SGID ────────────────────────────────────────────

def check_suid_binaries(client, root_pass):
    """Detecte les binaires SUID/SGID non-standard."""
    findings = []

    out, _, _ = execute_as_root(client,
        "find / -perm -4000 -type f 2>/dev/null | head -50",
        root_pass, timeout=30)

    for line in out.strip().splitlines():
        path = line.strip()
        if not path or not path.startswith('/'):
            continue
        if path in KNOWN_SUID:
            continue
        findings.append({
            'check': 'suid_unusual',
            'severity': 'high',
            'detail': f'Binaire SUID non-standard : {path}',
        })

    return findings


# ── Check 5 : MAJ securite en attente ───────────────────────────────────────

def check_pending_security_updates(client, root_pass):
    """Compte le nombre de MAJ securite en attente."""
    findings = []

    out, _, rc = execute_as_root(client,
        "apt list --upgradable 2>/dev/null | grep -i security | wc -l",
        root_pass, timeout=30)
    count = 0
    try:
        count = int(out.strip())
    except ValueError:
        pass

    if count > 0:
        severity = 'critical' if count >= 10 else 'high' if count >= 5 else 'medium'
        findings.append({
            'check': 'security_updates_pending',
            'severity': severity,
            'detail': f'{count} mises a jour de securite en attente',
        })

    return findings


# ── Check 6 : Permissions fichiers sensibles ────────────────────────────────

def check_file_permissions(client, root_pass):
    """Verifie les permissions des fichiers sensibles."""
    findings = []

    for filepath, expected in SENSITIVE_FILES.items():
        out, _, rc = execute_as_root(client,
            f"stat -c '%a' {filepath} 2>/dev/null || echo 'MISSING'",
            root_pass, timeout=5)
        actual = out.strip()
        if actual == 'MISSING':
            continue
        if actual != expected:
            severity = 'high' if filepath in ('/etc/shadow', '/etc/gshadow', '/etc/sudoers') else 'medium'
            findings.append({
                'check': 'file_permissions',
                'severity': severity,
                'detail': f'{filepath} : permissions {actual} (attendu {expected})',
            })

    return findings


# ── Aggregation : score global ───────────────────────────────────────────────

def run_full_audit(client, root_pass):
    """Execute tous les checks et calcule le score global."""
    all_findings = []

    checks = [
        ('accounts', check_accounts),
        ('sudoers', check_sudoers),
        ('ports', check_open_ports),
        ('suid', check_suid_binaries),
        ('updates', check_pending_security_updates),
        ('permissions', check_file_permissions),
    ]

    for name, func in checks:
        try:
            findings = func(client, root_pass)
            all_findings.extend(findings)
        except Exception as e:
            _log.warning("Cyber audit check '%s' failed: %s", name, e)
            all_findings.append({
                'check': f'{name}_error',
                'severity': 'info',
                'detail': f'Check {name} echoue',
            })

    # Calcul du score
    total_penalty = sum(SEVERITY_POINTS.get(f['severity'], 0) for f in all_findings)
    score = max(0, 100 - total_penalty)
    grade = _calculate_grade(score)

    # Compteurs par categorie
    counts = {
        'accounts_critical': sum(1 for f in all_findings if f['check'].startswith('account') and f['severity'] == 'critical'),
        'accounts_high': sum(1 for f in all_findings if f['check'].startswith('account') and f['severity'] == 'high'),
        'sudoers_critical': sum(1 for f in all_findings if f['check'].startswith('sudoers') and f['severity'] == 'critical'),
        'sudoers_high': sum(1 for f in all_findings if f['check'].startswith('sudoers') and f['severity'] == 'high'),
        'ports_critical': sum(1 for f in all_findings if f['check'].startswith('port') and f['severity'] == 'critical'),
        'ports_high': sum(1 for f in all_findings if f['check'].startswith('port') and f['severity'] == 'high'),
        'suid_high': sum(1 for f in all_findings if f['check'].startswith('suid') and f['severity'] == 'high'),
        'updates_pending': sum(1 for f in all_findings if f['check'] == 'security_updates_pending'),
    }

    return {
        'score': score,
        'grade': grade,
        'findings': all_findings,
        'counts': counts,
        'total_findings': len(all_findings),
    }


def _calculate_grade(score):
    if score >= 90: return 'A'
    if score >= 75: return 'B'
    if score >= 60: return 'C'
    if score >= 40: return 'D'
    return 'F'
