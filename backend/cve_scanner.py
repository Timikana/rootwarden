#!/usr/bin/env python3
"""
cve_scanner.py - Scan de vulnérabilités CVE via l'API REST OpenCVE pour RootWarden.

Rôle :
    Ce module interroge l'API OpenCVE pour détecter les CVE affectant les packages
    installés sur un serveur Linux distant (via SSH). Les résultats sont streamés
    sous forme de JSON-lines (générateur) et persistés dans la base de données MySQL.

Dépendances clés :
    - requests             : appels HTTP vers l'API OpenCVE (Basic Auth)
    - mysql.connector      : persistance des scans (tables cve_scans, cve_findings)
    - config.Config        : OPENCVE_URL, OPENCVE_USERNAME, OPENCVE_PASSWORD,
                             CVE_CACHE_TTL, DB_CONFIG
    - ssh_client (Paramiko): nécessaire pour get_installed_packages et detect_os_vendor

Stratégie de cache :
    OpenCVEClient maintient un cache mémoire TTL (durée configurable via CVE_CACHE_TTL)
    pour éviter de répéter des requêtes identiques au cours d'un même scan.

Note de sécurité :
    L'authentification auprès d'OpenCVE utilise HTTP Basic Auth sur HTTPS.
    Les credentials ne transitent pas en clair si OPENCVE_URL utilise https://.
"""
# cve_scanner.py - Intégration OpenCVE pour RootWarden
#
# Supporte :
#   - OpenCVE cloud   (https://app.opencve.io)
#   - OpenCVE on-prem (URL configurable via OPENCVE_URL)
# Auth : HTTP Basic (username / password)
# Stratégie : requête par package avec cache mémoire TTL-based

import re
import time
import json
import logging
import mysql.connector
import requests
from datetime import datetime
from config import Config

_log = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Utilitaires CVSS
# ────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'NONE': 4}


def cvss_to_severity(score: float) -> str:
    """
    Convertit un score CVSS numérique en niveau de sévérité textuel.

    Correspondance NVD standard :
        >= 9.0 → CRITICAL
        >= 7.0 → HIGH
        >= 4.0 → MEDIUM
        >  0.0 → LOW
        == 0.0 → NONE

    Args:
        score (float): Score CVSS (v2 ou v3), entre 0.0 et 10.0.

    Returns:
        Chaîne parmi : 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'.
    """
    if score >= 9.0: return 'CRITICAL'
    if score >= 7.0: return 'HIGH'
    if score >= 4.0: return 'MEDIUM'
    if score > 0.0:  return 'LOW'
    return 'NONE'


def best_cvss(cvss_dict: dict) -> float:
    """
    Extrait le meilleur score CVSS disponible.

    Supporte :
      - OpenCVE v1 / mock : {'v3': 7.5, 'v2': 6.0}
      - OpenCVE v2 on-prem : {'cvssV3_1': {'data': {'score': 7.5}}, ...}
      - Absent : retourne 5.0 (medium par défaut, permet le filtrage)
    """
    if not cvss_dict:
        return 5.0  # Score par défaut si pas de CVSS (permet d'inclure dans les scans)

    # Format v1 / mock
    v3 = cvss_dict.get('v3') or 0.0
    v2 = cvss_dict.get('v2') or 0.0
    if v3 or v2:
        return float(v3 if v3 else v2)

    # Format v2 on-prem (metrics nested)
    for key in ('cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
        metric = cvss_dict.get(key, {})
        if isinstance(metric, dict):
            data = metric.get('data', {})
            score = data.get('score') or data.get('baseScore') or 0.0
            if score:
                return float(score)

    return 5.0


# ────────────────────────────────────────────────────────────────────────────
# Client OpenCVE
# ────────────────────────────────────────────────────────────────────────────

class OpenCVEClient:
    """
    Client REST pour OpenCVE (cloud opencve.io ou instance on-prem v2).

    Modes d'authentification (priorité) :
        1. Bearer token (OPENCVE_TOKEN) - OpenCVE v2 on-prem
        2. Basic Auth (OPENCVE_USERNAME + OPENCVE_PASSWORD) - opencve.io cloud / mock

    Configuration via variables d'environnement :
        OPENCVE_URL       → URL de base (ex: https://app.opencve.io)
        OPENCVE_TOKEN     → Bearer token pour on-prem v2 (prioritaire si défini)
        OPENCVE_USERNAME  → identifiant (Basic Auth, fallback)
        OPENCVE_PASSWORD  → mot de passe (Basic Auth, fallback)
        CVE_CACHE_TTL     → durée du cache en secondes (défaut 3600)
    """

    def __init__(self):
        self.base_url = Config.OPENCVE_URL.rstrip('/')
        self.token = Config.OPENCVE_TOKEN
        self.auth = (Config.OPENCVE_USERNAME, Config.OPENCVE_PASSWORD) if not self.token else None
        self._cache: dict[str, tuple[float, dict]] = {}
        self.cache_ttl: int = Config.CVE_CACHE_TTL
        self._auth_mode = 'bearer' if self.token else 'basic'

    def _get(self, path: str, params: dict = None) -> dict:
        """
        Effectue un GET authentifié vers l'API OpenCVE avec cache mémoire TTL.

        La clé de cache est construite à partir du ``path`` et des ``params``
        triés alphabétiquement pour garantir l'unicité. Si une entrée valide
        (non expirée selon cache_ttl) existe, elle est retournée directement
        sans appel réseau.

        Args:
            path   (str) : Chemin de l'API (ex: '/api/cve').
            params (dict): Paramètres de query string (optionnel).

        Returns:
            dict : Réponse JSON désérialisée.

        Raises:
            requests.HTTPError    : Si le serveur retourne un statut HTTP >= 400.
            requests.ConnectionError: Si l'URL est injoignable.
        """
        cache_key = f"{path}#{json.dumps(sorted((params or {}).items()))}"
        now = time.time()
        if cache_key in self._cache:
            ts, data = self._cache[cache_key]
            if now - ts < self.cache_ttl:
                return data

        url = f"{self.base_url}{path}"
        kwargs = {'params': params, 'timeout': 15}
        if self.token:
            kwargs['headers'] = {'Authorization': f'Bearer {self.token}'}
        else:
            kwargs['auth'] = self.auth
        resp = requests.get(url, **kwargs)
        resp.raise_for_status()
        data = resp.json()
        self._cache[cache_key] = (now, data)
        return data

    def test_connection(self) -> tuple[bool, str]:
        """
        Teste la connectivité et l'authentification auprès de l'instance OpenCVE.

        Effectue une requête minimale (limit=1) sur /api/cve pour vérifier que
        l'URL est joignable et que les credentials sont valides.

        Returns:
            tuple[bool, str] : (True, message_ok) ou (False, message_erreur).
            Cas d'erreur gérés : ConnectionError, HTTP 401 (auth refusée),
            autres HTTPError, exceptions génériques.
        """
        try:
            self._get('/api/cve', {'limit': 1})
            return True, f"Connexion OK ({self.base_url}, auth={self._auth_mode})"
        except requests.ConnectionError:
            return False, f"Impossible de joindre {self.base_url}"
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else '?'
            if code == 401:
                hint = "OPENCVE_TOKEN" if self._auth_mode == 'bearer' else "OPENCVE_USERNAME / OPENCVE_PASSWORD"
                return False, f"Authentification refusee (verifiez {hint})"
            if code == 403:
                return False, f"Acces interdit (token valide mais permissions insuffisantes)"
            return False, f"Erreur HTTP {code}"
        except Exception as e:
            return False, str(e)

    def get_cves_for_package(self, package: str, vendor: str) -> list[dict]:
        """
        Retourne les CVEs OpenCVE pour un package donné.
        Supporte deux modes :
          - OpenCVE v1 / cloud / mock : ?vendor=X&product=Y
          - OpenCVE v2 on-prem : ?search=package (vendor/product = 404)
        Pagine automatiquement (max 3 pages).
        """
        results = []
        page = 1
        use_search = False  # On essaie d'abord vendor/product, fallback search

        while page <= 3:
            try:
                if use_search:
                    params = {'search': package, 'page': page}
                else:
                    params = {'vendor': vendor, 'product': package, 'page': page}

                data = self._get('/api/cve', params)
                batch = data.get('results', [])
                if not batch:
                    break

                # Normalise les champs entre v1 et v2
                for cve in batch:
                    if 'cve_id' in cve and 'id' not in cve:
                        cve['id'] = cve['cve_id']
                    if 'description' in cve and 'summary' not in cve:
                        cve['summary'] = cve['description']
                    if 'cvss' not in cve:
                        cve['cvss'] = {}

                results.extend(batch)
                if not data.get('next'):
                    break
                page += 1
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    if not use_search:
                        # v2 on-prem: vendor/product 404 → retry with search
                        use_search = True
                        continue
                    break
                _log.debug("OpenCVE HTTP error (%s / %s): %s", vendor, package, e)
                break
            except Exception as e:
                _log.debug("OpenCVE error (%s / %s): %s", vendor, package, e)
                break
        return results


# Singleton partagé (chargé une seule fois au démarrage du worker)
_opencve: OpenCVEClient | None = None


def get_opencve_client() -> OpenCVEClient:
    """
    Retourne l'instance singleton d'OpenCVEClient, en la créant si nécessaire.

    Le singleton est initialisé une seule fois au premier appel (pattern lazy init).
    Partager une instance unique permet de réutiliser le cache entre les appels
    au sein d'un même worker Flask.

    Returns:
        OpenCVEClient : Instance partagée du client OpenCVE.
    """
    global _opencve
    if _opencve is None:
        _opencve = OpenCVEClient()
    return _opencve


# ────────────────────────────────────────────────────────────────────────────
# Récupération des packages via SSH
# ────────────────────────────────────────────────────────────────────────────

_EPOCH_RE   = re.compile(r'^\d+:')
_DISTRO_RE  = re.compile(r'[+~].*$')


def get_installed_packages(ssh_client) -> list[dict]:
    """
    Liste les packages installés via dpkg-query (ne nécessite pas root).
    Retourne [{name, version, clean_version}] dédupliqués par nom.
    """
    stdin, stdout, stderr = ssh_client.exec_command(
        "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null",
        timeout=30,
    )
    output = stdout.read().decode('utf-8', errors='replace')
    seen = {}  # Déduplique par nom (ex: libc6:amd64 et libc6:i386 → un seul libc6)
    for line in output.strip().splitlines():
        parts = line.split('\t', 1)
        if len(parts) != 2:
            continue
        name, version = parts[0].strip(), parts[1].strip()
        if not name or not version or version in ('<none>', ''):
            continue
        clean_name = name.split(':')[0]  # retirer :amd64 etc.
        if clean_name in seen:
            continue  # Déjà vu - skip le doublon multiarch
        # Nettoyer le numéro de version (epoch + suffixe Debian)
        clean = _EPOCH_RE.sub('', version)
        clean = _DISTRO_RE.sub('', clean)
        seen[clean_name] = {
            'name':          clean_name,
            'version':       version,
            'clean_version': clean,
        }
    return list(seen.values())


def detect_os_vendor(ssh_client) -> str:
    """
    Détecte le vendor de l'OS Linux pour paramétrer les requêtes OpenCVE.

    Lit la clé ``ID`` de /etc/os-release via SSH et normalise en minuscules.
    Retourne 'debian' par défaut si la valeur est absente ou non reconnue,
    car la majorité des CVE de packages Debian/Ubuntu partagent le même vendor.

    Args:
        ssh_client: Client SSH Paramiko connecté au serveur cible.

    Returns:
        'debian' ou 'ubuntu' (str).
    """
    try:
        stdin, stdout, _ = ssh_client.exec_command(
            "grep -i '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"' | tr '[:upper:]' '[:lower:]'",
            timeout=10,
        )
        os_id = stdout.read().decode().strip()
        return os_id if os_id in ('debian', 'ubuntu') else 'debian'
    except Exception:
        return 'debian'


def get_system_components(ssh_client) -> list[dict]:
    """
    Collecte les composants systeme (kernel, distro, services) pour le scan CVE.
    Ces elements ne sont pas dans dpkg-query mais sont critiques pour la securite.

    Retourne une liste de dicts {name, version, clean_version, component_type}.
    """
    components = []

    # 1. Noyau Linux (uname -r → ex: 6.1.0-18-amd64)
    try:
        _, stdout, _ = ssh_client.exec_command("uname -r 2>/dev/null", timeout=10)
        kernel_full = stdout.read().decode().strip()
        if kernel_full:
            # Extraire la version majeure.mineure (6.1.0-18-amd64 → 6.1)
            parts = kernel_full.split('.')
            kernel_short = '.'.join(parts[:2]) if len(parts) >= 2 else kernel_full
            components.append({
                'name': 'linux_kernel',
                'version': kernel_full,
                'clean_version': kernel_short,
                'component_type': 'kernel',
            })
    except Exception as e:
        _log.debug("Kernel detection failed: %s", e)

    # 2. Distribution Linux (os-release → ex: debian 12, ubuntu 22.04)
    try:
        _, stdout, _ = ssh_client.exec_command(
            "cat /etc/os-release 2>/dev/null", timeout=10
        )
        os_data = {}
        for line in stdout.read().decode().strip().splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                os_data[k.strip()] = v.strip().strip('"')

        os_id = os_data.get('ID', '').lower()
        os_version = os_data.get('VERSION_ID', '')
        os_name = os_data.get('PRETTY_NAME', '')

        if os_id and os_version:
            # Product name pour OpenCVE : debian_linux, ubuntu_linux
            product = f"{os_id}_linux" if os_id in ('debian', 'ubuntu') else os_id
            components.append({
                'name': product,
                'version': os_name or f"{os_id} {os_version}",
                'clean_version': os_version,
                'component_type': 'distro',
            })
    except Exception as e:
        _log.debug("Distro detection failed: %s", e)

    # 3. OpenSSH (version du serveur SSH - cible frequente de CVE)
    try:
        _, stdout, _ = ssh_client.exec_command(
            "ssh -V 2>&1 | head -1", timeout=10
        )
        ssh_version_raw = stdout.read().decode().strip()
        # OpenSSH_9.2p1 Debian-2+deb12u3 → 9.2
        if 'OpenSSH' in ssh_version_raw:
            import re as _re
            match = _re.search(r'OpenSSH[_ ](\d+\.\d+)', ssh_version_raw)
            if match:
                components.append({
                    'name': 'openssh',
                    'version': ssh_version_raw,
                    'clean_version': match.group(1),
                    'component_type': 'service',
                })
    except Exception as e:
        _log.debug("OpenSSH detection failed: %s", e)

    # 4. OpenSSL (librairie crypto - CVE critiques frequentes)
    try:
        _, stdout, _ = ssh_client.exec_command(
            "openssl version 2>/dev/null | head -1", timeout=10
        )
        ssl_raw = stdout.read().decode().strip()
        # OpenSSL 3.0.11 → 3.0.11
        if ssl_raw and 'OpenSSL' in ssl_raw:
            import re as _re
            match = _re.search(r'OpenSSL\s+(\d+\.\d+\.\d+)', ssl_raw)
            if match:
                components.append({
                    'name': 'openssl',
                    'version': ssl_raw,
                    'clean_version': match.group(1),
                    'component_type': 'service',
                })
    except Exception as e:
        _log.debug("OpenSSL detection failed: %s", e)

    # 5. Apache / Nginx (si present)
    for svc_cmd, svc_name, svc_regex in [
        ("apache2 -v 2>/dev/null | head -1", "apache_http_server", r'Apache/(\d+\.\d+\.\d+)'),
        ("nginx -v 2>&1 | head -1", "nginx", r'nginx/(\d+\.\d+\.\d+)'),
        ("systemctl is-active docker 2>/dev/null && docker --version 2>/dev/null | head -1", "docker", r'(\d+\.\d+\.\d+)'),
    ]:
        try:
            _, stdout, _ = ssh_client.exec_command(svc_cmd, timeout=10)
            raw = stdout.read().decode().strip()
            if raw:
                import re as _re
                match = _re.search(svc_regex, raw)
                if match:
                    components.append({
                        'name': svc_name,
                        'version': raw,
                        'clean_version': match.group(1),
                        'component_type': 'service',
                    })
        except Exception:
            pass

    return components


# ────────────────────────────────────────────────────────────────────────────
# Scan complet (générateur → streaming)
# ────────────────────────────────────────────────────────────────────────────

def scan_server(ssh_client, machine_id: int, machine_name: str,
                min_cvss: float = 0.0):
    """
    Générateur qui scanne un serveur et yield des dicts d'événements :
      {'type': 'start',    'total': N, 'vendor': '...'}
      {'type': 'progress', 'current': i, 'total': N, 'package': '...'}
      {'type': 'finding',  ... données CVE ...}
      {'type': 'done',     'total_findings': N, 'packages_scanned': N}
      {'type': 'error',    'message': '...'}
    """
    opencve = get_opencve_client()
    try:
        # Etape 1 : detection OS
        yield {'type': 'progress', 'machine_id': machine_id,
               'step': 'detect_os', 'message': 'Detection du systeme d\'exploitation...'}
        vendor = detect_os_vendor(ssh_client)

        # Etape 2 : detection composants systeme (kernel, distro, services)
        yield {'type': 'progress', 'machine_id': machine_id,
               'step': 'system', 'message': 'Detection des composants systeme (kernel, services)...'}
        system_components = get_system_components(ssh_client)
        if system_components:
            comp_names = ', '.join(c['name'] for c in system_components)
            yield {'type': 'progress', 'machine_id': machine_id,
                   'step': 'system', 'message': f'{len(system_components)} composant(s) detecte(s) : {comp_names}'}

        # Etape 3 : recuperation des paquets installes
        yield {'type': 'progress', 'machine_id': machine_id,
               'step': 'packages', 'message': 'Recuperation des paquets installes (dpkg-query)...'}
        packages = get_installed_packages(ssh_client)

        # Fusionner : composants systeme + paquets dpkg
        all_items = system_components + packages
        total = len(all_items)

        yield {'type': 'start', 'machine_id': machine_id,
               'machine_name': machine_name, 'total': total, 'vendor': vendor,
               'system_components': len(system_components), 'dpkg_packages': len(packages)}

        yield {'type': 'progress', 'machine_id': machine_id,
               'step': 'scan', 'message': f'{len(system_components)} composant(s) + {len(packages)} paquet(s) - interrogation OpenCVE...',
               'total_packages': total}

        # Mapping vendor OpenCVE pour les composants systeme
        _SYSTEM_VENDORS = {
            'linux_kernel': 'linux',
            'debian_linux': 'debian',
            'ubuntu_linux': 'canonical',
            'openssh': 'openbsd',
            'openssl': 'openssl',
            'apache_http_server': 'apache',
            'nginx': 'f5',
            'docker': 'docker',
        }

        findings = []
        queried = 0
        skipped = 0
        total_cve_found = 0
        for i, pkg in enumerate(all_items):
            pct = round(((i + 1) / total) * 100) if total > 0 else 0
            comp_type = pkg.get('component_type', 'package')
            label = f"[{comp_type.upper()}] {pkg['name']}" if comp_type != 'package' else pkg['name']
            yield {'type': 'progress', 'machine_id': machine_id,
                   'current': i + 1, 'total': total, 'percent': pct,
                   'package': label, 'step': 'scan',
                   'component_type': comp_type}

            # Vendor : specifique pour composants systeme, sinon vendor OS
            pkg_vendor = _SYSTEM_VENDORS.get(pkg['name'], vendor)

            try:
                cves = opencve.get_cves_for_package(pkg['name'], pkg_vendor)
                queried += 1
            except Exception as pkg_err:
                _log.debug("Skipped %s: %s", pkg['name'], pkg_err)
                skipped += 1
                continue
            pkg_cve_count = 0
            for cve in cves:
                score = best_cvss(cve.get('cvss') or cve.get('metrics') or {})
                if score < min_cvss:
                    continue
                finding = {
                    'package':  pkg['name'],
                    'version':  pkg['version'],
                    'cve_id':   cve.get('id', ''),
                    'cvss':     round(score, 1),
                    'severity': cvss_to_severity(score),
                    'summary':  (cve.get('summary') or '')[:300],
                    'component_type': comp_type,
                }
                findings.append(finding)
                pkg_cve_count += 1
                total_cve_found += 1
                yield {'type': 'finding', 'machine_id': machine_id, **finding}
            # Emit cve_count for this package (even if 0) for UI tracking
            if pkg_cve_count == 0 and i % 10 == 0:
                # Only emit every 10 packages to avoid flooding for zero-CVE packages
                yield {'type': 'progress', 'machine_id': machine_id,
                       'current': i + 1, 'total': total, 'percent': pct,
                       'package': pkg['name'], 'cve_count': 0, 'step': 'scan',
                       'total_cve_found': total_cve_found}

        # Tri final : CRITICAL → LOW, puis score décroissant
        findings.sort(key=lambda x: (SEVERITY_ORDER.get(x['severity'], 5), -x['cvss']))

        # Persistance en base
        scan_id = _save_scan(machine_id, findings, total, min_cvss)

        # Notification webhook
        try:
            from webhooks import notify_cve_scan
            counts = {s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM')}
            for f in findings:
                if f.get('severity') in counts:
                    counts[f['severity']] += 1
            notify_cve_scan(machine_name, len(findings), counts['CRITICAL'], counts['HIGH'], counts['MEDIUM'], total)
        except Exception as wh_err:
            _log.debug("Webhook notification skipped: %s", wh_err)

        # Auto-resolution des remediations : les CVE non detectees passent en 'resolved'
        try:
            found_cve_ids = {f['cve_id'] for f in findings}
            conn_rem = mysql.connector.connect(**Config.DB_CONFIG)
            cur_rem = conn_rem.cursor(dictionary=True)
            cur_rem.execute(
                "SELECT id, cve_id FROM cve_remediation WHERE machine_id = %s AND status IN ('open','in_progress')",
                (machine_id,)
            )
            open_remediations = cur_rem.fetchall()
            auto_resolved = 0
            for rem in open_remediations:
                if rem['cve_id'] not in found_cve_ids:
                    cur_rem.execute(
                        "UPDATE cve_remediation SET status = 'resolved', resolved_at = NOW(), "
                        "resolution_note = CONCAT(IFNULL(resolution_note,''), ' [Auto-resolved: non detectee au scan du ', DATE_FORMAT(NOW(), '%%d/%%m/%%Y'), ']') "
                        "WHERE id = %s",
                        (rem['id'],)
                    )
                    auto_resolved += 1
            if auto_resolved > 0:
                conn_rem.commit()
                _log.info("Auto-resolved %d CVE remediations for %s", auto_resolved, machine_name)
            conn_rem.close()
        except Exception as rem_err:
            _log.debug("CVE auto-resolution skipped: %s", rem_err)

        yield {
            'type':             'done',
            'machine_id':       machine_id,
            'scan_id':          scan_id,
            'total_findings':   len(findings),
            'packages_scanned': total,
            'packages_queried': queried,
            'packages_skipped': skipped,
            'vendor':           vendor,
        }

    except Exception as e:
        _log.error("scan_server (%s) : %s", machine_name, e, exc_info=True)
        yield {'type': 'error', 'machine_id': machine_id, 'message': str(e)}


# ────────────────────────────────────────────────────────────────────────────
# Persistance MySQL
# ────────────────────────────────────────────────────────────────────────────

def _save_scan(machine_id: int, findings: list[dict],
               packages_scanned: int, min_cvss: float) -> int:
    """
    Persiste un scan CVE et ses findings dans la base de données MySQL.

    Insère une ligne dans ``cve_scans`` (compteurs par sévérité, statut 'completed')
    puis insère tous les findings dans ``cve_findings`` via executemany.
    Les deux insertions sont commitées dans la même transaction.

    Args:
        machine_id       (int) : Identifiant de la machine scannée.
        findings         (list): Liste de dicts findings (package, version, cve_id,
                                 cvss, severity, summary).
        packages_scanned (int) : Nombre total de packages analysés.
        min_cvss         (float): Seuil CVSS utilisé lors du scan.

    Returns:
        scan_id (int): Identifiant auto-incrémenté du scan inséré.

    Raises:
        mysql.connector.Error: En cas d'erreur d'insertion ou de connexion.
    """
    counts = {s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
    for f in findings:
        sev = f.get('severity', 'NONE')
        if sev in counts:
            counts[sev] += 1

    conn = mysql.connector.connect(**Config.DB_CONFIG)
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO cve_scans
                (machine_id, packages_scanned, cve_count,
                 critical_count, high_count, medium_count, low_count,
                 min_cvss, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'completed')
        """, (machine_id, packages_scanned, len(findings),
              counts['CRITICAL'], counts['HIGH'], counts['MEDIUM'], counts['LOW'],
              min_cvss))
        scan_id = cur.lastrowid

        if findings:
            insert_sql = """
                INSERT INTO cve_findings
                    (scan_id, machine_id, package_name, package_version,
                     cve_id, cvss_score, severity, summary)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """
            for f in findings:
                cur.execute(insert_sql, (
                    scan_id, machine_id, f['package'], f['version'],
                    f['cve_id'], f['cvss'], f['severity'],
                    (f.get('summary') or '')[:300],
                ))
        conn.commit()
        _log.info("Scan saved: scan_id=%s, machine_id=%s, findings=%d",
                  scan_id, machine_id, len(findings))
        return scan_id
    except Exception as e:
        _log.error("_save_scan FAILED machine_id=%s: %s", machine_id, e,
                   exc_info=True)
        raise
    finally:
        conn.close()


def get_last_scan_results(machine_id: int) -> dict | None:
    """
    Récupère les résultats du dernier scan CVE complété pour un serveur.

    Sélectionne le scan le plus récent avec status='completed' et charge
    tous ses findings triés par sévérité décroissante puis score CVSS décroissant.

    Args:
        machine_id (int): Identifiant de la machine en base.

    Returns:
        dict avec les clés :
            - scan     (dict) : Ligne de la table cve_scans.
            - findings (list) : Lignes de cve_findings pour ce scan.
        ou None si aucun scan complété n'existe pour cette machine.
    """
    conn = mysql.connector.connect(**Config.DB_CONFIG)
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT * FROM cve_scans
            WHERE machine_id = %s AND status = 'completed'
            ORDER BY scan_date DESC LIMIT 1
        """, (machine_id,))
        scan = cur.fetchone()
        if not scan:
            return None

        # Convert datetime to ISO string for JSON serialization
        for key in ('scan_date',):
            if key in scan and hasattr(scan[key], 'isoformat'):
                scan[key] = scan[key].isoformat()

        cur.execute("""
            SELECT package_name, package_version, cve_id,
                   cvss_score, severity, summary
            FROM cve_findings
            WHERE scan_id = %s
            ORDER BY
                FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW','NONE'),
                cvss_score DESC
        """, (scan['id'],))
        findings = cur.fetchall()

        return {
            'scan':     scan,
            'findings': findings,
        }
    finally:
        conn.close()


def get_scan_history(machine_id: int, limit: int = 10) -> list[dict]:
    """
    Retourne l'historique des scans CVE pour un serveur, du plus récent au plus ancien.

    Seules les colonnes résumées sont retournées (pas les findings individuels).

    Args:
        machine_id (int): Identifiant de la machine en base.
        limit      (int): Nombre maximum de scans à retourner (défaut : 10).

    Returns:
        list[dict] : Liste de dicts avec les colonnes id, scan_date, packages_scanned,
                     cve_count, critical_count, high_count, medium_count, low_count,
                     min_cvss, status. Vide si aucun scan trouvé.
    """
    conn = mysql.connector.connect(**Config.DB_CONFIG)
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, scan_date, packages_scanned, cve_count,
                   critical_count, high_count, medium_count, low_count,
                   min_cvss, status
            FROM cve_scans
            WHERE machine_id = %s
            ORDER BY scan_date DESC
            LIMIT %s
        """, (machine_id, limit))
        return cur.fetchall()
    finally:
        conn.close()
