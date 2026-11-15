"""
liste_blanche_cve.py - Les CVE qu'un administrateur a mises en liste blanche.

La table `cve_whitelist` etait ecrite (portail, POST /cve_whitelist) et lue par
PERSONNE : une CVE inscrite restait comptee, alertee, et pouvait ouvrir un
ticket automatique. Ce module est son seul lecteur cote scan.

Une entree vaut pour toutes les machines (`machine_id` NULL) ou pour une seule,
et cesse de valoir a sa date d'expiration (incluse).
"""

import logging

import mysql.connector

from config import Config

_log = logging.getLogger(__name__)


def cves_blanchies(machine_id: int) -> set[str]:
    """Identifiants des CVE actuellement blanchies pour cette machine.

    En cas d'erreur de lecture, rend un ensemble VIDE : une panne ne doit jamais
    faire taire une alerte. Le prix est une alerte en trop, jamais une en moins.
    """
    try:
        conn = mysql.connector.connect(**Config.DB_CONFIG)
    except Exception as e:
        _log.warning("Liste blanche CVE illisible (connexion) : %s", e)
        return set()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT cve_id FROM cve_whitelist "
            "WHERE (machine_id IS NULL OR machine_id = %s) "
            "AND (expires_at IS NULL OR expires_at >= CURDATE())",
            (int(machine_id),),
        )
        return {str(r[0]).strip().upper() for r in cur.fetchall() if r and r[0]}
    except Exception as e:
        _log.warning("Liste blanche CVE illisible : %s", e)
        return set()
    finally:
        conn.close()


def marque(findings: list[dict], blanchies: set[str]) -> int:
    """Pose `blanchie` sur chaque finding ; rend le nombre de findings blanchis."""
    n = 0
    for f in findings:
        f['blanchie'] = str(f.get('cve_id', '')).strip().upper() in blanchies
        n += 1 if f['blanchie'] else 0
    return n


def actifs(findings: list[dict]) -> list[dict]:
    """Les findings qui comptent : ceux qui ne sont pas en liste blanche."""
    return [f for f in findings if not f.get('blanchie')]
