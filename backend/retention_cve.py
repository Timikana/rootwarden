#!/usr/bin/env python3
"""
retention_cve.py - Retention des scans CVE, et par cascade de leurs findings.

Un scan n'est purge que s'il est A LA FOIS hors des `CVE_SCAN_RETENTION` plus
recents de sa machine (plancher, defaut 10) ET plus vieux que
`CVE_SCAN_RETENTION_DAYS` (defaut 90 ; 0 = jamais purge). `cve_findings`
reference `cve_scans` en `ON DELETE CASCADE` : supprimer le scan supprime ses
findings.

══ CE QUI NE MARCHAIT PAS (2026-10-26) ═══════════════════════════════════════

La purge vivait dans `_purge_old_logs`, qui s'arrete des la premiere ligne
quand `LOG_RETENTION_DAYS` vaut 0 — sa valeur par defaut. La retention des
scans CVE, qui a pourtant ses deux reglages, ne tournait donc JAMAIS sur une
installation par defaut. Constat en production : 3,5 millions de findings,
1,7 Go, et c'est cette table qui faisait tuer la sauvegarde.

══ PAR LOTS, ET BORNEE DANS LE TEMPS ════════════════════════════════════════

La premiere execution sur une table de cette taille supprimerait des millions
de lignes. Une seule requete les verrouillerait pendant de longues minutes, a
une heure que personne n'a choisie. Le scheduler purge donc par lots de
quelques scans, une transaction par lot, au plus `budget_s` secondes par heure :
le rattrapage s'etale. Pour le faire d'un coup, hors heures :

    docker exec rootwarden_python python /app/retention_cve.py --compte
    docker exec rootwarden_python python /app/retention_cve.py --purger

L'espace disque n'est rendu par InnoDB qu'apres `OPTIMIZE TABLE cve_findings`
(reconstruction de la table) : a jouer hors heures, apres le rattrapage.

══ LE DETAIL, SEPARE DU SCAN (2026-11-24) ═══════════════════════════════════

La retention des scans garde tout ce qui a moins de 90 jours : en production,
1 384 scans pour 32 machines, et 3,46 millions de findings. Or rien ne relit le
detail d'un vieux scan — la page, l'export, la comparaison et la resolution
automatique ne lisent que les DERNIERS — alors que le diagramme « Tendances CVE
(30 jours) » lit les COMPTEURS de `cve_scans`.

`purge_detail` supprime donc les findings des scans hors des
`CVE_FINDINGS_RETENTION` plus recents de leur machine (defaut 10, au moins 2 :
la comparaison en lit deux ; 0 = desactivee) et GARDE la ligne du scan et ses
compteurs. Meme mecanique : par lots, dans le budget horaire.
"""

import logging
import os
import sys
import time

_log = logging.getLogger(__name__)

# Scans supprimes par transaction. Un scan porte de quelques dizaines a
# quelques milliers de findings : un lot reste une transaction courte.
LOT_PAR_DEFAUT = 20

# Le predicat est celui de la retention depuis v1.37.9 (diagramme « Tendances
# CVE (30 jours) ») : seule la mecanique change, pas ce qui est garde.
_SELECTION = """
    SELECT s.id FROM cve_scans s
    LEFT JOIN (
        SELECT id FROM (
            SELECT id, ROW_NUMBER() OVER (PARTITION BY machine_id ORDER BY scan_date DESC) as rn
            FROM cve_scans
        ) ranked WHERE rn <= %s
    ) keep ON s.id = keep.id
    WHERE keep.id IS NULL
      AND s.scan_date < DATE_SUB(NOW(), INTERVAL %s DAY)
"""


# Scans dont le detail est supprime par transaction : quelques milliers de
# findings chacun, un lot reste une transaction courte.
LOT_DETAIL_PAR_DEFAUT = 5

# Les scans TERMINES seulement, classes deux fois : par date (la comparaison
# lit les deux plus recents par date) et par identifiant (la page lit le
# MAX(id)). Un scan garde son detail s'il est dans les N de L'UN OU L'AUTRE :
# aucun des deux lecteurs ne peut tomber sur un scan vide.
_SELECTION_DETAIL = """
    SELECT r.id FROM (
        SELECT id,
               ROW_NUMBER() OVER (PARTITION BY machine_id ORDER BY scan_date DESC, id DESC) AS rn_date,
               ROW_NUMBER() OVER (PARTITION BY machine_id ORDER BY id DESC) AS rn_id
        FROM cve_scans
        WHERE status = 'completed'
    ) r
    WHERE r.rn_date > %s AND r.rn_id > %s
      AND EXISTS (SELECT 1 FROM cve_findings f WHERE f.scan_id = r.id)
"""


def parametre_detail():
    """Scans par machine dont le detail est garde ; 0 = retention desactivee."""
    n = int(os.environ.get('CVE_FINDINGS_RETENTION', '10'))
    return 0 if n <= 0 else max(2, n)


def parametres():
    """(plancher de scans par machine, fenetre en jours)."""
    return (int(os.environ.get('CVE_SCAN_RETENTION', '10')),
            int(os.environ.get('CVE_SCAN_RETENTION_DAYS', '90')))


def _premiere_colonne(ligne):
    return ligne['id'] if isinstance(ligne, dict) else ligne[0]


def scans_a_purger(cur, lot):
    """Les identifiants d'au plus `lot` scans a purger, les plus anciens d'abord."""
    plancher, jours = parametres()
    cur.execute(_SELECTION + " ORDER BY s.id LIMIT %s", (plancher, jours, lot))
    return [_premiere_colonne(r) for r in cur.fetchall()]


def compte(conn):
    """Ce que la retention supprimerait : (scans, findings). N'ecrit rien."""
    plancher, jours = parametres()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*), COALESCE(SUM((SELECT COUNT(*) FROM cve_findings f "
        "WHERE f.scan_id = v.id)), 0) FROM (" + _SELECTION + ") v",
        (plancher, jours))
    scans, findings = cur.fetchone()
    return int(scans), int(findings)


def purge(conn, budget_s=None, lot=LOT_PAR_DEFAUT):
    """Supprime les scans hors retention par lots ; rend un bilan.

    `budget_s` : duree au-dela de laquelle on s'arrete entre deux lots (None =
    jusqu'au bout). Le bilan dit si la purge est `complete`.
    """
    _, jours = parametres()
    bilan = {'scans': 0, 'findings': 0, 'lots': 0, 'complete': False,
             'desactivee': jours <= 0}
    if jours <= 0:
        return bilan
    t0 = time.monotonic()
    while True:
        cur = conn.cursor()
        ids = scans_a_purger(cur, lot)
        if not ids:
            bilan['complete'] = True
            break
        marques = ','.join(['%s'] * len(ids))
        # `marques` ne porte que des `%s` : les valeurs passent en parametres.
        cur.execute(f"SELECT COUNT(*) FROM cve_findings WHERE scan_id IN ({marques})", ids)
        bilan['findings'] += int(cur.fetchone()[0])
        cur.execute(f"DELETE FROM cve_scans WHERE id IN ({marques})", ids)
        conn.commit()
        bilan['scans'] += len(ids)
        bilan['lots'] += 1
        if budget_s is not None and time.monotonic() - t0 >= budget_s:
            break
    if bilan['scans']:
        _log.info("Retention CVE : %d scan(s), %d finding(s) supprime(s) en %d lot(s)%s",
                  bilan['scans'], bilan['findings'], bilan['lots'],
                  '' if bilan['complete'] else ' — reste a purger, reprise a l\'heure suivante')
    return bilan


def scans_a_vider(cur, lot):
    """Les identifiants d'au plus `lot` scans dont le detail est a supprimer."""
    n = parametre_detail()
    cur.execute(_SELECTION_DETAIL + " ORDER BY r.id LIMIT %s", (n, n, lot))
    return [_premiere_colonne(r) for r in cur.fetchall()]


def compte_detail(conn):
    """Ce que la retention du detail supprimerait : (scans, findings). N'ecrit rien."""
    n = parametre_detail()
    if n <= 0:
        return 0, 0
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*), COALESCE(SUM((SELECT COUNT(*) FROM cve_findings f "
        "WHERE f.scan_id = v.id)), 0) FROM (" + _SELECTION_DETAIL + ") v",
        (n, n))
    scans, findings = cur.fetchone()
    return int(scans), int(findings)


def purge_detail(conn, budget_s=None, lot=LOT_DETAIL_PAR_DEFAUT):
    """Supprime les findings des scans hors des N derniers, par lots ; garde les scans.

    Meme contrat que `purge` : `budget_s` arrete entre deux lots, le bilan dit
    si la purge est `complete`.
    """
    bilan = {'scans': 0, 'findings': 0, 'lots': 0, 'complete': False,
             'desactivee': parametre_detail() <= 0}
    if bilan['desactivee']:
        return bilan
    t0 = time.monotonic()
    while True:
        cur = conn.cursor()
        ids = scans_a_vider(cur, lot)
        if not ids:
            bilan['complete'] = True
            break
        marques = ','.join(['%s'] * len(ids))
        # `marques` ne porte que des `%s` : les valeurs passent en parametres.
        cur.execute(f"DELETE FROM cve_findings WHERE scan_id IN ({marques})", ids)
        bilan['findings'] += max(0, int(cur.rowcount or 0))
        conn.commit()
        bilan['scans'] += len(ids)
        bilan['lots'] += 1
        if budget_s is not None and time.monotonic() - t0 >= budget_s:
            break
    if bilan['scans']:
        _log.info("Retention du detail CVE : %d finding(s) de %d scan(s) supprime(s) en %d lot(s)%s",
                  bilan['findings'], bilan['scans'], bilan['lots'],
                  '' if bilan['complete'] else ' — reste a purger, reprise a l\'heure suivante')
    return bilan


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    import mysql.connector
    from config import Config

    connexion = mysql.connector.connect(**Config.DB_CONFIG)
    try:
        if '--purger' in sys.argv[1:]:
            debut = time.monotonic()
            b = purge(connexion)
            print(f"{b['scans']} scan(s), {b['findings']} finding(s) supprime(s) "
                  f"en {time.monotonic() - debut:.0f} s")
            debut = time.monotonic()
            d = purge_detail(connexion)
            print(f"Detail : {d['findings']} finding(s) de {d['scans']} scan(s) supprime(s), "
                  f"scans gardes, en {time.monotonic() - debut:.0f} s")
        else:
            s, f = compte(connexion)
            plancher, jours = parametres()
            print(f"Retention : plancher {plancher} scans/machine, fenetre {jours} jours"
                  f"{' (DESACTIVEE)' if jours <= 0 else ''}")
            print(f"A purger : {s} scan(s), {f} finding(s).")
            n = parametre_detail()
            ds, df = compte_detail(connexion)
            print(f"Detail garde pour les {n} derniers scans/machine"
                  f"{' (DESACTIVEE)' if n <= 0 else ''} : {df} finding(s) de {ds} scan(s) "
                  f"a supprimer, scans gardes.")
            print("Rien n'a ete supprime (--purger pour supprimer).")
    finally:
        connexion.close()
