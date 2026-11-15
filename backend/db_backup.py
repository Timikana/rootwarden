#!/usr/bin/env python3
"""
db_backup.py - Sauvegarde automatique de la base de donnees MySQL.

Cree un dump mysqldump compresse (.sql.gz) dans /app/backups/ avec
rotation automatique (suppression des anciens fichiers selon BACKUP_RETENTION_DAYS).

Peut etre lance manuellement :
    python db_backup.py

Ou automatiquement via le scheduler (scheduler.py) si BACKUP_ENABLED=true.

Variables d'environnement :
    BACKUP_ENABLED        - true/false (defaut: false)
    BACKUP_RETENTION_DAYS - jours de conservation (defaut: 30)
    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME - credentials MySQL
"""

import os
import re
import sys
import gzip
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path

from config import Config

_log = logging.getLogger(__name__)

BACKUP_DIR = Path('/app/backups')

# Lignes lues a la fois par `create_backup` : la memoire ne depend plus de la
# taille des tables.
_LIGNES_PAR_PAQUET = 500

# Nom de backup valide : rootwarden_backup_YYYYMMDD_HHMMSS.sql.gz (anti path-traversal)
_BACKUP_NAME_RE = re.compile(r'^rootwarden_backup_\d{8}_\d{6}\.sql\.gz$')


def _safe_backup_path(filename):
    """Valide le nom (pas de traversal) et retourne le Path, ou leve ValueError."""
    name = os.path.basename(filename or '')
    if not _BACKUP_NAME_RE.fullmatch(name):
        raise ValueError("Nom de backup invalide")
    path = BACKUP_DIR / name
    if not path.exists():
        raise ValueError("Backup introuvable")
    return path


def _sha256_file(path):
    sha = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            sha.update(chunk)
    return sha.hexdigest()


# Caracteres qui changent l'etat du decoupage ; tous les autres sont recopies.
_SPECIAUX_SQL = re.compile(r"[';\\]")


def _nettoie_statement(brut):
    """Retire les lignes de commentaire pures ; rend None si rien ne reste."""
    stmt = brut.strip()
    if not stmt:
        return None
    lines = [ln for ln in stmt.splitlines() if not ln.strip().startswith('--')]
    return '\n'.join(lines).strip() or None


def _iter_sql(morceaux):
    """Decoupe un script SQL en statements, MORCEAU PAR MORCEAU.

    Memes regles que le decoupage d'avant (chaines simples quotees, echappement
    backslash, lignes `--` retirees), mais sans jamais tenir le script entier :
    `verify_backup` et `restore_backup` lisaient tout le dump decompresse puis
    construisaient la liste de TOUS ses statements. Une base dont la sauvegarde
    tient en memoire bornee doit aussi pouvoir se relire en memoire bornee.
    Un echappement coupe entre deux morceaux est reporte au suivant.
    """
    buf, in_str, report = [], False, False
    for texte in morceaux:
        if not texte:
            continue
        echappe = 0 if report else -1   # index du caractere echappe
        report = False
        debut = 0
        for m in _SPECIAUX_SQL.finditer(texte):
            i, ch = m.start(), m.group()
            if in_str:
                if i == echappe:
                    continue
                if ch == '\\':
                    if i + 1 < len(texte):
                        echappe = i + 1
                    else:
                        report = True
                elif ch == "'":
                    in_str = False
            elif ch == "'":
                in_str = True
            elif ch == ';':
                buf.append(texte[debut:i])
                stmt = _nettoie_statement(''.join(buf))
                buf, debut = [], i + 1
                if stmt:
                    yield stmt
        buf.append(texte[debut:])
    stmt = _nettoie_statement(''.join(buf))
    if stmt:
        yield stmt


def _split_sql(text):
    """Decoupe un script SQL complet en liste de statements (voir `_iter_sql`)."""
    return list(_iter_sql([text]))


def _lit_par_morceaux(path, taille=1 << 20):
    """Le dump decompresse, par morceaux de texte d'environ 1 Mo."""
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        for morceau in iter(lambda: f.read(taille), ''):
            yield morceau


def verify_backup(filename):
    """'Test de restauration' non destructif : verifie l'integrite (sha256) et
    la lisibilite du dump, compte les tables/statements. N'applique rien.

    Retourne {valid, sha_ok, has_sidecar, tables, statements, error}."""
    path = _safe_backup_path(filename)
    result = {'valid': False, 'sha_ok': None, 'has_sidecar': False,
              'tables': 0, 'statements': 0, 'error': None}
    sidecar = Path(str(path) + '.sha256')
    if sidecar.exists():
        result['has_sidecar'] = True
        try:
            expected = sidecar.read_text(encoding='utf-8').strip().split()[0]
            result['sha_ok'] = (expected == _sha256_file(path))
        except Exception:
            result['sha_ok'] = False
    if result['sha_ok'] is False:
        result['error'] = 'sha256 ne correspond pas (backup corrompu)'
        return result
    try:
        for stmt in _iter_sql(_lit_par_morceaux(path)):
            result['statements'] += 1
            if stmt.upper().startswith('CREATE TABLE'):
                result['tables'] += 1
        result['valid'] = result['tables'] > 0
        if not result['valid']:
            result['error'] = 'aucune table trouvee dans le dump'
    except Exception as e:
        result['error'] = f'lecture impossible : {e}'
    return result


def restore_backup(filename):
    """Restaure la base depuis un backup. DESTRUCTIF (DROP TABLE).

    Securite :
      - nom valide (anti path-traversal), sha256 verifie avant application ;
      - un backup de securite PRE-restauration est cree automatiquement ;
      - FOREIGN_KEY_CHECKS desactive pendant l'application puis reactive.

    Retourne {success, statements, safety_backup, error}."""
    path = _safe_backup_path(filename)

    # Verification d'integrite obligatoire avant toute application
    chk = verify_backup(filename)
    if not chk['valid'] or chk.get('sha_ok') is False:
        return {'success': False, 'error': chk.get('error') or 'backup invalide',
                'statements': 0, 'safety_backup': None}

    # Backup de securite avant ecrasement (best-effort mais loggue)
    safety = None
    try:
        safety = os.path.basename(create_backup())
        _log.info("Backup de securite pre-restauration cree: %s", safety)
    except Exception as e:
        _log.warning("Backup de securite pre-restauration echoue: %s", e)

    import mysql.connector

    conn = mysql.connector.connect(**Config.DB_CONFIG)
    applied = 0
    try:
        cur = conn.cursor()
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for s in _iter_sql(_lit_par_morceaux(path)):
            cur.execute(s)
            # Consommer d'eventuels resultats (DDL n'en a pas, mais par securite)
            try:
                cur.fetchall()
            except Exception:
                pass
            applied += 1
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
        conn.commit()
        _log.info("Restauration terminee depuis %s : %d statement(s)", filename, applied)
        return {'success': True, 'statements': applied, 'safety_backup': safety, 'error': None}
    except Exception as e:
        conn.rollback()
        _log.error("Restauration echouee (%s) apres %d statement(s): %s", filename, applied, e)
        return {'success': False, 'statements': applied, 'safety_backup': safety,
                'error': str(e)[:300]}
    finally:
        conn.close()


def _ferme_les_droits():
    """Dossier 0700, sauvegardes 0600 — y compris celles d'avant ce correctif.

    Audit du 2026-10-13, M-3 : un dump porte les empreintes des mots de passe,
    les mots de passe root des machines et les secrets TOTP. Mesure sur le poste
    de dev : 0644 dans un dossier 0755, lisibles par TOUS les comptes de l'hote.
    `mkdir(exist_ok=True)` ne corrige pas un dossier existant : on le resserre a
    chaque passage, et les dumps deja presents avec lui.
    """
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    for f in BACKUP_DIR.glob('rootwarden_backup_*'):
        try:
            if f.is_file() and not f.is_symlink():
                os.chmod(f, 0o600)
        except OSError as e:
            _log.warning("Droits de %s non resserres : %s", f.name, e)


def _ouvre_prive(chemin, mode_texte):
    """Ouvre en ecriture un fichier CREE en 0600 — jamais lisible, meme un instant.

    `os.open` avec un mode plutot qu'un `umask` : le processus est multi-thread,
    et l'umask est global au processus.
    """
    fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)   # si le fichier existait deja avec d'autres droits
    return os.fdopen(fd, mode_texte)


def create_backup() -> str:
    """Cree un backup mysqldump compresse. Retourne le chemin du fichier.

    Patch (bug/A08) : ecriture atomique via un fichier .tmp renomme seulement
    apres succes complet (avant, un dump tronque par une exception restait sur
    disque et etait considere comme un backup valide). Un sidecar .sha256 est
    ecrit pour permettre de verifier l'integrite avant restauration.
    Note A02 : le volume /app/backups doit etre chiffre au repos (le dump
    contient hashes/secrets chiffres) - cf. OPERATIONS.md."""
    _ferme_les_droits()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"rootwarden_backup_{timestamp}.sql.gz"
    filepath = BACKUP_DIR / filename
    tmppath = BACKUP_DIR / (filename + '.tmp')

    db = Config.DB_CONFIG

    _log.info("Backup MySQL en cours -> %s", filepath)

    conn = None
    try:
        import mysql.connector
        conn = mysql.connector.connect(**db)
        # Une vue COHERENTE de toute la base, comme `mysqldump --single-transaction` :
        # sans elle, une table lue a 00:01 et une autre a 00:04 peuvent se
        # contredire (un scan et ses findings ecrits entre les deux).
        conn.start_transaction(consistent_snapshot=True, readonly=True)
        cur = conn.cursor()

        with _ouvre_prive(tmppath, 'wb') as brut, \
                gzip.open(brut, 'wt', encoding='utf-8') as f:
            f.write(f"-- RootWarden backup {timestamp}\n")
            f.write(f"-- Database: {db['database']}\n\n")

            # Get all tables
            cur.execute("SHOW TABLES")
            tables = [row[0] for row in cur.fetchall()]

            for table in tables:
                # CREATE TABLE
                # `table` ne vient pas d'une entree : il vient de `SHOW TABLES` ci-dessus,
                # donc du CATALOGUE de la base. Un placeholder %s ne peut PAS porter un nom
                # de table ; la garde est ici que la liste est RENDUE DEPUIS SA SOURCE.
                # Injecter exigerait de pouvoir CREER une table au nom choisi — soit un
                # privilege DDL, soit une compromission deja totale.
                # nosemgrep: rw-sql-fstring-execute
                cur.execute(f"SHOW CREATE TABLE `{table}`")
                create_stmt = cur.fetchone()[1]
                f.write(f"\nDROP TABLE IF EXISTS `{table}`;\n")
                f.write(f"{create_stmt};\n\n")

                # INSERT rows
                # Meme `table`, meme raison qu'au SHOW CREATE ci-dessus.
                #
                # PAR PAQUETS, JAMAIS `fetchall()` (2026-10-26). La table entiere
                # etait chargee en memoire avant d'etre ecrite : le pic du
                # processus suivait la taille de la PLUS GROSSE table. Mesure sur
                # MySQL isole, lignes de 1 Ko : 50 000 lignes -> 85 Mo,
                # 200 000 -> 251 Mo. Dans un conteneur limite en memoire, une
                # base assez grosse fait tuer le backend par le noyau (OOM).
                # Par paquets : 31 Mo pour 50 000 lignes comme pour 800 000 (meme banc).
                # nosemgrep: rw-sql-fstring-execute
                cur.execute(f"SELECT * FROM `{table}`")
                cols = [desc[0] for desc in cur.description]
                col_names = ', '.join(f'`{c}`' for c in cols)
                while True:
                    rows = cur.fetchmany(_LIGNES_PAR_PAQUET)
                    if not rows:
                        break
                    for row in rows:
                        vals = []
                        for v in row:
                            if v is None:
                                vals.append('NULL')
                            elif isinstance(v, (int, float)):
                                vals.append(str(v))
                            elif isinstance(v, bytes):
                                vals.append(f"X'{v.hex()}'")
                            else:
                                escaped = str(v).replace("\\", "\\\\").replace("'", "\\'")
                                vals.append(f"'{escaped}'")
                        f.write(f"INSERT INTO `{table}` ({col_names}) VALUES ({', '.join(vals)});\n")

            f.write(f"\n-- End of backup {timestamp}\n")

        conn.close()
        conn = None

        # Rename atomique : le backup n'existe sous son nom final que s'il est
        # complet. Puis sidecar .sha256 pour verification d'integrite.
        os.replace(tmppath, filepath)
        sha = hashlib.sha256()
        with open(filepath, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                sha.update(chunk)
        with _ouvre_prive(str(filepath) + '.sha256', 'w') as sf:
            sf.write(f"{sha.hexdigest()}  {filename}\n")

        size_mb = filepath.stat().st_size / (1024 * 1024)
        _log.info("Backup cree: %s (%.1f MB, sha256 %s...)", filename, size_mb, sha.hexdigest()[:12])
        return str(filepath)

    except Exception as e:
        _log.error("Backup echoue: %s", e)
        # Nettoyer le .tmp partiel pour ne pas laisser de fichier corrompu.
        try:
            if tmppath.exists():
                tmppath.unlink()
        except Exception:
            pass
        raise
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def cleanup_old_backups():
    """Supprime les backups plus anciens que BACKUP_RETENTION_DAYS."""
    retention = int(os.environ.get('BACKUP_RETENTION_DAYS', '30'))
    if retention <= 0:
        return

    cutoff = datetime.now() - timedelta(days=retention)
    deleted = 0

    for f in BACKUP_DIR.glob('rootwarden_backup_*.sql.gz'):
        try:
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            if mtime < cutoff:
                f.unlink()
                # Supprimer le sidecar .sha256 associe s'il existe.
                sidecar = Path(str(f) + '.sha256')
                if sidecar.exists():
                    sidecar.unlink()
                deleted += 1
                _log.debug("Backup supprime: %s", f.name)
        except Exception as e:
            _log.warning("Erreur suppression %s: %s", f.name, e)

    nettoie_tmp_orphelins()

    if deleted > 0:
        _log.info("Purge backups: %d fichier(s) supprime(s) (retention %d jours)", deleted, retention)


# ══ L'ETAT DE LA SAUVEGARDE AUTOMATIQUE ═══════════════════════════════════
#
# 2026-10-26, constat en production : la sauvegarde etait tuee par le noyau
# (memoire) a chaque tentative, toutes les heures, depuis deux mois et demi.
# AUCUNE trace : un processus tue n'ecrit pas « Backup echoue », et le seul
# reste etait un `.tmp` vide — 1 686 au total. Le dernier dump valide datait
# d'aout ; rien ne le signalait.
#
# Ce fichier est ecrit AVANT le dump. S'il dit encore « en_cours » au demarrage
# suivant, la sauvegarde a ete interrompue : c'est le redemarrage qui la
# declare en echec, puisque le processus tue ne le pourra jamais.
_NOM_ETAT = '.etat-sauvegarde.json'

# Un `.tmp` que personne n'a ecrit depuis une heure est orphelin. Un dump EN
# COURS (une sauvegarde manuelle dans un autre worker) l'ecrit sans cesse.
_TMP_ORPHELIN_APRES_S = 3600

# Au-dela, une sauvegarde quotidienne est en retard.
_RETARD_HEURES = 26


def _active() -> bool:
    return os.environ.get('BACKUP_ENABLED', '').lower() == 'true'


def _lit_etat() -> dict:
    try:
        with open(BACKUP_DIR / _NOM_ETAT, encoding='utf-8') as f:
            etat = json.load(f)
        return etat if isinstance(etat, dict) else {}
    except (OSError, ValueError):
        return {}


def _ecrit_etat(etat: dict) -> None:
    """Ecriture atomique : un etat a moitie ecrit vaudrait un etat perdu."""
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    provisoire = BACKUP_DIR / (_NOM_ETAT + '.ecriture')
    with _ouvre_prive(provisoire, 'w') as f:
        json.dump(etat, f, ensure_ascii=False)
    os.replace(provisoire, BACKUP_DIR / _NOM_ETAT)


def sauvegarde_due(maintenant=None) -> bool:
    """Une sauvegarde automatique est-elle due aujourd'hui ?

    Le scheduler appelle `run_backup()` UNE FOIS PAR HEURE, et la sauvegarde
    tournait a chaque appel — alors que `BACKUP_ENABLED` est documente comme un
    « backup quotidien » (srv-docker.env.example). Desormais :
      - une sauvegarde du jour (automatique ou manuelle) suffit ;
      - UNE tentative automatique par jour, REUSSIE OU NON. Une tentative qui a
        echoue — ou qui a ete tuee — n'est pas relancee avant le lendemain : la
        relancer a l'heure suivante reproduirait l'echec, en boucle, comme en
        production. L'echec reste visible (`etat_sauvegarde`).
    """
    if not _active():
        return False
    jour = (maintenant or datetime.now()).strftime('%Y%m%d')
    # `*.sql.gz` exclut les `.tmp` (sauvegarde interrompue) et les `.sha256`.
    if any(BACKUP_DIR.glob(f'rootwarden_backup_{jour}_*.sql.gz')):
        return False
    tentee = str(_lit_etat().get('debut', ''))[:10].replace('-', '')
    return tentee != jour


def run_backup():
    """Point d'entree pour le scheduler : au plus une tentative par jour."""
    if not sauvegarde_due():
        return
    debut = datetime.now().isoformat(timespec='seconds')
    _ecrit_etat({'statut': 'en_cours', 'debut': debut})
    try:
        chemin = create_backup()
    except Exception as e:
        # `create_backup` a deja journalise « Backup echoue » et retire son .tmp.
        _ecrit_etat({'statut': 'echec', 'debut': debut,
                     'fin': datetime.now().isoformat(timespec='seconds'),
                     'cause': str(e)[:300]})
        return
    _ecrit_etat({'statut': 'ok', 'debut': debut,
                 'fin': datetime.now().isoformat(timespec='seconds'),
                 'fichier': os.path.basename(chemin)})
    try:
        cleanup_old_backups()
    except Exception as e:
        _log.warning("Rotation des sauvegardes echouee : %s", e)


def signale_sauvegarde_interrompue() -> bool:
    """Au demarrage du scheduler : une tentative restee « en_cours » a ete tuee.

    Rend True si elle a ete declaree en echec (et journalisee comme telle).
    """
    etat = _lit_etat()
    if etat.get('statut') != 'en_cours':
        return False
    cause = ("interrompue : le processus s'est arrete pendant la sauvegarde "
             "(memoire insuffisante ou redemarrage)")
    _ecrit_etat({**etat, 'statut': 'echec', 'cause': cause})
    _log.error("Backup echoue: sauvegarde automatique commencee le %s %s",
               etat.get('debut', '?'), cause)
    return True


def nettoie_tmp_orphelins(maintenant=None) -> int:
    """Supprime les `.tmp` que personne n'ecrit plus ; rend leur nombre."""
    limite = (maintenant or time.time()) - _TMP_ORPHELIN_APRES_S
    retires = 0
    for tmp in BACKUP_DIR.glob('rootwarden_backup_*.sql.gz.tmp'):
        try:
            if tmp.stat().st_mtime < limite:
                tmp.unlink()
                retires += 1
        except OSError:
            pass
    if retires:
        _log.warning("Sauvegardes : %d fichier(s) .tmp orphelin(s) supprime(s) "
                     "(sauvegardes interrompues)", retires)
    return retires


def _plus_recente(tentative, derniere_mtime) -> bool:
    """La tentative a-t-elle commence apres la derniere sauvegarde reussie ?"""
    if derniere_mtime is None:
        return True
    try:
        return datetime.fromisoformat(str(tentative.get('debut'))).timestamp() > derniere_mtime
    except ValueError:
        return True


def etat_sauvegarde(maintenant=None) -> dict:
    """L'etat de la sauvegarde automatique, pour la supervision.

    `niveau` : `desactivee`, `ok`, `en_cours`, `echec` (la derniere tentative a
    echoue), `en_retard` (aucune sauvegarde depuis plus de 26 h).
    """
    maintenant = maintenant or datetime.now()
    reussies = list(BACKUP_DIR.glob('rootwarden_backup_*.sql.gz')) if BACKUP_DIR.exists() else []
    derniere = max((f.stat().st_mtime for f in reussies), default=None)
    age_h = None if derniere is None else round(
        (maintenant.timestamp() - derniere) / 3600, 1)
    tentative = _lit_etat()
    orphelins = sum(1 for _ in BACKUP_DIR.glob('rootwarden_backup_*.sql.gz.tmp')) \
        if BACKUP_DIR.exists() else 0

    if not _active():
        niveau = 'desactivee'
    elif tentative.get('statut') == 'en_cours':
        niveau = 'en_cours'
    elif tentative.get('statut') == 'echec' and _plus_recente(tentative, derniere):
        # Un echec suivi d'une sauvegarde reussie (manuelle) n'est plus l'etat.
        niveau = 'echec'
    elif age_h is None or age_h > _RETARD_HEURES:
        niveau = 'en_retard'
    else:
        niveau = 'ok'

    return {
        'niveau': niveau,
        'active': _active(),
        'derniere_reussie': None if derniere is None
        else datetime.fromtimestamp(derniere).isoformat(timespec='seconds'),
        'age_heures': age_h,
        'derniere_tentative': tentative or None,
        'tmp_orphelins': orphelins,
    }


def list_backups() -> list:
    """Liste les backups existants (pour l'API)."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backups = []
    for f in sorted(BACKUP_DIR.glob('rootwarden_backup_*.sql.gz'), reverse=True):
        stat = f.stat()
        backups.append({
            'filename': f.name,
            'size_mb': round(stat.st_size / (1024 * 1024), 2),
            'created_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        })
    return backups


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    if '--etat' in sys.argv[1:]:
        # Pour une supervision sur l'hote :
        #   docker exec rootwarden_python python /app/db_backup.py --etat
        # Sortie 1 si la derniere tentative a echoue ou si la sauvegarde est en retard.
        etat = etat_sauvegarde()
        print(json.dumps(etat, ensure_ascii=False, indent=2))
        sys.exit(1 if etat['niveau'] in ('echec', 'en_retard') else 0)
    path = create_backup()
    print(f"Backup cree: {path}")
    cleanup_old_backups()
