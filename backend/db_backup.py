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
import gzip
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path

from config import Config

_log = logging.getLogger(__name__)

BACKUP_DIR = Path('/app/backups')

# Nom de backup valide : rootwarden_backup_YYYYMMDD_HHMMSS.sql.gz (anti path-traversal)
_BACKUP_NAME_RE = re.compile(r'^rootwarden_backup_\d{8}_\d{6}\.sql\.gz$')


def _safe_backup_path(filename):
    """Valide le nom (pas de traversal) et retourne le Path, ou leve ValueError."""
    name = os.path.basename(filename or '')
    if not _BACKUP_NAME_RE.match(name):
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


def _split_sql(text):
    """Decoupe un script SQL en statements en respectant les chaines simples
    quotees et l'echappement backslash (format produit par create_backup).
    Plus robuste qu'un split('; ') : un ';' dans une donnee ne casse rien."""
    stmts, buf, in_str, esc = [], [], False, False
    for ch in text:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == "'":
                in_str = False
        else:
            if ch == "'":
                in_str = True
                buf.append(ch)
            elif ch == ';':
                stmt = ''.join(buf).strip()
                if stmt:
                    stmts.append(stmt)
                buf = []
            else:
                buf.append(ch)
    tail = ''.join(buf).strip()
    if tail:
        stmts.append(tail)
    # Retire les lignes de commentaire pures
    out = []
    for s in stmts:
        lines = [ln for ln in s.splitlines() if not ln.strip().startswith('--')]
        cleaned = '\n'.join(lines).strip()
        if cleaned:
            out.append(cleaned)
    return out


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
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            content = f.read()
        stmts = _split_sql(content)
        result['statements'] = len(stmts)
        result['tables'] = sum(1 for s in stmts if s.upper().startswith('CREATE TABLE'))
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
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        content = f.read()
    stmts = _split_sql(content)

    conn = mysql.connector.connect(**Config.DB_CONFIG)
    applied = 0
    try:
        cur = conn.cursor()
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for s in stmts:
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


def create_backup() -> str:
    """Cree un backup mysqldump compresse. Retourne le chemin du fichier.

    Patch (bug/A08) : ecriture atomique via un fichier .tmp renomme seulement
    apres succes complet (avant, un dump tronque par une exception restait sur
    disque et etait considere comme un backup valide). Un sidecar .sha256 est
    ecrit pour permettre de verifier l'integrite avant restauration.
    Note A02 : le volume /app/backups doit etre chiffre au repos (le dump
    contient hashes/secrets chiffres) - cf. OPERATIONS.md."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

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
        cur = conn.cursor()

        with gzip.open(tmppath, 'wt', encoding='utf-8') as f:
            f.write(f"-- RootWarden backup {timestamp}\n")
            f.write(f"-- Database: {db['database']}\n\n")

            # Get all tables
            cur.execute("SHOW TABLES")
            tables = [row[0] for row in cur.fetchall()]

            for table in tables:
                # CREATE TABLE
                cur.execute(f"SHOW CREATE TABLE `{table}`")
                create_stmt = cur.fetchone()[1]
                f.write(f"\nDROP TABLE IF EXISTS `{table}`;\n")
                f.write(f"{create_stmt};\n\n")

                # INSERT rows
                cur.execute(f"SELECT * FROM `{table}`")
                rows = cur.fetchall()
                if rows:
                    cols = [desc[0] for desc in cur.description]
                    col_names = ', '.join(f'`{c}`' for c in cols)
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
        with open(str(filepath) + '.sha256', 'w', encoding='utf-8') as sf:
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

    # Purger aussi les .tmp orphelins (backups interrompus).
    for tmp in BACKUP_DIR.glob('rootwarden_backup_*.sql.gz.tmp'):
        try:
            tmp.unlink()
        except Exception:
            pass

    if deleted > 0:
        _log.info("Purge backups: %d fichier(s) supprime(s) (retention %d jours)", deleted, retention)


def run_backup():
    """Point d'entree pour le scheduler."""
    if os.environ.get('BACKUP_ENABLED', '').lower() != 'true':
        return
    try:
        create_backup()
        cleanup_old_backups()
    except Exception as e:
        _log.error("Backup echoue: %s", e)


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
    path = create_backup()
    print(f"Backup cree: {path}")
    cleanup_old_backups()
