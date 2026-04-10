#!/usr/bin/env python3
"""
db_backup.py — Sauvegarde automatique de la base de donnees MySQL.

Cree un dump mysqldump compresse (.sql.gz) dans /app/backups/ avec
rotation automatique (suppression des anciens fichiers selon BACKUP_RETENTION_DAYS).

Peut etre lance manuellement :
    python db_backup.py

Ou automatiquement via le scheduler (scheduler.py) si BACKUP_ENABLED=true.

Variables d'environnement :
    BACKUP_ENABLED        — true/false (defaut: false)
    BACKUP_RETENTION_DAYS — jours de conservation (defaut: 30)
    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME — credentials MySQL
"""

import os
import gzip
import logging
from datetime import datetime, timedelta
from pathlib import Path

from config import Config

_log = logging.getLogger(__name__)

BACKUP_DIR = Path('/app/backups')


def create_backup() -> str:
    """Cree un backup mysqldump compresse. Retourne le chemin du fichier."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"rootwarden_backup_{timestamp}.sql.gz"
    filepath = BACKUP_DIR / filename

    db = Config.DB_CONFIG

    _log.info("Backup MySQL en cours -> %s", filepath)

    try:
        import mysql.connector
        conn = mysql.connector.connect(**db)
        cur = conn.cursor()

        with gzip.open(filepath, 'wt', encoding='utf-8') as f:
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
        size_mb = filepath.stat().st_size / (1024 * 1024)
        _log.info("Backup cree: %s (%.1f MB)", filename, size_mb)
        return str(filepath)

    except Exception as e:
        _log.error("Backup echoue: %s", e)
        raise


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
                deleted += 1
                _log.debug("Backup supprime: %s", f.name)
        except Exception as e:
            _log.warning("Erreur suppression %s: %s", f.name, e)

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
