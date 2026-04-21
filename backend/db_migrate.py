#!/usr/bin/env python3
# db_migrate.py - Système de migration de base de données pour RootWarden
#
# Principe :
#   • Les fichiers de migration sont nommés NNN_description.sql
#     (ex: 001_initial_schema.sql, 002_cve_tables.sql)
#   • La table `schema_migrations` enregistre les versions appliquées
#   • Ce module est appelé au démarrage de Flask et applique
#     automatiquement les migrations en attente
#
# Usage manuel (CLI) :
#   python db_migrate.py                  → applique les migrations en attente
#   python db_migrate.py --status         → affiche l'état des migrations
#   python db_migrate.py --dry-run        → liste ce qui serait appliqué sans l'exécuter

import argparse
import logging
import re
import sys
from pathlib import Path

import mysql.connector
from mysql.connector import Error as MySQLError

from config import Config

_log = logging.getLogger(__name__)

# Répertoire contenant les fichiers .sql de migration (monté en volume Docker)
MIGRATIONS_DIR = Path('/app/migrations')

# Format attendu pour les noms de fichiers : NNN_description.sql
_MIGRATION_RE  = re.compile(r'^(\d{3})_[\w\-]+\.sql$')


# ──────────────────────────────────────────────────────────────────────────────
# Gestion de la connexion
# ──────────────────────────────────────────────────────────────────────────────

def _connect(retries: int = 5, delay: float = 3.0):
    """
    Établit une connexion MySQL avec mécanisme de retry pour les démarrages Docker.

    Au démarrage d'un stack Docker Compose, le conteneur MySQL peut ne pas être
    disponible immédiatement. Cette fonction tente la connexion jusqu'à ``retries``
    fois en attendant ``delay`` secondes entre chaque tentative.

    Args:
        retries (int)  : Nombre maximum de tentatives (défaut : 5).
        delay   (float): Délai fixe en secondes entre deux tentatives (défaut : 3.0).

    Returns:
        Connexion mysql.connector active.

    Raises:
        mysql.connector.Error: Si toutes les tentatives échouent.
    """
    import time
    for attempt in range(1, retries + 1):
        try:
            conn = mysql.connector.connect(**Config.DB_CONFIG)
            return conn
        except MySQLError as e:
            if attempt < retries:
                _log.warning(
                    "DB non disponible (tentative %d/%d) - nouvel essai dans %.0fs : %s",
                    attempt, retries, delay, e
                )
                time.sleep(delay)
            else:
                raise


# ──────────────────────────────────────────────────────────────────────────────
# Initialisation de la table de suivi
# ──────────────────────────────────────────────────────────────────────────────

_CREATE_TRACKING_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     VARCHAR(100) NOT NULL,
    filename    VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    applied_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    checksum    VARCHAR(64),
    PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""


def _ensure_tracking_table(conn) -> None:
    """
    Crée la table ``schema_migrations`` si elle n'existe pas encore.

    Cette table enregistre les migrations déjà appliquées (version, filename,
    description, timestamp, checksum SHA-256). L'instruction CREATE TABLE utilise
    IF NOT EXISTS pour être idempotente.

    Args:
        conn: Connexion MySQL active.
    """
    cur = conn.cursor()
    cur.execute(_CREATE_TRACKING_TABLE)
    conn.commit()
    cur.close()


# ──────────────────────────────────────────────────────────────────────────────
# Lecture des migrations disponibles
# ──────────────────────────────────────────────────────────────────────────────

def _load_migration_files() -> list[dict]:
    """
    Scanne MIGRATIONS_DIR et retourne la liste triée des migrations disponibles.
    Format retourné : [{'version': '001', 'filename': '001_...sql', 'path': Path, 'description': '...'}]
    """
    if not MIGRATIONS_DIR.exists():
        _log.error(
            "Répertoire de migrations introuvable : %s\n"
            "  → Vérifiez que le volume est monté dans docker-compose.yml :\n"
            "      - ./mysql/migrations:/app/migrations:ro",
            MIGRATIONS_DIR
        )
        return []

    migrations = []
    for path in sorted(MIGRATIONS_DIR.glob('*.sql')):
        m = _MIGRATION_RE.match(path.name)
        if not m:
            _log.debug("Fichier ignoré (nom invalide) : %s", path.name)
            continue
        version = m.group(1)
        # Extrait la description depuis le nom de fichier (ex: "cve_tables" → "Cve tables")
        desc_raw = path.stem[4:].replace('_', ' ')
        migrations.append({
            'version':     version,
            'filename':    path.name,
            'path':        path,
            'description': desc_raw.capitalize(),
        })
    return migrations


# ──────────────────────────────────────────────────────────────────────────────
# Lecture des migrations déjà appliquées
# ──────────────────────────────────────────────────────────────────────────────

def _heal_bogus_premarks(conn) -> int:
    """
    Self-heal : purge les lignes de `schema_migrations` pre-marquees par
    `mysql/init.sql` (checksum NULL) dont le fichier .sql existe sur disque.

    Contexte : historiquement `init.sql` inserait les versions 001..030 dans
    `schema_migrations` sans executer leur contenu. Si une migration n'etait
    pas folded dans init.sql (ex: 022 supervision, 027 notification_preferences),
    le runner la croyait appliquee et sautait son execution -> tables/colonnes
    manquantes en prod.

    Les migrations etant idempotentes (IF NOT EXISTS, conditional ALTER),
    supprimer les faux marquages force leur re-application sans risque.

    Returns:
        int : nombre de lignes purgees (0 si rien a faire).
    """
    cur = conn.cursor()
    cur.execute("SELECT version FROM schema_migrations WHERE checksum IS NULL")
    bogus = [r[0] for r in cur.fetchall()]
    if not bogus:
        cur.close()
        return 0

    files_on_disk = {m['version'] for m in _load_migration_files()}
    to_delete = [v for v in bogus if v in files_on_disk]
    if not to_delete:
        cur.close()
        return 0

    _log.warning(
        "Self-heal : %d migration(s) pre-marquee(s) sans checksum : %s. "
        "Purge pour re-application (idempotente).",
        len(to_delete), ', '.join(to_delete)
    )
    placeholders = ', '.join(['%s'] * len(to_delete))
    cur.execute(
        f"DELETE FROM schema_migrations WHERE version IN ({placeholders})",
        to_delete
    )
    conn.commit()
    cur.close()
    return len(to_delete)


def _get_applied_versions(conn) -> set[str]:
    """
    Récupère l'ensemble des versions de migrations déjà appliquées.

    Args:
        conn: Connexion MySQL active avec la table schema_migrations existante.

    Returns:
        set[str] : Ensemble des numéros de version appliqués (ex: {'001', '002'}).
    """
    cur = conn.cursor()
    cur.execute("SELECT version FROM schema_migrations ORDER BY version")
    applied = {row[0] for row in cur.fetchall()}
    cur.close()
    return applied


def get_migration_status(conn) -> list[dict]:
    """
    Retourne le statut détaillé de chaque migration disponible sur disque.

    Croise la liste des fichiers .sql présents dans MIGRATIONS_DIR avec les
    versions enregistrées en base pour indiquer si chaque migration est
    appliquée ou en attente.

    Args:
        conn: Connexion MySQL active avec la table schema_migrations existante.

    Returns:
        list[dict] : Un dict par migration avec les clés :
            - version     (str)      : Numéro de version (ex: '001').
            - filename    (str)      : Nom du fichier SQL.
            - description (str)      : Description lisible extraite du nom de fichier.
            - applied     (bool)     : True si la migration a été appliquée.
            - applied_at  (datetime) : Horodatage d'application, ou None si en attente.
    """
    applied_map = {}
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT version, applied_at FROM schema_migrations ORDER BY version")
    for row in cur.fetchall():
        applied_map[row['version']] = row['applied_at']
    cur.close()

    files = _load_migration_files()
    status = []
    for f in files:
        status.append({
            'version':     f['version'],
            'filename':    f['filename'],
            'description': f['description'],
            'applied':     f['version'] in applied_map,
            'applied_at':  applied_map.get(f['version']),
        })
    return status


# ──────────────────────────────────────────────────────────────────────────────
# Application d'une migration
# ──────────────────────────────────────────────────────────────────────────────

def _compute_checksum(sql: str) -> str:
    """
    Calcule une empreinte SHA-256 tronquée du contenu SQL d'une migration.

    Permet de détecter toute modification accidentelle d'un fichier de migration
    déjà appliqué (les 16 premiers caractères hex suffisent pour un identifiant).

    Args:
        sql (str): Contenu brut du fichier SQL.

    Returns:
        str : 16 premiers caractères hexadécimaux du hash SHA-256.
    """
    import hashlib
    return hashlib.sha256(sql.encode('utf-8')).hexdigest()[:16]


def _clean_sql(sql_raw: str) -> str:
    """
    Nettoie le SQL brut : retire les lignes de commentaires purs et les
    placeholder ``SELECT 1;`` en debut de fichier qui servaient de no-op.
    """
    lines = []
    for line in sql_raw.splitlines():
        stripped = line.strip()
        if stripped == 'SELECT 1;' or stripped == 'SELECT 1':
            continue
        lines.append(line)
    return '\n'.join(lines).strip()


def _execute_migration(conn, migration: dict, dry_run: bool = False) -> None:
    """
    Applique un fichier de migration via multi-statement natif de mysql-connector.
    En cas d'erreur, rollback et re-raise pour arreter le processus.
    """
    sql_raw = migration['path'].read_text(encoding='utf-8')
    checksum = _compute_checksum(sql_raw)

    _log.info("→ Applying %s : %s", migration['filename'], migration['description'])

    if dry_run:
        _log.info("  [DRY-RUN] %d caracteres SQL", len(sql_raw))
        return

    sql_clean = _clean_sql(sql_raw)
    if not sql_clean:
        _log.info("  (migration vide / placeholder)")
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO schema_migrations
               (version, filename, description, checksum)
               VALUES (%s, %s, %s, %s)""",
            (migration['version'], migration['filename'],
             migration['description'], checksum)
        )
        conn.commit()
        cur.close()
        return

    # Codes d'erreur MySQL tolerables dans les migrations (permet aux
    # migrations idempotentes d'ajouter des colonnes/index meme si l'admin
    # les a creees manuellement avant le run).
    # 1060 : Duplicate column name ; 1061 : Duplicate key name ;
    # 1091 : Can't drop ; 1826 : Duplicate foreign key.
    IDEMPOTENT_ERROR_CODES = {1060, 1061, 1091, 1826}

    cur = conn.cursor()
    try:
        # Split par ';' et execute chaque statement individuellement.
        # Apres chaque execute, on consomme les resultats pendants pour
        # eviter "Unread result found" qui causait les echecs silencieux.
        statements = [s.strip() for s in sql_clean.split(';') if s.strip()]
        stmt_count = 0
        tolerated = 0
        for stmt in statements:
            # Ignorer les commentaires purs
            lines = [l for l in stmt.splitlines() if not l.strip().startswith('--')]
            clean = '\n'.join(lines).strip()
            if not clean:
                continue
            try:
                cur.execute(clean)
            except mysql.connector.Error as e:
                if getattr(e, 'errno', None) in IDEMPOTENT_ERROR_CODES:
                    tolerated += 1
                    _log.debug("  (tolere %s : %s)", e.errno, str(e)[:100])
                    continue
                raise
            stmt_count += 1
            # Consommer les resultats (SELECT, EXECUTE, SHOW, etc.)
            # Sans cela, le prochain execute() echoue silencieusement.
            try:
                if cur.with_rows:
                    cur.fetchall()
            except Exception:
                pass
        if tolerated:
            _log.info("  %d statement(s) execute(s), %d tolere(s) idempotent(s)",
                      stmt_count, tolerated)
        else:
            _log.info("  %d statement(s) execute(s)", stmt_count)

        # Enregistre la migration comme appliquee. ON DUPLICATE KEY UPDATE
        # gere les migrations qui s'auto-inserent dans schema_migrations
        # (pattern legacy : 004, 005) et les pre-marques sans checksum.
        cur.execute(
            """INSERT INTO schema_migrations
               (version, filename, description, checksum)
               VALUES (%s, %s, %s, %s)
               ON DUPLICATE KEY UPDATE
                 checksum = VALUES(checksum),
                 applied_at = CURRENT_TIMESTAMP""",
            (migration['version'], migration['filename'],
             migration['description'], checksum)
        )
        conn.commit()
        _log.info("  ✓ Migration %s appliquee avec succes", migration['version'])

    except MySQLError as e:
        conn.rollback()
        _log.error(
            "  ✗ Echec de la migration %s : %s\n"
            "  → La migration a ete annulee (rollback). Corrigez le SQL et relancez.",
            migration['version'], e
        )
        raise
    finally:
        cur.close()


# ──────────────────────────────────────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────────────────────────────────────

def run_migrations(dry_run: bool = False, strict: bool = False) -> bool:
    """
    Applique toutes les migrations en attente.

    Args:
        dry_run : Si True, liste les migrations sans les appliquer.
        strict  : Si True, une migration échouée fait planter le serveur.

    Returns:
        True si toutes les migrations ont réussi (ou s'il n'y en avait pas).
        False en cas d'erreur (si strict=False).
    """
    _log.info("═══ Vérification des migrations de base de données ═══")

    try:
        conn = _connect()
    except MySQLError as e:
        _log.error("Impossible de se connecter à la base de données : %s", e)
        if strict:
            raise
        return False

    try:
        _ensure_tracking_table(conn)
        if not dry_run:
            _heal_bogus_premarks(conn)
        available = _load_migration_files()

        if not available:
            _log.warning(
                "Aucun fichier de migration trouvé dans %s", MIGRATIONS_DIR
            )
            return True

        applied   = _get_applied_versions(conn)
        pending   = [m for m in available if m['version'] not in applied]
        up_to_date = len(available) - len(pending)

        _log.info(
            "Migrations : %d disponible(s), %d déjà appliquée(s), %d en attente",
            len(available), up_to_date, len(pending)
        )

        if not pending:
            _log.info("✓ Base de données à jour - aucune migration à appliquer")
            return True

        for migration in pending:
            _execute_migration(conn, migration, dry_run=dry_run)

        if dry_run:
            _log.info("[DRY-RUN] %d migration(s) auraient été appliquées", len(pending))
        else:
            _log.info("✓ %d migration(s) appliquée(s) avec succès", len(pending))

        return True

    except Exception as e:
        _log.error("Erreur lors des migrations : %s", e)
        if strict:
            raise
        return False
    finally:
        conn.close()
    _log.info("═══════════════════════════════════════════════════════")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _cli_status():
    """
    Affiche un tableau de bord des migrations en mode CLI (option --status).

    Se connecte à la base de données, récupère le statut de chaque migration
    et affiche un tableau ASCII dans le terminal. Quitte avec le code 1 en cas
    d'erreur de connexion.
    """
    try:
        conn = _connect(retries=1)
        _ensure_tracking_table(conn)
        statuses = get_migration_status(conn)
        conn.close()
    except Exception as e:
        print(f"[ERREUR] Impossible de se connecter : {e}", file=sys.stderr)
        sys.exit(1)

    print("\n╔══════════════════════════════════════════════════════════╗")
    print(  "║              ROOTWARDEN - État des migrations             ║")
    print(  "╠═══════╦══════════════════════════════════╦═══════════════╣")
    print(  "║  Ver. ║ Description                      ║ Statut        ║")
    print(  "╠═══════╬══════════════════════════════════╬═══════════════╣")
    for s in statuses:
        status_str = f"✓ {s['applied_at'].strftime('%Y-%m-%d')}" if s['applied'] else "⏳ En attente"
        print(f"║  {s['version']}  ║ {s['description']:<32} ║ {status_str:<13} ║")
    print(  "╚═══════╩══════════════════════════════════╩═══════════════╝\n")

    pending = [s for s in statuses if not s['applied']]
    if pending:
        print(f"⚠️  {len(pending)} migration(s) en attente.")
        print("   Lancez : python db_migrate.py\n")
    else:
        print("✅  Base de données à jour.\n")


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler()],
    )

    parser = argparse.ArgumentParser(
        description='RootWarden - Gestionnaire de migrations de base de données'
    )
    parser.add_argument(
        '--status',   action='store_true',
        help='Affiche l\'état des migrations sans rien appliquer'
    )
    parser.add_argument(
        '--dry-run',  action='store_true',
        help='Simule l\'application des migrations sans les exécuter'
    )
    parser.add_argument(
        '--strict',   action='store_true',
        help='Arrête le processus (exit 1) en cas d\'erreur de migration'
    )
    args = parser.parse_args()

    if args.status:
        _cli_status()
        sys.exit(0)

    success = run_migrations(dry_run=args.dry_run, strict=args.strict)
    sys.exit(0 if success else 1)
