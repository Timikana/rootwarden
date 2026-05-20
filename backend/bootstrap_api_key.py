"""
bootstrap_api_key.py - Auto-insertion legacy api_key au demarrage du backend.

Contexte :
    Depuis v1.21, le backend Python verifie X-API-KEY contre la table api_keys
    et non plus contre Config.API_KEY. Sur une prod fraichement migree, tant
    qu'aucune ligne active ne matche le SHA-256 de Config.API_KEY (env), toutes
    les routes retournent 401.

    Le hotfix v1.21.4 / v1.21.5 fait ce bootstrap dans maj.sh (etape 5c). Mais
    si maj.sh est skip (script pas a jour, container db down au moment du run,
    deploy custom qui n'appelle pas maj.sh), le probleme persiste.

    Ce module deplace le bootstrap DANS LE BACKEND : a chaque demarrage du
    container python, on verifie qu'une cle active matche Config.API_KEY ;
    sinon on INSERT la legacy. Idempotent, sur. Plus de dependance shell.

Securite :
    - Insertion auto uniquement si Config.API_KEY est set (sinon no-op).
    - auto_generated=1 pour tracabilite UI/audit.
    - Nom suffixe date UTC pour eviter collision avec une eventuelle ancienne
      legacy revoquee laissee en base pour audit.
    - Pas de UPDATE silencieux : on ne ressuscite jamais une cle revoquee.
    - Aucun secret n'est log (seulement le prefix et le hash 12 premiers chars).
"""

import hashlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger('rootwarden')


def bootstrap_legacy_api_key():
    """
    Verifie la table api_keys et insere la legacy si necessaire.

    Algo :
      1. Si Config.API_KEY vide -> rien a faire (no-op silencieux).
      2. SELECT COUNT(*) WHERE key_hash=sha256(API_KEY) AND revoked_at IS NULL.
         Si >= 1 : tout est OK, log INFO bref et exit.
      3. Sinon INSERT IGNORE 'proxy-internal-legacy-bootstrap-YYYYMMDD'
         avec hash, prefix derive, scope=NULL, auto_generated=1.
      4. Log WARNING explicite avec action recommandee.

    Best-effort : toute exception est logged en warning et ne bloque pas
    le boot du backend (le scheduler et les routes doivent demarrer meme
    si MySQL est temporairement indisponible).
    """
    try:
        from config import Config
        env_key = getattr(Config, 'API_KEY', '') or ''
        if not env_key:
            logger.info("bootstrap_legacy_api_key: Config.API_KEY vide, skip")
            return

        key_hash = hashlib.sha256(env_key.encode('utf-8')).hexdigest()
        prefix_seed = hashlib.sha256(b'proxy-internal-legacy').hexdigest()[:6]
        legacy_prefix = f"legacy_{prefix_seed}"
        bootstrap_date = datetime.now(timezone.utc).strftime('%Y%m%d')
        legacy_name = f"proxy-internal-legacy-bootstrap-{bootstrap_date}"

        from routes.helpers import get_db_connection
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM api_keys "
                "WHERE key_hash = %s AND revoked_at IS NULL",
                (key_hash,)
            )
            row = cur.fetchone()
            active_match = int(row[0]) if row else 0

            if active_match >= 1:
                logger.info(
                    "bootstrap_legacy_api_key: cle active deja en base "
                    "(hash=%s..., count=%d), rien a faire",
                    key_hash[:12], active_match
                )
                return

            cur.execute("SELECT COUNT(*) FROM api_keys")
            row = cur.fetchone()
            total = int(row[0]) if row else 0

            cur.execute(
                "INSERT IGNORE INTO api_keys "
                "(name, key_prefix, key_hash, scope_json, created_by, auto_generated) "
                "VALUES (%s, %s, %s, NULL, NULL, 1)",
                (legacy_name, legacy_prefix, key_hash)
            )
            inserted = cur.rowcount
            conn.commit()

            if inserted == 1:
                logger.warning(
                    "bootstrap_legacy_api_key: aucune cle active ne matchait "
                    "Config.API_KEY (%d ligne(s) en base) -> insere %s "
                    "(prefix=%s, scope=NULL, auto_generated=1). "
                    "Action recommandee : cree une cle scopee dans /adm/api_keys.php "
                    "puis revoque cette legacy.",
                    total, legacy_name, legacy_prefix
                )
            else:
                logger.info(
                    "bootstrap_legacy_api_key: INSERT IGNORE noop "
                    "(collision name unique sur %s, probablement re-run le meme jour)",
                    legacy_name
                )
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(
            "bootstrap_legacy_api_key: echec best-effort (%s) - "
            "le backend demarre quand meme",
            exc
        )
