# config/config.py
"""
config.py - Configuration centralisée du projet RootWarden (Gestion_SSH_KEY).

Rôle :
    Charge et valide toutes les variables d'environnement au démarrage.
    Regroupe les paramètres sous la classe ``Config`` pour un accès global unifié.

Variables obligatoires (le backend s'arrête avec sys.exit(1) si elles sont absentes) :
    SECRET_KEY      - Clé AES-256 principale pour le chiffrement des mots de passe (hex 64 chars).
    API_KEY         - Clé d'authentification X-API-KEY requise sur toutes les routes sensibles.

Variables optionnelles notables :
    OLD_SECRET_KEY  - Ancienne clé AES pour migration transparente des mots de passe.
    OPENCVE_*       - Paramètres de connexion à l'instance OpenCVE (vide = fonctionnalité désactivée).
    MAIL_*          - Configuration SMTP pour l'envoi de rapports CVE par e-mail.
    DEBUG_MODE      - Active le mode debug Flask (NE JAMAIS utiliser en production).

Sécurité :
    Les clés de chiffrement ne doivent jamais être loguées ni exposées dans les réponses API.
    Utiliser srv-docker.env (exclu du dépôt git) pour les valeurs sensibles.

Dépendances : os, sys (stdlib uniquement - pas de dépendances tierces).
"""

import os
import sys

def _require_env(name: str) -> str:
    """
    Lit une variable d'environnement obligatoire.

    Si la variable est absente ou vide, affiche un message d'erreur explicite sur stderr
    et termine le processus avec ``sys.exit(1)`` pour bloquer tout démarrage insécurisé.

    Args:
        name (str): Nom de la variable d'environnement à lire.

    Returns:
        str: Valeur de la variable d'environnement.

    Raises:
        SystemExit: Si la variable est absente ou vide.
    """
    value = os.getenv(name)
    if not value:
        print(f"[ERREUR CRITIQUE] La variable d'environnement '{name}' est obligatoire. "
              f"Copiez srv-docker.env.example en srv-docker.env et renseignez vos valeurs.",
              file=sys.stderr)
        sys.exit(1)
    return value

class Config:
    """
    Classe de configuration globale du backend RootWarden.

    Tous les attributs sont des valeurs de classe (pas d'instance) : ils sont évalués
    une seule fois au chargement du module, avant le démarrage du serveur Flask.

    Attributs principaux :
        SECRET_KEY (str)      : Clé AES-256 principale (hex 64 chars ou brut 32 chars).
        OLD_SECRET_KEY (str)  : Ancienne clé pour migration transparente (optionnel).
        ENCRYPTION_KEY (str)  : Clé secondaire utilisée côté PHP.
        API_KEY (str)         : Clé HTTP X-API-KEY protégeant les routes sensibles.
        DB_CONFIG (dict)      : Paramètres de connexion MySQL (host, user, password, database, port).
        SSH_TIMEOUT (int)     : Timeout SSH en secondes (défaut : 360).
        DEBUG (bool)          : Mode debug Flask - false en production.
        LOG_LEVEL (str)       : Niveau de log Python (DEBUG, INFO, WARNING…).
        OPENCVE_URL (str)     : URL de l'instance OpenCVE.
        OPENCVE_USERNAME (str): Identifiant OpenCVE.
        OPENCVE_PASSWORD (str): Mot de passe OpenCVE.
        CVE_CACHE_TTL (int)   : Durée de mise en cache des résultats CVE en secondes.
        CVE_MIN_CVSS (float)  : Score CVSS minimum pour remonter une CVE (défaut : 7.0).
        MAIL_ENABLED (bool)   : Active l'envoi de rapports CVE par e-mail.
        MAIL_FROM (str)       : Adresse expéditeur des e-mails.
        MAIL_TO (str)         : Destinataires (séparés par des virgules).
        MAIL_SMTP_* (str/int) : Paramètres SMTP (host, port, user, password, TLS).
    """
    # Clés de chiffrement AES-256 - obligatoires, sans valeur par défaut
    SECRET_KEY     = _require_env('SECRET_KEY')
    OLD_SECRET_KEY = os.getenv('OLD_SECRET_KEY', '')  # Optionnel : ancienne clé pour migration
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', '')  # Optionnel : clé secondaire PHP (non utilisée par le backend Python)

    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'localhost')

    # Database Configuration
    DB_CONFIG = {
        'user':     os.getenv('DB_USER', 'rootwarden_user'),
        'password': os.getenv('DB_PASSWORD', 'rootwarden_password'),
        'host':     os.getenv('DB_HOST', 'db'),
        'database': os.getenv('DB_NAME', 'rootwarden'),
        'port':     int(os.getenv('DB_PORT', 3306)),
    }

    # SSH Configuration
    SSH_TIMEOUT = int(os.getenv('SSH_TIMEOUT', 360))

    # ── Mode Debug ──────────────────────────────────────────────────────────
    # DEBUG_MODE=true active :
    #   • Logging niveau DEBUG (très verbeux : requêtes SSH, déchiffrement, etc.)
    #   • Flask en mode debug (rechargement automatique, stack traces)
    #   • Réponses d'erreur détaillées dans l'API
    # ⚠️  NE JAMAIS activer en production : expose des informations sensibles.
    DEBUG         = os.getenv('DEBUG_MODE', 'false').lower() == 'true'
    LOG_LEVEL     = os.getenv('LOG_LEVEL', 'DEBUG' if DEBUG else 'INFO').upper()

    # Clé d'API pour authentifier les requêtes du frontend - obligatoire
    API_KEY = _require_env('API_KEY')

    # ── OpenCVE ─────────────────────────────────────────────────────────────
    # Supporte opencve.io (cloud) et les instances on-prem.
    # Laisser vide pour désactiver la fonctionnalité CVE.
    OPENCVE_URL      = os.getenv('OPENCVE_URL', 'https://app.opencve.io')
    OPENCVE_USERNAME = os.getenv('OPENCVE_USERNAME', '')
    OPENCVE_PASSWORD = os.getenv('OPENCVE_PASSWORD', '')
    OPENCVE_TOKEN    = os.getenv('OPENCVE_TOKEN', '')  # Bearer token pour OpenCVE v2 on-prem
    CVE_CACHE_TTL    = int(os.getenv('CVE_CACHE_TTL', '3600'))   # secondes
    CVE_MIN_CVSS     = float(os.getenv('CVE_MIN_CVSS', '7.0'))   # seuil par défaut

    # ── Notifications email ──────────────────────────────────────────────────
    MAIL_ENABLED       = os.getenv('MAIL_ENABLED', 'false').lower() == 'true'
    MAIL_FROM          = os.getenv('MAIL_FROM', '')
    MAIL_TO            = os.getenv('MAIL_TO', '')            # virgule pour plusieurs
    MAIL_SMTP_HOST     = os.getenv('MAIL_SMTP_HOST', 'localhost')
    MAIL_SMTP_PORT     = int(os.getenv('MAIL_SMTP_PORT', '587'))
    MAIL_SMTP_USER     = os.getenv('MAIL_SMTP_USER', '')
    MAIL_SMTP_PASSWORD = os.getenv('MAIL_SMTP_PASSWORD', '')
    MAIL_SMTP_TLS      = os.getenv('MAIL_SMTP_TLS', 'true').lower() == 'true'
