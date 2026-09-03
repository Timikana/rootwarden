#!/usr/bin/env python3
"""
ssh_key_manager.py - Gestion de la keypair Ed25519 de la plateforme RootWarden.

La plateforme utilise une paire de cles Ed25519 pour s'authentifier aupres
des serveurs distants sans stocker de password SSH en BDD.

Cycle de vie :
  1. generate_platform_key() cree la keypair au premier demarrage
  2. get_platform_private_key_path() retourne le chemin de la cle privee
  3. get_platform_public_key() retourne la pubkey (pour l'afficher dans l'UI)
  4. La cle est persistee dans un volume Docker nomme

Usage dans server.py :
  from ssh_key_manager import generate_platform_key, get_platform_public_key
  generate_platform_key()  # au demarrage
"""

import os
import time
from datetime import datetime
import logging
import base64
from pathlib import Path

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

_log = logging.getLogger(__name__)

PLATFORM_SSH_DIR = Path('/app/platform_ssh')
PRIVATE_KEY_PATH = PLATFORM_SSH_DIR / 'rootwarden_ed25519'
PUBLIC_KEY_PATH = PLATFORM_SSH_DIR / 'rootwarden_ed25519.pub'

# ══ L'ARCHIVE VIT HORS DE PORTEE DU CHEMIN D'AUTHENTIFICATION ═══════════════
#
# `get_platform_private_key()` ne lit QUE `PRIVATE_KEY_PATH` — un chemin fixe,
# jamais un motif (verifie : aucun glob sur `platform_ssh/` dans tout le
# backend, et seul ce module y touche). Un SOUS-REPERTOIRE lui est donc
# structurellement inatteignable.
#
# CE N'EST PAS UN DETAIL D'IMPLEMENTATION, C'EST LA CONDITION DU GESTE :
# on regenere une paire de cles parce qu'on SUPPOSE l'ancienne compromise. Si
# l'ancienne restait utilisable en repli, la rotation serait du theatre —
# l'attaquant qui la detient garderait son acces, et le portail affirmerait
# avoir tourne. L'archive est un artefact INERTE, pour une reprise humaine.
ARCHIVE_DIR = PLATFORM_SSH_DIR / 'archive'

# Delai de destruction. IL NE DEPEND PAS DE `LOG_RETENTION_DAYS` — cette
# variable vaut 0 par defaut et eteint deja trois nettoyages qui ne sont pas des
# politiques de retention (E-180). Une purge de SECRET accrochee a elle ne
# tournerait jamais, et personne ne le verrait.
#
# Un secret archive sans date de destruction est un secret permanent qui a
# seulement change de nom.
ARCHIVE_RETENTION_DAYS = int(os.getenv('PLATFORM_KEY_ARCHIVE_DAYS', '30'))


def _archive_platform_key():
    """Deplace la paire courante dans l'archive. Rend le prefixe, ou None.

    DEPLACE, ne copie pas : laisser la cle a sa place la garderait utilisable.
    """
    if not PRIVATE_KEY_PATH.exists() and not PUBLIC_KEY_PATH.exists():
        return None
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(str(ARCHIVE_DIR), 0o700)
    horodatage = datetime.now().strftime('%Y%m%dT%H%M%S')
    prefixe = ARCHIVE_DIR / f'rootwarden_ed25519.{horodatage}'
    for source, suffixe in ((PRIVATE_KEY_PATH, ''), (PUBLIC_KEY_PATH, '.pub')):
        if source.exists():
            cible = Path(str(prefixe) + suffixe)
            source.replace(cible)
            os.chmod(str(cible), 0o600)
    _log.warning("Ancienne keypair ARCHIVEE dans %s (destruction dans %d jours)",
                 prefixe, ARCHIVE_RETENTION_DAYS)
    return str(prefixe)


def purge_platform_key_archives():
    """Detruit les cles archivees plus vieilles que `ARCHIVE_RETENTION_DAYS`.

    Appelee a chaque rotation ET par l'ordonnanceur, hors de toute porte de
    retention. Les deux, parce qu'aucune des deux ne suffit : une rotation qui
    n'arrive plus laisserait l'archive indefiniment, et un ordonnanceur arrete
    ferait de meme.

    Rend le nombre de fichiers detruits.
    """
    if not ARCHIVE_DIR.exists() or ARCHIVE_RETENTION_DAYS <= 0:
        return 0
    limite = time.time() - ARCHIVE_RETENTION_DAYS * 86400
    detruits = 0
    for fichier in ARCHIVE_DIR.iterdir():
        try:
            if fichier.is_file() and fichier.stat().st_mtime < limite:
                fichier.unlink()
                detruits += 1
        except Exception as e:
            _log.error("Purge archive : %s non detruit (%s)", fichier, e)
    if detruits:
        _log.warning("Purge archive : %d cle(s) plateforme detruite(s) (> %d jours)",
                     detruits, ARCHIVE_RETENTION_DAYS)
    return detruits


def generate_platform_key():
    """
    Genere une paire de cles Ed25519 si elle n'existe pas encore.
    Idempotent : ne regenere pas si la cle existe deja.
    Affiche la pubkey dans les logs pour copie facile.
    """
    PLATFORM_SSH_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(str(PLATFORM_SSH_DIR), 0o755)
    # S'assurer que le dossier appartient au process courant
    _uid = os.getuid()
    _gid = os.getgid()
    try:
        os.chown(str(PLATFORM_SSH_DIR), _uid, _gid)
    except OSError:
        pass

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        pubkey = PUBLIC_KEY_PATH.read_text().strip()
        _log.info("Cle plateforme existante : %s", pubkey[:80] + '...')
        return

    _log.info("Generation de la keypair Ed25519 de la plateforme...")

    # Generer via cryptography
    private_key = Ed25519PrivateKey.generate()

    # Sauvegarder la cle privee au format OpenSSH
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )
    PRIVATE_KEY_PATH.write_bytes(pem)
    os.chmod(str(PRIVATE_KEY_PATH), 0o600)
    try:
        os.chown(str(PRIVATE_KEY_PATH), _uid, _gid)
    except OSError:
        pass

    # Sauvegarder la cle publique au format OpenSSH
    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
    pubkey_str = f"{pub} rootwarden-platform"
    PUBLIC_KEY_PATH.write_text(pubkey_str + '\n')
    os.chmod(str(PUBLIC_KEY_PATH), 0o644)
    try:
        os.chown(str(PUBLIC_KEY_PATH), _uid, _gid)
    except OSError:
        pass

    _log.info("=" * 60)
    _log.info("CLE PUBLIQUE DE LA PLATEFORME :")
    _log.info(pubkey_str)
    _log.info("=" * 60)


def get_platform_private_key_path() -> str:
    """Retourne le chemin de la cle privee, ou None si elle n'existe pas."""
    if PRIVATE_KEY_PATH.exists():
        return str(PRIVATE_KEY_PATH)
    return None


def get_platform_private_key():
    """Charge et retourne l'objet paramiko Ed25519Key, ou None."""
    path = get_platform_private_key_path()
    if not path:
        return None
    try:
        return paramiko.Ed25519Key.from_private_key_file(path)
    except Exception as e:
        _log.warning("Impossible de charger la cle plateforme : %s", e)
        return None


def get_platform_public_key() -> str:
    """Retourne la cle publique au format OpenSSH, ou None."""
    if PUBLIC_KEY_PATH.exists():
        return PUBLIC_KEY_PATH.read_text().strip()
    return None


def regenerate_platform_key():
    """
    Supprime et regenere la keypair. Necessite un re-deploiement
    sur tous les serveurs.
    """
    # ON ARCHIVE, ON NE DETRUIT PLUS. `unlink()` portait sur LA SEULE COPIE AU
    # MONDE : le volume `platform_ssh` n'est pas sauvegarde, ni par
    # l'infrastructure ni par RootWarden (mesure de l'exploitant, 2026-08-27).
    # Le geste detruisait donc un secret NON REPRODUCTIBLE, et une rotation
    # lancee par erreur etait irreversible.
    _archive_platform_key()
    purge_platform_key_archives()
    _log.warning("Ancienne keypair archivee - regeneration en cours")
    generate_platform_key()
