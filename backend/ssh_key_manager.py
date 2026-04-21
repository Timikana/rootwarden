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
    if PRIVATE_KEY_PATH.exists():
        PRIVATE_KEY_PATH.unlink()
    if PUBLIC_KEY_PATH.exists():
        PUBLIC_KEY_PATH.unlink()
    _log.warning("Ancienne keypair supprimee - regeneration en cours")
    generate_platform_key()
