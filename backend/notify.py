"""
notify.py — Module de notifications in-app pour RootWarden.

Cree des enregistrements dans la table `notifications` pour alerter
les utilisateurs via l'interface web (icone cloche + badge).

Usage :
    from notify import notify, notify_admins

    # Notification pour un utilisateur specifique
    notify(user_id=10, type='perm_granted', title='Permission accordee',
           message='can_deploy_keys pour 24h', link='/adm/admin_page.php#permissions')

    # Notification broadcast pour tous les admins (user_id=0)
    notify_admins(type='cve_critical', title='CVE critique detectee',
                  message='CVE-2024-1234 (CVSS 9.8) sur srv-web',
                  link='/security/cve_scan.php')
"""

import logging
from routes.helpers import get_db_connection

logger = logging.getLogger('rootwarden.notify')


def notify(user_id: int, type: str, title: str, message: str, link: str = None):
    """Cree une notification pour un utilisateur specifique."""
    try:
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO notifications (user_id, type, title, message, link) VALUES (%s, %s, %s, %s, %s)",
                (user_id, type, title[:255], message[:2000], link)
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("Echec creation notification: %s", e)


def notify_admins(type: str, title: str, message: str, link: str = None):
    """Cree une notification broadcast (user_id=0) visible par tous les admins."""
    notify(user_id=0, type=type, title=title, message=message, link=link)


def notify_all_users(type: str, title: str, message: str, link: str = None):
    """Cree une notification pour chaque utilisateur actif."""
    try:
        conn = get_db_connection()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id FROM users WHERE active = 1")
            users = cur.fetchall()
            for u in users:
                cur.execute(
                    "INSERT INTO notifications (user_id, type, title, message, link) VALUES (%s, %s, %s, %s, %s)",
                    (u['id'], type, title[:255], message[:2000], link)
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("Echec creation notifications broadcast: %s", e)


def cleanup_old_notifications(days: int = 90):
    """Supprime les notifications lues de plus de N jours."""
    try:
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM notifications WHERE read_at IS NOT NULL AND created_at < DATE_SUB(NOW(), INTERVAL %s DAY)",
                (days,)
            )
            deleted = cur.rowcount
            conn.commit()
            if deleted:
                logger.info("Purge notifications: %d supprimees (> %d jours)", deleted, days)
        finally:
            conn.close()
    except Exception as e:
        logger.warning("Echec purge notifications: %s", e)
