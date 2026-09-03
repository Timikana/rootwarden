"""
approvals.py - Workflow d'approbation 4-eyes (double validation).

Certaines actions destructives exigent l'aval d'un SECOND administrateur avant
de s'executer (au-dela du step-up 2FA, qui ne protege que contre le vol de
session). Modele "store-and-replay" :

  1. L'admin A declenche l'action -> gate() ne trouve pas d'approbation -> cree
     une demande 'pending' et renvoie un signal (l'action n'est PAS executee).
  2. L'admin B (different de A) approuve la demande via l'UI.
  3. L'admin A rejoue exactement la meme action -> gate() trouve une demande
     'approved' correspondante -> la marque 'executed' -> l'action s'execute.

Regle 4-eyes : approved_by != requested_by (impose cote route d'approbation).

Opt-in : desactive par defaut (APPROVAL_ENABLED=false) pour ne pas bloquer les
deploiements mono-admin. La liste des actions concernees est configurable.
Best-effort : toute erreur BDD -> fail-open (on autorise l'action) pour ne pas
bloquer l'exploitation a cause d'un incident d'infra.
"""
import json
import logging
from datetime import datetime, timedelta

import mysql.connector
from config import Config

_log = logging.getLogger(__name__)

ROLE_SUPERADMIN = 3

# ══ DEUX ACTIONS NE SE CONTOURNENT PAS ET NE SE REPLIENT PAS ════════════════
#
# E-201. Une SEULE liste gouverne DEUX regles — le contournement du role 3 et le
# repli sur erreur de base — parce que ce sont deux facons de laisser passer le
# meme geste, et qu'un drapeau par appelant les disperserait entre quatre
# endroits.
#
# ┌─ LE CONTOURNEMENT DU ROLE 3 EST LEVE ICI SCIEMMENT ─────────────────────┐
# │                                                                          │
# │ Il n'etait PAS un oubli : sa docstring dit qu'il existe parce que « sur   │
# │ un deploiement avec un seul administrateur, la regle 4-eyes ne pourrait   │
# │ jamais etre satisfaite et bloquerait toute action ».                      │
# │                                                                          │
# │ Or ces deux routes sont `@require_role(3)` : brancher la porte dessus     │
# │ REPRODUIT EXACTEMENT le cas pour lequel le contournement a ete ecrit. La  │
# │ brancher sans lever le contournement aurait donc pose une ligne qui ne    │
# │ peut jamais rien faire — une garde presente qui ne garde pas.            │
# │                                                                          │
# │ La levee est donc une DECISION, prise le 2026-08-27, et elle a une        │
# │ condition : l'exploitant cree un second compte d'administration reel.     │
# │ Sans lui, ces deux gestes deviennent impossibles.                         │
# │                                                                          │
# │ ET L'APPROBATEUR N'A PAS BESOIN DU ROLE 3 : `routes/approvals.py:28-29`   │
# │ exige `role(2)` + `can_admin_portal`, avec `approved_by != requested_by`. │
# │ Un role 2 porteur de la permission approuve donc une action de role 3 —   │
# │ separation des taches SANS escalade. Ne pas supposer l'inverse.          │
# └──────────────────────────────────────────────────────────────────────────┘
#
# LE REPLI : sur erreur de base, `gate()` rend `None` — l'action passe. C'est
# tenable pour un redemarrage ; ca ne l'est pas pour la rotation de la paire de
# cles de la flotte entiere ni pour le kill-switch du compte de service. Pour
# ces deux-la, une porte qui ECHOUE doit REFUSER.
#
# Un fail-closed EN BLOC changerait le comportement de `delete_remote_user` et
# `reboot_server`, qui refuseraient sur une simple erreur de base. La liste
# fermee l'evite : ailleurs, rien ne change.
ACTIONS_SANS_REPLI = frozenset({'regenerate_platform_key', 'revoke_service_account'})


def _conn():
    return mysql.connector.connect(**Config.DB_CONFIG)


def is_required(action_type):
    """True si action_type est soumise a approbation (et la feature activee)."""
    if not getattr(Config, 'APPROVAL_ENABLED', False):
        return False
    return action_type in Config.APPROVAL_ACTIONS


def find_request(cur, action_type, machine_id, target, requested_by, status):
    """Retourne la demande la plus recente correspondant a la cle, ou None."""
    cur.execute(
        "SELECT * FROM approval_requests WHERE action_type=%s AND "
        "(machine_id <=> %s) AND target=%s AND (requested_by <=> %s) AND status=%s "
        "ORDER BY id DESC LIMIT 1",
        (action_type, machine_id, target, requested_by, status))
    return cur.fetchone()


def _compte_approbateurs_eligibles(cur, requested_by):
    """Combien de comptes pourraient approuver une demande de `requested_by`.

    L'ELIGIBILITE SE COMPTE, ELLE NE SE SUPPOSE PAS. Sans ce comptage, `gate()`
    cree une demande que PERSONNE ne peut approuver et l'action reste bloquee
    sans que rien ne dise pourquoi — un fail-closed qui masque son motif est un
    fail-closed qu'on finit par croire casse.

    LE CRITERE EST MESURE, PAS RECOPIE. La consigne disait
    « role_id >= 2 ET can_admin_portal ». C'est TROP ETROIT :
    `routes/approvals.py:88-91` garde l'approbation par `@require_role(2)` +
    `@require_permission('can_admin_portal')`, et `require_permission` porte
    `if role_id >= 3: return func(...)` (`helpers.py`). **Un role 3 SANS la
    permission peut donc approuver**, et le critere etroit ne l'aurait pas
    compte — donc aurait refuse alors qu'une approbation etait possible.

    Aujourd'hui les deux comptes de role 3 portent la permission, donc les deux
    criteres coincident PAR ACCIDENT. Retirer `can_admin_portal` a un superadmin
    suffirait a les separer.

    `id <> requested_by` : la regle 4-eyes est appliquee a la DECISION
    (`routes/approvals.py:72`), et il faut la refleter ici — sinon un
    administrateur seul se compterait lui-meme et le blocage redeviendrait muet.
    """
    cur.execute(
        "SELECT COUNT(*) AS n FROM users u "
        "LEFT JOIN permissions p ON p.user_id = u.id "
        "WHERE u.active = 1 AND u.id <> %s "
        "AND (u.role_id >= %s OR COALESCE(p.can_admin_portal, 0) = 1)",
        (requested_by, ROLE_SUPERADMIN))
    ligne = cur.fetchone()
    if ligne is None:
        raise RuntimeError("comptage des approbateurs : aucune ligne rendue")
    return int(ligne['n'] if isinstance(ligne, dict) else ligne[0])


class AucunApprobateur(RuntimeError):
    """Levee quand aucun compte ne peut approuver la demande.

    Porte son MOTIF et la marche a suivre : un blocage lisible vaut infiniment
    mieux qu'une fonctionnalite briquee en silence.
    """


def gate(action_type, machine_id, target, payload, requested_by, role=None):
    """
    Verrou d'approbation. Retourne :
      - None                          -> l'action peut s'executer (pas requise,
                                         superadmin, ou approbation consommee).
      - {'status': 'pending', 'id'}   -> demande deja en attente (re-tentative).
      - {'status': 'created', 'id'}   -> demande creee a l'instant (1re tentative).

    target : chaine identifiant la cible exacte (username, 'reboot'...). Le
    rapprochement demande<->retentative se fait sur (action, machine, target,
    requested_by).

    Le SUPERADMIN (role 3) contourne l'approbation : sur un deploiement avec un
    seul administrateur, la regle 4-eyes (approbation par un 2e admin) ne pourrait
    jamais etre satisfaite et bloquerait toute action. Le contournement est
    journalise.
    """
    if not is_required(action_type):
        return None

    if (role is not None and int(role) >= ROLE_SUPERADMIN
            and action_type not in ACTIONS_SANS_REPLI):
        _log.info("Approbation 4-eyes contournee (superadmin) action=%s cible=%s",
                  action_type, target)
        return None

    target = (target or '')[:255]
    try:
        conn = _conn()
        try:
            cur = conn.cursor(dictionary=True)

            # Purge defensive des demandes expirees (pending au-dela du TTL)
            cur.execute(
                "UPDATE approval_requests SET status='expired' "
                "WHERE status='pending' AND expires_at IS NOT NULL AND expires_at < NOW()")

            # 1) Une approbation valide existe-t-elle ? -> consomme et autorise
            appr = find_request(cur, action_type, machine_id, target, requested_by, 'approved')
            if appr:
                cur.execute("UPDATE approval_requests SET status='executed' WHERE id=%s", (appr['id'],))
                conn.commit()
                _log.info("Approbation 4-eyes consommee (req #%s, action=%s)", appr['id'], action_type)
                return None

            # 2) Une demande est-elle deja en attente ? -> on ne duplique pas
            pend = find_request(cur, action_type, machine_id, target, requested_by, 'pending')
            if pend:
                return {'status': 'pending', 'id': pend['id']}

            # 3) Sinon : creation d'une nouvelle demande
            # E-205 : refuser en NOMMANT la cause, plutot que de creer une
            # demande que personne ne pourra approuver. Sur les deux actions de
            # `ACTIONS_SANS_REPLI` seulement : ailleurs, une demande en attente
            # reste utile — un approbateur cree plus tard pourra la valider,
            # et changer ca serait un durcissement non demande.
            if action_type in ACTIONS_SANS_REPLI:
                if _compte_approbateurs_eligibles(cur, requested_by) == 0:
                    raise AucunApprobateur(
                        "Aucun approbateur eligible autre que vous. Cette action exige "
                        "l'aval d'un SECOND administrateur : creez un compte de role 2 "
                        "porteur de la permission `can_admin_portal`."
                    )

            ttl_hours = int(getattr(Config, 'APPROVAL_TTL_HOURS', 24))
            expires = datetime.now() + timedelta(hours=ttl_hours)
            cur.execute(
                "INSERT INTO approval_requests (action_type, machine_id, target, payload, "
                "status, requested_by, expires_at) VALUES (%s,%s,%s,%s,'pending',%s,%s)",
                (action_type, machine_id, target,
                 json.dumps(payload or {}), requested_by, expires))
            conn.commit()
            req_id = cur.lastrowid
        finally:
            conn.close()
    except AucunApprobateur:
        # Ce n'est PAS une erreur de base : c'est un refus motive. Il traverse
        # tel quel, sans etre requalifie en « erreur interne ».
        raise
    except Exception as e:
        if action_type in ACTIONS_SANS_REPLI:
            # Une porte qui echoue REFUSE. L'appelant doit traiter cette
            # exception comme un refus, jamais la journaliser et continuer.
            _log.error("approvals.gate BDD error (FAIL-CLOSED) action=%s : %s",
                       action_type, e)
            raise
        _log.warning("approvals.gate BDD error (fail-open): %s", e)
        return None

    # Notification best-effort aux admins (hors connexion principale)
    try:
        from notify import notify_subscribed
        notify_subscribed(
            event_type='approval_request',
            title=f"Approbation requise : {action_type}",
            message=f"Une action '{action_type}' sur la cible '{target}' attend l'aval d'un 2e admin.",
            link='/approvals/',
            machine_id=machine_id,
        )
    except Exception:
        pass

    return {'status': 'created', 'id': req_id}
