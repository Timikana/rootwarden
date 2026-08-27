"""
routes/ssh.py - Routes SSH : deploiement, logs SSE, keypair plateforme, scan users.

Routes :
    POST /deploy                  - Lance le script de deploiement
    GET  /logs                    - Stream SSE du deployment.log
    POST /preflight_check         - Verifie connectivite SSH avant deploiement
    GET  /platform_key            - Retourne la cle publique plateforme
    POST /deploy_platform_key     - Deploie la pubkey plateforme sur les serveurs
    POST /deploy_service_account  - Deploie le compte rootwarden (NOPASSWD sudo)
    POST /test_platform_key       - Teste la connexion keypair sur un serveur
    POST /remove_ssh_password     - Supprime le password SSH d un serveur
    POST /reenter_ssh_password    - Re-saisit un password SSH
    POST /regenerate_platform_key - Regenere la keypair plateforme
    POST /scan_server_users       - Scanne les utilisateurs sur un serveur distant
"""

import os
import re
import json
import shlex
import socket
import base64
import hashlib
import logging
import subprocess
import threading
import time
import traceback
import paramiko
from flask import Blueprint, jsonify, request, Response
from routes.helpers import require_api_key, require_role, require_machine_access, check_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger, encryption, get_current_user
from configure_servers import (
    _motif_nom_invalide,
    _valid_username as _valid_username_decouvert,
)
from ssh_utils import ssh_session, execute_as_root, ensure_sudo_installed
from config import Config

bp = Blueprint('ssh', __name__)

# ─────────────────────────────────────────────────────────────────────────────
# Securite : validation des noms d'utilisateur (anti-injection OS command)
# ─────────────────────────────────────────────────────────────────────────────

# ── Helpers SSH keys parsing (v1.18.x) ──────────────────────────────────
_SSH_KEY_TYPE_RE = re.compile(r'^(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[a-z0-9-]+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$')


def _parse_ssh_key_line(line: str):
    """Parse une ligne authorized_keys -> dict ou None.

    Retourne {type, fingerprint_sha256, comment, data} ou None si invalide.
    Format attendu : ``<type> <base64_data> [comment]``. Les options
    (`from=`, `command=`, etc.) en prefixe sont ignorees. Lignes de
    commentaire (`#`) et vides ignorees.

    Le fingerprint SHA256 est calcule comme `ssh-keygen -lf` :
    base64(sha256(base64_decode(key_data))) sans padding.
    """
    line = (line or '').strip()
    if not line or line.startswith('#'):
        return None
    # Si options ssh (from=,command=,etc.) en prefixe, on saute jusqu'au type
    rest = line
    if not _SSH_KEY_TYPE_RE.match(rest.split(None, 1)[0]):
        # Cherche le prochain token qui ressemble a un type de cle
        tokens = rest.split()
        for i, tok in enumerate(tokens):
            if _SSH_KEY_TYPE_RE.match(tok):
                rest = ' '.join(tokens[i:])
                break
        else:
            return None
    parts = rest.split(None, 2)
    if len(parts) < 2:
        return None
    key_type = parts[0]
    key_data = parts[1]
    comment = parts[2].strip() if len(parts) > 2 else None
    if not _SSH_KEY_TYPE_RE.match(key_type):
        return None
    try:
        raw = base64.b64decode(key_data, validate=False)
    except Exception:
        return None
    if len(raw) < 8:
        return None
    digest = hashlib.sha256(raw).digest()
    fp = base64.b64encode(digest).decode('ascii').rstrip('=')
    return {
        'type': key_type[:32],
        'fingerprint': fp[:64],
        'comment': comment[:255] if comment else None,
        'data': key_data,
    }


def _parse_authorized_keys_dump(dump: str):
    """Parse le dump multi-user produit par scan_server_users.

    Format attendu : sequences ``###USER:xxx###`` ... ``###ENDUSER###``.
    Retourne ``{username: [parsed_keys]}``.

    Tolere les cas degrades :
    - authorized_keys sans newline finale -> ###ENDUSER### colle a la
      derniere cle ("ssh-ed25519 AAAA...comment###ENDUSER###")
    - ###USER:xxx### colle a un suffixe (theoriquement impossible mais safe)
    """
    result = {}
    if not dump:
        return result
    current_user = None
    buf = []
    for raw_line in dump.splitlines():
        # Si la ligne CONTIENT ###ENDUSER### (potentiellement collee a une cle)
        idx_end = raw_line.find('###ENDUSER###')
        if idx_end >= 0:
            # Capture le prefixe (potentielle derniere cle) avant le marqueur
            prefix = raw_line[:idx_end]
            if prefix.strip():
                buf.append(prefix)
            if current_user:
                parsed = [_parse_ssh_key_line(ln) for ln in buf]
                result[current_user] = [k for k in parsed if k]
            current_user = None
            buf = []
            # Le suffixe apres ###ENDUSER### pourrait theoriquement contenir
            # un nouveau ###USER:xxx### sur la meme ligne, on le retraite
            suffix = raw_line[idx_end + len('###ENDUSER###'):]
            if '###USER:' in suffix:
                raw_line = suffix
            else:
                continue
        if raw_line.startswith('###USER:') and raw_line.rstrip().endswith('###'):
            current_user = raw_line[len('###USER:'):raw_line.rstrip().rfind('###')].strip()
            buf = []
            continue
        if current_user is not None:
            buf.append(raw_line)
    return result


def _ensure_sshd_allows_user(client, root_pass, sa_name, logger):
    """Patche sshd_config pour ajouter sa_name a AllowUsers si necessaire.

    Sur serveurs hardenes (port custom, AllowUsers en place), creer un
    nouveau user `rootwarden` ne suffit pas : sshd refuse l'auth tant que
    l'user n'est pas explicitement liste. Ce helper :
      1. grep AllowUsers dans sshd_config + sshd_config.d/*.conf
      2. Si present et sa_name absent : backup + sed-append + sshd -t + reload
      3. Rollback si une etape echoue (restaure backup et reload)

    Returns (modified: bool, message: str). modified=True si patch applique.
    Idempotent : si sa_name deja dans AllowUsers, retourne (False, msg).
    """
    grep_cmd = (
        "grep -rEH '^[[:space:]]*AllowUsers[[:space:]]' "
        "/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true"
    )
    out, _, _ = execute_as_root(client, grep_cmd, root_pass, logger=logger)
    if not out or not out.strip():
        return False, "AllowUsers absent - pas de patch necessaire"

    # Format : /path/to/file:AllowUsers user1 user2 ...
    first_line = out.strip().split('\n')[0]
    if ':' not in first_line:
        return False, "Parse grep AllowUsers ambigu, skip"
    file_path, raw = first_line.split(':', 1)
    tokens = raw.strip().split()
    if not tokens or tokens[0].lower() != 'allowusers' or len(tokens) < 2:
        return False, "Format AllowUsers inattendu, skip"
    users_listed = tokens[1:]
    if sa_name in users_listed:
        return False, f"{sa_name} deja dans AllowUsers"

    fp_q = shlex.quote(file_path)
    bak_q = shlex.quote(file_path + '.bak.rw')
    sa_q = shlex.quote(sa_name)

    # 1. Backup
    _, err_b, code_b = execute_as_root(client, f"cp -a {fp_q} {bak_q}", root_pass, logger=logger)
    if code_b != 0:
        return False, f"Backup echoue : {(err_b or '')[:200]}"

    # 2. Patch via awk : ajoute sa_name a la fin de la 1re ligne AllowUsers
    patch_cmd = (
        f"awk -v u={sa_q} 'BEGIN{{f=0}} "
        f"/^[[:space:]]*AllowUsers[[:space:]]/ && !f {{print $0\" \"u; f=1; next}} "
        f"{{print}}' {fp_q} > /tmp/sshd_rw_patch.tmp && "
        f"mv /tmp/sshd_rw_patch.tmp {fp_q}"
    )
    _, err_p, code_p = execute_as_root(client, patch_cmd, root_pass, logger=logger)
    if code_p != 0:
        execute_as_root(client, f"cp -a {bak_q} {fp_q}", root_pass, logger=logger)
        return False, f"Patch awk echoue : {(err_p or '')[:200]}"

    # 3. Validation sshd -t
    _, err_t, code_t = execute_as_root(client, "sshd -t 2>&1", root_pass, logger=logger)
    if code_t != 0:
        execute_as_root(client, f"cp -a {bak_q} {fp_q}", root_pass, logger=logger)
        return False, f"sshd -t a refuse le patch : {(err_t or '')[:200]}"

    # 4. Reload sshd (different selon distrib : sshd vs ssh)
    reload_cmd = "systemctl reload sshd 2>&1 || systemctl reload ssh 2>&1 || true"
    _, err_r, code_r = execute_as_root(client, reload_cmd, root_pass, logger=logger)
    if code_r != 0:
        execute_as_root(client, f"cp -a {bak_q} {fp_q}", root_pass, logger=logger)
        execute_as_root(client, reload_cmd, root_pass, logger=logger)
        return False, f"reload sshd echoue, rollback effectue : {(err_r or '')[:200]}"

    logger.info("sshd AllowUsers patche : ajoute '%s' dans %s (backup %s.bak.rw)",
                sa_name, file_path, file_path)
    return True, f"AllowUsers patche : {sa_name} ajoute dans {file_path}"


def _validate_username(username: str) -> bool:
    """Valide qu'un nom d'utilisateur ne contient que des caracteres surs.

    ══ E-204 : C'ETAIT LA QUATRIEME IMPLEMENTATION, ET LA MEME FAUTE ════════

    Ce fichier portait sa PROPRE expression, `^[a-zA-Z0-9._-]{1,32}$` — soit
    exactement celle de `configure_servers` AVANT E-197. Elle acceptait donc
    `.` et `..`, qui ne sont pas des noms de compte mais des COMPOSANTS DE
    CHEMIN, sur quatre routes qui composent des chemins root
    (`/home/<nom>/.ssh/authorized_keys`) et appellent `userdel`.

    C'est ce trou qui a laisse passer la sonde fautive du 2026-08-27 : le nom
    `..` qu'elle croyait refuse a traverse tous les gardes et atteint une
    session SSH. Le defaut etait corrige a un endroit et pas ici.

    ══ ELLE DERIVE, ELLE NE RECOPIE PLUS ═══════════════════════════════════

    Le DOMAINE de ces quatre routes est celui des noms DECOUVERTS — ils
    viennent de `server_user_inventory`, donc du `/etc/passwd` d'une machine
    reelle, ou les majuscules existent (`Debian-exim`, `Timikana`). C'est le
    domaine de `configure_servers._valid_username`, et c'est de la qu'elle
    vient desormais.

    LA RESERVE D'E-198 NE S'APPLIQUE PAS ICI, et c'est mesure : elle portait sur
    le POINT, parce que `sudo` ignore les fichiers de `/etc/sudoers.d` dont le
    nom en contient un. **Aucune de ces quatre routes ne compose de nom de
    fichier `sudoers.d`** — elles font `userdel` et manipulent
    `authorized_keys`. Un point au milieu d'un nom (`john.doe`) y est donc
    legitime, et seuls `.` et `..` doivent tomber. C'est exactement ce que rend
    la source.
    """
    return _valid_username_decouvert(username)

# ─────────────────────────────────────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────────────────────────────────────
log_dir = os.getenv('LOG_DIR', '/app/logs')
deployment_log_file = os.path.join(log_dir, "deployment.log")
def rotate_logs_deployment():
    """Archive le journal du deploiement PRECEDENT, puis laisse la place au suivant.

    ══ E-196 : DEUX MECANISMES POUR UNE MEME NOTION, DONT UN INATTEIGNABLE ═══

    Ce fichier etait traite par deux regles qui ne se connaissaient pas :

      - cette rotation, PAR TAILLE — `si > 5 Mo, renommer en .1` ;
      - `open(deployment_log_file, "w")` dans `/deploy`, qui TRONQUE sans
        aucune condition, a chaque deploiement.

    La seconde rendait la premiere INATTEIGNABLE. Le fichier ne portant jamais
    qu'un seul deploiement, il n'atteignait pas 5 Mo, donc la rotation ne
    pouvait pas se declencher. Mesure du 2026-08-27 dans le conteneur :
    `deployment.log` = **0 octet**, et **aucun `deployment.log.1` n'a jamais
    existe**. Le seuil n'etait pas mal choisi : il etait hors d'atteinte.

    Consequence, et c'est ce qui compte : un deploiement qui meurt ne laissait
    AUCUNE trace apres le suivant — le verdict d'E-193 compris, alors qu'il est
    ecrit precisement pour dire ce qui a echoue.

    ══ UNE SEULE REGLE, ET ELLE NE DEPEND PLUS D'UNE TAILLE ══════════════════

    Le journal du deploiement precedent devient `.1`, et le suivant repart d'un
    fichier neuf. Deux generations au plus : l'espace reste borne sans qu'aucun
    seuil n'ait a etre choisi, et le seuil etait justement la piece qui ne
    servait a rien.

    Le `"w"` de `/deploy` cesse d'etre une SECONDE troncature : le fichier
    n'existe plus quand il s'execute, il ne fait plus que le creer.

    Et le flux SSE garde son sens : il envoie « d'abord le contenu existant »,
    et ce contenu reste celui du deploiement COURANT — pas un historique cumule
    qu'un exploitant relirait en croyant regarder son deploiement.
    """
    try:
        if os.path.exists(deployment_log_file) and os.path.getsize(deployment_log_file) > 0:
            precedent = deployment_log_file + ".1"
            if os.path.exists(precedent):
                os.remove(precedent)
            os.rename(deployment_log_file, precedent)
    except Exception as e:
        # Un archivage rate ne doit pas empecher le deploiement : au pire le
        # journal precedent est perdu, ce qui est l'etat d'avant ce correctif.
        logging.warning("Archivage du journal de deploiement echoue : %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Deploy + Logs SSE
# ─────────────────────────────────────────────────────────────────────────────

def _journalise_verdict_deploiement(texte: str) -> None:
    """Ajoute une ligne de verdict au journal de deploiement, sans le tronquer.

    Ouverture en `a` : le sous-processus vient d'ecrire dans ce fichier ouvert
    en `w`, et l'ecraser ici effacerait le journal qu'on cherche a conclure.
    """
    try:
        with open(deployment_log_file, "a") as f:
            f.write(f"\n[RootWarden] {texte}\n")
    except Exception as e:
        logging.error("[deploy] verdict non journalise : %s", e)


@bp.route('/deploy', methods=['POST'])
@require_api_key
@require_role(2)             # E-191
@require_machine_access      # E-191
@threaded_route
def deploy():
    """Lance le script de deploiement (configure_servers.py) en arriere-plan.

    ══ E-191 : CETTE ROUTE N'AVAIT QUE `@require_api_key` ════════════════════

    Elle ECRIT des cles SSH en root sur toutes les machines transmises, et elle
    en REVOQUE. Elle etait la moins gardee des trois gestes comparables :

        POST /deploy               flotte transmise, ecrit ET revoque   api_key SEUL
        POST /deploy_platform_key  UNE machine                          api_key + role(2) + machine_access
        POST /reboot_server        redemarre                            api_key + role(2) + machine_access

    `deploy_platform_key` est dans CE fichier, 270 lignes plus bas, avec un
    commentaire de patch explicite. Quelqu'un a durci le deploiement d'une cle
    sur une machine et laisse ouvert celui du parc entier : « le cas visible
    traite, le cas subtil pris a l'envers », a son maximum — le geste durci est
    le MOINS dangereux des deux.

    L'ancien commentaire disait : « La route n'est pas decoree car elle utilise
    deja un thread dedie pour le deploiement. » Executer dans un thread n'a
    AUCUN rapport avec l'autorisation. Un commentaire qui justifie une absence
    par une raison sans rapport est plus couteux qu'un silence : il decourage la
    question. Il est retire.

    ══ POURQUOI `role(2)` ET PAS `@require_permission('can_deploy_keys')` ═══

    La permission serait le miroir exact de la page — et elle CASSERAIT un
    chemin legitime. La page accepte les permissions TEMPORAIRES
    (`checkPermissionFromDB` interroge `temporary_permissions`), tandis que le
    backend lit `X-User-Permissions`, que la passerelle remplit depuis la
    session, c'est-a-dire les PERMANENTES seules. Un compte dont la permission
    est temporaire passerait la page et serait refuse ici.

    `role(2)` ferme l'ecart mesure sans rencontrer ce probleme.

    ══ CE QUE CELA RETIRE : RIEN, ET C'EST MESURE ═══════════════════════════

    Mesure du 2026-08-27 : **aucun compte actif de role 1 ne porte
    `can_deploy_keys`**, ni en permanent ni en temporaire (0 octroi non expire).
    `opsuser` — le compte que l'audit nommait comme tombant dans l'ecart — a
    `can_deploy_keys = 0` : la page le refusait deja, seul le chemin de requete
    l'acceptait. C'est exactement ce que ce correctif ferme.

    POSER LA GARDE N'EST PAS DECLENCHER LE GESTE. Le deploiement de cles reste
    interdit par l'exploitant (K4) — et c'est precisement pour cela que poser la
    garde ne coute rien.

    `@require_machine_access` est inerte au role 2 ; le controle qui travaille
    reste `check_machine_access(mid)` dans le corps, machine par machine. Il est
    pose pour aligner cette route sur sa voisine et pour qu'un abaissement futur
    du role ne soit pas silencieusement une ouverture.
    """
    try:
        data = request.json
        logging.debug(f"Donnees recues pour /deploy : {data}")
        if not data or 'machines' not in data:
            return jsonify({"success": False, "message": "Aucune machine selectionnee."}), 400

        # Verifier l'acces a chaque machine pour les users role < 2
        from routes.helpers import check_machine_access
        for mid in data['machines']:
            if not check_machine_access(mid):
                return jsonify({"success": False, "message": f"Acces refuse a la machine {mid}"}), 403

        machine_ids = [str(machine) for machine in data['machines']]
        logging.debug(f"Machines selectionnees pour le deploiement : {machine_ids}")
        # Rotation eventuelle des logs avant le lancement du deploiement
        rotate_logs_deployment()

        def run_deployment():
            # ══ LE CODE DE SORTIE DU SOUS-PROCESSUS EST LU, ET IL EST DIT ════
            #
            # E-193. `process.wait()` etait appele et son code JETE. La reponse
            # HTTP de cette route est un accuse de reception — un
            # `threading.Thread` dans le corps, pas un `@threaded_route` — donc
            # elle ne peut pas porter le verdict, et c'est normal. Mais il
            # n'etait porte NULLE PART : un deploiement qui meurt ne laissait
            # aucun signal, et le seul endroit ou l'exploitant regarde est le
            # flux SSE de `/logs`, qui ne lit que ce fichier.
            #
            # Le verdict est donc ECRIT DANS LE FLUX, la ou il est regarde.
            # `stream_logs` suit le fichier pendant 30 s d'inactivite : une
            # ligne ajoutee juste apres la fin du processus y parvient.
            #
            # Le terminateur `[Fin du flux de logs]` n'est PAS emis ici : c'est
            # un JETON DE PROTOCOLE que le client compare litteralement, et
            # l'ecrire dans le fichier ferait croire au client que le flux est
            # fini alors que le serveur continue de le tenir.
            code = None
            try:
                with open(deployment_log_file, "w") as log_file:
                    process = subprocess.Popen(
                        ["python3", "/app/configure_servers.py"] + machine_ids,
                        stdout=log_file,
                        stderr=subprocess.STDOUT
                    )
                    code = process.wait()
            except Exception as e:
                logging.error(f"Erreur lors de l'execution de configure_servers.py : {e}")
                _journalise_verdict_deploiement(
                    f"ECHEC : le deploiement n'a pas pu etre execute ({e}).")
                return

            if code == 0:
                logging.info("[deploy] configure_servers.py termine (code 0).")
                _journalise_verdict_deploiement("Deploiement termine (code 0).")
            else:
                logging.error("[deploy] configure_servers.py termine avec le code %s.", code)
                _journalise_verdict_deploiement(
                    f"ECHEC : le deploiement s'est termine avec le code {code}. "
                    f"Les gestes deja emis n'ont PAS ete annules.")
        thread = threading.Thread(target=run_deployment)
        thread.start()
        return jsonify({"success": True, "message": "Deploiement lance avec succes."})
    except Exception as e:
        logging.error(f"[deploy] Erreur interne : {traceback.format_exc()}")
        return jsonify({"success": False, "message": "Erreur interne du serveur."}), 500


@bp.route('/logs')
@require_api_key
@require_role(2)  # Patch A01-NEW-04 : SSE logs reservees admin (info disclosure)
@threaded_route
def stream_logs():
    """
    Stream en temps reel du fichier de log deployment.log via Server-Sent Events (SSE).
    """
    def generate_logs():
        try:
            with open(deployment_log_file, "r") as f:
                # Envoie d'abord le contenu existant (le deploiement a peut-etre deja commence)
                existing = f.read()
                if existing:
                    for line in existing.strip().splitlines():
                        yield f"data: {line}\n\n"
                # Puis attend les nouvelles lignes en temps reel
                idle = 0
                while idle < 60:  # Arrete apres 30s sans nouvelle ligne
                    line = f.readline()
                    if line:
                        yield f"data: {line.strip()}\n\n"
                        idle = 0
                    else:
                        time.sleep(0.5)
                        idle += 1
                yield "data: [Fin du flux de logs]\n\n"
        except Exception as e:
            logging.error(f"Erreur lors du streaming des logs : {e}")
            yield f"data: [Erreur] {e}\n\n"
    return Response(generate_logs(), content_type='text/event-stream', headers={"Cache-Control": "no-cache"})


# ─────────────────────────────────────────────────────────────────────────────
# Preflight Check
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/preflight_check', methods=['POST'])
@require_api_key
@threaded_route
def preflight_check():
    """
    Verifie la connectivite SSH et les prerequis avant un deploiement.
    Body JSON : {machines: [id, ...]}
    Retourne un rapport par machine : connectivite, version OS, espace disque.
    """
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machines', [])
    if not machine_ids:
        return jsonify({'success': False, 'message': 'Aucune machine specifiee'}), 400

    # Verifier l'acces a chaque machine
    from routes.helpers import check_machine_access
    for mid in machine_ids:
        if not check_machine_access(mid):
            return jsonify({'success': False, 'message': f'Acces refuse a la machine {mid}'}), 403

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        fmt = ','.join(['%s'] * len(machine_ids))
        cur.execute(
            f"SELECT id, name, ip, port, user, password, platform_key_deployed, service_account_deployed, users_scanned_at, cleanup_users FROM machines WHERE id IN ({fmt})",
            machine_ids
        )
        machines = cur.fetchall()
    finally:
        conn.close()

    # Verifier aussi qu'il y a des users avec des cles SSH
    conn2 = get_db_connection()
    try:
        cur2 = conn2.cursor(dictionary=True)
        cur2.execute("SELECT COUNT(*) as cnt FROM users WHERE active = 1 AND ssh_key IS NOT NULL AND ssh_key != ''")
        users_with_keys = cur2.fetchone()['cnt']
    finally:
        conn2.close()

    results = []
    for m in machines:
        result = {
            'machine_id': m['id'],
            'name': m['name'],
            'ip': m['ip'],
            'ssh_ok': False,
            'os_version': None,
            'disk_free': None,
            # E-194 : TOUJOURS present, et faux par defaut. L'audit d'impact
            # ci-dessous vit dans un `try` imbrique : quand il levait, il
            # journalisait sans rien ajouter a `errors`, et les trois champs
            # qu'il produit restaient ABSENTS. L'ecran composait alors
            # « badge OK · aucune erreur · aucun acces a revoquer · aucun
            # prerequis manquant » — pour une machine dont l'inventaire n'avait
            # pas pu etre lu. Un champ absent se rend comme une liste vide, et
            # une liste vide se lit « rien a revoquer ».
            #
            # Ce drapeau porte la difference entre « etabli et vide » et
            # « pas etabli ». Il vaut faux tant que l'audit n'a pas abouti —
            # y compris quand la connexion SSH echoue avant de l'atteindre.
            'audit_inventaire': False,
            'errors': [],
        }

        # Bloquer si le serveur n'a jamais ete scanne
        if not m.get('users_scanned_at'):
            result['errors'].append(
                "Scan utilisateurs requis avant le premier deploiement. "
                "Allez dans Utilisateurs distants pour scanner ce serveur."
            )
            result['scan_required'] = True
            results.append(result)
            continue

        # Bloquer si des users sont en pending_review
        conn_pending = get_db_connection()
        try:
            cur_p = conn_pending.cursor(dictionary=True)
            cur_p.execute(
                "SELECT COUNT(*) as cnt FROM server_user_inventory "
                "WHERE machine_id = %s AND status = 'pending_review'",
                (m['id'],)
            )
            pending = cur_p.fetchone()['cnt']
            if pending > 0:
                result['errors'].append(
                    f"{pending} utilisateur(s) en attente de classification. "
                    "Classifiez-les dans Utilisateurs distants avant de deployer."
                )
                result['scan_required'] = True
                results.append(result)
                continue
        finally:
            conn_pending.close()

        ssh_pass = server_decrypt_password(m.get('password', '')) or ''
        has_keypair = m.get('service_account_deployed') or m.get('platform_key_deployed', False)
        if not ssh_pass and not has_keypair:
            result['errors'].append('Ni mot de passe ni keypair disponible')
            results.append(result)
            continue

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((m['ip'], m['port']))
            sock.close()
        except Exception:
            result['errors'].append(f"Port {m['port']} injoignable sur {m['ip']}")
            results.append(result)
            continue

        try:
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
                result['ssh_ok'] = True
                result['auth_method'] = getattr(client, '_rootwarden_auth_method', 'unknown')

                # Version OS
                try:
                    stdin, stdout, stderr = client.exec_command("cat /etc/os-release | head -1", timeout=10)
                    result['os_version'] = (stdout.read().decode() or '').strip()[:100]
                except Exception:
                    pass

                # Espace disque
                try:
                    stdin, stdout, stderr = client.exec_command("df -h / | tail -1 | awk '{print $4}'", timeout=10)
                    result['disk_free'] = (stdout.read().decode() or '').strip()
                except Exception:
                    pass

                # ── Audit d'impact depuis l'inventaire ────────────────────
                try:
                    conn_inv = get_db_connection()
                    try:
                        cur_inv = conn_inv.cursor(dictionary=True)
                        cur_inv.execute(
                            "SELECT username, status, managed_by FROM server_user_inventory "
                            "WHERE machine_id = %s", (m['id'],)
                        )
                        inventory = cur_inv.fetchall()

                        cur_inv.execute(
                            "SELECT u.name FROM users u "
                            "JOIN user_machine_access uma ON u.id = uma.user_id "
                            "WHERE uma.machine_id = %s AND u.active = 1",
                            (m['id'],)
                        )
                        authorized = {r['name'] for r in cur_inv.fetchall()}
                    finally:
                        conn_inv.close()

                    user_impact = []
                    for row in inventory:
                        user_impact.append({
                            'name': row['username'],
                            'status': row['status'],
                            'managed_by': row['managed_by'],
                        })

                    result['user_impact'] = user_impact

                    # Users RootWarden absents du serveur (seront crees)
                    inv_names = {r['username'] for r in inventory}
                    result['users_to_create'] = sorted(authorized - inv_names)

                    # Users managed qui perdent l'acces (cle retiree, compte conserve)
                    managed_names = {r['username'] for r in inventory if r['status'] == 'managed' and r['managed_by'] == 'rootwarden'}
                    result['users_revoked'] = sorted(managed_names - authorized)

                    # L'audit a ABOUTI : les trois champs ci-dessus sont des
                    # constats, pas des absences.
                    result['audit_inventaire'] = True

                except Exception as ex:
                    logger.warning("Preflight inventory audit (%s): %s", m['name'], ex)
                    # E-194 : DIRE que l'audit a echoue, au lieu de laisser un
                    # champ absent. Sans cette ligne, la seule trace etait un
                    # `logger.warning` cote serveur — invisible a l'ecran qui
                    # prepare le deploiement.
                    result['errors'].append(
                        "Audit d'inventaire indisponible : la liste des acces qui "
                        "seront REVOQUES n'a pas pu etre etablie. Ne pas deployer "
                        "sans l'avoir relue."
                    )

        except Exception as e:
            result['errors'].append(f"Connexion SSH echouee: {str(e)[:100]}")

        results.append(result)

    return jsonify({
        'success': True,
        'results': results,
        'users_with_keys': users_with_keys,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Platform Key Management
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/platform_key', methods=['GET'])
@require_api_key
@threaded_route
def get_platform_key():
    """Retourne la cle publique de la plateforme."""
    from ssh_key_manager import get_platform_public_key
    pubkey = get_platform_public_key()
    if not pubkey:
        return jsonify({'success': False, 'message': 'Keypair non generee'}), 404
    return jsonify({'success': True, 'public_key': pubkey})


@bp.route('/deploy_platform_key', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : deploiement de cle plateforme reserve admin
@require_machine_access
@threaded_route
def deploy_platform_key():
    """
    Deploie la pubkey plateforme sur les serveurs selectionnes.
    Body JSON : {machine_ids: [int]}
    """
    from ssh_key_manager import get_platform_public_key
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    pubkey = get_platform_public_key()
    if not pubkey:
        return jsonify({'success': False, 'message': 'Keypair plateforme non generee'}), 500

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        fmt = ','.join(['%s'] * len(machine_ids))
        cur.execute(f"SELECT id, name, ip, port, user, password, root_password FROM machines WHERE id IN ({fmt})", machine_ids)
        machines = cur.fetchall()
    finally:
        conn.close()

    results = []
    for m in machines:
        r = {'machine_id': m['id'], 'name': m['name'], 'success': False, 'message': ''}
        ssh_pass = server_decrypt_password(m['password'])
        root_pass = server_decrypt_password(m['root_password'])

        if not ssh_pass:
            r['message'] = 'Dechiffrement password echoue'
            results.append(r)
            continue

        try:
            # Connexion en password (force) pour deployer la cle
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, force_password=True) as client:
                ssh_user = m['user']
                # Deployer pour l'utilisateur SSH (base64 safe - evite injection via pubkey)
                import base64 as _b64
                _key_b64 = _b64.b64encode((pubkey + '\n').encode()).decode()
                deploy_cmd = (
                    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
                    f"printf '%s' '{_key_b64}' | base64 -d >> ~/.ssh/authorized_keys && "
                    "sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys && "
                    "chmod 600 ~/.ssh/authorized_keys"
                )
                stdin, stdout, stderr = client.exec_command(deploy_cmd, timeout=15)
                stdout.read()

                # Deployer pour root (via sudo/su)
                root_cmd = (
                    "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
                    f"printf '%s' '{_key_b64}' | base64 -d >> /root/.ssh/authorized_keys && "
                    "sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys && "
                    "chmod 600 /root/.ssh/authorized_keys"
                )
                try:
                    execute_as_root(client, root_cmd, root_pass, logger=logger)
                except Exception as root_err:
                    logger.debug("Deploy platform key root failed for %s: %s", m['name'], root_err)

                # Tester la connexion en keypair
                try:
                    test_client = paramiko.SSHClient()
                    test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    from ssh_key_manager import get_platform_private_key
                    pkey = get_platform_private_key()
                    test_client.connect(hostname=m['ip'], port=m['port'], username=ssh_user, pkey=pkey, look_for_keys=False, allow_agent=False)
                    test_client.close()
                    r['success'] = True
                    r['message'] = 'Cle deployee et testee OK'
                    r['auth_method'] = 'keypair'

                    # Marquer keypair en BDD
                    conn2 = get_db_connection()
                    try:
                        cur2 = conn2.cursor()
                        cur2.execute("UPDATE machines SET platform_key_deployed = TRUE, platform_key_deployed_at = NOW() WHERE id = %s", (m['id'],))
                        conn2.commit()
                    finally:
                        conn2.close()

                    # Deployer le service account rootwarden dans la foulee
                    sa_ok = False
                    try:
                        sa_name = Config.NOM_COMPTE_SERVICE
                        if not re.match(r'^[a-z][a-z0-9_-]+$', sa_name):
                            raise ValueError(f"Nom de compte invalide: {sa_name}")
                        # Installer sudo si absent (utilise su - avec root_password)
                        try:
                            ensure_sudo_installed(client, root_pass, logger=logger)
                        except Exception as sudo_err:
                            logger.warning("Installation sudo echouee pour %s: %s", m['name'], sudo_err)

                        # Commandes separees (su -c casse le chainage &&)
                        import base64 as _b64

                        # Creer le user rootwarden
                        execute_as_root(client, f"id {sa_name} >/dev/null 2>&1 || /usr/sbin/useradd -r -m -s /bin/bash {sa_name}", root_pass, logger=logger)
                        execute_as_root(client, f"chown {sa_name}:{sa_name} /home/{sa_name}", root_pass, logger=logger)

                        # Deployer la keypair
                        key_b64 = _b64.b64encode(pubkey.encode()).decode()
                        execute_as_root(client, f"mkdir -p /home/{sa_name}/.ssh", root_pass, logger=logger)
                        execute_as_root(client, f"chmod 700 /home/{sa_name}/.ssh", root_pass, logger=logger)
                        execute_as_root(client, f"printf %s {key_b64} | base64 -d > /home/{sa_name}/.ssh/authorized_keys", root_pass, logger=logger)
                        execute_as_root(client, f"chmod 600 /home/{sa_name}/.ssh/authorized_keys", root_pass, logger=logger)
                        execute_as_root(client, f"chown -R {sa_name}:{sa_name} /home/{sa_name}/.ssh", root_pass, logger=logger)

                        # Configurer sudoers NOPASSWD
                        execute_as_root(client, f"echo '{sa_name} ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sa_name}", root_pass, logger=logger)
                        execute_as_root(client, f"chmod 440 /etc/sudoers.d/{sa_name}", root_pass, logger=logger)

                        # Valider sudoers
                        _, err_sudo, code_sudo = execute_as_root(
                            client, f"/usr/sbin/visudo -cf /etc/sudoers.d/{sa_name}", root_pass, logger=logger
                        )
                        if code_sudo == 0:
                            # Test connexion SA + sudo (avec retry automatique
                            # si sshd_config a AllowUsers qui bloque rootwarden,
                            # cas observe en prod sur serveurs hardenes).
                            def _try_sa_login():
                                sa_test = paramiko.SSHClient()
                                sa_test.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                sa_test.connect(
                                    hostname=m['ip'], port=m['port'], username=sa_name,
                                    pkey=pkey, look_for_keys=False, allow_agent=False, timeout=10
                                )
                                stdin_t, stdout_t, _ = sa_test.exec_command("sudo whoami", timeout=10)
                                whoami = stdout_t.read().decode().strip()
                                sa_test.close()
                                return whoami

                            whoami = ''
                            try:
                                whoami = _try_sa_login()
                            except paramiko.AuthenticationException:
                                # Auto-fix : sshd refuse peut-etre rootwarden via
                                # AllowUsers. On tente de patcher + retry.
                                modified, patch_msg = _ensure_sshd_allows_user(
                                    client, root_pass, sa_name, logger)
                                logger.info("Service account auth fail, patch sshd : %s", patch_msg)
                                if modified:
                                    try:
                                        whoami = _try_sa_login()
                                    except paramiko.AuthenticationException:
                                        logger.warning("Service account auth toujours refusee apres patch sshd")
                            if whoami == 'root':
                                sa_ok = True
                                conn3 = get_db_connection()
                                try:
                                    cur3 = conn3.cursor()
                                    cur3.execute(
                                        "UPDATE machines SET service_account_deployed = TRUE, "
                                        "service_account_deployed_at = NOW() WHERE id = %s",
                                        (m['id'],)
                                    )
                                    conn3.commit()
                                finally:
                                    conn3.close()
                    except Exception as sa_err:
                        logger.warning("Service account deploy failed for %s: %s", m['name'], sa_err)

                    if sa_ok:
                        r['message'] = 'Keypair + service account deployes OK'
                    else:
                        r['message'] = 'Keypair deployee OK (service account echoue - deployer manuellement)'

                    # Webhook notification
                    try:
                        from webhooks import send_webhook
                        send_webhook('deploy_complete', {
                            'title': f"Keypair deployee sur {m['name']}",
                            'message': f"Le serveur {m['name']} ({m['ip']}) utilise maintenant l'auth keypair Ed25519."
                                       + (" Service account rootwarden actif." if sa_ok else ""),
                        })
                    except Exception:
                        pass
                except Exception as test_err:
                    r['success'] = False
                    r['message'] = f'Cle deployee mais test echoue: {test_err}'

        except Exception as e:
            r['message'] = str(e)[:200]

        results.append(r)

    all_ok = all(r['success'] for r in results)
    return jsonify({'success': all_ok, 'results': results})


@bp.route('/revoke_service_account', methods=['POST'])
@require_api_key
@require_role(3)  # superadmin only - kill-switch
@threaded_route
def revoke_service_account():
    """
    Patch A04-INSEC-N5 (OWASP A04 Insecure Design) - kill-switch.

    Revoque le compte de service 'rootwarden' sur une ou plusieurs machines :
    - Supprime l'utilisateur Linux distant (userdel -r -f)
    - Retire le fichier /etc/sudoers.d/rootwarden
    - Marque service_account_deployed=0 en BDD
    - Audit log immutable

    Cas d'usage : compromission suspectee de la clé Ed25519 plateforme,
    rotation forcee, audit sortant. Superadmin only.

    Body JSON : {machine_ids: [int], reason: str}
    """
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    reason = (data.get('reason') or 'panic_revoke').strip()[:200]
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    from approvals import gate, AucunApprobateur
    # ══ E-201 : LA PORTE A QUATRE YEUX EST ENFIN INTERROGEE ═════════════════
    #
    # `Config.APPROVAL_ACTIONS` nommait cette action depuis toujours, et
    # `gate()` n'etait JAMAIS appele : l'approbation existait en configuration
    # seulement. Une garde declaree et jamais interrogee.
    #
    # LE SEUL `except` ATTRAPE LE REFUS MOTIVE, ET IL LE REND. Il n'avale
    # rien d'autre : sur les deux actions de `ACTIONS_SANS_REPLI`, `gate()`
    # LEVE aussi quand la base est indisponible, et cette levee-la traverse —
    # la porte qui echoue REFUSE. Attraper tout et continuer rendrait les deux
    # levees inutiles ; c'est le defaut des deux appels preexistants, dont le
    # `logger.debug` n'est meme pas journalise en exploitation.
    _uid, _role = get_current_user()
    try:
        _ap = gate('revoke_service_account', int(machine_ids[0]), 'compte de service',
                   {'machine_ids': machine_ids, 'reason': reason}, _uid, role=_role)
    except AucunApprobateur as _e:
        # Le blocage est LISIBLE : il dit sa cause et la marche a suivre. Une
        # fonctionnalite briquee en silence est pire qu'une fonctionnalite
        # bloquee qui s'explique.
        return jsonify({'success': False, 'approbateur_manquant': True,
                        'message': str(_e)}), 409
    if _ap is not None:
        return jsonify({
            'success': False, 'pending_approval': True, 'request_id': _ap['id'],
            'message': ("Demande d'approbation creee : un 2e administrateur doit valider "
                        "avant execution." if _ap['status'] == 'created'
                        else "Action deja en attente d'approbation par un 2e administrateur."),
        }), 202

    user_id, _ = get_current_user()
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        fmt = ','.join(['%s'] * len(machine_ids))
        cur.execute(
            f"SELECT id, name, ip, port, user, password, root_password, "
            f"service_account_deployed "
            f"FROM machines WHERE id IN ({fmt})", machine_ids
        )
        machines = cur.fetchall()
    finally:
        conn.close()

    import shlex as _shlex
    results = []
    for m in machines:
        # `sudoers_orphelin` est TOUJOURS present, meme a False : un champ
        # absent se lit « rien a dire », et ici il y a quelque chose a dire.
        r = {'machine_id': m['id'], 'name': m['name'], 'success': False,
             'message': '', 'sudoers_orphelin': False}
        try:
            ssh_pass = server_decrypt_password(m['password'])
            root_pass = server_decrypt_password(m['root_password'])
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger,
                             service_account=m.get('service_account_deployed', False)) as client:
                # Suppression user + sudoers (idempotent : si deja supprime, OK)
                # ══ L'ORDRE COMPTE, ET C'EST LE CORRECTIF CI-DESSUS QUI LE REND
                #    NECESSAIRE (E-218) ═══════════════════════════════════════
                #
                # Cette route se connecte desormais PAR le compte de service
                # quand il est deploye. Or `execute_as_root` en ce mode eleve
                # via `sudo sh -c`, donc en s'appuyant sur le fichier sudoers
                # que la premiere commande supprimait.
                #
                # L'elevation vaut pour toute l'invocation : la chaine se
                # terminait malgre tout. Mais un ARRET EN COURS DE ROUTE — le
                # delai de 30 s expire sur un `userdel -r` d'un gros repertoire,
                # une coupure reseau — laissait la machine dans un etat dont on
                # ne pouvait PLUS SORTIR : sudoers supprime, compte encore la,
                # `service_account_deployed` toujours a 1, et la tentative
                # suivante se reconnectant par un compte de service qui ne peut
                # plus eleverer. Sur une machine migree, `root_password` vaut
                # '' : aucun repli.
                #
                # Le retrait du sudoers passe donc EN DERNIER. Un echec partiel
                # laisse au pire un fichier orphelin — inerte, puisqu'aucun
                # compte ne porte plus ce nom — et la revocation reste rejouable.
                #
                # ══ ET LE VERDICT VERIFIE LES DEUX EFFETS ═══════════════════
                #
                # L'ancien ne controlait que l'absence du COMPTE. Il aurait donc
                # annonce une reussite en laissant le fichier sudoers en place :
                # un `rootwarden` recree a la main y aurait retrouve un
                # NOPASSWD: ALL que personne n'a accorde. Les `if` ne declenchent
                # pas `set -e`, contrairement a un `test … && exit`.
                cmd = (
                    "set -e; "
                    "userdel -r -f rootwarden 2>/dev/null || true; "
                    "rm -rf /home/rootwarden /var/spool/mail/rootwarden 2>/dev/null || true; "
                    "rm -f /etc/sudoers.d/rootwarden; "
                    "if id rootwarden 2>/dev/null; then exit 1; fi; "
                    "if [ -e /etc/sudoers.d/rootwarden ]; then exit 2; fi; "
                    "exit 0"
                )
                from ssh_utils import execute_as_root
                _, err_out, code = execute_as_root(client, cmd, root_pass, logger=logger, timeout=30)
                if code == 0:
                    # Update BDD
                    with get_db_connection() as conn2:
                        cur2 = conn2.cursor()
                        cur2.execute(
                            "UPDATE machines SET service_account_deployed = 0 WHERE id = %s",
                            (m['id'],)
                        )
                        conn2.commit()
                    r['success'] = True
                    r['message'] = 'Service account revoque'
                elif code == 2:
                    # ══ E-220 : LE DRAPEAU PASSE A 0, ET MA VERSION PRECEDENTE
                    #    DISAIT L'INVERSE ═════════════════════════════════════
                    #
                    # Elle le laissait a 1 « pour qu'un rejeu termine ». C'ETAIT
                    # FAUX, et le code juste au-dessus le prouve : on n'atteint
                    # `code == 2` qu'apres avoir passe `if id rootwarden`, donc
                    # LE COMPTE N'EXISTE PLUS. Avec le drapeau a 1, le rejeu
                    # ouvrirait sa session EN TANT QUE `rootwarden` — un compte
                    # supprime. Il ne s'authentifierait meme pas. Le chemin de
                    # rattrapage que ce commentaire promettait etait ferme.
                    #
                    # Et le drapeau a 1 AMPLIFIAIT le defaut ailleurs :
                    # `remove_ssh_password` (:1275) n'exige que ce drapeau. Elle
                    # aurait donc ACCEPTE de vider les deux mots de passe d'une
                    # machine dont le compte de service n'existe plus.
                    #
                    # A 0, les lecteurs redeviennent justes :
                    # `remove_ssh_password` REFUSE, et `has_keypair` cesse de
                    # compter un compte absent.
                    #
                    # ⚠ UNE TROISIEME RAISON FIGURAIT ICI ET ELLE ETAIT FAUSSE.
                    # Elle disait : « le rejeu passe par le compte NOMINAL, le
                    # seul qui puisse encore retirer le fichier ». Le rejeu part
                    # bien du compte nominal — mais il ne peut pas TERMINER.
                    # Releve par la session 5, verifie ici :
                    #
                    #   - meme avec le drapeau a 1, la connexion ABOUTIT :
                    #     `connect_ssh` attrape `AuthenticationException` sur sa
                    #     tentative 0 et se replie sur la cle de plateforme du
                    #     compte nominal (`ssh_utils.py:250`) ;
                    #   - ce qui echoue n'est donc pas l'authentification mais
                    #     l'ELEVATION : `_rootwarden_auth_method` vaut alors
                    #     'keypair', le court-circuit NOPASSWD ne s'applique pas,
                    #     et `root_password` est envoye — VIDE sur une machine
                    #     dont la migration est achevee.
                    #
                    # Le rejeu est donc ferme a 0 COMME a 1. Le drapeau reste a 0
                    # pour les deux premieres raisons, qui suffisent.
                    #
                    # ══ CE QUI EN DECOULE, ET QUI EST PIRE QUE « INCOMPLET » ══
                    #
                    # Sur une machine migree, AUCUN chemin du produit ne retire
                    # ce fichier. La raison a d'abord ete mal ecrite ici, et la
                    # vraie est plus simple et plus large :
                    #
                    #   AUCUNE routine du produit ne balaie `/etc/sudoers.d/` a
                    #   la recherche de fichiers sans compte correspondant.
                    #
                    # L'explication precedente accusait l'exception
                    # `if username == _RESERVED_SA_USER` de
                    # `_purge_legacy_sudoers`. Mesure : cette fonction n'est
                    # appelee que depuis `add_to_sudoers` et
                    # `remove_from_sudoers`, TOUJOURS avec le nom d'un
                    # utilisateur GERE par le portail. Elle ne regarde donc
                    # jamais `/etc/sudoers.d/rootwarden`, et son exception est un
                    # garde-fou de COLLISION DE NOMS — le cas ou un utilisateur
                    # du portail s'appellerait `rootwarden`. Elle ne protege pas
                    # l'orphelin : elle ne le croise pas.
                    #
                    # Le fichier survit parce que PERSONNE NE LE CHERCHE, pas
                    # parce qu'une regle le protege. Les deux autres maillons
                    # tiennent : le rejeu ne peut pas elever, et le seul geste
                    # qui l'ecrase — `deploy_service_account` — le REMPLACE en
                    # recreant le compte, il ne le retire pas.
                    # L'etat n'est ni transitoire ni auto-reparant : IL EST
                    # PERMANENT. Sur une machine NON migree (`root_password`
                    # present) le rejeu aboutit — le blocage est propre a l'etat
                    # vers lequel toute la page pousse.
                    #
                    # ══ UN CHANGEMENT DE COMPORTEMENT SUR K4, NOMME ══════════
                    #
                    # `configure_servers.py:758` : `if not use_sa:
                    # ensure_sudo_installed(...)`. Le drapeau a 0 fait donc
                    # EXECUTER cette etape au deploiement suivant. Installer
                    # `sudo` la ou il est deja present est sans effet, et si
                    # l'elevation manque l'echec est precoce — mais c'est un
                    # comportement qui change, et il vaut mieux l'ecrire que le
                    # decouvrir.
                    #
                    # ══ CE QUI RESTE, ET QUI N'A PAS DE PORTEUR EN BASE ══════
                    #
                    # Un `/etc/sudoers.d/rootwarden` orphelin : `NOPASSWD: ALL`
                    # pour un compte qui n'existe plus. Inerte tant que rien ne
                    # recree ce nom — et le seul purgeur du produit
                    # (`configure_servers._purge_legacy_sudoers`) l'EXCLUT
                    # explicitement, exception ecrite pour proteger un compte
                    # vivant et qui survit a sa disparition parce qu'elle ne la
                    # teste pas.
                    #
                    # Le nommer ici est donc le seul signalement qui existe. Une
                    # colonne serait le vrai porteur, mais c'est une migration
                    # sur `machines`, table de PRODUCTION : arbitrage exploitant,
                    # pas effet de bord d'un correctif.
                    with get_db_connection() as conn2:
                        cur2 = conn2.cursor()
                        cur2.execute(
                            "UPDATE machines SET service_account_deployed = 0 WHERE id = %s",
                            (m['id'],)
                        )
                        conn2.commit()
                    r['sudoers_orphelin'] = True
                    r['message'] = (
                        "Compte de service supprime, mais /etc/sudoers.d/rootwarden SUBSISTE : "
                        "NOPASSWD: ALL orphelin. Aucun geste du produit ne le retirera "
                        "(exception de purge). A retirer a la main sur la machine.")
                    logger.warning(
                        "revoke_service_account : sudoers ORPHELIN sur %s (machine_id=%s) — "
                        "NOPASSWD: ALL sans compte porteur, retrait manuel requis",
                        m['name'], m['id'])
                else:
                    r['message'] = (err_out or '')[-300:].strip() or f'exit={code}'
        except Exception as e:
            logger.exception("revoke_service_account %s : %s", m['name'], e)
            r['message'] = str(e)[:200]

        # Audit log immutable (HMAC chain cote PHP, ici juste user_logs INSERT)
        try:
            with get_db_connection() as conn3:
                cur3 = conn3.cursor()
                cur3.execute(
                    "INSERT INTO user_logs (user_id, action, created_at) VALUES (%s, %s, NOW())",
                    (user_id, f"[panic] revoke_service_account machine={_shlex.quote(m['name'])} "
                              f"reason={_shlex.quote(reason)} ok={r['success']}"
                              f"{' SUDOERS_ORPHELIN' if r['sudoers_orphelin'] else ''}")
                )
                conn3.commit()
        except Exception:
            pass

        results.append(r)

    return jsonify({
        'success': all(r['success'] for r in results),
        'count': len(results),
        'results': results,
    })


@bp.route('/deploy_service_account', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : deploiement compte service NOPASSWD:ALL reserve admin
@require_machine_access
@threaded_route
def deploy_service_account():
    """
    Deploie le compte de service 'rootwarden' sur les serveurs selectionnes.
    Cree l'utilisateur Linux, deploie la keypair, configure sudoers NOPASSWD:ALL.
    Body JSON : {machine_ids: [int]}
    """
    from ssh_key_manager import get_platform_public_key, get_platform_private_key
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    pubkey = get_platform_public_key()
    if not pubkey:
        return jsonify({'success': False, 'message': 'Keypair plateforme non generee'}), 500

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        fmt = ','.join(['%s'] * len(machine_ids))
        cur.execute(
            f"SELECT id, name, ip, port, user, password, root_password, "
            f"service_account_deployed "
            f"FROM machines WHERE id IN ({fmt})", machine_ids
        )
        machines = cur.fetchall()
    finally:
        conn.close()

    results = []
    for m in machines:
        r = {'machine_id': m['id'], 'name': m['name'], 'success': False, 'message': ''}
        ssh_pass = server_decrypt_password(m['password'])
        root_pass = server_decrypt_password(m['root_password'])

        try:
            # Connexion via keypair ou password existant
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger,
                             service_account=m.get('service_account_deployed', False)) as client:
                sa_name = 'rootwarden'

                # 0. Installer sudo si absent
                try:
                    ensure_sudo_installed(client, root_pass, logger=logger)
                except Exception as sudo_err:
                    logger.warning("Installation sudo echouee pour %s: %s", m['name'], sudo_err)

                # Commandes separees (pas de && - su -c casse le chainage)
                import base64 as _b64

                # 1. Creer l'utilisateur rootwarden s'il n'existe pas
                execute_as_root(client, f"id {sa_name} >/dev/null 2>&1 || /usr/sbin/useradd -r -m -s /bin/bash {sa_name}", root_pass, logger=logger)
                execute_as_root(client, f"chown {sa_name}:{sa_name} /home/{sa_name}", root_pass, logger=logger)

                # 2. Deployer la keypair plateforme
                key_b64 = _b64.b64encode(pubkey.encode()).decode()
                execute_as_root(client, f"mkdir -p /home/{sa_name}/.ssh", root_pass, logger=logger)
                execute_as_root(client, f"chmod 700 /home/{sa_name}/.ssh", root_pass, logger=logger)
                execute_as_root(client, f"printf %s {key_b64} | base64 -d > /home/{sa_name}/.ssh/authorized_keys", root_pass, logger=logger)
                execute_as_root(client, f"chmod 600 /home/{sa_name}/.ssh/authorized_keys", root_pass, logger=logger)
                execute_as_root(client, f"chown -R {sa_name}:{sa_name} /home/{sa_name}/.ssh", root_pass, logger=logger)

                # 3. Configurer sudoers NOPASSWD:ALL
                execute_as_root(client, f"echo '{sa_name} ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sa_name}", root_pass, logger=logger)
                execute_as_root(client, f"chmod 440 /etc/sudoers.d/{sa_name}", root_pass, logger=logger)

                # 4. Valider la syntaxe sudoers
                out, err, code = execute_as_root(
                    client, f"/usr/sbin/visudo -cf /etc/sudoers.d/{sa_name}", root_pass, logger=logger
                )
                if code != 0:
                    r['message'] = f'Validation sudoers echouee: {err}'
                    results.append(r)
                    continue

            # 5. Test : connexion en tant que rootwarden via keypair + sudo whoami
            try:
                pkey = get_platform_private_key()
                test_client = paramiko.SSHClient()
                test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                test_client.connect(
                    hostname=m['ip'], port=m['port'], username='rootwarden',
                    pkey=pkey, look_for_keys=False, allow_agent=False, timeout=10
                )
                stdin_t, stdout_t, stderr_t = test_client.exec_command("sudo whoami", timeout=10)
                whoami = stdout_t.read().decode().strip()
                test_client.close()

                if whoami != 'root':
                    r['message'] = f"Test sudo echoue: whoami={whoami}"
                    results.append(r)
                    continue
            except Exception as test_err:
                r['message'] = f"Test connexion service account echoue: {test_err}"
                results.append(r)
                continue

            # 6. Marquer en BDD
            conn2 = get_db_connection()
            try:
                cur2 = conn2.cursor()
                cur2.execute(
                    "UPDATE machines SET service_account_deployed = TRUE, "
                    "service_account_deployed_at = NOW() WHERE id = %s",
                    (m['id'],)
                )
                conn2.commit()
            finally:
                conn2.close()

            r['success'] = True
            r['message'] = f'Compte {sa_name} deploye et teste OK (sudo root)'

            # Webhook notification
            try:
                from webhooks import send_webhook
                send_webhook('deploy_complete', {
                    'title': f"Service account deploye sur {m['name']}",
                    'message': f"Le serveur {m['name']} ({m['ip']}) dispose maintenant du compte rootwarden (NOPASSWD sudo).",
                })
            except Exception:
                pass

        except Exception as e:
            r['message'] = str(e)[:200]

        results.append(r)

    all_ok = all(r['success'] for r in results)
    return jsonify({'success': all_ok, 'results': results})


@bp.route('/test_platform_key', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def test_platform_key():
    """Teste la connexion keypair sur un serveur (sans password)."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT ip, port, user, name, platform_key_deployed FROM machines WHERE id = %s",
            (int(machine_id),)
        )
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    # Label defensif : certaines machines ont name=NULL ou vide en BDD (import
    # historique ou edit ulterieur). Sans ce fallback, le toast affiche
    # "Connexion keypair OK sur " (nom vide) - bug remonte v1.18.0.
    label = (m.get('name') or '').strip() or f"{m['ip']}:{m['port']}"

    # Si la keypair n'a jamais ete deployee, message clair plutot qu'erreur
    # paramiko illisible. Le bouton "Tester" est visible meme avant deploiement.
    if not m.get('platform_key_deployed'):
        return jsonify({
            'success': False,
            'auth_method': 'none',
            'message': f"Cle non deployee sur {label} - clique 'Deployer' d'abord."
        })

    try:
        from ssh_key_manager import get_platform_private_key
        pkey = get_platform_private_key()
        if not pkey:
            return jsonify({'success': False, 'auth_method': 'none', 'message': 'Keypair non generee'})

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=m['ip'], port=m['port'], username=m['user'], pkey=pkey, look_for_keys=False, allow_agent=False, timeout=10)
        client.close()
        return jsonify({'success': True, 'auth_method': 'keypair', 'message': f"Connexion keypair OK sur {label}"})
    except paramiko.AuthenticationException:
        return jsonify({
            'success': False,
            'auth_method': 'password',
            'message': f"Authentification keypair refusee sur {label} - re-deploie la cle."
        })
    except Exception as e:
        return jsonify({'success': False, 'auth_method': 'password', 'message': f"Keypair echouee sur {label} : {e}"})


@bp.route('/remove_ssh_password', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : effacement des credentials SSH reserve admin
@require_machine_access
@threaded_route
def remove_ssh_password():
    """Supprime les passwords SSH et root d'un serveur (necessite service account deploye)."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT platform_key_deployed, service_account_deployed, name FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
        if not m:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404
        if not m.get('service_account_deployed'):
            return jsonify({'success': False, 'message': 'Service account non deploye - impossible de supprimer les passwords'}), 400

        cur.execute(
            "UPDATE machines SET password = '', root_password = '', ssh_password_required = FALSE WHERE id = %s",
            (int(machine_id),)
        )
        conn.commit()
        logger.info("Passwords SSH + root supprimes pour %s (id=%s)", m['name'], machine_id)
        return jsonify({'success': True, 'message': f"Passwords SSH + root supprimes pour {m['name']}"})
    finally:
        conn.close()


@bp.route('/reenter_ssh_password', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : reecriture des credentials SSH reserve admin
@require_machine_access
@threaded_route
def reenter_ssh_password():
    """Re-saisit un password SSH (rollback apres suppression)."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    password = data.get('password', '')
    if not machine_id or not password:
        return jsonify({'success': False, 'message': 'machine_id et password requis'}), 400

    encrypted = encryption.encrypt_password(password)
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE machines SET password = %s, ssh_password_required = TRUE WHERE id = %s", (encrypted, int(machine_id)))
        conn.commit()
        logger.info("Password SSH re-saisi pour machine %s", machine_id)
        return jsonify({'success': True, 'message': 'Password SSH restaure'})
    finally:
        conn.close()


@bp.route('/regenerate_platform_key', methods=['POST'])
@require_api_key
@require_role(3)
@threaded_route
def regenerate_platform_key_route():
    """Regenere la keypair plateforme. ATTENTION : necessite re-deploiement."""
    from approvals import gate, AucunApprobateur
    # ══ E-201 : LA PORTE A QUATRE YEUX EST ENFIN INTERROGEE ═════════════════
    #
    # `Config.APPROVAL_ACTIONS` nommait cette action depuis toujours, et
    # `gate()` n'etait JAMAIS appele : l'approbation existait en configuration
    # seulement. Une garde declaree et jamais interrogee.
    #
    # LE SEUL `except` ATTRAPE LE REFUS MOTIVE, ET IL LE REND. Il n'avale
    # rien d'autre : sur les deux actions de `ACTIONS_SANS_REPLI`, `gate()`
    # LEVE aussi quand la base est indisponible, et cette levee-la traverse —
    # la porte qui echoue REFUSE. Attraper tout et continuer rendrait les deux
    # levees inutiles ; c'est le defaut des deux appels preexistants, dont le
    # `logger.debug` n'est meme pas journalise en exploitation.
    _uid, _role = get_current_user()
    try:
        _ap = gate('regenerate_platform_key', 0, 'flotte',
                   {'portee': 'flotte entiere'}, _uid, role=_role)
    except AucunApprobateur as _e:
        # Le blocage est LISIBLE : il dit sa cause et la marche a suivre. Une
        # fonctionnalite briquee en silence est pire qu'une fonctionnalite
        # bloquee qui s'explique.
        return jsonify({'success': False, 'approbateur_manquant': True,
                        'message': str(_e)}), 409
    if _ap is not None:
        return jsonify({
            'success': False, 'pending_approval': True, 'request_id': _ap['id'],
            'message': ("Demande d'approbation creee : un 2e administrateur doit valider "
                        "avant execution." if _ap['status'] == 'created'
                        else "Action deja en attente d'approbation par un 2e administrateur."),
        }), 202

    from ssh_key_manager import regenerate_platform_key
    regenerate_platform_key()
    # Marquer tous les serveurs comme non-deployes
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE machines SET platform_key_deployed = FALSE, platform_key_deployed_at = NULL")
        conn.commit()
    finally:
        conn.close()
    from ssh_key_manager import get_platform_public_key
    return jsonify({'success': True, 'message': 'Keypair regeneree - re-deploiement requis', 'public_key': get_platform_public_key()})


@bp.route('/server_users_inventory', methods=['GET'])
@require_api_key
@require_role(2)  # aligne sur la page portee, qui exige role:2 (voir ComptesDistantsController)
@require_machine_access
@threaded_route
def server_users_inventory():
    """Rend l'inventaire des comptes distants d'une machine, AVEC ses drapeaux.

    ══ POURQUOI UNE ROUTE, ET PAS UNE COLONNE ═══════════════════════════════

    E-200. `nom_valide` et `motif_invalide` sont CALCULES (E-199), pas stockes :
    `server_user_inventory` porte quinze colonnes et aucune ne les nomme. Ils
    n'existaient donc qu'au RETOUR d'un scan — et la page rend son inventaire
    depuis la base, au chargement.

    Consequence : un compte nomme `..` restait invisible tant que personne
    n'avait relance un scan, c'est-a-dire precisement dans l'etat ou l'on en a
    le plus besoin.

    Persister le verdict aurait demande une migration, et surtout l'aurait rendu
    PERIMABLE : la colonne aurait garde le verdict du scan qui l'a posee, pendant
    que la regle, elle, peut changer. C'est la classe qu'E-195, E-196 et E-197
    ont coutee ce jour — une regle recopiee finit par diverger de celle qui
    decide. Ici la regle est appliquee A LA LECTURE, donc elle ne peut pas
    diverger d'elle-meme.

    ══ CETTE ROUTE NE JOINT AUCUNE MACHINE ══════════════════════════════════

    Elle lit la base et applique `_motif_nom_invalide`. Rien d'autre. C'est ce
    qui la distingue de `/scan_server_users`, qui ouvre une session SSH et reste
    un GESTE. Une page qui joint le parc en s'ouvrant a deja coute assez cher au
    chantier (`health_check.php`).

    ══ LE TOTAL VIENT DU SERVEUR, PAS DE LA LONGUEUR DE LA LISTE ════════════

    `total` est un `COUNT(*)`, jamais `len(comptes)`. La regle d'ecran est que
    le TOTAL gagne quand il contredit la liste : il compte tout, la liste ne
    porte que ce qui a voyage. Rendre `len()` ferait afficher un nombre PLUS
    PETIT que la realite le jour ou une borne apparaitrait — la direction
    dangereuse. Aucune borne n'existe aujourd'hui ; l'invariant tient d'avance.

    ══ `@require_machine_access` EST INERTE ICI, ET C'EST DIT ═══════════════

    `check_machine_access` rend `True` sans condition des le role 2
    (`helpers.py:299`), donc ce decorateur ne contraint rien sur une route
    gardee `@require_role(2)`. Il est conserve DELIBEREMENT, et pour une seule
    raison : le jour ou quelqu'un abaisserait le role pour ouvrir cette lecture
    plus largement, il deviendrait porteur — et cette route enumere des noms de
    comptes. Il n'est pas la pour proteger aujourd'hui ; il est la pour que
    l'abaissement du role ne soit pas silencieusement une divulgation.
    """
    machine_id = request.args.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400
    # Le cast vit HORS du `try` : une faute de la requete se refuse en 400,
    # elle ne casse pas en 500 (E-164).
    try:
        machine_id = int(machine_id)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'machine_id doit etre un nombre'}), 400

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT COUNT(*) AS n FROM server_user_inventory WHERE machine_id = %s",
                        (machine_id,))
            total = int((cur.fetchone() or {}).get('n', 0))

            cur.execute("""
                SELECT id, username, uid, home_dir, shell, status, managed_by,
                       keys_count, has_platform_key, first_seen_at, last_seen_at,
                       reviewed_by, reviewed_at, notes
                FROM server_user_inventory
                WHERE machine_id = %s
                ORDER BY username
            """, (machine_id,))
            comptes = cur.fetchall()

        for c in comptes:
            for k in ('first_seen_at', 'last_seen_at', 'reviewed_at'):
                if c.get(k) and hasattr(c[k], 'isoformat'):
                    c[k] = c[k].isoformat()
            # E-199 : le drapeau est RENSEIGNE, jamais omis — un champ absent se
            # rend comme une liste vide et ne se distingue pas de « rien a dire ».
            motif = _motif_nom_invalide(c.get('username'))
            c['nom_valide'] = motif is None
            c['motif_invalide'] = motif

        # E-199, condition 3 : `en_attente` appelle un TRAVAIL, donc une ligne
        # qui ne peut recevoir aucun geste n'y entre pas. `invalides_count` est
        # rendu a cote plutot que soustrait — les deux nombres ne demandent pas
        # le meme geste.
        return jsonify({
            'success': True,
            'machine_id': machine_id,
            'total': total,
            'comptes': comptes,
            'en_attente': sum(1 for c in comptes
                              if c['status'] == 'pending_review' and c['nom_valide']),
            # Toujours present, meme a zero.
            'invalides_count': sum(1 for c in comptes if not c['nom_valide']),
        })
    except Exception as e:
        logger.error("server_users_inventory(%s): %s", machine_id, e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/scan_server_users', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : enumeration des comptes distants reservee admin
@require_machine_access
@threaded_route
def scan_server_users():
    """Scanne les utilisateurs presents sur un serveur distant."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    mid = int(machine_id)
    ssh_pass = server_decrypt_password(m['password'])

    root_pass = server_decrypt_password(m.get('root_password') or '')

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
            # 1. Lister TOUS les users de /etc/passwd (no privilege requis).
            cmd = "awk -F: '{print $1\":\"$3\":\"$6\":\"$7}' /etc/passwd"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
            passwd_output = stdout.read().decode('utf-8', errors='replace')
            # E-183. Le code de sortie de CETTE lecture decide de la purge des
            # « fantomes », plus bas. Il n'etait jamais lu — et `recv_exit_status`
            # n'apparaissait pas une seule fois dans ce fichier.
            passwd_rc = stdout.channel.recv_exit_status()

            # 2. Dump des authorized_keys.
            # Strategie en 2 etages :
            #   a) Tente execute_as_root -> dump TOUS les users (root + home prot).
            #   b) En parallele : `cat ~/.ssh/authorized_keys` en simple user
            #      pour AU MOINS recuperer les cles du user connecte (ex: ses
            #      cles a lui dans ~/ qu'il peut lire sans sudo). Ainsi si
            #      root_password absent ou sudo refuse, on a quand meme le user.
            # Resultat : on merge les 2 dumps -- root prioritaire si il a vu.
            # IMPORTANT : `printf '\\n'` apres `cat` car les authorized_keys
            # ecrits par RootWarden via `printf '%s'` n'ont PAS de newline
            # finale -> le marqueur ###ENDUSER### colle sur la derniere cle,
            # le parser ne le voit pas -> les cles de l'user ne sont jamais
            # enregistrees. Bug observe sur 4 users (rootwarden, gbroussier,
            # kduplouy, cleopatre) v1.19.0.
            dump_script = (
                "awk -F: '{print $6\":\"$1}' /etc/passwd | "
                "while IFS=: read home user; do "
                "  ak=\"$home/.ssh/authorized_keys\"; "
                "  [ -r \"$ak\" ] || continue; "
                "  echo \"###USER:$user###\"; "
                "  cat \"$ak\"; "
                "  printf '\\n'; "
                "  echo \"###ENDUSER###\"; "
                "done"
            )
            ak_dump_root = ''
            # E-187 : UN DRAPEAU PAR LECTURE, PAS UN PAR FONCTION.
            # `scan_concluant` (E-183) mesure la lecture de `/etc/passwd`. Il ne
            # dit RIEN de ces deux dumps-ci, qui sont des lectures entierement
            # differentes — et ce sont elles qui alimentent la purge des cles et
            # la colonne `keys_count`.
            dump_root_ok = False
            try:
                ak_dump_root, _err, _code = execute_as_root(client, dump_script, root_pass,
                                                            logger=logger, timeout=30)
                # `_code` etait capture et JAMAIS lu. C'etait la seule occurrence
                # de ce nom dans la fonction : la valeur qui ferme le trou etait
                # deja la, a portee d'un `if`.
                dump_root_ok = (_code == 0)
                if not dump_root_ok:
                    logger.warning("scan_server_users(%s): dump root authorized_keys en ECHEC (code=%s) -- fallback simple-user", mid, _code)
                elif not ak_dump_root.strip():
                    logger.info("scan_server_users(%s): dump root vide (probable absence de fichiers ou silent fail). Fallback simple-user.", mid)
            except Exception as _e:
                logger.warning("scan_server_users(%s): dump root authorized_keys echoue (%s) -- fallback simple-user", mid, _e)

            # Fallback simple-user : recupere AU MOINS authorized_keys du user
            # connecte (et tout home world-readable, rare). Pas de filtre awk
            # de tous les users car cat /home/X/.ssh/* en simple user echoue
            # pour les autres -> on cible le user de connexion uniquement.
            ak_dump_user = ''
            dump_user_ok = False
            try:
                user_script = (
                    "ak=\"$HOME/.ssh/authorized_keys\"; "
                    "if [ -r \"$ak\" ]; then "
                    "  echo \"###USER:$(whoami)###\"; "
                    "  cat \"$ak\"; "
                    "  printf '\\n'; "
                    "  echo \"###ENDUSER###\"; "
                    "fi"
                )
                _stdin, _stdout, _stderr = client.exec_command(user_script, timeout=10)
                ak_dump_user = _stdout.read().decode('utf-8', errors='replace')
                # E-187 : ce code de sortie n'etait meme pas OBTENU.
                dump_user_ok = (_stdout.channel.recv_exit_status() == 0)
            except Exception as _e:
                logger.warning("scan_server_users(%s): dump simple-user echoue (%s)", mid, _e)

            # E-187 : AUCUNE des deux lectures de cles n'a abouti ?
            # Alors on n'a AUCUNE donnee de cles, et tout ce qui en decoule est
            # une invention : `keys_count = 0` sur chaque compte, et l'ensemble
            # `seen_keys` vide, dont la difference vaut TOUTES les cles connues.
            #
            # Ce drapeau ne porte que sur le cas NON AMBIGU — un code de sortie
            # non nul, ou une exception. Le cas « code nul mais dump vide » est
            # DELIBEREMENT laisse de cote : la boucle du script sort en 0 meme
            # sans rien emettre, donc un dump vide est aussi ce que rend une
            # machine qui n'a reellement aucune cle. Les distinguer demande une
            # mesure sur une machine a zero cle (Test-Server-Debian), attribuee
            # a la session 6. Trancher sans elle reproduirait E-183 dans l'autre
            # sens : purger a tort une machine qui n'a legitimement rien.
            cles_lues = dump_root_ok or dump_user_ok
            if not cles_lues:
                logger.warning(
                    "scan_server_users(%s): AUCUNE lecture de cles n'a abouti "
                    "(root=%s, simple-user=%s) — `keys_count` et la purge des cles "
                    "sont ABANDONNEES, l'inventaire des cles est conserve tel quel",
                    mid, dump_root_ok, dump_user_ok)

            # Parse les 2 dumps. Root gagne en cas de doublon (dump_root est
            # autoritatif). Le simple-user comble les trous.
            keys_root = _parse_authorized_keys_dump(ak_dump_root)
            keys_user = _parse_authorized_keys_dump(ak_dump_user)
            keys_by_user = dict(keys_user)  # base = user
            keys_by_user.update(keys_root)  # root ecrase si present
            logger.info("scan_server_users(%s): %d user(s) avec cles (root=%d, fallback=%d)",
                        mid, len(keys_by_user), len(keys_root), len(keys_user))

            from ssh_key_manager import get_platform_public_key
            platform_pubkey = get_platform_public_key() or ''
            platform_fragment = platform_pubkey.split()[1] if len(platform_pubkey.split()) > 1 else ''

            scanned_users = []
            for line in passwd_output.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.strip().split(':')
                if len(parts) < 4:
                    continue
                uname, uid_str, home, shell = parts[0], parts[1], parts[2], parts[3]
                uid = int(uid_str) if uid_str.isdigit() else 0

                if not re.match(r'^/[a-zA-Z0-9/_.-]+$', home):
                    continue

                user_keys = keys_by_user.get(uname, [])
                # Marque has_platform_key si le fragment de cle plateforme y est
                for k in user_keys:
                    k['is_platform'] = bool(platform_fragment and platform_fragment in k.get('data', ''))
                has_platform = any(k['is_platform'] for k in user_keys)

                scanned_users.append({
                    'name': uname,
                    'uid': uid,
                    'home': home,
                    'shell': shell,
                    'keys_count': len(user_keys),
                    'has_platform_key': has_platform,
                    'keys': user_keys,
                })

        # Peupler server_user_inventory
        conn_inv = get_db_connection()
        try:
            cur = conn_inv.cursor(dictionary=True)

            # Charger l'inventaire existant
            cur.execute("SELECT username, status FROM server_user_inventory WHERE machine_id = %s", (mid,))
            existing = {r['username']: r['status'] for r in cur.fetchall()}

            # Users RootWarden autorises
            cur.execute(
                "SELECT u.name FROM users u JOIN user_machine_access uma ON u.id = uma.user_id "
                "WHERE uma.machine_id = %s AND u.active = 1", (mid,)
            )
            rw_authorized = {r['name'] for r in cur.fetchall()}

            # Comptes systeme proteges
            sys_users = {'root', 'daemon', 'bin', 'sys', 'sync', 'nobody',
                         'www-data', 'sshd', 'rootwarden', m['user']}

            for u in scanned_users:
                uname = u['name']
                if uname in existing:
                    # Mettre a jour les infos (last_seen, keys)
                    #
                    # E-187 : les colonnes de CLES ne s'ecrivent que si une des
                    # deux lectures de cles a abouti. Sinon `keys_count` vaudrait
                    # 0 sur chaque compte — l'inventaire affirmerait qu'aucun
                    # compte de la machine ne porte de cle, ce qui est la donnee
                    # meme sur laquelle K4 raisonne. Les colonnes d'identite
                    # (uid, home, shell) viennent de `/etc/passwd`, deja garde
                    # par `scan_concluant` : elles restent ecrites.
                    if cles_lues:
                        cur.execute("""
                            UPDATE server_user_inventory
                            SET uid = %s, home_dir = %s, shell = %s, keys_count = %s,
                                has_platform_key = %s, last_seen_at = NOW()
                            WHERE machine_id = %s AND username = %s
                        """, (u['uid'], u['home'], u['shell'], u['keys_count'],
                              u['has_platform_key'], mid, uname))
                    else:
                        cur.execute("""
                            UPDATE server_user_inventory
                            SET uid = %s, home_dir = %s, shell = %s, last_seen_at = NOW()
                            WHERE machine_id = %s AND username = %s
                        """, (u['uid'], u['home'], u['shell'], mid, uname))
                else:
                    # Nouveau user - classifier automatiquement
                    shell_basename = (u.get('shell') or '').rsplit('/', 1)[-1].lower()
                    is_nologin_shell = shell_basename in ('nologin', 'false', 'sync', 'halt', 'shutdown')
                    if uname in sys_users or uname.lower() in sys_users:
                        auto_status = 'excluded'
                        auto_managed = 'manual'
                        auto_notes = 'Compte systeme (auto-classifie)'
                    elif is_nologin_shell:
                        auto_status = 'excluded'
                        auto_managed = 'manual'
                        auto_notes = f'Compte sans login (shell={u["shell"]}) - auto-classifie'
                    elif uname in rw_authorized:
                        auto_status = 'managed'
                        auto_managed = 'rootwarden'
                        auto_notes = 'Utilisateur RootWarden (auto-classifie)'
                    else:
                        auto_status = 'pending_review'
                        auto_managed = None
                        auto_notes = None

                    cur.execute("""
                        INSERT INTO server_user_inventory
                            (machine_id, username, uid, home_dir, shell, keys_count,
                             has_platform_key, status, managed_by, notes)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (mid, uname, u['uid'], u['home'], u['shell'], u['keys_count'],
                          u['has_platform_key'], auto_status, auto_managed, auto_notes))

            # Nettoyage des "fantomes" : users qui existaient en inventaire
            # mais qui ne sont plus sur le serveur (userdel manuel depuis une
            # autre console, compte systeme supprime, etc.). Sans ca, un
            # compte comme `cleopatre` reste visible a vie dans l'UI.
            # On identifie les fantomes = rows en DB non-touchees par ce scan.
            #
            # ══ E-183 : LE SENS DU REPLI CHANGE, ET C'EST DELIBERE ═══════════
            #
            # AVANT : « je n'ai rien vu » signifiait « il n'y a plus rien ».
            # APRES : « je n'ai rien vu » signifie « je ne sais pas ».
            #
            # Le code de sortie de la lecture de `/etc/passwd` n'etait jamais
            # lu. Une lecture qui echoue ou qui rend une sortie vide donnait
            # donc `scanned_users == []`, donc TOUTES les lignes d'inventaire
            # de la machine devenaient des « fantomes », donc etaient
            # SUPPRIMEES — avec `server_user_ssh_keys` dans la foulee. Un
            # incident SSH passager effacait 72 lignes d'inventaire et 20 cles,
            # et le journal l'annoncait comme un nettoyage reussi.
            #
            # C'est la forme DESTRUCTRICE de la classe « l'etat persiste ne suit
            # pas le verdict » (E-90, E-165) : pas « ecrire un etat faux » mais
            # « effacer un etat vrai ».
            #
            # L'asymetrie tranche : au pire, ce garde laisse un compte mort
            # visible a l'ecran — le defaut meme que le commentaire ci-dessus
            # voulait eviter, et qui se corrige au scan suivant. Sans lui, la
            # donnee est perdue. Et c'est cet inventaire qui fonde l'arbitrage
            # de K4 : un deploiement de cles raisonne dessus.
            #
            # Le repli est NOMME dans le journal, pas silencieux : remplacer un
            # faux succes par une absence ne serait qu'un autre mensonge.
            scanned_usernames = {u['name'] for u in scanned_users}
            scan_concluant = (passwd_rc == 0 and bool(scanned_users))
            if not scan_concluant:
                logger.warning(
                    "scan_server_users(%s): scan NON CONCLUANT (code=%s, %d compte(s) lu(s)) — "
                    "purge des fantomes ABANDONNEE, l'inventaire (%d ligne(s)) est conserve tel quel",
                    mid, passwd_rc, len(scanned_users), len(existing))
            ghost_usernames = ([u for u in existing.keys() if u not in scanned_usernames]
                               if scan_concluant else [])
            if ghost_usernames:
                placeholders = ','.join(['%s'] * len(ghost_usernames))
                cur.execute(
                    f"DELETE FROM server_user_inventory "
                    f"WHERE machine_id = %s AND username IN ({placeholders})",
                    (mid, *ghost_usernames))
                logger.info("scan_server_users(%s): %d fantome(s) purge(s) : %s",
                            mid, len(ghost_usernames), ','.join(ghost_usernames))

            conn_inv.commit()

            # Inventaire detaille des cles SSH (table server_user_ssh_keys
            # depuis migration 044). On upsert chaque cle vue ; les cles
            # disparues entre 2 scans sont supprimees -> drift detection
            # gratuite via ALTER de last_seen_at.
            try:
                seen_keys = set()  # {(username, fingerprint)}
                for u in scanned_users:
                    for k in u.get('keys', []):
                        seen_keys.add((u['name'], k['fingerprint']))
                        cur.execute("""
                            INSERT INTO server_user_ssh_keys
                                (machine_id, username, key_type, fingerprint_sha256,
                                 comment, is_platform_key)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                                key_type = VALUES(key_type),
                                comment = VALUES(comment),
                                is_platform_key = VALUES(is_platform_key),
                                last_seen_at = CURRENT_TIMESTAMP
                        """, (mid, u['name'], k['type'], k['fingerprint'],
                              k.get('comment'), 1 if k.get('is_platform') else 0))

                # Supprimer les cles qui n'ont pas ete revues sur ce scan
                cur.execute(
                    "SELECT username, fingerprint_sha256 FROM server_user_ssh_keys "
                    "WHERE machine_id = %s", (mid,))
                existing_keys = {(r['username'], r['fingerprint_sha256'])
                                 for r in cur.fetchall()}
                # E-183 puis E-187 : `seen_keys` depend de DEUX lectures —
                # celle de `/etc/passwd` (qui donne les comptes) et celle des
                # `authorized_keys` (qui donne les cles). Il faut les DEUX, et
                # c'est le defaut qu'E-183 avait laisse ouvert : `scan_concluant`
                # seul laissait une purge complete partir quand le dump des cles
                # avait echoue.
                stale = ((existing_keys - seen_keys)
                         if (scan_concluant and cles_lues) else set())
                if stale:
                    for uname, fp in stale:
                        cur.execute(
                            "DELETE FROM server_user_ssh_keys "
                            "WHERE machine_id = %s AND username = %s "
                            "AND fingerprint_sha256 = %s",
                            (mid, uname, fp))
                    logger.info("scan_server_users(%s): %d cle(s) SSH retiree(s)",
                                mid, len(stale))
                conn_inv.commit()
            except Exception as _e:
                logger.warning("scan_server_users: maj server_user_ssh_keys echoue (%s)", _e)
                conn_inv.rollback()

            # Marquer scanne — SEULEMENT si le scan a abouti.
            #
            # E-183, la face qui touche K4. `users_scanned_at` n'est pas un
            # horodatage d'affichage : c'est la PRECONDITION du preflight de
            # deploiement (`ssh.py:381`, « Bloquer si le serveur n'a jamais ete
            # scanne »). L'ecrire apres un scan qui n'a rien lu leve un garde de
            # surete sur le module le plus dangereux du chantier, en s'appuyant
            # sur un scan qui n'a pas eu lieu.
            if scan_concluant:
                cur.execute("UPDATE machines SET users_scanned_at = NOW() WHERE id = %s", (mid,))
                conn_inv.commit()
            else:
                logger.warning(
                    "scan_server_users(%s): `users_scanned_at` NON mis a jour — "
                    "le preflight de deploiement continue d'exiger un scan concluant", mid)

            # Recharger l'inventaire complet pour la reponse
            cur.execute("""
                SELECT username, uid, home_dir, shell, keys_count, has_platform_key,
                       status, managed_by, notes, reviewed_by, reviewed_at,
                       first_seen_at, last_seen_at
                FROM server_user_inventory WHERE machine_id = %s
                ORDER BY FIELD(status, 'pending_review', 'managed', 'excluded', 'unmanaged'), username
            """, (mid,))
            inventory = cur.fetchall()
            for row in inventory:
                for k in ('reviewed_at', 'first_seen_at', 'last_seen_at'):
                    if row.get(k) and hasattr(row[k], 'isoformat'):
                        row[k] = row[k].isoformat()

                # ══ E-199 : LA LIGNE EST INSEREE **ET** MARQUEE ══════════════
                #
                # Un compte nomme `..` dans un `/etc/passwd` est un INDICE de
                # manipulation de la machine. Le refuser a l'insertion rendrait
                # l'inventaire propre pendant que la machine porte l'anomalie —
                # un ecran propre sur une machine anormale est pire qu'un ecran
                # qui derange. On insere donc, et on DIT.
                #
                # LE DRAPEAU EST TOUJOURS RENSEIGNE, JAMAIS OMIS. C'est la
                # lecon d'E-183 puis d'E-190 : une information portee par
                # l'ABSENCE d'un champ ne se distingue pas de « rien a dire »,
                # et un champ absent se rend comme une liste vide ou un faux.
                # Meme forme que l'`audit_inventaire` d'E-194.
                #
                # Le motif est un CODE, pas une phrase : l'ecran l'affiche et
                # doit pouvoir SEPARER les causes. « pas de bouton parce que le
                # nom est invalide » et « pas de bouton parce que je n'ai pas la
                # permission » sont deux causes pour un meme vide.
                motif = _motif_nom_invalide(row.get('username'))
                row['nom_valide'] = motif is None
                row['motif_invalide'] = motif

            # ══ UNE LIGNE QUI NE PEUT RECEVOIR AUCUN GESTE NE GONFLE PAS ═════
            #    UN NOMBRE SUR LEQUEL ON DECIDE
            #
            # `pending_count` alimente « N comptes a examiner ». Une ligne au
            # nom invalide ne peut recevoir aucun geste distant — E-192 refuse
            # la revocation, `configure_user` et `deploy_user_config` refusent
            # aussi. La compter la ferait promettre un travail impossible.
            #
            # Les deux nombres sont rendus SEPAREMENT plutot qu'un seul
            # corrige : « 3 a examiner » et « 3 a examiner dont 1 illisible »
            # ne demandent pas le meme geste.
            pending_count = sum(1 for r in inventory
                                if r['status'] == 'pending_review' and r['nom_valide'])
            invalides_count = sum(1 for r in inventory if not r['nom_valide'])

        finally:
            conn_inv.close()

        # ══ E-187 : LE VERDICT, LA MOITIE QU'E-183 AVAIT LAISSEE ═════════════
        #
        # E-183 a corrige l'ETAT PERSISTE — plus rien n'est efface sur une
        # lecture ratee. Il n'a PAS corrige le verdict : cette route rendait
        # encore `success: True` inconditionnellement, avec un inventaire ancien
        # et aucun champ disant que rien n'avait ete lu. L'appelant recevait donc
        # une liste de comptes correcte, et croyait qu'elle venait de la machine.
        #
        # C'est l'INVERSE exact d'E-90, ou le verdict avait ete corrige et pas
        # l'etat persiste. La classe a deux moities ; les deux comptent.
        #
        # `lectures` nomme chaque source separement plutot que de rendre un seul
        # booleen : « je n'ai pas lu les comptes » et « j'ai lu les comptes mais
        # pas les cles » ne se corrigent pas de la meme facon, et une interface
        # qui ne recoit qu'un `false` ne peut pas le dire a l'exploitant.
        lectures = {
            'comptes': bool(scan_concluant),
            'cles_root': bool(dump_root_ok),
            'cles_utilisateur': bool(dump_user_ok),
        }
        concluant = scan_concluant and cles_lues
        reponse = {
            'success': bool(concluant),
            'concluant': bool(concluant),
            'lectures': lectures,
            'machine_id': m['id'],
            'machine_name': m['name'],
            'users': inventory,
            'pending_count': pending_count,
            # Toujours present, meme a zero : un ecran ne peut pas distinguer
            # « aucune ligne illisible » d'un champ absent.
            'invalides_count': invalides_count,
        }
        if not concluant:
            manquantes = [nom for nom, ok in lectures.items() if not ok]
            reponse['message'] = (
                "Scan non concluant : " + ", ".join(manquantes) +
                " n'a pas pu etre lu. L'inventaire affiche est celui du dernier "
                "scan abouti, il n'a pas ete modifie."
            )
        return jsonify(reponse)
    except Exception as e:
        logger.error("scan_server_users(%s): %s", machine_id, e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/sshd_allow_user', methods=['POST'])
@require_api_key
@require_role(2)
@require_machine_access
@threaded_route
def sshd_allow_user():
    """Patche sshd_config pour ajouter un username a AllowUsers.

    Endpoint manuel utilise depuis /adm/server_users.php quand un user a
    une cle SSH deposee mais ne peut pas se connecter (sshd refuse car
    AllowUsers ne le liste pas).

    Body JSON :
        machine_id (int)  : id du serveur
        username   (str)  : user a ajouter dans AllowUsers

    Garde-fous (helper _ensure_sshd_allows_user) :
    - Idempotent : skip si username deja dans AllowUsers
    - Skip si AllowUsers absent du sshd_config (rien a patcher)
    - Backup .bak.rw avant modification
    - Validation `sshd -t` apres patch
    - Rollback complet (restore backup + reload) si une etape rate

    Audit log entry par appel.
    """
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    username = (data.get('username') or '').strip()
    if not machine_id or not username:
        return jsonify({'success': False, 'message': 'machine_id et username requis'}), 400
    if not _validate_username(username):
        return jsonify({'success': False, 'message': 'username invalide'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, name, ip, port, user, password, root_password, "
            "service_account_deployed FROM machines WHERE id = %s",
            (int(machine_id),))
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    ssh_pass = server_decrypt_password(m['password'])
    root_pass = server_decrypt_password(m.get('root_password') or '')
    user_id, _ = get_current_user()

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger,
                         service_account=m.get('service_account_deployed', False)) as client:
            modified, msg = _ensure_sshd_allows_user(client, root_pass, username, logger)

        try:
            conn_a = get_db_connection()
            cur_a = conn_a.cursor()
            cur_a.execute(
                "INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                (user_id, f"[ssh] sshd_allow_user '{username}' sur {m['name']} : {msg[:200]}"))
            conn_a.commit()
            conn_a.close()
        except Exception:
            pass

        return jsonify({
            'success': True,
            'modified': modified,
            'message': f"{m['name']}: {msg}",
        })
    except Exception as e:
        logger.error("sshd_allow_user(%s, %s): %s", machine_id, username, e)
        return jsonify({'success': False, 'message': f'Erreur SSH : {str(e)[:200]}'}), 500


@bp.route('/server_user_keys', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def server_user_keys():
    """Liste les cles SSH inventoriees pour un user d'un serveur.

    Query params :
        machine_id (int)  : id du serveur (required)
        username   (str)  : username dont on veut les cles (required)

    Response :
        {success, keys: [{type, fingerprint, comment, is_platform,
                          owner_name, owner_id, first_seen_at, last_seen_at}]}

    Le cross-reference cherche dans `users.ssh_key` (cle publique stockee
    par chaque user RootWarden) un fingerprint match -> permet d'identifier
    "qui a depose cette cle".
    """
    machine_id = request.args.get('machine_id', type=int)
    username = (request.args.get('username') or '').strip()
    if not machine_id or not username:
        return jsonify({'success': False, 'message': 'machine_id et username requis'}), 400
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$', username):
        return jsonify({'success': False, 'message': 'username invalide'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)

        # 1. Cles inventoriees pour cette machine + user
        cur.execute("""
            SELECT key_type, fingerprint_sha256, comment, is_platform_key,
                   first_seen_at, last_seen_at
            FROM server_user_ssh_keys
            WHERE machine_id = %s AND username = %s
            ORDER BY is_platform_key DESC, first_seen_at ASC
        """, (machine_id, username))
        rows = cur.fetchall()

        # 2. Cross-reference avec users.ssh_key pour ownership
        # Calcule le fingerprint des cles users RootWarden et match.
        cur.execute("SELECT id, name, ssh_key FROM users WHERE active = 1 AND ssh_key IS NOT NULL AND ssh_key != ''")
        rw_users = cur.fetchall()
        rw_fp_map = {}  # {fingerprint: (id, name)}
        for u in rw_users:
            parsed = _parse_ssh_key_line(u['ssh_key'])
            if parsed:
                rw_fp_map[parsed['fingerprint']] = (u['id'], u['name'])

        keys = []
        for r in rows:
            fp = r['fingerprint_sha256']
            owner_id, owner_name = (None, None)
            if fp in rw_fp_map:
                owner_id, owner_name = rw_fp_map[fp]
            keys.append({
                'type': r['key_type'],
                'fingerprint': f"SHA256:{fp}",
                'comment': r['comment'],
                'is_platform': bool(r['is_platform_key']),
                'owner_id': owner_id,
                'owner_name': owner_name,
                'first_seen_at': str(r['first_seen_at']) if r['first_seen_at'] else None,
                'last_seen_at': str(r['last_seen_at']) if r['last_seen_at'] else None,
            })

        return jsonify({'success': True, 'keys': keys, 'count': len(keys)})
    except Exception as e:
        logger.error("server_user_keys(%s, %s): %s", machine_id, username, e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
    finally:
        conn.close()


@bp.route('/server_user_remove_key', methods=['POST'])
@require_api_key
@require_role(2)
@require_machine_access
@threaded_route
def server_user_remove_key():
    """Supprime UNE cle SSH precise du authorized_keys d'un user distant.

    Body JSON :
        machine_id (int)              : id du serveur (required)
        username   (str)              : compte distant (required)
        fingerprint_sha256 (str)      : fingerprint de la cle a virer (required)
        force (bool)                  : si true, autorise la suppression de la
                                        cle plateforme (par defaut bloquee)

    Side effects :
        - SSH (en root) -> reecrit ~/.ssh/authorized_keys sans la ligne ciblee
        - DELETE de la row dans server_user_ssh_keys
        - Audit log via user_logs
    """
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    username = (data.get('username') or '').strip()
    fingerprint = (data.get('fingerprint_sha256') or '').strip()
    # Strip eventuel prefixe "SHA256:" envoye par le frontend
    if fingerprint.startswith('SHA256:'):
        fingerprint = fingerprint[len('SHA256:'):]
    force = bool(data.get('force', False))

    if not machine_id or not username or not fingerprint:
        return jsonify({'success': False, 'message': 'machine_id, username et fingerprint_sha256 requis'}), 400
    if not _validate_username(username):
        return jsonify({'success': False, 'message': 'username invalide'}), 400
    if not re.match(r'^[A-Za-z0-9+/]{40,64}$', fingerprint):
        return jsonify({'success': False, 'message': 'fingerprint invalide'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, name, ip, port, user, password, root_password, "
            "service_account_deployed FROM machines WHERE id = %s",
            (int(machine_id),))
        m = cur.fetchone()
        if not m:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        # Verifie que la cle existe en BDD pour ce user/machine
        cur.execute(
            "SELECT key_type, comment, is_platform_key FROM server_user_ssh_keys "
            "WHERE machine_id = %s AND username = %s AND fingerprint_sha256 = %s",
            (int(machine_id), username, fingerprint))
        key_row = cur.fetchone()
        if not key_row:
            return jsonify({
                'success': False,
                'message': 'Cle non trouvee en inventaire - relance un scan'
            }), 404

        # Garde-fou : ne pas se locker hors du serveur en supprimant la cle
        # plateforme RootWarden, sauf si force=True explicite.
        if key_row.get('is_platform_key') and not force:
            return jsonify({
                'success': False,
                'message': "Suppression bloquee : c'est la cle plateforme RootWarden. "
                           "Utilise --force si tu veux vraiment te locker hors du serveur."
            }), 400
    finally:
        conn.close()

    ssh_pass = server_decrypt_password(m['password'])
    root_pass = server_decrypt_password(m.get('root_password') or '')
    fp_q = shlex.quote(fingerprint)
    user_q = shlex.quote(username)

    # Script bash root-side : pour CHAQUE ligne du authorized_keys, recalculer
    # le fingerprint via ssh-keygen -lf, comparer, garder la ligne si != cible.
    # ssh-keygen est universel sur tout systeme avec OpenSSH installe.
    remove_script = f"""
set -e
home=$(getent passwd {user_q} | cut -d: -f6)
ak="$home/.ssh/authorized_keys"
if [ ! -f "$ak" ]; then
    echo "no authorized_keys for {username}" >&2
    exit 1
fi
tmp=$(mktemp)
cp "$ak" "${{tmp}}.bak"
removed=0
while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    case "$line" in \\#*) echo "$line" >> "$tmp"; continue;; esac
    fp=$(printf '%s\\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{{print $2}}' | sed 's/^SHA256://')
    if [ "$fp" = {fp_q} ]; then
        removed=$((removed + 1))
    else
        echo "$line" >> "$tmp"
    fi
done < "$ak"
if [ "$removed" -eq 0 ]; then
    rm -f "$tmp" "${{tmp}}.bak"
    echo "fingerprint not found" >&2
    exit 2
fi
mv "$tmp" "$ak"
chown $(stat -c '%U:%G' "$home") "$ak" 2>/dev/null || true
chmod 600 "$ak"
echo "removed=$removed"
"""

    user_id, _ = get_current_user()
    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger,
                         service_account=m.get('service_account_deployed', False)) as client:
            out, err_out, code = execute_as_root(client, remove_script, root_pass,
                                                  logger=logger, timeout=30)
            if code != 0:
                logger.warning("server_user_remove_key(%s,%s): exit=%s err=%s",
                               machine_id, username, code, (err_out or '')[:300])
                return jsonify({
                    'success': False,
                    'message': f"Suppression echouee : {(err_out or out or 'erreur inconnue').strip()[:200]}"
                }), 500

        # Cleanup BDD
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM server_user_ssh_keys WHERE machine_id = %s "
                "AND username = %s AND fingerprint_sha256 = %s",
                (int(machine_id), username, fingerprint))
            # Audit log RGPD-friendly (action utilisateur trace)
            cur.execute(
                "INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                (user_id,
                 f"[ssh-keys] retire fingerprint {fingerprint[:16]}... "
                 f"de {username}@{m['name']} (type={key_row['key_type']})"))
            conn.commit()
        finally:
            conn.close()

        return jsonify({
            'success': True,
            'message': f"Cle SSH supprimee de {username}@{m['name']}",
            'fingerprint': fingerprint,
        })
    except Exception as e:
        logger.error("server_user_remove_key(%s, %s, %s): %s", machine_id, username, fingerprint, e)
        return jsonify({'success': False, 'message': f'Erreur SSH : {str(e)[:200]}'}), 500


@bp.route('/remove_user_keys', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : suppression de toutes les cles d'un user reservee admin
@require_machine_access
@threaded_route
def remove_user_keys():
    """
    Supprime les cles SSH d'un utilisateur sur un serveur distant.
    Peut supprimer toutes les cles ou seulement les cles RootWarden.
    Body JSON : {machine_id, username, mode: 'all'|'rootwarden_only'}
    """
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    username = (data.get('username') or '').strip()
    mode = data.get('mode', 'all')  # 'all' ou 'rootwarden_only'

    if not machine_id or not username:
        return jsonify({'success': False, 'message': 'machine_id et username requis'}), 400
    if not _validate_username(username):
        return jsonify({'success': False, 'message': 'Nom utilisateur invalide (caracteres interdits)'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    ssh_pass = server_decrypt_password(m['password'])
    root_pass = server_decrypt_password(m['root_password'])

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
            # Trouver le home de l'utilisateur
            stdin, stdout, stderr = client.exec_command(f"getent passwd {shlex.quote(username)} | cut -d: -f6", timeout=10)
            home = stdout.read().decode().strip()
            if not home:
                return jsonify({'success': False, 'message': f"Utilisateur '{username}' introuvable sur le serveur"})

            ak_path = f"{home}/.ssh/authorized_keys"

            # Valider le path (anti-injection)
            if not re.match(r'^/[a-zA-Z0-9/_.-]+$', ak_path):
                return jsonify({'success': False, 'message': 'Chemin invalide'}), 400

            if mode == 'all':
                # Supprimer TOUTES les cles (vider le fichier)
                cmd = f"printf '' > {ak_path}"
                execute_as_root(client, cmd, root_pass, logger=logger)
                return jsonify({'success': True, 'message': f"Toutes les cles de '{username}' supprimees"})
            else:
                # Supprimer seulement les cles RootWarden (qui contiennent @rootwarden ou rootwarden-platform)
                cmd = f"sed -i '/rootwarden/d' {ak_path} 2>/dev/null; echo OK"
                execute_as_root(client, cmd, root_pass, logger=logger)
                return jsonify({'success': True, 'message': f"Cles RootWarden de '{username}' supprimees"})

    except Exception as e:
        logger.error("[remove_user_keys] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/delete_remote_user', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : userdel distant irreversible reserve admin
@require_machine_access
@threaded_route
def delete_remote_user():
    """
    Supprime un utilisateur Linux sur un serveur distant (userdel).
    ATTENTION : action irreversible.
    Body JSON : {machine_id, username, remove_home: bool}
    """
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    username = (data.get('username') or '').strip()
    remove_home = data.get('remove_home', False)

    if not machine_id or not username:
        return jsonify({'success': False, 'message': 'machine_id et username requis'}), 400
    if not _validate_username(username):
        return jsonify({'success': False, 'message': 'Nom utilisateur invalide (caracteres interdits)'}), 400

    # Protection : ne jamais supprimer root ou l'utilisateur SSH de connexion
    protected = {'root', 'nobody', 'daemon', 'bin', 'sys', 'www-data'}
    if username in protected:
        return jsonify({'success': False, 'message': f"'{username}' est un utilisateur systeme protege"}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    # Protection : ne pas supprimer l'utilisateur SSH de connexion
    if username == m['user']:
        return jsonify({'success': False, 'message': f"'{username}' est l'utilisateur SSH de connexion - suppression interdite"}), 400

    # La garde ci-dessus protege `machines.user`. Elle ne suffit pas : sur une
    # machine deployee par compte de service, ce n'est PAS ce compte-la qui
    # ouvre la session.
    #
    # Mesure du 2026-08-27 sur le parc : `srv-zabbix` porte
    # `user = 'user'`, `service_account_deployed = 1`, et AUCUN mot de passe
    # stocke. Sa seule voie d'acces reelle est donc le compte de service — que
    # rien n'empechait de supprimer. Un `userdel` dessus verrouille la machine
    # DEFINITIVEMENT : plus de mot de passe, plus de cle, plus de compte.
    #
    # Le refus est POSE AVANT TOUTE SESSION SSH : rien n'est joint, rien n'est
    # tente. Et il ne depend d'aucune approbation — `gate()` contourne pour
    # `role >= 3`, donc un frein qui en dependrait serait inerte precisement
    # pour les comptes qui peuvent appeler cette route.
    #
    # Le nom vient de `Config.NOM_COMPTE_SERVICE`, partage avec l'authentification. Le
    # recopier ici ferait deux valeurs qui divergeraient — c'est le motif qui a
    # coute E-195, E-196 et E-197 le meme jour.
    # ══ COMMENT EPROUVER CETTE ROUTE — ET COMMENT JE M'Y SUIS PRIS DE TRAVERS
    #
    # Le 2026-08-27, une sonde de verification a appele cette route sur des
    # chemins qu'elle CROYAIT etre des refus. Son commentaire disait « aucun nom
    # valide n'a ete essaye ». C'etait une CROYANCE sur le comportement du
    # garde, pas une mesure. Resultat :
    #   - `userdel -f rootwarden` execute en root sur Test-Server-Debian
    #     (le compte n'existait pas : code 6, aucun degat — par chance) ;
    #   - un `client.connect()` emis vers `srv-zabbix`, LA PRODUCTION, que la
    #     regle du chantier interdit de joindre. L'authentification n'a pas
    #     abouti — par chance encore, pas par precaution.
    #
    # LA CAUSE : `_validate_username` de CE fichier (`:215`) accepte `..`, donc
    # le nom que la sonde croyait refuse traversait tous les gardes.
    #
    # LE MOTIF SUR EST DE RETIRER LA CIBLE, PAS DE RENFORCER LE GARDE :
    # eprouver cette route se fait avec un `machine_id` VALIDE MAIS INEXISTANT,
    # qui ne peut produire qu'un 404 — jamais avec une machine reelle, meme sur
    # un chemin qu'on croit refuse. Un garde-fou de sonde doit etre une
    # propriete MESUREE, pas une croyance sur ce qu'on sonde.
    #
    # ══ P5 : NE PAS SUPPRIMER LA SEULE VOIE D'ACCES QUI RESTE ════════════════
    if m.get('service_account_deployed') and username == Config.NOM_COMPTE_SERVICE:
        return jsonify({
            'success': False,
            'message': (f"'{username}' est le compte de service par lequel RootWarden "
                        f"accede a {m['name']} — le supprimer verrouillerait la machine. "
                        f"Suppression interdite."),
        }), 400

    # Approbation 4-eyes : suppression d'utilisateur distant = action destructive.
    # Si activee, exige l'aval d'un 2e admin avant execution (store-and-replay).
    try:
        from approvals import gate, AucunApprobateur
        _uid, _role = get_current_user()
        _ap = gate('delete_remote_user', int(machine_id), username,
                   {'username': username, 'remove_home': bool(remove_home)}, _uid, role=_role)
        if _ap is not None:
            msg = ("Demande d'approbation creee : un 2e administrateur doit valider avant suppression."
                   if _ap['status'] == 'created'
                   else "Action deja en attente d'approbation par un 2e administrateur.")
            return jsonify({'success': False, 'pending_approval': True,
                            'request_id': _ap['id'], 'message': msg}), 202
    except Exception as _e:
        # Une porte a quatre yeux qui s'ouvre doit laisser une TRACE : `debug`
        # n'est pas journalise en exploitation, donc la porte s'ouvrait et
        # personne ne le savait. Un repli silencieux n'est pas un repli.
        logger.error("approval gate (delete_remote_user) OUVERTE sur erreur : %s", _e)

    ssh_pass = server_decrypt_password(m['password'])
    root_pass = server_decrypt_password(m['root_password'])

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
            # Flags :
            #   -r : supprime le home directory + mail spool
            #   -f : force meme si l'user est connecte, meme si le group primaire
            #        porte le meme nom. On l'active par defaut : sans lui,
            #        un processus actif fait echouer userdel alors que dans
            #        99% des cas l'admin veut vraiment degager l'user.
            flags = ['-f']
            if remove_home:
                flags.append('-r')
            flag_str = ' '.join(flags)
            # Chemin absolu : su -c n'a pas /usr/sbin dans le PATH
            cmd = f"/usr/sbin/userdel {flag_str} {shlex.quote(username)} 2>&1"
            output, _, exit_code = execute_as_root(client, cmd, root_pass, logger=logger)
            output_str = output if isinstance(output, str) else str(output)

            if 'no such user' in output_str.lower():
                # Deja absent : on nettoie quand meme la DB et on renvoie success.
                _cleanup_user_inventory(machine_id, username)
                return jsonify({'success': True, 'message': f"'{username}' n'existait deja plus - inventaire nettoye"})

            # Verifier si l'utilisateur existe encore via `id`. C'est la
            # source de verite : userdel peut retourner exit != 0 avec des
            # warnings (mail spool, subuid, cron) alors que l'user EST
            # bien supprime. Sans ce check on renvoyait "Echec" a tort.
            #
            # IMPORTANT : on regarde l'EXIT CODE de `id` (universal), pas le
            # message qui depend de la locale. En FR : "utilisateur
            # inexistant", en EN : "no such user", en ES : "no existe el
            # usuario"... Le exit code lui est toujours 1 si user absent.
            # Bug v1.19.x : message FR ne matchait pas -> "echec" alors que
            # delete OK. Fix : exit_code est l'autorite, message en fallback.
            check, check_err, check_exit = execute_as_root(
                client, f"id {shlex.quote(username)} 2>&1", root_pass, timeout=5)
            check_str = (check or '').lower()
            user_gone = (
                (check_exit is not None and int(check_exit) != 0)
                or 'no such user' in check_str
                or 'does not exist' in check_str
                or 'utilisateur inexistant' in check_str
                or 'no existe el usuario' in check_str
            )

            # Journal des commandes (trail bastion)
            try:
                from command_logger import log_command
                _luid, _ = get_current_user()
                log_command(machine_id, _luid, cmd, context='delete_user',
                            success=bool(user_gone),
                            detail=f"remove_home={remove_home}")
            except Exception:
                pass

            if user_gone:
                if exit_code and int(exit_code) != 0:
                    # Warnings non-fatals : on logue mais on considere la suppression OK.
                    logger.info(
                        "userdel '%s' sur %s : exit=%s warnings mais user absent, OK. output=%s",
                        username, m['name'], exit_code, output_str.strip()[:200])
                _cleanup_user_inventory(machine_id, username)
                logger.info("User '%s' supprime sur %s (remove_home=%s)", username, m['name'], remove_home)
                return jsonify({
                    'success': True,
                    'message': f"Utilisateur '{username}' supprime de {m['name']}",
                    'warnings': output_str.strip() if exit_code else None,
                })

            # user_gone == False : userdel n'a vraiment pas fonctionne.
            logger.warning("userdel '%s' sur %s: user toujours present. exit=%s output=%s",
                           username, m['name'], exit_code, output_str)
            return jsonify({
                'success': False,
                'message': f"'{username}' toujours present apres userdel. Verifie : processus actif (`ps -u {username}`), quotas, NIS/LDAP. Sortie : {output_str.strip()[:300]}"
            })

    except Exception as e:
        logger.error("[delete_remote_user] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


def _cleanup_user_inventory(machine_id, username):
    """Nettoie server_user_inventory apres suppression confirmee d'un user."""
    try:
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM server_user_inventory WHERE machine_id = %s AND username = %s",
                (int(machine_id), username))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("cleanup server_user_inventory (%s/%s) failed: %s",
                       machine_id, username, e)


@bp.route('/machines/credential-status', methods=['GET'])
@require_api_key
@threaded_route
def machines_credential_status():
    """Dit, par machine, si le secret stocke DECHIFFRE EN VIDE — sans jamais le rendre.

    ══ POURQUOI CETTE ROUTE EXISTE ═══════════════════════════════════════════

    `(password <> '')` en SQL est FAUX comme predicat de « cette machine a un mot
    de passe ». Les deux portails ne chiffrent pas la chaine vide de la meme
    facon :

        Python  encrypt_password('')          -> ''          (chaine vide)
        PHP     encryptPassword('', false)    -> 'sodium:…'  (56 octets)

    Le formulaire legacy passe `$validate = false` : un mot de passe REELLEMENT
    VIDE saisi la-bas est donc stocke comme un cryptogramme NON VIDE, et
    `(password <> '')` rend VRAI pour une machine qui n'a pas de mot de passe.

    ══ L'ASYMETRIE VAUT POUR LES DEUX COLONNES CHIFFREES ════════════════════

    Elle ne tient a rien de propre a `password` : c'est le chiffrement de la
    chaine vide qui differe. **`root_password` est donc dans le meme cas**, et
    cette route rend les memes trois etats pour elle (`root_*`).

    C'est meme la colonne la plus consequente des deux : c'est celle dont depend
    l'ELEVATION, donc E-218 et E-219, et **c'est la seule que la page de cle de
    plateforme ne peut pas reecrire**. Un seul calcul les sert toutes les deux
    (`_trois_etats`) : deux copies divergeraient, et c'est le motif referme le
    meme jour sur les cinq `_resolve_ssh_creds`.

    Corollaire pour `indetermines` : ses entrees nomment **la colonne** et pas
    seulement la machine — « je n'ai pas su lire un secret » sans dire lequel
    n'apprend rien a un ecran qui en affiche deux.

    Le portage a REFUSE de reimplementer le dechiffrement pour trancher — et il
    a eu raison : *ne jamais recopier une regle de crypto.* Il n'existait
    qu'une issue honnete : que le backend, seul detenteur de la cle, expose le
    predicat DEJA CALCULE. Meme precedent qu'E-168 et INF-003.

    ══ CE QU'ELLE NE REND PAS ═══════════════════════════════════════════════

    Ni le secret, ni sa longueur, ni son cryptogramme, ni le nombre de
    caracteres. Rien qui aide a le deviner : des booleens, et le nom de la
    machine que l'appelant voit deja.

    ══ TROIS ETATS, PAS DEUX — ET C'EST LE COEUR ════════════════════════════

    `server_decrypt_password` rend `""` dans DEUX cas que rien ne distingue :
    le clair est vide, ou le dechiffrement a ECHOUE (fail-closed). Rendre un
    simple booleen « le mot de passe est vide » recopierait cette confusion dans
    l'interface, et un ecran afficherait « pas de mot de passe » pour une
    machine dont la cle a change.

        mot_de_passe_vide = true   le clair est vide, mesure
        mot_de_passe_vide = false  le clair n'est pas vide
        mot_de_passe_vide = null   INDETERMINE : le dechiffrement a echoue

    C'est la lecon d'E-183 puis d'E-194, deja appliquee a
    `/settings/announceable` : une interface doit pouvoir distinguer « c'est
    faux » de « je n'ai pas pu lire ». Les machines indeterminees sont AUSSI
    listees dans `indetermines`, toujours present meme vide.

    ══ ET LE BACKEND, LUI, CONFOND LES DEUX ═════════════════════════════════

    `joignable_selon_le_backend` reproduit EXACTEMENT ce que
    `helpers.resolve_ssh_creds` decidera — echec de dechiffrement compris, donc
    traite comme « pas de mot de passe ». Ce champ n'est pas une redite du
    precedent : quand il vaut `true` alors que `mot_de_passe_vide` vaut `null`,
    l'ecran sait que la decision du backend repose sur le keypair et non sur un
    secret qu'il aurait su lire. **Decrire le comportement, et pas seulement le
    fait, est ce qui evite de reimplementer le comportement.**

    ══ LA GARDE ════════════════════════════════════════════════════════════

    `@require_api_key` seule au niveau du decorateur, et le bornage est FAIT
    DANS LE CORPS, machine par machine, par `check_machine_access`. C'est
    delibere et c'est l'invariant qu'E-211 vient d'etablir : cette route ne
    prend AUCUN `machine_id`, donc `@require_machine_access` n'aurait rien
    trouve a refuser — un garde sans objet. Le perimetre du compte est la vraie
    borne, et elle est ici.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, password, root_password, "
                    "service_account_deployed, platform_key_deployed "
                    "FROM machines ORDER BY name")
        lignes = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("machines/credential-status : lecture BDD : %s", e)
        return jsonify({'success': False, 'message': 'Erreur BDD'}), 500

    machines, indetermines = [], []

    def _trois_etats(secret, machine_id, colonne):
        """Les trois etats d'UNE colonne chiffree. Rend (vide, dechiffrable).

        Un seul calcul pour `password` et `root_password` : la meme asymetrie
        Python/PHP vaut pour les deux, et deux copies divergeraient — c'est le
        motif qu'on vient de refermer sur les cinq `_resolve_ssh_creds`.
        """
        if not secret:
            return True, True
        try:
            return (encryption.decrypt_password(secret) == ''), True
        except Exception:
            # On ne journalise NI le secret NI l'exception telle quelle : un
            # message d'erreur de crypto peut porter des octets du cryptogramme.
            # Seuls l'identifiant de la machine et le nom de colonne sont traces.
            logger.warning("machines/credential-status : dechiffrement impossible "
                           "pour machine_id=%s colonne=%s", machine_id, colonne)
            indetermines.append({'machine_id': machine_id, 'colonne': colonne})
            return None, False

    for row in lignes:
        if not check_machine_access(row['id']):
            continue
        secret = row.get('password') or ''
        root_secret = row.get('root_password') or ''
        vide, dechiffrable = _trois_etats(secret, row['id'], 'password')
        root_vide, root_dechiffrable = _trois_etats(root_secret, row['id'], 'root_password')

        keypair = bool(row.get('service_account_deployed')
                       or row.get('platform_key_deployed'))
        # Reproduit `resolve_ssh_creds` A L'IDENTIQUE : un echec de
        # dechiffrement y devient une chaine vide, donc « pas de mot de passe ».
        mdp_effectif = '' if (vide or not dechiffrable) else 'x'
        machines.append({
            'machine_id': row['id'],
            'nom': row['name'],
            'secret_stocke': bool(secret),
            'mot_de_passe_vide': vide,
            'dechiffrable': dechiffrable,
            # `root_password` : meme prédicat, colonne distincte. C'est celle
            # dont depend l'ELEVATION, donc E-218 et E-219.
            'root_secret_stocke': bool(root_secret),
            'root_password_vide': root_vide,
            'root_dechiffrable': root_dechiffrable,
            'keypair_deploye': keypair,
            'joignable_selon_le_backend': bool(mdp_effectif) or keypair,
        })

    return jsonify({
        'success': True,
        'machines': machines,
        # Toujours present, meme vide — un champ absent se lit « rien a dire ».
        'indetermines': indetermines,
    })

