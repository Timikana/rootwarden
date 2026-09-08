"""
routes/iptables.py - Routes de gestion du pare-feu iptables.

Routes :
    POST /iptables           - Charger les regles
    POST /iptables-validate  - Valider (dry-run)
    POST /iptables-apply     - Appliquer
    POST /iptables-restore   - Restaurer depuis BDD
    GET  /iptables-history   - Historique des modifications
    POST /iptables-rollback  - Restaurer une version
    GET  /iptables-logs      - Streaming SSE des logs
"""

import time
import base64
import mysql.connector
from flask import Blueprint, jsonify, request, Response

from routes.helpers import resolve_ssh_creds as _resolve_ssh_creds
from routes.helpers import require_api_key, require_role, require_permission, require_machine_access, check_machine_access, get_current_user, threaded_route, get_db_connection, server_decrypt_password, logger
from ssh_utils import db_config, ssh_session, execute_as_root, execute_as_root_stream
from iptables_manager import get_iptables_rules, apply_iptables_rules

bp = Blueprint('iptables', __name__)


def _archive_puis_applique(client, root_password, data, mid,
                           rules_v4=None, rules_v6=None,
                           message="Regles appliquees.", motif=None):
    """Archive l'etat courant PUIS applique les regles. Le SEUL chemin d'application.

    ══ POURQUOI CETTE FONCTION EXISTE ═══════════════════════════════════════

    Ce fichier portait DEUX routes qui appliquent des regles de pare-feu sur une
    machine, memes gardes a la ligne pres, meme effet distant :

        POST /iptables         action="apply"   ->  appliquait SANS archiver
        POST /iptables-apply   action="apply"   ->  archivait puis appliquait

    ⚠ LA TRACE MANQUANTE ETAIT LE SYMPTOME ; DEUX IMPLEMENTATIONS DU MEME GESTE
    IRREVERSIBLE ETAIT LA CAUSE. Le remede n'est donc pas d'ajouter un archivage
    a la premiere route — ce serait une seconde copie, qui divergerait EN SILENCE
    pendant que les deux portes continueraient de « marcher ». Ce depot a deja
    paye trois copies du garde SSRF et trois compteurs 2FA.

    ══ CE QUE L'ABSENCE D'ARCHIVE COUTAIT ═══════════════════════════════════

        etat 0 --/iptables--------> etat 1   rien n'est archive : l'etat 0 est PERDU
        etat 1 --/iptables-apply--> etat 2   l'etat 1 est archive
        rollback depuis l'etat 2             restaure l'etat 1, PAS l'etat 0

    L'archive devenait NON CONTIGUE, et rien ne le disait. *Une archive avec un
    trou est plus dangereuse qu'une archive absente : l'absence se voit, le trou
    se lit comme une continuite.* Et `/iptables-rollback` APPLIQUE ce qu'il
    restaure — le trou etait actionnable.

    ══ POURQUOI LE VERBE N'A PAS ETE RETIRE ═════════════════════════════════

    `laravel/app/Services/ClesApi.php:60` donne aux cles d'API une portee a
    PREFIXE sur `^/iptables` : un consommateur legitime peut appeler
    `POST /iptables` aujourd'hui, et cette liste ne s'enumere pas.

    « Le backend l'expose aujourd'hui » fonde une obligation de compatibilite, la
    ou « le legacy l'expose deja » n'en fonde aucune : le legacy meurt, le backend
    reste.

    La capacite est donc INCHANGEE, aucun consommateur ne casse, et la trace est
    acquise pour les deux portes.
    """
    # LES REGLES SONT LUES ICI, et non heritees d'un local de l'appelant. Le
    # premier jet de cette fonction comptait sur `rules_v4` defini dans la route
    # appelante : les deux portes levaient `NameError`, et la suite de 672 tests
    # ne l'a pas vu parce qu'AUCUN n'exercait la branche `apply`.
    # QUATRE PORTES, UN SEUL CHEMIN. Les deux routes `action="apply"` lisent leurs
    # regles dans le corps de la requete ; `/iptables-restore` les lit dans
    # `iptables_rules` et `/iptables-rollback` dans `iptables_history`. Ces deux
    # dernieres les passent donc explicitement, et seules les premieres tombent
    # dans la lecture par defaut.
    if rules_v4 is None:
        rules_v4 = data.get('rules_v4')
        rules_v6 = data.get('rules_v6')

    # ⚠ LA GARDE EST EN AVAL, HORS DU `if` — et c'est tout son interet.
    #
    # Elle vivait SOUS la lecture par defaut, donc elle ne gardait que les deux
    # portes `apply`. `restore` et `rollback` controlent en amont (`:262`,
    # `:350`), donc l'angle mort etait DORMANT — mais sur par CONVENTION : une
    # cinquieme porte n'aurait ete forcee par rien.
    #
    # **Deux gardes en amont valent moins qu'une garde en aval : il faut les
    # repeter, et on ne repete pas ce qu'on ne voit pas.**
    if not (rules_v4 or '').strip():
        return jsonify({"success": False, "message": "Regles IPv4 manquantes."}), 400

    # Save history before apply
    # ⚠ CE QUE LA REPONSE DOIT DIRE, ET NE DISAIT PAS.
    #
    # Base injoignable -> l'archivage echoue -> l'application A LIEU quand meme
    # -> la reponse etait OCTET POUR OCTET celle du succes. Aucun champ ne la
    # distinguait, aucun test ne l'exercait.
    #
    # *Ce fichier dit lui-meme qu'une archive avec un trou est plus dangereuse
    # qu'une archive absente, parce que le trou se lit comme une continuite.* Le
    # chemin d'exception en fabriquait un, EN SILENCE — et c'est sur `rollback`
    # que ca coute le plus, la route dont tout l'argument est la reversibilite.
    #
    # ON NE BLOQUE PAS, ET CE N'EST PAS UN COMPROMIS : l'archive sert la
    # tracabilite, l'application sert la DISPONIBILITE. Rendre un pare-feu
    # inmodifiable parce qu'une table de journal est injoignable ferait de la
    # garde la chose qui empeche de se retablir — et sur `rollback`, bloquer
    # enfermerait l'operateur dans l'etat casse qu'il cherche a quitter.
    #
    # Mais que l'appelant ne puisse pas le SAVOIR n'est defendable en rien.
    archive = False
    archive_motif = None
    try:
        old_rules = get_iptables_rules(client, root_password)
        # L'AUTEUR NE VIENT PLUS DU CORPS DE LA REQUETE. Un client
        # pouvait signer une modification de pare-feu au nom de
        # n'importe qui ; et comme aucun frontend n'envoyait ce
        # champ, TOUTES les lignes d'historique valaient
        # litteralement « admin » — l'historique attribuait donc
        # chaque changement a un compte qui ne l'avait pas fait.
        # L'identite retenue est celle que get_current_user()
        # recharge EN BASE a partir de X-User-ID.
        user_id, _role_id = get_current_user()
        change_reason = motif if motif is not None else data.get('change_reason', '')
        # get_iptables_rules rend `file_rules_v4` / `file_rules_v6`
        # (le CONTENU du fichier persistant), jamais `rules_v4`. Lire
        # la mauvaise cle enregistrait TOUTES les versions vides —
        # et un rollback ecrasait alors /etc/iptables/rules.v4 par du
        # vide. C'est le fichier persistant qu'il faut archiver, pas
        # la sortie de `iptables -L` qui n'est pas rejouable.
        ancien_v4 = old_rules.get('file_rules_v4', '') or ''
        ancien_v6 = old_rules.get('file_rules_v6', '') or ''
        # La machine est celle DEJA RESOLUE par machine_id en tete de
        # requete. La retrouver par son adresse designait la mauvaise
        # ligne des que deux machines partagent une IP (NAT, ports
        # SSH differents) : l'historique d'un serveur recevait alors
        # les regles d'un autre.
        machine_pk = mid  # valeur RESOLUE, pas re-lue du client (source unique)
        with get_db_connection() as hist_conn:
            hist_cur = hist_conn.cursor()
            hist_cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
            u_row = hist_cur.fetchone()
            # Un identifiant numerique vaut mieux qu'un nom emprunte
            # quand le compte n'est plus la : il reste rattachable.
            changed_by = (u_row[0] if u_row else None) or "#%s" % user_id
            # Une version vide n'archive rien et rend le rollback
            # destructeur : on ne l'enregistre pas.
            if ancien_v4.strip():
                hist_cur.execute(
                    "INSERT INTO iptables_history (server_id, rules_v4, rules_v6, changed_by, change_reason) VALUES (%s, %s, %s, %s, %s)",
                    (machine_pk, ancien_v4, ancien_v6, changed_by, change_reason)
                )
                hist_conn.commit()
                archive = True
            else:
                # Pas un ECHEC : il n'y avait rien a archiver. Mais l'appelant
                # doit le savoir tout autant — dans les deux cas, aucune version
                # ne le ramenera ici.
                archive_motif = "etat_precedent_vide"
                logger.warning(
                    "[iptables:apply] machine_id=%s : fichier de regles vide, aucune version archivee",
                    machine_pk
                )
    except Exception as hist_err:
        archive_motif = "echec_archivage"
        logger.warning("Iptables history save failed: %s", hist_err)
    # L'ARCHIVE ENREGISTRE L'ETAT QUITTE, JAMAIS L'ETAT RESTAURE. Enregistrer
    # l'etat vers lequel on va dupliquerait une entree deja presente et rendrait
    # la chaine illisible : on ne saurait plus distinguer « voici ou j'etais » de
    # « voici ou je vais ».
    apply_iptables_rules(client, root_password, rules_v4, rules_v6)

    # LA REPONSE DIT SI L'ARCHIVE A EU LIEU. Un `success: true` seul etait
    # indiscernable entre « archive puis applique » et « applique sans trace ».
    reponse = {"success": True, "message": message, "archive": archive}
    if not archive:
        reponse["archive_motif"] = archive_motif
    return jsonify(reponse)




@bp.route('/iptables', methods=['POST'])
@require_api_key
@require_permission('can_manage_iptables')  # E-152
@require_machine_access
@threaded_route
def manage_iptables():
    try:
        data = request.get_json(silent=True) or {}  # robustesse : pas de 500 sur body non-JSON
        action = data.get('action')
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, mid, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        if not action:
            return jsonify({"success": False, "message": "Action manquante."}), 400
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            if action == "get":
                rules = get_iptables_rules(client, root_password)
                return jsonify({"success": True, **{k: rules.get(k) for k in ('current_rules_v4','current_rules_v6','file_rules_v4','file_rules_v6')}})
            elif action == "apply":
                # DELEGATION, JAMAIS DUPLICATION. Cette route appliquait SANS
                # archiver ; elle passe desormais par le SEUL chemin
                # d'application. Voir `_archive_puis_applique` pour ce que le
                # trou d'archive coutait au rollback.
                return _archive_puis_applique(client, root_password, data, mid)
            else:
                return jsonify({"success": False, "message": "Action non reconnue."}), 400
    except Exception as e:
        logger.error("[iptables] %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/iptables-validate', methods=['POST'])
@require_api_key
@require_permission('can_manage_iptables')  # E-152
@require_machine_access
@threaded_route
def validate_iptables():
    try:
        data = request.get_json(silent=True) or {}  # robustesse : pas de 500 sur body non-JSON
        rules_v4 = data.get('rules_v4', '')
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, mid, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        if not rules_v4.strip():
            return jsonify({"success": False, "message": "Regles IPv4 vides."}), 400
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            encoded = base64.b64encode(rules_v4.encode()).decode()
            test_cmd = f"printf '%s' '{encoded}' | base64 -d > /tmp/_ipt_test.rules && iptables-restore --test /tmp/_ipt_test.rules 2>&1; echo EXIT_CODE=$?"
            # ══ E-461 : CE GENERATEUR REND DES FRAGMENTS, PAS DES LIGNES ══════
            #
            # `execute_as_root_stream` fait `stdout.channel.recv(4096)` et cede le
            # texte tel quel (`ssh_utils.py:693-698`). Le nom `output_lines` que
            # portait cette variable AFFIRMAIT une propriete que le generateur ne
            # fournit pas — et c'est ce nom qui a fait tenir le defaut.
            #
            # Consequence mesuree : `EXIT_CODE=0` fait 12 octets. A cheval sur une
            # frontiere de 4096, AUCUN fragment ne le contient : le `any(...)`
            # rendait False et un jeu de regles VALIDE etait declare « Erreur de
            # syntaxe ». Et le `'\n'.join` aggravait le cas — il INSERAIT un saut
            # de ligne au milieu du marqueur, donc meme la chaine recollee ne le
            # portait plus.
            fragments = list(execute_as_root_stream(client, test_cmd, root_password, logger=logger))
            output = ''.join(fragments)          # recoller, PUIS decouper
            lignes = output.splitlines()

            # Le marqueur est la DERNIERE ligne `EXIT_CODE=` du flux, comparee en
            # ENTIER. Chercher la sous-chaine n'importe ou accepterait un
            # `EXIT_CODE=0` present dans un message d'erreur d'`iptables-restore`,
            # lequel peut citer une ligne des regles fournies par l'appelant.
            marqueurs = [l.strip() for l in lignes if l.strip().startswith('EXIT_CODE=')]
            exit_code = 0 if marqueurs and marqueurs[-1] == 'EXIT_CODE=0' else 1
            if exit_code == 0:
                return jsonify({"success": True, "message": "Regles valides.", "output": output})
            else:
                return jsonify({"success": False, "message": "Erreur de syntaxe.", "output": output})
    except Exception as e:
        logger.error("[iptables-validate] %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/iptables-apply', methods=['POST'])
@require_api_key
@require_permission('can_manage_iptables')  # E-152
@require_machine_access
@threaded_route
def manage_iptables_apply():
    try:
        data = request.get_json(silent=True) or {}  # robustesse : pas de 500 sur body non-JSON
        action = data.get('action')
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, mid, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        if not action:
            return jsonify({"success": False, "message": "Action manquante."}), 400
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            if action == "apply":
                # LE MEME CHEMIN QUE `/iptables`. Le bloc qui vivait ici a ete
                # DEPLACE dans `_archive_puis_applique` — pas recopie : deux
                # implementations d'un geste irreversible etaient la CAUSE du
                # defaut, la trace manquante n'en etait que le symptome.
                #
                # La validation des regles vit dans le helper, pas ici : une
                # seconde copie du controle « rules_v4 manquantes » divergerait
                # comme le reste.
                return _archive_puis_applique(client, root_password, data, mid)
            else:
                return jsonify({"success": False, "message": "Action non reconnue."}), 400
    except Exception as e:
        logger.error("[iptables-apply] %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/iptables-restore', methods=['POST'])
@require_api_key
@require_permission('can_manage_iptables')  # E-152
@require_machine_access
@threaded_route
def manage_iptables_restore():
    try:
        data = request.get_json(silent=True) or {}  # robustesse : pas de 500 sur body non-JSON
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, mid, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        with mysql.connector.connect(**db_config) as conn:
            cursor = conn.cursor(dictionary=True)
            # Par machine_id, pas par adresse : deux machines peuvent partager
            # une IP (NAT, ports SSH differents), et la sous-requete rendait
            # alors les regles enregistrees pour l'AUTRE — appliquees, elles,
            # sur celle que le client avait designee.
            cursor.execute(
                "SELECT rules_v4, rules_v6 FROM iptables_rules WHERE server_id = %s ORDER BY id DESC LIMIT 1",
                (mid,)  # valeur RESOLUE, pas re-lue du client
            )
            rules = cursor.fetchone()
        if not rules:
            return jsonify({"success": False, "message": "Aucune regle en BDD."}), 404
        # Une copie vide n'est pas une copie : l'appliquer viderait le pare-feu
        # de la machine. Meme garde que sur le retour a une version anterieure.
        if not (rules.get('rules_v4') or '').strip():
            return jsonify({"success": False, "message": "Copie enregistree vide, restauration refusee."}), 409
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            # LE MEME CHEMIN QUE LES TROIS AUTRES. Cette route appliquait sans
            # archiver : l'etat COURANT de la machine etait perdu, et un rollback
            # ulterieur ne pouvait plus y revenir.
            return _archive_puis_applique(
                client, root_password, data, mid,
                rules_v4=rules.get('rules_v4', ''), rules_v6=rules.get('rules_v6', ''),
                message="Regles restaurees.",
                motif="etat quitte avant restauration depuis la copie enregistree",
            )
    except Exception as e:
        logger.error("[iptables-restore] %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/iptables-history', methods=['GET'])
@require_api_key
@require_permission('can_manage_iptables')  # E-152
@require_machine_access
@threaded_route
def iptables_history():
    server_id = request.args.get('server_id')
    if not server_id:
        return jsonify({'success': False, 'message': 'server_id requis'}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, changed_by, change_reason, created_at FROM iptables_history WHERE server_id = %s ORDER BY created_at DESC LIMIT 20",
            (int(server_id),)
        )
        history = cur.fetchall()
        for h in history:
            h['created_at'] = h['created_at'].isoformat() if hasattr(h['created_at'], 'isoformat') else str(h['created_at'])
        return jsonify({'success': True, 'history': history})
    finally:
        conn.close()


@bp.route('/iptables-rollback', methods=['POST'])
@require_api_key
@require_permission('can_manage_iptables')
@threaded_route
def iptables_rollback():
    """Reapplique une version archivee des regles d'une machine.

    SECURITE — cette route ne peut PAS etre protegee par @require_machine_access.
    Son corps ne porte que `history_id` : le decorateur ne trouve alors ni
    machine_id ni server_id, `ids` reste vide, et il laisse passer. Tout compte
    authentifie pouvait donc faire appliquer par SSH un jeu de regles a
    n'importe quelle machine du parc, production comprise.

    Le controle est fait ICI, apres la resolution : on verifie l'acces a la
    machine QUE LA VERSION DESIGNE, pas a un identifiant que le demandeur aurait
    fourni. C'est la meme regle que pour l'export CVE — la verification porte sur
    l'objet atteint, jamais sur le parametre recu.
    """
    data = request.get_json(silent=True) or {}
    history_id = data.get('history_id')
    if not history_id:
        return jsonify({'success': False, 'message': 'history_id requis'}), 400
    try:
        history_id = int(history_id)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'history_id invalide'}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT h.*, m.ip, m.port, m.user, m.password, m.root_password, m.service_account_deployed, m.platform_key_deployed "
            "FROM iptables_history h JOIN machines m ON h.server_id = m.id WHERE h.id = %s",
            (history_id,)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Version introuvable'}), 404
        if not check_machine_access(row['server_id']):
            user_id, role_id = get_current_user()
            logger.warning(
                "[iptables-rollback] acces refuse machine_id=%s pour user_id=%s role=%s depuis %s",
                row['server_id'], user_id, role_id, request.remote_addr
            )
            return jsonify({'success': False, 'message': 'Acces refuse a cette machine'}), 403
        # Une version vide n'est pas une version : l'appliquer ecraserait le
        # fichier de regles persistant de la machine par du vide.
        if not (row.get('rules_v4') or '').strip():
            return jsonify({'success': False, 'message': 'Version vide, restauration refusee'}), 409
        ssh_pass = server_decrypt_password(row.get('password', '')) or ''
        root_pass = server_decrypt_password(row.get('root_password', '')) or ''
        with ssh_session(row['ip'], row['port'], row['user'], ssh_pass, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            # ⚠ LA ROUTE QUI DECIDAIT DE L'ARBITRAGE. Elle se presente comme
            # REVERSIBLE et ne l'etait pas : l'etat courant n'etait conserve
            # nulle part, donc on revenait en arriere et JAMAIS EN AVANT.
            #
            # *Une porte a sens unique habillee en porte reversible est pire
            # qu'une porte a sens unique* — l'operateur clique PARCE QUE le nom
            # lui promet qu'il pourra defaire.
            #
            # `data` n'est pas passe : le corps de cette route ne porte que
            # `history_id`, et `mid` vient de la version DESIGNEE, jamais d'un
            # parametre du demandeur.
            return _archive_puis_applique(
                client, root_pass, {}, row['server_id'],
                rules_v4=row['rules_v4'], rules_v6=row['rules_v6'],
                message="Regles restaurees",
                motif="etat quitte avant rollback vers la version #%s" % history_id,
            )
    except Exception as e:
        logger.error("[iptables-rollback] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
    finally:
        conn.close()


@bp.route('/iptables-logs')
@require_api_key
@require_role(2)  # Patch A01-NEW-04 : SSE logs reservees admin
@require_permission('can_manage_iptables')  # E-152
def iptables_logs():
    """Stream SSE des logs iptables."""
    log_file = '/app/logs/iptables.log'

    def generate():
        # Patch (A04/robustesse) : flux borne dans le temps + heartbeat. Avant,
        # `while True` sans borne mobilisait un thread/contexte indefiniment par
        # connexion -> saturation possible du pool. On arrete apres MAX_STREAM_S
        # et on emet un heartbeat (`: ping`) qui leve une exception si le client
        # est deconnecte, ce qui termine proprement le generateur.
        MAX_STREAM_S = 600  # 10 min max par connexion
        IDLE_TICK = 0.5
        start = time.monotonic()
        idle = 0
        try:
            with open(log_file, 'r') as f:
                f.seek(0, 2)
                while time.monotonic() - start < MAX_STREAM_S:
                    line = f.readline()
                    if line:
                        yield f"data: {line}\n\n"
                        idle = 0
                    else:
                        time.sleep(IDLE_TICK)
                        idle += 1
                        if idle % 20 == 0:  # heartbeat ~10s
                            yield ": ping\n\n"
                yield "data: [Flux ferme apres 10 min - rechargez pour continuer]\n\n"
        except FileNotFoundError:
            yield "data: [Fichier de log introuvable]\n\n"
        except (GeneratorExit, BrokenPipeError):
            return

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})
