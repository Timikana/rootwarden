import json
import time
import threading
from datetime import datetime
from flask import Blueprint, jsonify, request, Response
from routes.helpers import require_api_key, require_role, require_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger, get_current_user
from ssh_utils import ssh_session, validate_machine_id
from config import Config
from cve_scanner import scan_server, get_last_scan_results, get_scan_history, get_opencve_client
from mail_utils import send_cve_report

bp = Blueprint('cve', __name__)

# Verrou global : un seul scan CVE a la fois (evite l'epuisement du thread pool)
_scan_lock = threading.Lock()

# Patch A04-INSEC-N2 : rate-limit par user (dict en memoire, OK car worker
# unique Hypercorn). Pour multi-worker, deplacer en table SQL.
_user_scan_throttle: dict[int, float] = {}


def _stream_cve_scan(machine_ids: list[int], min_cvss: float,
                      per_machine_cvss: dict = None,
                      scan_source: str = 'hybrid'):
    """
    Générateur commun pour les routes /cve_scan et /cve_scan_all.
    Chaque événement est une ligne JSON terminée par \\n.

    per_machine_cvss : dict optionnel {machine_id (int): min_cvss (float)}
                       Si fourni, le seuil par machine est prioritaire sur min_cvss global.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        if machine_ids:
            fmt = ','.join(['%s'] * len(machine_ids))
            cur.execute(
                f"SELECT id, name, ip, port, user, password, root_password, platform_key_deployed, service_account_deployed "
                f"FROM machines WHERE id IN ({fmt})", machine_ids
            )
        else:
            cur.execute(
                "SELECT id, name, ip, port, user, password, root_password, platform_key_deployed, service_account_deployed FROM machines"
            )
        machines = cur.fetchall()
    finally:
        conn.close()

    if not machines:
        yield json.dumps({'type': 'error', 'message': 'Aucun serveur trouvé'}) + '\n'
        return

    for m in machines:
        ssh_user = m['user']
        ssh_pass = server_decrypt_password(m.get('password', '')) or ''
        root_pass = server_decrypt_password(m.get('root_password', '')) or ''
        has_keypair = m.get('service_account_deployed') or m.get('platform_key_deployed', False)
        if not ssh_pass and not has_keypair:
            yield json.dumps({'type': 'error', 'machine_id': m['id'],
                              'message': 'Ni mot de passe ni keypair disponible'}) + '\n'
            continue

        try:
            # Seuil par machine si fourni, sinon seuil global
            machine_cvss = float(per_machine_cvss.get(str(m['id']), per_machine_cvss.get(m['id'], min_cvss))) \
                if per_machine_cvss else min_cvss
            machine_cvss = max(0.0, min(10.0, machine_cvss))

            with ssh_session(m['ip'], m['port'], ssh_user, ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
                all_findings = []
                for event in scan_server(client, m['id'], m['name'], machine_cvss, scan_source=scan_source):
                    yield json.dumps(event, default=str) + '\n'
                    if event['type'] == 'finding':
                        all_findings.append(event)
                    elif event['type'] == 'done' and all_findings:
                        # Envoyer rapport email via MAIL_TO global (legacy)
                        send_cve_report(
                            machine_name=m['name'],
                            ip=m['ip'],
                            findings=all_findings,
                            min_cvss=min_cvss,
                        )
                        # Notifications ciblees via preferences utilisateur
                        try:
                            from notify import notify_subscribed
                            notify_subscribed(
                                event_type='cve_scan',
                                title=f"Scan CVE : {len(all_findings)} finding(s) sur {m['name']}",
                                message=f"{m['name']} ({m['ip']}) - {len(all_findings)} CVE detectee(s)",
                                link='/security/',
                                machine_id=m['id'],
                            )
                        except Exception:
                            pass
                        # Alerte securite si CVE critiques
                        criticals = [f for f in all_findings if f.get('severity') == 'CRITICAL']
                        if criticals:
                            try:
                                from notify import notify_subscribed as _ns
                                _ns(
                                    event_type='security_alert',
                                    title=f"{len(criticals)} CVE critique(s) sur {m['name']}",
                                    message=f"{criticals[0].get('cve_id', '?')} (CVSS {criticals[0].get('cvss_score', '?')}) + {len(criticals)-1} autre(s)" if len(criticals) > 1 else f"{criticals[0].get('cve_id', '?')} - CVSS {criticals[0].get('cvss_score', '?')}",
                                    link='/security/',
                                    machine_id=m['id'],
                                )
                            except Exception:
                                pass
        except Exception as e:
            logger.error("CVE scan (%s) : %s", m['name'], e)
            yield json.dumps({'type': 'error', 'machine_id': m['id'],
                              'message': str(e)}) + '\n'


@bp.route('/cve_scan', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def cve_scan():
    """
    Scanne un serveur spécifique (ou une liste) pour les CVEs.
    Body JSON : {machine_id: int | [int], min_cvss: float}
    Retourne un flux JSON-lines (text/plain).
    """
    data = request.get_json(silent=True) or {}
    raw_id = data.get('machine_id')
    min_cvss = float(data.get('min_cvss', Config.CVE_MIN_CVSS))
    min_cvss = max(0.0, min(10.0, min_cvss))
    scan_source = str(data.get('scan_source', 'hybrid')).lower()
    if scan_source not in ('fast', 'hybrid', 'precise'):
        scan_source = 'hybrid'
    logger.info("CVE scan request: machine_id=%s, min_cvss=%s, scan_source=%s, raw_data=%s", raw_id, min_cvss, scan_source, {k: data[k] for k in ('machine_id', 'min_cvss', 'per_machine_cvss', 'scan_source') if k in data})

    # Seuils par serveur : {"per_machine_cvss": {"1": 4.0, "2": 9.0}}
    per_machine_cvss = data.get('per_machine_cvss', None)

    if raw_id is None:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400

    if isinstance(raw_id, list):
        try:
            ids = [validate_machine_id(i) for i in raw_id]
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400
    else:
        try:
            ids = [validate_machine_id(raw_id)]
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400

    # Patch A04-INSEC-N2 (OWASP A04) : rate-limit par utilisateur (60s entre scans).
    # _scan_lock est global mais non-bloquant ; un user role=1 pouvait spammer
    # /cve_scan, chaque tentative consommait un thread+DB.
    user_id, _role = get_current_user()
    now_ts = time.time()
    last = _user_scan_throttle.get(user_id, 0)
    if user_id and (now_ts - last) < 60:
        return jsonify({
            'success': False,
            'message': f"Patientez {int(60 - (now_ts - last))}s avant un nouveau scan CVE."
        }), 429
    if user_id:
        _user_scan_throttle[user_id] = now_ts

    if not _scan_lock.acquire(blocking=False):
        return jsonify({'success': False, 'message': 'Un scan CVE est deja en cours. Reessayez plus tard.'}), 429

    def locked_stream():
        try:
            yield from _stream_cve_scan(ids, min_cvss, per_machine_cvss, scan_source=scan_source)
        finally:
            _scan_lock.release()

    return Response(locked_stream(), mimetype='text/plain')


@bp.route('/cve_scan_all', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def cve_scan_all():
    """
    Scanne TOUS les serveurs.
    Body JSON : {min_cvss: float}
    Retourne un flux JSON-lines (text/plain).
    """
    data = request.get_json(silent=True) or {}
    min_cvss = float(data.get('min_cvss', Config.CVE_MIN_CVSS))
    min_cvss = max(0.0, min(10.0, min_cvss))
    per_machine_cvss = data.get('per_machine_cvss', None)
    scan_source = str(data.get('scan_source', 'hybrid')).lower()
    if scan_source not in ('fast', 'hybrid', 'precise'):
        scan_source = 'hybrid'

    if not _scan_lock.acquire(blocking=False):
        return jsonify({'success': False, 'message': 'Un scan CVE est deja en cours. Reessayez plus tard.'}), 429

    def locked_stream():
        try:
            yield from _stream_cve_scan([], min_cvss, per_machine_cvss, scan_source=scan_source)
        finally:
            _scan_lock.release()

    return Response(locked_stream(), mimetype='text/plain')


@bp.route('/cve_results', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def cve_results():
    """
    Retourne les résultats du dernier scan pour un serveur.
    Query : ?machine_id=<int>
    """
    try:
        machine_id = validate_machine_id(request.args.get('machine_id'))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400

    results = get_last_scan_results(machine_id)
    if results is None:
        return jsonify({'success': True, 'scan': None, 'findings': []})
    return jsonify({'success': True, **results})


@bp.route('/cve_reprioritize', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def cve_reprioritize():
    """
    Re-enrichit (EPSS + CISA KEV) les findings du dernier scan d'une machine,
    SANS reconnexion SSH. Coeur de la boucle de priorisation : permet de
    rafraichir quotidiennement la probabilite d'exploitation et de remonter
    les CVE devenues "activement exploitees" (entrees au catalogue KEV) sans
    relancer un scan complet (lent).

    Body JSON : {machine_id: int}
    """
    data = request.get_json(silent=True) or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        # Dernier scan complete de la machine
        cur.execute(
            "SELECT id FROM cve_scans WHERE machine_id = %s AND status = 'completed' "
            "ORDER BY scan_date DESC LIMIT 1",
            (machine_id,)
        )
        scan = cur.fetchone()
        if not scan:
            return jsonify({'success': False, 'message': 'Aucun scan a re-prioriser'}), 404

        cur.execute(
            "SELECT id, cve_id, cvss_score FROM cve_findings WHERE scan_id = %s",
            (scan['id'],)
        )
        rows = cur.fetchall()
        if not rows:
            return jsonify({'success': True, 'enriched': 0, 'kev': 0, 'epss': 0})

        findings = [{'cve_id': r['cve_id'], 'cvss': r['cvss_score'] or 0.0} for r in rows]
        try:
            from cve_enrich import enrich_findings
            stats = enrich_findings(findings)
        except Exception as e:
            logger.error("cve_reprioritize enrich failed: %s", e)
            return jsonify({'success': False, 'message': 'Enrichissement indisponible'}), 503

        upd = conn.cursor()
        for r, f in zip(rows, findings):
            upd.execute(
                "UPDATE cve_findings SET epss_score=%s, epss_percentile=%s, kev=%s, "
                "kev_date_added=%s, priority_score=%s, priority_label=%s WHERE id=%s",
                (f.get('epss_score'), f.get('epss_percentile'),
                 1 if f.get('kev') else 0, f.get('kev_date_added'),
                 f.get('priority_score'), f.get('priority_label'), r['id'])
            )
        conn.commit()
        return jsonify({'success': True, 'enriched': len(rows),
                        'kev': stats.get('kev', 0), 'epss': stats.get('epss', 0)})
    finally:
        conn.close()


@bp.route('/cve_history', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def cve_history():
    """
    Retourne l'historique des scans pour un serveur.
    Query : ?machine_id=<int>&limit=<int>
    """
    try:
        machine_id = validate_machine_id(request.args.get('machine_id'))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400

    limit = min(int(request.args.get('limit', 10)), 50)
    history = get_scan_history(machine_id, limit)
    return jsonify({'success': True, 'history': history})


@bp.route('/cve_compare', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def cve_compare():
    """
    Compare 2 scans CVE et retourne les differences.
    Query : ?machine_id=<int>&scan1=<id>&scan2=<id>
    Si scan1/scan2 absents, compare les 2 derniers scans.
    """
    try:
        machine_id = validate_machine_id(request.args.get('machine_id'))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        scan1_id = request.args.get('scan1')
        scan2_id = request.args.get('scan2')

        if not scan1_id or not scan2_id:
            cur.execute(
                "SELECT id, scan_date FROM cve_scans WHERE machine_id = %s AND status = 'completed' ORDER BY scan_date DESC LIMIT 2",
                (machine_id,)
            )
            scans = cur.fetchall()
            if len(scans) < 2:
                return jsonify({'success': False, 'message': 'Moins de 2 scans disponibles pour comparaison'})
            scan2_id = scans[0]['id']  # plus recent
            scan1_id = scans[1]['id']  # precedent

        # Patch A01 (IDOR) : verifier que les DEUX scans appartiennent bien a la
        # machine autorisee. Avant, scan1/scan2 fournis en query etaient requetes
        # directement -> un user pouvait lire les findings de scans d'une autre
        # machine en devinant des ids sequentiels.
        try:
            s1, s2 = int(scan1_id), int(scan2_id)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'scan invalide'}), 400
        cur.execute(
            "SELECT id FROM cve_scans WHERE id IN (%s, %s) AND machine_id = %s",
            (s1, s2, machine_id)
        )
        owned = {r['id'] for r in cur.fetchall()}
        if s1 not in owned or s2 not in owned:
            return jsonify({'success': False, 'message': 'Scan introuvable pour cette machine'}), 403

        # CVE du scan 1 (ancien)
        cur.execute("SELECT cve_id, package_name, cvss_score, severity FROM cve_findings WHERE scan_id = %s", (int(scan1_id),))
        cves1 = {r['cve_id']: r for r in cur.fetchall()}

        # CVE du scan 2 (recent)
        cur.execute("SELECT cve_id, package_name, cvss_score, severity FROM cve_findings WHERE scan_id = %s", (int(scan2_id),))
        cves2 = {r['cve_id']: r for r in cur.fetchall()}

        # Diff
        added = [cves2[c] for c in cves2 if c not in cves1]
        removed = [cves1[c] for c in cves1 if c not in cves2]
        unchanged = len(set(cves1.keys()) & set(cves2.keys()))

        # Scan metadata
        cur.execute("SELECT id, scan_date, cve_count FROM cve_scans WHERE id IN (%s, %s)", (int(scan1_id), int(scan2_id)))
        meta = {r['id']: r for r in cur.fetchall()}
        for m in meta.values():
            if m.get('scan_date') and hasattr(m['scan_date'], 'isoformat'):
                m['scan_date'] = m['scan_date'].isoformat()

        return jsonify({
            'success': True,
            'scan1': meta.get(int(scan1_id)),
            'scan2': meta.get(int(scan2_id)),
            'added': added,
            'removed': removed,
            'added_count': len(added),
            'removed_count': len(removed),
            'unchanged': unchanged,
        })
    finally:
        conn.close()


@bp.route('/cve_test_connection', methods=['GET'])
@require_api_key
@threaded_route
def cve_test_connection():
    """Teste la connectivité avec l'instance OpenCVE configurée."""
    ok, msg = get_opencve_client().test_connection()
    return jsonify({'success': ok, 'message': msg,
                    'url': Config.OPENCVE_URL})


@bp.route('/cve_schedules', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def list_cve_schedules():
    """Liste toutes les planifications de scans CVE."""
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM cve_scan_schedules ORDER BY created_at DESC")
        schedules = cur.fetchall()
        for s in schedules:
            for k in ('last_run', 'next_run', 'created_at'):
                if s.get(k):
                    s[k] = s[k].isoformat() if hasattr(s[k], 'isoformat') else str(s[k])
        return jsonify({'success': True, 'schedules': schedules})
    finally:
        conn.close()


@bp.route('/cron_preview', methods=['GET'])
@require_api_key
@require_role(2)
def cron_preview():
    """Previsualise les N prochains declenchements d'une expression cron.

    Aide l'admin non-expert : on appelle cet endpoint en live pendant qu'il
    tape, et l'UI affiche "Prochains : 22/04 07:30, 07:35, 07:40...". Les
    presets UI (toutes les 5 min, quotidien 3h...) utilisent aussi cette
    route pour valider avant soumission.
    """
    expr = (request.args.get('expr') or '').strip()
    if not expr:
        return jsonify({'valid': False, 'error': 'expression requise'})
    try:
        from croniter import croniter
        from datetime import timezone
        if not croniter.is_valid(expr):
            return jsonify({'valid': False, 'error': 'Expression cron invalide'})
        # On fournit les datetimes en ISO 8601 UTC (suffixe Z) pour que le
        # frontend les convertisse automatiquement vers la TZ du navigateur
        # via new Date(iso).toLocaleString(). Evite le bug "il est 10h13
        # mais l'UI affiche 8h15" quand le container tourne en UTC.
        base = datetime.now(timezone.utc)
        it = croniter(expr, base)
        runs = []
        for _ in range(5):
            d = it.get_next(datetime)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            runs.append(d.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        # Description humaine basique (meilleure approche : python-crontab
        # descriptor, mais on evite une dep de plus).
        parts = expr.split()
        if len(parts) == 5:
            m, h, dom, mo, dow = parts
            if m.startswith('*/') or m.startswith('0/'):
                human = f"Toutes les {m.split('/')[-1]} minutes"
            elif m == '*' and h == '*':
                human = "Chaque minute"
            elif m.isdigit() and h == '*':
                human = f"A la minute {m} de chaque heure"
            elif m.isdigit() and h.isdigit() and dom == '*' and mo == '*' and dow == '*':
                human = f"Tous les jours a {int(h):02d}:{int(m):02d}"
            elif m.isdigit() and h.isdigit() and dow != '*':
                dn = {'0': 'dim', '1': 'lun', '2': 'mar', '3': 'mer', '4': 'jeu',
                      '5': 'ven', '6': 'sam', '7': 'dim'}.get(dow, dow)
                human = f"Tous les {dn} a {int(h):02d}:{int(m):02d}"
            else:
                human = f"Selon l'expression : {expr}"
        else:
            human = f"Selon l'expression : {expr}"
        return jsonify({'valid': True, 'next_runs': runs, 'human': human})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)[:200]})


# Liste fermee des portees offertes a la creation (E-388). Releve du
# portage : PlanificationsCve::CIBLES. 'all' en est absent DES DEUX
# cotes — il reste lisible, il n'est plus proposable.
PORTEES = ('tag', 'machines')


@bp.route('/cve_schedules', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def create_cve_schedule():
    """Cree une planification de scan CVE."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    cron_expr = (data.get('cron_expression') or '0 3 * * *').strip()
    min_cvss = float(data.get('min_cvss', 7.0))
    # E-388 : pas de defaut FABRIQUE. `('target_type') or ''` et non
    # `.get(..., 'all')` : une cle presente a `null` rend None, et le
    # defaut ne se declenche pas. Un champ absent, vide ou nul tombe
    # donc hors de la liste fermee — le refus est obtenu SANS branche.
    target_type = (data.get('target_type') or '').strip()
    target_value = (data.get('target_value') or '').strip()
    scan_source = str(data.get('scan_source', 'hybrid')).lower()
    if scan_source not in ('fast', 'hybrid', 'precise'):
        scan_source = 'hybrid'

    # ══ E-388 : « TOUT LE PARC » N'EST PLUS OFFERT A LA CREATION ═════════
    #
    # `PORTEES` ne contient PAS 'environment' : ni l'ecran ni l'executeur
    # CVE ne le connaissent (`scheduler.py` n'a que tag et machines). Une
    # valeur que l'executeur ne sait pas lire finirait dans son echec
    # ferme — l'accepter ici ne creerait qu'une planification muette.
    #
    # Cette garde ferme la CREATION. Elle ne ferme ni la lecture ni
    # l'execution d'une ligne 'all' deja en base : `scheduler.py` porte
    # une branche 'all' explicite. Cesser d'offrir n'est pas cesser de
    # savoir lire.
    if target_type == 'all':
        return jsonify({'success': False, 'message':
            "Portee 'all' refusee a la creation : choisis 'tag' ou 'machines'. "
            "Les planifications 'all' existantes continuent de fonctionner."}), 400
    if target_type not in PORTEES:
        return jsonify({'success': False, 'message':
            f"target_type requis, parmi {', '.join(PORTEES)}"}), 400
    if not target_value:
        return jsonify({'success': False, 'message':
            f"target_value requis pour la portee '{target_type}'"}), 400

    if not name:
        return jsonify({'success': False, 'message': 'Nom requis'}), 400

    # Valider l'expression cron
    try:
        from croniter import croniter
        if not croniter.is_valid(cron_expr):
            raise ValueError("Expression cron invalide")
        it = croniter(cron_expr)
        next_run = it.get_next(datetime)
        # Patch A04-INSEC-N1 (OWASP A04 Insecure Design) : refuse les schedules
        # plus frequents que 10 minutes. Sans ce clamp, '* * * * *' lancait un
        # scan par minute -> ban OpenCVE upstream + DoS interne + abus admin
        # malveillant. 600s = compromise raisonnable (cron quotidien typique).
        following = it.get_next(datetime)
        if (following - next_run).total_seconds() < 600:
            return jsonify({
                'success': False,
                'message': "Frequence cron trop elevee (intervalle minimum 10 minutes)"
            }), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Expression cron invalide: {e}'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO cve_scan_schedules (name, cron_expression, min_cvss, scan_source, target_type, target_value, next_run) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (name, cron_expr, min_cvss, scan_source, target_type, target_value, next_run)
        )
        conn.commit()
        return jsonify({'success': True, 'id': cur.lastrowid})
    finally:
        conn.close()


@bp.route('/cve_schedules/<int:schedule_id>', methods=['PUT'])
@require_api_key
@require_role(2)
@threaded_route
def update_cve_schedule(schedule_id):
    """Met a jour une planification existante."""
    data = request.get_json(silent=True) or {}
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM cve_scan_schedules WHERE id = %s", (schedule_id,))
        if not cur.fetchone():
            return jsonify({'success': False, 'message': 'Planification introuvable'}), 404

        updates = []
        params = []
        for field in ('name', 'cron_expression', 'min_cvss', 'scan_source', 'target_type', 'target_value', 'enabled'):
            if field in data:
                val = data[field]
                if field == 'scan_source':
                    val = str(val).lower()
                    if val not in ('fast', 'hybrid', 'precise'):
                        val = 'hybrid'
                # E-388 : sans ceci la garde de creation serait DECORATIVE.
                # Cette boucle ecrivait `target_type` sans aucun controle :
                # une planification 'tag' se repointait sur 'all' — ou sur
                # n'importe quelle chaine — par une simple modification.
                # Le champ ABSENT du corps n'entre pas dans la boucle : une
                # ligne 'all' existante reste modifiable sur ses autres
                # colonnes, conformement a « fermer la creation, pas la
                # lecture ».
                if field == 'target_type' and (val or '') not in PORTEES:
                    return jsonify({'success': False, 'message':
                        f"target_type invalide : {val!r}. Attendu parmi "
                        f"{', '.join(PORTEES)}. La portee 'all' ne se pose "
                        "plus par modification."}), 400
                updates.append(f"{field} = %s")
                params.append(val)

        if 'cron_expression' in data:
            try:
                from croniter import croniter
                next_run = croniter(data['cron_expression']).get_next(datetime)
                updates.append("next_run = %s")
                params.append(next_run)
            except Exception:
                pass

        if updates:
            params.append(schedule_id)
            cur.execute(f"UPDATE cve_scan_schedules SET {', '.join(updates)} WHERE id = %s", params)
            conn.commit()

        return jsonify({'success': True})
    finally:
        conn.close()


@bp.route('/cve_schedules/<int:schedule_id>', methods=['DELETE'])
@require_api_key
@require_role(2)
@threaded_route
def delete_cve_schedule(schedule_id):
    """Supprime une planification."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM cve_scan_schedules WHERE id = %s", (schedule_id,))
        conn.commit()
        return jsonify({'success': True, 'deleted': cur.rowcount > 0})
    finally:
        conn.close()


@bp.route('/cve_whitelist', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def list_cve_whitelist():
    """Liste les CVE en whitelist."""
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT w.*, m.name as machine_name FROM cve_whitelist w "
            "LEFT JOIN machines m ON w.machine_id = m.id "
            "ORDER BY w.created_at DESC"
        )
        items = cur.fetchall()
        for i in items:
            for k in ('created_at', 'expires_at'):
                if i.get(k) and hasattr(i[k], 'isoformat'):
                    i[k] = i[k].isoformat()
        return jsonify({'success': True, 'whitelist': items})
    finally:
        conn.close()


@bp.route('/cve_whitelist', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def add_cve_whitelist():
    """Ajoute une CVE en whitelist (faux positif accepte)."""
    data = request.get_json(silent=True) or {}
    cve_id = (data.get('cve_id') or '').strip()
    reason = (data.get('reason') or '').strip()
    machine_id = data.get('machine_id')  # None = global
    whitelisted_by = (data.get('whitelisted_by') or 'admin').strip()
    expires_at = data.get('expires_at')  # YYYY-MM-DD ou null

    if not cve_id or not reason:
        return jsonify({'success': False, 'message': 'cve_id et reason requis'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO cve_whitelist (cve_id, machine_id, reason, whitelisted_by, expires_at) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE reason = VALUES(reason), whitelisted_by = VALUES(whitelisted_by), expires_at = VALUES(expires_at)",
            (cve_id, machine_id, reason, whitelisted_by, expires_at)
        )
        conn.commit()
        return jsonify({'success': True, 'id': cur.lastrowid})
    finally:
        conn.close()


@bp.route('/cve_whitelist/<int:whitelist_id>', methods=['DELETE'])
@require_api_key
@require_role(2)
@threaded_route
def delete_cve_whitelist(whitelist_id):
    """Supprime une entree de la whitelist CVE."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM cve_whitelist WHERE id = %s", (whitelist_id,))
        conn.commit()
        return jsonify({'success': True, 'deleted': cur.rowcount > 0})
    finally:
        conn.close()


@bp.route('/cve_remediation', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def list_cve_remediation():
    """Liste les remediations filtrees par statut."""
    status = request.args.get('status')
    machine_id = request.args.get('machine_id')
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        query = """SELECT r.*, m.name as machine_name, u.name as assigned_name
                   FROM cve_remediation r
                   LEFT JOIN machines m ON r.machine_id = m.id
                   LEFT JOIN users u ON r.assigned_to = u.id
                   WHERE 1=1"""
        params = []
        if status:
            query += " AND r.status = %s"
            params.append(status)
        if machine_id:
            query += " AND r.machine_id = %s"
            params.append(int(machine_id))
        query += " ORDER BY FIELD(r.status,'open','in_progress','accepted','wont_fix','resolved'), r.deadline"
        cur.execute(query, params)
        items = cur.fetchall()
        for i in items:
            for k in ('opened_at', 'resolved_at', 'deadline'):
                if i.get(k) and hasattr(i[k], 'isoformat'):
                    i[k] = i[k].isoformat()
        return jsonify({'success': True, 'remediations': items})
    finally:
        conn.close()


@bp.route('/cve_remediation', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def upsert_cve_remediation():
    """Cree ou met a jour une remediation CVE."""
    data = request.get_json(silent=True) or {}
    cve_id = (data.get('cve_id') or '').strip()
    machine_id = data.get('machine_id')
    status = data.get('status', 'open')
    assigned_to = data.get('assigned_to')
    deadline = data.get('deadline')
    note = data.get('resolution_note', '')

    if not cve_id or not machine_id:
        return jsonify({'success': False, 'message': 'cve_id et machine_id requis'}), 400

    resolved_at = None
    if status == 'resolved':
        from datetime import datetime as dt
        resolved_at = dt.now()

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO cve_remediation (cve_id, machine_id, status, assigned_to, deadline, resolution_note, resolved_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON DUPLICATE KEY UPDATE status = VALUES(status), assigned_to = VALUES(assigned_to),
                   deadline = VALUES(deadline), resolution_note = VALUES(resolution_note),
                   resolved_at = VALUES(resolved_at)""",
            (cve_id, int(machine_id), status, assigned_to, deadline, note, resolved_at)
        )
        conn.commit()
        return jsonify({'success': True, 'id': cur.lastrowid})
    finally:
        conn.close()


@bp.route('/cve_remediation/stats', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def cve_remediation_stats():
    """Compteurs de remediation par statut."""
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT status, COUNT(*) as cnt FROM cve_remediation GROUP BY status ORDER BY status")
        rows = cur.fetchall()
        stats = {r['status']: r['cnt'] for r in rows}
        # Deadlines expirees
        cur.execute("SELECT COUNT(*) as cnt FROM cve_remediation WHERE deadline < CURDATE() AND status IN ('open','in_progress')")
        stats['overdue'] = cur.fetchone()['cnt']
        return jsonify({'success': True, 'stats': stats})
    finally:
        conn.close()
