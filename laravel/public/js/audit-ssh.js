/**
 * audit-ssh.js — audit de configuration SSH, sous-lot A1 : LECTURE SEULE.
 *
 * ══ CE QUE CE SCRIPT N'EMET JAMAIS ═══════════════════════════════════════
 *
 * Aucune requete autre que `GET`. Et parmi les `GET`, **aucun appel n'est
 * compose vers `POST /ssh-audit/policies`** — SEC-013 : l'ecriture de
 * politique est gardee par `require_role(2)` SEUL, la lecture par
 * `can_audit_ssh` + `require_machine_access`. L'ecriture est donc moins
 * gardee que la lecture, sur la MEME URL, et la passerelle ne peut pas les
 * separer : elle compare des CHEMINS, jamais des methodes.
 *
 * La fermeture se fait par l'ABSENCE. Une entree qu'on n'offre pas ne se
 * contourne pas.
 *
 * ══ `/results` : CE QUI LA REFERME N'EST PAS UNE GARDE ════════════════════
 *
 * `GET /ssh-audit/results` ne porte NI role NI permission : sa seule borne est
 * `require_machine_access`, inerte des le role 2. Ce qui la referme est la
 * ligne `if not machine_id: return 400` de son CORPS — un controle de
 * VALIDITE, pas un controle d'acces. On passe donc toujours le parametre, et
 * on ne compte pas sur ce filet.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var libelles = {};
    try {
        var bloc = document.getElementById('audit-ssh-libelles');
        if (bloc) { libelles = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { libelles = {}; }

    function t(cle, subst) {
        var s = libelles[cle];
        if (typeof s !== 'string') { return cle; }
        if (subst) {
            Object.keys(subst).forEach(function (k) { s = s.split(':' + k).join(String(subst[k])); });
        }
        return s;
    }

    function lis(chemin) {
        return fetch(PASSERELLE + chemin, { headers: { 'Accept': 'application/json' } })
            .then(function (r) {
                return r.json().then(
                    function (j) { return { ok: r.ok, corps: j }; },
                    function () { return { ok: false, corps: null }; }
                );
            })
            .catch(function () { return { ok: false, corps: null }; });
    }

    function vide(hote, texte, erreur) {
        hote.textContent = '';
        var d = document.createElement('div');
        d.className = erreur ? 'rw-vide rw-vide--erreur' : 'rw-vide';
        var p = document.createElement('p');
        p.className = 'rw-vide__texte';
        p.textContent = texte;
        d.appendChild(p);
        hote.appendChild(d);
    }

    // ── LE PANNEAU PARTAGE ───────────────────────────────────────────────
    var panneau = document.querySelector('[data-rw="audit-ssh-panneau"]');
    var pTitre = document.querySelector('[data-rw="audit-ssh-panneau-titre"]');
    var pTexte = document.querySelector('[data-rw="audit-ssh-panneau-texte"]');
    var pEffets = document.querySelector('[data-rw="audit-ssh-panneau-effets"]');
    var pFermer = document.querySelector('[data-rw="audit-ssh-panneau-fermer"]');

    function ouvrePanneau(texte, effets) {
        if (! panneau) { return; }
        pTitre.textContent = t('np_titre');
        pTexte.textContent = texte;

        pEffets.textContent = '';
        var lignes = (effets || []).filter(Boolean);
        pEffets.hidden = lignes.length === 0;
        lignes.forEach(function (l) {
            var li = document.createElement('li');
            li.textContent = l;
            pEffets.appendChild(li);
        });

        panneau.hidden = false;
        panneau.scrollIntoView({ block: 'nearest' });
    }

    if (pFermer) {
        pFermer.addEventListener('click', function () {
            panneau.hidden = true;
            pEffets.hidden = true;
            pEffets.textContent = '';
        });
    }

    var selecteur = document.querySelector('[data-rw="audit-ssh-serveur"]');

    // UN PANNEAU PARTAGE NOMME SA CIBLE. Il sert cinq boutons places a des
    // endroits differents de la page.
    function surServeur() {
        if (! selecteur || ! selecteur.value) { return ''; }
        var opt = selecteur.options[selecteur.selectedIndex];
        return t('np_sur_serveur', { nom: opt ? opt.textContent : '' });
    }

    // ── LES CAPACITES NON PORTEES ────────────────────────────────────────
    function brancher(ancre, message, detail, avecCible) {
        var b = document.querySelector('[data-rw="' + ancre + '"]');
        if (! b) { return; }
        b.addEventListener('click', function () {
            ouvrePanneau(message, [avecCible ? surServeur() : '', detail]);
        });
    }

    brancher('audit-ssh-relever', t('np_relever'), t('np_relever_detail'), true);
    brancher('audit-ssh-config', t('np_config'), t('np_config_detail'), true);
    // Celui-la ne nomme AUCUNE cible, et c'est le fait a dire : la route ne
    // prend aucun parametre. Il n'y a rien a viser, donc rien a restreindre.
    brancher('audit-ssh-parc', t('np_parc'), t('np_parc_detail'), false);
    brancher('audit-ssh-planif-creer', t('np_planif_creer'), t('np_planif_detail'), false);

    // Le panneau de planification porte en plus l'ambiguite d'E-280.
    var bPlanif = document.querySelector('[data-rw="audit-ssh-planif-creer"]');
    if (bPlanif) {
        bPlanif.addEventListener('click', function () {
            ouvrePanneau(t('np_planif_creer'), [t('np_planif_detail'), t('planif_cible_ambigue')]);
        });
    }

    // ── L'HISTORIQUE — `GET /results`, TOUJOURS avec `machine_id` ────────
    var hoteHisto = document.querySelector('[data-rw="audit-ssh-historique"]');

    function chargeHistorique(id) {
        if (! hoteHisto) { return; }
        if (! id) { vide(hoteHisto, t('historique_choisir')); return; }

        hoteHisto.textContent = t('chargement');
        lis('/ssh-audit/results?machine_id=' + encodeURIComponent(id)).then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { vide(hoteHisto, t('historique_err'), true); return; }
            var releves = r.corps.results || r.corps.history || [];
            if (! releves.length) { vide(hoteHisto, t('historique_vide')); return; }

            hoteHisto.textContent = '';
            var liste = document.createElement('div');
            liste.className = 'rw-liste-etats';
            releves.forEach(function (x) {
                var ligne = document.createElement('div');
                ligne.className = 'rw-liste-etats__ligne';

                var g = document.createElement('span');
                g.className = 'rw-liste-etats__nom';
                g.textContent = t('note') + ' ' + Number(x.score || 0) + ' · ' + t('lettre') + ' ' + String(x.grade || '');

                var d = document.createElement('span');
                // Les QUATRE severites, pas les deux plus graves. N'afficher que
                // critique et haute laisserait croire qu'un relevé sans elles est
                // sans constat — alors que le total peut etre eleve.
                d.textContent = [
                    Number(x.critical_count || 0) + ' ' + t('sev_critique'),
                    Number(x.high_count || 0) + ' ' + t('sev_haute'),
                    Number(x.medium_count || 0) + ' ' + t('sev_moyenne'),
                    Number(x.low_count || 0) + ' ' + t('sev_basse'),
                    t('le') + ' ' + String(x.scan_date || x.created_at || '').slice(0, 16),
                ].join(' · ');

                ligne.appendChild(g);
                ligne.appendChild(d);
                liste.appendChild(ligne);
            });
            hoteHisto.appendChild(liste);
        });
    }

    // ── LA POLITIQUE — `GET /policies` SEUL, jamais le POST ──────────────
    var hotePol = document.querySelector('[data-rw="audit-ssh-politique"]');

    function chargePolitique(id) {
        if (! hotePol) { return; }
        if (! id) { vide(hotePol, t('politique_choisir')); return; }

        hotePol.textContent = t('chargement');
        lis('/ssh-audit/policies?machine_id=' + encodeURIComponent(id)).then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { vide(hotePol, t('politique_err'), true); return; }
            var regles = r.corps.policies || [];
            if (! regles.length) { vide(hotePol, t('politique_vide')); return; }

            hotePol.textContent = '';
            var liste = document.createElement('div');
            liste.className = 'rw-liste-etats';
            regles.forEach(function (p) {
                var ligne = document.createElement('div');
                ligne.className = 'rw-liste-etats__ligne';

                var n = document.createElement('span');
                n.className = 'rw-liste-etats__nom';
                n.textContent = String(p.directive || p.rule_key || '');

                var e = document.createElement('span');
                var audite = p.audit === undefined ? p.enabled : p.audit;
                var bout = audite ? t('politique_auditee') : t('politique_ignoree');
                if (p.reason) { bout += ' — ' + t('politique_motif') + ' : ' + String(p.reason); }
                e.textContent = bout;

                ligne.appendChild(n);
                ligne.appendChild(e);
                liste.appendChild(ligne);
            });
            hotePol.appendChild(liste);
        });
    }

    if (selecteur) {
        selecteur.addEventListener('change', function () {
            chargeHistorique(selecteur.value);
            chargePolitique(selecteur.value);
        });
    }

    // ── LA FLOTTE — reservee a l'administration, NON bornee au perimetre ──
    var hoteFlotte = document.querySelector('[data-rw="audit-ssh-flotte"]');
    if (hoteFlotte) {
        hoteFlotte.textContent = t('chargement');
        lis('/ssh-audit/fleet').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { vide(hoteFlotte, t('flotte_err'), true); return; }
            var lignes = r.corps.fleet || r.corps.servers || [];
            if (! lignes.length) { vide(hoteFlotte, t('flotte_vide')); return; }

            hoteFlotte.textContent = '';
            var cadre = document.createElement('div');
            cadre.className = 'rw-tableau-cadre';
            var tab = document.createElement('table');
            tab.className = 'rw-tableau';

            var thead = document.createElement('thead');
            var tr = document.createElement('tr');
            ['th_serveur', 'th_ip', 'th_note', 'th_mention', 'th_critiques', 'th_releve_le'].forEach(function (c) {
                var th = document.createElement('th');
                th.textContent = t(c);
                tr.appendChild(th);
            });
            thead.appendChild(tr);
            tab.appendChild(thead);

            var tbody = document.createElement('tbody');
            lignes.forEach(function (m) {
                var l = document.createElement('tr');
                [
                    String(m.name || ''),
                    String(m.ip || ''),
                    m.score == null ? '—' : String(m.score),
                    String(m.grade || '—'),
                    m.critical_count == null ? '—' : String(m.critical_count),
                    String(m.last_scan || m.scan_date || '—').slice(0, 16),
                ].forEach(function (v) {
                    var td = document.createElement('td');
                    td.textContent = v;
                    l.appendChild(td);
                });
                tbody.appendChild(l);
            });
            tab.appendChild(tbody);
            cadre.appendChild(tab);
            hoteFlotte.appendChild(cadre);
        });
    }

    // ── LES PLANIFICATIONS — lecture seule en A1 ─────────────────────────
    var hotePlanifs = document.querySelector('[data-rw="audit-ssh-planifs"]');

    /*
     * ⚠ E-280 — CE QUE LA CIBLE VEUT DIRE, ET CE QU'ELLE NE DIT PAS.
     *
     * `scheduler.py` route sur `target_type` : `tag`, `environment`,
     * `machines`, et un `else` final. Ce `else` est atteint par « tout le
     * parc » — la valeur par defaut — ET par toute valeur non reconnue, ET
     * par un `target_value` vide sur `tag` ou `environment`. Les trois
     * passent par le MEME chemin.
     *
     * On distingue donc a l'ecran ce que la donnee permet de distinguer, et
     * on nomme le reste « non reconnu » plutot que de le presenter comme un
     * choix.
     */
    function cible(p) {
        var type = String(p.target_type || '');
        var valeur = p.target_value;

        if (type === 'tag' && valeur) { return t('planif_cible_tag', { valeur: String(valeur) }); }
        if (type === 'environment' && valeur) { return t('planif_cible_env', { valeur: String(valeur) }); }
        if (type === 'machines' && valeur) {
            var n = 0;
            try { var ids = JSON.parse(valeur); n = Array.isArray(ids) ? ids.length : 0; } catch (e) { n = 0; }
            return t('planif_cible_machines', { n: n });
        }
        if (type === 'all') { return t('planif_cible_parc'); }
        return t('planif_cible_inconnue');
    }

    if (hotePlanifs) {
        hotePlanifs.textContent = t('chargement');
        lis('/ssh-audit/schedules').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { vide(hotePlanifs, t('planifs_err'), true); return; }
            var planifs = r.corps.schedules || [];
            if (! planifs.length) { vide(hotePlanifs, t('planifs_vide')); return; }

            hotePlanifs.textContent = '';
            var liste = document.createElement('div');
            liste.className = 'rw-liste-etats';
            planifs.forEach(function (p) {
                var ligne = document.createElement('div');
                ligne.className = 'rw-liste-etats__ligne';

                var n = document.createElement('span');
                n.className = 'rw-liste-etats__nom';
                n.textContent = String(p.name || '');

                var d = document.createElement('span');
                d.textContent = [
                    String(p.cron_expression || ''),
                    cible(p),
                    p.enabled ? t('planif_active') : t('planif_suspendue'),
                    p.next_run ? t('planif_prochaine') + ' ' + String(p.next_run).slice(0, 16) : '',
                ].filter(Boolean).join(' · ');

                ligne.appendChild(n);
                ligne.appendChild(d);
                liste.appendChild(ligne);
            });
            hotePlanifs.appendChild(liste);
        });
    }
})();
