/**
 * wazuh.js — sous-lot R1 : LECTURE SEULE.
 *
 * ══ CE SCRIPT N'EMET QUE DES `GET` ════════════════════════════════════════
 *
 * Cinq lectures, et rien d'autre. Aucun des neuf gestes d'ecriture du module
 * n'est compose ici — fermeture par l'ABSENCE.
 *
 * ⚠ ET C'EST LA METHODE QUI DISCRIMINE, PAS LE CHEMIN. Trois chemins du
 * module portent deux methodes :
 *
 *     /wazuh/config        GET lit   ·  POST ecrit
 *     /wazuh/options       GET lit   ·  POST ecrit
 *     /wazuh/rules/<name>  GET lit   ·  DELETE supprime
 *
 * Un classement par chemin ne separe donc pas ce qu'on porte de ce qu'on
 * declare absent. `lis()` ci-dessous ne sait faire qu'un `GET` : c'est la
 * garantie, et elle est structurelle plutot que documentaire.
 *
 * ══ « ZERO » ET « JE N'AI PAS SU LIRE » NE SONT PAS LE MEME ECRAN ═════════
 *
 * `wazuh_agents` porte ZERO ligne, et c'est l'etat NORMAL : E-224 montre que
 * `install_all` rendait 500 sans `try` (un `AND a.id IS NULL` sur une table
 * sans colonne `id`), donc le module n'a jamais rien installe. **Un parc sans
 * agent n'est pas une base injoignable**, et rendre le meme ecran pour les
 * deux ferait passer un incident pour un fait.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var libelles = {};
    try {
        var bloc = document.getElementById('wazuh-libelles');
        if (bloc) { libelles = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { libelles = {}; }

    function t(cle) {
        var s = libelles[cle];
        return typeof s === 'string' ? s : cle;
    }

    /** GET, et seulement GET. Le helper ne sait pas muter. */
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

    function messageSeul(hote, texte, erreur) {
        hote.textContent = '';
        var d = document.createElement('div');
        d.className = erreur ? 'rw-vide rw-vide--erreur' : 'rw-vide';
        var p = document.createElement('p');
        p.className = 'rw-vide__texte';
        p.textContent = texte;
        d.appendChild(p);
        hote.appendChild(d);
    }

    function listeEtats(hote, paires) {
        hote.textContent = '';
        var l = document.createElement('div');
        l.className = 'rw-liste-etats';
        paires.forEach(function (p) {
            var ligne = document.createElement('div');
            ligne.className = 'rw-liste-etats__ligne';
            var n = document.createElement('span');
            n.className = 'rw-liste-etats__nom';
            n.textContent = p[0];
            var v = document.createElement('span');
            v.textContent = p[1];
            ligne.appendChild(n);
            ligne.appendChild(v);
            l.appendChild(ligne);
        });
        hote.appendChild(l);
    }

    // ── 1. LA CONFIGURATION DU MANAGER ───────────────────────────────────
    var hoteConfig = document.querySelector('[data-rw="wazuh-config"]');
    if (hoteConfig) {
        lis('/wazuh/config').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { messageSeul(hoteConfig, t('err_config'), true); return; }
            var c = r.corps.config;
            if (! c || Object.keys(c).length === 0) { messageSeul(hoteConfig, t('no_config')); return; }

            /*
             * ⚠ LES DEUX BOOLEENS DE MOT DE PASSE SE DISENT « VALEUR CHIFFREE ».
             *
             * Le backend les calcule par `bool(cfg.get('…_password'))` sur une
             * colonne CHIFFREE — mesure : `aes:sodium:…` sur 83 octets. Or le
             * chiffrement d'une chaine VIDE est non vide : le booleen mesure
             * donc la presence d'OCTETS, pas celle d'un secret.
             *
             * On rend ce que la donnee porte, pas ce qu'on aimerait qu'elle
             * dise. Moins, plutot que faux.
             */
            listeEtats(hoteConfig, [
                [t('manager_ip'), String(c.manager_ip || '—')],
                [t('manager_port'), String(c.manager_port || '—')],
                [t('registration_port'), String(c.registration_port || '—')],
                [t('registration_password'), c.registration_password_set ? t('pwd_set') : t('pwd_not_set')],
                [t('default_group'), String(c.default_group || '—')],
                [t('agent_version'), String(c.agent_version || '—')],
                [t('api_url'), String(c.api_url || '—')],
                [t('api_user'), String(c.api_user || '—')],
                [t('api_password'), c.api_password_set ? t('pwd_set') : t('pwd_not_set')],
            ]);
        });
    }

    // ── 2. LES AGENTS DU PARC ────────────────────────────────────────────
    var hoteAgents = document.querySelector('[data-rw="wazuh-agents"]');
    if (hoteAgents) {
        lis('/wazuh/servers').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { messageSeul(hoteAgents, t('err_servers'), true); return; }
            var serveurs = r.corps.servers || [];
            // ZERO n'est pas une panne : le texte le DIT, plutot que de rendre
            // le meme ecran vide que sur une erreur de lecture.
            if (! serveurs.length) { messageSeul(hoteAgents, t('no_servers')); return; }

            hoteAgents.textContent = '';
            var cadre = document.createElement('div');
            cadre.className = 'rw-tableau-cadre';
            var tab = document.createElement('table');
            tab.className = 'rw-tableau';

            var thead = document.createElement('thead');
            var tr = document.createElement('tr');
            ['col_agent_id', 'col_status', 'col_version', 'col_group', 'col_environment'].forEach(function (c) {
                var th = document.createElement('th');
                th.textContent = t(c);
                tr.appendChild(th);
            });
            thead.appendChild(tr);
            tab.appendChild(thead);

            var tbody = document.createElement('tbody');
            serveurs.forEach(function (s) {
                var l = document.createElement('tr');
                l.setAttribute('data-rw', 'wazuh-agent');
                /*
                 * ⚠ CETTE LISTE EST CELLE DES SERVEURS, PAS DES AGENTS.
                 *
                 * `machines LEFT JOIN wazuh_agents` : les colonnes d'agent sont
                 * VIDES quand la machine n'en a pas. Rendre « etat inconnu »
                 * dans ce cas ferait croire a un agent dont on ignore l'etat,
                 * alors qu'il n'y en a aucun — et `wazuh_agents` porte zero
                 * ligne sur ce parc. On distingue donc les deux.
                 */
                var aAgent = s.agent_id !== null && s.agent_id !== undefined && s.agent_id !== '';
                var etat = ! aAgent
                    ? t('sans_agent')
                    : (s.status ? t('status_' + String(s.status).toLowerCase()) : t('status_unknown'));
                [
                    String(s.name || '—'),
                    etat,
                    String(s.version || '—'),
                    String(s.group_name || '—'),
                    String(s.environment || '—'),
                ].forEach(function (v) {
                    var td = document.createElement('td');
                    td.textContent = v;
                    l.appendChild(td);
                });
                tbody.appendChild(l);
            });
            tab.appendChild(tbody);
            cadre.appendChild(tab);
            hoteAgents.appendChild(cadre);
        });
    }

    // ── 3. LES OPTIONS D'UN SERVEUR ──────────────────────────────────────
    var selecteur = document.querySelector('[data-rw="wazuh-serveur"]');
    var hoteOptions = document.querySelector('[data-rw="wazuh-options"]');
    if (selecteur && hoteOptions) {
        selecteur.addEventListener('change', function () {
            var id = selecteur.value;
            if (! id) { messageSeul(hoteOptions, t('choisir_serveur')); return; }

            messageSeul(hoteOptions, t('loading'));
            lis('/wazuh/options?machine_id=' + encodeURIComponent(id)).then(function (r) {
                if (! r.ok || ! r.corps || ! r.corps.success) { messageSeul(hoteOptions, t('err_options'), true); return; }
                var o = r.corps.options;
                if (! o || Object.keys(o).length === 0) { messageSeul(hoteOptions, t('no_options')); return; }

                var chemins = Array.isArray(o.fim_paths) ? o.fim_paths.join(', ') : String(o.fim_paths || '—');
                listeEtats(hoteOptions, [
                    [t('log_format'), String(o.log_format || '—')],
                    [t('syscheck_frequency'), String(o.syscheck_frequency || '—')],
                    [t('fim_paths'), chemins || '—'],
                    [t('active_response'), o.active_response ? '✓' : '—'],
                    [t('sca'), o.sca ? '✓' : '—'],
                    [t('rootcheck'), o.rootcheck ? '✓' : '—'],
                ]);
            });
        });
    }

    // ── 4. LES REGLES, DECODEURS ET LISTES CDB ───────────────────────────
    var hoteRegles = document.querySelector('[data-rw="wazuh-regles"]');
    if (hoteRegles) {
        lis('/wazuh/rules').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { messageSeul(hoteRegles, t('err_rules'), true); return; }
            var regles = r.corps.rules || [];
            if (! regles.length) { messageSeul(hoteRegles, t('no_rules')); return; }

            hoteRegles.textContent = '';
            var l = document.createElement('div');
            l.className = 'rw-liste-etats';
            regles.forEach(function (x) {
                var ligne = document.createElement('div');
                ligne.className = 'rw-liste-etats__ligne';
                ligne.setAttribute('data-rw', 'wazuh-regle');
                var n = document.createElement('span');
                n.className = 'rw-liste-etats__nom';
                n.textContent = String(x.name || x.rule_name || '—');
                var d = document.createElement('span');
                /*
                 * ⚠ E-335 — FLASK SERIALISE LES DATES EN RFC 1123, PAS EN ISO.
                 * `jsonify` rend « Tue, 26 May 2026 15:49:45 GMT », et un
                 * `slice(0, 10)` dessus donnait « Tue, 26 Ma » — vu a l'image.
                 * On PARSE au lieu de decouper : une date qui se lit par sa
                 * position suppose un format.
                 */
                var quand = '';
                if (x.updated_at) {
                    var d0 = new Date(x.updated_at);
                    quand = isNaN(d0.getTime()) ? String(x.updated_at) : d0.toISOString().slice(0, 10);
                }
                d.textContent = [x.kind, quand].filter(Boolean).join(' · ');
                ligne.appendChild(n);
                ligne.appendChild(d);
                l.appendChild(ligne);
            });
            hoteRegles.appendChild(l);
        });
    }
})();
