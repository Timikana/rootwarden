/**
 * wazuh.js — sous-lot R2 : LES QUATRE ECRITURES QUI N'OUVRENT PAS DE SSH.
 *
 * ══ LA GARDE DE R1 A CHANGE DE NATURE, ELLE N'A PAS DISPARU ═══════════════
 *
 * R1 fermait par l'ABSENCE : `lis()` ne savait faire qu'un `GET`, donc aucun
 * geste d'ecriture n'etait composable. Cette garantie tombe des qu'un helper
 * d'ecriture existe — **et la remplacer par un commentaire serait un recul.**
 *
 * Elle est donc remplacee par une LISTE FERMEE : `ecris()` refuse toute cible
 * qui n'est pas dans `ECRITURES_PERMISES`. Les six gestes SSH du module
 * (`install`, `install_all`, `detect`, `uninstall`, `restart`, `group`) ne sont
 * pas seulement absents du code : ils sont **inexprimables** par ce helper.
 *
 * *Ajouter `/wazuh/install` demanderait d'ajouter une ligne a la liste — un
 * geste visible en relecture, la ou un `fetch` de plus se serait fondu dans le
 * fichier.* C'est la difference entre une regle qu'on applique et une regle
 * qu'on doit se rappeler.
 *
 * ⚠ ET C'EST LA METHODE QUI DISCRIMINE, PAS LE CHEMIN. Trois chemins du
 * module portent deux methodes :
 *
 *     /wazuh/config        GET lit   ·  POST ecrit
 *     /wazuh/options       GET lit   ·  POST ecrit
 *     /wazuh/rules/<name>  GET lit   ·  DELETE supprime
 *
 * La liste fermee porte donc des COUPLES (methode, chemin), pas des chemins.
 *
 * ══ ⚠ QUATRE CHAMPS ETAIENT LUS SOUS UN NOM QUE LE BACKEND NE REND PAS ════
 *
 * Releve en portant R2, et corrige ici :
 *
 *     lu par R1            rendu par le backend
 *     o.active_response    active_response_enabled   (`wazuh.py:995`)
 *     o.sca                sca_enabled
 *     o.rootcheck          rootcheck_enabled
 *     x.kind               rule_type                 (`wazuh.py:1078`)
 *
 * Les quatre rendaient « — » ou du vide, **sans erreur**. Trois interrupteurs
 * de surveillance s'affichaient donc comme inactifs quels qu'ils soient, et le
 * type d'une regle ne s'affichait jamais. *Une valeur absente ne se signale pas
 * d'elle-meme : elle prend l'apparence d'une valeur fausse plausible.*
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

    /*
     * LA LISTE FERMEE DES ECRITURES — des COUPLES, pas des chemins.
     *
     * `/wazuh/rules/<name>` porte un nom variable : on ne peut donc pas
     * comparer la chaine entiere. La cible est nommee par une CLE, et c'est
     * `ecris()` qui construit l'URL a partir d'elle — *une URL construite par
     * l'appelant serait invisible a cette liste, et c'est exactement le piege
     * que le module a deja porte : `'/wazuh/rules/' + encodeURIComponent(name)`
     * echappe a tout motif litteral.*
     */
    var ECRITURES_PERMISES = {
        config:  { methode: 'POST',   chemin: function () { return '/wazuh/config'; } },
        options: { methode: 'POST',   chemin: function () { return '/wazuh/options'; } },
        regle:   { methode: 'POST',   chemin: function () { return '/wazuh/rules'; } },
        regleSuppr: {
            methode: 'DELETE',
            chemin: function (nom) { return '/wazuh/rules/' + encodeURIComponent(nom); }
        }
    };

    function jetonCsrf() {
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.getAttribute('content') : '';
    }

    /**
     * La SEULE facon d'ecrire depuis ce script. `cible` est une cle de
     * `ECRITURES_PERMISES` — une cle inconnue rend une erreur au lieu de partir
     * sur le reseau, ce qui rend un geste SSH inexprimable ici.
     */
    function ecris(cible, corps, argument) {
        var e = Object.prototype.hasOwnProperty.call(ECRITURES_PERMISES, cible)
            ? ECRITURES_PERMISES[cible] : null;
        if (! e) {
            // Fail-closed, et BRUYANT : un helper qui renverrait un echec muet
            // ferait passer une cible interdite pour une panne reseau.
            return Promise.resolve({ ok: false, statut: 0, corps: null, interdit: true });
        }
        var parametres = {
            method: e.methode,
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-TOKEN': jetonCsrf(),
                'Accept': 'application/json'
            }
        };
        if (corps !== null && corps !== undefined) {
            parametres.headers['Content-Type'] = 'application/json';
            parametres.body = JSON.stringify(corps);
        }
        return fetch(PASSERELLE + e.chemin(argument), parametres)
            .then(function (r) {
                return r.json().then(
                    function (j) { return { ok: r.ok, statut: r.status, corps: j }; },
                    function () { return { ok: r.ok, statut: r.status, corps: null }; }
                );
            })
            .catch(function () { return { ok: false, statut: 0, corps: null, reseau: true }; });
    }

    /** Le compte rendu d'une ecriture, et il DISTINGUE les issues. */
    function annonce(hote, texte, erreur) {
        if (! hote) { return; }
        hote.textContent = texte;
        hote.classList.toggle('rw-erreur', !! erreur);
    }

    /*
     * ⚠ « LE SERVEUR A REFUSE » ET « LE SERVEUR N'A PAS REPONDU » NE SONT PAS
     * LA MEME NOUVELLE, et la seconde porte une information que la premiere
     * n'a pas : **rien n'a ete enregistre**. Les confondre laisse quelqu'un
     * devant un ecran qui ne dit pas si son geste a pris.
     */
    function verdictEcriture(r) {
        if (r.interdit) { return { ok: false, texte: t('enr_echec') }; }
        if (r.reseau) { return { ok: false, texte: t('enr_reseau') }; }
        if (r.corps && r.corps.success) { return { ok: true, texte: t('enr_ok') }; }
        var m = r.corps && r.corps.message ? String(r.corps.message) : '';
        return {
            ok: false,
            texte: m ? t('enr_refuse').split(':message').join(m) : t('enr_echec')
        };
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
            prerempliConfig(c);
            /*
             * ⚠ CETTE LISTE NE REND PLUS QUE CE QUE LE FORMULAIRE NE PEUT PAS
             * DIRE — VU A L'IMAGE.
             *
             * En R1 elle affichait les neuf valeurs ; le formulaire de R2 les
             * affiche desormais toutes, PREREMPLIES, juste dessous. La page
             * montrait donc **deux fois la meme chose**, une fois en lecture et
             * une fois en saisie — et un lecteur ne peut pas savoir laquelle
             * fait foi.
             *
             * Les DEUX etats de mot de passe restent : ils ne sont PAS
             * representables dans un champ de saisie. Le backend blanchit les
             * secrets et ne rend que deux booleens ; un champ vide dirait
             * « aucune valeur », ce qui est faux quand il y en a une.
             */
            listeEtats(hoteConfig, [
                [t('registration_password'), c.registration_password_set ? t('pwd_set') : t('pwd_not_set')],
                [t('api_password'), c.api_password_set ? t('pwd_set') : t('pwd_not_set')],
            ]);
        });
    }

    var formConfig = document.querySelector('[data-rw="wazuh-config-form"]');
    var actionsConfig = document.querySelector('[data-rw="wazuh-config-actions"]');
    var annonceConfig = document.querySelector('[data-rw="wazuh-config-annonce"]');
    var aideMdp = document.querySelector('[data-rw="wazuh-mdp-conserve"]');

    function champ(nom) { return document.querySelector('[data-rw="' + nom + '"]'); }
    function valeur(nom) { var e = champ(nom); return e ? e.value : ''; }
    function coche(nom) { var e = champ(nom); return !! (e && e.checked); }

    /*
     * ⚠ LE FORMULAIRE NE PARAIT QU'UNE FOIS PREREMPLI, ET C'EST UNE PROPRIETE
     * DE SURETE, PAS DE CONFORT.
     *
     * `save_config` ecrit TOUS les champs : un formulaire vide soumis
     * remplacerait `default_group` par « default », `agent_version` par
     * « latest » et effacerait `api_url` — sans que rien ne le dise. **Un
     * formulaire d'edition affiche avant d'etre charge est un formulaire
     * d'effacement.**
     *
     * Les deux mots de passe font exception et restent vides : le backend ne
     * les rend pas (il les blanchit, `wazuh.py:222`), et un champ vide CONSERVE
     * la valeur (`:268-270`). C'est ce que dit `mdp_conserve`, affiche avec le
     * formulaire.
     */
    function prerempliConfig(c) {
        if (! formConfig) { return; }
        var e;
        e = champ('wazuh-manager-ip'); if (e) { e.value = c.manager_ip || ''; }
        e = champ('wazuh-manager-port'); if (e) { e.value = c.manager_port || 1514; }
        e = champ('wazuh-registration-port'); if (e) { e.value = c.registration_port || 1515; }
        e = champ('wazuh-default-group'); if (e) { e.value = c.default_group || 'default'; }
        e = champ('wazuh-agent-version'); if (e) { e.value = c.agent_version || 'latest'; }
        e = champ('wazuh-api-url'); if (e) { e.value = c.api_url || ''; }
        e = champ('wazuh-api-user'); if (e) { e.value = c.api_user || ''; }
        e = champ('wazuh-enable-ar'); if (e) { e.checked = !! c.enable_active_response; }
        formConfig.hidden = false;
        if (actionsConfig) { actionsConfig.hidden = false; }
        if (aideMdp) { aideMdp.hidden = false; }
    }

    var boutonConfig = document.querySelector('[data-rw="wazuh-config-enregistrer"]');
    if (boutonConfig) {
        boutonConfig.addEventListener('click', function () {
            boutonConfig.disabled = true;
            annonce(annonceConfig, t('enr_encours'), false);
            /*
             * Les deux mots de passe ne partent QUE s'ils ont ete saisis. Envoyer
             * une chaine vide serait indiscernable, cote backend, d'une saisie
             * vide — et la regle de conservation y repose sur `if reg_pwd`.
             */
            var corps = {
                manager_ip: valeur('wazuh-manager-ip').trim(),
                manager_port: parseInt(valeur('wazuh-manager-port'), 10) || 1514,
                registration_port: parseInt(valeur('wazuh-registration-port'), 10) || 1515,
                default_group: valeur('wazuh-default-group').trim(),
                agent_version: valeur('wazuh-agent-version').trim(),
                api_url: valeur('wazuh-api-url').trim(),
                api_user: valeur('wazuh-api-user').trim(),
                enable_active_response: coche('wazuh-enable-ar')
            };
            var rp = valeur('wazuh-reg-pwd');
            var ap = valeur('wazuh-api-pwd');
            if (rp) { corps.registration_password = rp; }
            if (ap) { corps.api_password = ap; }

            ecris('config', corps).then(function (r) {
                var v = verdictEcriture(r);
                annonce(annonceConfig, v.texte, ! v.ok);
                boutonConfig.disabled = false;
                if (v.ok) {
                    // Les champs de secret se VIDENT apres une reussite : les
                    // laisser garnis ferait repartir le meme secret au geste
                    // suivant, et il resterait dans le DOM entre-temps.
                    var a = champ('wazuh-reg-pwd'); if (a) { a.value = ''; }
                    var b = champ('wazuh-api-pwd'); if (b) { b.value = ''; }
                }
            });
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
                /*
                 * ⚠ TROIS NOMS CORRIGES : `active_response`, `sca` et
                 * `rootcheck` n'existent PAS dans la reponse. Le backend rend
                 * `active_response_enabled`, `sca_enabled`, `rootcheck_enabled`
                 * (`wazuh.py:995-996`). Les trois rendaient donc « — » quelle
                 * que soit la valeur reelle — trois interrupteurs de
                 * surveillance affiches comme inactifs, sans aucune erreur.
                 */
                listeEtats(hoteOptions, [
                    [t('log_format'), String(o.log_format || '—')],
                    [t('syscheck_frequency'), String(o.syscheck_frequency || '—')],
                    [t('fim_paths'), chemins || '—'],
                    [t('active_response'), o.active_response_enabled ? '✓' : '—'],
                    [t('sca'), o.sca_enabled ? '✓' : '—'],
                    [t('rootcheck'), o.rootcheck_enabled ? '✓' : '—'],
                ]);
                prerempliOptions(o);
            });
        });
    }

    var formOptions = document.querySelector('[data-rw="wazuh-options-form"]');
    var actionsOptions = document.querySelector('[data-rw="wazuh-options-actions"]');
    var annonceOptions = document.querySelector('[data-rw="wazuh-options-annonce"]');

    /*
     * Meme regle que la configuration : le formulaire ne parait qu'une fois
     * charge. `save_options` ecrit tous les champs — un envoi a vide remettrait
     * la frequence a 43200, viderait les chemins FIM et rallumerait SCA et
     * Rootcheck par defaut. **Sur un ecran de surveillance, un defaut applique
     * en silence est un reglage perdu sans trace.**
     */
    function prerempliOptions(o) {
        if (! formOptions) { return; }
        var e;
        e = champ('wazuh-opt-format');
        if (e) {
            // Une valeur hors de la liste fermee ne se pose PAS : `select.value`
            // rendrait '' et l'envoi suivant porterait une chaine vide, que le
            // backend refuse. On garde alors le premier choix, visible.
            var f = String(o.log_format || 'syslog');
            e.value = f;
            if (e.value !== f && e.options.length) { e.selectedIndex = 0; }
        }
        e = champ('wazuh-opt-freq'); if (e) { e.value = o.syscheck_frequency || 43200; }
        e = champ('wazuh-opt-fim');
        if (e) { e.value = Array.isArray(o.fim_paths) ? o.fim_paths.join('\n') : ''; }
        e = champ('wazuh-opt-ar'); if (e) { e.checked = !! o.active_response_enabled; }
        e = champ('wazuh-opt-sca'); if (e) { e.checked = !! o.sca_enabled; }
        e = champ('wazuh-opt-rk'); if (e) { e.checked = !! o.rootcheck_enabled; }
        formOptions.hidden = false;
        if (actionsOptions) { actionsOptions.hidden = false; }
    }

    var boutonOptions = document.querySelector('[data-rw="wazuh-options-enregistrer"]');
    if (boutonOptions) {
        boutonOptions.addEventListener('click', function () {
            var id = selecteur ? selecteur.value : '';
            // Sans serveur choisi il n'y a pas d'objet : on ne devine pas.
            if (! id) { annonce(annonceOptions, t('choisir_serveur'), true); return; }
            boutonOptions.disabled = true;
            annonce(annonceOptions, t('enr_encours'), false);

            var brut = valeur('wazuh-opt-fim').split('\n');
            var chemins = [];
            for (var i = 0; i < brut.length; i++) {
                var l = brut[i].trim();
                if (l) { chemins.push(l); }
            }
            ecris('options', {
                machine_id: parseInt(id, 10),
                log_format: valeur('wazuh-opt-format'),
                syscheck_frequency: parseInt(valeur('wazuh-opt-freq'), 10) || 43200,
                fim_paths: chemins,
                active_response_enabled: coche('wazuh-opt-ar'),
                sca_enabled: coche('wazuh-opt-sca'),
                rootcheck_enabled: coche('wazuh-opt-rk')
            }).then(function (r) {
                var v = verdictEcriture(r);
                annonce(annonceOptions, v.texte, ! v.ok);
                boutonOptions.disabled = false;
            });
        });
    }

    // ── 4. LES REGLES, DECODEURS ET LISTES CDB ───────────────────────────
    var hoteRegles = document.querySelector('[data-rw="wazuh-regles"]');

    /*
     * La liste se RECHARGE apres chaque ecriture, et c'est ce qui distingue un
     * ecran qui rend compte d'un ecran qui se souvient. *Le legacy recharge
     * aussi ; ce qui manquait etait le compte rendu QUAND le rechargement
     * contredit ce qu'on vient de croire.*
     */
    function rechargeListeRegles() {
        if (! hoteRegles) { return; }
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
                /*
                 * ⚠ `x.kind` N'EXISTE PAS. `list_rules` rend `rule_type`
                 * (`wazuh.py:1078`) : le type d'une regle ne s'affichait donc
                 * JAMAIS, et la ligne se reduisait a la date. Corrige ici.
                 */
                d.textContent = [x.rule_type, quand].filter(Boolean).join(' · ');
                ligne.appendChild(n);
                ligne.appendChild(d);

                // « Ouvrir » CHARGE la regle dans l'editeur — il ne la modifie
                // pas. Le nom vient de la donnee, jamais d'une saisie.
                var b = document.createElement('button');
                b.type = 'button';
                b.className = 'rw-bouton rw-bouton--discret';
                b.setAttribute('data-rw', 'wazuh-regle-ouvrir');
                b.textContent = t('regle_ouvrir');
                b.addEventListener('click', function () { ouvreRegle(String(x.name || '')); });
                ligne.appendChild(b);

                l.appendChild(ligne);
            });
            hoteRegles.appendChild(l);
        });
    }
    rechargeListeRegles();

    // ── 5. CREER, MODIFIER, SUPPRIMER UNE REGLE ──────────────────────────
    var annonceRegle = document.querySelector('[data-rw="wazuh-regle-annonce"]');
    var boutonSuppr = document.querySelector('[data-rw="wazuh-regle-supprimer"]');
    var panneau = document.querySelector('[data-rw="wazuh-suppr-panneau"]');
    var question = document.querySelector('[data-rw="wazuh-suppr-question"]');

    /*
     * ⚠ LE NOM VISE PAR LA SUPPRESSION EST CELUI D'UNE REGLE OUVERTE, PAS CELUI
     * DU CHAMP DE SAISIE.
     *
     * Le legacy prend `document.getElementById('wz-rule-name').value` puis
     * demande confirmation (`wazuh.js:287-289`) : on peut donc ouvrir une regle,
     * changer le nom dans le champ, et supprimer **une autre regle** — celle
     * dont on vient de taper le nom. Ici le bouton est INACTIF tant qu'aucune
     * regle n'a ete ouverte, et il vise `regleOuverte`, que seule la liste pose.
     */
    var regleOuverte = null;

    function poseBoutonSuppr() {
        if (boutonSuppr) { boutonSuppr.disabled = (regleOuverte === null); }
    }

    function ouvreRegle(nom) {
        if (! nom) { return; }
        annonce(annonceRegle, t('loading'), false);
        lis('/wazuh/rules/' + encodeURIComponent(nom)).then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success || ! r.corps.rule) {
                annonce(annonceRegle, t('err_rules'), true);
                return;
            }
            var g = r.corps.rule;
            var e;
            e = champ('wazuh-regle-nom'); if (e) { e.value = String(g.name || ''); }
            e = champ('wazuh-regle-type');
            if (e) {
                var ty = String(g.rule_type || 'rules');
                e.value = ty;
                if (e.value !== ty && e.options.length) { e.selectedIndex = 0; }
            }
            e = champ('wazuh-regle-contenu'); if (e) { e.value = String(g.content || ''); }
            regleOuverte = String(g.name || '');
            poseBoutonSuppr();
            annonce(annonceRegle, '', false);
        });
    }

    var boutonNouvelle = document.querySelector('[data-rw="wazuh-regle-nouvelle"]');
    if (boutonNouvelle) {
        boutonNouvelle.addEventListener('click', function () {
            var e;
            e = champ('wazuh-regle-nom'); if (e) { e.value = ''; }
            e = champ('wazuh-regle-contenu'); if (e) { e.value = ''; }
            e = champ('wazuh-regle-type'); if (e && e.options.length) { e.selectedIndex = 0; }
            // On QUITTE la regle ouverte : sans cette ligne, « Nouveau » puis
            // « Supprimer » viserait la precedente, invisible a l'ecran.
            regleOuverte = null;
            poseBoutonSuppr();
            annonce(annonceRegle, '', false);
        });
    }

    var boutonEnrRegle = document.querySelector('[data-rw="wazuh-regle-enregistrer"]');
    if (boutonEnrRegle) {
        boutonEnrRegle.addEventListener('click', function () {
            var nom = valeur('wazuh-regle-nom').trim();
            // Un nom vide n'est pas envoye : le backend le refuserait, mais un
            // aller-retour pour un champ manifestement vide n'apprend rien.
            // Sa FORME, elle, reste jugee par le serveur — voir `regle_aide_nom`.
            if (! nom) { annonce(annonceRegle, t('enr_echec'), true); return; }
            boutonEnrRegle.disabled = true;
            annonce(annonceRegle, t('enr_encours'), false);
            ecris('regle', {
                name: nom,
                rule_type: valeur('wazuh-regle-type'),
                content: valeur('wazuh-regle-contenu')
            }).then(function (r) {
                var v = verdictEcriture(r);
                annonce(annonceRegle, v.texte, ! v.ok);
                boutonEnrRegle.disabled = false;
                if (v.ok) {
                    regleOuverte = nom;
                    poseBoutonSuppr();
                    rechargeListeRegles();
                }
            });
        });
    }

    if (boutonSuppr && panneau) {
        boutonSuppr.addEventListener('click', function () {
            if (regleOuverte === null) { return; }
            /*
             * La question NOMME la regle. `textContent`, jamais `innerHTML` :
             * le nom vient de la base, et un nom n'est pas du balisage.
             */
            if (question) {
                question.textContent = t('suppr_question').split(':nom').join(regleOuverte);
            }
            panneau.hidden = false;
        });
    }
    var boutonAnnuler = document.querySelector('[data-rw="wazuh-suppr-annuler"]');
    if (boutonAnnuler && panneau) {
        boutonAnnuler.addEventListener('click', function () { panneau.hidden = true; });
    }
    var boutonConfirmer = document.querySelector('[data-rw="wazuh-suppr-confirmer"]');
    if (boutonConfirmer) {
        boutonConfirmer.addEventListener('click', function () {
            if (regleOuverte === null) { return; }
            var vise = regleOuverte;
            boutonConfirmer.disabled = true;
            annonce(annonceRegle, t('enr_encours'), false);
            ecris('regleSuppr', null, vise).then(function (r) {
                boutonConfirmer.disabled = false;
                if (panneau) { panneau.hidden = true; }
                /*
                 * ⚠ `delete_rule` REND 200 AVEC `success: false` QUAND RIEN N'A
                 * ETE SUPPRIME (`wazuh.py:1166` : `'success': deleted > 0`).
                 * Le traiter comme un echec generique dirait « la suppression a
                 * echoue » alors que la regle n'existait deja plus — deux etats
                 * qui appellent des gestes differents.
                 */
                if (r.corps && r.corps.success === false && r.corps.deleted === 0) {
                    annonce(annonceRegle, t('suppr_absente'), true);
                    rechargeListeRegles();
                    return;
                }
                var v = verdictEcriture(r);
                annonce(annonceRegle, v.ok ? t('suppr_ok') : v.texte, ! v.ok);
                if (v.ok) {
                    var e;
                    e = champ('wazuh-regle-nom'); if (e) { e.value = ''; }
                    e = champ('wazuh-regle-contenu'); if (e) { e.value = ''; }
                    regleOuverte = null;
                    poseBoutonSuppr();
                    rechargeListeRegles();
                }
            });
        });
    }
    poseBoutonSuppr();
})();
