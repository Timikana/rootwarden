/**
 * graylog.js - Transfert des journaux vers Graylog.
 *
 * Cinq differences avec `legacy/graylog/js/graylog.js`, toutes des corrections :
 *
 *   1. **AUCUNE BOITE NATIVE.** Le legacy pose deux `confirm()` et trois
 *      `alert()`. Une boite recouvre precisement ce sur quoi on decide, ne se
 *      style pas — geste destructeur et annulation au meme poids — et BLOQUE
 *      Puppeteer, donc aucun test ne peut mener l'action au bout. Ici la
 *      decision s'ouvre EN LIGNE et le resultat s'annonce dans la page.
 *   2. **« Tester » DEMANDE CONFIRMATION.** Le legacy ne le fait pas
 *      (`glTest`, js:100) : un seul clic ouvre une session SSH sur la machine de
 *      la ligne, et le tableau liste les machines de production. C'est le
 *      correctif le plus important de ce portage.
 *   3. **La confirmation NOMME la machine** — nom et adresse. Trois boutons par
 *      ligne, plusieurs lignes, et un libelle generique ne dit pas laquelle.
 *   4. **Rendu par `textContent`**, jamais par interpolation : le nom d'une
 *      machine peut venir d'un import CSV et n'a pas ete valide par une regle.
 *   5. **Un echec RESEAU se voit** : chaque appel est enveloppe, et « rien n'a
 *      ete modifie » est dit plutot que laisse deviner.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const L = JSON.parse(document.getElementById('graylog-libelles').textContent);

    const q = (nom) => document.querySelector(`[data-rw="${nom}"]`);

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    /** Annonce dans un porte-message DEDIE, jamais dans une classe approchante. */
    function annonce(nom, texte, type) {
        const e = q(nom);
        if (! e) return;
        e.textContent = texte;
        e.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
    }

    async function appelle(chemin, options) {
        const parametres = Object.assign({
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin',
        }, options || {});
        if (parametres.method && parametres.method !== 'GET') {
            parametres.headers = Object.assign({}, parametres.headers, {
                'X-CSRF-TOKEN': jetonCsrf(),
                'Content-Type': 'application/json',
            });
        }
        try {
            const r = await fetch(PASSERELLE + chemin, parametres);
            let json = null;
            try { json = await r.json(); } catch (e) { /* reponse non JSON */ }

            return { ok: r.ok, statut: r.status, corps: json };
        } catch (e) {
            return { ok: false, statut: 0, corps: null, reseau: true };
        }
    }

    /* ══ Onglets ═══════════════════════════════════════════════════════════ */

    function ouvreOnglet(nom) {
        document.querySelectorAll('[data-onglet]').forEach((b) => {
            const actif = b.dataset.onglet === nom;
            b.classList.toggle('rw-onglet--actif', actif);
            b.setAttribute('aria-selected', actif ? 'true' : 'false');
            const panneau = q('graylog-panneau-' + b.dataset.onglet);
            if (panneau) panneau.hidden = ! actif;
        });
        if (nom === 'deploy') chargeMachines();
        if (nom === 'templates') chargeGabarits();
    }

    /* ══ Configuration ═════════════════════════════════════════════════════ */

    async function chargeConfig() {
        const r = await appelle('/graylog/config');
        if (! r.ok || ! r.corps || ! r.corps.success || ! r.corps.config) {
            annonce('graylog-config-etat', r.reseau ? L.err_reseau : L.err_charge, 'echec');

            return;
        }
        const c = r.corps.config;
        q('graylog-hote').value = c.server_host || '';
        q('graylog-port').value = c.server_port || 514;
        q('graylog-protocole').value = c.protocol || 'udp';
        q('graylog-tls-ca').value = c.tls_ca_path || '';
        q('graylog-rl-burst').value = c.ratelimit_burst || 0;
        q('graylog-rl-interval').value = c.ratelimit_interval || 0;
    }

    async function enregistreConfig(bouton) {
        const hote = q('graylog-hote').value.trim();
        /*
         * REFUS AVANT ENVOI, ET LE REFUS N'ECRIT RIEN. Un hote vide produirait
         * une conf rsyslog qui ne transfere nulle part, sans que rien ne le
         * signale sur les machines. Le backend le refuse aussi ; on l'annonce
         * plus tot, on ne deplace pas la regle.
         */
        if (! hote) { annonce('graylog-config-etat', L.err_hote, 'echec'); return; }

        bouton.disabled = true;
        const r = await appelle('/graylog/config', {
            method: 'POST',
            body: JSON.stringify({
                server_host: hote,
                server_port: parseInt(q('graylog-port').value, 10) || 514,
                protocol: q('graylog-protocole').value,
                tls_ca_path: q('graylog-tls-ca').value.trim(),
                ratelimit_burst: parseInt(q('graylog-rl-burst').value, 10) || 0,
                ratelimit_interval: parseInt(q('graylog-rl-interval').value, 10) || 0,
            }),
        });
        bouton.disabled = false;
        if (r.ok && r.corps && r.corps.success) {
            annonce('graylog-config-etat', L.enregistre, 'ok');

            return;
        }
        annonce('graylog-config-etat',
            r.reseau ? L.err_reseau : ((r.corps && r.corps.message) || L.err_config), 'echec');
    }

    /* ══ Machines ══════════════════════════════════════════════════════════ */

    function cellule(texte) {
        const td = document.createElement('td');
        td.textContent = texte == null || texte === '' ? '—' : String(texte);

        return td;
    }

    function pastilleEtat(machine) {
        const td = document.createElement('td');
        const p = document.createElement('span');
        const actif = !! machine.forward_deployed;
        p.className = 'rw-pastille ' + (actif ? 'rw-pastille--ok' : 'rw-pastille--neutre');
        p.textContent = actif ? L.etat_transfere : L.etat_absent;
        td.appendChild(p);

        return td;
    }

    /**
     * LA CONFIRMATION, EN LIGNE ET SOUS LA LIGNE CONCERNEE.
     *
     * Elle nomme la machine et son adresse : trois boutons par ligne et
     * plusieurs lignes, un libelle generique ne dirait pas laquelle. Et elle
     * s'ouvre pour les TROIS gestes, « Tester » compris — c'est la correction
     * que le legacy n'a pas.
     */
    function ouvreConfirmation(ligne, machine, geste) {
        if (ligne.nextElementSibling
            && ligne.nextElementSibling.dataset.rw === 'graylog-panneau-machine') return;

        const titres = {
            deploy: L.confirm_titre_deploy,
            test: L.confirm_titre_test,
            uninstall: L.confirm_titre_retirer,
        };

        const tr = document.createElement('tr');
        tr.dataset.rw = 'graylog-panneau-machine';
        const td = document.createElement('td');
        td.colSpan = 6;
        /*
         * LE CONTENEUR FLEX VA *DANS* LA CELLULE, JAMAIS SUR ELLE.
         *
         * Defaut vu a l'image le 2026-08-26, invisible au DOM :
         * `.rw-panneau-decision` porte `display: flex`. Pose sur un `<td>`, il
         * ecrase `display: table-cell`, la cellule SORT du modele de tableau, et
         * son `colspan` est alors ignore — le panneau s'arretait au tiers de la
         * largeur sur un ecran de 1920, le reste de la ligne restant blanc.
         * Aucune assertion DOM ne pouvait le voir : l'attribut `colSpan` valait
         * bien 6.
         */
        const cadre = document.createElement('div');
        cadre.className = 'rw-panneau-decision';

        const bloc = document.createElement('div');
        bloc.className = 'rw-panneau-decision__texte';
        const titre = document.createElement('strong');
        titre.textContent = titres[geste] || '';
        const aide = document.createElement('p');
        aide.className = 'rw-aide';
        aide.textContent = String(L.confirm_aide)
            .replace(':machine', machine.name || ('#' + machine.id))
            .replace(':ip', machine.ip || '—');
        bloc.append(titre, aide);

        const actions = document.createElement('div');
        actions.className = 'rw-panneau-decision__actions';

        const annuler = document.createElement('button');
        annuler.type = 'button';
        annuler.className = 'rw-bouton rw-bouton--discret';
        annuler.dataset.rw = 'graylog-machine-annuler';
        annuler.textContent = L.confirm_annuler;
        annuler.addEventListener('click', () => tr.remove());

        const valider = document.createElement('button');
        valider.type = 'button';
        valider.className = 'rw-bouton rw-bouton--danger';
        valider.dataset.rw = 'graylog-machine-confirmer';
        valider.textContent = L.confirm_valider;
        valider.addEventListener('click', () => lanceGeste(machine, geste, valider, tr));

        actions.append(annuler, valider);
        cadre.append(bloc, actions);
        td.appendChild(cadre);
        tr.appendChild(td);
        ligne.after(tr);
    }

    async function lanceGeste(machine, geste, bouton, panneau) {
        bouton.disabled = true;
        const r = await appelle('/graylog/' + geste, {
            method: 'POST',
            body: JSON.stringify({ machine_id: machine.id }),
        });
        panneau.remove();

        if (r.reseau) { annonce('graylog-machines-etat', L.err_reseau, 'echec'); return; }
        const corps = r.corps || {};
        if (r.ok && corps.success) {
            /* Le detail est UTILE et il est rendu dans la page : version de
             * rsyslog, nombre de gabarits pousses, etiquette du test. Le legacy
             * le mettait dans un `alert()`, donc illisible et non copiable. */
            const parties = [];
            if (corps.rsyslog_version) parties.push('rsyslog ' + corps.rsyslog_version);
            if (corps.templates_pushed) parties.push(corps.templates_pushed.length + ' gabarit(s)');
            if (corps.tag) parties.push('tag ' + corps.tag);
            annonce('graylog-machines-etat', parties.join(' · ') || 'OK', 'ok');
        } else if (geste === 'uninstall') {
            /*
             * UN RETRAIT ECHOUE EST LE SEUL CAS OU L'UTILISATEUR CROIT AVOIR
             * ARRETE QUELQUE CHOSE.
             *
             * Le backend rendait `success: true` quoi qu'il arrive et marquait la
             * machine « non deployee » : l'ecran affirmait donc un retrait qui
             * pouvait n'avoir rien fait. Corrige cote backend, mais la page doit
             * DIRE ce qui reste possible, et le dire dans la langue de la
             * personne — le message du backend n'est pas traduit.
             *
             * Un deploiement rate fait perdre des journaux ; un retrait rate fait
             * croire qu'on a cesse d'en envoyer. Le second merite son propre
             * avertissement.
             */
            annonce('graylog-machines-etat', L.err_retrait_actif, 'echec');
        } else {
            annonce('graylog-machines-etat', corps.message || corps.stderr || L.err_config, 'echec');
        }
        chargeMachines();
    }

    async function chargeMachines() {
        const cadre = q('graylog-serveurs');
        const r = await appelle('/graylog/servers');
        cadre.textContent = '';

        if (! r.ok || ! r.corps || ! r.corps.success) {
            const p = document.createElement('p');
            p.className = 'rw-vide';
            p.textContent = r.reseau ? L.err_reseau : L.err_charge;
            cadre.appendChild(p);

            return;
        }
        const machines = r.corps.servers || [];
        if (! machines.length) {
            const p = document.createElement('p');
            p.className = 'rw-vide';
            p.textContent = L.aucune_machine;
            cadre.appendChild(p);

            return;
        }

        const table = document.createElement('table');
        table.className = 'rw-tableau';
        const thead = document.createElement('thead');
        const trh = document.createElement('tr');
        [L.col_nom, L.col_ip, L.col_etat, L.col_version, L.col_dernier, L.col_actions]
            .forEach((t) => {
                const th = document.createElement('th');
                th.textContent = t;
                trh.appendChild(th);
            });
        thead.appendChild(trh);
        const tbody = document.createElement('tbody');

        machines.forEach((m) => {
            const tr = document.createElement('tr');
            tr.appendChild(cellule(m.name));
            tr.appendChild(cellule(m.ip));
            tr.appendChild(pastilleEtat(m));
            tr.appendChild(cellule(m.rsyslog_version));
            tr.appendChild(cellule(m.last_deploy_at));

            const td = document.createElement('td');
            td.className = 'rw-tableau__actions';
            /*
             * LES TROIS BOUTONS DE LIGNE RESTENT DISCRETS.
             *
             * Le premier jet donnait a « Retirer » un `rw-bouton--avertissement`,
             * ce qui en faisait — vu a l'image — l'element le plus voyant du
             * tableau, plus que « Deployer ». Attirer l'oeil sur le geste
             * destructeur est l'inverse de ce qu'on veut. Le poids visuel
             * appartient au panneau de confirmation, ou l'action porte
             * `rw-bouton--danger` et l'annulation reste discrete.
             */
            [['deploy', L.btn_deploy],
             ['test', L.btn_test],
             ['uninstall', L.btn_retirer]].forEach(([geste, libelle]) => {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
                b.dataset.rw = 'graylog-machine-' + geste;
                b.dataset.machine = String(m.id);
                b.textContent = libelle;
                b.addEventListener('click', () => ouvreConfirmation(tr, m, geste));
                td.appendChild(b);
            });
            tr.appendChild(td);
            tbody.appendChild(tr);
        });

        table.append(thead, tbody);
        cadre.appendChild(table);
    }

    /* ══ Gabarits ══════════════════════════════════════════════════════════ */

    async function chargeGabarits() {
        const liste = q('graylog-gabarits');
        const r = await appelle('/graylog/templates');
        liste.textContent = '';

        const gabarits = (r.ok && r.corps && r.corps.success) ? (r.corps.templates || []) : null;
        if (gabarits === null) {
            const p = document.createElement('p');
            p.className = 'rw-vide';
            p.textContent = r.reseau ? L.err_reseau : L.err_charge;
            liste.appendChild(p);

            return;
        }
        if (! gabarits.length) {
            const p = document.createElement('p');
            p.className = 'rw-vide';
            p.textContent = L.gabarit_aucun;
            liste.appendChild(p);

            return;
        }
        gabarits.forEach((g) => {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'rw-bouton rw-bouton--discret';
            b.dataset.rw = 'graylog-gabarit-ouvrir';
            b.dataset.nom = g.name;
            const etat = g.enabled ? L.gabarit_actif_court : L.gabarit_inactif;
            b.textContent = `${g.name} — ${etat}`;
            b.addEventListener('click', () => ouvreGabarit(g.name));
            liste.appendChild(b);
        });
    }

    async function ouvreGabarit(nom) {
        const r = await appelle('/graylog/templates/' + encodeURIComponent(nom));
        if (! r.ok || ! r.corps || ! r.corps.success || ! r.corps.template) {
            annonce('graylog-gabarit-etat', r.reseau ? L.err_reseau : L.err_charge, 'echec');

            return;
        }
        const t = r.corps.template;
        q('graylog-gabarit-nom').value = t.name || '';
        q('graylog-gabarit-desc').value = t.description || '';
        q('graylog-gabarit-active').checked = !! t.enabled;
        q('graylog-gabarit-contenu').value = t.content || '';
        annonce('graylog-gabarit-etat', '', null);
    }

    function videGabarit() {
        q('graylog-gabarit-nom').value = '';
        q('graylog-gabarit-desc').value = '';
        q('graylog-gabarit-active').checked = false;
        q('graylog-gabarit-contenu').value = '';
        const panneau = q('graylog-gabarit-panneau');
        panneau.textContent = '';
        panneau.hidden = true;
        annonce('graylog-gabarit-etat', '', null);
    }

    async function enregistreGabarit(bouton) {
        const nom = q('graylog-gabarit-nom').value.trim();
        if (! nom) { annonce('graylog-gabarit-etat', L.err_gabarit_nom, 'echec'); return; }

        bouton.disabled = true;
        const r = await appelle('/graylog/templates', {
            method: 'POST',
            body: JSON.stringify({
                name: nom,
                description: q('graylog-gabarit-desc').value.trim(),
                content: q('graylog-gabarit-contenu').value,
                enabled: q('graylog-gabarit-active').checked,
            }),
        });
        bouton.disabled = false;
        if (r.ok && r.corps && r.corps.success) {
            annonce('graylog-gabarit-etat', L.gabarit_enregistre, 'ok');
            chargeGabarits();

            return;
        }
        annonce('graylog-gabarit-etat',
            r.reseau ? L.err_reseau : ((r.corps && r.corps.message) || L.err_gabarit), 'echec');
    }

    /** La confirmation de suppression, EN PAGE, et elle nomme le gabarit. */
    function confirmeSuppressionGabarit() {
        const nom = q('graylog-gabarit-nom').value.trim();
        if (! nom) { annonce('graylog-gabarit-etat', L.err_gabarit_nom, 'echec'); return; }

        const panneau = q('graylog-gabarit-panneau');
        panneau.textContent = '';

        const bloc = document.createElement('div');
        bloc.className = 'rw-panneau-decision__texte';
        const titre = document.createElement('strong');
        titre.textContent = L.confirm_titre_gabarit;
        const aide = document.createElement('p');
        aide.className = 'rw-aide';
        aide.textContent = String(L.confirm_aide_gabarit).replace(':nom', nom);
        bloc.append(titre, aide);

        const actions = document.createElement('div');
        actions.className = 'rw-panneau-decision__actions';

        const annuler = document.createElement('button');
        annuler.type = 'button';
        annuler.className = 'rw-bouton rw-bouton--discret';
        annuler.dataset.rw = 'graylog-gabarit-annuler';
        annuler.textContent = L.confirm_annuler;
        annuler.addEventListener('click', () => { panneau.textContent = ''; panneau.hidden = true; });

        const valider = document.createElement('button');
        valider.type = 'button';
        valider.className = 'rw-bouton rw-bouton--danger';
        valider.dataset.rw = 'graylog-gabarit-confirmer';
        valider.textContent = L.confirm_valider;
        valider.addEventListener('click', () => supprimeGabarit(nom, valider));

        actions.append(annuler, valider);
        panneau.append(bloc, actions);
        panneau.hidden = false;
    }

    async function supprimeGabarit(nom, bouton) {
        bouton.disabled = true;
        const r = await appelle('/graylog/templates/' + encodeURIComponent(nom),
            { method: 'DELETE' });
        const panneau = q('graylog-gabarit-panneau');
        panneau.textContent = '';
        panneau.hidden = true;

        if (r.ok && r.corps && r.corps.success) {
            videGabarit();
            annonce('graylog-gabarit-etat', L.gabarit_supprime, 'ok');
            chargeGabarits();

            return;
        }
        annonce('graylog-gabarit-etat',
            r.reseau ? L.err_reseau : ((r.corps && r.corps.message) || L.err_gabarit), 'echec');
    }

    /* ══ Cablage ═══════════════════════════════════════════════════════════ */

    document.querySelectorAll('[data-onglet]').forEach((b) => {
        b.addEventListener('click', () => ouvreOnglet(b.dataset.onglet));
    });
    q('graylog-config-enregistrer').addEventListener('click', (e) => enregistreConfig(e.currentTarget));
    q('graylog-rafraichir').addEventListener('click', chargeMachines);
    q('graylog-gabarit-nouveau').addEventListener('click', videGabarit);
    q('graylog-gabarit-enregistrer').addEventListener('click', (e) => enregistreGabarit(e.currentTarget));
    q('graylog-gabarit-supprimer').addEventListener('click', confirmeSuppressionGabarit);

    chargeConfig();
})();
