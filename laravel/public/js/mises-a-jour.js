/**
 * mises-a-jour.js - Module `update/`, sous-lot U1 : parc et filtres.
 *
 * Rendu par `textContent` et `createElement`, jamais par interpolation.
 *
 * LA DIFFERENCE QUI COMPTE : LE RAFRAICHISSEMENT NE PERD PLUS DE COLONNES.
 *
 * Le legacy affiche treize colonnes, puis les recharge depuis
 * `update/functions/list_machines.php`, qui n'en SELECTionne que onze.
 * Rafraichir la liste remplace donc « dernier redemarrage », « MAJ securite
 * planifiee » et « derniere execution » par « N/A » — mesure : la colonne
 * « dernier redemarrage » passe de renseignee a vide, sans qu'on l'ait demande
 * et sans rien annoncer.
 *
 * Ici, le rafraichissement et le filtrage passent tous deux par
 * `/filter_servers`, qui rend les QUATORZE colonnes, exclut les machines
 * archivees et applique le meme cloisonnement par role. Un rafraichissement ne
 * peut donc plus appauvrir ce qui etait affiche.
 *
 * Chargements SEQUENCES : chaque appel porte un numero, seul le dernier ecrit.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const corps = document.getElementById('server-table-body');
    const annonce = document.getElementById('maj-annonce');
    const libelles = JSON.parse(document.getElementById('maj-libelles').textContent);

    let parc = JSON.parse(document.getElementById('maj-parc').textContent) || [];
    let dernierChargement = 0;

    function jetonCsrf() {
        return document.querySelector('meta[name="csrf-token"]')?.content || '';
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
        const r = await fetch(PASSERELLE + chemin, parametres);
        let corpsJson = null;
        try { corpsJson = await r.json(); } catch (e) { /* reponse non JSON */ }
        return { ok: r.ok, statut: r.status, corps: corpsJson };
    }

    function dit(texte, ton) {
        annonce.textContent = texte || '';
        annonce.className = 'rw-annonce' + (ton ? ' rw-annonce--' + ton : '');

        // Le journal d'execution (U2) garde la trace de ce que la page a fait.
        // L'annonce, elle, ne montre que le dernier etat — les deux se
        // completent, ils ne se remplacent pas.
        if (window.rwJournal) window.rwJournal.ajoute(texte, ton === 'echec' ? 'error' : (ton || 'info'));
    }

    function heure() { return new Date().toLocaleTimeString(); }

    function cellule(texte, classes) {
        const td = document.createElement('td');
        if (classes) td.className = classes;
        td.textContent = texte;
        return td;
    }

    function message(titre, aide) {
        corps.replaceChildren();
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 13;
        td.className = 'rw-tableau__message';
        const t = document.createElement('div');
        t.className = 'rw-tableau__message-titre';
        t.textContent = titre;
        td.appendChild(t);
        if (aide) {
            const p = document.createElement('p');
            p.className = 'rw-tableau__message-aide';
            p.textContent = aide;
            td.appendChild(p);
        }
        tr.appendChild(td);
        corps.appendChild(tr);
    }

    /** Un bouton de relevé : il interroge la machine sans rien y changer. */
    function boutonReleve(libelle, infobulle, marque, action) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
        b.textContent = libelle;
        b.title = infobulle;
        b.dataset.rw = marque;
        b.addEventListener('click', () => action(b));
        return b;
    }

    function rend(machines, filtreActif) {
        if (!machines.length) {
            if (filtreActif) message(libelles.vide_filtre, libelles.vide_filtre_aide);
            else message(libelles.vide, libelles.vide_aide);
            return;
        }

        corps.replaceChildren();
        for (const m of machines) {
            const id = parseInt(m.id, 10);
            if (!id) continue;

            const tr = document.createElement('tr');
            tr.setAttribute('data-machine-id', String(id));
            tr.setAttribute('data-ip', m.ip ?? '');
            tr.setAttribute('data-port', String(m.port ?? 22));

            const tdCase = document.createElement('td');
            const coche = document.createElement('input');
            coche.type = 'checkbox';
            coche.name = 'selected_machines[]';
            coche.value = String(id);
            tdCase.appendChild(coche);
            tr.appendChild(tdCase);

            tr.appendChild(cellule(m.name ?? '', 'server-name rw-tableau__fort'));
            tr.appendChild(cellule(m.linux_version || libelles.non_verifie, 'linux-version'));
            tr.appendChild(cellule(m.last_checked || libelles.non_verifie, 'last-checked rw-tableau__discret'));
            tr.appendChild(cellule(`${m.ip ?? ''}:${m.port ?? ''}`, 'rw-tableau__discret'));
            tr.appendChild(cellule(m.online_status || libelles.inconnu, 'online-status'));
            tr.appendChild(cellule(m.maj_secu_date || libelles.aucune, 'maj-secu-date rw-tableau__discret'));
            tr.appendChild(cellule(m.maj_secu_last_exec_date || libelles.aucune, 'maj-secu-lastexec-date rw-tableau__discret'));

            const tdRedemarrage = cellule(m.last_reboot || libelles.aucune, 'last-reboot rw-tableau__discret');
            tdRedemarrage.id = 'last-reboot-' + id;
            tr.appendChild(tdRedemarrage);

            tr.appendChild(cellule(m.environment || 'OTHER', 'environment'));
            tr.appendChild(cellule(m.criticality || 'NON CRITIQUE', 'criticality'));
            tr.appendChild(cellule(m.network_type || 'INTERNE', 'network-type'));

            const tdActions = document.createElement('td');
            tdActions.className = 'rw-tableau__actions rw-tableau__actions--releves';
            tdActions.append(
                boutonReleve(libelles.btn_version, libelles.tip_version, 'version-' + id,
                             (b) => releveVersion(id, tr, b)),
                boutonReleve(libelles.btn_statut, libelles.tip_statut, 'statut-' + id,
                             (b) => releveStatut(id, tr, b)),
                boutonReleve(libelles.btn_reboot, libelles.tip_reboot, 'reboot-' + id,
                             (b) => releveRedemarrage(id, tr, b)),
            );
            tr.appendChild(tdActions);

            corps.appendChild(tr);
        }
    }

    /**
     * Relit le parc par la passerelle.
     *
     * `/filter_servers` sans filtre rend le parc entier avec ses quatorze
     * colonnes — c'est pour cela qu'il sert AUSSI au rafraichissement, la ou le
     * legacy appelle un endpoint qui en rend onze.
     */
    async function relit(filtres) {
        const numero = ++dernierChargement;
        const params = new URLSearchParams();
        for (const [cle, valeur] of Object.entries(filtres || {})) {
            if (valeur) params.set(cle, valeur);
        }
        const filtreActif = [...params.keys()].length > 0;

        const res = await appelle('/filter_servers' + (filtreActif ? '?' + params.toString() : ''));

        if (numero !== dernierChargement) return;

        if (!res.ok || !res.corps || !res.corps.success) {
            // L'erreur ne s'avale pas : garder les lignes precedentes les ferait
            // passer pour le resultat de la demande.
            message(libelles.err_load);
            dit(libelles.err_load, 'echec');
            return;
        }

        parc = res.corps.machines || [];
        rend(parc, filtreActif);
        dit(filtreActif
            ? libelles.filtre_ok.replace(':nombre', parc.length)
            : libelles.maj_ok.replace(':heure', heure()).replace(':nombre', parc.length));
    }

    function filtresCourants() {
        return {
            environment: document.getElementById('environment').value,
            criticality: document.getElementById('criticality').value,
            networkType: document.getElementById('network-type').value,
            // `/filter_servers` joint `machine_tags` quand `tag` est fourni.
            tag: document.getElementById('tag-filter')?.value || '',
        };
    }

    /** Ecrit une cellule de la ligne, sans toucher aux autres. */
    function ecrit(tr, classe, valeur) {
        const td = tr.querySelector('.' + classe);
        if (td) td.textContent = valeur;
    }

    async function releve(bouton, appel, apres) {
        const initial = bouton.textContent;
        bouton.disabled = true;
        bouton.textContent = libelles.en_cours;
        dit(libelles.en_cours);

        const res = await appel();

        bouton.disabled = false;
        bouton.textContent = initial;

        if (!res.ok || !res.corps || res.corps.success === false) {
            dit((res.corps && res.corps.message) || libelles.err_releve, 'echec');
            return;
        }
        apres(res.corps);
        dit(libelles.releve_ok, 'ok');
    }

    function releveVersion(id, tr, bouton) {
        return releve(bouton,
            () => appelle('/linux_version', { method: 'POST', body: JSON.stringify({ machine_id: id }) }),
            (c) => {
                if (c.linux_version) ecrit(tr, 'linux-version', c.linux_version);
                if (c.last_checked) ecrit(tr, 'last-checked', c.last_checked);
            });
    }

    function releveStatut(id, tr, bouton) {
        return releve(bouton,
            () => appelle('/server_status', { method: 'POST', body: JSON.stringify({ machine_id: id }) }),
            (c) => { if (c.status || c.online_status) ecrit(tr, 'online-status', c.status || c.online_status); });
    }

    function releveRedemarrage(id, tr, bouton) {
        return releve(bouton,
            () => appelle('/last_reboot', { method: 'POST', body: JSON.stringify({ machine_id: id }) }),
            (c) => { if (c.last_reboot) ecrit(tr, 'last-reboot', c.last_reboot); });
    }

    document.getElementById('filter-btn').addEventListener('click', () => relit(filtresCourants()));
    document.getElementById('refresh-list-btn').addEventListener('click', () => {
        document.getElementById('environment').value = '';
        document.getElementById('criticality').value = '';
        document.getElementById('network-type').value = '';
        const etiquette = document.getElementById('tag-filter');
        if (etiquette) etiquette.value = '';
        relit({});
    });

    // Premier rendu : les donnees sont deja la, aucun appel n'est necessaire.
    rend(parc, false);
})();
