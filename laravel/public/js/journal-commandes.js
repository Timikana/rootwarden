/**
 * journal-commandes.js - Journal des commandes, lecture seule.
 *
 * Rendu par `textContent` et non par interpolation : aucune donnee venue du
 * backend n'entre dans le DOM comme du HTML. Une commande journalisee contient
 * par nature des caracteres de shell.
 *
 * SEQUENCEMENT DES REQUETES. Le legacy lance un chargement a chaque changement
 * de filtre, sans ordonner les reponses : deux changements rapproches font
 * courir deux requetes, et la plus ancienne peut arriver en dernier et ecraser
 * la plus recente — l'utilisateur voit alors le resultat d'un filtre qu'il
 * vient de quitter. Mesure sur le legacy le 2026-08-18. Ici, chaque
 * chargement porte un numero et seul le dernier a le droit d'ecrire.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const corps = document.getElementById('cmdlog-tbody');
    const filtreMachine = document.getElementById('f-machine');
    const filtreContexte = document.getElementById('f-context');
    const boutonRafraichir = document.getElementById('refresh-btn');

    const libelles = JSON.parse(document.getElementById('cmdlog-libelles').textContent);

    /** Numero du dernier chargement demande. */
    let dernierChargement = 0;

    function messagePleineLargeur(texte, aide) {
        corps.replaceChildren();
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 6;
        td.className = 'rw-tableau__message';

        const titre = document.createElement('div');
        titre.className = 'rw-tableau__message-titre';
        titre.textContent = texte;
        td.appendChild(titre);

        if (aide) {
            const p = document.createElement('p');
            p.className = 'rw-tableau__message-aide';
            p.textContent = aide;
            td.appendChild(p);
        }

        tr.appendChild(td);
        corps.appendChild(tr);
    }

    function cellule(texte, classe) {
        const td = document.createElement('td');
        if (classe) td.className = classe;
        td.textContent = texte;
        return td;
    }

    /** Pastille de resultat : succes, echec, ou action encore en cours. */
    function pastilleResultat(succes) {
        const td = document.createElement('td');
        const span = document.createElement('span');
        if (succes === null || succes === undefined) {
            span.className = 'rw-pastille rw-pastille--attente';
            span.textContent = libelles.en_cours;
        } else if (succes) {
            span.className = 'rw-pastille rw-pastille--ok';
            span.textContent = 'OK';
        } else {
            span.className = 'rw-pastille rw-pastille--echec';
            span.textContent = libelles.failed;
        }
        td.appendChild(span);
        return td;
    }

    function rend(commandes) {
        if (!commandes.length) {
            messagePleineLargeur(libelles.empty, libelles.empty_aide);
            return;
        }

        corps.replaceChildren();
        for (const c of commandes) {
            const tr = document.createElement('tr');

            const quand = c.created_at ? new Date(c.created_at).toLocaleString() : '—';
            tr.appendChild(cellule(quand, 'rw-tableau__discret'));
            tr.appendChild(cellule(c.machine_name || (c.machine_id ? '#' + c.machine_id : '—')));
            tr.appendChild(cellule(c.user_name || (c.user_id ? '#' + c.user_id : libelles.system)));

            const tdContexte = document.createElement('td');
            const badge = document.createElement('span');
            badge.className = 'rw-etiquette';
            badge.textContent = c.context || '—';
            tdContexte.appendChild(badge);
            tr.appendChild(tdContexte);

            const tdCommande = document.createElement('td');
            const code = document.createElement('code');
            code.className = 'rw-code';
            code.textContent = c.command || '';
            tdCommande.appendChild(code);
            if (c.detail) {
                const detail = document.createElement('div');
                detail.className = 'rw-tableau__discret';
                detail.textContent = c.detail;
                tdCommande.appendChild(detail);
            }
            tr.appendChild(tdCommande);

            tr.appendChild(pastilleResultat(c.success));
            corps.appendChild(tr);
        }
    }

    async function appelle(chemin) {
        const r = await fetch(PASSERELLE + chemin, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin',
        });
        let corpsJson = null;
        try { corpsJson = await r.json(); } catch (e) { /* reponse non JSON */ }
        return { ok: r.ok, corps: corpsJson };
    }

    async function chargeContextes() {
        const res = await appelle('/command_log/contexts');
        if (!res.ok || !res.corps || !res.corps.success) return;
        for (const contexte of res.corps.contexts || []) {
            const option = document.createElement('option');
            option.value = contexte;
            option.textContent = contexte;
            filtreContexte.appendChild(option);
        }
    }

    async function charge() {
        const numero = ++dernierChargement;

        const parametres = new URLSearchParams({ limit: '200' });
        if (filtreMachine.value) parametres.set('machine_id', filtreMachine.value);
        if (filtreContexte.value) parametres.set('context', filtreContexte.value);

        const res = await appelle('/command_log?' + parametres.toString());

        // Une reponse depassee n'ecrit pas : entre-temps un autre filtre a ete
        // demande, et son resultat est le seul qui corresponde a l'ecran.
        if (numero !== dernierChargement) return;

        if (!res.ok || !res.corps || !res.corps.success) {
            messagePleineLargeur(libelles.err_load);
            return;
        }
        rend(res.corps.commands || []);
    }

    boutonRafraichir.addEventListener('click', charge);
    filtreMachine.addEventListener('change', charge);
    filtreContexte.addEventListener('change', charge);

    chargeContextes();
    charge();
})();
