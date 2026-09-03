/**
 * approbations.js - Workflow d'approbation a quatre yeux.
 *
 * Rendu par `textContent`, jamais par interpolation.
 *
 * PAS DE BOITE NATIVE. Le legacy demande le motif par `prompt()` et confirme
 * par `confirm()`. Ces boites ne se stylent pas, sortent du flux de la page, et
 * bloquent tout script qui pilote le navigateur. Ici, le rejet ouvre une
 * confirmation EN LIGNE dans la ligne concernee, avec un champ de motif : on
 * voit ce qu'on rejette au moment de le rejeter.
 *
 * Chargements SEQUENCES : chaque appel porte un numero, seul le dernier ecrit.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const corps = document.getElementById('appr-tbody');
    const libelles = JSON.parse(document.getElementById('appr-libelles').textContent);

    let statutCourant = 'pending';
    let dernierChargement = 0;

    /** Classe de pastille par etat. Un etat inconnu reste neutre. */
    const PASTILLE = {
        pending: 'rw-pastille--attente',
        approved: 'rw-pastille--ok',
        rejected: 'rw-pastille--echec',
        executed: 'rw-pastille--info',
        expired: 'rw-pastille--neutre',
    };

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

    function message(texte, aide) {
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

    /** Confirmation en ligne du rejet, avec motif. */
    function ouvreRejet(tr, demande) {
        if (tr.nextElementSibling?.dataset.rw === 'rejet-panneau') return;

        const ligne = document.createElement('tr');
        ligne.dataset.rw = 'rejet-panneau';
        const td = document.createElement('td');
        td.colSpan = 6;
        // `.rw-panneau-decision` porte `display: flex`. Pose SUR le `<td>`, il
        // ecrase `display: table-cell` : la cellule sort du modele de tableau et
        // son `colspan` est IGNORE — le panneau s'arrete a la largeur de la
        // premiere colonne, le reste de la ligne restant blanc. Aucune
        // assertion DOM ne l'attrape : `colSpan` vaut bien 6, c'est le RENDU
        // qui ment. Vu a l'image sur un portage voisin le 2026-08-26.
        //
        // Le conteneur flex va donc DANS la cellule, jamais sur elle.
        const cadre = document.createElement('div');
        cadre.className = 'rw-panneau-decision';
        td.appendChild(cadre);

        const etiquette = document.createElement('label');
        etiquette.className = 'rw-etiquette-champ';
        etiquette.textContent = libelles.motif;

        const champ = document.createElement('input');
        champ.type = 'text';
        champ.className = 'rw-saisie rw-saisie--compacte';
        champ.dataset.rw = 'rejet-motif';
        champ.placeholder = libelles.motif_indice;
        etiquette.appendChild(champ);

        const actions = document.createElement('div');
        actions.className = 'rw-panneau-decision__actions';

        const annuler = document.createElement('button');
        annuler.type = 'button';
        annuler.className = 'rw-bouton rw-bouton--discret';
        annuler.textContent = libelles.annuler;
        annuler.addEventListener('click', () => ligne.remove());

        const confirmer = document.createElement('button');
        confirmer.type = 'button';
        confirmer.className = 'rw-bouton rw-bouton--danger';
        confirmer.dataset.rw = 'rejet-confirmer';
        confirmer.textContent = libelles.confirmer;
        confirmer.addEventListener('click', () => decide(demande.id, 'reject', champ.value));

        actions.appendChild(annuler);
        actions.appendChild(confirmer);
        cadre.append(etiquette, actions);
        ligne.appendChild(td);
        tr.after(ligne);
        champ.focus();
    }

    function rend(demandes) {
        if (!demandes.length) {
            message(libelles.empty, libelles.empty_aide);
            return;
        }

        corps.replaceChildren();
        for (const d of demandes) {
            const tr = document.createElement('tr');

            const tdAction = document.createElement('td');
            const code = document.createElement('code');
            code.className = 'rw-code';
            code.textContent = d.action_type || '';
            tdAction.appendChild(code);
            tr.appendChild(tdAction);

            tr.appendChild(cellule(d.target || '—'));
            tr.appendChild(cellule(d.machine_name || (d.machine_id ? '#' + d.machine_id : '—')));
            tr.appendChild(cellule(d.requester || '—'));

            const tdEtat = document.createElement('td');
            const pastille = document.createElement('span');
            pastille.className = 'rw-pastille ' + (PASTILLE[d.status] || 'rw-pastille--neutre');
            pastille.textContent = d.status || '—';
            tdEtat.appendChild(pastille);
            tr.appendChild(tdEtat);

            const tdDecision = document.createElement('td');
            tdDecision.className = 'rw-tableau__actions';
            if (d.status === 'pending') {
                const approuver = document.createElement('button');
                approuver.type = 'button';
                approuver.className = 'rw-bouton rw-bouton--succes';
                approuver.textContent = libelles.approve;
                if (d.is_own) {
                    // Regle des quatre yeux : le backend la fait respecter aussi.
                    // Ici on la REND VISIBLE plutot que de laisser cliquer pour rien.
                    approuver.disabled = true;
                    approuver.title = libelles.own_hint;
                } else {
                    approuver.title = libelles.tip_approve;
                    approuver.addEventListener('click', () => decide(d.id, 'approve', ''));
                }

                const rejeter = document.createElement('button');
                rejeter.type = 'button';
                rejeter.className = 'rw-bouton rw-bouton--discret';
                rejeter.textContent = libelles.reject;
                rejeter.title = libelles.tip_reject;
                rejeter.addEventListener('click', () => ouvreRejet(tr, d));

                tdDecision.appendChild(approuver);
                tdDecision.appendChild(rejeter);
            } else if (d.approver) {
                tdDecision.appendChild(cellule(libelles.by + ' ' + d.approver, 'rw-tableau__discret'));
            }
            tr.appendChild(tdDecision);

            corps.appendChild(tr);
        }
    }

    async function charge() {
        const numero = ++dernierChargement;
        const res = await appelle('/approvals?status=' + encodeURIComponent(statutCourant));

        // Une reponse depassee n'ecrit pas : un autre onglet a ete demande.
        if (numero !== dernierChargement) return;

        if (!res.ok || !res.corps || !res.corps.success) {
            message(libelles.err_load);
            return;
        }
        rend(res.corps.approvals || []);
    }

    async function decide(id, action, motif) {
        const res = await appelle('/approvals/' + encodeURIComponent(id) + '/' + action, {
            method: 'POST',
            body: JSON.stringify({ reason: motif || '' }),
        });
        if (!res.ok || !res.corps || !res.corps.success) {
            message((res.corps && res.corps.message) || libelles.err_decide);
            return;
        }
        charge();
    }

    for (const onglet of document.querySelectorAll('.appr-tab')) {
        onglet.addEventListener('click', () => {
            statutCourant = onglet.dataset.status;
            for (const autre of document.querySelectorAll('.appr-tab')) {
                autre.classList.toggle('rw-onglet--actif', autre === onglet);
            }
            charge();
        });
    }

    charge();
})();
