/*
 * Liste blanche des CVE — l'ecran rendu au portage.
 *
 * ══ TOUT EST RENDU PAR `textContent` ═════════════════════════════════════
 *
 * Motif, nom de machine et auteur viennent de la base et sont saisis par des
 * humains. Aucun `innerHTML` : le rendu ne peut pas devenir une injection parce
 * qu'il n'existe aucun chemin ou du balisage serait interprete.
 *
 * ══ ⚠ LE JETON CSRF EST ENVOYE, ET CE N'EST PAS L'USAGE DE CE MODULE ══════
 *
 * Mesure du 2026-09-07 sur le portage servi :
 *
 *     POST /scan-cve/planifications  SANS X-CSRF-TOKEN, avec session  ->  419
 *     POST /scan-cve/planifications  AVEC le jeton                    ->  302
 *
 * `planification-cve.js` n'envoie aucun jeton — ni en en-tete, ni dans le corps
 * — et douze autres modules du portage sont dans le meme etat. **Ce fichier ne
 * reproduit pas cet usage** : il envoie le jeton, comme `approbations.js`.
 *
 * *Le constat est transmis a part ; il n'appartient pas a ce portage de le
 * corriger ailleurs, mais il n'appartient pas non plus a ce portage de le
 * repeter.*
 *
 * ══ LE VERBE EST EXIGE, PAS DEFAUTE ══════════════════════════════════════
 *
 * Une omission ferait retomber `fetch` sur GET, et `GET /scan-cve/liste-blanche`
 * EXISTE : la reponse serait 200 avec la liste, la creation n'aurait pas lieu, et
 * rien — ni le navigateur ni les journaux — ne porterait d'anomalie. La garde en
 * tete d'`envoie()` rend l'omission inexprimable plutot que reinterpretee.
 */
(function () {
    'use strict';

    function lisJson(id) {
        const n = document.getElementById(id);
        if (!n) { return null; }
        try { return JSON.parse(n.textContent); } catch { return null; }
    }

    const L = lisJson('lb-libelles') || {};
    const q = (nom) => document.querySelector('[data-rw="' + nom + '"]');

    // Sans le bloc, le script ne s'initialise pas : un role en dessous de 2 n'emet
    // aucun appel, la ou le legacy en emettait un refuse a chaque affichage.
    if (!q('lb-corps')) { return; }

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');
        return (m && m.content) || '';
    }

    async function envoie(methode, url, corps) {
        if (!methode) {
            throw new Error('envoie() : verbe HTTP requis — une omission retomberait '
                + 'sur GET, que cette route sert.');
        }
        try {
            const rep = await fetch(url, {
                method: methode,
                credentials: 'same-origin',
                headers: Object.assign(
                    { 'X-CSRF-TOKEN': jetonCsrf() },
                    corps ? { 'Content-Type': 'application/json' } : {}
                ),
                body: corps ? JSON.stringify(corps) : undefined,
            });
            const d = await rep.json().catch(() => ({}));
            return { ok: rep.ok, statut: rep.status, d };
        } catch {
            return { ok: false, statut: 0, d: {} };
        }
    }

    function annonce(texte, classe) {
        const zone = q('lb-annonce');
        if (!zone) { return; }
        zone.textContent = texte;
        zone.className = classe || '';
    }

    function cellule(texte, classe) {
        const td = document.createElement('td');
        td.textContent = texte == null ? '' : String(texte);
        if (classe) { td.className = classe; }
        return td;
    }

    function dateSeule(valeur) {
        if (!valeur) { return null; }
        const d = new Date(String(valeur).replace(' ', 'T'));
        return Number.isNaN(d.getTime()) ? String(valeur) : d.toLocaleDateString(L.langue || 'fr');
    }

    /**
     * L'echeance, avec l'etat qu'elle porte.
     *
     * Une entree ECHUE reste en base et cesse de blanchir : l'ecrire « echue »
     * plutot que de la masquer est le point de cette colonne. Une ligne qu'on ne
     * voit plus est une ligne dont personne ne sait qu'elle a expire.
     */
    function echeance(e) {
        if (!e.expires_at) { return { texte: L.sans_echeance || '', echue: false }; }
        const j = new Date(String(e.expires_at).replace(' ', 'T'));
        const passee = !Number.isNaN(j.getTime()) && j < new Date(new Date().toDateString());
        return { texte: dateSeule(e.expires_at), echue: passee };
    }

    function rend(entrees) {
        const corps = q('lb-corps');
        corps.textContent = '';

        const compte = q('lb-compte');
        if (compte) { compte.textContent = String(entrees.length); }

        if (!entrees.length) {
            const tr = document.createElement('tr');
            const td = cellule(L.vide || '');
            td.colSpan = 7;
            tr.appendChild(td);
            corps.appendChild(tr);
            return;
        }

        for (const e of entrees) {
            const tr = document.createElement('tr');
            const ech = echeance(e);

            tr.appendChild(cellule(e.cve_id));
            tr.appendChild(cellule(e.machine_id ? (e.machine_name || String(e.machine_id))
                                                : (L.portee_globale || '')));
            tr.appendChild(cellule(e.reason));
            tr.appendChild(cellule(e.whitelisted_by));

            const tdEch = cellule(ech.texte + (ech.echue ? ' — ' + (L.echue || '') : ''));
            if (ech.echue) { tdEch.className = 'rw-texte--attenue'; }
            tr.appendChild(tdEch);

            tr.appendChild(cellule(dateSeule(e.created_at)));

            const tdAction = document.createElement('td');
            const bouton = document.createElement('button');
            bouton.type = 'button';
            bouton.className = 'rw-bouton rw-bouton--discret';
            bouton.textContent = L.retirer || '';
            bouton.setAttribute('data-rw', 'lb-retirer');
            bouton.addEventListener('click', () => retire(e));
            tdAction.appendChild(bouton);
            tr.appendChild(tdAction);

            corps.appendChild(tr);
        }
    }

    async function charge() {
        const r = await envoie('GET', L.url_liste);
        if (!r.ok) { annonce(L.err_reseau || '', 'rw-annonce rw-annonce--echec'); return; }
        rend(Array.isArray(r.d.entrees) ? r.d.entrees : []);
    }

    async function pose() {
        const corps = {
            cve_id: (q('lb-cve').value || '').trim(),
            reason: (q('lb-motif').value || '').trim(),
            machine_id: q('lb-machine').value,
            expires_at: q('lb-expiration').value,
            sans_expiration: q('lb-sans-expiration').checked,
        };

        const r = await envoie('POST', L.url_liste, corps);

        if (r.ok) {
            q('lb-cve').value = '';
            q('lb-motif').value = '';
            q('lb-expiration').value = '';
            q('lb-sans-expiration').checked = false;
            annonce(L.posee || '', 'rw-annonce rw-annonce--ok');
            await charge();
            return;
        }

        // On rend le message de CHAQUE champ refuse, pas un « erreur » unique :
        // un refus qui ne dit pas lequel des cinq champs il vise se corrige au
        // hasard.
        annonce(r.d.message || L.err_reseau || '', 'rw-annonce rw-annonce--echec');
    }

    async function retire(e) {
        if (!window.confirm((L.confirmer_retrait || '') + ' — ' + (e.cve_id || ''))) { return; }

        const r = await envoie('DELETE', L.url_liste + '/' + encodeURIComponent(e.id));
        annonce(r.ok ? (L.retiree || '') : (r.d.message || L.err_reseau || ''),
                r.ok ? 'rw-annonce rw-annonce--ok' : 'rw-annonce rw-annonce--echec');
        await charge();
    }

    const bouton = q('lb-poser');
    if (bouton) { bouton.addEventListener('click', pose); }

    charge();
})();
