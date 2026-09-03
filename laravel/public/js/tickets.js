/**
 * tickets.js - Ticketing ITSM : liste et creation manuelle.
 *
 * Rendu par `textContent` et `createElement`, jamais par interpolation. La
 * colonne « Reference » porte une URL venue de l'ITSM — donnee EXTERNE : seul
 * `http(s)` est accepte, et le lien est construit par `setAttribute`, ce qui
 * retire tout besoin d'echapper des guillemets a la main.
 *
 * TROIS DIFFERENCES VOULUES AVEC LE LEGACY :
 *
 * 1. La COLLISION EST ANNONCEE AVANT LE CLIC. Le dedoublonnage porte sur
 *    (source, reference, machine) et non sur le resume : un ticket manuel
 *    n'ayant ni reference ni source variable, il ne peut en exister qu'UN par
 *    machine. Le legacy laisse creer, puis annonce « deja existant » dans une
 *    bulle. Ici, choisir une machine deja pourvue affiche l'avertissement et
 *    cite le ticket concerne.
 * 2. Le bouton reste INACTIF tant que le resume est vide, au lieu de reprocher
 *    apres coup.
 * 3. Le resultat est ecrit dans une region d'annonce durable, et le message de
 *    dedoublonnage DIT sur quelle cle il a joue.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const corps = document.getElementById('tickets-tbody');
    const etatFournisseur = document.getElementById('tickets-status');
    const annonce = document.getElementById('tickets-annonce');
    const collision = document.getElementById('t-collision');
    const formulaire = document.getElementById('ticket-form');
    const champResume = document.getElementById('t-summary');
    const champMachine = document.getElementById('t-machine');
    const champDesc = document.getElementById('t-desc');
    const boutonCreer = document.getElementById('t-save');
    const libelles = JSON.parse(document.getElementById('tickets-libelles').textContent);

    let dernierChargement = 0;
    let tickets = [];

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

    /**
     * Cellule de reference. `external_url` vient de l'ITSM : donnee externe.
     * Seul http(s) devient un lien — `javascript:` et consorts restent du
     * texte. `setAttribute` pose l'URL telle quelle, sans passer par une
     * chaine de HTML : il n'y a donc rien a echapper.
     */
    function celluleReference(t) {
        const td = document.createElement('td');
        td.className = 'rw-tableau__discret';
        const url = String(t.external_url || '');
        const libelle = t.external_id || t.ref || '—';

        if (/^https?:\/\//i.test(url)) {
            const a = document.createElement('a');
            a.className = 'rw-lien';
            a.setAttribute('href', url);
            a.setAttribute('target', '_blank');
            a.setAttribute('rel', 'noopener noreferrer');
            a.textContent = libelle;
            td.appendChild(a);
        } else {
            td.textContent = libelle;
        }
        return td;
    }

    function rendFournisseur(actif) {
        etatFournisseur.replaceChildren();
        const p = document.createElement('span');
        p.className = 'rw-pastille ' + (actif ? 'rw-pastille--ok' : 'rw-pastille--attente');
        p.textContent = actif ? libelles.provider_on : libelles.provider_off;
        etatFournisseur.appendChild(p);
    }

    function rend(liste) {
        if (!liste.length) {
            message(libelles.empty, libelles.empty_aide);
            return;
        }

        corps.replaceChildren();
        for (const t of liste) {
            const tr = document.createElement('tr');

            tr.appendChild(cellule(
                t.created_at ? new Date(t.created_at).toLocaleString() : '—',
                'rw-tableau__discret'));

            const tdSource = document.createElement('td');
            const source = document.createElement('span');
            source.className = 'rw-badge';
            source.textContent = t.source || '—';
            tdSource.appendChild(source);
            tr.appendChild(tdSource);

            tr.appendChild(cellule(t.summary || ''));
            tr.appendChild(cellule(
                t.machine_name || (t.machine_id ? '#' + t.machine_id : '—'),
                'rw-tableau__discret'));
            tr.appendChild(cellule(t.provider || '—', 'rw-tableau__discret'));
            tr.appendChild(celluleReference(t));

            corps.appendChild(tr);
        }
    }

    /**
     * Un ticket manuel existe-t-il deja pour la machine choisie ?
     *
     * C'est exactement la cle que le backend appliquera. La regle reste la
     * sienne — on la rend seulement visible AVANT le geste.
     */
    function verifieCollision() {
        const machine = champMachine.value || null;
        const existant = tickets.find(t =>
            (t.source || '') === 'manual'
            && !t.ref
            && String(t.machine_id ?? '') === String(machine ?? ''));

        if (existant) {
            collision.textContent = libelles.collision.replace(':resume', existant.summary || '');
            collision.className = 'rw-annonce rw-annonce--attention';
        } else {
            collision.textContent = '';
            collision.className = 'rw-annonce';
        }
    }

    /** Le bouton n'est actif que lorsque la creation a un sens. */
    function majBouton() {
        boutonCreer.disabled = champResume.value.trim().length === 0;
    }

    async function charge() {
        const numero = ++dernierChargement;
        const res = await appelle('/tickets');

        if (numero !== dernierChargement) return;

        if (!res.ok || !res.corps || !res.corps.success) {
            message(libelles.err_load);
            dit(libelles.err_load, 'echec');
            return;
        }
        tickets = res.corps.tickets || [];
        rendFournisseur(Boolean(res.corps.provider_enabled));
        rend(tickets);
        verifieCollision();
    }

    async function cree() {
        const resume = champResume.value.trim();
        if (!resume) { dit(libelles.err_summary, 'echec'); return; }

        boutonCreer.disabled = true;
        const res = await appelle('/tickets', {
            method: 'POST',
            body: JSON.stringify({
                source: 'manual',
                machine_id: champMachine.value || null,
                summary: resume,
                description: champDesc.value.trim(),
            }),
        });

        if (res.ok && res.corps && res.corps.success) {
            // `deduped` veut dire : rien n'a ete cree. Le dire clairement, et
            // dire sur quoi la cle a joue — sinon on repart en croyant avoir
            // ouvert un ticket qui n'existe pas.
            dit(res.corps.deduped ? libelles.deduped : libelles.created,
                res.corps.deduped ? 'attention' : 'ok');
            champResume.value = '';
            champDesc.value = '';
            formulaire.hidden = true;
        } else {
            dit((res.corps && res.corps.message) || libelles.err_create, 'echec');
        }

        majBouton();
        await charge();
    }

    document.getElementById('new-ticket-btn').addEventListener('click', () => {
        formulaire.hidden = !formulaire.hidden;
        if (!formulaire.hidden) { verifieCollision(); champResume.focus(); }
    });
    document.getElementById('t-cancel').addEventListener('click', () => { formulaire.hidden = true; });
    champResume.addEventListener('input', majBouton);
    champMachine.addEventListener('change', verifieCollision);
    boutonCreer.addEventListener('click', cree);

    majBouton();
    charge();
})();
