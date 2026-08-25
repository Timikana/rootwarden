/**
 * chatops.js - Correspondances « identifiant chat -> compte RootWarden ».
 *
 * Trois differences avec `legacy/chatops/js/main.js`, et les trois sont des
 * corrections :
 *
 *   1. **AUCUNE BOITE NATIVE.** Le legacy pose un `confirm()` pour supprimer.
 *      Cette boite recouvre precisement la ligne sur laquelle on decide, ne se
 *      style pas — action destructrice et annulation au meme poids — et BLOQUE
 *      Puppeteer, donc le test ne peut pas mener l'action au bout. Ici la
 *      confirmation s'ouvre EN LIGNE, sous la ligne concernee.
 *   2. **Rendu par `textContent`**, jamais par interpolation : un identifiant
 *      Slack et une etiquette sont des donnees saisies par un humain.
 *   3. **Un echec RESEAU se voit** : chaque appel est enveloppe et rend un
 *      objet, jamais une exception qui partirait dans le vide.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const L = JSON.parse(document.getElementById('chatops-libelles').textContent);
    const corps = document.querySelector('[data-rw="chatops-corps"]');
    const etat = document.querySelector('[data-rw="chatops-etat"]');
    const message = document.querySelector('[data-rw="chatops-message"]');

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    function annonce(texte, type) {
        message.textContent = texte;
        message.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
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

    function cellule(texte) {
        const td = document.createElement('td');
        td.textContent = texte == null ? '' : String(texte);

        return td;
    }

    /** L'etat de la fonctionnalite, dit clairement plutot que sous-entendu. */
    function rendEtat(active) {
        etat.textContent = active ? L.enabled : L.disabled;
        etat.className = 'rw-pastille ' + (active ? 'rw-pastille--ok' : 'rw-pastille--attente');
    }

    /**
     * La confirmation, EN LIGNE et sous la ligne concernee.
     *
     * Cachee par l'attribut `hidden` et non par une classe : le projet a paye
     * qu'une regle `display: flex` sur la classe rendait `hidden` sans effet.
     */
    function ouvreConfirmation(tr, correspondance) {
        if (tr.nextElementSibling?.dataset.rw === 'chatops-panneau') return;

        const ligne = document.createElement('tr');
        ligne.dataset.rw = 'chatops-panneau';
        const td = document.createElement('td');
        td.colSpan = 5;
        td.className = 'rw-panneau-decision';

        const bloc = document.createElement('div');
        bloc.className = 'rw-panneau-decision__texte';
        const titre = document.createElement('strong');
        titre.textContent = L.confirm_titre;
        const aide = document.createElement('p');
        aide.className = 'rw-aide';
        aide.textContent = String(L.confirm_aide)
            .replace(':chat', correspondance.chat_user_id)
            .replace(':plateforme', correspondance.platform);
        bloc.append(titre, aide);

        const actions = document.createElement('div');
        actions.className = 'rw-panneau-decision__actions';

        const annuler = document.createElement('button');
        annuler.type = 'button';
        annuler.className = 'rw-bouton rw-bouton--discret';
        annuler.dataset.rw = 'chatops-annuler';
        annuler.textContent = L.confirm_annuler;
        annuler.addEventListener('click', () => ligne.remove());

        const confirmer = document.createElement('button');
        confirmer.type = 'button';
        confirmer.className = 'rw-bouton rw-bouton--danger';
        confirmer.dataset.rw = 'chatops-confirmer';
        confirmer.textContent = L.confirm_supprimer;
        confirmer.addEventListener('click', () => supprime(correspondance, confirmer, ligne));

        actions.append(annuler, confirmer);
        td.append(bloc, actions);
        ligne.appendChild(td);
        tr.after(ligne);
    }

    function rend(correspondances) {
        corps.textContent = '';
        if (! correspondances.length) {
            const tr = document.createElement('tr');
            const td = cellule(L.empty);
            td.colSpan = 5;
            td.className = 'rw-vide';
            tr.appendChild(td);
            corps.appendChild(tr);

            return;
        }
        correspondances.forEach((m) => {
            const tr = document.createElement('tr');
            tr.appendChild(cellule(m.platform));
            tr.appendChild(cellule(m.chat_user_id));
            tr.appendChild(cellule(m.user_name || ('#' + m.user_id)));
            tr.appendChild(cellule(m.label || ''));
            const td = document.createElement('td');
            const bouton = document.createElement('button');
            bouton.type = 'button';
            bouton.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
            bouton.dataset.rw = 'chatops-supprimer';
            bouton.textContent = L.delete;
            bouton.addEventListener('click', () => ouvreConfirmation(tr, m));
            td.appendChild(bouton);
            tr.appendChild(td);
            corps.appendChild(tr);
        });
    }

    async function charge() {
        const r = await appelle('/chatops/users');
        if (! r.ok || ! r.corps || ! r.corps.success) {
            annonce(r.reseau ? L.err_reseau : L.err_load, 'echec');
            rendEtat(false);
            rend([]);

            return;
        }
        rendEtat(!! r.corps.enabled);
        rend(r.corps.mappings || []);
    }

    async function ajoute(bouton) {
        const charge_ = {
            platform: document.querySelector('[data-rw="chatops-plateforme"]').value,
            chat_user_id: document.querySelector('[data-rw="chatops-chatid"]').value.trim(),
            user_id: parseInt(document.querySelector('[data-rw="chatops-utilisateur"]').value, 10),
            label: document.querySelector('[data-rw="chatops-etiquette"]').value.trim(),
        };
        if (! charge_.chat_user_id) { annonce(L.err_chatid, 'echec'); return; }
        bouton.disabled = true;
        const r = await appelle('/chatops/users', { method: 'POST', body: JSON.stringify(charge_) });
        bouton.disabled = false;
        if (r.ok && r.corps && r.corps.success) {
            annonce(L.saved, 'ok');
            document.querySelector('[data-rw="chatops-chatid"]').value = '';
            document.querySelector('[data-rw="chatops-etiquette"]').value = '';
            charge();

            return;
        }
        annonce(r.reseau ? L.err_reseau : ((r.corps && r.corps.message) || L.err_save), 'echec');
    }

    async function supprime(correspondance, bouton, ligne) {
        bouton.disabled = true;
        const chemin = '/chatops/users/' + encodeURIComponent(correspondance.platform)
            + '/' + encodeURIComponent(correspondance.chat_user_id);
        const r = await appelle(chemin, { method: 'DELETE' });
        bouton.disabled = false;
        ligne.remove();
        if (r.ok && r.corps && r.corps.success) {
            annonce(L.deleted, 'ok');
            charge();

            return;
        }
        annonce(r.reseau ? L.err_reseau : L.err_save, 'echec');
    }

    document.querySelector('[data-rw="chatops-ajouter"]')
        .addEventListener('click', (e) => ajoute(e.currentTarget));
    charge();
})();
