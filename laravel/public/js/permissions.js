/**
 * permissions.js - Module `adm/`, sous-lot D5.
 *
 * LA CASE NE BOUGE QU'APRES LA REPONSE, et le refus de step-up OUVRE un panneau.
 *
 * Le legacy fait tout le contraire, sans le vouloir : sa case part en htmx, le
 * serveur repond 403 `step_up_required`, le modal qui permettrait d'y repondre
 * n'ecoute que `window.fetch`, et htmx ne remplace rien sur un 4xx. Resultat
 * mesure : le POST part, le refus revient, la base ne bouge pas, et l'ecran non
 * plus. Trois pieces correctes qui forment une impasse (PARITE E-119).
 */
(function () {
    'use strict';

    const L = JSON.parse(document.getElementById('perms-libelles').textContent);
    const annonce = document.querySelector('[data-rw="perms-annonce"]');
    const panneau = document.querySelector('[data-rw="perms-panneau-stepup"]');
    if (! annonce) return;

    let enAttente = null;

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    function dis(texte, type) {
        annonce.textContent = texte;
        annonce.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
    }

    function garnis(modele, valeurs) {
        return Object.keys(valeurs).reduce(
            (t, c) => t.split(':' + c).join(String(valeurs[c])), String(modele)
        );
    }

    async function appelle(chemin, corps) {
        try {
            const r = await fetch(chemin, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-TOKEN': jetonCsrf(),
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(corps || {}),
            });
            let json = null;
            try { json = await r.json(); } catch (e) { /* reponse non JSON */ }

            return { ok: r.ok, statut: r.status, corps: json };
        } catch (e) {
            return { ok: false, statut: 0, corps: null };
        }
    }

    function demandeStepUp(action, rejouer) {
        enAttente = { action, rejouer };
        const champ = panneau.querySelector('[data-rw="perms-stepup-code"]');
        champ.value = '';
        panneau.hidden = false;
        champ.focus();
    }

    async function valideStepUp() {
        if (! enAttente) return;
        const champ = panneau.querySelector('[data-rw="perms-stepup-code"]');
        const bouton = panneau.querySelector('[data-rw="perms-stepup-valider"]');
        bouton.disabled = true;
        const r = await appelle('/profil/step-up',
            { action: enAttente.action, code: champ.value.trim() });
        bouton.disabled = false;
        if (! r.ok || ! r.corps || ! r.corps.success) {
            dis((r.corps && r.corps.message) || garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        panneau.hidden = true;
        const rejouer = enAttente.rejouer;
        enAttente = null;
        await rejouer();
    }

    /**
     * Une bascule. La case REPREND son etat d'avant tant que le serveur n'a pas
     * confirme : une case cochee qui ne l'est pas en base est un mensonge.
     */
    async function bascule(caseCible) {
        const voulu = caseCible.checked;
        caseCible.checked = ! voulu;
        caseCible.disabled = true;

        const id = caseCible.dataset.userId;
        const estAcces = !! caseCible.dataset.machineId;
        const chemin = estAcces ? `/permissions/${id}/acces` : `/permissions/${id}`;
        const corps = estAcces
            ? { machine_id: caseCible.dataset.machineId, value: voulu ? 1 : 0 }
            : { permission: caseCible.dataset.permission, value: voulu ? 1 : 0 };

        const r = await appelle(chemin, corps);
        caseCible.disabled = false;

        if (r.corps && r.corps.step_up_required) {
            // Le refus s'ANNONCE, et il ouvre le chemin pour y repondre.
            dis(r.corps.message, 'attention');

            return demandeStepUp(r.corps.action, async () => {
                caseCible.checked = voulu;
                await bascule(caseCible);
            });
        }
        if (! r.corps) { dis(garnis(L.err_reseau, { statut: r.statut }), 'echec'); return; }
        if (! r.ok || ! r.corps.success) { dis(r.corps.message, 'echec'); return; }

        caseCible.checked = r.corps.actif;
        dis(r.corps.message, 'ok');
    }

    document.addEventListener('change', (ev) => {
        const c = ev.target;
        if (c instanceof HTMLInputElement && c.type === 'checkbox'
            && (c.dataset.permission || c.dataset.machineId)) {
            bascule(c);
        }
    });
    document.addEventListener('click', (ev) => {
        const rw = ev.target instanceof HTMLElement ? (ev.target.dataset.rw || '') : '';
        if (rw === 'perms-stepup-annuler') { panneau.hidden = true; enAttente = null; }
        if (rw === 'perms-stepup-valider') valideStepUp();
    });
})();
