/**
 * notifications-reglages.js - Module `adm/`, sous-lot D2 : les preferences.
 *
 * La case ENVOIE explicitement son etat. Le legacy s'en remet a la
 * serialisation que htmx fait d'une case sans `name` : cela marche — mesure,
 * `value=1` part bien — mais rien dans le balisage ne le dit, et le point d'API
 * exige pourtant `value`. Ici la valeur est posee a la main : ce que la route
 * lit et ce que la page envoie se lisent au meme endroit.
 *
 * Et, comme partout dans ce portage : l'ecran ne bouge qu'apres la reponse. Une
 * case qui se coche avant confirmation annonce un reglage qui peut ne pas avoir
 * ete enregistre.
 */
(function () {
    'use strict';

    const L = JSON.parse(document.getElementById('notif-reglages-libelles').textContent);
    const annonce = document.querySelector('[data-rw="notif-reglages-annonce"]');
    if (! annonce) return;

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    function dis(texte, type) {
        annonce.textContent = texte;
        annonce.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
    }

    async function bascule(case_) {
        const voulu = case_.checked;
        // On REMET l'etat d'avant : il ne bougera que si le serveur confirme.
        case_.checked = ! voulu;
        case_.disabled = true;

        let r;
        try {
            const rep = await fetch('/notifications/preferences', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-TOKEN': jetonCsrf(),
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    user_id: case_.dataset.userId,
                    event_type: case_.dataset.eventType,
                    value: voulu ? 1 : 0,
                }),
            });
            let json = null;
            try { json = await rep.json(); } catch (e) { /* reponse non JSON */ }
            r = { ok: rep.ok, statut: rep.status, corps: json };
        } catch (e) {
            r = { ok: false, statut: 0, corps: null };
        }
        case_.disabled = false;

        if (! r.ok || ! r.corps || ! r.corps.success) {
            dis((r.corps && r.corps.message) || L.err_reseau.replace(':statut', r.statut), 'echec');

            return;
        }
        case_.checked = r.corps.actif;
        dis(r.corps.message, 'ok');
    }

    document.addEventListener('change', (ev) => {
        const c = ev.target;
        if (c instanceof HTMLInputElement && c.type === 'checkbox' && c.dataset.eventType) {
            bascule(c);
        }
    });
})();
