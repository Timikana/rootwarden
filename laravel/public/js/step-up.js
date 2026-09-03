/**
 * step-up.js — LE DEFI DE RE-AUTHENTIFICATION, EN UN SEUL ENDROIT.
 *
 * ══ POURQUOI CE FICHIER EXISTE ═══════════════════════════════════════════
 *
 * Le patron etait ecrit DEUX FOIS — `comptes.js:158` et `permissions.js` — et
 * deux nouveaux consommateurs arrivaient : `politiques` et `acces-sftp`, dont
 * les gestes ecrivent des regles `sudo` et `sftp` sur des machines reelles.
 *
 * Recopier deux fois de plus en aurait fait QUATRE. **Trois implementations
 * d'une meme regle finissent par diverger, et celle-ci garde des deploiements
 * sudo.**
 *
 * ⚠ ET CE N'EST PAS UNE UNIFICATION, C'EST UN CHOIX QUI EN REDUIT LE COMPTE.
 * `comptes` et `permissions` gardent leur implementation : les unifier
 * toucherait des modules couverts par leurs propres suites, et ce n'est pas le
 * perimetre de ce sous-lot. **DEUX implementations subsistent**, et ce fichier
 * est l'endroit ou les faire converger le jour ou quelqu'un s'en chargera.
 *
 * Il n'y a pas d'etape de construction dans ce projet : pas d'`import`, donc
 * un fichier charge par les deux pages est ce qui s'approche le plus de
 * « reutiliser ».
 *
 * ══ CE QUE LE SERVEUR NOMME, LE CLIENT NE LE DEVINE PAS ══════════════════
 *
 * `PasserelleController` refuse avec un `403` qui porte
 * `step_up_required: true` ET `action`. L'action est DERIVEE DU CHEMIN
 * (`/policy/sudo/deploy` -> `policy_sudo_deploy`), et c'est le raffinement du
 * sous-lot A5 : le legacy fusionne les trois routes root sous `policy_action`,
 * si bien qu'un step-up consenti pour ANNULER une politique autorise un
 * DEPLOIEMENT SUDO pendant quinze minutes.
 *
 * **Ce module ne compose donc JAMAIS le nom de l'action.** Il transmet celui
 * que le serveur a nomme. Un client qui le devinerait recollerait le defaut.
 *
 * ══ CE QU'IL NE FAIT PAS ═════════════════════════════════════════════════
 *
 * Il n'appelle aucun geste. Il valide un second facteur puis REJOUE ce que
 * l'appelant lui a confie — sans cela, l'operateur devrait recommencer, et une
 * re-authentification qui ne sert a rien se transforme en gene qu'on cherche a
 * contourner.
 */
window.rwStepUp = (function () {
    'use strict';

    /**
     * @param {object} o
     * @param {Element} o.panneau   le panneau de decision, masque
     * @param {Element} o.champ     le champ du code a six chiffres
     * @param {Element} o.valider
     * @param {Element} o.annuler
     * @param {function} o.dis      (texte, type) — l'annonce de l'appelant
     * @param {object} o.textes     les libelles, deja substitues
     */
    function installe(o) {
        var enAttente = null;

        function ferme() {
            if (o.panneau) { o.panneau.hidden = true; }
            enAttente = null;
        }

        /**
         * Ouvre le defi et met le geste en attente.
         *
         * @param {string} action   NOMMEE PAR LE SERVEUR, jamais composee ici
         * @param {function} rejouer
         */
        function demande(action, rejouer) {
            if (! o.panneau || ! o.champ) { return; }
            enAttente = { action: action, rejouer: rejouer };
            o.champ.value = '';
            o.panneau.hidden = false;
            o.champ.focus();
        }

        function valide() {
            if (! enAttente) { return; }
            if (o.valider) { o.valider.disabled = true; }

            fetch('/profil/step-up', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRF-TOKEN': (document.querySelector('meta[name="csrf-token"]') || {}).content || '',
                },
                body: JSON.stringify({ action: enAttente.action, code: (o.champ.value || '').trim() }),
            }).then(function (r) {
                return r.json().then(function (j) { return { ok: r.ok, corps: j }; },
                    function () { return { ok: false, corps: null }; });
            }).catch(function () { return { ok: false, corps: null }; })
            .then(function (r) {
                if (o.valider) { o.valider.disabled = false; }
                if (! r.ok || ! r.corps || r.corps.success !== true) {
                    /*
                     * LE MESSAGE DU SERVEUR EST RENDU TEL QUEL. Les libelles de
                     * `step_up.php` sont deliberement peu bavards — ils disent
                     * qu'on refuse, pas ce qui manquerait pour reussir — et les
                     * reecrire ici les rendrait plus loquaces que voulu.
                     */
                    o.dis((r.corps && r.corps.message) || o.textes.panneau_echec, 'echec');

                    return;
                }
                var rejouer = enAttente.rejouer;
                ferme();
                if (typeof rejouer === 'function') { rejouer(); }
            });
        }

        if (o.valider) { o.valider.addEventListener('click', valide); }
        if (o.annuler) { o.annuler.addEventListener('click', ferme); }

        /**
         * Le point d'entree des appelants : rend `true` s'il a PRIS EN CHARGE
         * un refus de step-up, `false` sinon.
         *
         * ⚠ La detection porte sur `step_up_required`, PAS sur le message ni
         * sur le statut : un texte se traduit, un 403 sert a d'autres refus.
         */
        function intercepte(verdict, rejouer) {
            var c = verdict && verdict.corps;
            if (! c || c.step_up_required !== true || ! c.action) { return false; }
            demande(c.action, rejouer);

            return true;
        }

        return { intercepte: intercepte, ferme: ferme };
    }

    return { installe: installe };
})();
