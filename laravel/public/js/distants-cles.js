/*
 * Retrait d'UNE cle SSH precise sur un compte distant.
 *
 * ⚠⚠ `force` N'EST PAS CONSTRUIT, ET C'EST LE POINT DE CE FICHIER.
 *
 * `POST /server_user_remove_key` accepte quatre champs :
 *
 *     machine_id · username · fingerprint_sha256 · force
 *
 * `force: true` autorise le retrait de la CLE PLATEFORME — celle par laquelle
 * RootWarden atteint la machine. Le backend la protege (`ssh.py:2474`,
 * « ne pas se locker hors du serveur ») et ne cede qu'a un `force` explicite.
 *
 * Ce fichier ne met donc PAS `force: false` : il n'ecrit pas le champ du tout.
 * *Un `false` se retourne d'un caractere ; une absence demande d'AJOUTER une
 * ligne, et cette ligne se voit en relecture.* C'est la meme forme que la liste
 * fermee de `wazuh.js` — rendre inexprimable plutot que surveiller.
 *
 * ⛔ ET LE BOUTON N'EST PAS RENDU sur la ligne de la cle plateforme (la vue s'en
 * charge). Sans ca, il serait present et rendrait un 400 a chaque clic : un
 * bouton qui echoue toujours au meme endroit apprend a l'operateur que les
 * echecs sont normaux.
 *
 * ── CE QUE CE GESTE FAIT REELLEMENT ──────────────────────────────────────────
 * SSH en root sur la machine, reecriture de `~/.ssh/authorized_keys` sans la
 * ligne visee, puis suppression de la row dans `server_user_ssh_keys`. Ce n'est
 * pas une correction d'affichage : la cle ne rouvrira pas la session suivante.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';
    var CHEMIN = '/server_user_remove_key';

    var racine = document.querySelector('[data-rw="distants-cles-liste"]');
    if (! racine) { return; }

    var textes = {};
    var bloc = document.getElementById('distants-cles-libelles');
    if (bloc) {
        try { textes = JSON.parse(bloc.textContent) || {}; } catch (e) { textes = {}; }
    }

    function t(cle) {
        return Object.prototype.hasOwnProperty.call(textes, cle) ? textes[cle] : '';
    }

    function jetonCsrf() {
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.getAttribute('content') : '';
    }

    function annonce(ligne, message, estErreur) {
        var cellule = ligne.querySelector('[data-rw="distants-cle-verdict"]');
        if (! cellule) { return; }
        cellule.textContent = message;
        cellule.className = estErreur ? 'rw-erreur' : 'rw-confirmation';
    }

    racine.addEventListener('click', function (evenement) {
        var bouton = evenement.target.closest('[data-rw="distants-cle-retirer"]');
        if (! bouton) { return; }

        var ligne = bouton.closest('tr');
        if (! ligne) { return; }

        /*
         * LA CONFIRMATION NOMME L'EMPREINTE. « Retirer cette cle ? » ne dit pas
         * LAQUELLE quand la page en liste plusieurs — et se tromper de ligne est
         * l'erreur que cet ecran rend possible.
         */
        if (! window.confirm(t('confirme').replace(':empreinte', bouton.dataset.empreinte || ''))) {
            return;
        }

        bouton.disabled = true;

        /*
         * Le corps porte TROIS champs. Pas quatre. Voir l'en-tete de ce fichier.
         */
        fetch(PASSERELLE + CHEMIN, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CSRF-TOKEN': jetonCsrf()
            },
            body: JSON.stringify({
                machine_id: parseInt(racine.dataset.machine, 10),
                username: racine.dataset.username || '',
                fingerprint_sha256: bouton.dataset.empreinte || ''
            })
        }).then(function (reponse) {
            return reponse.json().catch(function () { return null; });
        }).then(function (corps) {
            if (corps && corps.success === true) {
                annonce(ligne, t('retiree'), false);
                ligne.classList.add('rw-ligne--retiree');
                bouton.remove();
                return;
            }
            /*
             * LE MESSAGE DU BACKEND EST RENDU TEL QUEL quand il existe : c'est
             * lui qui sait pourquoi il a refuse — cle plateforme, machine
             * injoignable, empreinte inconnue. Le remplacer par un libelle
             * generique ferait chercher au mauvais endroit.
             */
            annonce(ligne, (corps && corps.message) || t('echec'), true);
            bouton.disabled = false;
        }).catch(function () {
            annonce(ligne, t('echec'), true);
            bouton.disabled = false;
        });
    });
}());
