/*
 * Le parc de machines — module `adm/`, sous-lot D6a.
 *
 * DEUX COMPORTEMENTS SEULEMENT : le filtre d'affichage et le panneau de retrait.
 * Tout le reste est du HTML qui se soumet — l'ajout, la modification et la
 * suppression sont trois formulaires POST vers trois routes distinctes, qui
 * fonctionnent sans une ligne de JavaScript. Le legacy, lui, distingue ses trois
 * gestes par le `name` du bouton clique dans un POST unique.
 */
(function () {
    'use strict';

    var libelles = {};
    try {
        var bloc = document.getElementById('serveurs-libelles');
        if (bloc) { libelles = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) {
        // Un libelle illisible ne doit pas emporter le filtre ni le panneau de
        // retrait : on continue avec des chaines vides plutot que rien du tout.
        libelles = {};
    }

    /* ═══ Filtre d'affichage ══════════════════════════════════════════════ */

    var champ = document.querySelector('[data-rw="serveurs-filtre"]');
    var compteur = document.querySelector('[data-rw="serveurs-compte"]');
    var cartes = Array.prototype.slice.call(document.querySelectorAll('[data-rw="serveur-carte"]'));

    function filtre() {
        var terme = (champ.value || '').trim().toLowerCase();
        var vus = 0;

        cartes.forEach(function (carte) {
            var visible = terme === '' || (carte.dataset.cible || '').indexOf(terme) !== -1;
            carte.hidden = !visible;
            if (visible) { vus += 1; }
            // UNE CARTE MASQUEE SE REPLIE. Laisser un formulaire d'edition
            // ouvert dans une carte qu'on ne voit plus, c'est offrir un geste
            // sur une machine qu'on croit avoir ecartee.
            if (!visible) { carte.open = false; }
        });

        if (compteur && libelles.filtre_resultat) {
            compteur.textContent = libelles.filtre_resultat.replace('__N__', String(vus));
        }
    }

    if (champ && cartes.length) {
        champ.addEventListener('input', filtre);
    }

    /* ═══ Retrait du parc ═════════════════════════════════════════════════ */

    var panneau = document.querySelector('[data-rw="serveur-suppr-panneau"]');
    var titre = document.querySelector('[data-rw="serveur-suppr-titre"]');
    var formulaire = document.querySelector('[data-rw="serveur-suppr-form"]');
    var annuler = document.querySelector('[data-rw="serveur-suppr-annuler"]');

    // Le gabarit de l'adresse est lu UNE fois sur le panneau : il porte
    // l'identifiant reel dans son `data-action`, pose par le serveur.
    var gabarit = panneau ? (panneau.dataset.action || '') : '';

    function ouvre(id, nom) {
        if (!panneau || !formulaire) { return; }
        formulaire.setAttribute('action', gabarit.replace('__ID__', String(id)));
        if (titre && libelles.suppr_titre) {
            // `textContent`, jamais `innerHTML` : le nom vient de la base, et la
            // branche « journal » de `ssh/js/main.js` a montre ce que coute un
            // `innerHTML +=` sur une valeur qu'on n'a pas ecrite soi-meme.
            titre.textContent = libelles.suppr_titre.replace('__NOM__', nom);
        }
        panneau.hidden = false;
        panneau.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }

    document.querySelectorAll('[data-rw="serveur-supprimer"]').forEach(function (bouton) {
        bouton.addEventListener('click', function () {
            ouvre(bouton.dataset.id, bouton.dataset.nom || '');
        });
    });

    if (annuler && panneau) {
        annuler.addEventListener('click', function () { panneau.hidden = true; });
    }

    /* ═══ Test de connexion — sous-lot D6d ════════════════════════════════
     *
     * SEUL APPEL RESEAU DE CETTE PAGE, et il ne part QUE sur un clic. Une page
     * qui joint le parc en s'ouvrant, c'est `health_check.php` — qui ECRIT sur
     * `srv-zabbix` au simple chargement. Ici, rien ne part tant que personne ne
     * l'a demande, machine par machine.
     *
     * La sonde appartient au backend : elle passe par la passerelle, qui porte
     * les controles dans l'ordre et propage le statut tel quel.
     */
    var PASSERELLE = '/api/gateway';

    function resultatDe(id) {
        return document.querySelector('[data-rw="serveur-test-resultat"][data-id="' + id + '"]');
    }

    document.querySelectorAll('[data-rw="serveur-tester"]').forEach(function (bouton) {
        bouton.addEventListener('click', function () {
            var id = bouton.dataset.id;
            var sortie = resultatDe(id);
            if (! sortie) { return; }

            // LE BOUTON SE DESACTIVE PENDANT LA SONDE. Elle dure jusqu'a 5 s
            // cote backend ; sans cela, on clique trois fois en croyant que
            // rien ne se passe, et trois sondes partent.
            bouton.disabled = true;
            sortie.textContent = libelles.test_en_cours || '';

            fetch(PASSERELLE + '/server_status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ machine_id: parseInt(id, 10) }),
            }).then(function (r) {
                return r.json().catch(function () { return null; });
            }).then(function (d) {
                // FAIL-CLOSED SUR LA FORME DE LA REPONSE : sans `success`, on
                // annonce un echec de test, jamais un etat de machine. Un
                // `undefined` affiche comme « hors ligne » serait un mensonge.
                if (! d || d.success !== true) {
                    sortie.textContent = libelles.test_echec || '';

                    return;
                }
                var gabarit = d.status === 'online' ? libelles.test_en_ligne : libelles.test_hors_ligne;
                sortie.textContent = (gabarit || '').replace('__IP__', d.ip || '');
            }).catch(function () {
                sortie.textContent = libelles.test_echec || '';
            }).then(function () {
                bouton.disabled = false;
            });
        });
    });
}());
