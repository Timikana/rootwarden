/*
 * supervision.js - Module `supervision/`, sous-lot V1 : les onglets, le choix de
 * plateforme, et le garde de l'editeur.
 *
 * CE SCRIPT NE PARLE A PERSONNE. Pas un `fetch`, pas un `EventSource`, aucune
 * adresse. Tout ce qu'il montre est deja dans la page, rendu cote serveur
 * (decision S3/S4). C'est la difference mesuree avec le legacy, qui emet deux
 * requetes backend au chargement et les rejoue a CHAQUE bascule d'onglet.
 *
 * Les libelles viennent du MEME catalogue que la page, poses en donnees. Cote
 * legacy le JS lit un second catalogue ou onze cles du module manquent, et
 * `head.php` rend alors la cle elle-meme a l'ecran.
 */
(function () {
    'use strict';

    var libelles = {};
    try {
        libelles = JSON.parse(document.getElementById('superv-libelles').textContent);
    } catch (e) {
        // Sans libelles, mieux vaut une page sans script qu'une page qui affiche
        // des identifiants techniques.
        return;
    }

    /* ── Les onglets ────────────────────────────────────────────────────────
     * On derive la liste des DEUX cotes du meme attribut : jamais un index, ni
     * « le premier bouton ». Deplacer un bouton ne doit rien casser.
     */
    var onglets = [].slice.call(document.querySelectorAll('[data-rw^="onglet-"]'));

    function montreOnglet(nom) {
        onglets.forEach(function (bouton) {
            var sien = bouton.dataset.rw.replace('onglet-', '');
            var actif = sien === nom;
            bouton.classList.toggle('rw-onglet--actif', actif);
            bouton.setAttribute('aria-selected', actif ? 'true' : 'false');
            var panneau = document.querySelector('[data-rw="panneau-' + sien + '"]');
            if (panneau) { panneau.hidden = !actif; }
        });
    }

    onglets.forEach(function (bouton) {
        bouton.addEventListener('click', function () {
            montreOnglet(bouton.dataset.rw.replace('onglet-', ''));
        });
    });

    /* ── Le choix de plateforme ─────────────────────────────────────────────
     * La valeur vient d'un `<option>` que le serveur a ecrit depuis une liste
     * FERMEE : elle sert d'identifiant a `getElementById`, et il ne faut pas
     * qu'une valeur venue d'ailleurs y arrive un jour. On ne parcourt donc que
     * les blocs presents, sans jamais construire de selecteur libre.
     */
    var choixPlateforme = document.querySelector('[data-rw="superv-plateforme"]');
    if (choixPlateforme) {
        /*
         * Les blocs a basculer sont NOMMES ici, un par famille : la
         * configuration (V1) et le catalogue de profils (V2). Une liste
         * explicite plutot qu'un selecteur par prefixe — un prefixe attraperait
         * ce qu'un sous-lot suivant ajoutera, et le ferait disparaitre sans
         * qu'aucun test ne l'ait demande.
         */
        var familles = ['config-', 'profils-'];
        var blocs = [];
        [].slice.call(choixPlateforme.options).forEach(function (o) {
            familles.forEach(function (prefixe) {
                var bloc = document.getElementById(prefixe + o.value);
                if (bloc) { blocs.push({ nom: o.value, bloc: bloc }); }
            });
        });
        choixPlateforme.addEventListener('change', function () {
            blocs.forEach(function (b) {
                b.bloc.hidden = b.nom !== choixPlateforme.value;
            });
        });
    }

    /* ── Les panneaux de decision, ouverts sous leur ligne ──────────────────
     * Une suppression de profil est destructrice : elle emporte les assignations
     * (`ON DELETE CASCADE`). La decision se prend DONC dans la page, sous la ligne
     * concernee — une boite native recouvre precisement la ligne sur laquelle on
     * decide, ne se style pas, et bloque le test qui doit mener le geste au bout.
     *
     * Le bouton NOMME sa cible par `data-cible` : pas de selecteur derive du
     * `data-rw`, qui attraperait ce qu'un sous-lot suivant ajoutera.
     */
    [].slice.call(document.querySelectorAll('[data-cible]')).forEach(function (bouton) {
        bouton.addEventListener('click', function () {
            var panneau = document.getElementById(bouton.dataset.cible);
            if (! panneau) { return; }
            panneau.hidden = ! panneau.hidden;
        });
    });

    /* ── La detection de version — sous-lot V6 ──────────────────────────────
     * LE SEUL GESTE DE CETTE PAGE QUI JOINT UNE MACHINE. Il passe par la
     * passerelle parce que c'est le backend qui ouvre la session SSH (exception
     * declaree, comme K2/K3/K4).
     *
     * UN CLIENT QUI NE LIT PAS `resp.status` AVALE TOUS LES REFUS : un 403 ou un
     * 500 y ressemble a une reponse vide, et l'ecran conclut « aucun agent »
     * alors que personne n'a rien mesure. On lit donc le statut D'ABORD.
     *
     * Et le verdict RESTE a l'ecran : le legacy le passe a un `toast()` de 4 s
     * alors qu'une session SSH en demande le double — le message disparaissait
     * avant que son effet soit constatable.
     */
    var messageVersion = document.querySelector('[data-rw="superv-version-message"]');
    [].slice.call(document.querySelectorAll('[data-rw="superv-detecter-version"]'))
        .forEach(function (bouton) {
            bouton.addEventListener('click', function () {
                if (! messageVersion) { return; }
                var nom = bouton.dataset.nom || '';
                messageVersion.className = 'rw-annonce';
                messageVersion.textContent = libelles.version_en_cours.replace('{nom}', nom);
                bouton.disabled = true;

                var jeton = document.querySelector('meta[name="csrf-token"]');
                fetch(libelles.url_version, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': jeton ? jeton.content : '',
                    },
                    body: JSON.stringify({ machine_id: Number(bouton.dataset.machine) }),
                }).then(function (reponse) {
                    if (! reponse.ok) {
                        // Le statut d'abord : un refus ne se confond pas avec
                        // « aucun agent installe ».
                        messageVersion.className = 'rw-annonce rw-annonce--echec';
                        messageVersion.textContent = libelles.version_refus
                            .replace('{statut}', String(reponse.status));
                        return null;
                    }
                    return reponse.json();
                }).then(function (donnees) {
                    if (! donnees) { return; }
                    if (donnees.version) {
                        messageVersion.className = 'rw-annonce rw-annonce--ok';
                        messageVersion.textContent = libelles.version_trouvee
                            .replace('{version}', donnees.version)
                            .replace('{nom}', nom);
                    } else {
                        messageVersion.className = 'rw-annonce';
                        messageVersion.textContent = libelles.version_absente
                            .replace('{nom}', nom);
                    }
                }).catch(function () {
                    messageVersion.className = 'rw-annonce rw-annonce--echec';
                    messageVersion.textContent = libelles.version_echec;
                }).finally(function () {
                    bouton.disabled = false;
                });
            });
        });

    /* ── Le garde de l'editeur ──────────────────────────────────────────────
     * LE SEUL GESTE DE V1. Sans serveur choisi, il refuse — DANS la page, avec
     * une phrase traduite, et sans joindre quoi que ce soit. Cote legacy, ce
     * refus ouvre une boite native qui affiche la cle `editor_select_server`.
     *
     * La lecture reelle du fichier distant (V7) n'est pas portee : le bouton ne
     * fait donc rien de plus que ce refus, et la page annonce ou la faire.
     */
    var bouton = document.querySelector('[data-rw="superv-lire-config"]');
    var message = document.querySelector('[data-rw="superv-editeur-message"]');
    var serveur = document.querySelector('[data-rw="superv-serveur"]');

    if (bouton && message && serveur) {
        bouton.addEventListener('click', function () {
            /*
             * DEUX refus, jamais un silence. Sans serveur, c'est le garde du
             * legacy — la seule des onze cles cassees atteignable ici. Avec un
             * serveur, la lecture distante n'est pas portee (V7) et la page le
             * DIT : un bouton qui ne repond rien laisse croire a une panne.
             */
            message.textContent = serveur.value === ''
                ? libelles.editeur_sans_serveur
                : libelles.editeur_non_porte;
            message.hidden = false;
        });
        serveur.addEventListener('change', function () {
            message.hidden = true;
        });
    }
}());
