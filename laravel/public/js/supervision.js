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
