/**
 * bashrc.js - Deploiement du `.bashrc` standardise, sous-lot B1.
 *
 * B1 ne porte que la page : la bascule des trois onglets, et le compteur de
 * selection. Les gestes qui joignent une machine sont B2 et B4 — ce fichier
 * n'emet AUCUNE requete.
 *
 * DEUX CORRECTIONS DE PRESENTATION, toutes deux vues a l'image du legacy.
 *
 * 1. **Le compteur s'ENONCE.** Le legacy affiche « Serveurs cibles 0 ». Un `0`
 *    se lit comme une donnee, pas comme un etat. Et quand la selection contient
 *    une machine de production, le compteur le DIT — decider d'un geste sans
 *    savoir qu'il porte sur la production n'a pas de sens.
 *
 * 2. **Les onglets basculent par un clic reel**, avec `aria-selected` tenu a
 *    jour : la suite B1 clique le bouton et lit l'attribut, elle n'appelle
 *    aucune fonction de la page.
 */
(function () {
    'use strict';

    /* ═══ LES ONGLETS ═════════════════════════════════════════════════════ */

    var onglets = [].slice.call(document.querySelectorAll('[data-panneau]'));
    if (onglets.length) {
        onglets.forEach(function (bouton) {
            bouton.addEventListener('click', function () {
                onglets.forEach(function (b) {
                    var actif = (b === bouton);
                    b.classList.toggle('rw-onglet--actif', actif);
                    b.setAttribute('aria-selected', actif ? 'true' : 'false');
                    var panneau = document.querySelector(
                        '[data-rw="bashrc-panneau-' + b.dataset.panneau + '"]');
                    if (panneau) { panneau.hidden = ! actif; }
                });
            });
        });
    }

    /* ═══ LE COMPTEUR, QUI S'ENONCE ═══════════════════════════════════════ */

    var compteur = document.querySelector('[data-rw="bashrc-compteur"]');
    var cases = [].slice.call(document.querySelectorAll('[data-rw^="bashrc-cible-"]'));
    if (! compteur || ! cases.length) { return; }

    // Les phrases viennent du gabarit, jamais du JS : une chaine ecrite ici
    // echapperait aux deux catalogues et n'aurait pas de version anglaise.
    var textes = {};
    try {
        var bloc = document.getElementById('bashrc-textes');
        if (bloc) { textes = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { textes = {}; }

    function annonce() {
        var choisies = cases.filter(function (c) { return c.checked; });
        var prod = choisies.filter(function (c) { return c.dataset.sensible === '1'; }).length;

        if (choisies.length === 0) {
            compteur.textContent = textes.aucune || '';
        } else if (prod > 0) {
            compteur.textContent = (textes.avec_prod || '')
                .replace(':nb', String(choisies.length)).replace(':prod', String(prod));
        } else if (choisies.length === 1) {
            compteur.textContent = textes.une || '';
        } else {
            compteur.textContent = (textes.plusieurs || '').replace(':nb', String(choisies.length));
        }
        // La ligne porte l'etat de danger de la SELECTION, pas du parc : une
        // machine de production presente mais non cochee n'a pas a alarmer.
        compteur.classList.toggle('rw-erreur', prod > 0);
    }

    cases.forEach(function (c) { c.addEventListener('change', annonce); });
    annonce();
}());
