/**
 * services.js - Gestion des services systemd, sous-lot S1.
 *
 * S1 ne porte que la PAGE : le choix d'une machine, l'etat des filtres, et
 * l'avertissement quand la machine choisie est en production. **Ce fichier
 * n'emet aucune requete** — les lectures sont S2, les ecritures S3.
 *
 * DEUX CORRECTIONS DE PRESENTATION, toutes deux mesurees par S1 sur le legacy.
 *
 * 1. **Les filtres sont montres des le depart, desactives, avec la raison.** Le
 *    legacy les garde dans le DOM mais masques jusqu'au chargement d'un serveur
 *    (`etat=false categorie=false recherche=false` au chargement). Un filtre qui
 *    apparait sans prevenir se cherche.
 * 2. **Aucun cadre vide avant le premier geste.** Le legacy affiche un panneau
 *    de journaux noir et vide des l'ouverture ; ici un texte dit qu'il n'y a
 *    rien, et le cadre ne parait qu'avec du contenu.
 */
(function () {
    'use strict';

    var textes = {};
    try {
        var bloc = document.getElementById('services-textes');
        if (bloc) { textes = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { textes = {}; }

    var choix = document.querySelector('[data-rw="services-serveur"]');
    var charger = document.querySelector('[data-rw="services-charger"]');
    var etat = document.querySelector('[data-rw="services-etat"]');
    if (! choix || ! charger || ! etat) { return; }

    /** L'option retenue, ou `null` si c'est encore l'invite. */
    function machineChoisie() {
        var o = choix.options[choix.selectedIndex];

        return (o && o.value) ? o : null;
    }

    function majEtat() {
        var o = machineChoisie();
        charger.disabled = (o === null);

        if (o === null) {
            etat.textContent = textes.choisir_serveur || '';
            etat.classList.remove('rw-erreur');

            return;
        }
        // LA PRODUCTION SE DIT AU MOMENT DU CHOIX, pas au moment du geste.
        // Charger les services ne modifie rien — mais les gestes suivants, si,
        // et c'est maintenant qu'on decide sur quelle machine on travaillera.
        var sensible = (o.dataset.sensible === '1');
        etat.textContent = sensible ? (textes.sensible_confirmer || '') : '';
        etat.classList.toggle('rw-erreur', sensible);
    }

    choix.addEventListener('change', majEtat);
    majEtat();

    // Le bouton de chargement appartient a S2 : ici il ne fait rien, et **il ne
    // pretend pas le contraire** — il reste desactive tant qu'aucune machine
    // n'est choisie, puis annonce que le geste n'est pas encore porte.
    charger.addEventListener('click', function () {
        etat.textContent = textes.chargement || '';
        etat.classList.remove('rw-erreur');
    });
}());
