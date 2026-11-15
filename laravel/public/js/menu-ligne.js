/**
 * Menu d'actions d'une ligne de tableau.
 *
 * Cinq boutons par ligne empilaient chaque ligne sur trois rangees et
 * poussaient le tableau hors du champ. Les actions passent dans un menu ouvert
 * par un bouton (`popovertarget`) : l'API Popover place la liste au premier
 * plan — le cadre du tableau defile (`overflow: auto`) et rognerait une liste
 * en position absolue — et ferme seule au clic exterieur et a Echap.
 *
 * Ce script ne fait que trois choses : poser la liste sous son bouton, la
 * fermer apres un choix, la fermer quand la page defile (elle est en position
 * fixe et ne suivrait pas sa ligne).
 *
 * Les boutons gardent leur `data-rw` et leurs gestionnaires : un appel
 * `element.click()` les declenche menu ferme comme menu ouvert.
 */
(function () {
    'use strict';

    var MARGE = 4;

    function place(liste) {
        var bouton = document.querySelector('[popovertarget="' + liste.id + '"]');
        if (!bouton) { return; }
        var r = bouton.getBoundingClientRect();
        var largeur = liste.offsetWidth;
        var hauteur = liste.offsetHeight;
        // Aligne sur le bord droit du bouton, sans sortir de la fenetre.
        var gauche = Math.max(MARGE, Math.min(r.right - largeur, window.innerWidth - largeur - MARGE));
        // Dessous si la place y est, sinon dessus.
        var haut = r.bottom + MARGE + hauteur <= window.innerHeight
            ? r.bottom + MARGE
            : Math.max(MARGE, r.top - MARGE - hauteur);
        liste.style.left = gauche + 'px';
        liste.style.top = haut + 'px';
    }

    // `toggle` ne remonte pas : on l'ecoute en phase de capture.
    document.addEventListener('toggle', function (e) {
        var liste = e.target;
        if (!(liste instanceof HTMLElement) || !liste.classList.contains('rw-menu-ligne__liste')) { return; }
        var bouton = document.querySelector('[popovertarget="' + liste.id + '"]');
        if (bouton) { bouton.setAttribute('aria-expanded', e.newState === 'open' ? 'true' : 'false'); }
        if (e.newState === 'open') { place(liste); }
    }, true);

    // Un choix ferme le menu ; le geste lui-meme est deja parti.
    document.addEventListener('click', function (e) {
        var cible = e.target instanceof Element ? e.target.closest('.rw-menu-ligne__liste button, .rw-menu-ligne__liste a') : null;
        if (!cible) { return; }
        var liste = cible.closest('.rw-menu-ligne__liste');
        if (liste && liste.matches(':popover-open')) { liste.hidePopover(); }
    });

    function fermeTout() {
        [].slice.call(document.querySelectorAll('.rw-menu-ligne__liste:popover-open'))
            .forEach(function (l) { l.hidePopover(); });
    }
    window.addEventListener('scroll', fermeTout, true);
    window.addEventListener('resize', fermeTout);
})();
