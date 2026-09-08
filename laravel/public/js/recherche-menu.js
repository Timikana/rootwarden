/*
 * recherche-menu.js — la recherche VIVANTE de l'en-tete.
 *
 * ══ AUCUN SECOND CHEMIN ════════════════════════════════════════════════════
 *
 * Ce panneau appelle `GET /api/gateway/search`, exactement comme la page
 * `/recherche`. Il n'y a pas d'endpoint neuf : la capacite qui manquait au
 * portage etait l'ECRAN, pas le producteur. Un second endpoint aurait donne deux
 * chemins pour un seul geste, et le premier a diverger aurait ete la garde.
 *
 * ⚠ LES LIENS PASSENT PAR `RwLiens.resout`, PAS PAR UNE COPIE LOCALE. Cette
 * fonction re-enracine le chemin recu sur une base connue : c'est CE QUI empeche
 * un lien a schema relatif (`//exemple.com`) de changer d'hote. Une copie ici
 * serait une seconde regle de securite a faire diverger.
 *
 * ⚠ LES LIBELLES SONT CEUX DE LA PAGE (`lang/fr/search.php` et son jumeau
 * anglais), pas des textes jumeaux ecrits ici.
 *
 * ⚠ ET LE CHEMIN EST ECRIT EN ENTIER A DESSEIN : `lang/<etoile>/search.php`
 * contient la sequence qui FERME un commentaire de bloc. C'est ce qui a casse
 * ce fichier a sa premiere ecriture — tout ce qui suivait devenait du code, et
 * `node --check` designait une ligne trente plus bas.
 * Deux formulations pour un meme etat finissent par se contredire — et c'est
 * l'etat « aucun resultat » qui trompe le plus quand il differe d'un ecran a
 * l'autre.
 */
(function () {
    'use strict';

    var racine = document.querySelector('[data-rw="recherche-menu"]');
    if (! racine) { return; }

    var champ     = racine.querySelector('[data-rw="recherche-menu-champ"]');
    var etat      = racine.querySelector('[data-rw="recherche-menu-etat"]');
    var zone      = racine.querySelector('[data-rw="recherche-menu-resultats"]');
    var libelles  = {};
    try { libelles = JSON.parse(document.getElementById('rw-recherche-libelles').textContent); }
    catch (e) { libelles = {}; }

    var PASSERELLE = '/api/gateway';
    var MINIMUM    = 2;      // le backend rend `{results:{}, total:0}` en dessous
    var ATTENTE    = 250;    // ms
    var PAR_CAT    = 5;      // le panneau plafonne ; la page complete ne plafonne pas
    var minuterie  = null;
    var CATEGORIES = [
        { cle: 'machines', libelle: 'cat_machines' },
        { cle: 'users',    libelle: 'cat_users' },
        { cle: 'cves',     libelle: 'cat_cves' },
        { cle: 'tickets',  libelle: 'cat_tickets' },
        { cle: 'audit',    libelle: 'cat_audit' },
    ];

    function dis(texte) { if (etat) { etat.textContent = texte || ''; } }

    function vide() { if (zone) { zone.replaceChildren(); } }

    function ligne(item) {
        var cible = window.RwLiens ? window.RwLiens.resout(item.link) : null;
        var a = document.createElement('a');
        a.className = 'rw-resultat' + (cible && cible.externe ? ' rw-resultat--externe' : '');

        /*
         * Fail-closed : sans cible, AUCUN `href`. Un `href="null"` serait un lien
         * mort qui a l'air bon — le libelle reste lisible, ce qui est honnete.
         */
        if (cible && cible.url) { a.setAttribute('href', cible.url); }
        if (cible && cible.externe) {
            a.setAttribute('target', '_blank');
            a.setAttribute('rel', 'noopener noreferrer');
            a.setAttribute('title', libelles.ancien_portail || '');
        }

        var titre = document.createElement('div');
        titre.className = 'rw-resultat__titre';
        titre.textContent = item.label || '';
        a.appendChild(titre);

        if (item.sub) {
            var detail = document.createElement('div');
            detail.className = 'rw-resultat__detail';
            detail.textContent = item.sub;
            a.appendChild(detail);
        }
        if (cible && cible.externe) {
            var marqueur = document.createElement('span');
            marqueur.className = 'rw-resultat__marqueur';
            marqueur.setAttribute('aria-label', libelles.ancien_portail || '');
            marqueur.textContent = '↗';
            a.appendChild(marqueur);
        }

        return a;
    }

    function rend(resultats, total, terme) {
        vide();
        var bloc = document.createDocumentFragment();
        var rendus = 0;
        CATEGORIES.forEach(function (c) {
            var items = (resultats[c.cle] || []).slice(0, PAR_CAT);
            if (! items.length) { return; }
            var titre = document.createElement('div');
            titre.className = 'rw-sous-titre-fort';
            titre.textContent = (libelles[c.libelle] || c.cle) + ' (' + (resultats[c.cle] || []).length + ')';
            bloc.appendChild(titre);
            var liste = document.createElement('div');
            liste.className = 'rw-resultats';
            items.forEach(function (i) { liste.appendChild(ligne(i)); rendus++; });
            bloc.appendChild(liste);
        });

        if (! rendus) {
            dis(libelles.no_results || '');

            return;
        }
        zone.appendChild(bloc);
        dis(String(total || 0) + ' ' + (libelles.results_for || '') + ' "' + terme + '"');
    }

    function cherche(terme) {
        var q = String(terme || '').trim();

        /*
         * ⚠ EN DESSOUS DU SEUIL, ON N'EMET RIEN. Le backend repond
         * `{results:{}, total:0}` sous deux caracteres : apprendre la regle par une
         * reponse vide ferait partir une requete par frappe pour rien, et rendrait
         * « trop court » indiscernable de « aucun resultat ».
         */
        if (q.length < MINIMUM) {
            vide();
            dis(libelles.hint_min || '');

            return;
        }

        dis(libelles.searching || '');
        fetch(PASSERELLE + '/search?q=' + encodeURIComponent(q), {
            headers: { Accept: 'application/json' },
        }).then(function (r) { return r.json().catch(function () { return null; }); })
          .then(function (d) {
              if (! d || d.success !== true) {
                  vide();
                  dis(libelles.err || '');

                  return;
              }
              rend(d.results || {}, d.total, q);
          })
          .catch(function () {
              /*
               * ⚠ ON DIT L'ECHEC. Un `catch` qui se contente de cacher le panneau
               * transforme une capacite morte en capacite SILENCIEUSE : aucune
               * erreur, aucun resultat, rien a quoi se cogner — c'est ce silence
               * qui a fait survivre la recherche du legacy a son endpoint pendant
               * tout l'archivage.
               */
              vide();
              dis(libelles.err || '');
          });
    }

    if (champ) {
        champ.addEventListener('input', function () {
            clearTimeout(minuterie);
            minuterie = setTimeout(function () { cherche(champ.value); }, ATTENTE);
        });
    }

    // A l'ouverture du panneau : le seuil est ANNONCE, pas devine.
    racine.addEventListener('toggle', function () {
        if (racine.open) {
            if (champ) { champ.focus(); }
            if (! champ || champ.value.trim().length < MINIMUM) { dis(libelles.hint_min || ''); }
        }
    });
}());
