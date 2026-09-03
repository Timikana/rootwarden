/**
 * recherche.js - Recherche globale, rendue par categories.
 *
 * Rendu par `textContent` et `createElement`. Les liens sont poses par
 * `setAttribute` apres resolution : rien a echapper a la main.
 *
 * LA DIFFERENCE QUI COMPTE AVEC LE LEGACY : LES LIENS SONT TRADUITS.
 *
 * Le backend Python ne connait qu'un frontend et ecrit ses liens en dur vers
 * l'ancien portail — `/tickets/index.php`, `/adm/audit_log.php`. Chaque partie
 * archivee par la migration transforme un de ces liens en 404 : mesure, un
 * resultat « ticket » menait deja a une page disparue. La table de traduction
 * vient de `App\Support\LiensLegacy`, source unique, tenue a jour a chaque
 * archivage.
 *
 * Une partie encore servie par l'ancien portail garde son lien, mais le DIT :
 * meme fleche que dans le menu, et ouverture dans un nouvel onglet. Changer de
 * portail sans le dire trahit la personne qui clique.
 *
 * Chargements SEQUENCES : chaque appel porte un numero, seul le dernier ecrit.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const DEBOUNCE_MS = 300;

    const champ = document.getElementById('search-input');
    const etat = document.getElementById('search-meta');
    const zone = document.getElementById('search-results');
    const libelles = JSON.parse(document.getElementById('search-libelles').textContent);
    const table = JSON.parse(document.getElementById('search-liens').textContent);

    let dernierChargement = 0;
    let minuterie = null;

    const CATEGORIES = [
        { cle: 'machines', libelle: 'cat_machines' },
        { cle: 'users',    libelle: 'cat_users' },
        { cle: 'cves',     libelle: 'cat_cves' },
        { cle: 'tickets',  libelle: 'cat_tickets' },
        { cle: 'audit',    libelle: 'cat_audit' },
    ];

    async function appelle(chemin) {
        const r = await fetch(PASSERELLE + chemin, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin',
        });
        let corps = null;
        try { corps = await r.json(); } catch (e) { /* reponse non JSON */ }
        return { ok: r.ok, statut: r.status, corps };
    }

    function dit(texte, ton) {
        etat.textContent = texte || '';
        etat.className = 'rw-annonce' + (ton ? ' rw-annonce--' + ton : '');
    }

    /** `/tickets/index.php` et `/tickets/` designent la meme partie. */
    function normalise(chemin) {
        let c = '/' + String(chemin || '').replace(/^\/+/, '').split('?')[0].split('#')[0];
        c = c.replace(/\/index\.php$/, '/');
        return c.endsWith('/') ? c : c + '/';
    }

    /**
     * Ou envoyer quelqu'un qui suit ce lien ?
     *
     * Le chemin d'origine est conserve pour l'ancien portail : `/adm/audit_log.php`
     * n'est pas `/adm/audit_log/`.
     */
    function resout(chemin) {
        const interne = table.remplacements[normalise(chemin)];
        if (interne) return { url: interne, externe: false };

        const origine = '/' + String(chemin || '').replace(/^\/+/, '');
        return { url: table.base_legacy + origine, externe: true };
    }

    function vide(titre, aide) {
        zone.replaceChildren();
        const bloc = document.createElement('div');
        bloc.className = 'rw-vide';
        const t = document.createElement('div');
        t.className = 'rw-vide__titre';
        t.textContent = titre;
        bloc.appendChild(t);
        if (aide) {
            const p = document.createElement('p');
            p.className = 'rw-vide__texte';
            p.textContent = aide;
            bloc.appendChild(p);
        }
        zone.appendChild(bloc);
    }

    function carte(categorie, elements) {
        const div = document.createElement('div');
        div.className = 'rw-tuile';

        const titre = document.createElement('div');
        titre.className = 'rw-tuile__titre';
        titre.textContent = `${libelles[categorie.libelle]} (${elements.length})`;
        div.appendChild(titre);

        const liste = document.createElement('div');
        liste.className = 'rw-resultats';

        for (const item of elements) {
            const cible = resout(item.link);

            const a = document.createElement('a');
            a.className = 'rw-resultat' + (cible.externe ? ' rw-resultat--externe' : '');
            a.setAttribute('href', cible.url);
            if (cible.externe) {
                a.setAttribute('target', '_blank');
                a.setAttribute('rel', 'noopener noreferrer');
                a.setAttribute('title', libelles.ancien_portail);
            }

            const principal = document.createElement('div');
            principal.className = 'rw-resultat__titre';
            principal.textContent = item.label || '';
            a.appendChild(principal);

            if (item.sub) {
                const secondaire = document.createElement('div');
                secondaire.className = 'rw-resultat__detail';
                secondaire.textContent = item.sub;
                a.appendChild(secondaire);
            }

            if (cible.externe) {
                const marqueur = document.createElement('span');
                marqueur.className = 'rw-resultat__marqueur';
                marqueur.setAttribute('aria-label', libelles.ancien_portail);
                marqueur.textContent = '↗';
                a.appendChild(marqueur);
            }

            liste.appendChild(a);
        }

        div.appendChild(liste);
        return div;
    }

    async function cherche(terme) {
        const q = (terme || '').trim();

        if (q.length < 2) {
            zone.replaceChildren();
            dit(libelles.hint_min);
            return;
        }

        const numero = ++dernierChargement;
        dit(libelles.searching);

        const res = await appelle('/search?q=' + encodeURIComponent(q));

        // Une reponse depassee n'ecrit pas : la frappe a continue.
        if (numero !== dernierChargement) return;

        if (!res.ok || !res.corps || !res.corps.success) {
            zone.replaceChildren();
            dit(libelles.err, 'echec');
            return;
        }

        const resultats = res.corps.results || {};
        const cartes = CATEGORIES
            .filter(c => (resultats[c.cle] || []).length)
            .map(c => carte(c, resultats[c.cle]));

        if (cartes.length) {
            zone.replaceChildren(...cartes);
        } else {
            vide(libelles.no_results, libelles.no_results_aide);
        }

        dit(`${res.corps.total || 0} ${libelles.results_for} "${q}"`);
    }

    champ.addEventListener('input', () => {
        clearTimeout(minuterie);
        minuterie = setTimeout(() => cherche(champ.value), DEBOUNCE_MS);
    });

    if (champ.value.trim().length >= 2) cherche(champ.value);
    else dit(libelles.hint_min);
})();
