/*
 * liens-legacy.js — traduire un chemin de l'ANCIEN portail en cible de navigation.
 *
 * ══ POURQUOI CE FICHIER EXISTE : UNE SEULE COPIE ═══════════════════════════
 *
 * Le backend Python ne connait qu'un frontend et ecrit ses liens en dur vers
 * l'ancien portail (`/adm/audit_log.php`). Chaque partie archivee par la
 * migration transformerait un de ces liens en 404 : la table de traduction vient
 * de `App\Support\LiensLegacy`, source unique cote serveur.
 *
 * ⚠ ET C'EST AUSSI UNE REGLE DE SECURITE, d'ou l'extraction. `resout()`
 * RE-ENRACINE toujours le chemin recu sur une base connue, avec UN seul `/` :
 * un lien a schema relatif (`//exemple.com`) ne peut donc pas changer d'hote.
 * Remesure du 2026-09-08 sur le code reel, entrees hostiles, href LUS a l'ecran :
 *
 *     //evil.example.com/x        ->  <legacy>/evil.example.com/x
 *     https://evil.example.com/x  ->  <legacy>/https://evil.example.com/x
 *     javascript:alert(1)         ->  <legacy>/javascript:alert(1)
 *     ////evil.example.com/x      ->  <legacy>/evil.example.com/x
 *     TEMOIN /adm/audit_log.php   ->  <portage>/journal-audit    (DISCRIMINE)
 *
 * Aucun href ne quitte les deux origines connues, et aucun ne porte de
 * pseudo-schema. **La garde est dans la FORME, pas dans une liste de motifs** —
 * une classe de caracteres, elle, laisse passer `//exemple.com`.
 *
 * DEUX consommateurs : la page `/recherche` et le panneau de l'en-tete. Ils
 * partagent CE fichier plutot qu'une copie chacun — une regle de securite
 * dupliquee est une regle qui divergera.
 */
(function () {
    'use strict';

    /** `/tickets/index.php` et `/tickets/` designent la meme partie. */
    function normalise(chemin) {
        var c = '/' + String(chemin || '').replace(/^\/+/, '').split('?')[0].split('#')[0];
        c = c.replace(/\/index\.php$/, '/');

        return c.endsWith('/') ? c : c + '/';
    }

    /*
     * La table est cherchee dans l'en-tete D'ABORD (posee par le socle, donc
     * presente sur toutes les pages), puis sur la page de recherche. Deux
     * charges identiques valent mieux qu'une vue de plus a modifier — et la
     * seconde reste le repli si le socle change.
     */
    function table() {
        var ids = ['rw-liens-legacy', 'search-liens'];
        for (var i = 0; i < ids.length; i++) {
            var el = document.getElementById(ids[i]);
            if (! el) { continue; }
            try { return JSON.parse(el.textContent); } catch (e) { /* charge illisible */ }
        }

        return null;
    }

    /**
     * Ou envoyer quelqu'un qui suit ce lien ?
     *
     * Le chemin d'origine est conserve pour l'ancien portail : `/adm/audit_log.php`
     * n'est pas `/adm/audit_log/`.
     *
     * ⚠ FAIL-CLOSED : sans table, on ne fabrique PAS d'URL. Rendre `null` laisse
     * l'appelant afficher un libelle sans lien, ce qui est honnete ; inventer une
     * base ferait un lien mort qui a l'air bon.
     */
    function resout(chemin, tableFournie) {
        var t = tableFournie || table();
        if (! t || ! t.remplacements) { return null; }

        var interne = t.remplacements[normalise(chemin)];
        if (interne) { return { url: interne, externe: false }; }

        var origine = '/' + String(chemin || '').replace(/^\/+/, '');

        return { url: String(t.base_legacy || '') + origine, externe: true };
    }

    window.RwLiens = { normalise: normalise, resout: resout, table: table };
}());
