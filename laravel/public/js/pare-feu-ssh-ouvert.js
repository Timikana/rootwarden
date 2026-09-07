/*
 * LA PROPRIETE Q2 — « ce jeu de regles laisse-t-il le port SSH ouvert ? »
 *
 * ══ POURQUOI CE FICHIER EXISTE SEUL, ET AVANT TOUT GESTE ═════════════════
 *
 * `iptables-restore` REMPLACE ATOMIQUEMENT toutes les tables. Un jeu portant
 * `INPUT DROP` sans `ACCEPT` sur le port SSH ferme la session en cours **et
 * toutes les suivantes**. Le seul canal de RootWarden vers une machine est SSH,
 * et `/iptables-rollback` passe AUSSI par SSH : la reprise exige une console
 * physique.
 *
 * Q2 est la propriete qui refuse un tel jeu AVANT l'envoi. Elle est ecrite ici
 * AVANT que le geste d'application n'existe, deliberement : **une garde sans
 * geste est inerte ; un geste sans garde ne l'est pas.**
 *
 * ══ LE PIEGE QUI DECIDE DE TOUT : L'ORDRE ════════════════════════════════
 *
 * `iptables` evalue les regles DANS L'ORDRE, et la premiere qui matche decide.
 * Donc chercher « le texte contient-il un ACCEPT sur le port ? » est FAUX :
 *
 *     -A INPUT -j DROP
 *     -A INPUT -p tcp --dport 22 -j ACCEPT      <- JAMAIS ATTEINTE
 *
 * Ce jeu contient un `ACCEPT` sur 22 et coupe l'acces. Un predicat par simple
 * recherche de motif l'aurait declare sur. **C'est le cas que cette fonction
 * existe pour attraper, et c'est le seul qui coute une console physique.**
 *
 * ══ FAIL-CLOSED, ET LE COUT EST ASYMETRIQUE ══════════════════════════════
 *
 * Rend `null` — « je ne sais pas » — plutot que `true` des que la lecture est
 * incertaine : texte vide, port invalide, aucune politique lisible. L'appelant
 * doit traiter `null` comme un REFUS.
 *
 *     refuser un jeu sain      un clic de plus
 *     accepter un jeu qui coupe  un deplacement physique jusqu'a la machine
 *
 * ══ CE QU'ELLE NE FAIT PAS ═══════════════════════════════════════════════
 *
 * ⛔ Elle n'emet RIEN. Aucune requete, aucun reseau, aucun effet. Elle lit un
 *    texte et rend un verdict.
 * ⛔ Elle ne remplace pas `iptables-restore --test` (I4), qui juge la SYNTAXE.
 *    Un jeu peut etre syntaxiquement valide et couper l'acces : ce sont deux
 *    questions, et I4 ne pose pas celle-ci.
 * ⛔ **C'est un garde d'INTERFACE.** Une requete forgee vers la passerelle ne le
 *    rencontre pas, et le backend n'inspecte pas les regles. « Q2 vert » veut
 *    dire « le geste est rendu difficile depuis l'ecran », jamais « le geste
 *    irreversible est impossible ».
 *
 * SOURCE UNIQUE : la page ET l'epreuve (`laravel/tests/Outils/q2-ssh-ouvert.mjs`)
 * lisent CE fichier. Une seconde copie divergerait, et divergerait en silence.
 */
(function (racine) {
    'use strict';

    /** Le jeton `--dport` couvre-t-il ce port ? Gere `N` et la plage `A:B`. */
    function couvre(jeton, port) {
        var i = jeton.indexOf(':');
        if (i === -1) { return Number(jeton) === port; }
        var bas = Number(jeton.slice(0, i) || 0);
        var haut = Number(jeton.slice(i + 1) || 65535);

        return port >= bas && port <= haut;
    }

    /** Les cibles integrees. Tout autre nom est une chaine personnalisee. */
    var REGLEMENTAIRES = {
        ACCEPT: 1, DROP: 1, REJECT: 1, LOG: 1, RETURN: 1,
        MARK: 1, DNAT: 1, SNAT: 1, MASQUERADE: 1, REDIRECT: 1, TCPMSS: 1
    };

    /**
     * La regle porte-t-elle une contrainte de port, et couvre-t-elle le notre ?
     * @return {boolean|null}  true = couvre · false = exclut · null = AUCUNE
     *                         contrainte de port (elle matche tous les ports)
     */
    function couvreLePort(l, port) {
        if (/!\s*--dports?\s/.test(l)) { return false; }

        var un = l.match(/(?:^|\s)--dport\s+(\S+)/);
        if (un) { return couvre(un[1], port); }

        var plusieurs = l.match(/(?:^|\s)--dports\s+(\S+)/);
        if (plusieurs) {
            return plusieurs[1].split(',').some(function (p) {
                return couvre(p, port);
            });
        }

        return null;
    }

    /**
     * Cet `ACCEPT` ouvre-t-il le port a une connexion NEUVE ?
     *
     * @return {boolean|null}  true  = il l'ouvre, prouve
     *                         false = il ne l'ouvre PAS, prouve
     *                         null  = INDECIDABLE d'ici
     *
     * ══ POURQUOI TROIS VALEURS ET NON DEUX ═══════════════════════════════
     *
     * « ne prouve pas qu'il ouvre » recouvre deux choses tres differentes :
     *
     *     -p udp --dport 22        il n'ouvre pas SSH/TCP, et on le SAIT
     *     --state ESTABLISHED      il n'admet pas de connexion NEUVE, on le SAIT
     *     -i eth0 / -s 10.0.0.5    il ouvre peut-etre — pour NOTRE chemin
     *                              d'acces, on ne peut pas le dire
     *
     * Les confondre faisait dire a l'ecran « ces regles ferment le port SSH »
     * sur un jeu qui le laisse ouvert. **C'est une accusation FAUSSE, et un
     * garde qui accuse a tort s'use plus vite qu'un garde absent** : l'operateur
     * qui SAIT que son jeu est bon apprend que le garde se trompe, donc a passer
     * outre. (Ecart releve en revue, 2026-09-07.)
     */
    function ouvreLePort(l, portCouvert) {
        if (portCouvert !== true) { return false; }

        var proto = l.match(/(?:^|\s)-p\s+(\S+)/);
        if (proto && proto[1].toLowerCase() !== 'tcp') { return false; }

        var etats = l.match(/--(?:c)?state\s+(\S+)/);
        if (etats && ! /\bNEW\b/i.test(etats[1])) { return false; }

        // INDECIDABLE : l'ouverture est peut-etre reelle, mais rien ici ne dit
        // si elle vaut pour le chemin par lequel RootWarden joint la machine.
        if (/(?:^|\s)!?\s*-i\s+\S+/.test(l)) { return null; }
        if (/(?:^|\s)!?\s*-s\s+\S+/.test(l)) { return null; }

        return true;
    }

    /**
     * @param  {string} texte  un jeu de regles au format `iptables-save`
     * @param  {number} port   le port SSH DE CETTE MACHINE, lu en base
     * @return {boolean|null}  true = ouvert · false = coupe · null = indecidable
     */
    function laisseLeSshOuvert(texte, port) {
        if (!port || !Number.isInteger(port) || port < 1 || port > 65535) {
            return null;
        }

        var lignes = String(texte || '').split('\n');

        /*
         * ⛔ PRE-BALAYAGE : `-I` INSERE EN TETE.
         *
         * L'ordre du FICHIER n'est alors plus l'ordre d'EVALUATION, et tout le
         * fichier devient illisible pour nous — pas seulement ce qui suit.
         *
         * ⚠ CE CONTROLE ETAIT D'ABORD DANS LA BOUCLE, ET IL N'A RIEN GARDE :
         * un `-A … --dport 22 -j ACCEPT` place AVANT le `-I` decidait `true` et
         * rendait la main avant que le `-I` ne soit lu. **Une garde placee sur
         * le chemin d'un `return` anterieur n'est pas une garde** — c'est la
         * meme faute que celle qu'elle devait attraper, d'un cran plus haut.
         */
        for (var k = 0; k < lignes.length; k++) {
            if (/^\s*-I\s+INPUT\b/.test(lignes[k])) { return null; }
        }

        var politique = null;
        var vuUneRegle = false;
        var indecidable = false;

        for (var i = 0; i < lignes.length; i++) {
            var l = lignes[i].trim();
            if (l === '' || l.charAt(0) === '#') { continue; }

            var pol = l.match(/^:INPUT\s+(\w+)/);
            if (pol) { politique = pol[1].toUpperCase(); continue; }

            if (! /^-A\s+INPUT\b/.test(l)) { continue; }
            vuUneRegle = true;

            var cible = l.match(/-j\s+(\w+)/);
            cible = cible ? cible[1].toUpperCase() : '';

            /*
             * Un saut vers une CHAINE PERSONNALISEE : le sort du paquet se joue
             * ailleurs, et on ne sait pas le suivre. On ne tranche pas.
             */
            if (cible !== '' && ! REGLEMENTAIRES[cible]) { return null; }

            // Une cible non terminale (LOG, MARK…) ne decide pas du sort du
            // paquet : la regle suivante continue de s'appliquer.
            if (cible !== 'ACCEPT' && cible !== 'DROP' && cible !== 'REJECT') {
                continue;
            }

            var portCouvert = couvreLePort(l, port);

            /*
             * ══ L'ASYMETRIE, ET C'EST LE CŒUR DE CE FICHIER ══════════════════
             *
             * Le repli « aucune contrainte de port => la regle matche tout »
             * est CONSERVATEUR pour un DROP et PERMISSIF pour un ACCEPT. Les
             * traiter pareil est un fail-OPEN, sur le seul chemin du produit
             * dont l'erreur coute un deplacement physique.
             *
             * Revue du 2026-09-07 : cinq jeux forges passaient pour OUVERTS,
             * dont les DEUX PREMIERES LIGNES de presque tout pare-feu durci —
             *
             *     -A INPUT -i lo -j ACCEPT
             *     -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
             *
             * La seconde est la pire : elle laisse vivre la session EN COURS et
             * tue toutes les suivantes. L'operateur lit « applique, tout va
             * bien » et le decouvre au prochain acces.
             */
            if (cible === 'ACCEPT') {
                var ouvre = ouvreLePort(l, portCouvert);
                // SEULE UNE PREUVE D'OUVERTURE OUVRE.
                if (ouvre === true) { return true; }
                // Une ouverture INDECIDABLE ne decide pas non plus — mais elle
                // interdit de conclure « ces regles ferment » plus bas.
                if (ouvre === null) { indecidable = true; }
                continue;
            }

            // DROP / REJECT : conservateur. Sans contrainte de port, la regle
            // attrape tout, donc aussi le notre.
            if (portCouvert !== false) { return false; }
        }

        /*
         * ⚠ L'AVEU PLUTOT QUE L'ACCUSATION. Si un `ACCEPT` couvrait le port sans
         * qu'on puisse trancher, on n'a pas le droit de dire « ces regles
         * ferment » : on dit « je ne sais pas ». Les deux se traitent en REFUS
         * cote appelant — c'est le MESSAGE qui differe, pas la decision.
         */
        if (politique === 'ACCEPT') { return true; }
        if (indecidable) { return null; }
        if (politique === 'DROP' || politique === 'REJECT') { return false; }

        return vuUneRegle ? false : null;
    }

    racine.rwLaisseLeSshOuvert = laisseLeSshOuvert;
}(typeof globalThis !== 'undefined' ? globalThis : this));
