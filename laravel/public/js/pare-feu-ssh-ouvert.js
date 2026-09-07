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
        var politique = null;
        var vuUneRegle = false;

        for (var i = 0; i < lignes.length; i++) {
            var l = lignes[i].trim();
            if (l === '' || l.charAt(0) === '#') { continue; }

            var pol = l.match(/^:INPUT\s+(\w+)/);
            if (pol) { politique = pol[1].toUpperCase(); continue; }

            if (! /^-[AI]\s+INPUT\b/.test(l)) { continue; }
            vuUneRegle = true;

            var cible = l.match(/-j\s+(\w+)/);
            cible = cible ? cible[1].toUpperCase() : '';
            // Une cible non terminale (LOG, MARK…) ne decide pas du sort du
            // paquet : la regle suivante continue de s'appliquer.
            if (cible !== 'ACCEPT' && cible !== 'DROP' && cible !== 'REJECT') {
                continue;
            }

            var dport = l.match(/(?:^|\s)--dport\s+(\S+)/);
            var dports = l.match(/(?:^|\s)--dports\s+(\S+)/);
            var concerne;

            if (/!\s*--dports?\s/.test(l)) {
                // `! --dport 22` matche tout SAUF 22 : la regle ne decide pas
                // du sort de notre port.
                concerne = false;
            } else if (dport) {
                concerne = couvre(dport[1], port);
            } else if (dports) {
                concerne = dports[1].split(',').some(function (p) {
                    return couvre(p, port);
                });
            } else {
                // AUCUNE contrainte de port : la regle matche tout, donc aussi
                // le notre. C'est le cas du `-A INPUT -j DROP` place trop haut.
                concerne = true;
            }

            if (! concerne) { continue; }

            return cible === 'ACCEPT';   // LA PREMIERE QUI PEUT S'APPLIQUER DECIDE
        }

        if (politique === 'DROP' || politique === 'REJECT') { return false; }
        if (politique === 'ACCEPT') { return true; }

        // Des regles INPUT mais aucune politique lisible : on ne tranche pas.
        return vuUneRegle ? false : null;
    }

    racine.rwLaisseLeSshOuvert = laisseLeSshOuvert;
}(typeof globalThis !== 'undefined' ? globalThis : this));
