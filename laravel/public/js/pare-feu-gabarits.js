/*
 * LES GABARITS DE RÈGLES — Q1 : LE PORT SSH VIENT DE LA MACHINE, JAMAIS DE `22`
 *
 * ══ CE QUE CE FICHIER CORRIGE ════════════════════════════════════════════
 *
 * Les cinq gabarits du legacy (`legacy/iptables/js/main.js:358-425`) codent
 * `--dport 22` EN DUR. Le gabarit `deny_all` porte même ce commentaire :
 *
 *     # ATTENTION: seul SSH est ouvert pour ne pas perdre l'acces
 *     -A INPUT -p tcp --dport 22 -j ACCEPT
 *
 * **L'intention est écrite ; l'implémentation suppose 22.** Sur une machine dont
 * `sshd` écoute ailleurs, appliquer ce gabarit ferme l'accès — y compris celui de
 * RootWarden, dont le seul canal est SSH, et `/iptables-rollback` passe AUSSI par
 * SSH : la reprise exige une console physique.
 *
 * Le port de chaque machine est en base et déjà transmis à la page
 * (`Iptables.php:107`, `pare-feu.js:200`). **Il n'a jamais manqué : il n'était
 * pas employé.**
 *
 * ══ POURQUOI CE DÉFAUT EST INVISIBLE ═════════════════════════════════════
 *
 * Les trois machines du parc écoutent aujourd'hui sur 22. **Le gabarit est donc
 * correct par coïncidence**, et le restera jusqu'à la première machine qui ne
 * l'est pas — c'est-à-dire jusqu'au durcissement qu'on recommande par ailleurs.
 *
 * > **Un défaut armé par la bonne pratique qu'on prescrit ne se manifeste que
 * > chez celui qui l'a suivie.**
 *
 * ══ LA PROPRIÉTÉ QUI LES GOUVERNE, ET ELLE EST MESURÉE ═══════════════════
 *
 * **Chaque gabarit, rendu pour un port donné, DOIT satisfaire Q2** —
 * `rwLaisseLeSshOuvert(texte, port) === true`. La vérification est jouée sur les
 * cinq gabarits × sept ports par `laravel/tests/Outils/q1-gabarits.mjs`.
 *
 * *C'est le point : le gabarit n'est pas « relu et jugé correct », il est PASSÉ
 * AU GARDE que l'application lui opposera.* **Un gabarit que Q2 refuse est un
 * gabarit qu'on ne doit pas proposer.**
 *
 * ⛔ CE FICHIER N'APPLIQUE RIEN. Il rend du TEXTE. Aucune requête, aucun réseau,
 *    aucune machine jointe. Le geste d'application n'existe pas encore.
 */
(function (racine) {
    'use strict';

    /*
     * Le corps commun. `:FORWARD` varie — `docker` doit router entre conteneurs,
     * les autres non — donc il est passé, pas déduit.
     */
    function entete(forward) {
        return [
            '*filter',
            ':INPUT DROP [0:0]',
            ':FORWARD ' + forward + ' [0:0]',
            ':OUTPUT ACCEPT [0:0]',
            '# Loopback',
            '-A INPUT -i lo -j ACCEPT',
            '# Connexions etablies',
            '-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT',
        ];
    }

    /*
     * ⚠ LA LIGNE SSH EST LA SEULE QUI PORTE UN PORT VARIABLE, ET C'EST VOULU.
     *
     * Les autres services gardent leurs ports canoniques : 80 est HTTP partout,
     * 3306 est MySQL partout. Le port SSH, lui, est une PROPRIETE DE LA MACHINE —
     * c'est la seule valeur que le gabarit ne peut pas connaitre d'avance.
     */
    function ligneSsh(port) {
        return [
            '# SSH — port de CETTE machine, lu en base (Q1)',
            '-A INPUT -p tcp --dport ' + port + ' -j ACCEPT',
        ];
    }

    var PING = '-A INPUT -p icmp --icmp-type echo-request -j ACCEPT';

    var FABRIQUES = {
        web: function (port) {
            return entete('DROP')
                .concat(ligneSsh(port))
                .concat([
                    '# HTTP + HTTPS',
                    '-A INPUT -p tcp --dport 80 -j ACCEPT',
                    '-A INPUT -p tcp --dport 443 -j ACCEPT',
                    '# ICMP ping',
                    PING,
                ]);
        },

        db: function (port) {
            return entete('DROP')
                .concat(ligneSsh(port))
                .concat([
                    '# MySQL (reseau interne uniquement)',
                    '-A INPUT -p tcp --dport 3306 -s 10.0.0.0/8 -j ACCEPT',
                    '-A INPUT -p tcp --dport 3306 -s 172.16.0.0/12 -j ACCEPT',
                    '-A INPUT -p tcp --dport 3306 -s 192.168.0.0/16 -j ACCEPT',
                    '# PostgreSQL',
                    '-A INPUT -p tcp --dport 5432 -s 10.0.0.0/8 -j ACCEPT',
                    PING,
                ]);
        },

        ssh_seul: function (port) {
            return entete('DROP')
                .concat(ligneSsh(port))
                .concat([PING]);
        },

        /*
         * ⚠ LE GABARIT DONT L'INTENTION ETAIT ECRITE ET NON TENUE.
         *
         * Le legacy porte « seul SSH est ouvert pour ne pas perdre l'acces » —
         * au-dessus d'un `--dport 22` en dur. **Ici l'intention EST
         * l'implementation**, et c'est le gabarit ou l'ecart coutait le plus :
         * c'est celui qu'on choisit quand on veut tout fermer.
         */
        tout_fermer: function (port) {
            return entete('DROP').concat(ligneSsh(port));
        },

        docker: function (port) {
            // `:FORWARD ACCEPT` : Docker route entre conteneurs par cette chaine.
            // Le mettre a DROP couperait le reseau des conteneurs, pas l'acces.
            return entete('ACCEPT')
                .concat(ligneSsh(port))
                .concat([
                    '# HTTP + HTTPS (reverse proxy)',
                    '-A INPUT -p tcp --dport 80 -j ACCEPT',
                    '-A INPUT -p tcp --dport 443 -j ACCEPT',
                    '# Docker bridge',
                    '-A INPUT -i docker0 -j ACCEPT',
                    PING,
                ]);
        },
    };

    /**
     * @param  {string} nom   une cle de `FABRIQUES`
     * @param  {number} port  le port SSH DE CETTE MACHINE, lu en base
     * @return {string|null}  le jeu de regles, ou `null` si l'un des deux
     *                        arguments ne permet pas de le fabriquer
     *
     * ⚠ REND `null` PLUTOT QU'UN GABARIT PAR DEFAUT. Un port absent ou invalide
     * ferait retomber sur 22 — c'est-a-dire reproduire exactement le defaut que
     * ce fichier existe pour fermer, et le reproduire EN SILENCE.
     */
    function gabarit(nom, port) {
        if (! Object.prototype.hasOwnProperty.call(FABRIQUES, nom)) { return null; }
        if (! port || ! Number.isInteger(port) || port < 1 || port > 65535) { return null; }

        return FABRIQUES[nom](port).concat(['COMMIT']).join('\n');
    }

    /** Les noms disponibles, DERIVES de la table — jamais une seconde liste. */
    function noms() {
        return Object.keys(FABRIQUES);
    }

    racine.rwGabaritPareFeu = gabarit;
    racine.rwGabaritsPareFeu = noms;
}(typeof globalThis !== 'undefined' ? globalThis : this));
