/*
 * Les comptes distants — module `adm/`, sous-lot D8.
 *
 * QUATRE GESTES JOIGNENT LA MACHINE, ET AUCUN NE PART SEUL. Le scan est
 * declenche par un clic, jamais au chargement. Les trois autres MODIFIENT la
 * machine distante et passent par un panneau qui nomme la consequence avant de
 * partir — dont `/delete_remote_user`, qui fait un `userdel` IRREVERSIBLE.
 *
 * Le legacy pose ces trois gestes en boutons minuscules au bout de chaque
 * ligne du tableau : trois gestes distants, dont un sans retour, a la portee
 * d'un clic mal vise. Ici il faut designer le compte, puis confirmer.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var libelles = {};
    try {
        var bloc = document.getElementById('distants-libelles');
        if (bloc) { libelles = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { libelles = {}; }

    function dit(selecteur, texte) {
        var e = document.querySelector(selecteur);
        if (e) { e.textContent = texte || ''; }
    }

    /**
     * Appelle la passerelle et rend un verdict FAIL-CLOSED.
     *
     * Sans `success === true`, on annonce un echec — jamais une reussite par
     * defaut. Un `undefined` affiche comme « fait » serait un mensonge, et
     * c'est ici un mensonge sur une machine qu'on vient de modifier.
     */
    function appelle(chemin, corps) {
        return fetch(PASSERELLE + chemin, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(corps),
        }).then(function (r) {
            return r.json().catch(function () { return null; });
        }).then(function (d) {
            return d && d.success === true;
        }).catch(function () {
            return false;
        });
    }

    /**
     * Comme `appelle()`, mais rend le CORPS et non un verdict.
     *
     * `appelle()` reste le fail-closed des trois gestes destructeurs : eux n'ont
     * besoin que de « c'est parti ou non ». Le scan, lui, a besoin de ce que le
     * serveur DIT — et depuis E-187 le serveur dit beaucoup plus qu'un booleen.
     */
    function lit(chemin, corps) {
        return fetch(PASSERELLE + chemin, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(corps),
        }).then(function (r) {
            return r.json().catch(function () { return null; });
        }).catch(function () { return null; });
    }

    /*
     * ══ E-187 : TROIS ISSUES, ET LE VERDICT NE SE JETTE PLUS ══════════════
     *
     * `POST /scan_server_users` rendait toujours `success: true`. Il rend
     * desormais `false` avec `lectures` — un drapeau PAR SOURCE — quand une
     * lecture a manque, et il n'ecrase plus l'inventaire dans ce cas.
     *
     * L'ecran testait bien `success` : il n'a jamais annonce un faux succes. Ce
     * qu'il faisait, c'est jeter le CORPS — donc `lectures`, donc la seule
     * information qui distingue « je n'ai pas lu les comptes » de « j'ai lu les
     * comptes mais pas les cles ». Les deux ne se corrigent pas pareil, et
     * « Le scan n'a pas abouti » etait trop absolu pour le second : les comptes
     * affiches sont frais, seuls les compteurs de cles sont perimes.
     *
     * LES SOURCES SONT NOMMEES EN MOTS, PAS EN CHAMPS. Le `message` du backend
     * enumere `cles_root, cles_utilisateur` — des identifiants. Les afficher tels
     * quels serait la meme faute qu'une cle i18n rendue a l'ecran : on traduit
     * les drapeaux ici, et la parite FR/EN les couvre.
     */
    function sourcesManquantes(lectures) {
        var noms = {
            comptes: libelles.scan_source_comptes,
            cles_root: libelles.scan_source_cles_root,
            cles_utilisateur: libelles.scan_source_cles_utilisateur,
        };

        return Object.keys(noms)
            .filter(function (c) { return lectures[c] === false; })
            .map(function (c) { return noms[c] || c; });
    }

    /*
     * ══ E-199 : UNE LIGNE QU'AUCUN GESTE NE PEUT VISER LE DIT ═════════════
     *
     * Le scan insere une ligne dont le nom est illisible plutot que de la
     * refuser — un compte nomme `..` dans un `/etc/passwd` est un INDICE de
     * manipulation, et le faire disparaitre de l'ecran serait perdre le signal.
     * Il la MARQUE : `nom_valide` et `motif_invalide`, tous deux TOUJOURS
     * renseignes, plus un `invalides_count` rendu meme a zero.
     *
     * ══ POURQUOI CET ENCART N'APPARAIT QU'APRES UN SCAN ══════════════════
     *
     * Le drapeau est calcule par la ROUTE, sur des lignes lues en base — ce
     * n'est pas une colonne. Cette page, elle, rend son inventaire depuis la
     * base au chargement : elle ne voit donc le drapeau qu'au retour d'un scan.
     *
     * Recopier la regle en PHP serait plus court et ce serait la mauvaise idee :
     * la question « quels gestes sont offerts » est tranchee par le BACKEND, et
     * une regle recopiee finit par diverger de celle qui decide — ce depot en
     * compte deja trois occurrences. On affiche donc ce que le serveur DIT,
     * quand il le dit, et l'affichage durable demande que le verdict soit
     * persiste ou expose sur un chemin de lecture. Dit au Lead, pas devine ici.
     *
     * LE MOTIF EST UN CODE, DONC IL SE TRADUIT. Le backend rend `vide`,
     * `trop_long`, `composant_de_chemin`, `caracteres_interdits` — sans espace,
     * une cause par code. Un code inconnu se DIT inconnu plutot que de
     * s'afficher tel quel : ce serait un identifiant a l'ecran.
     */
    function libelleMotif(code) {
        var connus = {
            vide: libelles.motif_vide,
            trop_long: libelles.motif_trop_long,
            composant_de_chemin: libelles.motif_composant_de_chemin,
            caracteres_interdits: libelles.motif_caracteres_interdits,
        };

        return connus[code] || libelles.motif_inconnu || '';
    }

    function rendIllisibles(donnees) {
        var encart = document.querySelector('[data-rw="distants-illisibles"]');
        if (! encart) { return; }
        var lignes = (donnees.users || []).filter(function (u) { return u.nom_valide === false; });
        /*
         * `invalides_count` FAIT AUTORITE SUR LE NOMBRE, la liste sur les noms.
         * Les deux viennent du serveur ; si elles se contredisaient, c'est le
         * compte du serveur qui a raison — il porte le total, la liste ne porte
         * que ce qui a voyage.
         */
        var total = Number(donnees.invalides_count);
        if (! Number.isFinite(total)) { total = lignes.length; }
        if (total === 0) {
            encart.hidden = true;
            encart.innerHTML = '';

            return;
        }
        encart.innerHTML = '';
        var titre = document.createElement('p');
        titre.className = 'rw-sous-titre-fort';
        titre.textContent = libelles.illisibles_titre || '';
        encart.appendChild(titre);

        var texte = document.createElement('p');
        texte.className = 'rw-prose';
        // `textContent` : ces noms viennent d'un `/etc/passwd` distant, donc de
        // ce que le root de la machine a bien voulu y ecrire.
        texte.textContent = (libelles.illisibles_texte || '')
            .replace('{nombre}', String(total))
            .replace('{liste}', lignes.map(function (u) {
                return (u.name || u.username || '') + ' (' + libelleMotif(u.motif_invalide) + ')';
            }).join(', '));
        encart.appendChild(texte);

        // LA CONSEQUENCE EST BLOQUANTE, ET C'ETAIT LE MANQUE. Une de ces lignes
        // en « attente d'examen » bloque le deploiement de cles : le compteur du
        // preflight les compte, deliberement — en exclure une aurait desserre un
        // garde. L'ecran qui envoie les classer doit le DIRE.
        var bloque = document.createElement('p');
        bloque.className = 'rw-annonce rw-annonce--attention';
        bloque.textContent = libelles.illisibles_bloquant || '';
        encart.appendChild(bloque);

        encart.hidden = false;
    }

    /* ═══ Le scan ═════════════════════════════════════════════════════════ */

    var boutonScan = document.querySelector('[data-rw="distants-scanner"]');
    if (boutonScan) {
        boutonScan.addEventListener('click', function () {
            var machine = parseInt(boutonScan.dataset.machine, 10);
            // LE BOUTON SE DESACTIVE : le scan ouvre une session SSH et dure.
            // Sans cela on clique trois fois en croyant que rien ne se passe,
            // et trois sessions partent.
            boutonScan.disabled = true;
            dit('[data-rw="distants-scan-etat"]', libelles.scan_en_cours);

            lit('/scan_server_users', { machine_id: machine }).then(function (d) {
                var zone = document.querySelector('[data-rw="distants-scan-etat"]');
                if (! d) {
                    // Ni JSON, ni reseau : on ne sait meme pas ce qui a echoue.
                    dit('[data-rw="distants-scan-etat"]', libelles.scan_echec);
                    if (zone) { zone.className = 'rw-annonce rw-annonce--echec'; }
                } else if (d.success !== true) {
                    var lectures = d.lectures || {};
                    var manquantes = sourcesManquantes(lectures);
                    var phrase = (libelles.scan_non_concluant || '')
                        .replace('{sources}', manquantes.join(', '));
                    // La seconde phrase n'apparait QUE dans le cas ou elle est
                    // vraie : les comptes lus, les cles non. Une reserve
                    // permanente devient un decor qu'on ne lit plus.
                    if (lectures.comptes === true) {
                        phrase += ' ' + (libelles.scan_comptes_lus || '');
                    }
                    dit('[data-rw="distants-scan-etat"]', phrase);
                    if (zone) { zone.className = 'rw-annonce rw-annonce--attention'; }
                } else {
                    dit('[data-rw="distants-scan-etat"]', libelles.scan_fait);
                    if (zone) { zone.className = 'rw-annonce rw-annonce--ok'; }
                }
                // Concluant ou non : `invalides_count` est calcule AVANT le
                // verdict, donc l'information existe dans les deux cas.
                if (d) { rendIllisibles(d); }
                boutonScan.disabled = false;
            });
        });
    }

    /* ═══ Les trois gestes qui MODIFIENT ══════════════════════════════════ */

    var panneau = document.querySelector('[data-rw="distant-panneau"]');
    var choix = document.querySelector('[data-rw="distants-geste-compte"]');
    var enCours = null;

    /*
     * Chaque geste porte SA phrase, et elle dit ce qu'il engage — pas ce qu'il
     * s'appelle. « Supprimer le compte » ne dit pas que le repertoire personnel
     * part avec lui ; la requete, elle, porte `remove_home: true`.
     */
    var GESTES = {
        cles: { chemin: '/remove_user_keys', titre: 'panneau_cles_titre', texte: 'panneau_cles_texte' },
        sshd: { chemin: '/sshd_allow_user', titre: 'panneau_sshd_titre', texte: 'panneau_sshd_texte' },
        suppression: { chemin: '/delete_remote_user', titre: 'panneau_suppr_titre', texte: 'panneau_suppr_texte' },
    };

    function ouvre(nomGeste) {
        if (! panneau || ! choix) { return; }
        var compte = choix.value;
        if (! compte) {
            dit('[data-rw="distant-geste-etat"]', libelles.geste_sans_compte);

            return;
        }
        enCours = { geste: GESTES[nomGeste], compte: compte };
        var g = enCours.geste;
        var machine = panneau.dataset.nomMachine || '';
        // `textContent`, jamais `innerHTML` : le nom vient de la base.
        dit('[data-rw="distant-panneau-titre"]',
            (libelles[g.titre] || '').replace('__NOM__', compte).replace('__MACHINE__', machine));
        dit('[data-rw="distant-panneau-texte"]',
            (libelles[g.texte] || '').replace('__NOM__', compte).replace('__MACHINE__', machine));
        dit('[data-rw="distant-geste-etat"]', '');
        panneau.hidden = false;
        panneau.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }

    [['distant-retirer-cles', 'cles'], ['distant-sshd', 'sshd'], ['distant-supprimer', 'suppression']]
        .forEach(function (paire) {
            var b = document.querySelector('[data-rw="' + paire[0] + '"]');
            if (b) { b.addEventListener('click', function () { ouvre(paire[1]); }); }
        });

    var annuler = document.querySelector('[data-rw="distant-annuler"]');
    if (annuler && panneau) {
        annuler.addEventListener('click', function () { panneau.hidden = true; enCours = null; });
    }

    var confirmer = document.querySelector('[data-rw="distant-confirmer"]');
    if (confirmer && panneau) {
        confirmer.addEventListener('click', function () {
            if (! enCours) { return; }
            var machine = parseInt(panneau.dataset.machine, 10);
            var corps = { machine_id: machine, username: enCours.compte };
            // `remove_home` est ANNONCE dans le panneau : la requete ne porte
            // rien que la phrase de confirmation n'ait dit.
            if (enCours.geste.chemin === '/delete_remote_user') { corps.remove_home = true; }

            confirmer.disabled = true;
            dit('[data-rw="distant-geste-etat"]', libelles.geste_en_cours);

            appelle(enCours.geste.chemin, corps).then(function (ok) {
                dit('[data-rw="distant-geste-etat"]', ok ? libelles.geste_fait : libelles.geste_echec);
                confirmer.disabled = false;
                panneau.hidden = true;
                enCours = null;
            });
        });
    }
}());
