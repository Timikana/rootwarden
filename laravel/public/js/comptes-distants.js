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

            appelle('/scan_server_users', { machine_id: machine }).then(function (ok) {
                dit('[data-rw="distants-scan-etat"]', ok ? libelles.scan_fait : libelles.scan_echec);
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
