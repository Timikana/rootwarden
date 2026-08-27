/**
 * cle-plateforme.js — sous-lot P1 : la cle PUBLIQUE, et rien d'autre.
 *
 * Ce script ne fait qu'une chose qui sorte : `GET /platform_key`, une lecture.
 * Deployer, tester, relever les comptes, effacer un mot de passe et faire
 * tourner la cle sont P2, P3 et P4 — et P4 ne s'executera jamais sur ce banc.
 *
 * `window.RW_CLE_PLATEFORME` est pose des la premiere ligne : une suite s'en
 * sert pour ASSERTER que ce fichier a ete charge ET evalue. Un `<script>`
 * present dans le HTML ne prouve ni l'un ni l'autre.
 */
window.RW_CLE_PLATEFORME = true;

(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var textes = {};
    try {
        var bloc = document.getElementById('cle-textes');
        if (bloc) { textes = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { textes = {}; }

    var message = document.querySelector('[data-rw="cle-message"]');
    var valeur = document.querySelector('[data-rw="cle-valeur"]');
    var copier = document.querySelector('[data-rw="cle-copier"]');
    var annonce = document.querySelector('[data-rw="cle-annonce"]');
    if (! message || ! valeur) { return; }

    function poseMessage(cleTitre, cleTexte, enErreur) {
        message.innerHTML = '';
        var bloc2 = document.createElement('div');
        bloc2.className = enErreur ? 'rw-vide rw-vide--erreur' : 'rw-vide';
        bloc2.setAttribute('data-rw', enErreur ? 'cle-echec' : 'cle-absente');
        var t = document.createElement('p');
        t.className = 'rw-sous-titre-fort';
        t.textContent = textes[cleTitre] || '';
        var x = document.createElement('p');
        x.className = 'rw-prose';
        x.textContent = textes[cleTexte] || '';
        bloc2.appendChild(t);
        bloc2.appendChild(x);
        message.appendChild(bloc2);
    }

    /*
     * ══ TROIS ISSUES, PAS DEUX ════════════════════════════════════════════
     *
     * `GET /platform_key` rend 200 avec `public_key`, ou **404** avec
     * `{'success': false, 'message': 'Keypair non generee'}` (`ssh.py:511`).
     *
     * Ce 404 est un VERDICT — « aucune paire n'existe encore » — et pas un
     * echec de lecture. Les confondre ferait annoncer une panne la ou il n'y a
     * qu'un etat initial, ou l'inverse : promettre qu'il n'y a pas de cle alors
     * que la lecture n'a pas abouti. Le statut est donc lu AVANT le corps.
     *
     * Le legacy n'en distingue aucune : il pose la reponse dans un `<div>` et
     * laisse « Chargement… » a l'ecran quand elle n'arrive pas.
     */
    var attente = document.createElement('p');
    attente.className = 'rw-aide';
    attente.textContent = textes.cle_chargement || '';
    message.appendChild(attente);

    fetch(PASSERELLE + '/platform_key', { headers: { Accept: 'application/json' } })
        .then(function (r) {
            return r.json()
                .catch(function () { return null; })
                .then(function (d) { return { statut: r.status, corps: d }; });
        })
        .then(function (rep) {
            message.innerHTML = '';
            if (rep.statut === 404) {
                // VERDICT : le backend dit qu'aucune paire n'est generee.
                poseMessage('cle_absente_titre', 'cle_absente', false);

                return;
            }
            var cle = rep.corps && rep.corps.success === true
                ? String(rep.corps.public_key == null ? '' : rep.corps.public_key).trim()
                : '';
            if (cle === '') {
                // NI 404, NI CLE : on ne sait pas. On ne dit pas « absente ».
                poseMessage('cle_echec', 'cle_echec', true);

                return;
            }
            // `textContent` : une cle publique est une donnee, pas du balisage.
            valeur.textContent = cle;
            valeur.hidden = false;
            if (copier) { copier.hidden = false; }
        })
        .catch(function () {
            message.innerHTML = '';
            poseMessage('cle_echec', 'cle_echec', true);
        });

    /*
     * ══ P2 : LE TEST DE CONNEXION — QUATRE SITUATIONS, PAS DEUX ═══════════
     *
     * `POST /test_platform_key` rend quatre reponses distinctes, et le legacy
     * les replie toutes sur `d.success ? 'success' : 'error'` :
     *
     *   success, `keypair`   la cle fonctionne
     *   false,   `none`      la cle n'est pas deployee, ou aucune paire n'existe
     *                        — **ce n'est pas un echec, c'est l'etape d'avant**,
     *                        et le legacy la peint en ROUGE
     *   false,   `password`  AuthenticationException : la cle est REFUSEE
     *   false,   `password`  toute autre exception : machine injoignable, delai…
     *
     * **Les deux dernieres sont indiscernables** : le backend rend le meme
     * `auth_method` et ne differe que par le TEXTE du message. Distinguer
     * demanderait de lire une phrase francaise — donc l'ecran ne pretend pas
     * savoir laquelle : il dit les deux causes et rapporte ce que le serveur
     * dit. *Une mesure plus fine que la donnee est une invention.*
     *
     * Et `auth_method: 'password'` ne veut PAS dire « authentifie par mot de
     * passe » : il veut dire « la cle n'a pas marche ». Le mot n'est pas montre
     * a l'ecran, il induirait en erreur.
     *
     * LE MESSAGE DU SERVEUR PORTE UN `str(e)` DE PARAMIKO. Il est rendu par
     * `textContent`, jamais interpole : une banniere SSH distante hostile ne
     * peut pas s'echapper de son noeud de texte.
     *
     * CE GESTE N'ECRIT RIEN — ni sur la machine, ni en base. Verifie route par
     * route : aucun `INSERT`, `UPDATE` ni `DELETE` dans `test_platform_key`.
     */
    var journal = document.querySelector('[data-rw="cle-test-journal"]');

    function journalise(texte, classe) {
        if (! journal) { return; }
        var p = document.createElement('p');
        p.textContent = texte;
        if (classe) { p.className = classe; }
        journal.appendChild(p);
        journal.classList.remove('rw-journal--vide');
        journal.scrollTop = journal.scrollHeight;
        journal.scrollIntoView({ block: 'nearest' });
    }

    function remplit(modele, valeurs) {
        var t = textes[modele] || '';
        Object.keys(valeurs).forEach(function (c) {
            t = t.split(':' + c).join(String(valeurs[c]));
        });

        return t;
    }

    [].slice.call(document.querySelectorAll('[data-rw^="cle-tester-"]'))
        .forEach(function (bouton) {
            bouton.addEventListener('click', function () {
                var machine = parseInt(bouton.dataset.machine, 10);
                var nom = bouton.dataset.nom || '';
                if (! machine) { return; }
                // LE BOUTON SE DESACTIVE : le test ouvre une session SSH et dure.
                // Sans cela on clique trois fois en croyant que rien ne se passe.
                bouton.disabled = true;
                journalise(remplit('test_en_cours', { machine: nom }), 'rw-aide');

                fetch(PASSERELLE + '/test_platform_key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ machine_id: machine }),
                }).then(function (r) {
                    return r.json().catch(function () { return null; });
                }).then(function (d) {
                    if (! d || typeof d.success !== 'boolean') {
                        // NI VERDICT NI ECHEC DE LA CLE : la reponse est illisible.
                        journalise(remplit('test_indecis', { machine: nom }), 'rw-non-resolu');

                        return;
                    }
                    if (d.success === true) {
                        journalise(remplit('test_ok', { machine: nom }), 'rw-annonce--ok');

                        return;
                    }
                    if (d.auth_method === 'none') {
                        // UN ETAT, PAS UN ECHEC. Le legacy le peint en rouge.
                        journalise(remplit('test_rien_a_tester', { machine: nom }), 'rw-aide');

                        return;
                    }
                    journalise(remplit('test_echec', {
                        machine: nom,
                        message: String(d.message == null ? '' : d.message),
                    }), 'rw-non-resolu');
                }).catch(function () {
                    journalise(remplit('test_indecis', { machine: nom }), 'rw-non-resolu');
                }).finally(function () {
                    bouton.disabled = false;
                });
            });
        });

    /*
     * COPIER SANS `prompt()` NI SELECTION FORCEE. Le legacy rend le bloc
     * `select-all` et cliquable, ce qui fait qu'un clic pour lire selectionne
     * tout. Ici le geste est un bouton, et son resultat est ANNONCE dans une
     * region persistante — une bulle disparue ne dit plus si la copie a eu lieu.
     */
    if (copier) {
        copier.addEventListener('click', function () {
            var texte = valeur.textContent || '';
            if (texte === '' || ! navigator.clipboard) { return; }
            navigator.clipboard.writeText(texte).then(function () {
                if (annonce) {
                    annonce.textContent = textes.cle_copiee || '';
                    annonce.className = 'rw-aide rw-annonce--ok';
                }
            }).catch(function () { /* le presse-papiers peut etre refuse */ });
        });
    }
}());
