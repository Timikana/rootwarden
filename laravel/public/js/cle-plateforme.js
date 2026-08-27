/**
 * cle-plateforme.js — la cle de plateforme, P1 a P3.
 *
 * P1 : `GET /platform_key`, une lecture. P2 : `/test_platform_key`, une lecture
 * distante. P3 : QUATRE ECRITURES — `/deploy_platform_key`,
 * `/deploy_service_account`, `/remove_ssh_password`, `/reenter_ssh_password`.
 * P4, la rotation, n'est pas portee : elle agit sur tout le parc sans viser de
 * machine et detruit la cle privee en cours.
 *
 * Aucun `confirm()` ni `prompt()` : les gestes passent par un panneau de
 * decision dans la page, qui nomme sa cible et sa consequence, et le mot de
 * passe se saisit dans un champ masque.
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
    /* ═══════════════════════════════════════════════════════════════════
     * P3 — LES QUATRE GESTES QUI ECRIVENT
     * ═══════════════════════════════════════════════════════════════════
     *
     * ══ CE QUE CHAQUE ROUTE ACCEPTE, ET CE QUE LE LEGACY EN FAIT ═════════
     *
     * `deploy_platform_key` et `deploy_service_account` prennent une LISTE
     * (`machine_ids`) : un geste de parc part en UNE requete, et rend un
     * `results[]` par machine.
     *
     * `remove_ssh_password` et `reenter_ssh_password` prennent UNE machine
     * (`machine_id`). L'effacement de parc est donc N requetes, et le legacy en
     * fait une boucle client (`platform_keys.php:330-341`) : fermer l'onglet a
     * mi-parcours laisse le parc a moitie migre, et le compteur final ne
     * reflete plus rien. La route n'accepte pas de liste — le porter « en une
     * requete » demanderait une route nouvelle, donc du backend. Il est donc
     * PORTE TEL QUEL et ANNONCE : la progression est ecrite machine par machine,
     * et une interruption laisse une trace lisible.
     *
     * ══ LE PLAFOND DE 120 s DE LA PASSERELLE ════════════════════════════
     *
     * `PasserelleController:130` impose 120 s aux routes qui ne sont pas dans
     * `RoutesBackend::EN_FLUX` — et ces deux routes de deploiement n'y sont pas.
     * Or elles sont les plus longues du module : par machine, une session SSH,
     * une installation de `sudo` au besoin, une dizaine de commandes en root et
     * deux connexions de test, le tout SEQUENTIEL et dans une seule requete
     * HTTP (`threaded_route` bloque sur `future.result()`, il ne rend pas la
     * main plus tot).
     *
     * Consequence : sur un geste de parc, le navigateur peut voir la requete
     * expirer PENDANT QUE LE BACKEND CONTINUE D'ECRIRE. Un depassement de delai
     * n'est donc PAS un echec — c'est une absence de verdict, et le message le
     * dit ainsi. Annoncer « echoue » ferait croire qu'aucune cle n'a ete
     * deployee et qu'aucun `NOPASSWD: ALL` n'a ete accorde, alors que les deux
     * ont peut-etre eu lieu. Signale au Lead : ce plafond est un reglage de la
     * passerelle, pas un defaut de portage.
     */
    var portees = {};
    try {
        var blocP = document.getElementById('cle-portees');
        if (blocP) { portees = JSON.parse(blocP.textContent || '{}'); }
    } catch (e) { portees = {}; }

    var panneau = document.querySelector('[data-rw="cle-panneau"]');
    var pTitre = document.querySelector('[data-rw="cle-panneau-titre"]');
    var pTexte = document.querySelector('[data-rw="cle-panneau-texte"]');
    var pEffets = document.querySelector('[data-rw="cle-panneau-effets"]');
    var pCibles = document.querySelector('[data-rw="cle-panneau-cibles"]');
    var pProd = document.querySelector('[data-rw="cle-panneau-prod"]');
    var pChamp = document.querySelector('[data-rw="cle-panneau-champ"]');
    var pMotif = document.querySelector('[data-rw="cle-panneau-motif"]');
    var pMotifVal = document.querySelector('[data-rw="cle-panneau-motif-valeur"]');
    var pBorne = document.querySelector('[data-rw="cle-panneau-borne"]');
    var pMdp = document.querySelector('[data-rw="cle-panneau-mdp"]');
    var pAnnuler = document.querySelector('[data-rw="cle-panneau-annuler"]');
    var pConfirmer = document.querySelector('[data-rw="cle-panneau-confirmer"]');
    var jGeste = document.querySelector('[data-rw="cle-geste-journal"]');
    var bRecharger = document.querySelector('[data-rw="cle-recharger"]');

    // Sans panneau il n'y a pas de geste possible : on ne branche RIEN plutot
    // que de laisser des boutons qui agiraient sans decision.
    //
    // UN DRAPEAU, PAS UN `return`. Un `return` ici sortirait de la fonction
    // englobante et emporterait le bouton « copier » declare plus bas — un
    // garde qui casse une piece etrangere a ce qu'il garde.
    var gestesActifs = !! (panneau && pConfirmer);

    var GESTES = {
        deployer:       { route: '/deploy_platform_key',    liste: true,  mdp: false },
        compte_service: { route: '/deploy_service_account', liste: true,  mdp: false },
        effacer:        { route: '/remove_ssh_password',    liste: false, mdp: false },
        ressaisir:      { route: '/reenter_ssh_password',   liste: false, mdp: true },
        // LA CONTREPARTIE DE L'OCTROI. La route prend une LISTE, exige un
        // motif, et passe par la porte a quatre yeux — d'ou trois issues de
        // plus que les autres gestes, traitees dans `noteVerdict`.
        revoquer:       { route: '/revoke_service_account', liste: true,  motif: true },
    };

    var enCours = null;

    function noteGeste(texte, classe) {
        if (! jGeste) { return; }
        var p = document.createElement('p');
        p.textContent = texte;
        if (classe) { p.className = classe; }
        jGeste.appendChild(p);
        jGeste.classList.remove('rw-journal--vide');
        jGeste.scrollTop = jGeste.scrollHeight;
        if (bRecharger) { bRecharger.hidden = false; }
    }

    function ferme() {
        panneau.hidden = true;
        enCours = null;
        if (pMdp) { pMdp.value = ''; }
        if (pChamp) { pChamp.hidden = true; }
        if (pMotifVal) { pMotifVal.value = ''; }
        if (pMotif) { pMotif.hidden = true; }
        if (pBorne) { pBorne.hidden = true; }
        if (pProd) { pProd.hidden = true; pProd.textContent = ''; }
    }

    function ouvre(geste, cibles) {
        var p = (textes.panneaux || {})[geste] || {};
        enCours = { geste: geste, cibles: cibles };

        pTitre.textContent = p.titre || '';
        if (pTexte) { pTexte.textContent = p.texte || ''; }

        // Les effets sont POSES A NEUF a chaque ouverture : reutiliser la liste
        // precedente ferait lire les consequences d'un autre geste.
        if (pEffets) {
            pEffets.textContent = '';
            (p.effets || []).forEach(function (e) {
                var li = document.createElement('li');
                li.textContent = e;
                pEffets.appendChild(li);
            });
        }

        if (pCibles) {
            pCibles.textContent = cibles.ids.length === 1
                ? remplit('panneau_cible_une', { nom: cibles.noms[0] || '' })
                : remplit('panneau_cible_n', {
                    n: cibles.ids.length,
                    noms: cibles.noms.join(', '),
                });
        }

        // LA PRODUCTION SE NOMME. Le legacy ne distingue rien : un geste de parc
        // y engloutit la production sans que son libelle change.
        if (pProd) {
            var prod = cibles.sensibles || [];
            pProd.hidden = prod.length === 0;
            pProd.textContent = prod.length === 0
                ? ''
                : remplit('panneau_prod', { noms: prod.join(', ') });
        }

        if (pChamp) { pChamp.hidden = ! GESTES[geste].mdp; }
        if (pMotif) { pMotif.hidden = ! GESTES[geste].motif; }
        // LA BORNE EST DITE DANS LE PANNEAU, pas seulement dans le journal :
        // c'est ici que la decision se prend, et un avertissement qui arrive
        // apres le clic n'a pas averti.
        //
        // Elle vient d'une CARTE par geste, jamais d'un `geste === '...'` :
        // deux gestes butent sur la meme cause backend et ne la rencontrent pas
        // au meme endroit. Un geste sans borne n'affiche rien du tout — le
        // paragraphe reste `hidden`, il ne se vide pas en laissant un blanc.
        if (pBorne) {
            var borne = (textes.bornes || {})[geste] || '';
            pBorne.textContent = borne;
            pBorne.hidden = borne === '';
        }
        panneau.hidden = false;
        panneau.scrollIntoView({ block: 'nearest' });
        if (GESTES[geste].mdp && pMdp) { pMdp.focus(); }
        else if (GESTES[geste].motif && pMotifVal) { pMotifVal.focus(); }
    }

    /* Le verdict PAR MACHINE, tire de `results` et non du `success` global.
     * `deploy_platform_key` rend `success: all(...)` : sur trois machines dont
     * une echoue, le global est faux et deux machines ont pourtant recu la cle.
     * Lire le global seul perdrait ces deux-la. */
    function noteResultats(d, cibles) {
        var res = (d && Array.isArray(d.results)) ? d.results : null;
        if (! res) {
            noteGeste(textes.geste_sans_verdict || '', 'rw-non-resolu');

            return;
        }
        var ok = 0;
        res.forEach(function (r) {
            var reussi = r && r.success === true;
            if (reussi) { ok += 1; }
            noteGeste(remplit(reussi ? 'geste_ligne_ok' : 'geste_ligne_echec', {
                machine: String((r && r.name) || ''),
                message: String((r && r.message) || ''),
            }), reussi ? 'rw-annonce--ok' : 'rw-non-resolu');
        });
        noteGeste(remplit('geste_bilan', { ok: ok, total: cibles.ids.length }),
            ok === cibles.ids.length ? 'rw-annonce--ok' : 'rw-annonce--attention');
    }

    /* LE STATUT REMONTE AVEC LE CORPS. La porte a quatre yeux repond 202
     * (« demande creee ») ou 409 (« aucun approbateur disponible ») : ce sont
     * des etats DEFINIS, et les confondre avec « absence de verdict » ferait
     * dire « je ne sais pas » a un serveur qui vient de dire precisement
     * pourquoi rien n'a ete fait. */
    function envoie(route, corps) {
        return fetch(PASSERELLE + route, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(corps),
        }).then(function (r) {
            return r.json().catch(function () { return null; }).then(function (d) {
                return { statut: r.status, corps: d };
            });
        });
    }

    /* Les deux issues de la porte a quatre yeux, avant tout verdict d'ecriture.
     * Rend `true` si la reponse est une issue de porte — donc si RIEN n'a ete
     * ecrit et qu'il ne faut surtout pas conclure a un echec du geste. */
    function noteIssueDePorte(d) {
        if (! d) { return false; }
        if (d.pending_approval === true) {
            noteGeste(textes.geste_approbation_attente || '', 'rw-annonce--attention');

            return true;
        }
        if (d.approbateur_manquant === true) {
            noteGeste(remplit('geste_approbation_absente', {
                message: String(d.message || ''),
            }), 'rw-annonce--attention');

            return true;
        }

        return false;
    }

    /* L'EFFACEMENT DE PARC : N requetes, et la progression est ECRITE.
     * Une interruption laisse donc dans le journal le nombre exact de machines
     * traitees — le legacy ne rendait qu'un `ok/total` final, jamais atteint si
     * l'onglet se fermait. */
    function effaceEnSerie(cibles) {
        var fait = 0;
        var ok = 0;

        function suivante(i) {
            if (i >= cibles.ids.length) {
                noteGeste(remplit('effacement_bilan', { ok: ok, total: cibles.ids.length }),
                    ok === cibles.ids.length ? 'rw-annonce--ok' : 'rw-annonce--attention');

                return Promise.resolve();
            }

            return envoie('/remove_ssh_password', { machine_id: cibles.ids[i] })
                .then(function (rep) {
                    var d = rep.corps;
                    fait += 1;
                    var reussi = d && d.success === true;
                    if (reussi) { ok += 1; }
                    noteGeste(remplit(reussi ? 'geste_ligne_ok' : 'geste_ligne_echec', {
                        machine: String(cibles.noms[i] || ''),
                        message: String((d && d.message) || ''),
                    }), reussi ? 'rw-annonce--ok' : 'rw-non-resolu');

                    return suivante(i + 1);
                })
                .catch(function (e) {
                    // On S'ARRETE : continuer apres une requete dont on ne sait
                    // rien enchainerait des ecritures a l'aveugle.
                    noteGeste(remplit('geste_echec_reseau', {
                        message: String((e && e.message) || ''),
                    }), 'rw-non-resolu');
                    noteGeste(remplit('effacement_interrompu', {
                        fait: fait, total: cibles.ids.length,
                    }), 'rw-annonce--attention');
                });
        }

        return suivante(0);
    }

    if (gestesActifs) {
    pConfirmer.addEventListener('click', function () {
        if (! enCours) { return; }
        var geste = enCours.geste;
        var cibles = enCours.cibles;
        var def = GESTES[geste];

        var motif = '';
        if (def.motif) {
            motif = ((pMotifVal && pMotifVal.value) || '').trim();
            if (motif === '') {
                // CE GESTE RETIRE UN ACCES : il ne s'enregistre pas sans raison.
                // Le panneau reste ouvert, la decision deja prise n'est pas perdue.
                noteGeste(textes.motif_vide || '', 'rw-annonce--attention');

                return;
            }
        }

        var motDePasse = '';
        if (def.mdp) {
            motDePasse = (pMdp && pMdp.value) || '';
            if (motDePasse === '') {
                // RIEN N'EST ENVOYE, et le panneau reste ouvert : refermer ferait
                // perdre la decision deja prise.
                noteGeste(textes.ressaisie_mdp_vide || '', 'rw-annonce--attention');

                return;
            }
        }

        pConfirmer.disabled = true;
        if (pAnnuler) { pAnnuler.disabled = true; }
        noteGeste(remplit('geste_en_cours', { cibles: cibles.noms.join(', ') }), 'rw-aide');

        var travail;
        if (def.liste) {
            var charge = { machine_ids: cibles.ids };
            if (def.motif) { charge.reason = motif; }
            travail = envoie(def.route, charge).then(function (rep) {
                if (noteIssueDePorte(rep.corps)) { return; }
                noteResultats(rep.corps, cibles);
            });
        } else if (geste === 'effacer' && cibles.ids.length > 1) {
            travail = effaceEnSerie(cibles);
        } else {
            var corps = { machine_id: cibles.ids[0] };
            if (def.mdp) { corps.password = motDePasse; }
            travail = envoie(def.route, corps).then(function (rep) {
                var d = rep.corps;
                if (noteIssueDePorte(d)) { return; }
                if (! d || typeof d.success !== 'boolean') {
                    noteGeste(textes.geste_sans_verdict || '', 'rw-non-resolu');

                    return;
                }
                noteGeste(remplit(d.success ? 'geste_ligne_ok' : 'geste_ligne_echec', {
                    machine: String(cibles.noms[0] || ''),
                    message: String(d.message || ''),
                }), d.success ? 'rw-annonce--ok' : 'rw-non-resolu');
            });
        }

        travail.catch(function (e) {
            // NI REUSSITE NI ECHEC. Un depassement du plafond de 120 s de la
            // passerelle arrive ici alors que le backend ECRIT ENCORE.
            noteGeste(remplit('geste_echec_reseau', {
                message: String((e && e.message) || ''),
            }), 'rw-non-resolu');
        }).finally(function () {
            pConfirmer.disabled = false;
            if (pAnnuler) { pAnnuler.disabled = false; }
            // Le mot de passe ne SURVIT PAS au geste, meme en cas d'echec : le
            // laisser dans le champ le laisse dans la page.
            ferme();
        });
    });

    if (pAnnuler) { pAnnuler.addEventListener('click', ferme); }

    if (bRecharger) {
        bRecharger.addEventListener('click', function () { window.location.reload(); });
    }

    // ── Les boutons PAR LIGNE ────────────────────────────────────────────
    [].slice.call(document.querySelectorAll('[data-geste][data-machine]'))
        .forEach(function (bouton) {
            bouton.addEventListener('click', function () {
                var id = parseInt(bouton.dataset.machine, 10);
                if (! id || ! GESTES[bouton.dataset.geste]) { return; }
                // LA PRODUCTION SE NOMME AUSSI SUR UNE LIGNE SEULE. Mon
                // premier jet mettait `sensibles: []` en se disant que le
                // tableau porte deja la mention — mais alors deployer sur la
                // PRODUCTION depuis sa ligne ouvrait un panneau muet, et c'est
                // le seul endroit ou la decision se prend. Le drapeau est
                // TRANSMIS par l'attribut, calcule par `estSensible()` cote
                // serveur : une transmission, pas une regle recopiee.
                var nom = bouton.dataset.nom || '';
                ouvre(bouton.dataset.geste, {
                    ids: [id],
                    noms: [nom],
                    sensibles: bouton.dataset.sensible === '1' ? [nom] : [],
                });
            });
        });

    // ── Les boutons DE PARC ──────────────────────────────────────────────
    [].slice.call(document.querySelectorAll('[data-portee="parc"]'))
        .forEach(function (bouton) {
            bouton.addEventListener('click', function () {
                var geste = bouton.dataset.geste;
                var portee = portees[geste];
                if (! portee || ! portee.ids || portee.ids.length === 0) { return; }
                ouvre(geste, portee);
            });
        });
    }

    /* ═══════════════════════════════════════════════════════════════════
     * E-219 — DEMANDER AU SEUL QUI PUISSE REPONDRE
     * ═══════════════════════════════════════════════════════════════════
     *
     * Le tableau et les compteurs rendus par le serveur reposent sur
     * `(password <> '')`. Ce test compte des OCTETS dans une colonne chiffree,
     * pas la presence d'un secret : PHP chiffre la chaine vide en `sodium:…`,
     * Python rend `''`. Un mot de passe REELLEMENT vide saisi depuis l'ancien
     * portail rend donc la colonne NON VIDE, et le compteur surestime.
     *
     * Le portage ne recalcule rien : il DEMANDE. `GET /machines/credential-status`
     * rend trois etats — vide, non vide, et `null` INDETERMINE quand le
     * dechiffrement a echoue. Ce troisieme etat est le plus important : sans lui
     * « je n'ai pas su lire » se deguiserait en « c'est vide ».
     *
     * CE QUE CETTE REPONSE NE COUVRE PAS : le predicat ne porte que sur
     * `password`. `root_password` n'y figure pas, et c'est pourtant la colonne
     * sans chemin de reecriture depuis cette page. Son etat affiche reste donc
     * calcule sur la colonne, avec la meme approximation — dit a l'ecran plutot
     * que laisse a supposer.
     *
     * UN ECHEC DE CETTE REQUETE NE VALIDE RIEN. L'encart annonce alors que les
     * compteurs restent approximatifs. Le silence aurait laisse croire a un
     * accord.
     */
    var credEncart = document.querySelector('[data-rw="cle-credential"]');
    var credVerdict = document.querySelector('[data-rw="cle-credential-verdict"]');

    function annonceCredential(texte, classe) {
        if (! credEncart || ! credVerdict) { return; }
        credVerdict.textContent = texte;
        credVerdict.className = 'rw-prose' + (classe ? ' ' + classe : '');
        credEncart.hidden = false;
    }

    /* Pose un badge dans la cellule « Mot de passe » d'une ligne. Le badge
     * s'AJOUTE au texte du serveur, il ne le remplace pas : l'ecran montre les
     * deux reponses et dit laquelle vient d'ou. Effacer le texte serveur
     * cacherait la divergence au lieu de la nommer. */
    function badgeMotDePasse(id, cle, classe) {
        var cellule = document.querySelector('[data-rw="cle-mdp-' + id + '"]');
        if (! cellule) { return; }
        var badge = document.createElement('span');
        badge.className = 'rw-badge ' + classe;
        badge.setAttribute('data-rw', 'cle-mdp-badge-' + id);
        badge.textContent = textes[cle] || '';
        cellule.appendChild(badge);
    }

    if (credEncart) {
        fetch(PASSERELLE + '/machines/credential-status', {
            headers: { Accept: 'application/json' },
        }).then(function (r) {
            return r.json().catch(function () { return null; });
        }).then(function (d) {
            if (! d || d.success !== true || ! Array.isArray(d.machines)) {
                annonceCredential(textes.credential_echec || '', 'rw-annonce--attention');

                return;
            }

            var divergentes = [];
            var indeterminees = [];

            d.machines.forEach(function (m) {
                var id = m.machine_id;
                var ligne = document.querySelector('[data-rw="cle-ligne-' + id + '"]');
                // Le serveur n'a pas rendu cette ligne (filtre d'acces cote
                // backend, ou machine ajoutee depuis le rendu) : rien a annoter,
                // et surtout rien a compter comme un ecart.
                if (! ligne) { return; }

                var vuServeur = ligne.dataset.mdp || '';
                // Le serveur a-t-il annonce un mot de passe UTILISATEUR ?
                // `root` seul ne concerne pas ce predicat, qui ne lit que
                // `password` — l'y inclure inventerait une divergence.
                var serveurDitMdp = vuServeur === 'les_deux' || vuServeur === 'utilisateur';

                if (m.mot_de_passe_vide === null || m.dechiffrable === false) {
                    indeterminees.push(String(m.nom || id));
                    badgeMotDePasse(id, 'badge_mdp_illisible', 'rw-badge--attention');

                    return;
                }
                if (m.mot_de_passe_vide === true && serveurDitMdp) {
                    divergentes.push(String(m.nom || id));
                    badgeMotDePasse(id, 'badge_mdp_vide_reel', 'rw-badge--alerte');
                }
            });

            // LES DEUX SONT DITS, ET SEPAREMENT. Les fondre en un nombre
            // reunirait « la colonne se trompe » et « je n'ai pas su lire »,
            // qui n'appellent pas le meme geste.
            var lignes = [];
            if (divergentes.length > 0) {
                lignes.push(remplit('credential_divergence', {
                    n: divergentes.length, noms: divergentes.join(', '),
                }));
            }
            if (indeterminees.length > 0) {
                lignes.push(remplit('credential_indetermine', {
                    n: indeterminees.length, noms: indeterminees.join(', '),
                }));
            }
            if (lignes.length === 0) {
                annonceCredential(textes.credential_accord || '', 'rw-annonce--ok');

                return;
            }
            annonceCredential(lignes.join(' '), 'rw-annonce--attention');
        }).catch(function () {
            annonceCredential(textes.credential_echec || '', 'rw-annonce--attention');
        });
    }

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
