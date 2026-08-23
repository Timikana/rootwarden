/*
 * supervision.js - Module `supervision/`, sous-lot V1 : les onglets, le choix de
 * plateforme, et le garde de l'editeur.
 *
 * CE SCRIPT NE PARLE A PERSONNE. Pas un `fetch`, pas un `EventSource`, aucune
 * adresse. Tout ce qu'il montre est deja dans la page, rendu cote serveur
 * (decision S3/S4). C'est la difference mesuree avec le legacy, qui emet deux
 * requetes backend au chargement et les rejoue a CHAQUE bascule d'onglet.
 *
 * Les libelles viennent du MEME catalogue que la page, poses en donnees. Cote
 * legacy le JS lit un second catalogue ou onze cles du module manquent, et
 * `head.php` rend alors la cle elle-meme a l'ecran.
 */
(function () {
    'use strict';

    var libelles = {};
    try {
        libelles = JSON.parse(document.getElementById('superv-libelles').textContent);
    } catch (e) {
        // Sans libelles, mieux vaut une page sans script qu'une page qui affiche
        // des identifiants techniques.
        return;
    }

    /* ── Les onglets ────────────────────────────────────────────────────────
     * On derive la liste des DEUX cotes du meme attribut : jamais un index, ni
     * « le premier bouton ». Deplacer un bouton ne doit rien casser.
     */
    var onglets = [].slice.call(document.querySelectorAll('[data-rw^="onglet-"]'));

    function montreOnglet(nom) {
        onglets.forEach(function (bouton) {
            var sien = bouton.dataset.rw.replace('onglet-', '');
            var actif = sien === nom;
            bouton.classList.toggle('rw-onglet--actif', actif);
            bouton.setAttribute('aria-selected', actif ? 'true' : 'false');
            var panneau = document.querySelector('[data-rw="panneau-' + sien + '"]');
            if (panneau) { panneau.hidden = !actif; }
        });
    }

    onglets.forEach(function (bouton) {
        bouton.addEventListener('click', function () {
            montreOnglet(bouton.dataset.rw.replace('onglet-', ''));
        });
    });

    /* ── Le choix de plateforme ─────────────────────────────────────────────
     * La valeur vient d'un `<option>` que le serveur a ecrit depuis une liste
     * FERMEE : elle sert d'identifiant a `getElementById`, et il ne faut pas
     * qu'une valeur venue d'ailleurs y arrive un jour. On ne parcourt donc que
     * les blocs presents, sans jamais construire de selecteur libre.
     */
    var choixPlateforme = document.querySelector('[data-rw="superv-plateforme"]');
    if (choixPlateforme) {
        /*
         * Les blocs a basculer sont NOMMES ici, un par famille : la
         * configuration (V1) et le catalogue de profils (V2). Une liste
         * explicite plutot qu'un selecteur par prefixe — un prefixe attraperait
         * ce qu'un sous-lot suivant ajoutera, et le ferait disparaitre sans
         * qu'aucun test ne l'ait demande.
         */
        var familles = ['config-', 'profils-'];
        var blocs = [];
        [].slice.call(choixPlateforme.options).forEach(function (o) {
            familles.forEach(function (prefixe) {
                var bloc = document.getElementById(prefixe + o.value);
                if (bloc) { blocs.push({ nom: o.value, bloc: bloc }); }
            });
        });
        choixPlateforme.addEventListener('change', function () {
            blocs.forEach(function (b) {
                b.bloc.hidden = b.nom !== choixPlateforme.value;
            });
            /*
             * LE CHEMIN DE L'EDITEUR SUIT LA PLATEFORME. Les quatre valeurs
             * viennent du SERVEUR, donc de la meme source que celle que le
             * backend lira — la ou le legacy les tient en dur cote client
             * (`main.js:27-32`) et finit par nommer un fichier qu'il ne lit pas.
             */
            var cible = document.querySelector('[data-rw="superv-editeur-chemin"]');
            if (! cible) { return; }
            try {
                var chemins = JSON.parse(libelles.chemins_config || '{}');
                if (chemins[choixPlateforme.value]) {
                    cible.textContent = chemins[choixPlateforme.value];
                }
            } catch (e) { /* un chemin inchange vaut mieux qu'un chemin invente */ }
        });
    }

    /* ── Les panneaux de decision, ouverts sous leur ligne ──────────────────
     * Une suppression de profil est destructrice : elle emporte les assignations
     * (`ON DELETE CASCADE`). La decision se prend DONC dans la page, sous la ligne
     * concernee — une boite native recouvre precisement la ligne sur laquelle on
     * decide, ne se style pas, et bloque le test qui doit mener le geste au bout.
     *
     * Le bouton NOMME sa cible par `data-cible` : pas de selecteur derive du
     * `data-rw`, qui attraperait ce qu'un sous-lot suivant ajoutera.
     */
    [].slice.call(document.querySelectorAll('[data-cible]')).forEach(function (bouton) {
        bouton.addEventListener('click', function () {
            var panneau = document.getElementById(bouton.dataset.cible);
            if (! panneau) { return; }
            panneau.hidden = ! panneau.hidden;
        });
    });

    /* ── La detection de version — sous-lot V6 ──────────────────────────────
     * LE SEUL GESTE DE CETTE PAGE QUI JOINT UNE MACHINE. Il passe par la
     * passerelle parce que c'est le backend qui ouvre la session SSH (exception
     * declaree, comme K2/K3/K4).
     *
     * UN CLIENT QUI NE LIT PAS `resp.status` AVALE TOUS LES REFUS : un 403 ou un
     * 500 y ressemble a une reponse vide, et l'ecran conclut « aucun agent »
     * alors que personne n'a rien mesure. On lit donc le statut D'ABORD.
     *
     * Et le verdict RESTE a l'ecran : le legacy le passe a un `toast()` de 4 s
     * alors qu'une session SSH en demande le double — le message disparaissait
     * avant que son effet soit constatable.
     */
    var messageVersion = document.querySelector('[data-rw="superv-version-message"]');
    [].slice.call(document.querySelectorAll('[data-rw="superv-detecter-version"]'))
        .forEach(function (bouton) {
            bouton.addEventListener('click', function () {
                if (! messageVersion) { return; }
                var nom = bouton.dataset.nom || '';
                messageVersion.className = 'rw-annonce';
                messageVersion.textContent = libelles.version_en_cours.replace('{nom}', nom);
                bouton.disabled = true;

                var jeton = document.querySelector('meta[name="csrf-token"]');
                fetch(libelles.url_version, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': jeton ? jeton.content : '',
                    },
                    body: JSON.stringify({ machine_id: Number(bouton.dataset.machine) }),
                }).then(function (reponse) {
                    if (! reponse.ok) {
                        // Le statut d'abord : un refus ne se confond pas avec
                        // « aucun agent installe ».
                        messageVersion.className = 'rw-annonce rw-annonce--echec';
                        messageVersion.textContent = libelles.version_refus
                            .replace('{statut}', String(reponse.status));
                        return null;
                    }
                    return reponse.json();
                }).then(function (donnees) {
                    if (! donnees) { return; }
                    if (donnees.version) {
                        messageVersion.className = 'rw-annonce rw-annonce--ok';
                        messageVersion.textContent = libelles.version_trouvee
                            .replace('{version}', donnees.version)
                            .replace('{nom}', nom);
                    } else {
                        messageVersion.className = 'rw-annonce';
                        messageVersion.textContent = libelles.version_absente
                            .replace('{nom}', nom);
                    }
                }).catch(function () {
                    messageVersion.className = 'rw-annonce rw-annonce--echec';
                    messageVersion.textContent = libelles.version_echec;
                }).finally(function () {
                    bouton.disabled = false;
                });
            });
        });

    /* ── Le garde de l'editeur ──────────────────────────────────────────────
     * LE SEUL GESTE DE V1. Sans serveur choisi, il refuse — DANS la page, avec
     * une phrase traduite, et sans joindre quoi que ce soit. Cote legacy, ce
     * refus ouvre une boite native qui affiche la cle `editor_select_server`.
     *
     * La lecture reelle du fichier distant (V7) n'est pas portee : le bouton ne
     * fait donc rien de plus que ce refus, et la page annonce ou la faire.
     */
    var bouton = document.querySelector('[data-rw="superv-lire-config"]');
    var message = document.querySelector('[data-rw="superv-editeur-message"]');
    var serveur = document.querySelector('[data-rw="superv-serveur"]');
    var contenu = document.querySelector('[data-rw="superv-editeur-contenu"]');
    var cheminAffiche = document.querySelector('[data-rw="superv-editeur-chemin"]');
    var sauvegardes = document.querySelector('[data-rw="superv-sauvegardes"]');
    /*
     * DECLAREES ICI, PAS PLUS BAS. La liste des sauvegardes est rendue plus haut
     * dans ce fichier que le panneau de restauration, et ses boutons s'en
     * servent : les declarer apres ne tenait que par le hoisting de `var`, ce qui
     * marche et se lit comme un defaut.
     */
    var panneauRestaurer = document.querySelector('[data-rw="superv-panneau-restaurer"]');
    var messageRestaurer = document.querySelector('[data-rw="superv-restaurer-message"]');
    var annulerRestaurer = document.querySelector('[data-rw="superv-restaurer-annuler"]');
    var confirmerRestaurer = document.querySelector('[data-rw="superv-restaurer-confirmer"]');
    var coutRestaurer = document.querySelector('[data-rw="superv-restaurer-cout"]');

    /** Le nom du serveur choisi, pour que les messages nomment leur cible. */
    function nomDuServeur() {
        if (! serveur) { return ''; }
        var opt = serveur.options[serveur.selectedIndex];
        return opt ? opt.textContent.trim() : '';
    }

    function appelleLaMachine(url, sur, alors) {
        /*
         * UN REPLI QUI NE REFUSE PAS N'EST PAS UN REPLI. `fetch('')` ne « ne part
         * pas » : il POSTe sur la page courante. Une route inconnue doit donc
         * arreter le geste ici, franchement.
         */
        if (! url) { return Promise.reject(new Error('route inconnue')); }
        var jeton = document.querySelector('meta[name="csrf-token"]');
        return fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': jeton ? jeton.content : '',
            },
            body: JSON.stringify({ machine_id: Number(sur) }),
        }).then(function (reponse) {
            /*
             * LE STATUT D'ABORD, ET LES TROIS CAS SEPARES. Un 404 veut dire
             * « le fichier n'existe pas » — ce qui est une reponse, pas une
             * panne ; un autre refus veut dire « on ne vous a pas laisse
             * regarder ». Les confondre fait conclure a tort.
             */
            if (reponse.status === 404) { return { absent: true }; }
            if (! reponse.ok) { return { refus: reponse.status }; }
            return reponse.json();
        }).then(alors);
    }

    if (bouton && message && serveur) {
        bouton.addEventListener('click', function () {
            if (serveur.value === '') {
                // Le garde du legacy, seule des onze cles cassees atteignable
                // sans joindre une machine (ferme depuis V1).
                message.className = 'rw-annonce';
                message.textContent = libelles.editeur_sans_serveur;

                return;
            }
            var nom = nomDuServeur();
            message.className = 'rw-annonce';
            message.textContent = libelles.editeur_lecture_en_cours.replace('{nom}', nom);
            bouton.disabled = true;

            appelleLaMachine(routeCourante('lecture'), serveur.value, function (donnees) {
                if (donnees.absent) {
                    message.className = 'rw-annonce';
                    message.textContent = libelles.editeur_absent
                        .replace('{chemin}', cheminAffiche ? cheminAffiche.textContent : '')
                        .replace('{nom}', nom);
                    if (contenu) { contenu.value = ''; }

                    return;
                }
                if (donnees.refus) {
                    message.className = 'rw-annonce rw-annonce--echec';
                    message.textContent = libelles.editeur_refus
                        .replace('{statut}', String(donnees.refus));

                    return;
                }
                // LE CHEMIN AFFICHE DEVIENT CELUI QUI A ETE LU. Le legacy garde
                // le sien, ecrit en dur, meme quand le backend en lit un autre.
                if (cheminAffiche && donnees.path) {
                    cheminAffiche.textContent = donnees.path;
                    // « Fichier a lire » devient « Fichier lu » : la page ne
                    // pretend une lecture qu'une fois qu'elle a eu lieu.
                    var etiquette = document.querySelector('[data-rw="superv-editeur-chemin-etiquette"]');
                    if (etiquette) { etiquette.textContent = libelles.editeur_chemin_lu; }
                }
                if (contenu) { contenu.value = donnees.config || ''; }
                message.className = 'rw-annonce rw-annonce--ok';
                message.textContent = libelles.editeur_lu
                    .replace('{chemin}', donnees.path || '')
                    .replace('{nom}', nom);
            }).catch(function () {
                message.className = 'rw-annonce rw-annonce--echec';
                message.textContent = libelles.editeur_echec;
            }).finally(function () {
                bouton.disabled = false;
            });
        });
        serveur.addEventListener('change', function () {
            message.className = 'rw-annonce';
            /*
             * CHANGER DE SERVEUR VIDE LA ZONE — ET LE DIT, DEPUIS V9. La
             * configuration d'un serveur n'a aucun sens pour un autre : la vider
             * est correct. Mais V7 laissait ce champ en LECTURE SEULE, donc la
             * vider ne perdait rien ; depuis que V9 le rend modifiable, le meme
             * geste peut effacer ce que quelqu'un vient de taper. Un effacement
             * silencieux devient une perte de travail : on l'annonce.
             */
            var avait = contenu && contenu.value.trim() !== '';
            if (contenu) { contenu.value = ''; }
            message.textContent = avait ? libelles.editeur_change_serveur : '';
        });
    }

    /* ── La liste des sauvegardes — sous-lot V7, lecture seule ──────────────
     * RESTAURER une sauvegarde MODIFIE la machine : c'est V9. Ici on ne fait que
     * compter ce qui existe, et le dire.
     */
    var boutonSauvegardes = document.querySelector('[data-rw="superv-lire-sauvegardes"]');
    if (boutonSauvegardes && sauvegardes && serveur) {
        boutonSauvegardes.addEventListener('click', function () {
            if (serveur.value === '') {
                sauvegardes.textContent = libelles.editeur_sans_serveur;

                return;
            }
            boutonSauvegardes.disabled = true;
            appelleLaMachine(routeCourante('sauvegardes'), serveur.value, function (donnees) {
                if (donnees.absent || donnees.refus) {
                    sauvegardes.textContent = libelles.editeur_refus
                        .replace('{statut}', String(donnees.refus || 404));

                    return;
                }
                /*
                 * V9 : la liste porte un bouton par ligne. Elle est rendue par
                 * `textContent`, jamais par interpolation — un nom de fichier
                 * vient d'une machine distante, donc d'une source qu'on ne
                 * controle pas.
                 */
                var liste = donnees.backups || [];
                sauvegardes.textContent = '';
                if (liste.length === 0) {
                    var vide = document.createElement('p');
                    vide.className = 'rw-aide';
                    vide.textContent = libelles.sauvegardes_aucune;
                    sauvegardes.appendChild(vide);

                    return;
                }
                var titre = document.createElement('p');
                titre.className = 'rw-aide';
                titre.textContent = libelles.sauvegardes_nombre
                    .replace('{nombre}', String(liste.length));
                sauvegardes.appendChild(titre);

                liste.forEach(function (b) {
                    var ligne = document.createElement('div');
                    ligne.className = 'rw-actions';
                    ligne.setAttribute('data-rw', 'superv-sauvegarde');

                    var nom = document.createElement('code');
                    nom.className = 'rw-actions__gauche';
                    nom.textContent = b.filename;
                    ligne.appendChild(nom);

                    var bouton = document.createElement('button');
                    bouton.type = 'button';
                    bouton.className = 'rw-bouton rw-bouton--discret';
                    bouton.setAttribute('data-rw', 'superv-restaurer');
                    bouton.setAttribute('data-cible', b.filename);
                    bouton.textContent = libelles.restaurer_bouton;
                    /*
                     * LE BOUTON OUVRE, IL N'ENVOIE PAS. Cote legacy le meme clic
                     * ecrase la configuration et redemarre l'agent, sans la
                     * moindre confirmation.
                     */
                    bouton.addEventListener('click', function () {
                        if (! panneauRestaurer || ! coutRestaurer) { return; }
                        panneauRestaurer.setAttribute('data-cible', b.filename);
                        coutRestaurer.textContent = libelles.restaurer_cout
                            .replace('{nom}', b.filename)
                            .replace('{chemin}', cheminCourant());
                        panneauRestaurer.hidden = false;
                        if (messageRestaurer) {
                            messageRestaurer.className = 'rw-annonce';
                            messageRestaurer.textContent = '';
                        }
                        annulerRestaurer.focus();
                    });
                    ligne.appendChild(bouton);
                    sauvegardes.appendChild(ligne);
                });
            }).catch(function () {
                sauvegardes.textContent = libelles.editeur_echec;
            }).finally(function () {
                boutonSauvegardes.disabled = false;
            });
        });
    }

    /* ── La reconfiguration ──────────────────────────────────── sous-lot V10
     *
     * LE VERDICT VIENT DE CE QUE LE FLUX A MONTRE, PAS DE SON DERNIER MARQUEUR.
     * Mesure (PARITE E-85) sur la machine de test, sans `systemctl` :
     *
     *     Exécution terminée (code 127).
     *     SUCCESS_MACHINE::2::Reconfiguration reussie pour Test-Server-Debian.
     *
     * Le redemarrage a echoue et le marqueur conclut a la reussite. L'information
     * est dans le flux DEUX LIGNES plus haut. Un portage qui lirait le marqueur
     * heriterait du mensonge : on lit donc le flux ENTIER, et on en tire QUATRE
     * issues distinctes.
     *
     * ON PARSE LE NOMBRE, PAS LA PHRASE. « Exécution terminée (code 127). » est
     * une phrase francaise, susceptible de changer ; `(code N)` est la partie
     * protocole. Meme raison qu'un jeton de protocole n'est pas un libelle.
     *
     * LA PASSERELLE BUFFERISE, ET C'EST ASSUME : `/supervision/` n'est pas dans
     * `EN_FLUX`. Mesure : une reconfiguration d'UNE machine dure **1,4 s**. Tenir
     * la connexion pour la rendre « vivante » n'apporterait rien a ce prix-la —
     * le geste est par ligne, pas sur le parc.
     */
    var panneauReconf = document.querySelector('[data-rw="superv-panneau-reconf"]');
    var messageReconf = document.querySelector('[data-rw="superv-reconf-message"]');
    var annulerReconf = document.querySelector('[data-rw="superv-reconf-annuler"]');
    var confirmerReconf = document.querySelector('[data-rw="superv-reconf-confirmer"]');
    var coutReconf = document.querySelector('[data-rw="superv-reconf-cout"]');
    var journalReconf = document.querySelector('[data-rw="superv-reconf-journal"]');

    /**
     * Les QUATRE issues d'un flux de reconfiguration, tirees de son CONTENU.
     *
     * `partielle` est celle que le legacy perd : la configuration EST ecrite, une
     * commande distante a echoue, et le marqueur terminal dit quand meme reussi.
     */
    function verdictDuFlux(texte) {
        var lignes = texte.split('\n');
        var echecMachine = lignes.some(function (l) { return l.indexOf('ERROR_MACHINE::') === 0; });
        var succesMachine = lignes.some(function (l) { return l.indexOf('SUCCESS_MACHINE::') === 0; });
        var erreurEcriture = lignes.some(function (l) { return l.indexOf('ERROR:') === 0; });
        // `(code N)` : la partie PROTOCOLE de « Exécution terminée (code N). »
        var codes = [];
        lignes.forEach(function (l) {
            var m = l.match(/\(code (\d+)\)/);
            if (m) { codes.push(Number(m[1])); }
        });
        var commandeEchouee = codes.some(function (c) { return c !== 0; });
        var avertissements = lignes.filter(function (l) { return l.indexOf('WARN:') === 0; });

        if (echecMachine) { return { issue: 'echec', codes: codes, avertissements: avertissements }; }
        if (! succesMachine) { return { issue: 'inacheve', codes: codes, avertissements: avertissements }; }
        if (commandeEchouee || erreurEcriture) {
            return { issue: 'partielle', codes: codes, avertissements: avertissements };
        }

        return { issue: 'reussite', codes: codes, avertissements: avertissements };
    }

    function fermeReconf() {
        if (! panneauReconf) { return; }
        panneauReconf.hidden = true;
        panneauReconf.removeAttribute('data-cible');
        panneauReconf.removeAttribute('data-nom');
    }

    if (panneauReconf && messageReconf && annulerReconf && confirmerReconf && coutReconf) {
        [].slice.call(document.querySelectorAll('[data-rw="superv-reconfigurer"]'))
            .forEach(function (bouton) {
                bouton.addEventListener('click', function () {
                    // OUVRIR N'ENVOIE RIEN. Le legacy, lui, part au premier clic.
                    panneauReconf.setAttribute('data-cible', bouton.dataset.machine || '');
                    panneauReconf.setAttribute('data-nom', bouton.dataset.nom || '');
                    coutReconf.textContent = libelles.reconf_cout
                        .replace('{nom}', bouton.dataset.nom || '')
                        .replace('{chemin}', cheminCourant());
                    var ligneFusion = document.querySelector('[data-rw="superv-reconf-effet-fusion"]');
                    if (ligneFusion) {
                        ligneFusion.textContent = libelles.reconf_effet_fusion
                            .replace('{chemin}', cheminCourant());
                    }
                    panneauReconf.hidden = false;
                    messageReconf.className = 'rw-annonce';
                    messageReconf.textContent = '';
                    if (journalReconf) { journalReconf.hidden = true; journalReconf.textContent = ''; }
                    annulerReconf.focus();
                });
            });

        annulerReconf.addEventListener('click', function () { fermeReconf(); });

        confirmerReconf.addEventListener('click', function () {
            var machine = panneauReconf.getAttribute('data-cible') || '';
            var nom = panneauReconf.getAttribute('data-nom') || '';
            if (machine === '') { return; }
            confirmerReconf.disabled = true;
            annulerReconf.disabled = true;
            messageReconf.className = 'rw-annonce';
            messageReconf.textContent = libelles.reconf_en_cours.replace('{nom}', nom);

            var route = routeCourante('reconfiguration');
            if (! route) {
                messageReconf.className = 'rw-annonce rw-annonce--echec';
                messageReconf.textContent = libelles.reconf_echec;
                confirmerReconf.disabled = false;
                annulerReconf.disabled = false;
                fermeReconf();

                return;
            }

            var jeton = document.querySelector('meta[name="csrf-token"]');
            fetch(route, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': jeton ? jeton.content : '',
                },
                /*
                 * UNE SEULE MACHINE, DANS LA LISTE QUE LA ROUTE ATTEND. Le
                 * backend lit `machine_ids` en premier ; le portage n'y met
                 * jamais qu'un element, parce qu'il n'a aucune case a cocher.
                 */
                body: JSON.stringify({ machine_ids: [Number(machine)] }),
            }).then(function (reponse) {
                // LE STATUT D'ABORD. Un 400 « Aucune configuration globale » n'est
                // pas un flux : c'est un refus, et il ne se lit pas comme un log.
                if (! reponse.ok) {
                    messageReconf.className = 'rw-annonce rw-annonce--echec';
                    messageReconf.textContent = libelles.reconf_refus
                        .replace('{statut}', String(reponse.status));

                    return null;
                }

                return reponse.text();
            }).then(function (texte) {
                if (texte === null || texte === undefined) { return; }
                if (journalReconf) {
                    journalReconf.textContent = texte;
                    journalReconf.hidden = false;
                }
                var verdict = verdictDuFlux(texte);
                var codes = verdict.codes.filter(function (c) { return c !== 0; }).join(', ');

                if (verdict.issue === 'reussite') {
                    messageReconf.className = 'rw-annonce rw-annonce--ok';
                    messageReconf.textContent = libelles.reconf_reussie.replace('{nom}', nom);
                } else if (verdict.issue === 'partielle') {
                    // CE CAS EST TOUT LE SUJET DE V10.
                    messageReconf.className = 'rw-annonce rw-annonce--attention';
                    messageReconf.textContent = libelles.reconf_partielle
                        .replace('{nom}', nom)
                        .replace('{codes}', codes || '?');
                } else if (verdict.issue === 'echec') {
                    messageReconf.className = 'rw-annonce rw-annonce--echec';
                    messageReconf.textContent = libelles.reconf_echouee.replace('{nom}', nom);
                } else {
                    messageReconf.className = 'rw-annonce rw-annonce--echec';
                    messageReconf.textContent = libelles.reconf_inachevee.replace('{nom}', nom);
                }

                if (verdict.avertissements.length > 0) {
                    messageReconf.textContent += ' ' + libelles.reconf_avertissements
                        .replace('{nombre}', String(verdict.avertissements.length));
                }
            }).catch(function () {
                messageReconf.className = 'rw-annonce rw-annonce--echec';
                messageReconf.textContent = libelles.reconf_echec;
            }).finally(function () {
                fermeReconf();
                confirmerReconf.disabled = false;
                annulerReconf.disabled = false;
            });
        });
    }

    /* ── L'ecriture du fichier distant ───────────────────────── sous-lot V9
     *
     * TROIS ISSUES, LUES SUR UN BOOLEEN. Le backend distingue « ecrit et
     * redemarre », « ecrit mais le service n'a pas redemarre » et « pas ecrit » ;
     * il l'exprime par `restarted`, ajoute exprès pour que le client n'ait pas a
     * analyser une phrase francaise. Le legacy, lui, perd le cas du milieu : son
     * `toast(__('config_remote_saved') || res.message, 'success')` n'atteint
     * jamais `res.message`, puisqu'une cle absente est RENDUE TELLE QUELLE donc
     * non vide. L'avertissement que le backend prend la peine de construire
     * n'arrive donc jamais a l'ecran — et l'ecran affiche `config_remote_saved`
     * en vert.
     *
     * LE MESSAGE DU BACKEND N'EST PAS REPRIS TEL QUEL : il est en francais
     * uniquement et porte la sortie d'erreur brute de la commande distante
     * (« sh: 1: systemctl: not found »). Le portage dit l'ISSUE, traduite, et
     * garde la trace technique hors de l'ecran.
     */
    var boutonSauver = document.querySelector('[data-rw="superv-sauver"]');
    var panneauSauver = document.querySelector('[data-rw="superv-panneau-sauver"]');
    var messageSauver = document.querySelector('[data-rw="superv-sauver-message"]');
    var annulerSauver = document.querySelector('[data-rw="superv-sauver-annuler"]');
    var confirmerSauver = document.querySelector('[data-rw="superv-sauver-confirmer"]');
    var coutSauver = document.querySelector('[data-rw="superv-sauver-cout"]');

    /**
     * LA ROUTE SUIT LA PLATEFORME, comme le chemin — correctif de V7.
     *
     * Les quatre URL etaient FIGEES sur `/supervision/zabbix/...` pendant que le
     * chemin affiche suivait le selecteur : choisir Telegraf annoncait
     * `/etc/telegraf/telegraf.conf` et lisait `/etc/zabbix/zabbix_agent2.conf`.
     * C'est le defaut E-79 que V7 reprochait au legacy, revenu par la ROUTE au
     * lieu du CHEMIN. Les deux viennent maintenant du serveur, indexes par la
     * meme cle.
     *
     * Repli fail-closed : sans route connue on rend une chaine vide, et
     * l'appelant ne part pas. Mieux vaut un geste qui ne se fait pas qu'un geste
     * qui vise le mauvais fichier.
     */
    function routeCourante(geste) {
        var plateforme = choixPlateforme ? choixPlateforme.value : 'zabbix';
        try {
            var table = JSON.parse(libelles.routes_machine || '{}');

            return (table[plateforme] && table[plateforme][geste]) || '';
        } catch (e) {
            return '';
        }
    }

    /**
     * LE CHEMIN ANNONCE EST CELUI QUE LA PAGE AFFICHE, qui vient du SERVEUR.
     * Le relire ici plutot que de recalculer depuis une table locale evite
     * exactement le defaut du legacy (E-79) : deux chemins a l'ecran, dont un
     * faux. Une seule source, donc un seul chemin possible.
     */
    function cheminCourant() {
        return cheminAffiche ? cheminAffiche.textContent.trim() : '';
    }

    if (boutonSauver && panneauSauver && messageSauver && annulerSauver
        && confirmerSauver && contenu && serveur) {
        boutonSauver.addEventListener('click', function () {
            messageSauver.className = 'rw-annonce';
            // Les deux gardes AVANT d'ouvrir : ouvrir un panneau de decision pour
            // un geste qui sera refuse fait decider dans le vide.
            if (serveur.value === '') {
                messageSauver.textContent = libelles.editeur_sans_serveur;

                return;
            }
            if (contenu.value.trim() === '') {
                messageSauver.textContent = libelles.editeur_sauver_vide;

                return;
            }
            // Le chemin annonce suit la plateforme choisie, comme la lecture.
            if (coutSauver && cheminCourant()) {
                coutSauver.textContent = libelles.editeur_sauver_cout
                    .replace('{chemin}', cheminCourant());
            }
            panneauSauver.hidden = false;
            boutonSauver.hidden = true;
            annulerSauver.focus();
        });

        annulerSauver.addEventListener('click', function () {
            panneauSauver.hidden = true;
            boutonSauver.hidden = false;
            boutonSauver.focus();
        });

        confirmerSauver.addEventListener('click', function () {
            confirmerSauver.disabled = true;
            annulerSauver.disabled = true;
            messageSauver.className = 'rw-annonce';
            messageSauver.textContent = libelles.editeur_sauver_en_cours;

            var jeton = document.querySelector('meta[name="csrf-token"]');
            var routeEcriture = routeCourante('ecriture');
            if (! routeEcriture) {
                messageSauver.className = 'rw-annonce rw-annonce--echec';
                messageSauver.textContent = libelles.editeur_sauver_echec;
                confirmerSauver.disabled = false; annulerSauver.disabled = false;

                return;
            }
            fetch(routeEcriture, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': jeton ? jeton.content : '',
                },
                body: JSON.stringify({
                    machine_id: Number(serveur.value),
                    config: contenu.value,
                }),
            }).then(function (reponse) {
                // LE STATUT D'ABORD : un refus n'est pas un echec d'ecriture.
                if (! reponse.ok) {
                    messageSauver.className = 'rw-annonce rw-annonce--echec';
                    messageSauver.textContent = libelles.editeur_sauver_refus
                        .replace('{statut}', String(reponse.status));

                    return null;
                }

                return reponse.json();
            }).then(function (donnees) {
                if (! donnees) { return; }
                if (! donnees.success) {
                    messageSauver.className = 'rw-annonce rw-annonce--echec';
                    messageSauver.textContent = libelles.editeur_sauver_echec;

                    return;
                }
                if (donnees.restarted === false) {
                    // LE TROISIEME CAS : le fichier EST ecrit, le service ne
                    // tourne pas. Ni une reussite ni un echec.
                    messageSauver.className = 'rw-annonce rw-annonce--attention';
                    messageSauver.textContent = libelles.editeur_sauve_sans_redemarrage;

                    return;
                }
                messageSauver.className = 'rw-annonce rw-annonce--ok';
                messageSauver.textContent = libelles.editeur_sauve_et_redemarre;
            }).catch(function () {
                messageSauver.className = 'rw-annonce rw-annonce--echec';
                messageSauver.textContent = libelles.editeur_sauver_echec;
            }).finally(function () {
                panneauSauver.hidden = true;
                boutonSauver.hidden = false;
                confirmerSauver.disabled = false;
                annulerSauver.disabled = false;
            });
        });
    }

    /* ── La restauration d'une sauvegarde ────────────────────── sous-lot V9
     *
     * LE LEGACY N'A AUCUNE CONFIRMATION : sa liste s'ouvre dans une fenetre
     * modale et chaque ligne porte un bouton qui, d'un SEUL clic, ecrase la
     * configuration courante et redemarre l'agent. Ici la restauration passe par
     * le panneau de decision partage, qui NOMME la sauvegarde visee.
     */

    function fermeRestauration() {
        if (! panneauRestaurer) { return; }
        panneauRestaurer.hidden = true;
        panneauRestaurer.removeAttribute('data-cible');
    }

    if (panneauRestaurer && messageRestaurer && annulerRestaurer && confirmerRestaurer) {
        annulerRestaurer.addEventListener('click', function () {
            fermeRestauration();
        });

        confirmerRestaurer.addEventListener('click', function () {
            var nom = panneauRestaurer.getAttribute('data-cible') || '';
            if (nom === '' || ! serveur || serveur.value === '') { return; }
            confirmerRestaurer.disabled = true;
            annulerRestaurer.disabled = true;
            messageRestaurer.className = 'rw-annonce';
            messageRestaurer.textContent = libelles.restaurer_en_cours.replace('{nom}', nom);

            var jeton = document.querySelector('meta[name="csrf-token"]');
            var routeRestauration = routeCourante('restauration');
            if (! routeRestauration) {
                messageRestaurer.className = 'rw-annonce rw-annonce--echec';
                messageRestaurer.textContent = libelles.restaurer_echec;
                confirmerRestaurer.disabled = false; annulerRestaurer.disabled = false;

                return;
            }
            fetch(routeRestauration, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': jeton ? jeton.content : '',
                },
                body: JSON.stringify({
                    machine_id: Number(serveur.value),
                    backup_name: nom,
                }),
            }).then(function (reponse) {
                if (! reponse.ok) {
                    messageRestaurer.className = 'rw-annonce rw-annonce--echec';
                    messageRestaurer.textContent = libelles.restaurer_refus
                        .replace('{statut}', String(reponse.status));

                    return null;
                }

                return reponse.json();
            }).then(function (donnees) {
                if (! donnees) { return; }
                if (! donnees.success) {
                    messageRestaurer.className = 'rw-annonce rw-annonce--echec';
                    messageRestaurer.textContent = libelles.restaurer_echec;

                    return;
                }
                if (donnees.restarted === false) {
                    messageRestaurer.className = 'rw-annonce rw-annonce--attention';
                    messageRestaurer.textContent = libelles.restaure_sans_redemarrage
                        .replace('{nom}', nom);

                    return;
                }
                messageRestaurer.className = 'rw-annonce rw-annonce--ok';
                messageRestaurer.textContent = libelles.restaure_et_redemarre
                    .replace('{nom}', nom);
            }).catch(function () {
                messageRestaurer.className = 'rw-annonce rw-annonce--echec';
                messageRestaurer.textContent = libelles.restaurer_echec;
            }).finally(function () {
                fermeRestauration();
                confirmerRestaurer.disabled = false;
                annulerRestaurer.disabled = false;
            });
        });
    }

    /* ── Le releve du parc, en tache de fond ─────────────────── sous-lot V8
     *
     * DEUX TEMPS, ET LE PREMIER N'ENVOIE RIEN. Le bouton ouvre un panneau de
     * decision qui chiffre le cout et NOMME les machines de production ; seule
     * la confirmation part. Le legacy, lui, lance la rafale au clic, sans rien
     * annoncer : `ids x 4 plateformes` requetes en parallele, filtre de table
     * ignore, production comprise.
     *
     * LE VERDICT RESTE A L'ECRAN. Une reponse de mise en file arrive en moins
     * d'une seconde, mais le balayage lui-meme dure des minutes : le resultat se
     * lit dans le centre de taches, et l'annonce y renvoie par un lien plutot
     * que de faire croire que tout est fini.
     */
    var boutonReleve = document.querySelector('[data-rw="superv-relever-parc"]');
    var panneauReleve = document.querySelector('[data-rw="superv-panneau-releve"]');
    var messageReleve = document.querySelector('[data-rw="superv-releve-message"]');
    var annulerReleve = document.querySelector('[data-rw="superv-releve-annuler"]');
    var confirmerReleve = document.querySelector('[data-rw="superv-releve-confirmer"]');

    if (boutonReleve && panneauReleve && messageReleve && annulerReleve && confirmerReleve) {
        boutonReleve.addEventListener('click', function () {
            // OUVRIR N'EST PAS ENVOYER : aucune requete ne part d'ici.
            panneauReleve.hidden = false;
            boutonReleve.hidden = true;
            messageReleve.className = 'rw-annonce';
            messageReleve.textContent = '';
            annulerReleve.focus();
        });

        annulerReleve.addEventListener('click', function () {
            panneauReleve.hidden = true;
            boutonReleve.hidden = false;
            boutonReleve.focus();
        });

        confirmerReleve.addEventListener('click', function () {
            confirmerReleve.disabled = true;
            annulerReleve.disabled = true;
            messageReleve.className = 'rw-annonce';
            messageReleve.textContent = libelles.releve_en_cours;

            var jeton = document.querySelector('meta[name="csrf-token"]');
            fetch(libelles.url_releve_parc, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': jeton ? jeton.content : '',
                },
                /*
                 * Corps VIDE : la portee est le parc, et c'est le SERVEUR qui
                 * l'etablit. Envoyer une liste d'identifiants lue dans le
                 * tableau reviendrait a laisser le navigateur decider quelles
                 * machines sont jointes — le defaut meme du legacy, dont la
                 * liste ne correspond plus a ce qui est affiche des qu'on
                 * filtre.
                 */
                body: '{}',
            }).then(function (reponse) {
                // LE STATUT D'ABORD. Un refus ne se confond ni avec un parc
                // vide ni avec une panne : ce sont trois cas.
                if (! reponse.ok) {
                    messageReleve.className = 'rw-annonce rw-annonce--echec';
                    messageReleve.textContent = libelles.releve_refus
                        .replace('{statut}', String(reponse.status));

                    return null;
                }

                return reponse.json();
            }).then(function (donnees) {
                if (! donnees) { return; }
                if (! donnees.queued) {
                    messageReleve.className = 'rw-annonce rw-annonce--attention';
                    messageReleve.textContent = libelles.releve_aucune;

                    return;
                }
                messageReleve.className = 'rw-annonce rw-annonce--ok';
                messageReleve.textContent = libelles.releve_lance
                    .replace('{machines}', String(donnees.queued))
                    .replace('{tache}', String(donnees.task_id || '?'));
                // Le suivi vit dans le centre de taches, deja porte.
                var lien = document.createElement('a');
                lien.className = 'rw-lien';
                lien.href = libelles.url_taches;
                lien.textContent = ' ' + libelles.releve_voir_taches;
                messageReleve.appendChild(lien);
            }).catch(function () {
                messageReleve.className = 'rw-annonce rw-annonce--echec';
                messageReleve.textContent = libelles.releve_echec;
            }).finally(function () {
                panneauReleve.hidden = true;
                boutonReleve.hidden = false;
                confirmerReleve.disabled = false;
                annulerReleve.disabled = false;
            });
        });
    }
}());
