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

    /** Le nom du serveur choisi, pour que les messages nomment leur cible. */
    function nomDuServeur() {
        if (! serveur) { return ''; }
        var opt = serveur.options[serveur.selectedIndex];
        return opt ? opt.textContent.trim() : '';
    }

    function appelleLaMachine(url, sur, alors) {
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

            appelleLaMachine(libelles.url_lecture_config, serveur.value, function (donnees) {
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
            message.textContent = '';
            if (contenu) { contenu.value = ''; }
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
            appelleLaMachine(libelles.url_sauvegardes, serveur.value, function (donnees) {
                if (donnees.absent || donnees.refus) {
                    sauvegardes.textContent = libelles.editeur_refus
                        .replace('{statut}', String(donnees.refus || 404));

                    return;
                }
                var liste = donnees.backups || [];
                sauvegardes.textContent = liste.length === 0
                    ? libelles.sauvegardes_aucune
                    : libelles.sauvegardes_nombre.replace('{nombre}', String(liste.length))
                        + ' ' + liste.map(function (b) { return b.filename; }).join(', ');
            }).catch(function () {
                sauvegardes.textContent = libelles.editeur_echec;
            }).finally(function () {
                boutonSauvegardes.disabled = false;
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
