/*
 * Pare-feu iptables — sous-lot I1 : la consultation.
 *
 * ══ CE FICHIER EXISTE D'ABORD POUR REPARER UNE UI MUETTE ═════════════════
 *
 * `legacy/iptables/js/main.js` appelle `showNotification` TREIZE fois, et cette
 * fonction vise `#notifications` — un identifiant qui n'apparait nulle part dans
 * `legacy/iptables/index.php` (mesure : zero occurrence). Les treize appels
 * levent une `TypeError`, y compris ceux places dans un `catch`.
 *
 * Consequence mesuree : appliquer un jeu de regles REUSSIT sur la machine et
 * l'ecran ne dit rien — ni succes, ni erreur. Tous les sous-lots suivants
 * heritent de la zone d'annonce posee ici.
 *
 * ══ I1 N'EMET QUE `action: "get"` ════════════════════════════════════════
 *
 * `POST /iptables` porte DEUX gestes sous une seule route : `get` lit, `apply`
 * ECRIT le pare-feu. La passerelle filtre sur le CHEMIN, jamais sur le corps :
 * elle ne peut donc pas les distinguer. La fermeture est ici, et elle est PAR
 * L'ABSENCE — aucun champ d'edition, aucun bouton d'application, aucune branche
 * qui compose autre chose que `get`. C'est la seule forme qu'une requete forgee
 * ne contourne pas.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var textes = {};
    try {
        var blocTextes = document.getElementById('ipt-textes');
        if (blocTextes) { textes = JSON.parse(blocTextes.textContent || '{}'); }
    } catch (e) { textes = {}; }

    /*
     * Le port SSH par machine, lu EN BASE par le controleur. Les cinq gabarits
     * du legacy codent `--dport 22` en dur ; les trois machines du parc ecoutent
     * sur 22, donc le defaut n'est pas arme — et c'est ce qui le rend invisible.
     * La table est chargee des I1 pour que I4 et I5 n'aient jamais a supposer.
     */
    var ports = {};
    try {
        var blocPorts = document.getElementById('ipt-ports');
        if (blocPorts) { ports = JSON.parse(blocPorts.textContent || '{}'); }
    } catch (e) { ports = {}; }

    var selecteur = document.querySelector('[data-rw="ipt-serveur"]');
    var message   = document.querySelector('[data-rw="ipt-etat-message"]');
    var annonce   = document.querySelector('[data-rw="ipt-annonce"]');
    var bouton    = document.querySelector('[data-rw="ipt-relever"]');
    var blocs     = document.querySelector('[data-rw="ipt-blocs"]');

    /*
     * I2 — declares ICI et non plus bas : `surChoix()` les emploie, et laisser
     * la portee dependre du HISSAGE se relit mal. Un fichier qui grossit par
     * accumulation merite qu'on le tienne lisible a chaque ajout.
     */
    var sectionCopie  = document.querySelector('[data-rw="ipt-copie"]');
    var boutonCharger = document.querySelector('[data-rw="ipt-copie-charger"]');
    var boutonEnreg   = document.querySelector('[data-rw="ipt-copie-enregistrer"]');
    var annonceCopie  = document.querySelector('[data-rw="ipt-copie-annonce"]');
    var blocsCopie    = document.querySelector('[data-rw="ipt-copie-blocs"]');

    // I4 — meme raison.
    var sectionValid   = document.querySelector('[data-rw="ipt-valid"]');
    var boutonValid    = document.querySelector('[data-rw="ipt-valid-lancer"]');
    var annonceValid   = document.querySelector('[data-rw="ipt-valid-annonce"]');
    var etatValidZone  = document.querySelector('[data-rw="ipt-valid-etat"]');

    // I3 — declares ici pour la meme raison que ceux d'I2.
    var sectionHisto   = document.querySelector('[data-rw="ipt-histo"]');
    var annonceHisto   = document.querySelector('[data-rw="ipt-histo-annonce"]');
    var cadreHisto     = document.querySelector('[data-rw="ipt-histo-cadre"]');
    var corpsHisto     = document.querySelector('[data-rw="ipt-histo-corps"]');
    var etatHistoZone  = document.querySelector('[data-rw="ipt-histo-etat"]');

    /*
     * CE QUE LE DERNIER RELEVE A RENDU.
     *
     * `null` tant qu'aucun releve n'a abouti — c'est ce qui tient le bouton
     * d'enregistrement DESACTIVE. La regle « il n'y a rien a enregistrer » se
     * lit donc AVANT le geste, au lieu d'etre un refus apres le clic.
     */
    var dernierReleve = null;

    /*
     * CE QUE LA DERNIERE LECTURE DE LA COPIE A RENDU — l'objet que I4 valide.
     *
     * Distinct de `dernierReleve` a dessein : le releve vient de LA MACHINE, la
     * copie vient de LA BASE, et les deux peuvent differer — c'est meme la
     * situation que ce module existe pour rendre visible. Valider le releve
     * reviendrait a demander a la machine de se valider elle-meme.
     */
    var derniereCopie = null;

    if (!selecteur || !bouton || !blocs) { return; }

    function t(cle, remplacements) {
        var s = textes[cle] || cle;
        if (remplacements) {
            Object.keys(remplacements).forEach(function (k) {
                s = s.split(':' + k).join(String(remplacements[k]));
            });
        }
        return s;
    }

    /**
     * Un appel qui ne REJETTE jamais.
     *
     * Le defaut corrige dans `mises-a-jour.js` : un `try` qui n'entourait que
     * `r.json()` laissait `fetch()` rejeter sur une coupure reseau ou une session
     * expiree, l'appelant s'arretait AVANT de reactiver son bouton, et l'ecran
     * restait fige sur « en cours » indefiniment.
     *
     * On rend donc toujours une forme constante. Le statut `0` distingue « la
     * requete n'est pas partie » de « elle est partie et a ete refusee » — deux
     * causes qu'un ecran ne doit pas confondre.
     */
    function appelle(chemin, corps) {
        return fetch(PASSERELLE + chemin, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(corps)
        }).then(function (r) {
            return r.text().then(function (brut) {
                var donnees = {};
                try { donnees = JSON.parse(brut); } catch (e) { donnees = {}; }
                return { ok: r.ok, statut: r.status, corps: donnees };
            });
        }).catch(function (e) {
            if (window.console) { console.error('[pare-feu]', e); }
            return { ok: false, statut: 0, corps: {} };
        });
    }

    function annonceDire(texte, variante) {
        if (!annonce) { return; }
        annonce.textContent = texte || '';
        annonce.className = 'rw-annonce' + (variante ? ' rw-annonce--' + variante : '');
    }

    // ── Le choix de la machine ──────────────────────────────────────────

    function optionChoisie() {
        return selecteur.options[selecteur.selectedIndex] || null;
    }

    /**
     * Ce que la page dit AVANT le geste.
     *
     * Deux faits, et le second n'a l'air de rien tant qu'on ne modifie pas les
     * regles : le port SSH de CETTE machine. Un jeu de regles qui ne le laisse
     * pas ouvert coupe l'acces, RootWarden compris, et la reprise exige une
     * console physique.
     */
    function surChoix() {
        var opt = optionChoisie();
        var id = selecteur.value;
        blocs.hidden = true;
        blocs.replaceChildren();
        annonceDire('');
        // UNE SEULE NOTION DE « LA MACHINE » : changer de cible efface ce qui
        // appartenait a la precedente. Sans cela on enregistrerait sous une
        // machine les regles relevees sur une autre (E-162, porte par F3).
        dernierReleve = null;
        if (boutonEnreg) { boutonEnreg.disabled = true; }
        if (sectionCopie) { sectionCopie.hidden = !id; }
        if (blocsCopie) { blocsCopie.hidden = true; blocsCopie.replaceChildren(); }
        annonceCopieDire('');
        // I3 : l'historique suit la MACHINE, pas le releve. Il est en base.
        if (sectionHisto) { sectionHisto.hidden = !id; }
        if (cadreHisto) { cadreHisto.hidden = true; }
        if (corpsHisto) { corpsHisto.replaceChildren(); }
        if (etatHistoZone) { etatHistoZone.replaceChildren(); }
        annonceHistoDire('');
        if (id) { chargeHistorique(); }
        // I4 : la validation porte sur la copie de CETTE machine. Changer de
        // cible la perime — comme `dernierReleve` plus haut, et pour la meme
        // raison (E-162 : enregistrer sous une machine ce qui vient d'une autre).
        derniereCopie = null;
        if (sectionValid) { sectionValid.hidden = !id; }
        if (boutonValid) { boutonValid.disabled = true; }
        if (etatValidZone) { etatValidZone.replaceChildren(); }
        /*
         * I5 : le jeu compose depend du PORT de la machine choisie. Changer de
         * cible le perime donc TOTALEMENT — comme `dernierReleve` et
         * `derniereCopie` plus haut, et pour la meme raison : appliquer sur une
         * machine un jeu compose pour le port d'une autre est exactement le
         * defaut que Q1 existe pour empecher.
         *
         * Le panneau de consentement se referme aussi : ouvert sur une machine,
         * il nommerait la precedente pendant que le geste porterait sur la
         * nouvelle.
         */
        if (sectionAppl) { sectionAppl.hidden = !id; }
        if (selGabarit) { selGabarit.value = ''; }
        fermeConsentement();
        annonceApplDire('');
        composeLeJeu();

        /*
         * I6 : la version lue appartient a la machine PRECEDENTE, et son verdict
         * Q2 a ete calcule sur le port de celle-la. Changer de cible perime donc
         * tout — la meme raison que `dernierReleve`, `derniereCopie` et le jeu
         * de I5. Restaurer sur une machine une version lue sur une autre est
         * exactement ce que le `WHERE id = ? AND server_id = ?` du service
         * empeche cote serveur ; l'ecran ne doit pas non plus le proposer.
         */
        rbRemetAZero();
        annonceValidDire('');

        if (!id || !opt) {
            bouton.disabled = true;
            if (message) { message.textContent = t('choisir'); }
            return;
        }

        bouton.disabled = false;

        var morceaux = [];
        if (opt.getAttribute('data-sensible') === '1') {
            morceaux.push(t('sensible_avert'));
        }
        var port = ports[String(id)];
        if (port) {
            morceaux.push(t('port_ssh_annonce', { port: port }));
        }
        if (message) { message.textContent = morceaux.join(' '); }
    }

    selecteur.addEventListener('change', surChoix);

    // ── Le rendu des quatre blocs ───────────────────────────────────────

    /*
     * LE BACKEND FABRIQUE SES MARQUEURS D'ABSENCE, ET JETTE LES CODES DE SORTIE.
     *
     * `iptables_manager.get_iptables_rules` compose :
     *     cat /etc/iptables/rules.v4 2>/dev/null || echo ''
     *     cat /etc/iptables/rules.v6 2>/dev/null || echo 'No IPv6 rules'
     * et retient `out, _, _` — les trois codes de sortie sont perdus.
     *
     * Consequence : une chaine VIDE recouvre trois situations — le fichier est
     * absent, le fichier existe et est vide, la lecture a echoue. **Le portage ne
     * peut pas les distinguer : cette information a ete jetee en amont.** Il peut
     * cesser de faire semblant, et c'est ce qu'il fait — meme regle qu'E-161 sur
     * `fail2ban`, ou le marqueur `[FICHIER ABSENT]` devenait le CONTENU affiche
     * du fichier.
     *
     * `No IPv6 rules` est reconnu comme le marqueur qu'il est, et rendu comme
     * une phrase, jamais comme le contenu d'un fichier.
     */
    var MARQUEUR_V6_ABSENT = 'No IPv6 rules';

    function blocDeTexte(titre, valeur, estFichier) {
        var article = document.createElement('article');
        article.className = 'rw-section';

        var h = document.createElement('p');
        h.className = 'rw-sous-titre-fort';
        h.textContent = titre;
        article.appendChild(h);

        var brut = String(valeur == null ? '' : valeur);
        var nettoye = brut.trim();

        if (nettoye === MARQUEUR_V6_ABSENT) {
            article.appendChild(etatVide(t('fichier_absent_titre'), t('fichier_absent')));
            return article;
        }
        if (nettoye === '') {
            // Trois situations sous une seule valeur — on dit laquelle on ne
            // peut PAS trancher, plutot que d'en choisir une au hasard.
            article.appendChild(estFichier
                ? etatVide(t('fichier_absent_titre'), t('fichier_absent'))
                : etatVide(t('bloc_vide_titre'), t('bloc_vide')));
            return article;
        }

        /*
         * `textContent`, jamais d'interpolation : ce texte vient d'un
         * pseudo-terminal distant. Il porte l'ECHO de la commande, donc du
         * contenu que la machine ecrit sur son terminal.
         */
        var pre = document.createElement('pre');
        pre.className = 'rw-fichier';
        pre.textContent = brut;
        article.appendChild(pre);
        return article;
    }

    function etatVide(titre, texte) {
        var d = document.createElement('div');
        d.className = 'rw-vide rw-vide--compact';
        var t1 = document.createElement('p');
        t1.className = 'rw-vide__titre';
        t1.textContent = titre;
        var t2 = document.createElement('p');
        t2.className = 'rw-vide__texte';
        t2.textContent = texte;
        d.append(t1, t2);
        return d;
    }

    function rendLeReleve(donnees) {
        blocs.replaceChildren();
        blocs.appendChild(blocDeTexte(t('bloc_actives_v4'), donnees.current_rules_v4, false));
        blocs.appendChild(blocDeTexte(t('bloc_actives_v6'), donnees.current_rules_v6, false));
        blocs.appendChild(blocDeTexte(t('bloc_fichier_v4'), donnees.file_rules_v4, true));
        blocs.appendChild(blocDeTexte(t('bloc_fichier_v6'), donnees.file_rules_v6, true));
        blocs.hidden = false;
    }

    // ── Le relevé ───────────────────────────────────────────────────────

    function releve() {
        var id = selecteur.value;
        var opt = optionChoisie();
        if (!id) {
            annonceDire(t('aucune_machine_choisie'), 'echec');
            return;
        }

        var repos = bouton.textContent;
        bouton.disabled = true;
        bouton.textContent = t('chargement');
        annonceDire(t('chargement'));
        blocs.hidden = true;
        blocs.replaceChildren();

        appelle('/iptables', { machine_id: Number(id), action: 'get' }).then(function (r) {
            /*
             * LE BOUTON EST RENDU DANS LE MEME BLOC SYNCHRONE QUE LE VERDICT.
             * C'est le signal sur lequel une suite peut s'accrocher sans
             * dependre d'un libelle ni d'une langue — attendre l'annonce
             * recolterait le message de travail, jamais le resultat.
             */
            bouton.disabled = false;
            bouton.textContent = repos;

            // Statut 0 : la requete n'est pas partie. Ce n'est ni un succes ni
            // un refus, et le dire evite d'accuser la machine.
            if (r.statut === 0) {
                annonceDire(t('echec_reseau'), 'echec');
                return;
            }
            if (!r.ok || !r.corps || r.corps.success !== true) {
                var m = (r.corps && r.corps.message) ? String(r.corps.message) : t('echec');
                annonceDire(m, 'echec');
                return;
            }

            dernierReleve = r.corps;
            if (boutonEnreg) { boutonEnreg.disabled = false; }
            rendLeReleve(r.corps);
            annonceDire(t('releve_ok', {
                machine: opt ? (opt.getAttribute('data-nom') || '') : ''
            }), 'ok');
        });
    }

    bouton.addEventListener('click', releve);


    // ════════════════════════════════════════════════════════════════════
    //  SOUS-LOT I2 — LA COPIE EN BASE
    // ════════════════════════════════════════════════════════════════════
    //
    // Ces deux gestes visent le CONTROLEUR DU PORTAGE, pas la passerelle : ils
    // lisent et ecrivent la base du portail et ne joignent aucune machine.
    // Ils portent donc le jeton de falsification, que le cadre attend sur les
    // methodes mutantes du groupe `web`.

    function jetonCsrf() {
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.content : '';
    }

    /** Meme contrat qu'`appelle` : ne rejette jamais, forme constante. */
    function appellePortage(chemin, corps) {
        return fetch(chemin, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CSRF-TOKEN': jetonCsrf()
            },
            body: JSON.stringify(corps)
        }).then(function (r) {
            return r.text().then(function (brut) {
                var d = {};
                try { d = JSON.parse(brut); } catch (e) { d = {}; }
                return { ok: r.ok, statut: r.status, corps: d };
            });
        }).catch(function (e) {
            if (window.console) { console.error('[pare-feu/copie]', e); }
            return { ok: false, statut: 0, corps: {} };
        });
    }

    function annonceCopieDire(texte, variante) {
        if (!annonceCopie) { return; }
        annonceCopie.textContent = texte || '';
        annonceCopie.className = 'rw-annonce' + (variante ? ' rw-annonce--' + variante : '');
    }

    function chargeLaCopie() {
        var id = selecteur.value;
        if (!id) { annonceCopieDire(t('aucune_machine_choisie'), 'echec'); return; }

        var repos = boutonCharger.textContent;
        boutonCharger.disabled = true;
        boutonCharger.textContent = t('chargement');
        annonceCopieDire(t('chargement'));
        blocsCopie.hidden = true;
        blocsCopie.replaceChildren();

        appellePortage('/pare-feu/copie', { machine_id: Number(id) }).then(function (r) {
            boutonCharger.disabled = false;
            boutonCharger.textContent = repos;

            /*
             * TOUTE SORTIE QUI N'EST PAS UNE COPIE LUE PERIME `derniereCopie`.
             *
             * Sans ces deux lignes, un chargement en echec laisserait en place
             * la copie de l'appel PRECEDENT et le bouton de validation resterait
             * actif : on validerait un objet que l'ecran ne montre plus.
             */
            derniereCopie = null;
            if (boutonValid) { boutonValid.disabled = true; }

            if (r.statut === 0) { annonceCopieDire(t('echec_reseau'), 'echec'); return; }
            if (!r.ok || r.corps.success !== true) {
                // `aucune_copie` n'est PAS un echec : c'est un etat normal, et il
                // porte son propre champ. Le distinguer d'un refus evite de
                // peindre en rouge une machine dont personne n'a encore
                // enregistre les regles.
                annonceCopieDire(String(r.corps.message || t('echec')),
                                 r.corps.aucune_copie ? '' : 'echec');
                return;
            }

            derniereCopie = r.corps;
            /*
             * LE BOUTON DE VALIDATION SUIT LE CONTENU, PAS LA PRESENCE.
             *
             * `/iptables-validate` refuse une copie dont `rules_v4` est vide
             * (400, « Regles IPv4 vides. »). Une copie ecrite par le legacy
             * peut l'etre : c'est le portage qui interdit d'en enregistrer une,
             * pas la table. Plutot que d'envoyer une requete qu'on sait
             * refusee, la regle se lit ICI — et AVEC SA RAISON : un bouton
             * desactive sans explication est le defaut qu'on repare ailleurs.
             */
            if (boutonValid) {
                var aDuV4 = String(r.corps.rules_v4 || '').trim() !== '';
                boutonValid.disabled = !aDuV4;
                if (!aDuV4) { annonceValidDire(t('valid_v4_vide'), 'attention'); }
            }

            blocsCopie.replaceChildren();
            blocsCopie.appendChild(blocDeTexte(t('copie_bloc_v4'), r.corps.rules_v4, false));
            blocsCopie.appendChild(blocDeTexte(t('copie_bloc_v6'), r.corps.rules_v6, false));
            blocsCopie.hidden = false;

            var morceaux = [t('copie_le', { date: String(r.corps.enregistre_le || '') })];
            /*
             * PLUSIEURS COPIES : ON LE DIT.
             *
             * `iptables_rules` n'a aucune contrainte d'unicite sur `server_id`.
             * Afficher la plus recente sans annoncer qu'il en existe d'autres
             * laisserait croire qu'il n'y en a qu'une.
             */
            if (Number(r.corps.lignes || 0) > 1) {
                morceaux.push(t('copie_lignes_multiples', { nb: r.corps.lignes }));
            }
            annonceCopieDire(morceaux.join(' '), 'ok');
        });
    }

    function enregistreLaCopie() {
        var id = selecteur.value;
        if (!id) { annonceCopieDire(t('aucune_machine_choisie'), 'echec'); return; }
        if (!dernierReleve) { annonceCopieDire(t('copie_rien_a_enregistrer'), 'echec'); return; }

        var repos = boutonEnreg.textContent;
        boutonEnreg.disabled = true;
        boutonEnreg.textContent = t('chargement');
        annonceCopieDire(t('chargement'));

        /*
         * ON ENVOIE LES DEUX CHAMPS, MEME VIDES.
         *
         * Le controleur exige leur PRESENCE (`has()`) parce que
         * `ConvertEmptyStringsToNull` rend une chaine vide indiscernable d'un
         * champ absent. Une machine sans regle IPv6 est un cas normal : omettre
         * la cle ferait refuser un enregistrement legitime.
         */
        appellePortage('/pare-feu/copie/enregistrer', {
            machine_id: Number(id),
            rules_v4: String(dernierReleve.file_rules_v4 || dernierReleve.current_rules_v4 || ''),
            rules_v6: String(dernierReleve.file_rules_v6 || '')
        }).then(function (r) {
            boutonEnreg.disabled = false;
            boutonEnreg.textContent = repos;

            /*
             * TOUTE SORTIE QUI N'EST PAS UNE COPIE LUE PERIME `derniereCopie`.
             *
             * Sans ces deux lignes, un chargement en echec laisserait en place
             * la copie de l'appel PRECEDENT et le bouton de validation resterait
             * actif : on validerait un objet que l'ecran ne montre plus.
             */
            derniereCopie = null;
            if (boutonValid) { boutonValid.disabled = true; }

            if (r.statut === 0) { annonceCopieDire(t('echec_reseau'), 'echec'); return; }
            if (!r.ok || r.corps.success !== true) {
                annonceCopieDire(String(r.corps.message || t('echec')), 'echec');
                return;
            }
            annonceCopieDire(String(r.corps.message || ''), 'ok');
            // Un second temoin : on relit ce qu'on vient d'ecrire. Une reussite
            // annoncee n'est pas une reussite verifiee.
            chargeLaCopie();
        });
    }

    if (boutonCharger) { boutonCharger.addEventListener('click', chargeLaCopie); }
    if (boutonEnreg)   { boutonEnreg.addEventListener('click', enregistreLaCopie); }


    // ════════════════════════════════════════════════════════════════════
    //  SOUS-LOT I3 — L'HISTORIQUE DES VERSIONS ARCHIVEES
    // ════════════════════════════════════════════════════════════════════
    //
    // Il se charge au CHOIX de la machine, jamais apres un releve. Le legacy
    // appelle `loadHistory()` dans la branche de succes de son releve : une
    // machine injoignable masque alors son propre historique, qui est pourtant
    // en BASE et ne demande aucune machine (E-156).

    function annonceHistoDire(texte, variante) {
        if (!annonceHisto) { return; }
        annonceHisto.textContent = texte || '';
        annonceHisto.className = 'rw-annonce' + (variante ? ' rw-annonce--' + variante : '');
    }

    /** Rend l'auteur d'une version, jamais un `#7` brut. */
    function auteurTexte(auteur) {
        if (!auteur || !auteur.forme) { return t('histo_auteur_inconnu'); }
        if (auteur.forme === 'nom') { return String(auteur.valeur || ''); }
        if (auteur.forme === 'compte_supprime') {
            return t('histo_auteur_supprime', { id: String(auteur.valeur || '') });
        }
        return t('histo_auteur_inconnu');
    }

    function etatHisto(titre, texte) {
        etatHistoZone.replaceChildren();
        etatHistoZone.appendChild(etatVide(titre, texte));
    }

    function chargeHistorique() {
        var id = selecteur.value;
        if (!id) { return; }

        annonceHistoDire(t('histo_chargement'));
        cadreHisto.hidden = true;
        corpsHisto.replaceChildren();
        etatHistoZone.replaceChildren();

        appellePortage('/pare-feu/historique', { machine_id: Number(id) }).then(function (r) {
            /*
             * TROIS ISSUES, PAS UNE. Le legacy replie l'echec de lecture et
             * l'absence d'historique sur le meme message — or les deux appellent
             * des gestes opposes : reessayer, ou ne rien attendre.
             */
            if (r.statut === 0 || !r.ok || r.corps.success !== true) {
                annonceHistoDire('', '');
                etatHisto(t('histo_echec_titre'),
                          String(r.corps.message || t('histo_echec')));
                return;
            }

            if (r.corps.aucun_historique) {
                annonceHistoDire('', '');
                etatHisto(t('histo_vide_titre'), t('histo_vide'));
                return;
            }

            var versions = r.corps.versions || [];
            for (var i = 0; i < versions.length; i++) {
                var v = versions[i];
                var tr = document.createElement('tr');
                tr.dataset.rw = 'ipt-histo-ligne-' + v.id;

                var tdDate = document.createElement('td');
                tdDate.className = 'rw-tableau__fort';
                tdDate.textContent = String(v.date || '');

                var tdAuteur = document.createElement('td');
                tdAuteur.textContent = auteurTexte(v.auteur);

                var tdMotif = document.createElement('td');
                var motif = String(v.motif || '').trim();
                // Un motif absent se DIT : une cellule vide se lit aussi bien
                // « pas de motif » que « la colonne n'a pas ete lue ».
                tdMotif.textContent = motif !== '' ? motif : t('histo_sans_motif');
                if (motif === '') { tdMotif.className = 'rw-tableau__discret'; }

                /*
                 * I6 — LE BOUTON DE RETOUR ARRIERE. Il ne declenche AUCUN geste :
                 * il LIT la version pour la montrer et repondre a Q2. Le geste
                 * lui-meme attend un consentement, deux ecrans plus loin.
                 */
                var tdAction = document.createElement('td');
                var bRb = document.createElement('button');
                bRb.type = 'button';
                bRb.className = 'rw-bouton rw-bouton--minuscule';
                bRb.dataset.rw = 'ipt-rb-choisir-' + v.id;
                bRb.textContent = t('rb_bouton');
                bRb.addEventListener('click', (function (id, date) {
                    return function () { litLaVersion(id, date); };
                }(v.id, String(v.date || ''))));
                tdAction.appendChild(bRb);

                tr.append(tdDate, tdAuteur, tdMotif, tdAction);
                corpsHisto.appendChild(tr);
            }
            cadreHisto.hidden = false;

            /*
             * LE TOTAL, PAS LA LONGUEUR DE LA LISTE. La route du backend rend
             * 20 lignes au plus sans annoncer de total : on ne peut alors pas
             * distinguer « il y en a 20 » de « il y en a 200 » (E-154).
             */
            var total = Number(r.corps.total || 0);
            var affichees = Number(r.corps.affichees || versions.length);
            annonceHistoDire(
                affichees < total
                    ? t('histo_tronque', { affichees: affichees, total: total })
                    : t('histo_tout', { nb: total }));
        });
    }


    // ════════════════════════════════════════════════════════════════════
    //  SOUS-LOT I4 — LA VALIDATION A BLANC
    // ════════════════════════════════════════════════════════════════════
    //
    // ══ CE QUE CE GESTE TOUCHE ══════════════════════════════════════════
    //
    // C'est le PREMIER geste du portage de ce module qui joint une machine
    // pour y ECRIRE : il ouvre une session SSH, depose `/tmp/_ipt_test.rules`
    // et lance `iptables-restore --test` dessus. Aucune table du pare-feu
    // n'est modifiee — mais « ne modifie rien » n'est pas « ne fait rien »,
    // et l'ecran l'annonce AVANT le clic, pas dans le compte rendu.
    //
    // La passerelle ne protege PAS ce chemin en particulier : `/iptables-`
    // est une entree a PREFIXE dans la liste blanche (dernier caractere `-`
    // => `str_starts_with`), donc le meme prefixe ouvre `/iptables-validate`,
    // `/iptables-apply` et `/iptables-rollback` sans les distinguer. Ce qui
    // tient ici, ce sont la garde du backend (`can_manage_iptables` +
    // `require_machine_access`) et le fait que ce script ne compose aucune
    // autre requete. La fermeture reste PAR L'ABSENCE, comme en I1.
    //
    // ══ CE QU'ON VALIDE : LA COPIE, PAS LE RELEVE ═══════════════════════
    //
    // Le legacy valide le contenu de sa zone d'edition. Le portage n'en offre
    // pas — c'est justement sa fermeture — alors il valide l'objet qui existe :
    // la copie en base. La chaine devient lisible : I2 enregistre, I4 valide
    // ce qui est enregistre, et un futur I5 appliquerait le meme objet.
    //
    // Valider `dernierReleve` reviendrait a demander a la machine de valider
    // ce qu'elle vient elle-meme de rendre.
    //
    // ══ TROIS ISSUES, ET LA TROISIEME PORTE UN DOUTE ════════════════════
    //
    // `/iptables-validate` rend `success: false` pour QUATRE situations : des
    // identifiants irresolus (400), des regles vides (400), une erreur interne
    // (500), et « erreur de syntaxe » (200). Se fier a `success` seul
    // confondrait « vos regles sont invalides » avec « je n'ai rien pu
    // verifier » — deux verdicts qui appellent des gestes opposes : corriger
    // les regles, ou reessayer.
    //
    // Le discriminant est donc le STATUT : seul un 200 porte un verdict sur
    // les regles. Tout le reste est un contrôle qui n'a pas abouti, et l'ecran
    // le dit ainsi.
    //
    // Et ce verdict de 200 lui-meme n'est pas sur. Le backend le calcule par
    //     exit_code = 0 if any('EXIT_CODE=0' in l for l in output_lines) else 1
    // sur des fragments de 4096 octets rendus par `execute_as_root_stream`.
    // Un marqueur `EXIT_CODE=0` a cheval sur deux fragments n'est retrouve
    // dans AUCUN des deux, et un jeu de regles VALIDE est alors declare
    // invalide. Le portage ne repare pas le backend : il cesse de presenter
    // cette incertitude comme un verdict, et le dit a qui lit l'ecran.
    //
    // ══ CE QUE LA VALIDATION NE COUVRE PAS ══════════════════════════════
    //
    // `rules_v6` n'est ni envoye ni lu : la route ne connait que `rules_v4`.
    // Une copie dont l'IPv6 est mal forme passe ce controle et echoue a
    // l'application. C'est ecrit sur la page, avant le geste.

    function annonceValidDire(texte, variante) {
        if (!annonceValid) { return; }
        annonceValid.textContent = texte || '';
        annonceValid.className = 'rw-annonce' + (variante ? ' rw-annonce--' + variante : '');
    }

    /** Le bloc de detail : un etat nomme, puis la sortie brute si elle existe. */
    function detailValid(titre, texte, sortie) {
        if (!etatValidZone) { return; }
        etatValidZone.replaceChildren();
        if (titre) { etatValidZone.appendChild(etatVide(titre, texte)); }

        var brut = String(sortie == null ? '' : sortie);
        if (brut.trim() === '') { return; }

        var h = document.createElement('p');
        h.className = 'rw-sous-titre-fort';
        h.textContent = t('valid_sortie');

        /*
         * `textContent`, jamais d'interpolation : cette sortie vient d'un
         * pseudo-terminal distant, qui ECHOTE la commande envoyee. Meme regle
         * que `blocDeTexte`, et pour la meme raison.
         */
        var pre = document.createElement('pre');
        pre.className = 'rw-fichier';
        pre.textContent = brut;

        etatValidZone.append(h, pre);
    }

    function valideAblanc() {
        var id = selecteur.value;
        if (!id) { annonceValidDire(t('aucune_machine_choisie'), 'echec'); return; }
        // La regle se lit avant le geste — le bouton naît desactive — mais on la
        // tient aussi ici : l'etat d'un bouton n'est pas une garde.
        if (!derniereCopie) { annonceValidDire(t('valid_sans_copie'), 'echec'); return; }
        var v4 = String(derniereCopie.rules_v4 || '');
        if (v4.trim() === '') { annonceValidDire(t('valid_v4_vide'), 'attention'); return; }

        var repos = boutonValid.textContent;
        boutonValid.disabled = true;
        boutonValid.textContent = t('valid_en_cours');
        annonceValidDire(t('valid_en_cours'));
        if (etatValidZone) { etatValidZone.replaceChildren(); }

        appelle('/iptables-validate', {
            machine_id: Number(id),
            rules_v4: v4
        }).then(function (r) {
            // Rendu dans le meme bloc synchrone que le verdict, comme le releve.
            boutonValid.disabled = false;
            boutonValid.textContent = repos;

            var corps = r.corps || {};

            // 1. La requete n'est pas partie. Ni valide, ni invalide : rien n'a
            //    ete verifie, et rien n'a ete touche sur la machine.
            if (r.statut === 0) {
                annonceValidDire(t('echec_reseau'), 'echec');
                detailValid(t('valid_echec_titre'), t('valid_echec'), '');
                return;
            }

            // 2. Elle est partie et n'a pas rendu 200 : refus, regles vides,
            //    identifiants irresolus, erreur interne. Toujours pas un verdict
            //    sur les regles — on ne l'affiche donc pas comme tel.
            if (r.statut !== 200) {
                annonceValidDire(String(corps.message || t('echec')), 'echec');
                detailValid(t('valid_echec_titre'), t('valid_echec'), corps.output);
                return;
            }

            // 3. Un verdict, enfin — et le seul cas ou `success` veut dire
            //    quelque chose sur les regles.
            if (corps.success === true) {
                annonceValidDire(t('valid_ok'), 'ok');
                detailValid('', '', corps.output);
                return;
            }

            /*
             * 4. DECLAREES INVALIDES — en `attention`, pas en `echec`.
             *
             * La nuance n'est pas cosmetique : la detection du code de sortie
             * est faillible sur une sortie longue (voir l'en-tete). Peindre en
             * rouge un verdict qui peut etre faux ferait corriger des regles
             * saines. L'ecran affiche la sortie et dit de la lire.
             */
            annonceValidDire(t('valid_invalide_court'), 'attention');
            detailValid(t('valid_invalide_titre'), t('valid_invalide'), corps.output);
        });
    }

    if (boutonValid) { boutonValid.addEventListener('click', valideAblanc); }

    // ══════════════════════════════════════════════════════════════════════════
    //  SOUS-LOT I5 — APPLIQUER UN JEU DE REGLES
    // ══════════════════════════════════════════════════════════════════════════
    //
    // ⚠ CE QUE CE SOUS-LOT CREE, ET CE QU'IL NE CREE PAS.
    //
    // `RoutesBackend:114` porte `/iptables-` et compare PAR PREFIXE :
    // `/iptables-apply` traverse DEJA la passerelle sans cet ecran. I5 ne cree
    // donc pas l'atteignabilite du geste — il cree l'ECRAN. Un geste qui n'etait
    // atteignable que par requete forgee devient un bouton, et c'est pour cela que
    // les quatre proprietes ci-dessous ne sont pas negociables.
    //
    //   Q1  le port SSH vient de la MACHINE, jamais de `22` en dur
    //   Q2  un jeu qui fermerait SSH est refuse AVANT tout envoi, le doute aussi
    //   Q3  tout retour produit un message visible
    //   Q4  avant consentement, AUCUNE requete n'est emise
    var sectionAppl  = document.querySelector('[data-rw="ipt-appl"]');
    var selGabarit   = document.querySelector('[data-rw="ipt-appl-gabarit"]');
    var apercuAppl   = document.querySelector('[data-rw="ipt-appl-apercu"]');
    var sshDit       = document.querySelector('[data-rw="ipt-appl-ssh"]');
    var boutonAppl   = document.querySelector('[data-rw="ipt-appl-bouton"]');
    var annonceAppl  = document.querySelector('[data-rw="ipt-appl-annonce"]');
    var etatApplZone = document.querySelector('[data-rw="ipt-appl-etat"]');
    var confAppl     = document.querySelector('[data-rw="ipt-appl-conf"]');
    var confTitre    = document.querySelector('[data-rw="ipt-appl-conf-titre"]');
    var confTexte    = document.querySelector('[data-rw="ipt-appl-conf-texte"]');
    var confOk       = document.querySelector('[data-rw="ipt-appl-conf-ok"]');
    var confNon      = document.querySelector('[data-rw="ipt-appl-conf-non"]');

    /*
     * Q1 — LE PORT SSH EST LU, PAS SUPPOSE. La table vient du serveur
     * (`ipt-ports`, remplie en base). Sans elle on ne compose AUCUN gabarit :
     * fail-closed, parce que le repli evident (`22`) est precisement ce que Q1
     * corrige, et qu'il enfermerait dehors quiconque a change son port.
     */
    var portsSsh = null;
    try { portsSsh = JSON.parse(document.getElementById('ipt-ports').textContent); }
    catch (e) { portsSsh = null; }

    /** Le jeu compose et son verdict Q2. `null` tant que rien n'est composable. */
    var jeuCourant = null;

    function annonceApplDire(texte, variante) {
        if (!annonceAppl) { return; }
        annonceAppl.textContent = texte || '';
        annonceAppl.className = 'rw-annonce' + (variante ? ' rw-annonce--' + variante : '');
    }

    function portDe(id) {
        if (!portsSsh || !id) { return null; }
        var p = portsSsh[String(id)];

        return (typeof p === 'number' && isFinite(p) && p > 0) ? p : null;
    }

    /*
     * Compose le jeu choisi et rend le verdict Q2 A L'ECRAN, avant le bouton.
     * Un jeu qui fermerait SSH doit se lire AVANT qu'on ait envie de cliquer.
     */
    function composeLeJeu() {
        jeuCourant = null;
        if (apercuAppl) { apercuAppl.textContent = ''; }
        if (sshDit) { sshDit.textContent = ''; sshDit.className = 'rw-annonce'; }
        if (boutonAppl) { boutonAppl.disabled = true; }

        var id = selecteur ? selecteur.value : '';
        var nom = selGabarit ? selGabarit.value : '';
        if (!id || !nom) { return; }

        var port = portDe(id);
        if (port === null || !window.rwGabaritPareFeu || !window.rwLaisseLeSshOuvert) {
            // Ni port lu, ni modules charges : on ne compose rien et on le DIT.
            annonceApplDire(t('appl_ssh_doute', { port: '?' }), 'echec');

            return;
        }

        var regles = window.rwGabaritPareFeu(nom, port);
        if (typeof regles !== 'string' || regles.trim() === '') { return; }
        if (apercuAppl) { apercuAppl.textContent = regles; }

        // Q2 — trois valeurs, et le doute compte comme un refus.
        var ouvert = window.rwLaisseLeSshOuvert(regles, port);
        if (ouvert === true) {
            sshDit.textContent = t('appl_ssh_ouvert', { port: port });
            sshDit.className = 'rw-annonce rw-annonce--ok';
            jeuCourant = { nom: nom, regles: regles, port: port };
            if (boutonAppl) { boutonAppl.disabled = false; }

            return;
        }
        sshDit.textContent = ouvert === false
            ? t('appl_ssh_ferme', { port: port })
            : t('appl_ssh_doute', { port: port });
        sshDit.className = 'rw-annonce rw-annonce--echec';
    }

    /*
     * Q4 — OUVRIR LE PANNEAU N'EMET RIEN. Cette fonction ne fait que remplir et
     * afficher : aucun `appelle()` n'y figure, et c'est la propriete qui se mesure
     * AU RESEAU. Le bouton de confirmation nait desactive dans la vue et ne
     * s'active qu'ici — un panneau ferme ne doit rien pouvoir declencher.
     */
    function demandeConsentement() {
        if (!jeuCourant) { return; }
        var o = optionChoisie();
        var machine = o ? (o.textContent || '').trim() : '';
        if (confTitre) { confTitre.textContent = t('appl_conf_titre', { machine: machine }); }
        if (confTexte) {
            confTexte.textContent = t('appl_conf_texte', { machine: machine, gabarit: jeuCourant.nom });
        }
        if (confAppl) { confAppl.hidden = false; }
        if (confOk) { confOk.disabled = false; }

        /*
         * ⚠ ON AMENE LE PANNEAU SOUS LES YEUX. Vu a l'image : le panneau s'ouvre
         * SOUS le bouton, donc hors de l'ecran quand la page est longue — et un
         * clic qui ne montre rien se lit comme un bouton mort. La personne
         * recliquerait, ou conclurait que le geste a echoue.
         *
         * Aucune assertion de DOM ne pouvait le voir : le panneau etait bien
         * `hidden = false`, correctement rempli, et invisible.
         */
        if (confAppl && confAppl.scrollIntoView) {
            confAppl.scrollIntoView({ block: 'center' });
        }
    }

    function fermeConsentement() {
        if (confAppl) { confAppl.hidden = true; }
        if (confOk) { confOk.disabled = true; }
    }

    /*
     * Q3 — TOUT RETOUR PRODUIT UN MESSAGE VISIBLE. On ne lit ni `success` seul ni
     * le statut seul : `rwRetourPareFeu` distingue les huit cas, dont QUATRE
     * portent `sur: false` — ils disent « je ne sais pas », jamais « ca a echoue ».
     */
    function rendLeRetour(r) {
        var verdict = window.rwRetourPareFeu
            ? window.rwRetourPareFeu(r.corps, r.statut, r.statut === 0)
            : { ton: 'inabouti', titre: 'ipt_retour_contrat_inconnu', detail: '', sur: false };

        var variante = verdict.ton === 'succes' ? 'ok'
            : (verdict.ton === 'echec' ? 'echec' : 'attention');
        annonceApplDire(t(verdict.titre), variante);
        if (etatApplZone) {
            etatApplZone.replaceChildren();
            if (verdict.detail) {
                var pre = document.createElement('pre');
                pre.className = 'rw-fichier';
                pre.textContent = String(verdict.detail);
                etatApplZone.appendChild(pre);
            }
        }

        // Un geste dont le verdict n'est PAS sur laisse l'historique a relire :
        // c'est la seule facon de savoir ce que la machine porte vraiment.
        if (verdict.sur === true && verdict.ton === 'succes') { chargeHistorique(); }
    }

    function applique() {
        if (!jeuCourant) { return; }
        var id = selecteur ? selecteur.value : '';
        if (!id) { annonceApplDire(t('aucune_machine_choisie'), 'echec'); return; }

        fermeConsentement();
        var repos = boutonAppl.textContent;
        boutonAppl.disabled = true;
        boutonAppl.textContent = t('appl_en_cours');
        annonceApplDire(t('appl_en_cours'));
        if (etatApplZone) { etatApplZone.replaceChildren(); }

        appelle('/iptables-apply', {
            action: 'apply',
            machine_id: Number(id),
            rules_v4: jeuCourant.regles
        }).then(function (r) {
            boutonAppl.disabled = false;
            boutonAppl.textContent = repos;
            rendLeRetour(r);
        });
    }

    function garnisLesGabarits() {
        if (!selGabarit || !window.rwGabaritsPareFeu) { return; }
        selGabarit.replaceChildren();
        var vide = document.createElement('option');
        vide.value = '';
        vide.textContent = t('choisir');
        selGabarit.appendChild(vide);
        window.rwGabaritsPareFeu().forEach(function (n) {
            var o = document.createElement('option');
            o.value = n;
            o.textContent = n;
            selGabarit.appendChild(o);
        });
    }

    if (selGabarit) { selGabarit.addEventListener('change', composeLeJeu); }
    if (boutonAppl) { boutonAppl.addEventListener('click', demandeConsentement); }
    if (confOk) { confOk.addEventListener('click', applique); }
    if (confNon) {
        confNon.addEventListener('click', function () {
            fermeConsentement();
            annonceApplDire(t('appl_annule'), 'attention');
        });
    }
    garnisLesGabarits();

    // ══════════════════════════════════════════════════════════════════════
    //  SOUS-LOT I6 — LE RETOUR ARRIERE
    // ══════════════════════════════════════════════════════════════════════
    //
    // ⚠ PLUS DANGEREUX QUE L'APPLICATION, ET NON MOINS :
    //
    //   APPLIQUER       l'operateur ECRIT les regles, il les a sous les yeux
    //   RETOUR ARRIERE  l'operateur choisit une DATE, il ne peut pas se relire
    //
    // Le legacy y met un `confirm()` de navigateur, et rien d'autre : ni Q1 ni Q2.
    // Laisser ce geste la-bas n'aurait pas ete de la prudence — c'aurait ete
    // laisser le plus dangereux des cinq sans aucune garde pendant que le portail
    // gardé prend les quatre plus surs.
    //
    // ⚠ ET Q2 SE CALCULE SUR LE PORT ACTUEL. `iptables_history` ne porte AUCUN
    // port : une version etait valide LE JOUR DE SON ARCHIVAGE. Si le port SSH a
    // change depuis — c'est-a-dire si quelqu'un a suivi le durcissement qu'on
    // prescrit — la restaurer FERME l'acces. Et la reprise passerait elle aussi
    // par SSH.
    var sectionRb   = document.querySelector('[data-rw="ipt-rb"]');
    var rbArchive   = document.querySelector('[data-rw="ipt-rb-archive"]');
    var rbApercu    = document.querySelector('[data-rw="ipt-rb-apercu"]');
    var rbSsh       = document.querySelector('[data-rw="ipt-rb-ssh"]');
    var rbBouton    = document.querySelector('[data-rw="ipt-rb-bouton"]');
    var rbAnnonce   = document.querySelector('[data-rw="ipt-rb-annonce"]');
    var rbEtatZone  = document.querySelector('[data-rw="ipt-rb-etat"]');
    var rbConf      = document.querySelector('[data-rw="ipt-rb-conf"]');
    var rbConfTitre = document.querySelector('[data-rw="ipt-rb-conf-titre"]');
    var rbConfTexte = document.querySelector('[data-rw="ipt-rb-conf-texte"]');
    var rbConfOk    = document.querySelector('[data-rw="ipt-rb-conf-ok"]');
    var rbConfNon   = document.querySelector('[data-rw="ipt-rb-conf-non"]');

    /** La version lue et son verdict. `null` tant que rien n'est restaurable. */
    var versionCourante = null;

    /*
     * ══ LE JETON DE LECTURE — POURQUOI UN COMPTEUR ET PAS TROIS DESARMEMENTS ══
     *
     * `rbRemetAZero()` desarmait deja tout AVANT la lecture. C'est juste pour un
     * enchainement sequentiel, et FAUX en concurrence : la lecture est
     * asynchrone, et les trois chemins de REFUS du `.then()` rendaient la main
     * sans rien desarmer.
     *
     *     1. clic sur la version B      -> requete B partie
     *     2. clic sur la version A      -> rbRemetAZero() desarme, requete A partie
     *     3. la reponse B arrive        -> Q2 vrai -> versionCourante = B, bouton ACTIF
     *     4. la reponse A arrive        -> affiche A et « SSH ferme », NE DESARME PAS
     *
     * ⚠ ET CE N'EST PAS UN ENTRELACEMENT RARE. La premiere redaction de cette
     * note disait « la reponse B arrive TARD », comme s'il fallait une
     * conjonction improbable. **B a ete demandee EN PREMIER : qu'elle revienne
     * avant A est l'ordre NORMAL.** La seule condition reelle est que
     * l'operateur clique A avant que B ne reponde — c'est-a-dire un operateur
     * impatient, pas une course. *Corrige en relecture : je vendais mon propre
     * defaut moins probable qu'il n'est.*
     *
     *     -> l'ecran montre A et son REFUS, le bouton est arme sur B.
     *        L'operateur lit un refus, voit un bouton actif, clique, et applique
     *        un jeu de regles de pare-feu QU'IL N'A PAS LU.
     *
     * Desarmer dans les trois refus serait EXHAUSTIF : juste tant que personne
     * n'ajoute un quatrieme chemin de sortie. Le jeton rend la reponse perimee
     * INEXPRIMABLE — elle ne peut plus rien ecrire du tout, pas meme l'apercu.
     * C'est le rang que ce depot prefere : inexprimable > derive > exhaustif.
     *
     * ⚠ UNE SECONDE FERMETURE PAR L'ABSENCE, ET ELLE N'ETAIT PAS ECRITE.
     * Cette chaine n'a AUCUN `.catch`. Elle est sure aujourd'hui pour une seule
     * raison : `appellePortage()` rattrape en interne et rend `{statut: 0}`,
     * donc tout rejet devient une RESOLUTION et passe par le `.then()` — donc
     * par le jeton.
     *
     * *Le jour ou `appellePortage` cesserait de rattraper, une reponse PERDUE
     * resterait exprimable : l'ecran tiendrait indefiniment sur `rb_lecture`, et
     * le jeton n'y pourrait rien puisque rien ne s'executerait.* Ajouter un
     * `.catch` ici serait du rang EXHAUSTIF, celui que ce docblock place en
     * dernier — on ne l'ajoute donc pas. **Mais une fermeture par l'absence qui
     * n'est pas ECRITE se perd au premier refactor : celle-ci l'est maintenant.**
     *
     * ⚠ ET IL VIT DANS `rbRemetAZero()`, PAS DANS `litLaVersion()`. Les deux
     * appelants comptent : changer de machine (`:211`) perime aussi une lecture
     * en vol, et le docblock de ce site le disait deja — « changer de cible
     * perime donc tout ». Le jeton ne fait qu'y ajouter ce qui n'etait pas encore
     * arrivable au moment ou il a ete ecrit.
     */
    var jetonLecture = 0;

    function rbDire(texte, variante) {
        if (!rbAnnonce) { return; }
        rbAnnonce.textContent = texte || '';
        rbAnnonce.className = 'rw-annonce' + (variante ? ' rw-annonce--' + variante : '');
    }

    function fermeRbConsentement() {
        if (rbConf) { rbConf.hidden = true; }
        if (rbConfOk) { rbConfOk.disabled = true; }
    }

    function rbRemetAZero() {
        // Toute lecture en vol devient perimee ICI : voir le docblock du jeton.
        jetonLecture += 1;
        versionCourante = null;
        if (sectionRb) { sectionRb.hidden = true; }
        if (rbApercu) { rbApercu.textContent = ''; }
        if (rbArchive) { rbArchive.textContent = ''; }
        if (rbSsh) { rbSsh.textContent = ''; rbSsh.className = 'rw-annonce'; }
        if (rbBouton) { rbBouton.disabled = true; }
        if (rbEtatZone) { rbEtatZone.replaceChildren(); }
        fermeRbConsentement();
        rbDire('');
    }

    /*
     * Lit la version archivee — LECTURE SEULE, aucune machine jointe — puis rend
     * Q2 sur le port ACTUEL. Le bouton de restauration ne s'active que si Q2 rend
     * `true` : `false` ET `null` refusent tous les deux.
     */
    function litLaVersion(versionId, date) {
        var id = selecteur ? selecteur.value : '';
        if (!id) { rbDire(t('aucune_machine_choisie'), 'echec'); return; }
        rbRemetAZero();
        // APRES le remise a zero : c'est elle qui incremente le jeton.
        var mien = jetonLecture;
        if (sectionRb) { sectionRb.hidden = false; }
        rbDire(t('rb_lecture'));

        appellePortage('/pare-feu/version', { machine_id: Number(id), version_id: Number(versionId) })
            .then(function (r) {
                /*
                 * ⛔ PREMIERE INSTRUCTION, AVANT TOUT RENDU. Un seul `textContent`
                 * place au-dessus et le jeton ne gouvernerait pas CE rendu-la :
                 * la garde doit dominer TOUS les chemins de sortie qui la suivent,
                 * et elle ne les domine que si rien ne la precede.
                 */
                if (mien !== jetonLecture) { return; }

                var corps = r.corps || {};
                if (r.statut !== 200 || corps.success !== true) {
                    // Le serveur rend deja sa phrase ; on ne la reformule pas.
                    rbDire(String(corps.message || t('rb_lecture_echec')), 'echec');

                    return;
                }
                var regles = String(corps.rules_v4 || '');
                var port = Number(corps.port_ssh || 0);
                if (rbApercu) { rbApercu.textContent = regles; }
                if (rbArchive) { rbArchive.textContent = t('rb_archive_le', { date: date || corps.created_at }); }
                rbDire('');

                if (!window.rwLaisseLeSshOuvert || !port) {
                    rbSsh.textContent = t('rb_ssh_doute', { port: port || '?' });
                    rbSsh.className = 'rw-annonce rw-annonce--echec';

                    return;
                }
                var ouvert = window.rwLaisseLeSshOuvert(regles, port);
                if (ouvert === true) {
                    rbSsh.textContent = t('rb_ssh_ouvert', { port: port });
                    rbSsh.className = 'rw-annonce rw-annonce--ok';
                    versionCourante = { id: Number(versionId), date: date, regles: regles, port: port };
                    if (rbBouton) { rbBouton.disabled = false; }

                    return;
                }
                rbSsh.textContent = ouvert === false
                    ? t('rb_ssh_ferme', { port: port })
                    : t('rb_ssh_doute', { port: port });
                rbSsh.className = 'rw-annonce rw-annonce--echec';
            });
    }

    /* Q4 — ouvrir le panneau n'emet rien : aucun `appelle()` ici. */
    function demandeRbConsentement() {
        if (!versionCourante) { return; }
        var o = optionChoisie();
        var machine = o ? (o.textContent || '').trim() : '';
        if (rbConfTitre) {
            rbConfTitre.textContent = t('rb_conf_titre', { date: versionCourante.date, machine: machine });
        }
        if (rbConfTexte) { rbConfTexte.textContent = t('rb_conf_texte', { machine: machine }); }
        if (rbConf) { rbConf.hidden = false; }
        if (rbConfOk) { rbConfOk.disabled = false; }
        if (rbConf && rbConf.scrollIntoView) { rbConf.scrollIntoView({ block: 'center' }); }
    }

    /** Rend une sortie brute dans la zone d'etat du retour arriere. */
    function rbDetail(texte) {
        if (!rbEtatZone || !texte) { return; }
        var pre = document.createElement('pre');
        pre.className = 'rw-fichier';
        pre.textContent = String(texte);
        rbEtatZone.appendChild(pre);
    }

    /*
     * ══ LA VALIDATION AVANT LE RETOUR ARRIERE ════════════════════════════════
     *
     * `apply` validait, `restaure` ne validait pas, et les DEUX appellent
     * `apply_iptables_rules()` en aval. Ce n'etait pas « une validation en
     * moins » mais un defaut A RETARDEMENT :
     *
     *     iptables_manager.apply_iptables_rules()
     *       1. _write_rules_safe(...)  ->  ECRIT /etc/iptables/rules.v4
     *       2. iptables-restore < ...  ->  CHARGE
     *
     * Le fichier est ecrit AVANT d'etre charge. Un jeu illisible ecrase le
     * fichier persistant puis echoue : la machine garde ses regles **jusqu'au
     * prochain redemarrage**, et se releve SANS PARE-FEU. *Charger d'abord et
     * n'ecrire qu'au succes rendrait cette classe inoffensive — c'est le backend,
     * donc l'exploitant. En attendant, on ferme par le haut.*
     *
     * ⚠ CE QUI A TENU CETTE CORRECTION FERMEE UNE NUIT : « ne compose aucune
     * requete de plus sous `/iptables-`, la fermeture est PAR L'ABSENCE ». Juste
     * comme regle, inapplicable ici — ce script compose DEJA `/iptables`,
     * `/iptables-validate`, `/iptables-apply` et `/iptables-rollback`. La
     * fermeture porte sur QUELS points d'acces sont atteints, pas sur combien de
     * fois. Un cinquieme site vers un point deja atteint n'elargit rien.
     *
     * ══ REFUSER DANS LES DEUX CAS, AVEC DEUX MESSAGES ════════════════════════
     *
     *     verdict « invalide »          -> REFUS, une ACCUSATION, qui doit etre vraie
     *     aucun verdict possible        -> REFUS, un AVEU : « je n'ai pas verifie »
     *
     * Les deux se traitent en refus ; **c'est le message qui differe**, et cette
     * distinction est exactement celle que Q2 a fait payer trois rondes. Un refus
     * qui accuse a tort s'use plus vite qu'un garde absent : celui qui sait son
     * jeu bon apprend que le garde se trompe.
     *
     * ⛔ ET AUCUNE ECHAPPATOIRE. Offrir un contournement, meme derriere un second
     * consentement, revient a rouvrir le chemin non valide — donc a n'avoir rien
     * ferme.
     *
     * *L'objection « refuser sur une machine injoignable retire une capacite de
     * REPRISE » ne tient pas : le seul canal est SSH, et `/iptables-rollback`
     * passe par lui. Si `validate` echoue faute de machine, l'`apply` echouerait
     * pour la meme raison. Refuser n'enleve rien — il rend explicite un echec qui
     * allait arriver.*
     */
    function restaure() {
        if (!versionCourante) { return; }
        var id = selecteur ? selecteur.value : '';
        if (!id) { rbDire(t('aucune_machine_choisie'), 'echec'); return; }

        fermeRbConsentement();
        var repos = rbBouton.textContent;
        rbBouton.disabled = true;
        rbBouton.textContent = t('rb_valid_en_cours');
        rbDire(t('rb_valid_en_cours'));
        if (rbEtatZone) { rbEtatZone.replaceChildren(); }

        /*
         * ⚠ LE MEME JETON QU'A LA LECTURE, ET POUR LA MEME RAISON. Entre cette
         * validation et le retour arriere il y a une attente reseau : l'operateur
         * peut cliquer une autre version, et `rbRemetAZero()` incremente alors le
         * jeton. Sans cette capture, une validation tardive relancerait le geste
         * sur une version que l'ecran ne montre plus. *C'est le defaut que le
         * jeton vient de fermer un cran plus haut ; il n'y avait aucune raison de
         * le reintroduire un cran plus bas.*
         */
        var mien = jetonLecture;
        var version = versionCourante;

        appelle('/iptables-validate', {
            machine_id: Number(id),
            rules_v4: version.regles
        }).then(function (rv) {
            if (mien !== jetonLecture) { return; }

            var cv = rv.corps || {};
            rbBouton.disabled = false;
            rbBouton.textContent = repos;

            // 1. Rien n'est parti : ni valide, ni invalide. AVEU.
            if (rv.statut === 0) {
                rbDire(t('rb_valid_indecidable', { motif: t('echec_reseau') }), 'attention');
                return;
            }

            // 2. Partie, mais pas de verdict sur les REGLES : identifiants
            //    irresolus, regles vides, erreur interne. AVEU, pas accusation.
            if (rv.statut !== 200) {
                rbDire(t('rb_valid_indecidable', {
                    motif: String(cv.message || t('echec'))
                }), 'attention');
                rbDetail(cv.output);
                return;
            }

            // 3. Un verdict, et il refuse. ACCUSATION — elle porte sur les regles.
            if (cv.success !== true) {
                rbDire(t('rb_valid_invalide'), 'echec');
                rbDetail(cv.output);
                return;
            }

            // 4. Valide. C'est le SEUL chemin qui applique.
            appliqueLeRetour(version, repos);
        });
    }

    /** Le geste lui-meme. Atteint UNIQUEMENT apres un verdict `valide`. */
    function appliqueLeRetour(version, repos) {
        var mien = jetonLecture;
        rbBouton.disabled = true;
        rbBouton.textContent = t('rb_en_cours');
        rbDire(t('rb_en_cours'));

        appelle('/iptables-rollback', { history_id: version.id }).then(function (r) {
            if (mien !== jetonLecture) { return; }

            rbBouton.disabled = false;
            rbBouton.textContent = repos;

            // Q3 — le meme juge que I5, donc la meme phrase pour le meme cas.
            var verdict = window.rwRetourPareFeu
                ? window.rwRetourPareFeu(r.corps, r.statut, r.statut === 0)
                : { ton: 'inabouti', titre: 'ipt_retour_contrat_inconnu', detail: '', sur: false };
            var variante = verdict.ton === 'succes' ? 'ok'
                : (verdict.ton === 'echec' ? 'echec' : 'attention');
            rbDire(t(verdict.titre), variante);
            if (rbEtatZone && verdict.detail) {
                var pre = document.createElement('pre');
                pre.className = 'rw-fichier';
                pre.textContent = String(verdict.detail);
                rbEtatZone.appendChild(pre);
            }
            // Un retour arriere reussi ARCHIVE l'etat precedent : l'historique a
            // donc une ligne de plus, et la liste doit le refleter.
            if (verdict.sur === true && verdict.ton === 'succes') { chargeHistorique(); }
        });
    }

    if (rbBouton) { rbBouton.addEventListener('click', demandeRbConsentement); }
    if (rbConfOk) { rbConfOk.addEventListener('click', restaure); }
    if (rbConfNon) {
        rbConfNon.addEventListener('click', function () {
            fermeRbConsentement();
            rbDire(t('rb_annule'), 'attention');
        });
    }

    surChoix();
}());
