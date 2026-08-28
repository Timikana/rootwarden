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

                tr.append(tdDate, tdAuteur, tdMotif);
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

    surChoix();
}());
