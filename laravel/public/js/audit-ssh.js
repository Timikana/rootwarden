/**
 * audit-ssh.js — audit de configuration SSH.
 *
 * ⚠ CE FICHIER A ETE « LECTURE SEULE » JUSQU'A A2, ET IL NE L'EST PLUS.
 *
 * A1 declarait « aucune requete autre que GET ». C'etait vrai, et A2 l'a rendu
 * FAUX en portant la creation d'un releve planifie. La phrase est corrigee
 * DANS LE MEME COMMIT que le geste : un en-tete qui affirme une propriete que
 * le fichier n'a plus est pire qu'un en-tete absent, parce qu'on le croit.
 *
 * L'ECRITURE, ET SON PERIMETRE EXACT : `POST /ssh-audit/schedules`, et rien
 * d'autre. Ni `DELETE /schedules/<id>`, ni `POST /schedules/<id>/toggle`, ni
 * aucune des routes qui joignent une machine.
 *
 * ══ CE QUE CE SCRIPT N'EMET JAMAIS ═══════════════════════════════════════
 *
 * Aucune requete autre que `GET`. Et parmi les `GET`, **aucun appel n'est
 * compose vers `POST /ssh-audit/policies`** — SEC-013 : l'ecriture de
 * politique est gardee par `require_role(2)` SEUL, la lecture par
 * `can_audit_ssh` + `require_machine_access`. L'ecriture est donc moins
 * gardee que la lecture, sur la MEME URL, et la passerelle ne peut pas les
 * separer : elle compare des CHEMINS, jamais des methodes.
 *
 * La fermeture se fait par l'ABSENCE. Une entree qu'on n'offre pas ne se
 * contourne pas.
 *
 * ══ `/results` : CE QUI LA REFERME N'EST PAS UNE GARDE ════════════════════
 *
 * `GET /ssh-audit/results` ne porte NI role NI permission : sa seule borne est
 * `require_machine_access`, inerte des le role 2. Ce qui la referme est la
 * ligne `if not machine_id: return 400` de son CORPS — un controle de
 * VALIDITE, pas un controle d'acces. On passe donc toujours le parametre, et
 * on ne compte pas sur ce filet.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var libelles = {};
    try {
        var bloc = document.getElementById('audit-ssh-libelles');
        if (bloc) { libelles = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { libelles = {}; }

    function t(cle, subst) {
        var s = libelles[cle];
        if (typeof s !== 'string') { return cle; }
        if (subst) {
            Object.keys(subst).forEach(function (k) { s = s.split(':' + k).join(String(subst[k])); });
        }
        return s;
    }

    function lis(chemin) {
        return fetch(PASSERELLE + chemin, { headers: { 'Accept': 'application/json' } })
            .then(function (r) {
                return r.json().then(
                    function (j) { return { ok: r.ok, corps: j }; },
                    function () { return { ok: false, corps: null }; }
                );
            })
            .catch(function () { return { ok: false, corps: null }; });
    }

    /*
     * ══ A2 : CE FICHIER ECRIT DESORMAIS, ET LE HEADER LE DIT ═════════════
     *
     * UNE SEULE route en ecriture : `POST /ssh-audit/schedules`. Le helper ne
     * prend pas de methode en parametre — il ne sait faire qu'un POST, sur le
     * chemin qu'on lui donne. Un helper generique `envoie(methode, chemin)`
     * ouvrirait DELETE et les deux `toggle` sans qu'aucun code les demande.
     */
    function ecris(chemin, corps) {
        return fetch(PASSERELLE + chemin, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(corps),
        }).then(function (r) {
            return r.json().then(
                function (j) { return { ok: r.ok, corps: j }; },
                function () { return { ok: false, corps: null }; }
            );
        }).catch(function () { return { ok: false, corps: null }; });
    }

    function vide(hote, texte, erreur) {
        hote.textContent = '';
        var d = document.createElement('div');
        d.className = erreur ? 'rw-vide rw-vide--erreur' : 'rw-vide';
        var p = document.createElement('p');
        p.className = 'rw-vide__texte';
        p.textContent = texte;
        d.appendChild(p);
        hote.appendChild(d);
    }

    // ── LE PANNEAU PARTAGE ───────────────────────────────────────────────
    var panneau = document.querySelector('[data-rw="audit-ssh-panneau"]');
    var pTitre = document.querySelector('[data-rw="audit-ssh-panneau-titre"]');
    var pTexte = document.querySelector('[data-rw="audit-ssh-panneau-texte"]');
    var pEffets = document.querySelector('[data-rw="audit-ssh-panneau-effets"]');
    var pFermer = document.querySelector('[data-rw="audit-ssh-panneau-fermer"]');
    var pLegacy = document.querySelector('[data-rw="audit-ssh-panneau-legacy"]');

    /*
     * ⚠ LE TITRE ETAIT FIGE SUR « Pas encore porte », et A2 l'a rendu FAUX.
     *
     * Vu a l'image, pas a l'assertion : le panneau de confirmation d'un geste
     * PORTE s'ouvrait en annoncant « Pas encore porte ». Toutes mes mesures DOM
     * etaient vertes — le panneau s'ouvrait, ses trois effets etaient rendus,
     * le bouton de confirmation apparaissait — et le titre disait le contraire
     * du reste.
     *
     * Le troisieme parametre est OPTIONNEL : les quatre panneaux de capacite
     * non portee gardent `np_titre` sans changer d'appel.
     */
    function ouvrePanneau(texte, effets, titre) {
        if (! panneau) { return; }
        pTitre.textContent = titre || t('np_titre');
        pTexte.textContent = texte;

        pEffets.textContent = '';
        var lignes = (effets || []).filter(Boolean);
        pEffets.hidden = lignes.length === 0;
        lignes.forEach(function (l) {
            var li = document.createElement('li');
            li.textContent = l;
            pEffets.appendChild(li);
        });

        panneau.hidden = false;
        panneau.scrollIntoView({ block: 'nearest' });
    }

    /*
     * La fermeture est NOMMEE parce que A2 l'appelle apres son ecriture, et
     * parce qu'elle DESARME le rappel de confirmation : un bouton partage qui
     * garde le geste du panneau precedent agit sur autre chose que ce qu'on a
     * lu — et il suffirait de le demasquer pour le declencher.
     */
    function fermePanneau() {
        if (! panneau) { return; }
        panneau.hidden = true;
        pEffets.hidden = true;
        pEffets.textContent = '';
        var c = document.querySelector('[data-rw="audit-ssh-panneau-confirmer"]');
        if (c) {
            c.hidden = true;
            c.disabled = false;
            // Le libelle revient a celui d'A2 : deux gestes se partagent ce
            // bouton, et un libelle qui survit a son panneau ment.
            c.textContent = t('planif_valider');
        }
        // ...et le lien legacy REVIENT : les quatre gestes non portes en ont
        // besoin, et c'est leur action principale.
        if (pLegacy) { pLegacy.hidden = false; }
        gesteConfirme = null;
    }

    if (pFermer) { pFermer.addEventListener('click', fermePanneau); }

    var selecteur = document.querySelector('[data-rw="audit-ssh-serveur"]');

    // UN PANNEAU PARTAGE NOMME SA CIBLE. Il sert cinq boutons places a des
    // endroits differents de la page.
    function surServeur() {
        if (! selecteur || ! selecteur.value) { return ''; }
        var opt = selecteur.options[selecteur.selectedIndex];
        return t('np_sur_serveur', { nom: opt ? opt.textContent : '' });
    }

    // ── LES CAPACITES NON PORTEES ────────────────────────────────────────
    function brancher(ancre, message, detail, avecCible) {
        var b = document.querySelector('[data-rw="' + ancre + '"]');
        if (! b) { return; }
        b.addEventListener('click', function () {
            ouvrePanneau(message, [avecCible ? surServeur() : '', detail]);
        });
    }

    // Celui-la ne nomme AUCUNE cible, et c'est le fait a dire : la route ne
    // prend aucun parametre. Il n'y a rien a viser, donc rien a restreindre.
    brancher('audit-ssh-parc', t('np_parc'), t('np_parc_detail'), false);

    /*
     * ══ A LIRE PAR QUI PORTERA LA CREATION DE PLANIFICATION ══════════════
     *
     * Ce panneau sera remplace par un formulaire. Une contrainte doit voyager
     * avec ce remplacement, sans quoi elle se perdra :
     *
     * Un correctif backend en attente fera REFUSER une planification `tag`
     * dont le champ de portee est vide, au lieu de la faire tomber sur le
     * parc entier (E-280). C'est la bonne correction — **mais le refus sera
     * SILENCIEUX si l'interface ne le rend pas.** L'exploitant aura demande
     * un relevé par tag, laisse la case blanche, et n'aura ni relevé ni
     * message.
     *
     * Donc : **un champ de portee vide se refuse A L'ECRAN, avec la raison,
     * avant que la requete parte.** Et pas par un `required` muet — le
     * premier garde vit dans le NAVIGATEUR, le second dans le serveur, et
     * les deux doivent dire la MEME chose. Un `required` seul rendrait une
     * soumission bloquee sans texte, ce qui est le meme silence deplace d'un
     * cran.
     *
     * Ce n'est pas au correctif backend de le dire : un refus qui n'a pas
     * d'ecran se lit comme une panne.
     */
    /*
     * ══ A4 — RELEVER UN SERVEUR ══════════════════════════════════════════
     *
     * ⚠ CE GESTE JOINT LA MACHINE **ET ECRIT EN BASE**.
     *
     * `np_relever_detail` dit « c'est une lecture, mais c'est une connexion » —
     * vrai, et INCOMPLET. Mesure de `ssh_audit.py:143-165` : le geste persiste
     * un releve (`_save_audit_result`), l'inscrit au journal d'audit
     * (`_log_audit_action`) et leve des notifications (`notify_subscribed`).
     *
     * ⚠ ET J'AI FAILLI ECRIRE QU'IL ENVOYAIT DES COURRIELS. Le mot
     * « notification » m'a fait supposer un canal sortant. `notify.py:122`
     * filtre `np.channel IN ('inapp', 'both')`, et `notify.py` ne contient
     * AUCUNE occurrence de smtp, webhook, telegram ni slack : **rien ne sort.**
     * Le dire faux aurait fait renoncer a un geste sur, l'inverse exact du
     * defaut qu'on corrige d'habitude.
     *
     * `relever_ecrit` complete la reserve SANS la modifier : ce qui est garde
     * doit rester tel quel pour rester comparable d'un sous-lot a l'autre.
     *
     * ⛔ CE GESTE N'EST PAS EXERCE ICI, et jamais vers `srv-zabbix`.
     */
    var relMessage = document.querySelector('[data-rw="audit-ssh-relever-message"]');

    function annonceReleve(texte, echec) {
        if (! relMessage) { return; }
        relMessage.className = 'rw-annonce' + (echec ? ' rw-annonce--echec' : ' rw-annonce--ok');
        relMessage.textContent = texte;
    }

    function lanceReleve() {
        if (! selecteur || ! selecteur.value) { return; }
        var mid = selecteur.value;
        if (pConfirmer) { pConfirmer.disabled = true; }
        annonceReleve(t('relever_en_cours'), false);

        ecris('/ssh-audit/scan', { machine_id: Number(mid) }).then(function (r) {
            fermePanneau();
            /*
             * TROIS ISSUES SEPAREES, comme pour A3 : un refus n'est pas un
             * echec de releve, et aucun des deux n'est une reussite muette.
             */
            if (! r.ok) {
                annonceReleve(t('relever_refus', {
                    message: (r.corps && r.corps.message) || '',
                }), true);

                return;
            }
            if (! r.corps || r.corps.success !== true) {
                annonceReleve(t('relever_echec', {
                    message: (r.corps && r.corps.message) || '',
                }), true);

                return;
            }
            annonceReleve(t('relever_fait', {
                grade: String(r.corps.grade || (r.corps.result && r.corps.result.grade) || '?'),
                score: String(r.corps.score || (r.corps.result && r.corps.result.score) || 0),
            }), false);
            // LE RELEVE EST RELU, pas ajoute a la main : le backend a calcule
            // la note et l'a persistee, et une ligne fabriquee ici porterait
            // la valeur qu'on croit plutot que celle qu'il a inscrite.
            chargeHistorique(mid);
        });
    }

    var bRelever = document.querySelector('[data-rw="audit-ssh-relever"]');
    if (bRelever) {
        bRelever.addEventListener('click', function () {
            if (! selecteur || ! selecteur.value) {
                ouvrePanneau(t('relever_sans_serveur'), [], t('relever_titre'));
                if (pLegacy) { pLegacy.hidden = true; }
                if (pConfirmer) { pConfirmer.hidden = true; }
                gesteConfirme = null;

                return;
            }
            ouvrePanneau(t('np_relever_detail'), [
                surServeur(),
                t('relever_ecrit'),
            ], t('relever_titre'));
            if (pLegacy) { pLegacy.hidden = true; }
            if (pConfirmer) {
                pConfirmer.hidden = false;
                pConfirmer.disabled = false;
                pConfirmer.textContent = t('relever_lancer');
            }
            gesteConfirme = lanceReleve;
        });
    }

    /*
     * ══ A3 — LIRE `sshd_config` SUR UN SERVEUR ═══════════════════════════
     *
     * ⚠ CE GESTE JOINT LA MACHINE. `POST /ssh-audit/config` ouvre une session
     * SSH REELLE (`ssh_audit.py:372`) pour lire le fichier. C'est une LECTURE
     * — rien n'est ecrit, ni sur la machine ni en base — mais ce n'est pas une
     * lecture locale, et le panneau le dit AVANT le clic.
     *
     * L'ECRITURE, elle, reste NON PORTEE : `np_config` le declare toujours, et
     * `np_config_detail` garde sa reserve, qui porte precisement sur elle —
     * ecrire dans `sshd_config` et recharger le service peut couper le seul
     * canal dont RootWarden dispose pour y revenir.
     *
     * LA LECTURE SEULE EST DITE A L'ECRAN, pas deduite de l'absence d'un
     * bouton : une absence se lit comme un oubli.
     */
    var cfgBloc = document.querySelector('[data-rw="audit-ssh-config-bloc"]');
    var cfgTitre = document.querySelector('[data-rw="audit-ssh-config-titre"]');
    var cfgContenu = document.querySelector('[data-rw="audit-ssh-config-contenu"]');

    function litConfig() {
        if (! selecteur || ! selecteur.value) { return; }
        var mid = selecteur.value;
        var opt = selecteur.options[selecteur.selectedIndex];
        var nom = opt ? opt.textContent : String(mid);

        if (pConfirmer) { pConfirmer.disabled = true; }
        if (cfgBloc && cfgTitre && cfgContenu) {
            cfgBloc.hidden = false;
            cfgTitre.textContent = t('cfg_titre_resultat', { nom: nom });
            cfgContenu.textContent = t('cfg_en_cours');
        }

        ecris('/ssh-audit/config', { machine_id: Number(mid) }).then(function (r) {
            fermePanneau();
            if (! cfgContenu) { return; }
            /*
             * LES TROIS ISSUES SONT SEPAREES. Un refus (« on ne vous a pas
             * laisse regarder ») n'est pas un echec de lecture (« le fichier
             * n'a pas pu etre lu »), et aucun des deux n'est un fichier vide.
             * Les confondre fait chercher au mauvais endroit — la lecon des
             * trois issues exclusives que cette page applique deja ailleurs.
             */
            if (! r.ok) {
                cfgContenu.textContent = t('cfg_refus', {
                    message: (r.corps && r.corps.message) || '',
                });
                return;
            }
            if (! r.corps || r.corps.success !== true) {
                cfgContenu.textContent = t('cfg_echec', {
                    message: (r.corps && r.corps.message) || '',
                });
                return;
            }
            var contenu = String(r.corps.config || '');
            cfgContenu.textContent = contenu === '' ? t('cfg_vide') : contenu;
        });
    }

    var bConfig = document.querySelector('[data-rw="audit-ssh-config"]');
    if (bConfig) {
        bConfig.addEventListener('click', function () {
            if (! selecteur || ! selecteur.value) {
                // SANS CIBLE, PAS DE PANNEAU. Un panneau qui demande de
                // confirmer une lecture « sur le serveur choisi » alors
                // qu'aucun ne l'est ferait consentir a rien de nommable.
                ouvrePanneau(t('cfg_sans_serveur'), [], t('cfg_titre'));
                if (pLegacy) { pLegacy.hidden = true; }
                if (pConfirmer) { pConfirmer.hidden = true; }
                gesteConfirme = null;
                return;
            }
            ouvrePanneau(t('cfg_texte'), [surServeur()], t('cfg_titre'));
            if (pLegacy) { pLegacy.hidden = true; }
            if (pConfirmer) {
                pConfirmer.hidden = false;
                pConfirmer.disabled = false;
                pConfirmer.textContent = t('cfg_lire');
            }
            gesteConfirme = litConfig;
        });
    }

    /*
     * ══ A2 — LA CREATION D'UN RELEVE PLANIFIE ════════════════════════════
     *
     * LA CONTRAINTE LAISSEE PAR A1 EST HONOREE, et elle disait ceci : « un
     * champ de portee vide se refuse A L'ECRAN, avec la raison, avant que la
     * requete parte. Et pas par un `required` muet — le premier garde vit dans
     * le NAVIGATEUR, le second dans le serveur, et les deux doivent dire la
     * MEME chose. »
     *
     * Donc AUCUN `required` sur le selecteur de valeur : le refus est un
     * TEXTE, `planif_valeur_requise`, qui nomme la consequence — sans valeur,
     * la portee viserait tout le parc, production comprise. Un `required`
     * seul bloquerait la soumission sans rien dire, ce qui est le meme silence
     * deplace d'un cran.
     *
     * Le rempart, lui, est cote serveur : `400` sur une portee hors liste,
     * `400` sur une portee non-`all` sans valeur. Ce formulaire evite
     * l'erreur ; il ne la refuse pas A LA PLACE du backend.
     */
    var planifBloc = document.querySelector('[data-rw="audit-ssh-planif-bloc"]');
    var planifNom = document.querySelector('[data-rw="audit-ssh-planif-nom"]');
    var planifFreq = document.querySelector('[data-rw="audit-ssh-planif-freq"]');
    var planifPortee = document.querySelector('[data-rw="audit-ssh-planif-portee"]');
    var planifValeur = document.querySelector('[data-rw="audit-ssh-planif-valeur"]');
    var planifValeurBloc = document.querySelector('[data-rw="audit-ssh-planif-valeur-bloc"]');
    var planifValeurAide = document.querySelector('[data-rw="audit-ssh-planif-valeur-aide"]');
    var planifMessage = document.querySelector('[data-rw="audit-ssh-planif-message"]');
    var planifValider = document.querySelector('[data-rw="audit-ssh-planif-valider"]');
    var planifAnnuler = document.querySelector('[data-rw="audit-ssh-planif-annuler"]');
    var pConfirmer = document.querySelector('[data-rw="audit-ssh-panneau-confirmer"]');

    var LISTES = { environment: [], tag: [], machines: [] };
    try {
        var blocListes = document.getElementById('audit-ssh-planif-listes');
        if (blocListes) { LISTES = JSON.parse(blocListes.textContent || '{}'); }
    } catch (e) { LISTES = { environment: [], tag: [], machines: [] }; }

    /** Ce que « Confirmer » executera. Remis a null par la fermeture. */
    var gesteConfirme = null;
    if (pConfirmer) {
        pConfirmer.addEventListener('click', function () {
            if (typeof gesteConfirme === 'function') { gesteConfirme(); }
        });
    }

    /*
     * Le retour du geste. Meme idiome que `comptes.js` : la CLASSE porte le
     * verdict, pas seulement le texte — un succes rendu dans un style d'erreur
     * se lit comme un echec.
     */
    function annoncePlanif(texte, echec) {
        if (! planifMessage) { return; }
        planifMessage.className = echec ? 'rw-erreur' : 'rw-annonce rw-annonce--ok';
        planifMessage.textContent = texte;
        planifMessage.hidden = false;
    }

    function dis(hote, texte) {
        if (! hote) { return; }
        hote.textContent = texte || '';
        hote.hidden = ! texte;
    }

    /*
     * La valeur de portee : une liste FERMEE par type, remplie depuis les
     * donnees du serveur. `all` n'a pas de valeur — et c'est le seul cas ou
     * son absence est legitime.
     *
     * Une liste VIDE se dit : « aucun tag n'est porte par une machine du
     * parc » vaut mieux qu'un selecteur vide, qui se lit comme une panne.
     */
    function majValeur() {
        // Repli VIDE, plus « all ». Le commentaire ci-dessus choisissait « tout
        // le parc » pour ne pas afficher un selecteur vide — un raisonnement
        // d'AFFICHAGE, qui produisait le defaut le plus large a la SOUMISSION.
        var type = planifPortee ? planifPortee.value : '';
        if (! planifValeur || ! planifValeurBloc) { return; }
        planifValeur.innerHTML = '';
        dis(planifValeurAide, '');

        // `!type` couvre le repli : sans selecteur, on ne demande pas une
        // valeur pour une portee qu'on ne connait pas.
        if (! type || type === 'all') {
            planifValeurBloc.hidden = true;
            return;
        }
        planifValeurBloc.hidden = false;
        var valeurs = LISTES[type] || [];
        if (! valeurs.length) {
            dis(planifValeurAide, type === 'tag' ? t('planif_aucun_tag') : t('planif_aucune_machine'));
            return;
        }
        valeurs.forEach(function (v) {
            var o = document.createElement('option');
            if (type === 'machines') {
                o.value = String(v.id);
                o.textContent = String(v.nom);
            } else {
                o.value = String(v);
                o.textContent = String(v);
            }
            planifValeur.appendChild(o);
        });
    }

    if (planifPortee) { planifPortee.addEventListener('change', majValeur); }

    var bPlanif = document.querySelector('[data-rw="audit-ssh-planif-creer"]');
    if (bPlanif && planifBloc) {
        bPlanif.addEventListener('click', function () {
            planifBloc.hidden = ! planifBloc.hidden;
            if (! planifBloc.hidden) {
                dis(planifMessage, '');
                majValeur();
                planifBloc.scrollIntoView({ block: 'nearest' });
            }
        });
    }
    if (planifAnnuler && planifBloc) {
        planifAnnuler.addEventListener('click', function () {
            planifBloc.hidden = true;
            dis(planifMessage, '');
        });
    }

    /** Ce que la planification VISERA, en clair, pour le panneau. */
    function porteeAnnoncee(type, valeur) {
        if (type === 'all') { return t('planif_cible_parc'); }
        if (type === 'tag') { return t('planif_cible_tag', { valeur: valeur }); }
        if (type === 'environment') { return t('planif_cible_env', { valeur: valeur }); }
        return t('planif_cible_machines', { n: 1 });
    }

    if (planifValider) {
        planifValider.addEventListener('click', function () {
            var nom = (planifNom && planifNom.value || '').trim();
            var type = planifPortee ? planifPortee.value : '';
            var valeur = (type !== 'all' && planifValeur) ? planifValeur.value : '';

            // LES DEUX REFUS SONT DES TEXTES, jamais un blocage muet.
            if (! nom) {
                dis(planifMessage, t('planif_nom_requis'));
                if (planifNom) { planifNom.focus(); }
                return;
            }
            /*
             * `! type` D'ABORD : sans selecteur, le repli valait « all » et
             * cette garde ne tirait pas — on soumettait donc un releve du parc
             * entier sans valeur. Desormais l'absence de portee REFUSE, comme
             * une valeur manquante.
             */
            if (! type || (type !== 'all' && ! valeur)) {
                dis(planifMessage, t('planif_valeur_requise'));
                return;
            }
            dis(planifMessage, '');

            /*
             * LE PANNEAU AVANT L'ECRITURE. Ce qu'on arme ouvre des sessions
             * SSH reelles, a repetition, sans personne devant l'ecran :
             * `np_planif_detail` le dit, et `planif_cible_ambigue` dit que
             * « tout le parc » est a la fois un choix legitime et ce que
             * produit une cible incomplete.
             */
            ouvrePanneau(t('np_planif_detail'), [
                porteeAnnoncee(type, valeur),
                type === 'all' ? t('planif_cible_ambigue') : '',
            ], t('planif_conf_titre'));
            /*
             * LE LIEN VERS L'ANCIEN PORTAIL N'A AUCUN OBJET ICI : ce geste est
             * porte. L'offrir a cote d'un « Enregistrer » qui fonctionne
             * inviterait a aller le faire ailleurs — et a l'image il etait
             * rendu comme l'action PRINCIPALE, a droite du bouton qui marche.
             */
            if (pLegacy) { pLegacy.hidden = true; }
            if (pConfirmer) {
                pConfirmer.hidden = false;
                pConfirmer.disabled = false;
            }
            gesteConfirme = function () { enregistrePlanif(nom, type, valeur); };
        });
    }

    /*
     * L'ECRITURE. `cron_expression` part telle que le selecteur la porte —
     * une des QUATRE valeurs de `AuditSshController::FREQUENCES`. Le backend
     * la revalide (croniter + plancher de dix minutes) : c'est lui qui garde.
     */
    function enregistrePlanif(nom, type, valeur) {
        if (pConfirmer) { pConfirmer.disabled = true; }
        var corps = {
            name: nom,
            cron_expression: planifFreq ? planifFreq.value : '',
            target_type: type,
        };
        if (type !== 'all') { corps.target_value = valeur; }

        ecris('/ssh-audit/schedules', corps).then(function (r) {
            var ok = r.ok && r.corps && r.corps.success === true;
            fermePanneau();
            if (! ok) {
                annoncePlanif(t('planif_echec', {
                    message: (r.corps && r.corps.message) || '',
                }), true);
                return;
            }
            if (planifBloc) { planifBloc.hidden = true; }
            dis(planifMessage, '');
            annoncePlanif(t('planif_creee', {
                nom: nom,
                quand: String(r.corps.next_run || '').slice(0, 16),
            }));
            chargePlanifs();
        });
    }

    // ── L'HISTORIQUE — `GET /results`, TOUJOURS avec `machine_id` ────────
    var hoteHisto = document.querySelector('[data-rw="audit-ssh-historique"]');

    function chargeHistorique(id) {
        if (! hoteHisto) { return; }
        if (! id) { vide(hoteHisto, t('historique_choisir')); return; }

        hoteHisto.textContent = t('chargement');
        lis('/ssh-audit/results?machine_id=' + encodeURIComponent(id)).then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { vide(hoteHisto, t('historique_err'), true); return; }
            var releves = r.corps.results || r.corps.history || [];
            if (! releves.length) { vide(hoteHisto, t('historique_vide')); return; }

            hoteHisto.textContent = '';
            var liste = document.createElement('div');
            liste.className = 'rw-liste-etats';
            releves.forEach(function (x) {
                var ligne = document.createElement('div');
                ligne.className = 'rw-liste-etats__ligne';

                var g = document.createElement('span');
                g.className = 'rw-liste-etats__nom';
                g.textContent = t('note') + ' ' + Number(x.score || 0) + ' · ' + t('lettre') + ' ' + String(x.grade || '');

                var d = document.createElement('span');
                // Les QUATRE severites, pas les deux plus graves. N'afficher que
                // critique et haute laisserait croire qu'un relevé sans elles est
                // sans constat — alors que le total peut etre eleve.
                d.textContent = [
                    Number(x.critical_count || 0) + ' ' + t('sev_critique'),
                    Number(x.high_count || 0) + ' ' + t('sev_haute'),
                    Number(x.medium_count || 0) + ' ' + t('sev_moyenne'),
                    Number(x.low_count || 0) + ' ' + t('sev_basse'),
                    t('le') + ' ' + String(x.scan_date || x.created_at || '').slice(0, 16),
                ].join(' · ');

                ligne.appendChild(g);
                ligne.appendChild(d);
                liste.appendChild(ligne);
            });
            hoteHisto.appendChild(liste);
        });
    }

    // ── LA POLITIQUE — `GET /policies` SEUL, jamais le POST ──────────────
    var hotePol = document.querySelector('[data-rw="audit-ssh-politique"]');

    function chargePolitique(id) {
        if (! hotePol) { return; }
        if (! id) { vide(hotePol, t('politique_choisir')); return; }

        hotePol.textContent = t('chargement');
        lis('/ssh-audit/policies?machine_id=' + encodeURIComponent(id)).then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { vide(hotePol, t('politique_err'), true); return; }
            var regles = r.corps.policies || [];
            if (! regles.length) { vide(hotePol, t('politique_vide')); return; }

            hotePol.textContent = '';
            var liste = document.createElement('div');
            liste.className = 'rw-liste-etats';
            regles.forEach(function (p) {
                var ligne = document.createElement('div');
                ligne.className = 'rw-liste-etats__ligne';

                var n = document.createElement('span');
                n.className = 'rw-liste-etats__nom';
                n.textContent = String(p.directive || p.rule_key || '');

                var e = document.createElement('span');
                var audite = p.audit === undefined ? p.enabled : p.audit;
                var bout = audite ? t('politique_auditee') : t('politique_ignoree');
                if (p.reason) { bout += ' — ' + t('politique_motif') + ' : ' + String(p.reason); }
                e.textContent = bout;

                ligne.appendChild(n);
                ligne.appendChild(e);
                liste.appendChild(ligne);
            });
            hotePol.appendChild(liste);
        });
    }

    if (selecteur) {
        selecteur.addEventListener('change', function () {
            chargeHistorique(selecteur.value);
            chargePolitique(selecteur.value);
        });
    }

    // ── LA FLOTTE — reservee a l'administration, NON bornee au perimetre ──
    var hoteFlotte = document.querySelector('[data-rw="audit-ssh-flotte"]');
    if (hoteFlotte) {
        hoteFlotte.textContent = t('chargement');
        lis('/ssh-audit/fleet').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { vide(hoteFlotte, t('flotte_err'), true); return; }
            var lignes = r.corps.fleet || r.corps.servers || [];
            if (! lignes.length) { vide(hoteFlotte, t('flotte_vide')); return; }

            hoteFlotte.textContent = '';
            var cadre = document.createElement('div');
            cadre.className = 'rw-tableau-cadre';
            var tab = document.createElement('table');
            tab.className = 'rw-tableau';

            var thead = document.createElement('thead');
            var tr = document.createElement('tr');
            ['th_serveur', 'th_ip', 'th_note', 'th_mention', 'th_critiques', 'th_releve_le'].forEach(function (c) {
                var th = document.createElement('th');
                th.textContent = t(c);
                tr.appendChild(th);
            });
            thead.appendChild(tr);
            tab.appendChild(thead);

            var tbody = document.createElement('tbody');
            lignes.forEach(function (m) {
                var l = document.createElement('tr');
                [
                    String(m.name || ''),
                    String(m.ip || ''),
                    m.score == null ? '—' : String(m.score),
                    String(m.grade || '—'),
                    m.critical_count == null ? '—' : String(m.critical_count),
                    String(m.last_scan || m.scan_date || '—').slice(0, 16),
                ].forEach(function (v) {
                    var td = document.createElement('td');
                    td.textContent = v;
                    l.appendChild(td);
                });
                tbody.appendChild(l);
            });
            tab.appendChild(tbody);
            cadre.appendChild(tab);
            hoteFlotte.appendChild(cadre);
        });
    }

    // ── LES PLANIFICATIONS — lecture seule en A1 ─────────────────────────
    var hotePlanifs = document.querySelector('[data-rw="audit-ssh-planifs"]');

    /*
     * ⚠ E-280 — CE QUE LA CIBLE VEUT DIRE, ET CE QU'ELLE NE DIT PAS.
     *
     * `scheduler.py` route sur `target_type` : `tag`, `environment`,
     * `machines`, et un `else` final.
     *
     * CORRIGE apres remesure : `target_type` EST une liste fermee en base
     * (`enum('all','tag','environment','machines') NOT NULL DEFAULT 'all'`),
     * donc une valeur inventee est refusee. Ce qui reste atteignable est une
     * cible INCOMPLETE — « par tag » dont le champ est reste blanc :
     * `elif target_type == 'tag' and target_value` est faux, et l'on tombe
     * dans le `else`.
     *
     * **Une garde placee dans la CONDITION D'ENTREE ne garde pas la branche :
     * elle en detourne.** La branche `machines` fait l'inverse — elle entre,
     * puis rend `WHERE 1=0` sur une liste vide. Deux facons opposees de
     * traiter le meme cas, dans la meme fonction.
     *
     * On distingue donc a l'ecran ce que la donnee permet de distinguer, et
     * on nomme le reste « non reconnu » plutot que de le presenter comme un
     * choix.
     */
    function cible(p) {
        var type = String(p.target_type || '');
        var valeur = p.target_value;

        if (type === 'tag' && valeur) { return t('planif_cible_tag', { valeur: String(valeur) }); }
        if (type === 'environment' && valeur) { return t('planif_cible_env', { valeur: String(valeur) }); }
        if (type === 'machines' && valeur) {
            var n = 0;
            try { var ids = JSON.parse(valeur); n = Array.isArray(ids) ? ids.length : 0; } catch (e) { n = 0; }
            return t('planif_cible_machines', { n: n });
        }
        if (type === 'all') { return t('planif_cible_parc'); }
        return t('planif_cible_inconnue');
    }

    /*
     * Nommee pour A2 : apres une creation, la liste est RELUE plutot que
     * completee a la main. Le backend a resolu `next_run` lui-meme, et une
     * ligne ajoutee au DOM porterait la valeur qu'on croit plutot que celle
     * qu'il a inscrite.
     */
    function chargePlanifs() {
        if (! hotePlanifs) { return; }
        hotePlanifs.textContent = t('chargement');
        return lis('/ssh-audit/schedules').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { vide(hotePlanifs, t('planifs_err'), true); return; }
            var planifs = r.corps.schedules || [];
            if (! planifs.length) { vide(hotePlanifs, t('planifs_vide')); return; }

            hotePlanifs.textContent = '';
            var liste = document.createElement('div');
            liste.className = 'rw-liste-etats';
            planifs.forEach(function (p) {
                var ligne = document.createElement('div');
                ligne.className = 'rw-liste-etats__ligne';

                var n = document.createElement('span');
                n.className = 'rw-liste-etats__nom';
                n.textContent = String(p.name || '');

                var d = document.createElement('span');
                d.textContent = [
                    String(p.cron_expression || ''),
                    cible(p),
                    p.enabled ? t('planif_active') : t('planif_suspendue'),
                    p.next_run ? t('planif_prochaine') + ' ' + String(p.next_run).slice(0, 16) : '',
                ].filter(Boolean).join(' · ');

                ligne.appendChild(n);
                ligne.appendChild(d);
                liste.appendChild(ligne);
            });
            hotePlanifs.appendChild(liste);
        });
    }

    chargePlanifs();
})();
