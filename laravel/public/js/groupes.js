/**
 * groupes.js — groupes de machines, sous-lot R1 : LECTURE SEULE.
 *
 * ══ CE QUE CE SCRIPT N'EMET JAMAIS ═══════════════════════════════════════
 *
 * Aucune requete autre que `GET`. Les trois gestes qui ecrivent — creation,
 * suppression, action de masse — ne sont pas portes : leurs boutons ouvrent
 * un panneau qui dit ce qu'ils engagent, puis renvoient vers l'ancien portail.
 *
 * ══ PAS DE `confirm()` ═══════════════════════════════════════════════════
 *
 * Le legacy confirme les deux actions de masse et la suppression par des
 * boites natives. Elles sont proscrites ici : elles recouvrent la ligne sur
 * laquelle on decide, ne se stylent pas, et BLOQUENT Puppeteer.
 *
 * ══ RENDU SANS `innerHTML` SUR DE LA DONNEE ══════════════════════════════
 *
 * Tout ce qui vient du backend passe par `textContent`. Le legacy fait de
 * meme via un `escHtml` maison ; on n'en a pas besoin en construisant les
 * noeuds.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var libelles = {};
    try {
        var bloc = document.getElementById('groupes-libelles');
        if (bloc) { libelles = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { libelles = {}; }

    function t(cle, subst) {
        var s = libelles[cle];
        if (typeof s !== 'string') { return cle; }
        if (subst) {
            Object.keys(subst).forEach(function (k) {
                s = s.split(':' + k).join(String(subst[k]));
            });
        }
        return s;
    }

    var liste = document.querySelector('[data-rw="groupes-liste"]');
    if (! liste) { return; }

    var panneau = document.querySelector('[data-rw="groupes-panneau"]');
    var panneauTitre = document.querySelector('[data-rw="groupes-panneau-titre"]');
    var panneauTexte = document.querySelector('[data-rw="groupes-panneau-texte"]');
    var panneauEffets = document.querySelector('[data-rw="groupes-panneau-effets"]');
    var panneauFermer = document.querySelector('[data-rw="groupes-panneau-fermer"]');

    // ── LE PANNEAU ───────────────────────────────────────────────────────
    function fermePanneau() {
        if (! panneau) { return; }
        panneau.hidden = true;
        panneauEffets.hidden = true;
        panneauEffets.textContent = '';
        // Sans cela, le bouton reste visible sur le panneau SUIVANT — celui
        // d'un geste non porte, qui n'a rien a confirmer.
        var c = document.querySelector('[data-rw="groupes-panneau-confirmer"]');
        if (c) { c.hidden = true; }
        // ...et le lien legacy REVIENT : les gestes non portes en ont besoin.
        if (panneauLegacy) { panneauLegacy.hidden = false; }
    }

    function ouvrePanneau(titre, texte, effets) {
        if (! panneau) { return; }
        panneauTitre.textContent = titre;
        panneauTexte.textContent = texte;

        panneauEffets.textContent = '';
        var lignes = (effets || []).filter(function (l) { return l; });
        // Une liste vide reste MASQUEE. Le defaut qu'on reproche au legacy est
        // precisement d'afficher une ligne blanche a la place d'une absence.
        panneauEffets.hidden = lignes.length === 0;
        lignes.forEach(function (l) {
            var li = document.createElement('li');
            li.textContent = l;
            panneauEffets.appendChild(li);
        });

        panneau.hidden = false;
        panneau.scrollIntoView({ block: 'nearest' });
    }

    if (panneauFermer) { panneauFermer.addEventListener('click', fermePanneau); }

    var enCours = null;
    var panneauConfirmer = document.querySelector('[data-rw="groupes-panneau-confirmer"]');
    var panneauLegacy = document.querySelector('[data-rw="groupes-panneau-legacy"]');
    if (panneauConfirmer) { panneauConfirmer.addEventListener('click', enregistre); }

    // ── LA PASSERELLE, EN LECTURE SEULE ──────────────────────────────────
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
     * ══ R2 — LE SEUL APPEL MUTANT DE CE FICHIER ══════════════════════════
     *
     * `POST /groups` ecrit `machine_groups` et `machine_group_members`. Il ne
     * joint AUCUNE machine : c'est ce qui le rend portable sans arbitrage,
     * contrairement aux deux actions de masse.
     *
     * Pas de jeton CSRF a poser : `PreventRequestForgery` du cadre accepte une
     * requete de MEME ORIGINE, et c'en est une. En ajouter un donnerait
     * l'illusion d'un controle qui vit ailleurs.
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

    // ── LE RESUME DES FILTRES ────────────────────────────────────────────
    var COLONNES = ['environment', 'criticality', 'network_type', 'lifecycle_status', 'tags'];

    function resumeFiltres(groupe) {
        if (groupe.group_type === 'static') { return ''; }

        var f = groupe.filters;
        if (! f || typeof f !== 'object') { f = {}; }

        var morceaux = [];
        COLONNES.forEach(function (c) {
            if (Array.isArray(f[c]) && f[c].length) { morceaux.push(f[c].join(', ')); }
        });

        /*
         * ══ E-274 : LE CAS QUE LE LEGACY REND EN LIGNE BLANCHE ═══════════
         *
         * `filtersSummary({})` rend `''`. Or `_resolve_dynamic`
         * (`backend/routes/groups.py:77`) termine par :
         *
         *     where = (' AND '.join(clauses)) if clauses else '1=1'
         *
         * Zero critere coche => `WHERE 1=1` => LE PARC ENTIER, production
         * comprise. L'ancien portail presente donc le groupe le plus large
         * possible comme une ligne vide, et le seul indice est un compteur
         * qui ne se distingue en rien de celui d'un groupe voulu.
         */
        return morceaux.length ? morceaux.join(' · ') : t('sans_filtre');
    }

    // ── LES PANNEAUX DES GESTES NON PORTES ───────────────────────────────
    /*
     * ══ R2 — LE FORMULAIRE, ET LA PORTEE ANNONCEE AVANT D'ECRIRE ═════════
     *
     * « Enregistrer » n'enregistre pas : il ouvre le panneau de decision, qui
     * dit ce que le groupe contiendra. C'est ce qui ferme E-274 — un groupe
     * dynamique SANS critere vise le parc entier, et le legacy le creait en
     * deux gestes sans jamais l'ecrire.
     */
    var form = document.querySelector('[data-rw="groupes-formulaire"]');
    var champNom = document.querySelector('[data-rw="groupes-nom"]');
    var champDesc = document.querySelector('[data-rw="groupes-desc"]');
    var blocFiltres = document.querySelector('[data-rw="groupes-filtres"]');
    var blocMembres = document.querySelector('[data-rw="groupes-membres"]');
    var msgForm = document.querySelector('[data-rw="groupes-form-message"]');

    function typeChoisi() {
        var r = document.querySelector('input[name="g-type"]:checked');
        return r ? r.value : 'dynamic';
    }

    function basculeType() {
        var dyn = typeChoisi() === 'dynamic';
        if (blocFiltres) { blocFiltres.hidden = ! dyn; }
        if (blocMembres) { blocMembres.hidden = dyn; }
    }

    function filtresCoches() {
        var f = {};
        document.querySelectorAll('.gf:checked').forEach(function (cb) {
            var c = cb.getAttribute('data-col');
            (f[c] = f[c] || []).push(cb.value);
        });
        return f;
    }

    function membresCoches() {
        return Array.prototype.map.call(
            document.querySelectorAll('.gm:checked'),
            function (cb) { return parseInt(cb.value, 10); }
        ).filter(function (n) { return ! isNaN(n); });
    }

    function ouvreFormulaire() {
        if (! form) { return; }
        form.hidden = false;
        basculeType();
        if (champNom) { champNom.focus(); }
    }

    function fermeFormulaire() {
        if (! form) { return; }
        form.hidden = true;
        if (champNom) { champNom.value = ''; }
        if (champDesc) { champDesc.value = ''; }
        document.querySelectorAll('.gf:checked, .gm:checked').forEach(function (cb) { cb.checked = false; });
        if (msgForm) { msgForm.textContent = ''; }
        basculeType();
    }

    /** Ce que le groupe contiendra, dit AVANT d'ecrire. */
    function porteeAnnoncee() {
        if (typeChoisi() === 'static') {
            var n = membresCoches().length;
            return [n ? t('portee_statique').split(':n').join(String(n)) : t('portee_statique_vide')];
        }
        var f = filtresCoches();
        var cles = Object.keys(f);
        if (! cles.length) {
            /*
             * ⚠ LE CAS QUE LE LEGACY CREE EN SILENCE. `'1=1'` => tout le parc.
             *
             * Et la reserve sur les archivees n'est pas decorative :
             * `_resolve_dynamic` (`backend/routes/groups.py:61-77`) ne filtre
             * pas `lifecycle_status`. Mais c'est DELIBERE, et non une
             * incoherence : `archived` est une valeur COCHABLE ici comme au
             * legacy (`groups/index.php:96`) et figure dans la liste blanche
             * des colonnes filtrables du backend (`groups.py:36`). Un groupe
             * DOIT pouvoir viser les archivees.
             *
             * Ce qui se signale a l'ecran n'est donc pas une contradiction,
             * c'est qu'un groupe SANS critere en contient sans qu'on l'ait
             * demande. Il y a une definition du parc et une definition de ce
             * qu'on accepte de JOINDRE -- les exclusions vues ailleurs sont
             * dans les chemins qui AGISSENT.
             */
            return [t('portee_aucun_filtre'), t('portee_archivees')];
        }
        var liste = cles.map(function (c) { return f[c].join(', '); }).join(' · ');
        return [t('portee_filtres').split(':liste').join(liste)];
    }

    function demandeEnregistrement() {
        var nom = (champNom && champNom.value || '').trim();
        if (! nom) {
            if (msgForm) { msgForm.textContent = t('err_nom'); }
            if (champNom) { champNom.focus(); }
            return;
        }
        enCours = { nom: nom };
        ouvrePanneau(t('form_titre'), nom, porteeAnnoncee());
        if (panneauConfirmer) { panneauConfirmer.hidden = false; }
        /*
         * Le lien vers l'ancien portail n'a AUCUN objet ici : ce geste est
         * porte. L'offrir a cote d'un « Enregistrer » qui fonctionne inviterait
         * a aller le faire ailleurs — c'est ce qui entretient le legacy qu'on
         * veut eteindre.
         */
        if (panneauLegacy) { panneauLegacy.hidden = true; }
    }

    function enregistre() {
        var corps = {
            name: (champNom && champNom.value || '').trim(),
            description: (champDesc && champDesc.value || ''),
            group_type: typeChoisi(),
            filters: typeChoisi() === 'dynamic' ? filtresCoches() : {},
            member_ids: typeChoisi() === 'static' ? membresCoches() : [],
        };
        ecris('/groups', corps).then(function (r) {
            fermePanneau();
            if (! r.ok || ! r.corps || ! r.corps.success) {
                if (msgForm) { msgForm.textContent = (r.corps && r.corps.message) || t('err_creation'); }
                return;
            }
            fermeFormulaire();
            charge();
        });
    }

    /*
     * ══ UN PANNEAU PARTAGE NOMME SA CIBLE ════════════════════════════════
     *
     * Il vit au niveau de la PAGE — lecon de F5, un element partage par
     * plusieurs cartes ne vit dans aucune d'elles — et sert donc quatre
     * boutons appartenant a des cartes differentes. Sans cette ligne il
     * decrit un geste sans dire sur quoi il porte, ce qui est pire qu'une
     * boite native : celle-la, au moins, s'ouvre a l'endroit du clic.
     *
     * Vu a l'image, pas a l'assertion.
     */
    function surGroupe(groupe) {
        return t('np_sur_groupe', { nom: groupe.name == null ? '' : String(groupe.name) });
    }

    function panneauSupprimer(groupe) {
        ouvrePanneau(t('np_titre'), t('np_supprimer'), [
            surGroupe(groupe),
            t('np_supprimer_detail'),
        ]);
    }

    function panneauDerive(groupe) {
        ouvrePanneau(t('np_titre'), t('np_derive'), [
            surGroupe(groupe),
            t('np_derive_detail'),
        ]);
    }

    /*
     * ══════════════════════════════════════════════════════════════════════
     *  A LIRE PAR QUI REMPLACERA CE PANNEAU PAR LE VRAI BOUTON
     * ══════════════════════════════════════════════════════════════════════
     *
     * L'action groupee `cve_scan` ENVOIE DE VRAIS COURRIELS — un par machine
     * a resultats. Ce n'est pas une prudence de principe : c'est une chaine
     * d'appels lue, et recoupee par deux sessions.
     *
     *     backend/routes/groups.py:269   from routes.cve import _stream_cve_scan
     *     backend/routes/groups.py:278   for _line in _stream_cve_scan([mid], min_cvss)
     *     backend/routes/cve.py:77       send_cve_report(...)
     *     srv-docker.env:206             MAIL_ENABLED=true      <- EN SERVICE
     *
     * **Ce geste reste sous interdiction de declenchement**, comme les autres
     * actions de masse : un seul clic produit N sessions SSH et N envois.
     *
     * ── POURQUOI CETTE NOTE EST ICI ET PAS SEULEMENT A L'ECRAN ───────────
     *
     * Le panneau ci-dessous DIT deja ce fait a l'utilisateur. Mais ce texte
     * disparaitra avec le panneau — c'est-a-dire au moment exact ou quelqu'un
     * le remplacera par le bouton reel, donc **au moment ou le fait compte le
     * plus**.
     *
     * **Une reserve qui vit dans l'objet qu'elle protege meurt quand cet objet
     * est remplace.** Le commentaire, lui, survit a la substitution.
     *
     * ══ LE PANNEAU LE PLUS IMPORTANT DU MODULE ═══════════════════════════
     *
     * Un clic, N machines, et pour CHACUNE : une session SSH reelle et un
     * rapport envoye par courriel. Le `confirm()` du legacy ne nomme ni le
     * nombre, ni les machines, ni la production.
     *
     * On RESOUT donc les membres avant d'afficher — c'est une lecture, et
     * c'est la lecture que le legacy ne fait pas avant de demander un
     * consentement. Puis on nomme la production separement.
     */
    function panneauCve(groupe) {
        ouvrePanneau(t('np_titre'), t('np_cve'), [surGroupe(groupe), t('np_cve_detail')]);

        lis('/groups/' + encodeURIComponent(groupe.id) + '/members').then(function (r) {
            var membres = (r.ok && r.corps && r.corps.success && Array.isArray(r.corps.members))
                ? r.corps.members : null;

            if (membres === null) {
                // On n'invente pas un nombre. Le panneau garde son avertissement
                // de nature, sans chiffre — un compte faux serait pire que pas
                // de compte du tout sur ce geste-la.
                ouvrePanneau(t('np_titre'), t('np_cve'), [
                    surGroupe(groupe),
                    t('np_cve_detail'),
                    t('membres_err'),
                    t('np_cve_derive'),
                ]);
                return;
            }

            var prod = membres.filter(function (m) { return m && m.environment === 'PROD'; })
                              .map(function (m) { return m.name; });

            var effets = [
                surGroupe(groupe),
                t('np_cve_detail'),
                t('np_cve_membres', { n: membres.length }),
            ];
            if (prod.length) { effets.push(t('np_cve_prod', { noms: prod.join(', ') })); }
            effets.push(t('np_cve_derive'));

            ouvrePanneau(t('np_titre'), t('np_cve'), effets);
        });
    }

    // ── LE DEPLIAGE DES MEMBRES — la seule lecture de la carte ───────────
    function basculeMembres(groupe, boite, bouton) {
        if (! boite.hidden) {
            boite.hidden = true;
            bouton.textContent = t('act_membres');
            return;
        }

        boite.hidden = false;
        bouton.textContent = t('act_masquer');
        boite.textContent = t('chargement');

        lis('/groups/' + encodeURIComponent(groupe.id) + '/members').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) {
                boite.textContent = t('membres_err');
                return;
            }
            var membres = r.corps.members || [];
            if (! membres.length) {
                boite.textContent = t('membres_aucun');
                return;
            }
            boite.textContent = '';
            membres.forEach(function (m) {
                var ligne = document.createElement('div');
                ligne.className = 'rw-liste-etats__ligne';

                var nom = document.createElement('span');
                nom.className = 'rw-liste-etats__nom';
                nom.textContent = m.name == null ? '' : String(m.name);

                var detail = document.createElement('span');
                detail.textContent = [m.environment, m.criticality].filter(Boolean).join(' / ');

                ligne.appendChild(nom);
                ligne.appendChild(detail);
                boite.appendChild(ligne);
            });
        });
    }

    // ── LE RENDU DES CARTES ──────────────────────────────────────────────
    function bouton(libelle, classe, ancre, action, titre) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'rw-bouton rw-bouton--minuscule ' + classe;
        b.textContent = libelle;
        b.setAttribute('data-rw', ancre);
        if (titre) { b.title = titre; }
        b.addEventListener('click', action);
        return b;
    }

    function carte(groupe) {
        var c = document.createElement('div');
        c.className = 'rw-carte';
        c.setAttribute('data-rw', 'groupes-carte');
        c.setAttribute('data-groupe', String(groupe.id));

        var nom = document.createElement('h2');
        nom.className = 'rw-sous-titre-fort';
        nom.textContent = groupe.name == null ? '' : String(groupe.name);
        c.appendChild(nom);

        var type = document.createElement('span');
        type.className = 'rw-badge rw-badge--neutre';
        type.textContent = groupe.group_type === 'static' ? t('type_statique') : t('type_dynamique');
        c.appendChild(type);

        if (groupe.description) {
            var d = document.createElement('p');
            d.className = 'rw-prose';
            d.textContent = String(groupe.description);
            c.appendChild(d);
        }

        var membres = document.createElement('p');
        membres.className = 'rw-vide__texte';
        membres.setAttribute('data-rw', 'groupes-carte-membres');
        membres.textContent = t('membres') + ' : ' + Number(groupe.member_count || 0);
        c.appendChild(membres);

        var resume = resumeFiltres(groupe);
        if (resume) {
            var rp = document.createElement('p');
            rp.className = 'rw-vide__texte';
            rp.setAttribute('data-rw', 'groupes-carte-filtres');
            rp.textContent = resume;
            c.appendChild(rp);
        }

        /*
         * ── DEUX VALEURS QUE LE LEGACY CALCULE ET N'AFFICHE PAS ──────────
         * `list_groups` rend `creator` et normalise `created_at` en ISO
         * (`groups.py:107-119`), et `renderGroups` n'affiche ni l'un ni
         * l'autre : la donnee voyage jusqu'au navigateur et y meurt.
         */
        var provenance = [];
        if (groupe.creator) { provenance.push(t('cree_par') + ' : ' + String(groupe.creator)); }
        if (groupe.created_at) { provenance.push(t('cree_le') + ' : ' + String(groupe.created_at).slice(0, 10)); }
        if (provenance.length) {
            var pp = document.createElement('p');
            pp.className = 'rw-vide__texte';
            pp.setAttribute('data-rw', 'groupes-carte-provenance');
            pp.textContent = provenance.join(' · ');
            c.appendChild(pp);
        }

        var boite = document.createElement('div');
        boite.className = 'rw-liste-etats';
        boite.setAttribute('data-rw', 'groupes-carte-liste-membres');
        boite.hidden = true;

        var actions = document.createElement('div');
        actions.className = 'rw-actions--groupe';

        var bMembres = bouton(t('act_membres'), 'rw-bouton--discret', 'groupes-voir-membres',
            function () { basculeMembres(groupe, boite, bMembres); }, t('aide_membres'));
        actions.appendChild(bMembres);

        actions.appendChild(bouton(t('act_derive'), 'rw-bouton--discret', 'groupes-derive',
            function () { panneauDerive(groupe); }));
        actions.appendChild(bouton(t('act_cve'), 'rw-bouton--avertissement', 'groupes-cve',
            function () { panneauCve(groupe); }));
        actions.appendChild(bouton(t('act_supprimer'), 'rw-bouton--danger', 'groupes-supprimer',
            function () { panneauSupprimer(groupe); }));

        c.appendChild(actions);
        c.appendChild(boite);
        return c;
    }

    function rendVide() {
        liste.textContent = '';
        var v = document.createElement('div');
        v.className = 'rw-vide';
        v.setAttribute('data-rw', 'groupes-vide');

        var titre = document.createElement('p');
        titre.className = 'rw-vide__titre';
        titre.textContent = t('vide_titre');

        var texte = document.createElement('p');
        texte.className = 'rw-vide__texte';
        texte.textContent = t('vide_texte');

        v.appendChild(titre);
        v.appendChild(texte);
        liste.appendChild(v);
    }

    function rendErreur() {
        liste.textContent = '';
        var v = document.createElement('div');
        v.className = 'rw-vide rw-vide--erreur';
        v.setAttribute('data-rw', 'groupes-erreur');
        var p = document.createElement('p');
        p.className = 'rw-vide__texte';
        // UNE LECTURE RATEE N'EST PAS « AUCUN GROUPE ». Rendre l'etat vide ici
        // affirmerait un fait que la reponse ne porte pas.
        p.textContent = t('err_charge');
        v.appendChild(p);
        liste.appendChild(v);
    }

    function charge() {
        lis('/groups').then(function (r) {
            if (! r.ok || ! r.corps || ! r.corps.success) { rendErreur(); return; }

            var groupes = Array.isArray(r.corps.groups) ? r.corps.groups : [];
            if (! groupes.length) { rendVide(); return; }

            liste.textContent = '';
            var grille = document.createElement('div');
            grille.className = 'rw-grille';
            groupes.forEach(function (g) { grille.appendChild(carte(g)); });
            liste.appendChild(grille);
        });
    }

    var bNouveau = document.querySelector('[data-rw="groupes-nouveau"]');
    if (bNouveau) { bNouveau.addEventListener('click', ouvreFormulaire); }

    var bAnnuler = document.querySelector('[data-rw="groupes-annuler"]');
    if (bAnnuler) { bAnnuler.addEventListener('click', fermeFormulaire); }
    var bEnregistrer = document.querySelector('[data-rw="groupes-enregistrer"]');
    if (bEnregistrer) { bEnregistrer.addEventListener('click', demandeEnregistrement); }
    document.querySelectorAll('input[name="g-type"]').forEach(function (r) {
        r.addEventListener('change', basculeType);
    });

    charge();
})();
