/**
 * bashrc.js - Deploiement du `.bashrc` standardise, sous-lot B1.
 *
 * B1 ne porte que la page : la bascule des trois onglets, et le compteur de
 * selection. Les gestes qui joignent une machine sont B2 et B4 — ce fichier
 * n'emet AUCUNE requete.
 *
 * DEUX CORRECTIONS DE PRESENTATION, toutes deux vues a l'image du legacy.
 *
 * 1. **Le compteur s'ENONCE.** Le legacy affiche « Serveurs cibles 0 ». Un `0`
 *    se lit comme une donnee, pas comme un etat. Et quand la selection contient
 *    une machine de production, le compteur le DIT — decider d'un geste sans
 *    savoir qu'il porte sur la production n'a pas de sens.
 *
 * 2. **Les onglets basculent par un clic reel**, avec `aria-selected` tenu a
 *    jour : la suite B1 clique le bouton et lit l'attribut, elle n'appelle
 *    aucune fonction de la page.
 */
(function () {
    'use strict';

    /* ═══ LES ONGLETS ═════════════════════════════════════════════════════ */

    var onglets = [].slice.call(document.querySelectorAll('[data-panneau]'));
    if (onglets.length) {
        onglets.forEach(function (bouton) {
            bouton.addEventListener('click', function () {
                onglets.forEach(function (b) {
                    var actif = (b === bouton);
                    b.classList.toggle('rw-onglet--actif', actif);
                    b.setAttribute('aria-selected', actif ? 'true' : 'false');
                    var panneau = document.querySelector(
                        '[data-rw="bashrc-panneau-' + b.dataset.panneau + '"]');
                    if (panneau) { panneau.hidden = ! actif; }
                });
            });
        });
    }

    /* ═══ LE COMPTEUR, QUI S'ENONCE ═══════════════════════════════════════ */

    var compteur = document.querySelector('[data-rw="bashrc-compteur"]');
    var cases = [].slice.call(document.querySelectorAll('[data-rw^="bashrc-cible-"]'));
    if (! compteur || ! cases.length) { return; }

    // Les phrases viennent du gabarit, jamais du JS : une chaine ecrite ici
    // echapperait aux deux catalogues et n'aurait pas de version anglaise.
    var textes = {};
    try {
        var bloc = document.getElementById('bashrc-textes');
        if (bloc) { textes = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { textes = {}; }

    function annonce() {
        var choisies = cases.filter(function (c) { return c.checked; });
        var prod = choisies.filter(function (c) { return c.dataset.sensible === '1'; }).length;

        if (choisies.length === 0) {
            compteur.textContent = textes.aucune || '';
        } else if (prod > 0) {
            compteur.textContent = (textes.avec_prod || '')
                .replace(':nb', String(choisies.length)).replace(':prod', String(prod));
        } else if (choisies.length === 1) {
            compteur.textContent = textes.une || '';
        } else {
            compteur.textContent = (textes.plusieurs || '').replace(':nb', String(choisies.length));
        }
        // La ligne porte l'etat de danger de la SELECTION, pas du parc : une
        // machine de production presente mais non cochee n'a pas a alarmer.
        compteur.classList.toggle('rw-erreur', prod > 0);
    }

    cases.forEach(function (c) { c.addEventListener('change', annonce); });
    annonce();

    /* ═══ B2 : LES DEUX LECTURES DISTANTES ════════════════════════════════ */

    var PASSERELLE = '/api/gateway';

    var etatComptes = document.querySelector('[data-rw="bashrc-comptes-etat"]');
    var blocComptes = document.querySelector('[data-rw="bashrc-comptes"]');
    var corpsComptes = document.querySelector('[data-rw="bashrc-comptes-corps"]');
    var toutCocher = document.querySelector('[data-rw="bashrc-comptes-tout"]');
    var boutonApercu = document.querySelector('[data-rw="bashrc-apercu"]');
    var panneauApercu = document.querySelector('[data-rw="bashrc-apercu-panneau"]');
    var contenuApercu = document.querySelector('[data-rw="bashrc-apercu-contenu"]');
    if (! etatComptes || ! blocComptes) { return; }

    /** La machine cochee, s'il n'y en a QU'UNE. Sinon `null`. */
    function machineUnique() {
        var choisies = cases.filter(function (c) { return c.checked; });

        return choisies.length === 1 ? parseInt(choisies[0].value, 10) : null;
    }

    /**
     * Appelle la passerelle. FAIL-CLOSED : sans `success === true` on annonce un
     * echec plutot qu'un tableau vide, qui se lirait comme « cette machine n'a
     * aucun compte » — un mensonge sur ce qu'on a pu observer.
     */
    function lit(chemin, options) {
        return fetch(PASSERELLE + chemin, options || {})
            .then(function (r) { return r.json().catch(function () { return null; }); })
            .then(function (d) { return (d && d.success === true) ? d : null; })
            .catch(function () { return null; });
    }

    function videComptes(message) {
        blocComptes.hidden = true;
        corpsComptes.innerHTML = '';
        panneauApercu.hidden = true;
        etatComptes.textContent = message;
    }

    function ligneCompte(u) {
        var tr = document.createElement('tr');
        var estRoot = (u.name === 'root');

        var tdCase = document.createElement('td');
        var etiquette = document.createElement('label');
        etiquette.className = 'rw-champ rw-champ--case';
        var boite = document.createElement('input');
        boite.type = 'checkbox';
        boite.className = 'rw-case';
        boite.value = u.name;
        boite.setAttribute('data-rw', 'bashrc-compte-' + u.name);
        var cache = document.createElement('span');
        cache.className = 'rw-visuellement-cache';
        cache.textContent = u.name;
        etiquette.appendChild(boite);
        etiquette.appendChild(cache);
        tdCase.appendChild(etiquette);

        var tdNom = document.createElement('td');
        var fort = document.createElement('span');
        fort.className = 'rw-tableau__fort';
        fort.textContent = u.name;
        tdNom.appendChild(fort);
        // `root` SE SIGNALE. Le legacy l'affiche comme les autres alors que son
        // `.bashrc` s'execute a chaque connexion administrateur.
        if (estRoot) {
            var marque = document.createElement('span');
            marque.className = 'rw-badge rw-badge--alerte';
            marque.setAttribute('data-rw', 'bashrc-marque-root');
            marque.title = textes.root_aide || '';
            // Le badge NOMME LE ROLE, il ne repete pas le nom du compte : la
            // ligne affichait « root root ».
            marque.textContent = textes.root || '';
            tdNom.appendChild(marque);
        }

        var tdUid = document.createElement('td');
        tdUid.textContent = String(u.uid);
        var tdHome = document.createElement('td');
        var codeHome = document.createElement('code');
        codeHome.className = 'rw-code';
        codeHome.textContent = u.home || '';
        tdHome.appendChild(codeHome);
        var tdFichier = document.createElement('td');
        tdFichier.textContent = u.exists ? ((u.size || 0) + ' o') : (textes.absent || '');
        // `has_custom` EST RENDU PAR LA ROUTE, ET LE LEGACY LE JETTE ICI.
        //
        // C'est le seul signal qui dit si « fusionner » preservera quoi que ce
        // soit pour ce compte — et il arrive AVANT le choix, pas apres. Sans
        // blocs marques `USER CUSTOM`, « fusionner » equivaut a « ecraser »
        // (voir MODULE-BASHRC.md §4.5).
        if (u.has_custom) {
            var perso = document.createElement('span');
            perso.className = 'rw-badge rw-badge--note';
            perso.setAttribute('data-rw', 'bashrc-perso-' + u.name);
            perso.title = textes.perso_aide || '';
            perso.textContent = textes.perso || '';
            tdFichier.appendChild(document.createTextNode(' '));
            tdFichier.appendChild(perso);
        }

        [tdCase, tdNom, tdUid, tdHome, tdFichier].forEach(function (t) { tr.appendChild(t); });
        if (estRoot) { tr.className = 'rw-ligne-sensible'; }

        return tr;
    }

    function chargeComptes() {
        var mid = machineUnique();
        var choisies = cases.filter(function (c) { return c.checked; }).length;
        if (choisies === 0) { videComptes(textes.choisir || ''); return; }
        if (mid === null) { videComptes(textes.plusieurs_cochees || ''); return; }

        etatComptes.textContent = textes.chargement || '';
        blocComptes.hidden = true;
        panneauApercu.hidden = true;

        lit('/bashrc/users?machine_id=' + mid).then(function (d) {
            if (! d || ! Array.isArray(d.users)) { videComptes(textes.echec || ''); return; }
            if (d.users.length === 0) { videComptes(textes.aucun || ''); return; }
            corpsComptes.innerHTML = '';
            d.users.forEach(function (u) { corpsComptes.appendChild(ligneCompte(u)); });
            etatComptes.textContent = '';
            blocComptes.hidden = false;
            if (toutCocher) { toutCocher.checked = false; }
        });
    }

    cases.forEach(function (c) { c.addEventListener('change', chargeComptes); });

    if (toutCocher) {
        toutCocher.addEventListener('change', function () {
            corpsComptes.querySelectorAll('input[type="checkbox"]').forEach(function (b) {
                b.checked = toutCocher.checked;
            });
        });
    }

    if (boutonApercu) {
        boutonApercu.addEventListener('click', function () {
            var mid = machineUnique();
            var comptes = [].slice.call(corpsComptes.querySelectorAll('input[type="checkbox"]'))
                .filter(function (b) { return b.checked; })
                .map(function (b) { return b.value; });

            panneauApercu.hidden = false;

            // E-376 : TROIS etats, un seul message. `chargeComptes` les separe
            // deja vingt lignes plus haut — on lui applique sa propre
            // convention plutot que d'en inventer une, et AUCUNE cle nouvelle
            // n'est necessaire.
            //
            // Le defaut n'etait pas seulement d'etre peu discriminant :
            // `apercu_vide` ne parle que des COMPTES (« Cochez au moins un
            // compte »). L'afficher quand la MACHINE est en cause prescrivait
            // le mauvais remede, a quelqu'un qui avait peut-etre deja coche
            // ses comptes.
            if (cases.filter(function (c) { return c.checked; }).length === 0) {
                contenuApercu.textContent = textes.choisir || '';

                return;
            }
            if (mid === null) {
                contenuApercu.textContent = textes.plusieurs_cochees || '';

                return;
            }
            if (comptes.length === 0) {
                contenuApercu.textContent = textes.apercu_vide || '';

                return;
            }
            contenuApercu.textContent = textes.apercu_chargement || '';
            boutonApercu.disabled = true;

            // `mode` PART TOUJOURS, et vaut `merge` — le defaut du legacy.
            // Le selecteur de mode appartient au DEPLOIEMENT (B4) ; tant qu'il
            // n'est pas porte, l'apercu montre ce que montrerait le legacy sans
            // qu'on ait touche a son selecteur. A relier au selecteur des qu'il
            // existe, sans quoi l'apercu montrerait un autre mode que celui qui
            // sera deploye — et un apercu qui ne correspond pas au geste est
            // pire que pas d'apercu.
            lit('/bashrc/preview', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ machine_id: mid, users: comptes, mode: 'merge' }),
            }).then(function (d) {
                boutonApercu.disabled = false;
                if (! d || ! Array.isArray(d.results)) {
                    contenuApercu.textContent = textes.apercu_echec || '';

                    return;
                }
                contenuApercu.innerHTML = '';
                d.results.forEach(function (r) {
                    var bloc = document.createElement('div');
                    var titre = document.createElement('p');
                    titre.className = 'rw-sous-titre-fort';
                    titre.textContent = r.user + ' — '
                        + (textes.taille || '').replace(':avant', String(r.current_bytes || 0))
                            .replace(':apres', String(r.new_bytes || 0));
                    // LE DIFF SE REND LIGNE A LIGNE.
                    //
                    // Une premiere redaction employait `.rw-code--fichier`, qui
                    // porte `white-space: nowrap` parce qu'il est fait pour UN
                    // NOM DE FICHIER : tout le diff s'affichait sur une seule
                    // ligne. Un diff a plat ne se lit pas, il se devine.
                    //
                    // Chaque ligne devient un element pour porter sa couleur.
                    // `textContent` partout : le diff vient d'un fichier de la
                    // machine, donc d'une source qu'on ne controle pas.
                    var diff = document.createElement('pre');
                    diff.className = 'rw-diff';
                    (r.diff || '').split('\n').forEach(function (l) {
                        var ligne = document.createElement('span');
                        var classe = 'rw-diff__ligne';
                        if (/^\+\+\+|^---|^@@/.test(l)) { classe += ' rw-diff__ligne--entete'; }
                        else if (l.charAt(0) === '+') { classe += ' rw-diff__ligne--ajout'; }
                        else if (l.charAt(0) === '-') { classe += ' rw-diff__ligne--retrait'; }
                        ligne.className = classe;
                        ligne.textContent = l || ' ';
                        diff.appendChild(ligne);
                    });
                    bloc.appendChild(titre);
                    bloc.appendChild(diff);
                    contenuApercu.appendChild(bloc);
                });
            });
        });
    }

    chargeComptes();

    /* ═══ B3 : L'ONGLET GABARIT ═══════════════════════════════════════════ */

    var editeur = document.querySelector('[data-rw="bashrc-gabarit-editeur"]');
    var metaLignes = document.querySelector('[data-rw="bashrc-gabarit-lignes"]');
    var metaOctets = document.querySelector('[data-rw="bashrc-gabarit-octets"]');
    var metaSha = document.querySelector('[data-rw="bashrc-gabarit-sha"]');
    var encartDanger = document.querySelector('[data-rw="bashrc-gabarit-danger"]');
    var listeDanger = document.querySelector('[data-rw="bashrc-gabarit-danger-liste"]');
    var etatGabarit = document.querySelector('[data-rw="bashrc-gabarit-etat"]');
    var enregistrer = document.querySelector('[data-rw="bashrc-gabarit-enregistrer"]');
    var annuler = document.querySelector('[data-rw="bashrc-gabarit-annuler"]');
    if (! editeur) { return; }

    var gabaritOrigine = null;

    /**
     * Les formes reconnues, compilees depuis les motifs du SERVICE.
     *
     * Jamais recopiees ici : `Bashrc::MOTIFS_DANGEREUX` est la seule source du
     * portage. Un motif illisible est ignore plutot que de faire tomber tout le
     * scan — mais il n'est alors reconnu par rien, ce qui vaut mieux qu'une page
     * qui ne charge pas.
     */
    var formes = [];
    Object.keys(textes.motifs || {}).forEach(function (nom) {
        try { formes.push({ nom: nom, re: new RegExp(textes.motifs[nom]) }); } catch (e) { /* ignore */ }
    });

    function reconnait(contenu) {
        return formes.filter(function (f) { return f.re.test(contenu); }).map(function (f) { return f.nom; });
    }

    function majMeta(contenu) {
        if (metaLignes) { metaLignes.textContent = String(contenu.split('\n').length); }
        if (metaOctets) {
            // En OCTETS, comme le stockage. `length` compte des caracteres, et
            // le gabarit fait 22 412 octets pour 17 814 caracteres : afficher
            // l'un sous le nom de l'autre ferait croire a un contenu tronque.
            metaOctets.textContent = String(new TextEncoder().encode(contenu).length);
        }
    }

    function majDanger(contenu) {
        var trouves = reconnait(contenu);
        if (! encartDanger || ! listeDanger) { return trouves; }
        if (trouves.length === 0) { encartDanger.hidden = true; return trouves; }
        // NOMMER CE QUI EST RECONNU. « Attention » sans le motif ne permet pas
        // de juger : c'est la difference entre un avertissement et une alarme.
        listeDanger.textContent = ' ' + (textes.d_reconnu || '') + ' ' + trouves.join(', ') + '. ';
        encartDanger.hidden = false;

        return trouves;
    }

    function majModifie() {
        var change = (gabaritOrigine !== null && editeur.value !== gabaritOrigine);
        if (enregistrer) { enregistrer.disabled = ! change; }
        if (annuler) { annuler.disabled = ! change; }
        if (etatGabarit) { etatGabarit.textContent = change ? (textes.g_modifie || '') : ''; }
        majMeta(editeur.value);
        majDanger(editeur.value);
    }

    function chargeGabarit() {
        etatGabarit.textContent = textes.g_chargement || '';
        lit('/bashrc/template').then(function (d) {
            if (! d || typeof d.content !== 'string') {
                etatGabarit.textContent = textes.g_echec || '';

                return;
            }
            gabaritOrigine = d.content;
            editeur.value = d.content;
            if (metaSha && d.sha8) { metaSha.textContent = d.sha8; }
            etatGabarit.textContent = '';
            majMeta(d.content);
            majDanger(d.content);
            majModifie();
        });
    }

    editeur.addEventListener('input', majModifie);
    if (annuler) {
        annuler.addEventListener('click', function () {
            if (gabaritOrigine === null) { return; }
            editeur.value = gabaritOrigine;
            majModifie();
        });
    }

    if (enregistrer) {
        enregistrer.addEventListener('click', function () {
            var trouves = majDanger(editeur.value);
            // DEUX CONFIRMATIONS DISTINCTES : celle qui NOMME ce qui a ete
            // reconnu, et celle qui rappelle simplement la portee du geste. Une
            // seule phrase pour les deux cas dirait moins dans le cas grave.
            var question = trouves.length
                ? (textes.d_confirmer || '') + '\n\n• ' + trouves.join('\n• ')
                : (textes.g_confirmer || '');
            if (! window.confirm(question)) { return; }

            enregistrer.disabled = true;
            etatGabarit.textContent = textes.g_encours || '';
            lit('/bashrc/template', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: editeur.value }),
            }).then(function (d) {
                if (! d) {
                    etatGabarit.textContent = textes.g_erreur || '';
                    enregistrer.disabled = false;

                    return;
                }
                gabaritOrigine = editeur.value;
                if (metaSha && d.sha8) { metaSha.textContent = d.sha8; }
                etatGabarit.textContent = textes.g_enregistre || '';
                majModifie();
            });
        });
    }

    // Le gabarit se charge a l'ouverture de SON onglet, pas au chargement de la
    // page : il fait 22 Ko et n'interesse pas qui vient deployer.
    var ongletGabarit = document.querySelector('[data-rw="bashrc-onglet-gabarit"]');
    if (ongletGabarit) {
        ongletGabarit.addEventListener('click', function () {
            if (gabaritOrigine === null) { chargeGabarit(); }
        });
    }
}());
