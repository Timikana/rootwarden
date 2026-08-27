/**
 * services.js - Gestion des services systemd, sous-lot S1.
 *
 * S1 ne porte que la PAGE : le choix d'une machine, l'etat des filtres, et
 * l'avertissement quand la machine choisie est en production. **Ce fichier
 * n'emet aucune requete** — les lectures sont S2, les ecritures S3.
 *
 * DEUX CORRECTIONS DE PRESENTATION, toutes deux mesurees par S1 sur le legacy.
 *
 * 1. **Les filtres sont montres des le depart, desactives, avec la raison.** Le
 *    legacy les garde dans le DOM mais masques jusqu'au chargement d'un serveur
 *    (`etat=false categorie=false recherche=false` au chargement). Un filtre qui
 *    apparait sans prevenir se cherche.
 * 2. **Aucun cadre vide avant le premier geste.** Le legacy affiche un panneau
 *    de journaux noir et vide des l'ouverture ; ici un texte dit qu'il n'y a
 *    rien, et le cadre ne parait qu'avec du contenu.
 */
(function () {
    'use strict';

    var textes = {};
    try {
        var bloc = document.getElementById('services-textes');
        if (bloc) { textes = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { textes = {}; }

    var choix = document.querySelector('[data-rw="services-serveur"]');
    var charger = document.querySelector('[data-rw="services-charger"]');
    var etat = document.querySelector('[data-rw="services-etat"]');
    if (! choix || ! charger || ! etat) { return; }

    /** L'option retenue, ou `null` si c'est encore l'invite. */
    function machineChoisie() {
        var o = choix.options[choix.selectedIndex];

        return (o && o.value) ? o : null;
    }

    function majEtat() {
        var o = machineChoisie();
        charger.disabled = (o === null);

        if (o === null) {
            etat.textContent = textes.choisir_serveur || '';
            etat.classList.remove('rw-erreur');

            return;
        }
        // LA PRODUCTION SE DIT AU MOMENT DU CHOIX, pas au moment du geste.
        // Charger les services ne modifie rien — mais les gestes suivants, si,
        // et c'est maintenant qu'on decide sur quelle machine on travaillera.
        var sensible = (o.dataset.sensible === '1');
        etat.textContent = sensible ? (textes.sensible_confirmer || '') : '';
        etat.classList.toggle('rw-erreur', sensible);
    }

    choix.addEventListener('change', majEtat);
    majEtat();

    /* ═══ S2 : L'ENUMERATION DISTANTE ════════════════════════════════════ */

    var PASSERELLE = '/api/gateway';

    var blocTableau = document.querySelector('[data-rw="services-bloc-tableau"]');
    var corps = document.querySelector('[data-rw="services-tableau"]');
    var compte = document.querySelector('[data-rw="services-compte"]');
    var journaux = document.querySelector('[data-rw="services-journaux"]');
    var journauxVide = document.querySelector('[data-rw="services-journaux-vide"]');
    var filtreEtat = document.querySelector('[data-rw="services-filtre-etat"]');
    var filtreCategorie = document.querySelector('[data-rw="services-filtre-categorie"]');
    var recherche = document.querySelector('[data-rw="services-recherche"]');
    var aideFiltres = document.querySelector('[data-rw="services-filtres-aide"]');

    var tous = [];

    /** Ajoute une ligne au journal de la page, et le rend visible. */
    function journalise(message) {
        if (! journaux) { return; }
        var l = document.createElement('span');
        l.textContent = message;
        journaux.appendChild(l);
        journaux.appendChild(document.createTextNode('\n'));
        journaux.hidden = false;
        if (journauxVide) { journauxVide.hidden = true; }
    }

    /**
     * Appelle la passerelle. FAIL-CLOSED : sans `success === true` on rend
     * `null`, jamais un tableau vide — qui se lirait comme « cette machine n'a
     * aucun service », un mensonge sur ce qu'on a pu observer.
     */
    function lit(chemin, envoi) {
        return fetch(PASSERELLE + chemin, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(envoi),
        }).then(function (r) { return r.json().catch(function () { return null; }); })
          .then(function (d) { return (d && d.success === true) ? d : null; })
          .catch(function () { return null; });
    }

    /**
     * Normalise une entree rendue par le backend.
     *
     * **DEUX DEFAUTS DE S2 CORRIGES ICI**, et le banc les avait masques : sans
     * systemd sur la machine d'essai, le tableau est toujours vide, donc rien de
     * faux ne s'affichait.
     *
     * 1. **Le backend envoie `unit_file_state`, pas `enabled`.** La premiere
     *    redaction lisait `svc.enabled` — toujours `undefined` — et affichait
     *    donc « non » pour TOUS les services, y compris ceux qui demarrent au
     *    boot.
     * 2. **C'est une CHAINE, pas un booleen** : `enabled`, `disabled`, `static`,
     *    `masked`, `unknown`. Un `svc.enabled ? oui : non` aurait rendu « oui »
     *    pour `disabled`, `static` ET `masked` — trois etats sur cinq affiches a
     *    l'envers. On rend donc L'ETAT REEL, qui ne peut pas mentir, plutot
     *    qu'un oui/non qui ne sait pas dire « statique ».
     * 3. Le nom perd son suffixe `.service`, comme dans le legacy.
     */
    function normalise(svc) {
        return {
            nom: (svc.name || '').replace(/\.service$/, ''),
            actif: svc.active,
            sous: svc.sub,
            boot: svc.unit_file_state || svc.enabled || 'unknown',
            categorie: svc.category || '',
            description: svc.description || '',
            protege: !! svc.protected,
        };
    }

    /** Le libelle d'un etat au demarrage — jamais un oui/non. */
    function libelleBoot(etat) {
        var cle = 'boot_' + etat;

        return textes[cle] || textes.boot_unknown || etat;
    }

    function libelleEtat(svc) {
        if (svc.active === 'failed' || svc.sub === 'failed') { return textes.etat_echoue || ''; }

        return svc.active === 'active' ? (textes.etat_actif || '') : (textes.etat_arrete || '');
    }

    function ligne(brut) {
        var svc = normalise(brut);
        var tr = document.createElement('tr');

        var tdNom = document.createElement('td');
        var fort = document.createElement('span');
        fort.className = 'rw-tableau__fort';
        fort.textContent = svc.nom;
        tdNom.appendChild(fort);
        // UN SERVICE PROTEGE SE DIT, ET DIT PAR QUI. La protection est appliquee
        // au BACKEND, aux cinq routes mutantes — mesure par S3 : `stop sshd`
        // rend 403 « Service protege » avant toute session SSH. Le marquer sans
        // le dire laisserait croire a un simple masquage d'ecran.
        if (svc.protege) {
            var marque = document.createElement('span');
            marque.className = 'rw-badge rw-badge--alerte';
            marque.setAttribute('data-rw', 'services-protege-' + svc.nom);
            marque.title = textes.protege_aide || '';
            marque.textContent = textes.protege || '';
            tdNom.appendChild(document.createTextNode(' '));
            tdNom.appendChild(marque);
        }

        var tdEtat = document.createElement('td');
        var pastille = document.createElement('span');
        var classe = (svc.actif === 'active') ? 'ok'
            : ((svc.actif === 'failed' || svc.sous === 'failed') ? 'echec' : 'neutre');
        pastille.className = 'rw-pastille rw-pastille--' + classe;
        pastille.textContent = libelleEtat({ active: svc.actif, sub: svc.sous });
        tdEtat.appendChild(pastille);

        // L'ETAT AU DEMARRAGE, TEL QUEL. `static` et `masked` ne sont ni « oui »
        // ni « non » : les y ramener perdrait ce qui compte pour decider.
        var tdBoot = document.createElement('td');
        tdBoot.textContent = libelleBoot(svc.boot);
        if (svc.boot === 'static' || svc.boot === 'masked') {
            tdBoot.title = textes['boot_' + svc.boot + '_aide'] || '';
        }

        var tdCategorie = document.createElement('td');
        tdCategorie.textContent = svc.categorie;
        var tdDescription = document.createElement('td');
        tdDescription.textContent = svc.description;
        var tdActions = document.createElement('td');
        tdActions.className = 'rw-tableau__actions';
        actions(svc).forEach(function (b) { tdActions.appendChild(b); });

        [tdNom, tdEtat, tdBoot, tdCategorie, tdDescription, tdActions]
            .forEach(function (t) { tr.appendChild(t); });
        tr.setAttribute('data-rw', 'services-ligne-' + svc.nom);
        tr.dataset.nom = svc.nom.toLowerCase();
        tr.dataset.etat = classe;
        tr.dataset.categorie = svc.categorie;

        return tr;
    }

    /**
     * Les gestes offerts pour un service — S3.
     *
     * Memes regles que le legacy : arreter/redemarrer si actif, demarrer sinon ;
     * activer/desactiver selon l'etat au demarrage, et **rien** pour `static` ou
     * `masked`, qui n'ont pas d'interrupteur.
     *
     * Un service PROTEGE recoit des boutons DESACTIVES — et le titre dit que
     * c'est le backend qui refuse, pas l'ecran qui masque.
     */
    function actions(svc) {
        var liste = [];
        var boutons = [];
        if (svc.actif === 'active') {
            boutons.push(['stop', textes.act_arreter, 'rw-bouton--danger', textes.confirmer_arreter]);
            boutons.push(['restart', textes.act_redemarrer, 'rw-bouton--avertissement', textes.confirmer_redemarrer]);
        } else {
            boutons.push(['start', textes.act_demarrer, 'rw-bouton--succes', textes.confirmer_demarrer]);
        }
        if (svc.boot === 'enabled') {
            boutons.push(['disable', textes.act_desactiver, 'rw-bouton--discret', textes.confirmer_desactiver]);
        } else if (svc.boot !== 'static' && svc.boot !== 'masked') {
            boutons.push(['enable', textes.act_activer, 'rw-bouton--discret', textes.confirmer_activer]);
        }

        boutons.forEach(function (b) {
            var el = document.createElement('button');
            el.type = 'button';
            el.className = 'rw-bouton rw-bouton--minuscule ' + b[2];
            el.textContent = b[1] || b[0];
            el.setAttribute('data-rw', 'services-action-' + b[0] + '-' + svc.nom);
            if (svc.protege) {
                el.disabled = true;
                el.title = textes.protege_aide || '';
            } else {
                el.addEventListener('click', function () { pilote(b[0], svc.nom, b[3] || ''); });
            }
            liste.push(el);
        });

        return liste;
    }

    /**
     * Pilote un service. **Confirme d'abord, et la question NOMME le service ET
     * la machine** — le legacy le fait aussi, c'est de la parite.
     *
     * Une confirmation qui ne dit pas sur quoi elle porte ne fait que ralentir
     * le clic.
     */
    function pilote(geste, nom, question) {
        var o = machineChoisie();
        if (! o) { return; }
        var texte = (question || '').replace(':service', nom)
            .replace(':machine', o.dataset.nom || '');
        if (! window.confirm(texte)) { return; }

        journalise(texte);
        lit('/services/' + geste, {
            machine_id: parseInt(o.value, 10),
            service: nom,
        }).then(function (d) {
            if (! d) {
                journalise((textes.geste_echec || '').replace(':service', nom)
                    .replace(':message', ''));

                return;
            }
            journalise((textes.geste_fait || '').replace(':service', nom)
                .replace(':message', d.message || ''));
            // L'ETAT A CHANGE : on le relit plutot que de le deviner. Deviner
            // afficherait le resultat qu'on ESPERE, pas celui qu'on a obtenu.
            if (charger) { charger.click(); }
        });
    }

    function remplitFiltre(select, valeurs) {
        if (! select) { return; }
        select.innerHTML = '';
        // `optionTous` et non `tous` : le tableau des services porte deja ce
        // nom dans la portee englobante. Une variable qui en masque une autre ne
        // casse rien aujourd'hui et coute cher le jour ou on lit vite.
        var optionTous = document.createElement('option');
        optionTous.value = '';
        optionTous.textContent = textes.filtre_tous || '';
        select.appendChild(optionTous);
        valeurs.forEach(function (v) {
            var o = document.createElement('option');
            o.value = v; o.textContent = v;
            select.appendChild(o);
        });
        select.disabled = false;
    }

    function applique() {
        var e = filtreEtat ? filtreEtat.value : '';
        var c = filtreCategorie ? filtreCategorie.value : '';
        var q = recherche ? recherche.value.trim().toLowerCase() : '';
        var visibles = 0;
        [].slice.call(corps.querySelectorAll('tr')).forEach(function (tr) {
            var garde = (! e || tr.dataset.etat === e)
                && (! c || tr.dataset.categorie === c)
                && (! q || tr.dataset.nom.indexOf(q) !== -1);
            tr.hidden = ! garde;
            if (garde) { visibles += 1; }
        });
        if (compte) {
            compte.textContent = visibles === 0
                ? (textes.aucun_resultat || '')
                : (textes.resultat_compte || '').replace(':visibles', String(visibles))
                    .replace(':total', String(tous.length));
        }
    }

    [filtreEtat, filtreCategorie].forEach(function (f) {
        if (f) { f.addEventListener('change', applique); }
    });
    if (recherche) { recherche.addEventListener('input', applique); }

    charger.addEventListener('click', function () {
        var o = machineChoisie();
        if (! o) { return; }
        charger.disabled = true;
        etat.textContent = textes.chargement || '';
        etat.classList.remove('rw-erreur');
        journalise((textes.chargement || '') + ' ' + (o.dataset.nom || ''));

        lit('/services/list', { machine_id: parseInt(o.value, 10) }).then(function (d) {
            charger.disabled = false;
            if (! d || ! Array.isArray(d.services)) {
                etat.textContent = textes.echec || '';
                etat.classList.add('rw-erreur');
                journalise(textes.echec || '');

                return;
            }
            tous = d.services;
            corps.innerHTML = '';
            tous.forEach(function (svc) { corps.appendChild(ligne(svc)); });

            // UN ZERO S'ENONCE, ET IL DIT D'OU IL VIENT. Le legacy affiche
            // « 0 services charges » : exact, mais indistinguable d'une
            // enumeration en echec. Or l'appel a REUSSI — c'est la machine qui
            // n'expose rien. La difference decide du geste suivant.
            if (tous.length === 0) {
                blocTableau.hidden = true;
                // L'EXPLICATION VA SOUS LE BOUTON, LE CONSTAT AU JOURNAL.
                // Ecrire la meme phrase aux deux endroits la faisait paraitre
                // DEUX FOIS a l'ecran — le travers du « Connecte en tant que »
                // affiche deux fois. Le journal CONSIGNE ce qui s'est passe ;
                // l'etat EXPLIQUE ce qu'on voit.
                etat.textContent = textes.aucun_systemd || '';
                journalise((textes.journal_lu || '').replace(':machine', o.dataset.nom || '')
                    .replace(':nb', '0'));

                return;
            }

            blocTableau.hidden = false;
            etat.textContent = '';
            journalise((textes.journal_lu || '').replace(':machine', o.dataset.nom || '')
                .replace(':nb', String(tous.length)));

            // LES FILTRES SE REMPLISSENT DEPUIS LES DONNEES RENDUES, jamais
            // depuis une liste ecrite ici : les categories vivent dans
            // `services_manager.SERVICE_CATEGORIES`, cote backend.
            var etats = [];
            var categories = [];
            // ON RECLASSE DEPUIS L'ENTREE NORMALISEE, pas depuis la forme brute :
            // dupliquer la classification ici, c'est se donner deux copies qui
            // finiront par diverger — et c'est exactement par la que le defaut
            // `unit_file_state` etait entre.
            tous.map(normalise).forEach(function (svc) {
                var cl = (svc.actif === 'active') ? 'ok'
                    : ((svc.actif === 'failed' || svc.sous === 'failed') ? 'echec' : 'neutre');
                if (etats.indexOf(cl) === -1) { etats.push(cl); }
                if (svc.categorie && categories.indexOf(svc.categorie) === -1) {
                    categories.push(svc.categorie);
                }
            });
            remplitFiltre(filtreEtat, etats.sort());
            remplitFiltre(filtreCategorie, categories.sort());
            if (recherche) { recherche.disabled = false; }
            if (aideFiltres) { aideFiltres.textContent = textes.filtres_actifs || ''; }
            applique();
        });
    });
}());
