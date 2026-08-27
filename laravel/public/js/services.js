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

    function libelleEtat(svc) {
        if (svc.active === 'failed' || svc.sub === 'failed') { return textes.etat_echoue || ''; }

        return svc.active === 'active' ? (textes.etat_actif || '') : (textes.etat_arrete || '');
    }

    function ligne(svc) {
        var tr = document.createElement('tr');

        var tdNom = document.createElement('td');
        var fort = document.createElement('span');
        fort.className = 'rw-tableau__fort';
        fort.textContent = svc.name;
        tdNom.appendChild(fort);
        // UN SERVICE PROTEGE SE DIT, ET DIT PAR QUI. La protection est appliquee
        // au BACKEND, aux cinq routes mutantes — pas seulement ici. Le marquer
        // sans le dire laisserait croire a un simple masquage d'ecran.
        if (svc.protected) {
            var marque = document.createElement('span');
            marque.className = 'rw-badge rw-badge--alerte';
            marque.setAttribute('data-rw', 'services-protege-' + svc.name);
            marque.title = textes.protege_aide || '';
            marque.textContent = textes.protege || '';
            tdNom.appendChild(document.createTextNode(' '));
            tdNom.appendChild(marque);
        }

        var tdEtat = document.createElement('td');
        var pastille = document.createElement('span');
        var classe = (svc.active === 'active') ? 'ok'
            : ((svc.active === 'failed' || svc.sub === 'failed') ? 'echec' : 'neutre');
        pastille.className = 'rw-pastille rw-pastille--' + classe;
        pastille.textContent = libelleEtat(svc);
        tdEtat.appendChild(pastille);

        var tdActive = document.createElement('td');
        tdActive.textContent = svc.enabled ? (textes.active_oui || '') : (textes.active_non || '');
        var tdCategorie = document.createElement('td');
        tdCategorie.textContent = svc.category || '';
        var tdDescription = document.createElement('td');
        tdDescription.textContent = svc.description || '';

        [tdNom, tdEtat, tdActive, tdCategorie, tdDescription].forEach(function (t) { tr.appendChild(t); });
        tr.setAttribute('data-rw', 'services-ligne-' + svc.name);
        tr.dataset.nom = (svc.name || '').toLowerCase();
        tr.dataset.etat = classe;
        tr.dataset.categorie = svc.category || '';

        return tr;
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
            tous.forEach(function (svc) {
                var cl = (svc.active === 'active') ? 'ok'
                    : ((svc.active === 'failed' || svc.sub === 'failed') ? 'echec' : 'neutre');
                if (etats.indexOf(cl) === -1) { etats.push(cl); }
                if (svc.category && categories.indexOf(svc.category) === -1) { categories.push(svc.category); }
            });
            remplitFiltre(filtreEtat, etats.sort());
            remplitFiltre(filtreCategorie, categories.sort());
            if (recherche) { recherche.disabled = false; }
            if (aideFiltres) { aideFiltres.textContent = textes.filtres_actifs || ''; }
            applique();
        });
    });
}());
