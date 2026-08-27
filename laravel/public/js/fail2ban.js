/**
 * fail2ban.js - Fail2ban, sous-lot F1 : statut et jails.
 *
 * **Marqueur de chargement.** `window.RW_FAIL2BAN` est pose des la premiere
 * ligne : `go-fail2ban-f1.mjs` s'en sert pour ASSERTER que ce script a bien ete
 * charge ET evalue. Une premiere redaction de sa suite avortait
 * `/fail2ban/js/main.js` sans le voir, et passait au vert en mesurant une page
 * dont le script n'avait jamais tourne — un `<script>` present dans le HTML ne
 * prouve ni l'un ni l'autre.
 *
 * F1 ne fait qu'une chose qui sorte : `/fail2ban/status`, sur la machine
 * CHOISIE, et sur un geste EXPLICITE. Bannir, installer, redemarrer, modifier
 * une jail ou la liste blanche sont F4, F5 et F6.
 */
window.RW_FAIL2BAN = true;

(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var textes = {};
    try {
        var bloc = document.getElementById('f2b-textes');
        if (bloc) { textes = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { textes = {}; }

    var choix = document.querySelector('[data-rw="f2b-serveur"]');
    var relever = document.querySelector('[data-rw="f2b-relever"]');
    var message = document.querySelector('[data-rw="f2b-etat-message"]');
    var blocStatut = document.querySelector('[data-rw="f2b-statut"]');
    var contenuStatut = document.querySelector('[data-rw="f2b-statut-contenu"]');
    var blocJails = document.querySelector('[data-rw="f2b-jails-bloc"]');
    var compteJails = document.querySelector('[data-rw="f2b-jails-compte"]');
    var grilleJails = document.querySelector('[data-rw="f2b-jails"]');
    if (! choix || ! relever || ! message) { return; }

    function machineChoisie() {
        var o = choix.options[choix.selectedIndex];

        return (o && o.value) ? o : null;
    }

    function majChoix() {
        var o = machineChoisie();
        relever.disabled = (o === null);
        if (o === null) {
            message.textContent = textes.choisir || '';
            message.classList.remove('rw-erreur');

            return;
        }
        // FAIL2BAN PROTEGE LA MACHINE. Sur une machine de production, le dire au
        // moment du CHOIX : les gestes qui suivront la laisseraient exposee, et
        // c'est maintenant qu'on decide sur quoi on travaille.
        var sensible = (o.dataset.sensible === '1');
        message.textContent = sensible ? (textes.sensible_avert || '') : '';
        message.classList.toggle('rw-erreur', sensible);
    }

    choix.addEventListener('change', majChoix);
    majChoix();

    /** FAIL-CLOSED : sans `success === true`, on rend `null`, jamais un objet vide. */
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
     * L'etat, en TROIS valeurs et non en booleen.
     *
     * « Pas installe », « installe mais arrete » et « actif » appellent des
     * gestes differents : les replier sur « ca marche / ca ne marche pas »
     * ferait perdre celui qui compte — car une machine sans fail2ban et une
     * machine dont le service est tombe ne se reparent pas pareil.
     */
    function etatDe(d) {
        if (! d.installed) { return 'absent'; }

        return d.running ? 'actif' : 'arrete';
    }

    function rendStatut(d) {
        var etat = etatDe(d);
        contenuStatut.innerHTML = '';

        var pastille = document.createElement('span');
        pastille.className = 'rw-pastille rw-pastille--'
            + (etat === 'actif' ? 'ok' : (etat === 'absent' ? 'echec' : 'attente'));
        pastille.setAttribute('data-rw', 'f2b-etat-' + etat);
        pastille.textContent = textes['etat_' + etat] || etat;
        contenuStatut.appendChild(pastille);

        // UN ETAT QUI N'EST PAS « ACTIF » DIT CE QU'IL IMPLIQUE. « Arrete » seul
        // ne dit pas qu'aucune adresse n'est bannie pendant ce temps.
        if (etat !== 'actif' && textes['etat_' + etat + '_aide']) {
            var aide = document.createElement('p');
            aide.className = 'rw-aide';
            aide.textContent = textes['etat_' + etat + '_aide'];
            contenuStatut.appendChild(aide);
        }
        blocStatut.hidden = false;
    }

    /**
     * LE PLURIEL, COMPOSE ET NON PARENTHESE.
     *
     * « 1 bannies » etait rendu a l'ecran. Aucune assertion ne pouvait le voir :
     * la propriete testee etait « le compteur affiche un nombre ». Vu a l'image.
     *
     * Le seuil est `n > 1` et non `n !== 1` : en francais, zero prend le
     * SINGULIER (« 0 bannie »). En anglais la forme est invariable, la regle ne
     * change donc rien — et une regle par langue vivrait dans le catalogue, pas
     * ici.
     */
    function pluriel(cleUne, clePlusieurs, n) {
        var modele = textes[n > 1 ? clePlusieurs : cleUne] || '';

        return modele.replace(':nb', String(n));
    }

    function rendJails(jails) {
        grilleJails.innerHTML = '';
        var total = 0;
        (jails || []).forEach(function (j) {
            total += (j.currently_banned || 0);
            var carte = document.createElement('div');
            carte.className = 'rw-carte';
            carte.setAttribute('data-rw', 'f2b-jail-' + (j.name || ''));
            var titre = document.createElement('p');
            titre.className = 'rw-sous-titre-fort';
            titre.textContent = j.name || '';
            var compte = document.createElement('p');
            compte.className = 'rw-aide';
            compte.textContent = pluriel('compte_bannies_une', 'compte_bannies_plusieurs',
                j.currently_banned || 0);
            carte.appendChild(titre);
            carte.appendChild(compte);
            grilleJails.appendChild(carte);
        });

        // UN ZERO S'ENONCE. « 0 jail » se lit comme une donnee ; « fail2ban
        // tourne, mais ne surveille rien » se comprend sans interpreter.
        compteJails.textContent = (jails && jails.length)
            ? pluriel('jails_une', 'jails_plusieurs', jails.length)
                + ' · ' + pluriel('adresses_une', 'adresses_plusieurs', total)
            : (textes.jails_aucune || '');
        blocJails.hidden = false;
    }

    /**
     * UN ECRAN NE PORTE PAS DEUX VERITES SUR LE MEME OBJET.
     *
     * Le tableau « Dernier releve connu » restait a l'ancienne valeur pendant
     * que la zone « Etat » annoncait la nouvelle : la meme machine y figurait
     * « installe, mais arrete » ET « actif », a dix centimetres d'ecart. Vu a
     * l'image du sous-lot F1.
     *
     * Le releve ECRIT le cache cote backend : mettre la ligne a jour ne fait
     * qu'afficher ce qui vient d'y etre range. La date devient « a l'instant »
     * plutot qu'un horodatage forge ici — c'est le serveur qui tient l'heure.
     */
    function majLigneCache(id, d) {
        var tr = document.querySelector('[data-rw="f2b-cache-' + id + '"]');
        if (! tr) { return; }
        var cases = tr.querySelectorAll('td');
        if (cases.length < 4) { return; }

        var etat = etatDe(d);
        cases[1].innerHTML = '';
        var pastille = document.createElement('span');
        pastille.className = 'rw-pastille rw-pastille--'
            + (etat === 'actif' ? 'ok' : (etat === 'absent' ? 'echec' : 'attente'));
        pastille.textContent = textes['etat_' + etat] || etat;
        cases[1].appendChild(pastille);
        if (etat !== 'actif' && textes['etat_' + etat + '_aide']) {
            var aide = document.createElement('div');
            aide.className = 'rw-aide';
            aide.textContent = textes['etat_' + etat + '_aide'];
            cases[1].appendChild(aide);
        }

        var total = 0;
        (d.jails || []).forEach(function (j) { total += (j.currently_banned || 0); });
        // Une machine SANS fail2ban n'a pas « zero adresse bannie » : elle n'a
        // pas de compteur du tout. Le tiret cadratin le dit, le zero mentirait.
        cases[2].textContent = d.installed ? String(total) : '—';
        cases[3].textContent = textes.cache_maintenant || '';
    }

    relever.addEventListener('click', function () {
        var o = machineChoisie();
        if (! o) { return; }
        relever.disabled = true;
        message.textContent = textes.chargement || '';
        message.classList.remove('rw-erreur');
        blocStatut.hidden = true;
        blocJails.hidden = true;

        lit('/fail2ban/status', { machine_id: parseInt(o.value, 10) }).then(function (d) {
            relever.disabled = false;
            if (! d) {
                message.textContent = textes.echec || '';
                message.classList.add('rw-erreur');

                return;
            }
            message.textContent = '';
            rendStatut(d);
            majLigneCache(parseInt(o.value, 10), d);
            // LES JAILS NE SE RENDENT QUE SI LE SERVICE TOURNE. Une grille vide
            // sous un « pas installe » ferait croire a un service sans jails.
            if (etatDe(d) === 'actif') { rendJails(d.jails); }
        });
    });
}());
