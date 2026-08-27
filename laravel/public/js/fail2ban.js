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

    var noms = {};
    try {
        var blocNoms = document.getElementById('f2b-noms');
        if (blocNoms) { noms = JSON.parse(blocNoms.textContent || '{}'); }
    } catch (e) { noms = {}; }

    var sectionHisto = document.querySelector('[data-rw="f2b-historique"]');
    var compteHisto = document.querySelector('[data-rw="f2b-historique-compte"]');
    var messageHisto = document.querySelector('[data-rw="f2b-historique-message"]');
    var cadreHisto = document.querySelector('[data-rw="f2b-historique-cadre"]');
    var corpsHisto = document.querySelector('[data-rw="f2b-historique-corps"]');
    var sectionFrise = document.querySelector('[data-rw="f2b-frise"]');
    var cadreFrise = document.querySelector('[data-rw="f2b-frise-cadre"]');
    var barresFrise = document.querySelector('[data-rw="f2b-frise-barres"]');
    var axeFrise = document.querySelector('[data-rw="f2b-frise-axe"]');
    var messageFrise = document.querySelector('[data-rw="f2b-frise-message"]');

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

    choix.addEventListener('change', function () {
        majChoix();
        // L'HISTORIQUE SE CHARGE AU CHOIX, PAS AU RELEVE. Il est en base et ne
        // depend d'aucune machine : le rendre tributaire d'une session SSH le
        // masquerait exactement quand on vient le consulter (E-156).
        chargeHistorique();
        chargeFrise();
    });
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

    /**
     * UN ETAT VIDE DIT CE QUI MANQUE, ET POURQUOI.
     *
     * Le legacy sort par `return` des que la reponse est vide, laissant les
     * sections `hidden` : « aucun ban enregistre » et « la lecture a echoue »
     * produisent alors **exactement le meme ecran** — rien (E-153). Les deux
     * fonctions finissent d'ailleurs par un `catch (_) {}`.
     */
    function poseMessage(hote, cleTitre, cleTexte, enErreur) {
        hote.innerHTML = '';
        var bloc = document.createElement('div');
        bloc.className = enErreur ? 'rw-vide rw-vide--erreur' : 'rw-vide';
        bloc.setAttribute('data-rw', enErreur ? 'f2b-echec' : 'f2b-vide');
        var titre = document.createElement('p');
        titre.className = 'rw-sous-titre-fort';
        titre.textContent = textes[cleTitre] || '';
        var texte = document.createElement('p');
        texte.className = 'rw-prose';
        texte.textContent = textes[cleTexte] || '';
        bloc.appendChild(titre);
        bloc.appendChild(texte);
        hote.appendChild(bloc);
    }

    /**
     * LA DATE SUIT LA LANGUE DE L'INTERFACE.
     *
     * Le legacy ecrit `toLocaleString('fr-FR')` en dur (`main.js:298`) : la date
     * reste au format francais meme en anglais (E-158). On lit la langue sur
     * `<html lang>`, que le gabarit du portage remplit par `app()->getLocale()`
     * — a la difference du legacy, qui l'ecrit « fr » en dur.
     */
    function langue() {
        return document.documentElement.getAttribute('lang') || 'fr';
    }
    function dateLisible(brut) {
        if (! brut) { return ''; }
        var d = new Date(brut);
        if (isNaN(d.getTime())) { return String(brut); }

        return d.toLocaleString(langue());
    }

    /**
     * LA COLONNE « PAR » NOMME UNE PERSONNE.
     *
     * `performed_by` porte l'identifiant NUMERIQUE depose par `X-User-ID`, ou la
     * chaine litterale `admin` en repli (E-157). Ce qui ne se resout pas ne se
     * DEVINE pas : on le dit.
     */
    function auteur(valeur) {
        var v = String(valeur == null ? '' : valeur).trim();
        if (v === '') { return { texte: textes.par_repli || '', resolu: false, aide: textes.par_repli_aide || '' }; }
        if (v === 'admin') { return { texte: textes.par_repli || '', resolu: false, aide: textes.par_repli_aide || '' }; }
        if (Object.prototype.hasOwnProperty.call(noms, v)) {
            return { texte: noms[v], resolu: true, aide: '' };
        }
        if (/^\d+$/.test(v)) {
            return { texte: (textes.par_inconnu || '').replace(':id', v), resolu: false, aide: '' };
        }

        return { texte: v, resolu: true, aide: '' };
    }

    function machineDuChoix() {
        var o = machineChoisie();

        return o ? { id: parseInt(o.value, 10), total: parseInt(o.dataset.histo || '0', 10) } : null;
    }

    /** FAIL-CLOSED en LECTURE : `undefined` = echec, `[]` = vide et c'est tout. */
    function litGet(chemin) {
        return fetch(PASSERELLE + chemin, { headers: { Accept: 'application/json' } })
            .then(function (r) { return r.json().catch(function () { return null; }); })
            .then(function (d) { return (d && d.success === true) ? d : null; })
            .catch(function () { return null; });
    }

    function rendHistorique(lignes, total) {
        corpsHisto.innerHTML = '';
        lignes.forEach(function (h) {
            var tr = document.createElement('tr');
            [
                dateLisible(h.created_at),
                h.jail || '',
                h.ip_address || '',
            ].forEach(function (v, i) {
                var td = document.createElement('td');
                if (i === 2) { td.className = 'rw-tableau__mono'; }
                td.textContent = v;
                tr.appendChild(td);
            });

            var tdAction = document.createElement('td');
            var pastille = document.createElement('span');
            var estBan = h.action === 'ban';
            pastille.className = 'rw-pastille rw-pastille--' + (estBan ? 'echec' : 'ok');
            pastille.setAttribute('data-rw', 'f2b-action-' + (h.action || ''));
            pastille.textContent = textes[estBan ? 'action_ban' : 'action_unban'] || (h.action || '');
            tdAction.appendChild(pastille);
            tr.appendChild(tdAction);

            var a = auteur(h.performed_by);
            var tdPar = document.createElement('td');
            tdPar.textContent = a.texte;
            if (! a.resolu) { tdPar.className = 'rw-non-resolu'; }
            if (a.aide) { tdPar.title = a.aide; }
            tr.appendChild(tdPar);

            corpsHisto.appendChild(tr);
        });

        // UN TABLEAU TRONQUE DIT QU'IL L'EST. La route rend 50 lignes au plus et
        // n'annonce aucun total : le legacy affiche donc les cinquante dernieres
        // en ayant l'air exhaustif (E-154). Le total vient de la page.
        var montre = lignes.length;
        compteHisto.textContent = (total > montre)
            ? (textes.histo_tronque || '').replace(':montre', String(montre)).replace(':total', String(total))
            : (textes.histo_tout || '').replace(':nb', String(montre));
        compteHisto.setAttribute('data-rw-tronque', total > montre ? '1' : '0');
    }

    function chargeHistorique() {
        var m = machineDuChoix();
        if (! sectionHisto) { return; }
        if (! m) {
            sectionHisto.hidden = true;

            return;
        }
        sectionHisto.hidden = false;
        cadreHisto.hidden = true;
        compteHisto.textContent = '';
        messageHisto.innerHTML = '';

        litGet('/fail2ban/history?server_id=' + m.id).then(function (d) {
            if (! d) {
                poseMessage(messageHisto, 'histo_echec_titre', 'histo_echec', true);

                return;
            }
            var lignes = d.history || [];
            if (! lignes.length) {
                poseMessage(messageHisto, 'histo_vide_titre', 'histo_vide', false);

                return;
            }
            cadreHisto.hidden = false;
            rendHistorique(lignes, Math.max(m.total, lignes.length));
        });
    }

    /**
     * LA FRISE : LA HAUTEUR ET L'ECHELLE MESURENT LA MEME GRANDEUR.
     *
     * Le legacy calcule son echelle sur `ban + unban` et la hauteur sur `ban`
     * seul : une barre est systematiquement plus basse que son echelle ne le
     * laisse croire, et un jour de six debans tombe au plancher, en vert, comme
     * un jour vide (E-155).
     *
     * Et la hauteur est posee en PIXELS, calculee sur `clientHeight` : une
     * hauteur en pourcentage se resout contre le parent, et si celui-ci tire sa
     * hauteur d'une classe purgee, toutes les barres valent zero (E-159).
     */
    function rendFrise(stats) {
        var jours = {};
        (stats || []).forEach(function (s) {
            if (! jours[s.day]) { jours[s.day] = { ban: 0, unban: 0 }; }
            jours[s.day][s.action] = (jours[s.day][s.action] || 0) + (s.count || 0);
        });
        var cles = Object.keys(jours).sort();
        barresFrise.innerHTML = '';
        axeFrise.innerHTML = '';
        if (! cles.length) { return 0; }

        var totalMax = 1;
        cles.forEach(function (j) {
            totalMax = Math.max(totalMax, jours[j].ban + jours[j].unban);
        });
        // `clientHeight` du cadre des barres, moins la place du nombre ecrit
        // au-dessus. Mesure en pixels, jamais un pourcentage.
        var haut = Math.max(40, (barresFrise.clientHeight || 148) - 18);

        cles.forEach(function (j) {
            var c = jours[j];
            var total = c.ban + c.unban;
            var barre = document.createElement('div');
            barre.className = 'rw-frise__barre';
            barre.setAttribute('data-rw', 'f2b-barre-' + j);

            var valeur = document.createElement('span');
            valeur.className = 'rw-frise__valeur';
            valeur.textContent = String(total);
            barre.appendChild(valeur);

            var corps = document.createElement('div');
            var domine = c.ban > 0 && c.unban > 0 ? 'mixte' : (c.ban > 0 ? 'ban' : 'unban');
            corps.className = 'rw-frise__corps rw-frise__corps--' + domine;
            if (domine === 'mixte') {
                corps.style.setProperty('--rw-part-unban',
                    Math.round((c.unban / total) * 100) + '%');
            }
            corps.style.height = Math.max(4, Math.round((total / totalMax) * haut)) + 'px';
            barre.appendChild(corps);

            var phrase = (textes.frise_jour || '')
                .replace(':date', j).replace(':bans', String(c.ban)).replace(':unbans', String(c.unban));
            barre.setAttribute('aria-label', phrase);
            barre.title = phrase;
            barresFrise.appendChild(barre);

            // L'AXE EST VISIBLE. Le legacy ne met les dates que dans `title`.
            var etiquette = document.createElement('span');
            etiquette.className = 'rw-frise__date';
            // La date de l'axe suit la LANGUE, comme celles du tableau : un
            // fragment d'ISO (« 08-24 ») n'est ni francais ni anglais, et se lit
            // a l'envers selon le lecteur.
            var d = new Date(j + 'T00:00:00');
            etiquette.textContent = isNaN(d.getTime())
                ? j
                : d.toLocaleDateString(langue(), { day: '2-digit', month: '2-digit' });
            axeFrise.appendChild(etiquette);
        });

        return cles.length;
    }

    function chargeFrise() {
        var m = machineDuChoix();
        if (! sectionFrise) { return; }
        if (! m) {
            sectionFrise.hidden = true;

            return;
        }
        sectionFrise.hidden = false;
        messageFrise.innerHTML = '';
        cadreFrise.hidden = true;

        litGet('/fail2ban/stats?server_id=' + m.id + '&days=30').then(function (d) {
            if (! d) {
                poseMessage(messageFrise, 'histo_echec_titre', 'histo_echec', true);

                return;
            }
            var n = rendFrise(d.stats || []);
            if (! n) {
                poseMessage(messageFrise, 'frise_vide_titre', 'frise_vide', false);

                return;
            }
            cadreFrise.hidden = false;
        });
    }

    relever.addEventListener('click', function () {
        var o = machineChoisie();
        if (! o) { return; }
        relever.disabled = true;
        message.textContent = textes.chargement || '';
        message.classList.remove('rw-erreur');
        blocStatut.hidden = true;
        blocJails.hidden = true;
        // Le releve rafraichit l'historique et la frise QUOI QU'IL ARRIVE a la
        // machine : ce sont des lectures en base (E-156).
        chargeHistorique();
        chargeFrise();

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
