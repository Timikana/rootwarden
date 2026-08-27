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

    var voirConfig = document.querySelector('[data-rw="f2b-voir-config"]');
    var voirLogs = document.querySelector('[data-rw="f2b-voir-logs"]');
    var sectionConfig = document.querySelector('[data-rw="f2b-config"]');
    var sourceConfig = document.querySelector('[data-rw="f2b-config-source"]');
    var messageConfig = document.querySelector('[data-rw="f2b-config-message"]');
    var contenuConfig = document.querySelector('[data-rw="f2b-config-contenu"]');
    var sectionLogs = document.querySelector('[data-rw="f2b-logs"]');
    var sourceLogs = document.querySelector('[data-rw="f2b-logs-source"]');
    var messageLogs = document.querySelector('[data-rw="f2b-logs-message"]');
    var contenuLogs = document.querySelector('[data-rw="f2b-logs-contenu"]');
    var sectionServices = document.querySelector('[data-rw="f2b-services-bloc"]');
    var messageServices = document.querySelector('[data-rw="f2b-services-message"]');
    var listeServices = document.querySelector('[data-rw="f2b-services"]');

    var detailJail = document.querySelector('[data-rw="f2b-jail-detail"]');
    var nomJail = document.querySelector('[data-rw="f2b-jail-nom"]');
    var configJail = document.querySelector('[data-rw="f2b-jail-config"]');
    var fermerJail = document.querySelector('[data-rw="f2b-jail-fermer"]');
    var messageBannies = document.querySelector('[data-rw="f2b-bannies-message"]');
    var cadreBannies = document.querySelector('[data-rw="f2b-bannies-cadre"]');
    var corpsBannies = document.querySelector('[data-rw="f2b-bannies-corps"]');
    var champBan = document.querySelector('[data-rw="f2b-ban-ip"]');
    var boutonBannir = document.querySelector('[data-rw="f2b-bannir"]');
    var boutonTout = document.querySelector('[data-rw="f2b-tout-debannir"]');
    var confirmation = document.querySelector('[data-rw="f2b-confirmation"]');
    var confTitre = document.querySelector('[data-rw="f2b-confirmation-titre"]');
    var confTexte = document.querySelector('[data-rw="f2b-confirmation-texte"]');
    var confirmer = document.querySelector('[data-rw="f2b-confirmer"]');
    var annuler = document.querySelector('[data-rw="f2b-annuler"]');
    var journalGestes = document.querySelector('[data-rw="f2b-journal"]');

    var jailCourante = null;

    var blocBlanche = document.querySelector('[data-rw="f2b-blanche"]');
    var sourceBlanche = document.querySelector('[data-rw="f2b-blanche-source"]');
    var messageBlanche = document.querySelector('[data-rw="f2b-blanche-message"]');
    var listeBlanche = document.querySelector('[data-rw="f2b-blanche-liste"]');
    var champBlanche = document.querySelector('[data-rw="f2b-blanche-ip"]');
    var ajouterBlanche = document.querySelector('[data-rw="f2b-blanche-ajouter"]');
    var reglages = document.querySelector('[data-rw="f2b-jail-reglages"]');
    var reglagesTitre = document.querySelector('[data-rw="f2b-reglages-titre"]');
    var champMaxretry = document.querySelector('[data-rw="f2b-maxretry"]');
    var champBantime = document.querySelector('[data-rw="f2b-bantime"]');
    var champFindtime = document.querySelector('[data-rw="f2b-findtime"]');
    var boutonActiver = document.querySelector('[data-rw="f2b-jail-activer"]');
    var reglagesAnnuler = document.querySelector('[data-rw="f2b-reglages-annuler"]');

    var jailAActiver = null;

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
        /*
         * CHANGER DE MACHINE EFFACE CE QUI APPARTENAIT A LA PRECEDENTE.
         *
         * Sans cela, la configuration de A resterait a l'ecran sous le nom de B
         * — la meme confusion qu'E-162, par un autre chemin. Les deux boutons de
         * lecture se recachent : ils ne se rouvrent qu'apres un releve qui dit
         * que fail2ban est installe SUR CETTE machine.
         */
        if (voirConfig) { voirConfig.hidden = true; }
        if (voirLogs) { voirLogs.hidden = true; }
        if (sectionConfig) { sectionConfig.hidden = true; }
        if (sectionLogs) { sectionLogs.hidden = true; }
        if (sectionServices) { sectionServices.hidden = true; }
        // Le detail d'une jail appartient a UNE machine : il se referme avec elle.
        if (detailJail) { detailJail.hidden = true; }
        jailCourante = null;
        if (confirmation) { confirmation.hidden = true; }
        if (blocBlanche) { blocBlanche.hidden = true; }
        if (reglages) { reglages.hidden = true; }
        jailAActiver = null;
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
            // OUVRIR LE DETAIL EST UNE LECTURE : la carte est un bouton, pas une
            // `div` cliquable — un lecteur d'ecran doit savoir qu'elle agit.
            carte.setAttribute('role', 'button');
            carte.setAttribute('tabindex', '0');
            carte.addEventListener('click', function () { ouvreJail(j.name || ''); });
            carte.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); ouvreJail(j.name || ''); }
            });
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

    /*
     * ══ UNE SEULE NOTION DE « LA MACHINE » ════════════════════════════════
     *
     * Le legacy en a deux : `loadConfig` lit `getServer()` — le SELECTEUR — et
     * douze autres gestes lisent `_currentServer`, pose au dernier releve
     * REUSSI. Relever sur A, changer le selecteur pour B, et tout agit sur A
     * pendant que l'ecran montre B (E-162). Les `confirm()` nomment la vraie
     * cible : la confirmation dit vrai, c'est le selecteur qui ment.
     *
     * Ici il n'y a **aucune** variable de machine « courante ». Tout part de
     * `machineChoisie()`, c'est-a-dire de ce que l'ecran affiche. Un geste ne
     * peut donc pas viser une machine que l'operateur ne regarde pas.
     */
    function nomMachineChoisie() {
        var o = machineChoisie();

        return o ? (o.dataset.nom || o.textContent || '').trim() : '';
    }

    /**
     * LIRE UN FICHIER DISTANT — et distinguer TROIS issues, pas deux.
     *
     * Le legacy en distingue une : il pose la reponse dans un `<pre>`. Le
     * marqueur `[FICHIER ABSENT]`, fabrique par un `|| echo` du shell, y devient
     * donc le contenu du fichier (E-161).
     *
     *   la lecture echoue      -> on le dit, et ce n'est PAS « fichier vide » ;
     *   le fichier est absent  -> on le dit, dans la langue de l'interface ;
     *   le fichier existe      -> on l'affiche tel quel.
     */
    var ABSENCE = /^\s*\[(FICHIER|LOG|FILE) ABSENT\]\s*$/i;

    function rendFichier(cadre, cles, texte) {
        cadre.source.textContent = '';
        cadre.message.innerHTML = '';
        cadre.contenu.hidden = true;
        cadre.section.hidden = false;

        if (texte === null) {
            poseMessage(cadre.message, 'lecture_echec_titre', 'lecture_echec', true);

            return 'echec';
        }
        if (ABSENCE.test(texte)) {
            poseMessage(cadre.message, cles.titre, cles.texte, false);

            return 'absent';
        }
        cadre.contenu.textContent = texte;
        cadre.contenu.hidden = false;
        cadre.source.textContent = (textes.lu_a_l_instant || '')
            .replace(':machine', nomMachineChoisie());

        return 'contenu';
    }

    /** FAIL-CLOSED : sans `success === true`, on rend `null`, jamais du vide. */
    function litDistant(chemin, envoi) {
        return fetch(PASSERELLE + chemin, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(envoi),
        }).then(function (r) { return r.json().catch(function () { return null; }); })
          .then(function (d) { return (d && d.success === true) ? d : null; })
          .catch(function () { return null; });
    }

    function litConfig() {
        var o = machineChoisie();
        if (! o) { return; }
        voirConfig.disabled = true;
        litDistant('/fail2ban/config', { machine_id: parseInt(o.value, 10) }).then(function (d) {
            voirConfig.disabled = false;
            rendFichier({
                section: sectionConfig, source: sourceConfig,
                message: messageConfig, contenu: contenuConfig,
            }, { titre: 'fichier_absent_titre', texte: 'fichier_absent' },
                d === null ? null : String(d.config == null ? '' : d.config));
        });
    }

    function litLogs() {
        var o = machineChoisie();
        if (! o) { return; }
        voirLogs.disabled = true;
        litDistant('/fail2ban/logs', { machine_id: parseInt(o.value, 10), lines: 100 })
            .then(function (d) {
                voirLogs.disabled = false;
                rendFichier({
                    section: sectionLogs, source: sourceLogs,
                    message: messageLogs, contenu: contenuLogs,
                }, { titre: 'journal_absent_titre', texte: 'journal_absent' },
                    d === null ? null : String(d.logs == null ? '' : d.logs));
            });
    }

    /**
     * LES SERVICES DETECTES — et l'etat s'ecrit en MOT.
     *
     * Le legacy distingue installe et absent par `opacity-50`. Elle n'est pas
     * purgee aujourd'hui, mais une distinction qui ne tient qu'a une classe
     * utilitaire est a un purge pres de disparaitre — trois defauts de ce
     * chantier viennent de la — et elle ne dit rien a un lecteur d'ecran.
     */
    function rendServices(services) {
        listeServices.innerHTML = '';
        messageServices.innerHTML = '';
        sectionServices.hidden = false;
        if (! services || ! services.length) {
            poseMessage(messageServices, 'services_vide_titre', 'services_vide', false);

            return;
        }
        services.forEach(function (s) {
            var ligne = document.createElement('div');
            ligne.className = 'rw-liste-etats__ligne'
                + (s.installed ? '' : ' rw-liste-etats__ligne--absent');
            ligne.setAttribute('data-rw', 'f2b-service-' + (s.service || ''));

            var nom = document.createElement('span');
            nom.className = 'rw-liste-etats__nom';
            nom.textContent = s.service || '';
            ligne.appendChild(nom);

            var etat = document.createElement('span');
            etat.className = 'rw-pastille rw-pastille--' + (s.installed ? 'ok' : 'attente');
            etat.textContent = textes[s.installed ? 'services_installe' : 'services_absent'] || '';
            ligne.appendChild(etat);

            var jails = document.createElement('span');
            jails.className = 'rw-liste-etats__jails';
            (s.jails || []).forEach(function (j) {
                if (s.installed && ! j.enabled) {
                    // ACTIVER UNE JAIL EST UNE ECRITURE : c'est un bouton, pas
                    // une pastille. Et il n'est offert que si le service est la.
                    var b = document.createElement('button');
                    b.type = 'button';
                    b.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
                    b.setAttribute('data-rw', 'f2b-activer-' + (j.name || ''));
                    b.textContent = (j.name || '') + ' +';
                    b.addEventListener('click', function () { ouvreReglages(j.name || ''); });
                    jails.appendChild(b);

                    return;
                }
                var p = document.createElement('span');
                p.className = 'rw-badge ' + (j.enabled ? 'rw-badge--ok' : 'rw-badge--neutre');
                p.textContent = (j.name || '') + (j.enabled
                    ? ' \u00b7 ' + (textes.services_jail_active || '') : '');
                jails.appendChild(p);
            });
            ligne.appendChild(jails);
            listeServices.appendChild(ligne);
        });
    }

    function detecteServices() {
        var o = machineChoisie();
        if (! o) { return; }
        litDistant('/fail2ban/services', { machine_id: parseInt(o.value, 10) })
            .then(function (d) {
                if (! d) {
                    listeServices.innerHTML = '';
                    messageServices.innerHTML = '';
                    sectionServices.hidden = false;
                    poseMessage(messageServices, 'lecture_echec_titre', 'lecture_echec', true);

                    return;
                }
                rendServices(d.services || []);
            });
    }

    /* ══ F4 : LE DETAIL D'UNE JAIL, ET LES DEUX GESTES QUI ECRIVENT ══════ */

    function journalise(texte, enErreur) {
        if (! journalGestes) { return; }
        var p = document.createElement('p');
        p.textContent = texte;
        if (enErreur) { p.className = 'rw-non-resolu'; }
        journalGestes.appendChild(p);
        journalGestes.scrollTop = journalGestes.scrollHeight;
    }

    function remplit(modele, valeurs) {
        var t = textes[modele] || '';
        Object.keys(valeurs).forEach(function (c) {
            t = t.split(':' + c).join(String(valeurs[c]));
        });

        return t;
    }

    function rendConfigJail(cfg) {
        configJail.innerHTML = '';
        [
            ['jail_maxretry', cfg && cfg.maxretry],
            ['jail_bantime', cfg && cfg.bantime],
            ['jail_findtime', cfg && cfg.findtime],
        ].forEach(function (paire) {
            var bloc = document.createElement('div');
            bloc.className = 'rw-faits__bloc';
            var dt = document.createElement('dt');
            dt.textContent = textes[paire[0]] || '';
            var dd = document.createElement('dd');
            // UNE VALEUR NON LUE SE DIT. Un tiret laisserait croire a un zero.
            dd.textContent = (paire[1] === null || paire[1] === undefined || paire[1] === '')
                ? (textes.jail_inconnu || '')
                : (paire[0] === 'jail_maxretry'
                    ? String(paire[1])
                    : remplit('jail_secondes', { nb: paire[1] }));
            bloc.appendChild(dt);
            bloc.appendChild(dd);
            configJail.appendChild(bloc);
        });
    }

    function rendBannies(liste) {
        corpsBannies.innerHTML = '';
        messageBannies.innerHTML = '';
        if (! liste || ! liste.length) {
            cadreBannies.hidden = true;
            poseMessage(messageBannies, 'bannies_vide_titre', 'bannies_vide', false);

            return;
        }
        cadreBannies.hidden = false;
        liste.forEach(function (adresse) {
            var tr = document.createElement('tr');
            tr.setAttribute('data-rw', 'f2b-bannie-' + adresse);
            var tdIp = document.createElement('td');
            tdIp.className = 'rw-tableau__mono';
            tdIp.textContent = adresse;
            tr.appendChild(tdIp);
            var tdAction = document.createElement('td');
            var b = document.createElement('button');
            b.type = 'button';
            b.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
            b.setAttribute('data-rw', 'f2b-debannir-' + adresse);
            b.textContent = textes.debannir || '';
            b.addEventListener('click', function () { demandeDebannir(adresse); });
            tdAction.appendChild(b);
            tr.appendChild(tdAction);
            corpsBannies.appendChild(tr);
        });
    }

    function ouvreJail(nom) {
        var o = machineChoisie();
        if (! o) { return; }
        jailCourante = nom;
        detailJail.hidden = false;
        confirmation.hidden = true;
        nomJail.textContent = remplit('jail_detail_titre', { jail: nom });
        configJail.innerHTML = '';
        corpsBannies.innerHTML = '';
        messageBannies.innerHTML = '';
        cadreBannies.hidden = true;

        litDistant('/fail2ban/jail', { machine_id: parseInt(o.value, 10), jail: nom })
            .then(function (d) {
                if (! d) {
                    poseMessage(messageBannies, 'lecture_echec_titre', 'lecture_echec', true);
                    rendConfigJail(null);

                    return;
                }
                rendConfigJail(d.config || null);
                rendBannies(d.banned_ips || d.banned || []);
            });
    }

    /*
     * ══ LE PANNEAU DE DECISION NOMME SA CIBLE ═════════════════════════════
     *
     * Le legacy ouvre `confirm(__('f2b_confirm_ban', {ip, jail, server}))` — et
     * son catalogue ignore les trois parametres : la boite dit « Bannir cette
     * IP ? ». On confirme un geste destructeur sans savoir sur quelle adresse ni
     * sur quelle machine (E-167), alors que la machine peut differer de celle
     * qu'affiche le selecteur (E-162).
     *
     * Ici le panneau dit l'adresse, la jail, LA MACHINE, et ce que le geste
     * ENGAGE — pas seulement ce qu'il fait.
     */
    var gestEnAttente = null;

    function demande(cleTitre, cleTexte, valeurs, geste) {
        gestEnAttente = geste;
        confTitre.textContent = remplit(cleTitre, valeurs);
        confTexte.textContent = remplit(cleTexte, valeurs);
        confirmation.hidden = false;
        // Le panneau vit au niveau de la PAGE : il peut etre loin du geste.
        confirmation.scrollIntoView({ block: 'nearest' });
        confirmer.focus();
    }

    function ferme() {
        confirmation.hidden = true;
        gestEnAttente = null;
    }

    /** Validee AVANT tout envoi : rien ne part sur une saisie qui n'est pas une adresse. */
    function adresseValide(v) {
        return /^(\d{1,3}\.){3}\d{1,3}$/.test(v)
            ? v.split('.').every(function (n) { return Number(n) <= 255; })
            : /^[0-9a-f:]+$/i.test(v) && v.indexOf(':') !== -1;
    }

    function demandeBannir() {
        var o = machineChoisie();
        if (! o || ! jailCourante) { return; }
        var adresse = (champBan.value || '').trim();
        if (! adresseValide(adresse)) {
            journalise(textes.ban_invalide || '', true);

            return;
        }
        demande('conf_titre_ban', 'conf_texte_ban',
            { ip: adresse, jail: jailCourante, machine: nomMachineChoisie() },
            function () {
                agit('/fail2ban/ban',
                    { machine_id: parseInt(o.value, 10), jail: jailCourante, ip: adresse });
            });
    }

    function demandeDebannir(adresse) {
        var o = machineChoisie();
        if (! o || ! jailCourante) { return; }
        demande('conf_titre_debannir', 'conf_texte_debannir',
            { ip: adresse, jail: jailCourante, machine: nomMachineChoisie() },
            function () {
                agit('/fail2ban/unban',
                    { machine_id: parseInt(o.value, 10), jail: jailCourante, ip: adresse });
            });
    }

    function demandeToutDebannir() {
        var o = machineChoisie();
        if (! o || ! jailCourante) { return; }
        demande('conf_titre_tout', 'conf_texte_tout',
            { jail: jailCourante, machine: nomMachineChoisie(),
              nb: corpsBannies.querySelectorAll('tr').length },
            function () {
                agit('/fail2ban/unban_all',
                    { machine_id: parseInt(o.value, 10), jail: jailCourante });
            });
    }

    /**
     * UNE REUSSITE SE VERIFIE, ELLE NE S'ANNONCE PAS.
     *
     * Le backend teste desormais le code de retour (E-165 corrige au meme lot).
     * La page ne fait donc que RELAYER ce qu'il dit — et elle recharge le detail
     * de la jail apres, ce qui donne un second temoin : la liste des adresses
     * bannies doit refleter le geste.
     */
    function agit(chemin, envoi) {
        ferme();
        var nom = jailCourante;
        fetch(PASSERELLE + chemin, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(envoi),
        }).then(function (r) { return r.json().catch(function () { return null; }); })
          .then(function (d) {
              if (! d) {
                  journalise(remplit('geste_echoue', { message: textes.lecture_echec || '' }), true);

                  return;
              }
              if (d.success === true) {
                  journalise(remplit('geste_reussi', { message: d.message || '' }), false);
                  champBan.value = '';
              } else {
                  journalise(remplit('geste_echoue', { message: d.message || '' }), true);
              }
              // Second temoin : on relit, quel que soit le verdict annonce.
              if (nom) { ouvreJail(nom); }
          })
          .catch(function () {
              journalise(remplit('geste_echoue', { message: textes.lecture_echec || '' }), true);
          });
    }

    if (boutonBannir) { boutonBannir.addEventListener('click', demandeBannir); }
    if (boutonTout) { boutonTout.addEventListener('click', demandeToutDebannir); }
    if (confirmer) { confirmer.addEventListener('click', function () {
        var g = gestEnAttente;
        if (g) { g(); }
    }); }
    if (annuler) { annuler.addEventListener('click', ferme); }
    if (fermerJail) { fermerJail.addEventListener('click', function () {
        detailJail.hidden = true;
        jailCourante = null;
        ferme();
    }); }

    /* ══ F5 : LA LISTE BLANCHE, ET LES REGLAGES D'UNE JAIL ═══════════════ */

    /**
     * UNE ENTREE QU'ON NE PEUT PAS RETIRER NE PORTE PAS DE BOUTON.
     *
     * `_validate_ip` appelle `ipaddress.ip_address()` : un CIDR y leve une
     * `ValueError`. Le « × » de `127.0.0.1/8` ne peut donc JAMAIS aboutir — et
     * c'est l'une des deux entrees que le backend suppose par defaut (E-169).
     * Ce n'est pas le refus qui est fautif, c'est de l'OFFRIR.
     *
     * La regle est la meme que celle du backend, pas une approximation : une
     * adresse, jamais un reseau.
     */
    function estUneAdresse(v) {
        var t = String(v || '').trim();
        if (t.indexOf('/') !== -1) { return false; }

        return /^(\d{1,3}\.){3}\d{1,3}$/.test(t)
            ? t.split('.').every(function (n) { return Number(n) <= 255; })
            : /^[0-9a-f:]+$/i.test(t) && t.indexOf(':') !== -1;
    }

    function rendBlanche(ips, lue) {
        listeBlanche.innerHTML = '';
        messageBlanche.innerHTML = '';
        blocBlanche.hidden = false;
        var machine = nomMachineChoisie();

        // LUE OU SUPPOSEE : le backend le dit desormais (E-168).
        sourceBlanche.textContent = lue
            ? remplit('blanche_lue', { machine: machine })
            : '';
        if (! lue) {
            var bloc = document.createElement('div');
            bloc.className = 'rw-vide';
            bloc.setAttribute('data-rw', 'f2b-blanche-supposee');
            var t = document.createElement('p');
            t.className = 'rw-sous-titre-fort';
            t.textContent = textes.blanche_supposee_titre || '';
            var x = document.createElement('p');
            x.className = 'rw-prose';
            x.textContent = remplit('blanche_supposee', { machine: machine });
            bloc.appendChild(t);
            bloc.appendChild(x);
            messageBlanche.appendChild(bloc);
        }
        if (! ips || ! ips.length) {
            poseMessage(messageBlanche, 'blanche_vide_titre', 'blanche_vide', false);

            return;
        }

        ips.forEach(function (adresse) {
            var ligne = document.createElement('div');
            ligne.className = 'rw-liste-etats__ligne';
            ligne.setAttribute('data-rw', 'f2b-blanche-' + adresse);

            var nom = document.createElement('span');
            nom.className = 'rw-liste-etats__nom rw-tableau__mono';
            nom.textContent = adresse;
            ligne.appendChild(nom);

            var actions = document.createElement('span');
            actions.className = 'rw-liste-etats__jails';
            // Une entree SUPPOSEE n'est pas dans le fichier : il n'y a rien a en
            // retirer. Une entree qui n'est pas une adresse ne peut pas l'etre.
            if (lue && estUneAdresse(adresse)) {
                var b = document.createElement('button');
                b.type = 'button';
                b.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
                b.setAttribute('data-rw', 'f2b-blanche-retirer-' + adresse);
                b.textContent = textes.blanche_retirer || '';
                b.addEventListener('click', function () { demandeRetraitBlanche(adresse); });
                actions.appendChild(b);
            } else {
                var raison = document.createElement('span');
                raison.className = 'rw-non-resolu';
                raison.setAttribute('data-rw', 'f2b-blanche-figee-' + adresse);
                raison.textContent = textes.blanche_non_retirable || '';
                raison.title = lue
                    ? remplit('blanche_non_retirable_aide', { ip: adresse })
                    : (textes.blanche_supposee_titre || '');
                actions.appendChild(raison);
            }
            ligne.appendChild(actions);
            listeBlanche.appendChild(ligne);
        });
    }

    function chargeBlanche() {
        var o = machineChoisie();
        if (! blocBlanche || ! o) { return; }
        litDistant('/fail2ban/whitelist', { machine_id: parseInt(o.value, 10), action: 'list' })
            .then(function (d) {
                if (! d) {
                    listeBlanche.innerHTML = '';
                    messageBlanche.innerHTML = '';
                    blocBlanche.hidden = false;
                    poseMessage(messageBlanche, 'lecture_echec_titre', 'lecture_echec', true);

                    return;
                }
                rendBlanche(d.ips || [], d.lue === true);
            });
    }

    /*
     * LES DEUX GESTES CONFIRMENT, ET LES DEUX ANNONCENT LE REDEMARRAGE.
     *
     * Le legacy ne fait confirmer que le RETRAIT d'une exemption — donc le geste
     * qui renforce la protection. Ajouter une exemption, qui l'affaiblit, passe
     * sans un mot ; et aucun des deux ne dit que `manage_whitelist` finit par
     * `restart_fail2ban`, donc que tous les bans en cours seront perdus (E-170).
     */
    function demandeAjoutBlanche() {
        var o = machineChoisie();
        if (! o) { return; }
        var adresse = (champBlanche.value || '').trim();
        if (! estUneAdresse(adresse)) {
            journalise(textes.ban_invalide || '', true);

            return;
        }
        demande('conf_titre_blanche_ajout', 'conf_texte_blanche_ajout',
            { ip: adresse, machine: nomMachineChoisie() },
            function () {
                agitBlanche({ machine_id: parseInt(o.value, 10), action: 'add', ip: adresse });
            });
    }

    function demandeRetraitBlanche(adresse) {
        var o = machineChoisie();
        if (! o) { return; }
        demande('conf_titre_blanche_retrait', 'conf_texte_blanche_retrait',
            { ip: adresse, machine: nomMachineChoisie() },
            function () {
                agitBlanche({ machine_id: parseInt(o.value, 10), action: 'remove', ip: adresse });
            });
    }

    function agitBlanche(envoi) {
        ferme();
        litDistant('/fail2ban/whitelist', envoi).then(function (d) {
            if (! d) {
                journalise(remplit('geste_echoue', { message: textes.lecture_echec || '' }), true);
                chargeBlanche();

                return;
            }
            journalise(remplit('geste_reussi', { message: d.message || '' }), false);
            champBlanche.value = '';
            rendBlanche(d.ips || [], d.lue === true);
        });
    }

    /** Les reglages d'une jail : l'avertissement AVANT les champs. */
    function ouvreReglages(nom) {
        jailAActiver = nom;
        reglagesTitre.textContent = remplit('jail_reglages_titre',
            { jail: nom, machine: nomMachineChoisie() });
        reglages.hidden = false;
        reglages.scrollIntoView({ block: 'nearest' });
    }

    function demandeActivation() {
        var o = machineChoisie();
        if (! o || ! jailAActiver) { return; }
        var maxretry = Math.max(1, Math.min(100, parseInt(champMaxretry.value, 10) || 5));
        var bantime = Math.max(60, parseInt(champBantime.value, 10) || 3600);
        var findtime = Math.max(60, parseInt(champFindtime.value, 10) || 600);
        demande('conf_titre_jail', 'conf_texte_jail',
            { jail: jailAActiver, machine: nomMachineChoisie(),
              maxretry: maxretry, bantime: bantime, findtime: findtime },
            function () {
                var nom = jailAActiver;
                ferme();
                reglages.hidden = true;
                jailAActiver = null;
                litDistant('/fail2ban/enable_jail', {
                    machine_id: parseInt(o.value, 10), jail: nom,
                    maxretry: maxretry, bantime: bantime, findtime: findtime,
                }).then(function (d) {
                    journalise(d
                        ? remplit('geste_reussi', { message: d.message || '' })
                        : remplit('geste_echoue', { message: textes.lecture_echec || '' }), ! d);
                    detecteServices();
                    chargeBlanche();
                });
            });
    }

    if (ajouterBlanche) { ajouterBlanche.addEventListener('click', demandeAjoutBlanche); }
    if (boutonActiver) { boutonActiver.addEventListener('click', demandeActivation); }
    if (reglagesAnnuler) { reglagesAnnuler.addEventListener('click', function () {
        reglages.hidden = true;
        jailAActiver = null;
        ferme();
    }); }

    if (voirConfig) { voirConfig.addEventListener('click', litConfig); }
    if (voirLogs) { voirLogs.addEventListener('click', litLogs); }

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
            // LES LECTURES DE F3 NE S'OFFRENT QUE SI LE SERVICE EST LA. Proposer
            // de lire un fichier dont on sait qu'il n'existe pas n'est pas une
            // offre — et la detection des services n'aurait rien a detecter.
            if (voirConfig) { voirConfig.hidden = ! d.installed; }
            if (voirLogs) { voirLogs.hidden = ! d.installed; }
            if (d.installed) { detecteServices(); chargeBlanche(); }
            // LES JAILS NE SE RENDENT QUE SI LE SERVICE TOURNE. Une grille vide
            // sous un « pas installe » ferait croire a un service sans jails.
            if (etatDe(d) === 'actif') { rendJails(d.jails); }
        });
    });
}());
