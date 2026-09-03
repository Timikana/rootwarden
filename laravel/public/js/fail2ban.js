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
 * CHOISIE, et sur un geste EXPLICITE. Bannir et debannir sont F4, les jails et
 * la liste blanche F5, les deux gestes de parc F6.
 *
 * ══ F6 : DEUX GESTES QUI NE VISENT AUCUNE MACHINE ════════════════════════
 *
 * `ban_all_servers` et `install_all` ne prennent aucun `machine_id` : leurs
 * cibles sont choisies EN BASE par le backend, et elles sont TOUTES jointes,
 * `srv-zabbix` comprise. Rien ici ne calcule cette portee : elle est LUE sur
 * la meme base, par `/fail2ban/portee`, avec le SQL des deux routes.
 */
window.RW_FAIL2BAN = true;

(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';
    /*
     * ROUTE DU PORTAGE, PAS DE LA PASSERELLE. Elle ne joint aucune machine :
     * elle relit en base ce que les deux gestes de parc toucheraient. Il faut
     * la relire apres un releve — un releve ECRIT le cache, donc la portee
     * change, et un ecran qui garderait l'ancienne porterait deux verites sur
     * le meme objet.
     */
    var PORTEE = '/fail2ban/portee';

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

    /* ── F6 : les deux gestes de parc et leur portee ─────────────────── */
    var zonePortee = document.querySelector('[data-rw="f2b-portee"]');
    var messagePortee = document.querySelector('[data-rw="f2b-portee-message"]');
    var relirePortee = document.querySelector('[data-rw="f2b-portee-relire"]');
    var boutonInstallerParc = document.querySelector('[data-rw="f2b-installer-parc"]');
    var boutonBannirParc = document.querySelector('[data-rw="f2b-bannir-parc"]');
    var aideParcBan = document.querySelector('[data-rw="f2b-parc-ban-aide"]');
    var blocRecopie = document.querySelector('[data-rw="f2b-recopie-bloc"]');
    var champRecopie = document.querySelector('[data-rw="f2b-recopie"]');
    var messageRecopie = document.querySelector('[data-rw="f2b-recopie-message"]');

    /*
     * ══ UNE PORTEE INCONNUE N'EST PAS UNE PORTEE VIDE ═════════════════════
     *
     * Le repli `{ installer: [], bannir: [] }` se rendrait « ce geste ne
     * toucherait aucune machine » — une phrase FAUSSE et rassurante, alors que
     * la verite est « on ne sait pas ». Meme famille que l'etat vide qui
     * promettait « aucun paquet en attente » quand un depot etait injoignable.
     *
     * `porteeLue` porte donc la difference, et les deux gestes sont REFUSES
     * tant qu'elle est fausse : un geste de parc ne s'envoie pas sans savoir
     * sur combien de machines il porte. Fail-closed.
     */
    var portee = { installer: [], bannir: [], parc: 0 };
    var porteeLue = false;
    try {
        var blocPortee = document.getElementById('f2b-portee-donnees');
        if (blocPortee) {
            var brut = JSON.parse(blocPortee.textContent || 'null');
            // On exige la FORME, pas seulement un objet : un JSON valide mais
            // d'une autre forme donnerait des listes `undefined`.
            if (brut && Array.isArray(brut.installer) && Array.isArray(brut.bannir)) {
                portee = brut;
                porteeLue = true;
            }
        }
    } catch (e) { porteeLue = false; }

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
        /*
         * CHANGER DE MACHINE ANNULE LA DECISION EN COURS, il ne la CACHE pas.
         *
         * Cette ligne posait `confirmation.hidden = true` — le panneau
         * disparaissait mais `gestEnAttente` restait arme, avec la machine
         * PRECEDENTE dans sa fermeture. C'est la forme exacte du defaut
         * d'`update/` (« un panneau qui s'ouvre repart d'un etat connu »), et F6
         * le rend consequent : un geste en attente peut viser tout le parc.
         * `ferme()` remet aussi la recopie a zero.
         */
        ferme();
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
        // Le cadre annoncait « aucun geste » par son `aria-label` : il ne peut
        // plus le dire des qu'il porte une ligne.
        journalGestes.classList.remove('rw-journal--vide');
        /*
         * LE JOURNAL VIT AU NIVEAU DE LA PAGE, DONC LOIN DU GESTE.
         *
         * Meme raison que pour le panneau de decision : un verdict ecrit hors du
         * champ ne vaut pas mieux qu'un verdict ecrit dans une section cachee.
         * `nearest` ne bouge rien s'il est deja visible.
         */
        journalGestes.scrollIntoView({ block: 'nearest' });
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

            /*
             * ══ F8 — LA GEOLOCALISATION ══════════════════════════════════
             *
             * ⚠ LE LIBELLE NE PORTE PAS L'ADRESSE, ET LE RESULTAT NON PLUS.
             *
             * `go-fail2ban-f4.mjs:566` mesure qu'une adresse bannie APPARAIT
             * dans cette liste, par `includes()` sur son `innerText`. Un
             * bouton « Geolocaliser <ip> » rendrait cette assertion
             * satisfiable par le BOUTON et non par le BAN : elle ne rougirait
             * pas, elle deviendrait vraie pour une autre raison. **Un faux
             * vert sur une assertion de surete ne se signale jamais.**
             *
             * L'adresse vit dans la cellule voisine et dans le JOURNAL. Elle
             * n'a pas besoin d'etre ici.
             *
             * Le span est declare AVANT le bouton : la fermeture capturerait
             * la variable et non sa valeur, donc l'ordre inverse marcherait —
             * mais il se relit comme un bug, et un lecteur ne devrait pas
             * avoir a raisonner sur le hissage pour valider une ligne.
             */
            var pays = document.createElement('span');
            pays.className = 'rw-badge';
            pays.setAttribute('data-rw', 'f2b-geoip-pays-' + adresse);
            pays.hidden = true;

            var g = document.createElement('button');
            g.type = 'button';
            g.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
            g.setAttribute('data-rw', 'f2b-geoip-' + adresse);
            g.textContent = textes.geo_bouton || '';
            g.addEventListener('click', function () { demandeGeo(adresse, pays); });
            tdAction.appendChild(g);
            tdAction.appendChild(pays);

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
    /** Le nombre a recopier, ou `null` quand le geste n'en demande pas. */
    var attendueRecopie = null;

    /**
     * Remet le panneau dans l'etat des gestes machine par machine.
     *
     * Appele a CHAQUE ouverture et a chaque fermeture : sans cela, un geste de
     * parc laisserait sa recopie exigee — ou son bouton desactive — au geste
     * suivant, qui n'a rien demande. Un panneau qui s'ouvre repart d'un etat
     * connu, c'est la lecon des quatre panneaux d'`update/`.
     */
    function reinitialiseRecopie() {
        attendueRecopie = null;
        if (champRecopie) { champRecopie.value = ''; }
        if (blocRecopie) { blocRecopie.hidden = true; }
        if (messageRecopie) { messageRecopie.hidden = true; }
        if (confirmer) { confirmer.disabled = false; }
    }

    /**
     * Ouvre le panneau de decision.
     *
     * `options.recopie` — un NOMBRE — exige de le recopier avant que
     * « Confirmer » ne s'active : c'est ce qui distingue une decision d'un
     * acquiescement, et le nombre choisi est celui qu'il faut justement lire
     * (combien de machines le geste touche).
     *
     * `options.bloque` rend la confirmation IMPOSSIBLE, parce que le geste ne
     * peut rien faire : on n'envoie pas une requete dont on sait qu'elle ne
     * touchera aucune machine. Le panneau s'ouvre quand meme — c'est lui qui
     * explique pourquoi il n'y a rien a faire.
     */
    function demande(cleTitre, cleTexte, valeurs, geste, options) {
        var opt = options || {};
        gestEnAttente = geste;
        confTitre.textContent = remplit(cleTitre, valeurs);
        confTexte.textContent = remplit(cleTexte, valeurs);
        reinitialiseRecopie();
        if (opt.bloque) {
            gestEnAttente = null;
            confirmer.disabled = true;
        } else if (typeof opt.recopie === 'number' && blocRecopie && champRecopie) {
            attendueRecopie = String(opt.recopie);
            blocRecopie.hidden = false;
            confirmer.disabled = true;
        }
        confirmation.hidden = false;
        /*
         * `center`, ET NON `nearest` — VU A L'IMAGE, AUX DEUX GRANDES LARGEURS.
         *
         * Le panneau vit au niveau de la PAGE : quand le geste part du bas de
         * page, il est AU-DESSUS de la fenetre, et `nearest` fait le defilement
         * MINIMUM — donc il l'aligne en haut, exactement la ou l'en-tete collant
         * du gabarit le recouvre. Mesure des captures de F6 : a 1400 px on lisait
         * « critiques, et 2 n'ont jamais ete relevees… », a 1920 px seulement
         * « machines a la fois… » — le TITRE et le debut du texte etaient
         * caches. On confirmait une installation sur tout un parc sans voir sur
         * quoi elle portait.
         *
         * Aucune assertion ne pouvait le voir : `innerText` rend le texte
         * recouvert comme le reste. C'est le troisieme defaut de ce chantier a ne
         * se montrer qu'a l'image pour cette raison precise — le plan le note
         * pour `block: 'start'`, et `nearest` retombe dessus des que l'element
         * est au-dessus du champ visible.
         */
        confirmation.scrollIntoView({ block: 'center' });
        if (blocRecopie && ! blocRecopie.hidden) { champRecopie.focus(); }
        else if (! confirmer.disabled) { confirmer.focus(); }
    }

    function ferme() {
        confirmation.hidden = true;
        gestEnAttente = null;
        reinitialiseRecopie();
    }

    if (champRecopie) {
        champRecopie.addEventListener('input', function () {
            if (attendueRecopie === null) { return; }
            var saisi = (champRecopie.value || '').trim();
            var juste = saisi === attendueRecopie;
            confirmer.disabled = ! juste;
            // Un nombre faux se DIT ; un champ encore vide n'est pas une faute.
            if (messageRecopie) { messageRecopie.hidden = juste || saisi === ''; }
        });
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

    /*
     * ══ F8 — INTERROGER UN TIERS SUR UNE ADRESSE ════════════════════════
     *
     * ⚠ C'EST UN APPEL SORTANT, EN CLAIR, VERS UN SERVICE TIERS.
     *
     *     fail2ban_manager.py:397   http://ip-api.com/json/<ip>   HTTP, pas HTTPS
     *
     * Le panneau NOMME le tiers et l'absence de chiffrement : « un service
     * tiers » laisse croire a une relation contractuelle, « ip-api.com, en
     * clair » dit ce qui se passe. Il porte AUSSI le fait rassurant — les
     * adresses privees, de bouclage et reservees ne partent pas, elles sont
     * resolues localement.
     *
     * *Un panneau qui n'annonce que le risque fait renoncer a un geste sur ;
     * un panneau qui n'annonce que la garantie fait consentir a un geste qui
     * ne l'est pas.*
     *
     * ⛔ LA RESERVE DU BACKEND N'EST PAS RECOPIEE. Elle dit « l'IP est deja
     * publique, donc fuite negligeable ». C'est faux : ce qui n'est pas
     * public, c'est LE FAIT QUE NOTRE INFRASTRUCTURE L'A BANNIE — un
     * observateur du trafic sortant ne lit pas une adresse, il lit la carte de
     * ce que nous bloquons. Une reserve fausse recopiee devient une
     * justification.
     */
    function demandeGeo(adresse, hotePays) {
        demande('geo_conf_titre', 'geo_conf_texte', { ip: adresse }, function () {
            ferme();
            if (hotePays) {
                hotePays.hidden = false;
                hotePays.textContent = textes.geo_en_cours || '';
            }
            litDistant('/fail2ban/geoip', { ip: adresse }).then(function (d) {
                /*
                 * QUATRE ISSUES, ET ELLES NE SE CONFONDENT PAS :
                 *   pas de reponse      -> le geste a echoue
                 *   countryCode « LO »  -> RIEN N'EST PARTI, l'adresse est locale
                 *   countryCode « ?? »  -> le tiers n'a pas su repondre
                 *   sinon               -> un pays
                 *
                 * Confondre les deux du milieu ferait croire a une
                 * transmission qui n'a pas eu lieu, ou a un silence qui n'en
                 * est pas un.
                 */
                if (! d) {
                    if (hotePays) { hotePays.textContent = ''; hotePays.hidden = true; }
                    journalise(remplit('geo_echec', { message: '' }), true);

                    return;
                }
                var code = String(d.countryCode || '??');
                var detail = code === 'LO' ? (textes.geo_locale || '')
                    : code === '??' ? (textes.geo_inconnu || '')
                    : remplit('geo_resultat', { pays: String(d.country || ''), code: code });
                if (hotePays) { hotePays.textContent = detail; hotePays.hidden = false; }
                journalise(remplit('geo_journal', { ip: adresse, detail: detail }), false);
            });
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
        // Meme correction que pour le panneau de decision : `nearest` glisse sous
        // l'en-tete collant des que la section est au-dessus du champ visible.
        reglages.scrollIntoView({ block: 'center' });
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

    /*
     * ══ F7 — DESACTIVER LA JAIL OUVERTE ══════════════════════════════════
     *
     * `POST /fail2ban/disable_jail` ouvre une session SSH reelle
     * (`backend/routes/fail2ban.py:418`) et arrete la surveillance. **Ce n'est
     * pas destructeur — « Activer la jail » le retablit — mais c'est une
     * BAISSE DE GARDE** : la machine cesse d'etre protegee contre le force
     * brute.
     *
     * Le panneau nomme donc la CONSEQUENCE et non le mecanisme. Ce qui compte
     * pour qui decide n'est pas qu'un fichier change, c'est que la protection
     * s'arrete — et que les adresses deja bannies, elles, ne sont pas
     * liberees.
     *
     * ⚠ Mesure du 2026-09-02 : ce geste n'a JAMAIS ete exerce — 0 occurrence
     * dans `command_log`, `tasks` et `user_logs`, temoin a 5 920 lignes. Le
     * L'ECRAN le dit — dans la vue, a cote du bouton et donc visible AVANT le
     * clic. Pas dans le panneau : `demande()` ne lit que `bloque` et
     * `recopie`, et lui passer une option de plus l'aurait fait transmettre
     * une cle que personne ne lit.
     */
    function demandeDesactivation() {
        var o = machineChoisie();
        var nom = jailCourante;
        if (! o || ! nom) { return; }
        demande('conf_titre_desact', 'conf_texte_desact',
            { jail: nom, machine: nomMachineChoisie() },
            function () {
                ferme();
                litDistant('/fail2ban/disable_jail', {
                    machine_id: parseInt(o.value, 10), jail: nom,
                }).then(function (d) {
                    journalise(d
                        ? remplit('geste_reussi', { message: d.message || '' })
                        : remplit('geste_echoue', { message: textes.lecture_echec || '' }), ! d);
                    // On RELIT l'etat au lieu de le deduire du code de retour :
                    // c'est la regle du module, et elle vaut ici autant
                    // qu'ailleurs.
                    detecteServices();
                });
            });
    }

    var boutonDesactiver = document.querySelector('[data-rw="f2b-jail-desactiver"]');
    if (boutonDesactiver) { boutonDesactiver.addEventListener('click', demandeDesactivation); }

    if (ajouterBlanche) { ajouterBlanche.addEventListener('click', demandeAjoutBlanche); }
    if (boutonActiver) { boutonActiver.addEventListener('click', demandeActivation); }
    if (reglagesAnnuler) { reglagesAnnuler.addEventListener('click', function () {
        reglages.hidden = true;
        jailAActiver = null;
        ferme();
    }); }

    /* ══ F6 : LES DEUX GESTES SUR TOUT LE PARC ═══════════════════════════
     *
     * `POST /fail2ban/ban_all_servers` et `POST /fail2ban/install_all` sont les
     * deux seules routes du module qui ne prennent AUCUNE machine : le backend
     * choisit ses cibles en base et les joint toutes.
     *
     * Le legacy ouvre pour chacune une boite native qui ne nomme rien :
     * « Bannir cette IP sur TOUS les serveurs ? » — alors que le corps envoye
     * porte l'adresse — et « Installer Fail2ban sur tous les serveurs sans
     * Fail2ban ? », dont le corps est VIDE : la portee est decidee entierement
     * cote serveur, et l'operateur ne peut pas la connaitre, meme en principe
     * (E-173). Ici la portee est LUE, NOMMEE, et chiffree avant le geste.
     */

    /** Les noms, tels qu'on les montre. C'est ce qui rend la portee lisible. */
    function nomsDe(liste) {
        return (liste || []).map(function (m) { return m.nom; }).join(', ');
    }

    /**
     * Une cible, avec ce qui decide qu'elle en est une.
     *
     * La date de releve est rendue PAR MACHINE, et son absence porte son propre
     * mot : « jamais relevee » n'est pas « relevee il y a longtemps », c'est
     * l'absence de ligne — et c'est precisement ce qui met la machine dans la
     * portee d'une installation (E-172).
     */
    function ligneCible(m) {
        var ligne = document.createElement('div');
        ligne.className = 'rw-liste-etats__ligne';
        ligne.setAttribute('data-rw', 'f2b-cible-' + m.id);

        var nom = document.createElement('span');
        nom.className = 'rw-liste-etats__nom';
        nom.textContent = m.nom || '';
        ligne.appendChild(nom);

        var marques = document.createElement('span');
        marques.className = 'rw-liste-etats__jails';

        // LA PRODUCTION SE NOMME SUR LA LIGNE QUI LA VISE, pas dans une phrase
        // d'ensemble : c'est cette machine-la qui recevrait le geste.
        if (m.sensible) {
            var prod = document.createElement('span');
            prod.className = 'rw-badge rw-badge--alerte';
            prod.setAttribute('data-rw', 'f2b-cible-prod-' + m.id);
            prod.textContent = textes.sensible || '';
            prod.title = textes.sensible_avert || '';
            marques.appendChild(prod);
        }
        // UNE CIBLE QUE LE SELECTEUR NE MONTRE PAS. Les deux requetes de parc ne
        // filtrent pas `lifecycle_status`, la liste du haut de page si.
        if (m.archivee) {
            var arch = document.createElement('span');
            arch.className = 'rw-badge rw-badge--neutre';
            arch.setAttribute('data-rw', 'f2b-cible-archivee-' + m.id);
            arch.textContent = textes.portee_archivee || '';
            arch.title = textes.portee_archivee_aide || '';
            marques.appendChild(arch);
        }

        var etat = document.createElement('span');
        etat.className = m.jamais ? 'rw-non-resolu' : 'rw-tableau__discret';
        etat.setAttribute('data-rw',
            (m.jamais ? 'f2b-cible-jamais-' : 'f2b-cible-date-') + m.id);
        etat.textContent = m.jamais
            ? (textes.portee_jamais || '')
            : remplit('portee_releve_le', { date: dateLisible(m.releve_le) });
        marques.appendChild(etat);

        ligne.appendChild(marques);

        return ligne;
    }

    function phrase(hote, classe, texte) {
        if (! texte) { return; }
        var p = document.createElement('p');
        p.className = classe;
        p.textContent = texte;
        hote.appendChild(p);
    }

    function rendUnePortee(hote, cibles, cleAvec, cleSans, marqueur) {
        var parc = portee.parc || 0;
        if (! cibles.length) {
            phrase(hote, 'rw-aide', remplit(cleSans, { parc: parc }));

            return;
        }
        phrase(hote, 'rw-aide', remplit(cleAvec, { nb: cibles.length, parc: parc }));
        var liste = document.createElement('div');
        liste.className = 'rw-liste-etats';
        liste.setAttribute('data-rw', marqueur);
        cibles.forEach(function (m) { liste.appendChild(ligneCible(m)); });
        hote.appendChild(liste);
    }

    /**
     * LA PORTEE, RENDUE UNE SEULE FOIS ET AU MEME ENDROIT.
     *
     * Un seul rendu, alimente par la page puis par la relecture : il ne peut
     * donc pas exister deux versions de cette liste — ni entre le premier
     * affichage et les suivants, ni entre cette section et le bloc du detail
     * d'une jail, qui lit la MEME donnee.
     */
    function rendPortee() {
        var installer = portee.installer || [];
        var bannir = portee.bannir || [];

        if (! porteeLue) {
            if (zonePortee) {
                // `poseMessage` vide l'hote lui-meme et pose son propre titre.
                poseMessage(zonePortee, 'portee_inconnue_titre', 'portee_inconnue', true);
                zonePortee.hidden = false;
            }
            if (aideParcBan) {
                aideParcBan.textContent = textes.parc_ban_inconnue || '';
                aideParcBan.classList.add('rw-erreur');
            }

            return;
        }

        if (zonePortee) {
            zonePortee.innerHTML = '';
            phrase(zonePortee, 'rw-sous-titre-fort', textes.portee_titre || '');
            phrase(zonePortee, 'rw-prose', textes.portee_cache || '');
            rendUnePortee(zonePortee, installer,
                'portee_installer', 'portee_installer_aucune', 'f2b-portee-installer');
            rendUnePortee(zonePortee, bannir,
                'portee_bannir', 'portee_bannir_aucune', 'f2b-portee-bannir');

            // L'EXPLICATION S'AFFICHE, elle ne vit pas dans une infobulle : c'est
            // la seule information qui dise POURQUOI une machine est visee.
            if (installer.some(function (m) { return m.jamais; })) {
                phrase(zonePortee, 'rw-prose', textes.portee_jamais_aide || '');
            }
            if (installer.concat(bannir).some(function (m) { return m.archivee; })) {
                phrase(zonePortee, 'rw-prose', textes.portee_archivee_aide || '');
            }
            // DEVOILE SEULEMENT MAINTENANT : voir le commentaire de la vue.
            zonePortee.hidden = false;
        }

        // Le bloc du detail d'une jail dit la MEME portee, en une ligne.
        if (aideParcBan) {
            aideParcBan.textContent = bannir.length
                ? remplit('parc_ban_aide', { nb: bannir.length, machines: nomsDe(bannir) })
                : (textes.parc_ban_aide_aucune || '');
            aideParcBan.classList.toggle('rw-erreur', bannir.length === 0);
        }
    }

    /**
     * RELIRE LA PORTEE, PARCE QU'UN RELEVE L'A PEUT-ETRE CHANGEE.
     *
     * `/fail2ban/status` appelle `_update_status_cache` : relever une machine
     * REECRIT la ligne qui decide de sa presence dans les deux portees. Sans
     * cette relecture, l'ecran garderait celles du chargement — le defaut que F1
     * a corrige sur la ligne du tableau de cache, ici a l'echelle du parc.
     *
     * On ne DEDUIT rien de la reponse du releve : on relit la base. Une
     * deduction serait fausse des que les deux raisonnements divergeraient, et
     * c'est le backend qui decide.
     */
    function rechargePortee() {
        return fetch(PORTEE, { headers: { Accept: 'application/json' } })
            .then(function (r) { return r.json().catch(function () { return null; }); })
            .then(function (d) {
                if (! d || d.success !== true || ! d.portee) {
                    if (messagePortee) {
                        messagePortee.textContent = textes.portee_echec || '';
                        messagePortee.classList.add('rw-erreur');
                    }

                    return;
                }
                portee = d.portee;
                porteeLue = true;
                rendPortee();
                if (messagePortee) {
                    messagePortee.textContent = textes.portee_relue || '';
                    messagePortee.classList.remove('rw-erreur');
                }
            })
            .catch(function () {
                if (messagePortee) {
                    messagePortee.textContent = textes.portee_echec || '';
                    messagePortee.classList.add('rw-erreur');
                }
            });
    }

    /**
     * UN VERDICT DE PARC SE DERIVE DES MACHINES, PAS DU DRAPEAU GLOBAL.
     *
     * `install_all` rendait `success: True` **en dur** quel que soit le
     * resultat : « Fail2ban installe sur 0/2 serveurs » arrivait avec un succes
     * annonce. Cinquieme occurrence d'E-165 sur ce module, et derniere qui
     * restait — `ban_all_servers` avait ete corrige au lot precedent et sa
     * voisine oubliee, une fois de plus. **Corrige depuis, en v1.38.13** : la
     * route compose desormais `ok == len(results) and len(results) > 0`.
     *
     * Ce code garde quand meme sa propre derivation, et c'est delibere. Chaque
     * entree de `results` porte un verdict honnete — le backend y teste `rc` — et
     * un ecran qui compte les machines lui-meme ne depend plus de la justesse
     * d'un drapeau. Meme traitement pour les deux routes : rien ne distingue
     * leurs reponses a l'ecran, donc rien ne doit les distinguer ici.
     *
     * `total` et `reussis` que la route rend desormais ne sont PAS lus : les
     * compter sur `results` mesure ce qui est affiche ligne par ligne, donc
     * l'ecran ne peut pas annoncer un compte que sa propre liste contredit.
     */
    function agitParc(chemin, envoi, cibles, apresInstall) {
        ferme();
        journalise(remplit('parc_envoi', { nb: cibles.length }), false);
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
              var resultats = d.results || [];
              var reussies = resultats.filter(function (r) { return r.success === true; }).length;
              var toutes = resultats.length > 0 && reussies === resultats.length;

              // La phrase du backend porte le compte : on la garde telle quelle,
              // mais c'est NOTRE decompte qui decide si elle se lit en reussite.
              // Une phrase absente ne devient pas une ligne vide.
              if (d.message) { journalise(String(d.message), ! toutes); }
              resultats.forEach(function (r) {
                  /*
                   * UN ECHEC SANS DETAIL SE DIT SANS TIRET EN L'AIR.
                   *
                   * `install_all` n'ajoute `error` que dans sa branche
                   * d'exception : un `rc != 0` rend `{server, success: false}`
                   * tout court. « echoue — » aurait laisse un tiret pendant a
                   * l'ecran, ce qui se lit comme un detail perdu.
                   */
                  var detail = r.error || (r.exit_code == null ? '' : String(r.exit_code));
                  journalise(remplit('parc_resultat_machine', {
                      machine: r.server || '',
                      etat: r.success === true
                          ? (textes.parc_ok || '')
                          : (detail
                              ? remplit('parc_echec', { message: detail })
                              : (textes.parc_echec_muet || '')),
                  }), r.success !== true);
              });
              if (! resultats.length) { journalise(textes.parc_rien || '', true); }

              /*
               * INSTALLER N'EST PAS RELEVER. `install_all` n'ecrit pas le cache :
               * la portee restera identique jusqu'a ce que chaque machine soit
               * relevee. Sans cette ligne, on installerait, on relirait la
               * portee, on y retrouverait les memes machines — et on en
               * concluerait que le geste n'a rien fait.
               */
              if (apresInstall) { journalise(textes.parc_apres_install || '', false); }

              rechargePortee();
              /*
               * SECOND TEMOIN — ET SEULEMENT S'IL EN EST UN.
               *
               * Relire le detail de la jail affichee ne prouve quelque chose que
               * si la machine affichee etait DANS la portee. Le faire dans tous
               * les cas ouvrirait une session SSH de plus qui ne temoigne de
               * rien : `install_all` ne touche aucune jail, et le ban de parc ne
               * touche pas forcement la machine qu'on regarde.
               */
              var vue = machineChoisie();
              var etaitVisee = vue !== null && cibles.some(function (m) {
                  return m.id === parseInt(vue.value, 10);
              });
              if (jailCourante && etaitVisee) { ouvreJail(jailCourante); }
          })
          .catch(function () {
              journalise(remplit('geste_echoue', { message: textes.lecture_echec || '' }), true);
          });
    }

    /*
     * ══ CE QUE LA VALIDATION DU NAVIGATEUR N'EST PAS ══════════════════════
     *
     * E-174, trouve dans CE module : `_validate_ip` appelait
     * `ipaddress.ip_address()` pour son effet de bord et rendait la chaine
     * RECUE. L'identifiant de portee IPv6 — ce qui suit un `%` — n'est soumis a
     * aucune contrainte, il traversait donc le validateur, se retrouvait
     * interpole dans la commande distante, et le `sh -c` l'interpretait : une
     * execution de commande en root. **Le pire vecteur etait
     * `POST /fail2ban/ban_all_servers`** — role 2, aucun controle d'acces
     * machine — c'est-a-dire la route que ce geste-ci appelle.
     *
     * **Ferme dans le backend** : refus de tout `%` (`fail2ban_manager.py:56`)
     * ET `shlex.quote` a l'INTERIEUR de la commande (`:221`, `:230`). Deux
     * verrous, parce que le premier ferme le vecteur connu et le second la
     * classe. La normalisation, elle, n'aurait rien ferme : `str(ip_address())`
     * conserve l'identifiant de portee tel quel — la parade « normaliser puis
     * comparer » vaut quand la valeur sert a COMPARER, et ici elle COMPOSE.
     *
     * Ce que fait `adresseValide` ci-dessus, et ce qu'elle ne fait pas. Mesure :
     * elle refuse les quatre charges d'E-174 (`fe80::1%;id;`, `%$(id)`,
     * `` %`id` ``, `%'`) et `203.0.113.7; id`, elle accepte `203.0.113.7`,
     * `fe80::1` et `2001:db8::1`. **Rien d'hostile ne peut donc PARTIR de cette
     * page — et ce n'est pas la garde** : une requete forgee ne passe pas par
     * cet ecran. La garde est celle du backend ; celle-ci evite un aller-retour
     * et un message inutilement tardif, comme pour un ban d'une seule machine.
     */
    function demandeBanParc() {
        if (! jailCourante || ! champBan) { return; }
        if (! porteeLue) {
            demande('conf_titre_parc_inconnue', 'conf_texte_parc_inconnue',
                {}, null, { bloque: true });

            return;
        }
        var adresse = (champBan.value || '').trim();
        // Validee AVANT tout envoi, comme pour un ban d'une seule machine.
        if (! adresseValide(adresse)) {
            journalise(textes.ban_invalide || '', true);

            return;
        }
        var cibles = portee.bannir || [];
        if (! cibles.length) {
            demande('conf_titre_parc_ban_vide', 'conf_texte_parc_ban_vide',
                { ip: adresse }, null, { bloque: true });

            return;
        }
        demande('conf_titre_parc_ban', 'conf_texte_parc_ban',
            { ip: adresse, jail: jailCourante, nb: cibles.length, machines: nomsDe(cibles) },
            function () {
                agitParc('/fail2ban/ban_all_servers',
                    { ip: adresse, jail: jailCourante }, cibles, false);
            },
            { recopie: cibles.length });
    }

    function demandeInstallParc() {
        if (! porteeLue) {
            demande('conf_titre_parc_inconnue', 'conf_texte_parc_inconnue',
                {}, null, { bloque: true });

            return;
        }
        var cibles = portee.installer || [];
        if (! cibles.length) {
            demande('conf_titre_parc_install_vide', 'conf_texte_parc_install_vide',
                { parc: portee.parc || 0 }, null, { bloque: true });

            return;
        }
        demande('conf_titre_parc_install', 'conf_texte_parc_install',
            {
                nb: cibles.length,
                machines: nomsDe(cibles),
                prod: cibles.filter(function (m) { return m.sensible; }).length,
                jamais: cibles.filter(function (m) { return m.jamais; }).length,
            },
            // Le corps est VIDE, comme celui du legacy : c'est le backend qui
            // choisit. Ce que le portage ajoute, c'est de le DIRE avant.
            function () { agitParc('/fail2ban/install_all', {}, cibles, true); },
            { recopie: cibles.length });
    }

    if (boutonBannirParc) { boutonBannirParc.addEventListener('click', demandeBanParc); }
    if (boutonInstallerParc) { boutonInstallerParc.addEventListener('click', demandeInstallParc); }
    if (relirePortee) { relirePortee.addEventListener('click', rechargePortee); }

    // La portee s'affiche des le chargement : elle ne depend d'aucun geste, et
    // c'est une information qui vaut par elle-meme.
    rendPortee();

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
            // LE RELEVE A REECRIT LE CACHE : la portee des gestes de parc a
            // peut-etre change. On la relit en base plutot que de la deduire de
            // la reponse qu'on vient de lire.
            rechargePortee();
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
