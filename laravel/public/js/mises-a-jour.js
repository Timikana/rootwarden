/**
 * mises-a-jour.js - Module `update/`, PORTE EN ENTIER (sous-lots U1 a U6b).
 *
 * Parc et filtres, constats, planification, redemarrage, mises a jour de
 * securite, mise a jour complete et reparation dpkg. Le legacy est archive.
 * Un fichier qui a grossi par accumulation : le relire EN ENTIER avant d'y
 * ajouter quoi que ce soit — une relecture integrale y a trouve quatre defauts
 * qu'aucun test ne montrait.
 *
 * Rendu par `textContent` et `createElement`, jamais par interpolation.
 *
 * LA DIFFERENCE QUI COMPTE : LE RAFRAICHISSEMENT NE PERD PLUS DE COLONNES.
 *
 * Le legacy affiche treize colonnes, puis les recharge depuis
 * `update/functions/list_machines.php`, qui n'en SELECTionne que onze.
 * Rafraichir la liste remplace donc « dernier redemarrage », « MAJ securite
 * planifiee » et « derniere execution » par « N/A » — mesure : la colonne
 * « dernier redemarrage » passe de renseignee a vide, sans qu'on l'ait demande
 * et sans rien annoncer.
 *
 * Ici, le rafraichissement et le filtrage passent tous deux par
 * `/filter_servers`, qui rend les QUATORZE colonnes, exclut les machines
 * archivees et applique le meme cloisonnement par role. Un rafraichissement ne
 * peut donc plus appauvrir ce qui etait affiche.
 *
 * Chargements SEQUENCES : chaque appel porte un numero, seul le dernier ecrit.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const corps = document.getElementById('server-table-body');
    const annonce = document.getElementById('maj-annonce');
    const libelles = JSON.parse(document.getElementById('maj-libelles').textContent);

    let parc = JSON.parse(document.getElementById('maj-parc').textContent) || [];
    let dernierChargement = 0;

    function jetonCsrf() {
        return document.querySelector('meta[name="csrf-token"]')?.content || '';
    }

    async function appelle(chemin, options) {
        const parametres = Object.assign({
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin',
        }, options || {});
        if (parametres.method && parametres.method !== 'GET') {
            parametres.headers = Object.assign({}, parametres.headers, {
                'X-CSRF-TOKEN': jetonCsrf(),
                'Content-Type': 'application/json',
            });
        }
        // `fetch` REJETTE quand le reseau lache ou que la passerelle ne repond
        // pas. Sans ce filet, la promesse remonte jusqu'a l'appelant, qui
        // s'arrete AVANT de reactiver son bouton : l'ecran reste fige sur « en
        // cours » indefiniment. Cinq appelants etaient dans ce cas.
        //
        // L'erreur n'est pas AVALEE : elle part en console et l'appel rend un
        // echec explicite, que chaque appelant sait deja annoncer.
        let r;
        try {
            r = await fetch(PASSERELLE + chemin, parametres);
        } catch (e) {
            console.error('passerelle injoignable :', chemin, e);
            return {
                ok: false,
                statut: 0,
                corps: { success: false, message: libelles.err_reseau },
            };
        }

        let corpsJson = null;
        try { corpsJson = await r.json(); } catch (e) { /* reponse non JSON */ }
        return { ok: r.ok, statut: r.status, corps: corpsJson };
    }

    function dit(texte, ton) {
        annonce.textContent = texte || '';
        annonce.className = 'rw-annonce' + (ton ? ' rw-annonce--' + ton : '');

        // Le journal d'execution (U2) garde la trace de ce que la page a fait.
        // L'annonce, elle, ne montre que le dernier etat — les deux se
        // completent, ils ne se remplacent pas.
        if (window.rwJournal) window.rwJournal.ajoute(texte, ton === 'echec' ? 'error' : (ton || 'info'));
    }

    function heure() { return new Date().toLocaleTimeString(); }

    /**
     * Normalise un horodatage, d'ou qu'il vienne.
     *
     * Les quatre colonnes de dates arrivent sous DEUX formes : le premier rendu
     * les tient du controleur, qui rend le format MySQL (`2026-08-19 14:03:00`),
     * et les relectures les tiennent de `/filter_servers`, qui applique
     * `isoformat()` cote Python (`2026-08-19T14:03:00`). Quatre colonnes
     * changeaient donc de forme au premier « Rafraichir ». Le rendu etant
     * commun, la normalisation l'est aussi : un seul endroit, pas six.
     */
    function horodatage(valeur) {
        if (!valeur) return valeur;
        return String(valeur).replace('T', ' ').slice(0, 19);
    }

    function cellule(texte, classes) {
        const td = document.createElement('td');
        if (classes) td.className = classes;
        td.textContent = texte;
        return td;
    }

    function message(titre, aide) {
        corps.replaceChildren();
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 8;
        td.className = 'rw-tableau__message';
        const t = document.createElement('div');
        t.className = 'rw-tableau__message-titre';
        t.textContent = titre;
        td.appendChild(t);
        if (aide) {
            const p = document.createElement('p');
            p.className = 'rw-tableau__message-aide';
            p.textContent = aide;
            td.appendChild(p);
        }
        tr.appendChild(td);
        corps.appendChild(tr);
    }

    /** Un bouton de relevé : il interroge la machine sans rien y changer. */
    function boutonReleve(libelle, infobulle, marque, action) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
        b.textContent = libelle;
        b.title = infobulle;
        b.dataset.rw = marque;
        b.addEventListener('click', () => action(b));
        return b;
    }

    /**
     * Le menu d'actions de la ligne (public/js/menu-ligne.js). Les boutons y
     * gardent leur `data-rw` et leurs gestionnaires.
     */
    function menuLigne(id, nom, boutons) {
        const conteneur = document.createElement('div');
        conteneur.className = 'rw-menu-ligne';

        const liste = document.createElement('div');
        liste.className = 'rw-menu-ligne__liste';
        liste.id = 'maj-menu-' + id;
        liste.setAttribute('popover', 'auto');
        liste.append(...boutons);

        const ouvre = document.createElement('button');
        ouvre.type = 'button';
        ouvre.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule rw-menu-ligne__bouton';
        ouvre.setAttribute('popovertarget', liste.id);
        ouvre.setAttribute('aria-expanded', 'false');
        ouvre.setAttribute('aria-label', (libelles.actions_pour || '').replace(':machine', nom));
        ouvre.dataset.rw = 'maj-menu-' + id;
        ouvre.append(document.createTextNode(libelles.btn_actions || ''), icone('chevron-down'));

        conteneur.append(ouvre, liste);
        return conteneur;
    }

    /** Une valeur lisible par sa classe, dans une cellule qui en porte plusieurs. */
    function sousValeur(texte, classe) {
        const s = document.createElement('span');
        s.className = classe;
        s.textContent = texte;
        return s;
    }

    /** Une icone du sprite, a l'adresse versionnee que la page emploie deja. */
    function icone(nom) {
        const ns = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('class', 'rw-icone');
        svg.setAttribute('aria-hidden', 'true');
        svg.setAttribute('focusable', 'false');
        const use = document.createElementNS(ns, 'use');
        const sprite = (document.querySelector('use[href*="/icones/lucide.svg"]')?.getAttribute('href') || '/icones/lucide.svg').split('#')[0];
        use.setAttribute('href', sprite + '#i-' + nom);
        svg.appendChild(use);
        return svg;
    }

    function rend(machines, filtreActif) {
        if (!machines.length) {
            if (filtreActif) message(libelles.vide_filtre, libelles.vide_filtre_aide);
            else message(libelles.vide, libelles.vide_aide);
            return;
        }

        corps.replaceChildren();
        for (const m of machines) {
            const id = parseInt(m.id, 10);
            if (!id) continue;

            const tr = document.createElement('tr');
            tr.setAttribute('data-machine-id', String(id));
            tr.setAttribute('data-ip', m.ip ?? '');
            tr.setAttribute('data-port', String(m.port ?? 22));

            const tdCase = document.createElement('td');
            const coche = document.createElement('input');
            coche.type = 'checkbox';
            coche.name = 'selected_machines[]';
            coche.value = String(id);
            // Une case sans nom se lit « case a cocher, non cochee » : laquelle ?
            coche.setAttribute('aria-label', (libelles.selectionner || '').replace(':machine', m.name ?? ''));
            tdCase.appendChild(coche);
            tr.appendChild(tdCase);

            // TREIZE COLONNES EN HUIT. L'adresse et le contexte (environnement,
            // criticite, reseau) se lisent sous le nom ; la planification et sa
            // derniere execution partagent une cellule. Chaque valeur garde sa
            // CLASSE : `ecrit()` et les suites la retrouvent par elle.
            const tdNom = document.createElement('td');
            const nom = document.createElement('span');
            nom.className = 'server-name rw-tableau__fort';
            nom.textContent = m.name ?? '';
            const contexte = document.createElement('span');
            contexte.className = 'rw-tableau__sous-ligne';
            contexte.append(
                sousValeur(`${m.ip ?? ''}:${m.port ?? ''}`, 'ip-port'), ' · ',
                sousValeur(m.environment || 'OTHER', 'environment'), ' · ',
                sousValeur(m.criticality || 'NON CRITIQUE', 'criticality'), ' · ',
                sousValeur(m.network_type || 'INTERNE', 'network-type'),
            );
            tdNom.append(nom, contexte);
            tr.appendChild(tdNom);

            // Le menu porte sa propre disposition : la cellule reste une cellule.
            const tdActions = document.createElement('td');
            tdActions.append(menuLigne(id, m.name ?? '', [
                boutonReleve(libelles.btn_version, libelles.tip_version, 'version-' + id,
                             (b) => releveVersion(id, tr, b)),
                boutonReleve(libelles.btn_statut, libelles.tip_statut, 'statut-' + id,
                             (b) => releveStatut(id, tr, b)),
                boutonReleve(libelles.btn_reboot, libelles.tip_reboot, 'reboot-' + id,
                             (b) => releveRedemarrage(id, tr, b)),
                boutonReleve(libelles.btn_planifier_secu, libelles.tip_planifier_secu,
                             'planifier-secu-' + id,
                             () => ouvrePlanification(id, m.name ?? '')),
            ]));
            tr.appendChild(tdActions);

            tr.appendChild(cellule(m.linux_version || libelles.non_verifie, 'linux-version'));
            tr.appendChild(cellule(horodatage(m.last_checked) || libelles.non_verifie, 'last-checked rw-tableau__discret'));
            const tdEtat = cellule('', 'online-status');
            tdEtat.replaceChildren(pastilleEtat(m.online_status));
            tr.appendChild(tdEtat);
            const tdPlanif = document.createElement('td');
            tdPlanif.className = 'rw-tableau__discret';
            const execution = document.createElement('span');
            execution.className = 'rw-tableau__sous-ligne';
            execution.append(`${libelles.planif_execution || ''} `,
                sousValeur(horodatage(m.maj_secu_last_exec_date) || libelles.aucune, 'maj-secu-lastexec-date'));
            tdPlanif.append(sousValeur(horodatage(m.maj_secu_date) || libelles.aucune, 'maj-secu-date'), execution);
            tr.appendChild(tdPlanif);

            const tdRedemarrage = cellule(horodatage(m.last_reboot) || libelles.aucune, 'last-reboot rw-tableau__discret');
            tdRedemarrage.id = 'last-reboot-' + id;
            tr.appendChild(tdRedemarrage);


            corps.appendChild(tr);
        }
    }

    /**
     * Relit le parc par la passerelle.
     *
     * `/filter_servers` sans filtre rend le parc entier avec ses quatorze
     * colonnes — c'est pour cela qu'il sert AUSSI au rafraichissement, la ou le
     * legacy appelle un endpoint qui en rend onze.
     */
    async function relit(filtres) {
        const numero = ++dernierChargement;
        const params = new URLSearchParams();
        for (const [cle, valeur] of Object.entries(filtres || {})) {
            if (valeur) params.set(cle, valeur);
        }
        const filtreActif = [...params.keys()].length > 0;

        const res = await appelle('/filter_servers' + (filtreActif ? '?' + params.toString() : ''));

        if (numero !== dernierChargement) return;

        if (!res.ok || !res.corps || !res.corps.success) {
            // L'erreur ne s'avale pas : garder les lignes precedentes les ferait
            // passer pour le resultat de la demande.
            message(libelles.err_load);
            // Recompter APRES avoir vide le tableau : sans cela le compteur
            // continuait d'annoncer les machines d'un tableau qui n'existe plus.
            // Deux affirmations contradictoires a l'ecran, et l'action suivante
            // repondait « aucune machine retenue » — ce que l'ecran dementait.
            compteSelection();
            dit(libelles.err_load, 'echec');
            return;
        }

        parc = res.corps.machines || [];
        rend(parc, filtreActif);
        compteSelection();
        dit(filtreActif
            ? libelles.filtre_ok.replace(':nombre', parc.length)
            : libelles.maj_ok.replace(':heure', heure()).replace(':nombre', parc.length));
    }

    function filtresCourants() {
        return {
            environment: document.getElementById('environment').value,
            criticality: document.getElementById('criticality').value,
            networkType: document.getElementById('network-type').value,
            // `/filter_servers` joint `machine_tags` quand `tag` est fourni.
            tag: document.getElementById('tag-filter')?.value || '',
        };
    }

    /** Ecrit une cellule de la ligne, sans toucher aux autres. */
    /* LA DISPONIBILITE EST UN ETAT : une pastille coloree, pas « ONLINE » brut.
       Le backend rend ONLINE / OFFLINE (casse variable) ; le reste est inconnu. */
    function pastilleEtat(valeur) {
        const v = String(valeur || '').toLowerCase();
        const s = document.createElement('span');
        s.className = 'rw-pastille ' + (v === 'online' ? 'rw-pastille--ok' : v === 'offline' ? 'rw-pastille--echec' : 'rw-pastille--neutre');
        s.textContent = v === 'online' ? libelles.en_ligne : v === 'offline' ? libelles.hors_ligne : libelles.inconnu;
        s.title = String(valeur || '');
        return s;
    }

    function ecritEtat(tr, valeur) {
        const td = tr.querySelector('.online-status');
        if (td) td.replaceChildren(pastilleEtat(valeur));
    }

    function ecrit(tr, classe, valeur) {
        const td = tr.querySelector('.' + classe);
        if (td) td.textContent = valeur;
    }

    async function releve(bouton, appel, apres) {
        const initial = bouton.textContent;
        bouton.disabled = true;
        bouton.textContent = libelles.en_cours;
        dit(libelles.en_cours);

        const res = await appel();

        bouton.disabled = false;
        bouton.textContent = initial;

        if (!res.ok || !res.corps || res.corps.success === false) {
            dit((res.corps && res.corps.message) || libelles.err_releve, 'echec');
            return;
        }
        apres(res.corps);
        dit(libelles.releve_ok, 'ok');
    }

    function releveVersion(id, tr, bouton) {
        return releve(bouton,
            () => appelle('/linux_version', { method: 'POST', body: JSON.stringify({ machine_id: id }) }),
            (c) => {
                if (c.linux_version) ecrit(tr, 'linux-version', c.linux_version);
                if (c.last_checked) ecrit(tr, 'last-checked', horodatage(c.last_checked));
            });
    }

    function releveStatut(id, tr, bouton) {
        return releve(bouton,
            () => appelle('/server_status', { method: 'POST', body: JSON.stringify({ machine_id: id }) }),
            (c) => { if (c.status || c.online_status) ecritEtat(tr, c.status || c.online_status); });
    }

    function releveRedemarrage(id, tr, bouton) {
        return releve(bouton,
            () => appelle('/last_reboot', { method: 'POST', body: JSON.stringify({ machine_id: id }) }),
            (c) => { if (c.last_reboot) ecrit(tr, 'last-reboot', horodatage(c.last_reboot)); });
    }

    /* ═════════════════════════════════════════════════════════════════════
       Sous-lot U3 — le constat « paquets en attente »

       CE QUE FAIT LA ROUTE, LU DANS `backend/routes/updates.py` AVANT DE
       CLIQUER. `/pending_packages` ouvre une session SSH et lance, en root :

           apt-get update -qq 2>/dev/null; apt list --upgradable

       Elle n'installe RIEN et ne supprime rien. Elle n'est pas pour autant
       sans effet sur la machine : `apt-get update` REECRIT l'index local des
       paquets. C'est une ecriture, meme si ce n'est pas un changement d'etat
       du systeme.

       Le backend decoupe lui-meme la sortie et ne renvoie que des noms et des
       versions : aucune ligne brute ne remonte au navigateur. C'est ce qui
       permet de porter ce constat-ci alors que la simulation, qui diffuse son
       flux tel quel, reste au legacy — voir PARITE.md, E-17.

       Le POINT-VIRGULE entre les deux commandes, et la stderr jetee, font
       qu'un echec du rafraichissement passe inapercu : la reponse vaut alors
       « 0 paquet » sans distinguer « la machine est a jour » de « je n'ai pas
       pu regarder ». L'etat vide ne promet donc pas que la machine est a jour.
       ═════════════════════════════════════════════════════════════════════ */

    /**
     * Referme tous les panneaux de decision sauf celui qu'on ouvre.
     *
     * Quatre panneaux — planification, redemarrage, mises a jour de securite,
     * et le panneau generique de U6b —
     * portent sur la MEME selection. Deux ouverts en meme temps laissent croire
     * a deux gestes en attente ; la capture l'a montre avant que ce ne soit une
     * regle.
     */
    function fermeLesAutresPanneaux(garde) {
        for (const id of ['schedule-form', 'reboot-panneau', 'secu-panneau', 'action-panneau']) {
            if (id === garde) continue;
            const el = document.getElementById(id);
            if (el) el.hidden = true;
        }
    }

    const boutonPaquets = document.getElementById('pending-packages-btn');
    const compteurSelection = document.getElementById('selection-count');

    /** Ligne de journal sur le panneau d'un serveur, ou dans la zone generale. */
    function journal(texte, genre, serveur) {
        if (window.rwJournal) window.rwJournal.ajoute(texte, genre, serveur);
    }

    function machinesCochees() {
        const choix = [];
        for (const c of corps.querySelectorAll('input[name="selected_machines[]"]:checked')) {
            const tr = c.closest('tr');
            const nom = tr ? (tr.querySelector('.server-name')?.textContent || '') : '';
            const id = parseInt(c.value, 10);
            if (id) choix.push({ id: id, nom: nom });
        }
        return choix;
    }

    /*
     * La regle « il faut au moins une machine » est appliquee par la page comme
     * par le legacy. Elle se REND VISIBLE avant le geste : le compteur dit
     * combien de machines sont retenues, plutot que de laisser decouvrir apres
     * coup qu'il n'y en avait aucune.
     */
    function compteSelection() {
        if (!compteurSelection) return;
        const n = corps.querySelectorAll('input[name="selected_machines[]"]:checked').length;
        compteurSelection.textContent = n
            ? libelles.selection.replace(':nombre', n)
            : libelles.selection_vide;
        compteurSelection.setAttribute('data-nombre', String(n));
    }

    async function paquetsEnAttente() {
        const choix = machinesCochees();
        if (!choix.length) {
            dit(libelles.aucune_selection, 'echec');
            return;
        }

        const initial = boutonPaquets.textContent;
        boutonPaquets.disabled = true;
        boutonPaquets.textContent = libelles.paquets_en_cours;
        dit(libelles.paquets_en_cours);

        let echecs = 0;

        // En SERIE : chaque machine ouvre une session SSH et lance un
        // `apt-get update`. Les lancer toutes de front n'accelere rien et rend
        // le journal illisible.
        for (const m of choix) {
            const res = await appelle('/pending_packages', {
                method: 'POST',
                body: JSON.stringify({ machine_id: m.id }),
            });
            const c = res.corps;

            if (!res.ok || !c || c.success === false) {
                echecs++;
                // UNE ERREUR NE S'AVALE PAS : elle se nomme, sur le panneau du
                // serveur concerne, et le constat n'est pas annonce comme reussi.
                journal((c && c.message) || libelles.paquets_err, 'error', m.nom);
                continue;
            }

            const nombre = c.count || 0;
            if (!nombre) {
                journal(libelles.paquets_aucun, 'ok', m.nom);
                journal(libelles.paquets_aucun_reserve, 'info', m.nom);
                continue;
            }

            journal(libelles.paquets_nombre.replace(':nombre', nombre), 'info', m.nom);
            for (const p of (c.packages || [])) {
                const versions = p.current ? p.current + ' -> ' + p.available : p.available;
                journal('  - ' + p.name + ' (' + versions + ')', 'info', m.nom);
            }
        }

        boutonPaquets.disabled = false;
        boutonPaquets.textContent = initial;
        dit(echecs
            ? libelles.paquets_fin_partielle.replace(':nombre', echecs)
            : libelles.paquets_fin.replace(':nombre', choix.length),
            echecs ? 'echec' : 'ok');
    }

    /* ═════════════════════════════════════════════════════════════════════
       Sous-lot U4 — la planification

       CE QUE FONT LES ROUTES, LU DANS `backend/routes/updates.py` AVANT DE
       CLIQUER. Les deux ECRIVENT un fichier dans `/etc/cron.d/` sur la machine
       distante, en root, puis redemarrent cron :

         /schedule_advanced_update           -> /etc/cron.d/auto_update_advanced
         /schedule_advanced_security_update  -> /etc/cron.d/auto_security_update_advanced
                                                + UPDATE machines.maj_secu_date

       POURQUOI LE PORTAGE N'APPELLE PAS LA MEME ROUTE QUE LE LEGACY.
       `saveAdvancedSchedule()` envoie `{machine_id, date, time, repeat}` a
       `/schedule_update`, qui attend `interval_minutes` : la validation echoue
       et la reponse est un 400, toujours. La planification generale du legacy
       n'a donc jamais rien planifie. La route qui correspond au formulaire est
       `/schedule_advanced_update`, et personne ne l'appelle. Voir PARITE.md,
       E-18.

       LA RECURRENCE NE VEUT PAS DIRE CE QUE SON NOM LAISSE CROIRE (E-19) :
       cron n'a pas de champ ANNEE, donc « ne pas repeter » revient chaque
       annee ; et la planification generale ecrit l'hebdomadaire le LUNDI
       (`* * 1`) et le mensuel le PREMIER du mois (`1 * *`), quelle que soit la
       date choisie — la planification de securite, elle, suit la date. Le
       formulaire montre l'expression reellement ecrite AVANT le geste.

       LA PLANIFICATION GENERALE A ETE RETIREE du portage (2026-11-15) : elle
       forcait le lundi et le 1er du mois et sa date n'etait affichee nulle
       part, a cote d'une planification qui fait le meme `apt-get upgrade` en
       suivant la date choisie. Seule `/schedule_advanced_security_update`
       reste appelee ; les routes generales sont retirees du backend
       (2026-11-16).
       ═════════════════════════════════════════════════════════════════════ */

    const planif = JSON.parse(document.getElementById('maj-planif-libelles')?.textContent || '{}');
    const formulaire = document.getElementById('schedule-form');
    const champDate = document.getElementById('sched-date');
    const champHeure = document.getElementById('sched-time');
    const champRecurrence = document.getElementById('sched-repeat');
    const zoneApercu = document.getElementById('sched-apercu');
    const titrePlanif = document.getElementById('sched-titre');
    const machinePlanif = document.getElementById('sched-machine');
    const boutonEnregistrer = document.getElementById('sched-save');
    const etatExistantes = document.getElementById('sched-existantes-etat');
    const listeExistantes = document.getElementById('sched-existantes');

    /** Machine en cours d'edition ; null quand le formulaire est ferme. */
    let planifEnCours = null;

    /**
     * Expression cron que le BACKEND va ecrire, et sa lecture en clair.
     *
     * Reproduit exactement les deux fonctions Python. Toute divergence entre
     * cet apercu et le fichier pose sur la machine est un defaut : le test de
     * U4 compare les deux.
     */
    function calculeCron(date, heureChoisie, recurrence) {
        // `heureChoisie` et non `heure` : `heure()` est l'horloge du journal.
        // Des ENTIERS, sans zero initial : le backend ecrit `f"{_minute} {_heure}"`
        // sur des `int`, donc `30 3`, et un apercu `30 03` ne disait pas
        // exactement ce que la machine recevait. Mesure par u4 le 2026-11-15.
        const entier = (v) => String(parseInt(v, 10));
        const [hh, mm] = heureChoisie.split(':').map(entier);
        const [, mois, jour] = date.split('-').map(entier);
        const jourJs = new Date(date + 'T00:00:00').getDay();
        const jourCron = jourJs === 0 ? 7 : jourJs;   // Python : weekday() + 1

        if (recurrence === 'daily') {
            return { cron: `${mm} ${hh} * * *`, texte: planif.apercu_daily, reserve: '' };
        }
        if (recurrence === 'weekly') {
            return {
                cron: `${mm} ${hh} * * ${jourCron}`,
                texte: planif.apercu_weekly.replace(':jour', planif.jours[jourCron - 1]),
                reserve: '',
            };
        }
        if (recurrence === 'monthly') {
            return {
                cron: `${mm} ${hh} ${jour} * *`,
                texte: planif.apercu_monthly.replace(':jour', jour),
                reserve: '',
            };
        }
        return {
            cron: `${mm} ${hh} ${jour} ${mois} *`,
            texte: planif.apercu_none.replace(':jour', jour).replace(':mois', mois),
            reserve: planif.reserve_annuel,
        };
    }

    function montreApercu() {
        if (!planifEnCours) return;
        const d = champDate.value;
        const h = champHeure.value;
        if (!d || !h) {
            zoneApercu.textContent = planif.apercu_incomplet;
            zoneApercu.className = 'rw-apercu rw-apercu--incomplet';
            boutonEnregistrer.disabled = true;
            return;
        }
        const r = calculeCron(d, h, champRecurrence.value);
        const heureTexte = r.texte.replace(':heure', h);
        zoneApercu.textContent = heureTexte + '  —  ' + r.cron + (r.reserve ? '  ' + r.reserve : '');
        zoneApercu.className = 'rw-apercu' + (r.reserve ? ' rw-apercu--reserve' : '');
        boutonEnregistrer.disabled = false;
    }

    function ouvrePlanification(id, nom) {
        planifEnCours = { id: id, nom: nom };
        titrePlanif.textContent = planif.titre_secu;
        machinePlanif.textContent = planif.desc_secu.replace(':machine', nom);
        fermeLesAutresPanneaux('schedule-form');
        // Repartir d'un etat connu, comme les trois autres panneaux : sans
        // cela, la date saisie pour une AUTRE machine reste dans le champ et
        // l'apercu la declare valide — le bouton naît actif.
        champDate.value = '';
        champHeure.value = '';
        champRecurrence.selectedIndex = 0;
        boutonEnregistrer.disabled = true;

        formulaire.hidden = false;
        montreApercu();
        lisPlanificationsMachine(id, nom);
        formulaire.scrollIntoView({ block: 'nearest' });
        champDate.focus();
    }

    function fermePlanification() {
        planifEnCours = null;
        formulaire.hidden = true;
    }

    /*
     * CE QUI EST DEJA SUR LA MACHINE. La base ne garde que la planification
     * actuelle (`maj_secu_date`) ; l'ancien bouton « Planifier » et la
     * planification par intervalle posaient leurs propres fichiers cron, que
     * rien ne montrait. On les lit donc sur la machine, a chaque ouverture.
     *
     * Le numero de lecture ecarte une reponse arrivee apres qu'on a ouvert le
     * panneau d'une AUTRE machine : sans lui, la liste de A s'afficherait sous
     * le nom de B.
     */
    let lectureCourante = 0;

    /** L'etat de la lecture ; vide, son paragraphe disparait avec sa marge. */
    function ecritEtatExistantes(texte) {
        etatExistantes.textContent = texte;
        etatExistantes.hidden = !texte;
    }

    async function lisPlanificationsMachine(id, nom) {
        const numero = ++lectureCourante;
        listeExistantes.hidden = true;
        listeExistantes.replaceChildren();
        ecritEtatExistantes(planif.existantes_lecture);

        const res = await appelle('/scheduled_updates', {
            method: 'POST',
            body: JSON.stringify({ machine_id: id }),
        });
        if (numero !== lectureCourante) return;

        const c = res.corps;
        if (!res.ok || !c || c.success === false) {
            ecritEtatExistantes(planif.existantes_err
                .replace(':message', (c && c.message) || String(res.statut)));
            return;
        }
        rendPlanifications(id, nom, (c.planifications || []).filter((p) => p.present));
    }

    function rendPlanifications(id, nom, presentes) {
        listeExistantes.replaceChildren();
        if (!presentes.length) {
            ecritEtatExistantes(planif.existantes_aucune);
            listeExistantes.hidden = true;
            return;
        }
        ecritEtatExistantes('');
        for (const p of presentes) {
            const li = document.createElement('li');
            li.className = 'rw-planifs-machine__ligne';
            li.dataset.rw = 'planif-machine-' + p.fichier;

            const corpsLigne = document.createElement('div');
            corpsLigne.className = 'rw-planifs-machine__corps';
            const titre = sousValeur(planif.fichiers[p.fichier] || p.fichier, 'rw-tableau__fort');
            const chemin = sousValeur('/etc/cron.d/' + p.fichier, 'rw-code rw-tableau__discret');
            corpsLigne.append(titre, chemin);
            for (const e of p.expressions || []) {
                corpsLigne.append(sousValeur(e, 'rw-code'));
            }

            const actions = document.createElement('div');
            actions.className = 'rw-planifs-machine__actions';
            actions.append(boutonRetrait(id, nom, p.fichier, actions));

            li.append(corpsLigne, actions);
            listeExistantes.append(li);
        }
        listeExistantes.hidden = false;
    }

    /*
     * Retirer se decide DANS la ligne : un premier clic remplace le bouton par
     * « Confirmer le retrait » et « Annuler ». Aucune boite native.
     */
    function boutonRetrait(id, nom, fichier, actions) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'rw-bouton rw-bouton--danger-discret rw-bouton--minuscule';
        b.textContent = planif.btn_retirer;
        b.dataset.rw = 'retirer-' + fichier;
        b.addEventListener('click', () => {
            const confirmer = document.createElement('button');
            confirmer.type = 'button';
            confirmer.className = 'rw-bouton rw-bouton--danger rw-bouton--minuscule';
            confirmer.textContent = planif.btn_confirmer_retrait;
            confirmer.dataset.rw = 'confirmer-retrait-' + fichier;
            const annuler = document.createElement('button');
            annuler.type = 'button';
            annuler.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
            annuler.textContent = planif.btn_annuler;
            annuler.addEventListener('click', () => actions.replaceChildren(boutonRetrait(id, nom, fichier, actions)));
            confirmer.addEventListener('click', () => retire(id, nom, fichier, confirmer, annuler));
            actions.replaceChildren(annuler, confirmer);
            confirmer.focus();
        });
        return b;
    }

    async function retire(id, nom, fichier, confirmer, annuler) {
        confirmer.disabled = true;
        annuler.disabled = true;
        confirmer.textContent = planif.retrait_en_cours;
        const libelle = planif.fichiers[fichier] || fichier;

        const res = await appelle('/scheduled_updates/remove', {
            method: 'POST',
            body: JSON.stringify({ machine_id: id, fichier: fichier }),
        });
        const c = res.corps;
        if (!res.ok || !c || c.success === false) {
            journal((c && c.message) || planif.retrait_err, 'error', nom);
            dit((c && c.message) || planif.retrait_err, 'echec');
        } else {
            journal(planif.retrait_ok.replace(':fichier', '/etc/cron.d/' + fichier).replace(':machine', nom), 'ok', nom);
            dit(planif.retrait_ok.replace(':fichier', libelle).replace(':machine', nom), 'ok');
            // Retirer la planification actuelle efface aussi sa date en base.
            if (fichier === 'auto_security_update_advanced') await relit(filtresCourants());
        }
        // L'etat affiche est celui que la MACHINE rend, relu apres le geste.
        if (planifEnCours && planifEnCours.id === id) await lisPlanificationsMachine(id, nom);
    }

    async function enregistrePlanification() {
        if (!planifEnCours) return;
        const d = champDate.value;
        const h = champHeure.value;
        if (!d || !h) { dit(planif.sched_incomplet, 'echec'); return; }

        const nom = planifEnCours.nom;
        const attendu = calculeCron(d, h, champRecurrence.value);
        const chemin = '/schedule_advanced_security_update';

        const initial = boutonEnregistrer.textContent;
        boutonEnregistrer.disabled = true;
        boutonEnregistrer.textContent = planif.sched_en_cours;
        dit(planif.sched_en_cours);

        const res = await appelle(chemin, {
            method: 'POST',
            body: JSON.stringify({
                machine_id: planifEnCours.id,
                date: d,
                time: h,
                repeat: champRecurrence.value,
            }),
        });

        boutonEnregistrer.disabled = false;
        boutonEnregistrer.textContent = initial;

        const c = res.corps;
        if (!res.ok || !c || c.success === false) {
            // UNE ERREUR NE S'AVALE PAS : le formulaire reste ouvert, avec ce
            // qui a ete saisi, et la machine est nommee.
            journal((c && c.message) || planif.sched_err, 'error', nom);
            dit((c && c.message) || planif.sched_err, 'echec');
            return;
        }

        journal(planif.sched_pose.replace(':cron', attendu.cron), 'ok', nom);
        if (attendu.reserve) journal(attendu.reserve, 'info', nom);

        fermePlanification();

        // La planification de securite ecrit AUSSI `machines.maj_secu_date` :
        // relire le parc plutot que d'ecrire la cellule nous-memes, pour que la
        // colonne montre ce que la BASE contient.
        await relit(filtresCourants());

        dit(planif.sched_ok.replace(':machine', nom), 'ok');
    }

    champDate.addEventListener('change', montreApercu);
    champHeure.addEventListener('change', montreApercu);
    champRecurrence.addEventListener('change', montreApercu);
    document.getElementById('sched-cancel').addEventListener('click', fermePlanification);
    boutonEnregistrer.addEventListener('click', enregistrePlanification);

    /* ═════════════════════════════════════════════════════════════════════
       Sous-lot U5 — le redemarrage

       CE QUE FAIT LA ROUTE, LU DANS `backend/routes/monitoring.py` AVANT DE
       CLIQUER. `/reboot_server` est la SEULE route mutante du module a exiger
       un role (`@require_role(2)`), et elle passe DEUX gardes avant toute
       session SSH :

         1. la fenetre de maintenance (`maintenance.is_allowed`) -> 423 dehors ;
         2. l'approbation a quatre yeux (`approvals.gate`) -> 202 avec
            `pending_approval` et l'identifiant de la demande.

       La porte ne laisse passer que dans trois cas : l'action n'est pas soumise
       a approbation, le demandeur est SUPERADMIN (role 3, contournement
       journalise), ou une demande DEJA APPROUVEE existe — elle est alors
       consommee et le redemarrage part. C'est ce troisieme cas qui a envoye
       deux redemarrages reels sur la machine 2 le 2026-08-18.

       Ensuite seulement : `systemctl reboot` si le delai vaut 0, sinon
       `shutdown -r +N` avec un message diffuse aux sessions ouvertes.

       CE QUE LE PORTAGE CHANGE (voir PARITE.md, E-20 et E-21) :
       - la decision se prend EN LIGNE et le bouton naît DESACTIVE ; le legacy
         empile deux `confirm()` natifs qui posent deux fois la meme question ;
       - le delai est OFFERT : le backend accepte 0 a 1440 minutes, le legacy
         envoie toujours 0 ;
       - une demande d'approbation creee est annoncee pour ce qu'elle est, et
         non comme une erreur.
       ═════════════════════════════════════════════════════════════════════ */

    const boutonRedemarrer = document.getElementById('reboot-btn');
    const panneauRedemarrage = document.getElementById('reboot-panneau');
    const listeMachines = document.getElementById('reboot-machines');
    const champNombre = document.getElementById('reboot-nombre');
    const consigneNombre = document.getElementById('reboot-consigne');
    const champDelai = document.getElementById('reboot-delai');
    const boutonConfirmer = document.getElementById('reboot-confirmer');

    /** Machines retenues au moment de l'ouverture du panneau. */
    let redemarrageEnCours = null;

    function ouvreRedemarrage() {
        const choix = machinesCochees();
        if (!choix.length) {
            dit(libelles.aucune_selection, 'echec');
            return;
        }
        redemarrageEnCours = choix;

        listeMachines.textContent = libelles.reboot_machines
            .replace(':nombre', choix.length)
            .replace(':machines', choix.map(m => m.nom).join(', '));
        consigneNombre.textContent = libelles.reboot_consigne.replace(':nombre', choix.length);

        champNombre.value = '';
        // Le delai aussi : c'est le seul champ des quatre panneaux qui restait
        // en place. Le geste delibere porte sur le NOMBRE, donc personne ne
        // relit un delai qu'il n'a pas touche — celui choisi pour une machine
        // repartait avec la suivante, et `shutdown -r +60` prenait la place du
        // redemarrage immediat attendu.
        champDelai.selectedIndex = 0;
        boutonConfirmer.disabled = true;
        fermeLesAutresPanneaux('reboot-panneau');
        panneauRedemarrage.hidden = false;
        panneauRedemarrage.scrollIntoView({ block: 'nearest' });
        champNombre.focus();
    }

    function fermeRedemarrage() {
        redemarrageEnCours = null;
        panneauRedemarrage.hidden = true;
    }

    /*
     * Le bouton ne s'active que si le nombre de machines est RECOPIE. Deux « OK »
     * d'affilee sont un reflexe ; recopier un nombre est un geste.
     */
    function verifieConsigne() {
        const attendu = redemarrageEnCours ? String(redemarrageEnCours.length) : '';
        boutonConfirmer.disabled = champNombre.value.trim() !== attendu;
    }

    async function confirmeRedemarrage() {
        if (!redemarrageEnCours) return;
        const choix = redemarrageEnCours;
        const delai = parseInt(champDelai.value, 10) || 0;

        boutonConfirmer.disabled = true;
        const initial = boutonConfirmer.textContent;
        boutonConfirmer.textContent = libelles.reboot_en_cours;
        dit(libelles.reboot_en_cours);

        let demandes = 0;
        let echecs = 0;

        for (const m of choix) {
            journal(libelles.reboot_demande.replace(':machine', m.nom), 'info', m.nom);

            const res = await appelle('/reboot_server', {
                method: 'POST',
                body: JSON.stringify({ machine_id: m.id, delay_minutes: delai }),
            });
            const c = res.corps;

            // 202 + `pending_approval` N'EST PAS UNE ERREUR : c'est le
            // fonctionnement normal de la regle des quatre yeux. Le legacy
            // l'affiche en rouge parce qu'il ne regarde que `success`.
            if (c && c.pending_approval) {
                demandes++;
                journal(libelles.reboot_attente.replace(':id', c.request_id), 'ok', m.nom);
                continue;
            }
            if (res.statut === 423) {
                echecs++;
                journal((c && c.message) || libelles.reboot_fenetre, 'error', m.nom);
                continue;
            }
            if (!res.ok || !c || c.success === false) {
                echecs++;
                journal((c && c.message) || libelles.reboot_err, 'error', m.nom);
                continue;
            }
            journal(c.message || libelles.reboot_envoye, 'ok', m.nom);
        }

        boutonConfirmer.textContent = initial;
        fermeRedemarrage();

        if (echecs) {
            dit(libelles.reboot_fin_partielle.replace(':nombre', echecs), 'echec');
        } else if (demandes) {
            dit(libelles.reboot_fin_attente.replace(':nombre', demandes), 'ok');
        } else {
            dit(libelles.reboot_fin.replace(':nombre', choix.length), 'ok');
        }
    }

    if (boutonRedemarrer) boutonRedemarrer.addEventListener('click', ouvreRedemarrage);
    champNombre.addEventListener('input', verifieConsigne);
    document.getElementById('reboot-annuler').addEventListener('click', fermeRedemarrage);
    boutonConfirmer.addEventListener('click', confirmeRedemarrage);

    /* ═════════════════════════════════════════════════════════════════════
       Sous-lot U6a — les deux actions qui DIFFUSENT leur sortie

       CE QUE FONT LES ROUTES, LU DANS `backend/routes/updates.py` AVANT DE
       CLIQUER.

       `/dry_run_update` : `apt-get update && apt-get upgrade --dry-run`.
       N'installe rien. Reecrit l'index local des paquets.

       `/security_updates` : `apt-get update && apt-get upgrade --with-new-pkgs
       --only-upgrade -y`. INSTALLE. Et, si elle trouve apt ou dpkg deja en
       cours, elle fait un `killall -9` puis SUPPRIME LES VERROUS avant de
       lancer `dpkg --configure -a`. Le libelle du legacy ne le dit nulle part ;
       le panneau de decision du portage le dit avant le geste.

       Les deux rendent `Response(generate(), 'text/plain')` : leur corps est un
       FLUX. C'est ce flux qui portait le mot de passe root jusqu'au correctif du
       2026-08-19 — d'ou le fait que la simulation soit restee au legacy
       jusqu'ici (PARITE.md, E-17).

       CE QUE LA MESURE DIT DU DIRECT : la passerelle relaie morceau par morceau
       (`RoutesBackend::EN_FLUX`), mais le backend livre son corps d'un seul
       tenant entre conteneurs. Aucune des deux interfaces n'affiche donc de
       progression ligne a ligne aujourd'hui. Le journal recoit tout a la fin.
       ═════════════════════════════════════════════════════════════════════ */

    const boutonSimuler = document.getElementById('dry-run-btn');
    const boutonSecurite = document.getElementById('security-update-btn');
    const panneauSecurite = document.getElementById('secu-panneau');
    const listeSecurite = document.getElementById('secu-machines');
    const champSecurite = document.getElementById('secu-confirmation');
    const consigneSecurite = document.getElementById('secu-consigne');
    const boutonSecuriteOk = document.getElementById('secu-confirmer');

    /** Machines retenues au moment de l'ouverture du panneau de securite. */
    let securiteEnCours = null;

    /**
     * Verse un flux `text/plain` dans le journal du serveur, ligne par ligne.
     *
     * Passe par la passerelle comme tout le reste ; `appelle()` ne convient pas
     * ici, car il tente de lire du JSON.
     */
    async function verseLeFlux(chemin, machine) {
        const reponse = await fetch(PASSERELLE + chemin, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': jetonCsrf(),
                'X-Requested-With': 'XMLHttpRequest',
            },
            credentials: 'same-origin',
            body: JSON.stringify({ machine_id: machine.id }),
        });

        if (!reponse.ok) {
            // 423 : hors fenetre de maintenance. Le backend le dit en JSON.
            // Noms distincts de `message()` (l'etat vide du tableau) et de
            // `corps` (le <tbody>) : deux declarations de plus haut que ce bloc
            // masquait sans le dire.
            let messageErreur = libelles.flux_err;
            try {
                const corpsJson = await reponse.json();
                if (corpsJson && corpsJson.message) messageErreur = corpsJson.message;
            } catch (e) { /* reponse non JSON */ }
            journal(messageErreur, 'error', machine.nom);
            return false;
        }

        const lecteur = reponse.body.getReader();
        const decodeur = new TextDecoder();
        let reste = '';

        // Les lignes sont ecrites au fur et a mesure de leur ARRIVEE. Si le
        // backend se met un jour a livrer progressivement, l'affichage suivra
        // sans qu'il y ait rien a changer ici.
        for (;;) {
            const { done, value } = await lecteur.read();
            if (done) break;
            reste += decodeur.decode(value, { stream: true });
            const lignes = reste.split('\n');
            reste = lignes.pop();
            for (const ligne of lignes) {
                const propre = ligne.replace(/\r$/, '');
                if (propre.trim()) journal(propre, 'info', machine.nom);
            }
        }
        if (reste.trim()) journal(reste.replace(/\r$/, ''), 'info', machine.nom);
        return true;
    }

    /** Enchaine un flux sur chaque machine retenue, en serie. */
    async function surChaqueMachine(bouton, chemin, choix, libelleEnCours, libelleFin, executeUne) {
        // Sans quatrieme forme, on deverse un FLUX — le comportement de U6a.
        const executeSurUne = executeUne || verseLeFlux;
        const initial = bouton.textContent;
        bouton.disabled = true;
        bouton.textContent = libelleEnCours;
        dit(libelleEnCours);

        let echecs = 0;
        for (const m of choix) {
            journal(libelles.flux_debut.replace(':machine', m.nom), 'info', m.nom);
            let ok = false;
            try {
                ok = await executeSurUne(chemin, m);
            } catch (e) {
                journal(libelles.flux_err, 'error', m.nom);
            }
            if (!ok) echecs++;
            else journal(libelles.flux_fini, 'ok', m.nom);
        }

        bouton.disabled = false;
        bouton.textContent = initial;
        dit(echecs
            ? libelles.flux_fin_partielle.replace(':nombre', echecs)
            : libelleFin.replace(':nombre', choix.length),
            echecs ? 'echec' : 'ok');
    }

    async function simule() {
        const choix = machinesCochees();
        if (!choix.length) { dit(libelles.aucune_selection, 'echec'); return; }
        await surChaqueMachine(boutonSimuler, '/dry_run_update', choix,
            libelles.simulation_en_cours, libelles.simulation_fin);
    }

    function ouvreSecurite() {
        const choix = machinesCochees();
        if (!choix.length) { dit(libelles.aucune_selection, 'echec'); return; }
        securiteEnCours = choix;

        listeSecurite.textContent = libelles.secu_machines
            .replace(':nombre', choix.length)
            .replace(':machines', choix.map(m => m.nom).join(', '));
        consigneSecurite.textContent = libelles.secu_consigne;

        champSecurite.value = '';
        boutonSecuriteOk.disabled = true;
        fermeLesAutresPanneaux('secu-panneau');
        panneauSecurite.hidden = false;
        panneauSecurite.scrollIntoView({ block: 'nearest' });
        champSecurite.focus();
    }

    function fermeSecurite() {
        securiteEnCours = null;
        panneauSecurite.hidden = true;
    }

    /*
     * Recopier le mot demande. Une mise a jour de securite installe des paquets
     * et peut tuer un apt en cours : le geste doit differer d'un simple clic.
     */
    function verifieConsigneSecurite() {
        boutonSecuriteOk.disabled =
            champSecurite.value.trim().toUpperCase() !== libelles.secu_mot.toUpperCase();
    }

    async function confirmeSecurite() {
        if (!securiteEnCours) return;
        const choix = securiteEnCours;
        fermeSecurite();
        await surChaqueMachine(boutonSecurite, '/security_updates', choix,
            libelles.secu_en_cours, libelles.secu_fin);
        // La date de derniere execution a pu changer en base.
        await relit(filtresCourants());
    }

    if (boutonSimuler) boutonSimuler.addEventListener('click', simule);
    if (boutonSecurite) boutonSecurite.addEventListener('click', ouvreSecurite);
    champSecurite.addEventListener('input', verifieConsigneSecurite);
    document.getElementById('secu-annuler').addEventListener('click', fermeSecurite);
    boutonSecuriteOk.addEventListener('click', confirmeSecurite);

    /* ═════════════════════════════════════════════════════════════════════
       Sous-lot U6b — la mise a jour complete et la reparation dpkg

       CE QUE FONT LES ROUTES, LU AVANT DE CLIQUER.

       `/update` (backend/routes/updates.py) : consulte la fenetre de
       maintenance (423 dehors), puis, si apt ou dpkg tourne deja, les TUE
       (`killall -9`), supprime leurs quatre verrous et lance
       `dpkg --configure -a` — avant seulement de diffuser
       `apt update && apt full-upgrade -y`. C'est un FLUX `text/plain`.

       `/dpkg_repair` : `killall -9 apt apt-get dpkg`, `rm -f` sur les quatre
       verrous, puis `dpkg --configure -a`. Rend du JSON avec `output`.
       Elle ne consulte NI la fenetre de maintenance, NI l'approbation, et
       n'ecrit AUCUNE trace bastion — c'est l'action la plus destructive du
       module et la moins tracee. Constat porte dans MODULE-UPDATE.md.

       CE QUI N'EST PAS PORTE, ET POURQUOI. `/apt_update` et `/custom_update`
       existent cote backend mais AUCUN bouton du legacy ne les appelle :
       `aptUpdate()` et `customUpdate()` n'ont pas d'appelant et lisent cinq
       elements de formulaire absents de la page. Les porter reviendrait a
       inventer une capacite, pas a en migrer une. Voir PARITE.md, E-22.
       ═════════════════════════════════════════════════════════════════════ */

    const boutonComplete = document.getElementById('full-update-btn');
    const boutonDpkg = document.getElementById('dpkg-repair-btn');
    const panneauAction = document.getElementById('action-panneau');
    const titreAction = document.getElementById('action-titre');
    const machinesAction = document.getElementById('action-machines');
    const consequencesAction = document.getElementById('action-consequences');
    const reserveAction = document.getElementById('action-reserve');
    const consigneAction = document.getElementById('action-consigne');
    const champAction = document.getElementById('action-confirmation');
    const boutonActionOk = document.getElementById('action-confirmer');

    /** Machines retenues et reglage de l'action en cours de decision. */
    let actionEnCours = null;

    /**
     * Les deux actions de U6b, decrites plutot que codees deux fois.
     *
     * `mode` dit comment la reponse se lit : un FLUX se deverse ligne a ligne
     * dans le journal, un JSON s'y depose d'un bloc.
     */
    const ACTIONS = {
        complete: {
            bouton: () => boutonComplete,
            chemin: '/update',
            mode: 'flux',
            titre: () => libelles.complete_titre,
            consequences: () => libelles.complete_consequences,
            reserve: () => libelles.complete_reserve,
            mot: () => libelles.complete_mot,
            consigne: () => libelles.complete_consigne,
            libelleBouton: () => libelles.complete_bouton,
            enCours: () => libelles.complete_en_cours,
            fin: () => libelles.complete_fin,
        },
        dpkg: {
            bouton: () => boutonDpkg,
            chemin: '/dpkg_repair',
            mode: 'json',
            titre: () => libelles.dpkg_titre,
            consequences: () => libelles.dpkg_consequences,
            reserve: () => libelles.dpkg_reserve,
            mot: () => libelles.dpkg_mot,
            consigne: () => libelles.dpkg_consigne,
            libelleBouton: () => libelles.dpkg_bouton,
            enCours: () => libelles.dpkg_en_cours,
            fin: () => libelles.dpkg_fin,
        },
    };

    /** Verse une reponse JSON dans le journal du serveur. */
    async function verseLeJson(chemin, machine) {
        const res = await appelle(chemin, {
            method: 'POST',
            body: JSON.stringify({ machine_id: machine.id }),
        });
        const c = res.corps;

        if (!res.ok || !c || c.success === false) {
            journal((c && c.message) || libelles.dpkg_err, 'error', machine.nom);
            return false;
        }
        if (c.message) journal(c.message, 'ok', machine.nom);
        // `/dpkg_repair` rend la sortie de `dpkg --configure -a` dans `output`.
        for (const ligne of String(c.output || '').split('\n')) {
            const propre = ligne.replace(/\r$/, '');
            if (propre.trim()) journal(propre, 'info', machine.nom);
        }
        return true;
    }

    function ouvreAction(nom) {
        const reglage = ACTIONS[nom];
        const choix = machinesCochees();
        if (!choix.length) {
            dit(libelles.aucune_selection, 'echec');
            return;
        }
        actionEnCours = { choix: choix, reglage: reglage };

        titreAction.textContent = reglage.titre();
        machinesAction.textContent = libelles.action_machines
            .replace(':nombre', choix.length)
            .replace(':machines', choix.map(m => m.nom).join(', '));
        consequencesAction.textContent = reglage.consequences();
        reserveAction.textContent = reglage.reserve();
        consigneAction.textContent = reglage.consigne();
        boutonActionOk.textContent = reglage.libelleBouton();

        champAction.value = '';
        boutonActionOk.disabled = true;
        fermeLesAutresPanneaux('action-panneau');
        panneauAction.hidden = false;
        panneauAction.scrollIntoView({ block: 'nearest' });
        champAction.focus();
    }

    function fermeAction() {
        actionEnCours = null;
        panneauAction.hidden = true;
    }

    function verifieConsigneAction() {
        const attendu = actionEnCours ? actionEnCours.reglage.mot() : null;
        boutonActionOk.disabled =
            !attendu || champAction.value.trim().toUpperCase() !== attendu.toUpperCase();
    }

    async function confirmeAction() {
        if (!actionEnCours) return;
        const { choix, reglage } = actionEnCours;
        fermeAction();
        await surChaqueMachine(reglage.bouton(), reglage.chemin, choix,
            reglage.enCours(), reglage.fin(),
            reglage.mode === 'json' ? verseLeJson : null);
    }

    if (boutonComplete) boutonComplete.addEventListener('click', () => ouvreAction('complete'));
    if (boutonDpkg) boutonDpkg.addEventListener('click', () => ouvreAction('dpkg'));
    if (champAction) champAction.addEventListener('input', verifieConsigneAction);
    if (panneauAction) {
        document.getElementById('action-annuler').addEventListener('click', fermeAction);
        boutonActionOk.addEventListener('click', confirmeAction);
    }

    corps.addEventListener('change', (e) => {
        if (e.target && e.target.name === 'selected_machines[]') compteSelection();
    });
    if (boutonPaquets) boutonPaquets.addEventListener('click', paquetsEnAttente);

    document.getElementById('filter-btn').addEventListener('click', () => relit(filtresCourants()));
    document.getElementById('refresh-list-btn').addEventListener('click', () => {
        document.getElementById('environment').value = '';
        document.getElementById('criticality').value = '';
        document.getElementById('network-type').value = '';
        const etiquette = document.getElementById('tag-filter');
        if (etiquette) etiquette.value = '';
        relit({});
    });

    // Premier rendu : les donnees sont deja la, aucun appel n'est necessaire.
    rend(parc, false);
    compteSelection();
})();
