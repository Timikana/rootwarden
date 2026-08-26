/**
 * maintenance.js - Fenetres de maintenance.
 *
 * Quatre differences avec `legacy/maintenance/js/main.js`, toutes des
 * corrections :
 *
 *   1. **AUCUNE BOITE NATIVE.** Le legacy supprime derriere un `confirm()` :
 *      cette boite recouvre la ligne sur laquelle on decide, ne se style pas, et
 *      BLOQUE Puppeteer. Ici la confirmation s'ouvre EN LIGNE.
 *   2. **Rendu par `textContent`**, jamais par interpolation.
 *   3. **Un echec RESEAU se voit** : chaque appel est enveloppe.
 *   4. **Le formulaire se cache par `hidden`**, pas par une classe : le projet a
 *      paye qu'une regle `display:` sur la classe rendait `hidden` sans effet.
 *
 * ══ LA CINQUIEME, ET LA PLUS IMPORTANTE : LE VERDICT N'EST PLUS RECALCULE ═══
 *
 * « Cette fenetre est-elle ouverte maintenant ? » etait calcule DEUX FOIS : ici
 * en JavaScript, et dans `backend/maintenance.py:_in_window` en Python. Le
 * premier jet de ce fichier faisait de meme, en promettant de « suivre le Python
 * pas a pas ».
 *
 * C'etait la mauvaise reponse, et la mesure du 2026-08-25 l'a montre : les deux
 * calculs ne lisent pas la MEME HORLOGE. Le navigateur est en CEST, le conteneur
 * qui applique la regle est en UTC — deux heures d'ecart. Une fenetre
 * 22:00 -> 06:00 etait annoncee « active » de 22:00 a 06:00 locales alors qu'elle
 * n'autorisait reellement que de 00:00 a 08:00 locales. Suivre le Python « pas a
 * pas » ne protege de rien quand ce n'est pas le pas qui differe, mais l'heure.
 *
 * `list_windows` rend donc desormais `active_now` par fenetre, calcule par
 * `_in_window` elle-meme, et `server_time`. Ce fichier ne fait plus que
 * l'AFFICHER. La regle n'est pas deplacee vers le navigateur : elle y est
 * annoncee, telle qu'elle sera appliquee.
 *
 * L'heure du serveur est montree a cote du tableau, sans quoi un exploitant
 * voyant « fermee » a 07:00 n'aurait aucun moyen de comprendre pourquoi.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const L = JSON.parse(document.getElementById('maint-libelles').textContent);
    const JOURS = [L.mon, L.tue, L.wed, L.thu, L.fri, L.sat, L.sun];
    const corps = document.querySelector('[data-rw="maint-corps"]');
    const formulaire = document.querySelector('[data-rw="maint-formulaire"]');
    const message = document.querySelector('[data-rw="maint-message"]');

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    function annonce(texte, type) {
        message.textContent = texte;
        message.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
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
        try {
            const r = await fetch(PASSERELLE + chemin, parametres);
            let json = null;
            try { json = await r.json(); } catch (e) { /* reponse non JSON */ }

            return { ok: r.ok, statut: r.status, corps: json };
        } catch (e) {
            return { ok: false, statut: 0, corps: null, reseau: true };
        }
    }

    function cellule(texte) {
        const td = document.createElement('td');
        td.textContent = texte == null ? '' : String(texte);

        return td;
    }

    function pastillesJours(csv) {
        const td = document.createElement('td');
        const set = String(csv || '').split(',').map((s) => parseInt(s, 10));
        JOURS.forEach((nom, i) => {
            const p = document.createElement('span');
            p.className = 'rw-pastille ' + (set.includes(i) ? 'rw-pastille--info' : 'rw-pastille--neutre');
            p.textContent = nom;
            td.appendChild(p);
        });

        return td;
    }

    function pastilleEtat(f) {
        const td = document.createElement('td');
        const p = document.createElement('span');
        if (! f.enabled) {
            p.className = 'rw-pastille rw-pastille--neutre';
            p.textContent = L.disabled;
        } else if (f.active_now) {
            p.className = 'rw-pastille rw-pastille--ok';
            p.textContent = L.active_now;
        } else {
            p.className = 'rw-pastille rw-pastille--attente';
            p.textContent = L.closed_now;
        }
        td.appendChild(p);

        return td;
    }

    /** La confirmation, EN LIGNE et sous la ligne concernee. */
    function ouvreConfirmation(tr, f) {
        if (tr.nextElementSibling?.dataset.rw === 'maint-panneau') return;

        const ligne = document.createElement('tr');
        ligne.dataset.rw = 'maint-panneau';
        const td = document.createElement('td');
        td.colSpan = 6;
        /*
         * LE CONTENEUR FLEX VA *DANS* LA CELLULE, JAMAIS SUR ELLE.
         *
         * `.rw-panneau-decision` porte `display: flex`. Pose sur un `<td>`, il
         * ecrase `display: table-cell` : la cellule SORT du modele de tableau et
         * son `colspan` est ignore — le panneau s'arretait au tiers de la largeur
         * sur un ecran large, le reste de la ligne restant blanc. Aucune
         * assertion DOM ne pouvait le voir, `colSpan` valant bien 6.
         *
         * Defaut vu a l'image sur `graylog/` le 2026-08-26, puis retrouve ici et
         * dans trois autres fichiers du portage. Voir PARITE E-139.
         */
        const cadre = document.createElement('div');
        cadre.className = 'rw-panneau-decision';

        const bloc = document.createElement('div');
        bloc.className = 'rw-panneau-decision__texte';
        const titre = document.createElement('strong');
        titre.textContent = L.confirm_titre;
        const aide = document.createElement('p');
        aide.className = 'rw-aide';
        aide.textContent = String(L.confirm_aide).replace(':name', f.name);
        bloc.append(titre, aide);

        const actions = document.createElement('div');
        actions.className = 'rw-panneau-decision__actions';

        const annuler = document.createElement('button');
        annuler.type = 'button';
        annuler.className = 'rw-bouton rw-bouton--discret';
        annuler.dataset.rw = 'maint-annuler-suppression';
        annuler.textContent = L.confirm_annuler;
        annuler.addEventListener('click', () => ligne.remove());

        const confirmer = document.createElement('button');
        confirmer.type = 'button';
        confirmer.className = 'rw-bouton rw-bouton--danger';
        confirmer.dataset.rw = 'maint-confirmer';
        confirmer.textContent = L.confirm_supprimer;
        confirmer.addEventListener('click', () => supprime(f, confirmer, ligne));

        actions.append(annuler, confirmer);
        cadre.append(bloc, actions);
        td.appendChild(cadre);
        ligne.appendChild(td);
        tr.after(ligne);
    }

    function rend(fenetres) {
        corps.textContent = '';
        if (! fenetres.length) {
            const tr = document.createElement('tr');
            const td = cellule(L.empty);
            td.colSpan = 6;
            td.className = 'rw-vide';
            tr.appendChild(td);
            corps.appendChild(tr);

            return;
        }
        fenetres.forEach((f) => {
            const tr = document.createElement('tr');
            tr.appendChild(cellule(f.name));
            tr.appendChild(cellule(f.scope === 'machine'
                ? (f.machine_name || ('#' + f.machine_id))
                : L.scope_global));
            tr.appendChild(pastillesJours(f.days));
            tr.appendChild(cellule(f.start_time + ' → ' + f.end_time));
            tr.appendChild(pastilleEtat(f));

            const td = document.createElement('td');
            const basculer = document.createElement('button');
            basculer.type = 'button';
            basculer.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
            basculer.dataset.rw = 'maint-basculer';
            basculer.textContent = f.enabled ? L.disable : L.enable;
            basculer.addEventListener('click', () => bascule(f, basculer));
            const supprimer = document.createElement('button');
            supprimer.type = 'button';
            supprimer.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
            supprimer.dataset.rw = 'maint-supprimer';
            supprimer.textContent = L.delete;
            supprimer.addEventListener('click', () => ouvreConfirmation(tr, f));
            td.append(basculer, supprimer);
            tr.appendChild(td);
            corps.appendChild(tr);
        });
    }

    async function charge() {
        const r = await appelle('/maintenance/windows');
        if (! r.ok || ! r.corps || ! r.corps.success) {
            annonce(r.reseau ? L.err_reseau : L.err_load, 'echec');
            rend([]);

            return;
        }
        rend(r.corps.windows || []);
        montreHorlogeServeur(r.corps.server_time, r.corps.server_offset);
        majEtatPortee(r.corps.windows || []);
    }

    /**
     * LA PASTILLE D'ENSEMBLE DOIT SUIVRE LES GESTES DE LA PAGE.
     *
     * Elle est rendue une premiere fois par le serveur, qui a compte — c'est ce
     * qui evite un affichage vide au chargement. Mais la page CREE, BASCULE et
     * SUPPRIME des fenetres : sans cette mise a jour, elle continue d'annoncer
     * l'etat d'avant. Defaut mesure le 2026-08-25 : apres avoir cree une fenetre
     * limitee a une machine, la pastille affichait encore « Aucune restriction ».
     *
     * Le calcul se fait sur la liste que le backend vient de rendre, et il ne
     * duplique aucune regle d'horaire : ce sont deux comptages sur `scope` et
     * `enabled`, exactement la condition du `WHERE` de `is_allowed`.
     */
    function majEtatPortee(fenetres) {
        const pastille = document.querySelector('[data-rw="maint-etat-flotte"]');
        if (! pastille) return;

        const globales = fenetres.filter((f) => f.enabled && f.scope === 'global').length;
        const machines = new Set(fenetres
            .filter((f) => f.enabled && f.scope === 'machine' && f.machine_id != null)
            .map((f) => f.machine_id)).size;

        let etat = 'libre';
        let libelle = L.etat_libre;
        if (globales > 0) {
            etat = 'flotte';
            libelle = L.etat_restreint;
        } else if (machines > 0) {
            etat = 'machines';
            libelle = pluriel(L.etat_machines, machines).replace(':n', String(machines));
        }

        pastille.setAttribute('data-rw-etat', etat);
        pastille.className = 'rw-pastille ' + (etat === 'libre' ? 'rw-pastille--ok' : 'rw-pastille--attente');
        pastille.textContent = libelle;
        pastille.title = (L.etat_detail || '')
            .replace(':n', String(fenetres.filter((f) => f.enabled).length))
            .replace(':g', String(globales));
    }

    /**
     * Les formes de pluriel de Laravel arrivent ici telles quelles, separees par
     * une barre : « :n machine restreinte|:n machines restreintes ». Le cadre
     * choisit d'habitude la branche cote PHP ; ce fichier n'a que la chaine, il
     * doit donc trancher lui-meme. Deux formes suffisent aux deux langues du
     * projet — une troisieme se lirait ici comme une absence de branche, pas
     * comme un silence.
     */
    function pluriel(forme, nombre) {
        const formes = String(forme || '').split('|');

        return formes.length > 1 && nombre !== 1 ? formes[1] : formes[0];
    }

    /**
     * NOMMER L'HORLOGE QUI DECIDE.
     *
     * Le verdict « active maintenant » vient du serveur. Si son horloge n'est pas
     * celle du navigateur — mesure du 2026-08-25 : UTC contre CEST — un
     * exploitant lisant « fermee » a 07:00 doit pouvoir voir POURQUOI, sans quoi
     * il conclura a une panne. On ne l'affiche que lorsque les deux diffèrent :
     * une information toujours presente cesse d'etre lue.
     */
    function montreHorlogeServeur(heure, decalage) {
        const cible = document.querySelector('[data-rw="maint-horloge"]');
        if (! cible) return;
        if (! heure) { cible.hidden = true; return; }
        const d = new Date();
        const local = String(d.getHours()).padStart(2, '0') + ':'
            + String(d.getMinutes()).padStart(2, '0');
        // Comparaison a la MINUTE, et une minute de tolerance : deux horloges
        // justes peuvent se croiser au changement de minute, et clignoter alors
        // ferait douter d'un ecart qui n'existe pas.
        const differe = Math.abs(enMinutesHM(local) - enMinutesHM(heure)) > 1;
        cible.textContent = L.horloge_serveur
            .replace(':heure', heure)
            .replace(':decalage', decalage || '');
        cible.hidden = ! differe;
    }

    function enMinutesHM(hhmm) {
        const p = String(hhmm || '0:0').split(':');

        return (Number(p[0]) * 60) + (Number(p[1]) || 0);
    }

    async function enregistre(bouton) {
        const nom = document.querySelector('[data-rw="maint-nom"]').value.trim();
        if (! nom) { annonce(L.err_name, 'echec'); return; }
        const portee = document.querySelector('[data-rw="maint-portee"]').value;
        const jours = Array.from(document.querySelectorAll('[data-rw="maint-jour"]'))
            .filter((c) => c.checked)
            .map((c) => parseInt(c.value, 10));
        if (! jours.length) { annonce(L.err_days, 'echec'); return; }

        bouton.disabled = true;
        const r = await appelle('/maintenance/windows', {
            method: 'POST',
            body: JSON.stringify({
                name: nom,
                scope: portee,
                machine_id: portee === 'machine'
                    ? parseInt(document.querySelector('[data-rw="maint-machine"]').value, 10)
                    : null,
                days: jours,
                start_time: document.querySelector('[data-rw="maint-debut"]').value,
                end_time: document.querySelector('[data-rw="maint-fin"]').value,
                enabled: document.querySelector('[data-rw="maint-activee"]').checked,
            }),
        });
        bouton.disabled = false;
        if (r.ok && r.corps && r.corps.success) {
            annonce(L.saved, 'ok');
            ferme();
            charge();

            return;
        }
        annonce(r.reseau ? L.err_reseau : ((r.corps && r.corps.message) || L.err_save), 'echec');
    }

    async function bascule(f, bouton) {
        bouton.disabled = true;
        const r = await appelle('/maintenance/windows/' + encodeURIComponent(f.id), {
            method: 'PUT',
            body: JSON.stringify({ enabled: ! f.enabled }),
        });
        bouton.disabled = false;
        if (r.ok && r.corps && r.corps.success) { charge(); return; }
        annonce(r.reseau ? L.err_reseau : L.err_save, 'echec');
    }

    async function supprime(f, bouton, ligne) {
        bouton.disabled = true;
        const r = await appelle('/maintenance/windows/' + encodeURIComponent(f.id),
            { method: 'DELETE' });
        bouton.disabled = false;
        ligne.remove();
        if (r.ok && r.corps && r.corps.success) {
            annonce(L.deleted, 'ok');
            charge();

            return;
        }
        annonce(r.reseau ? L.err_reseau : L.err_save, 'echec');
    }

    function ouvre() { formulaire.hidden = false; }
    function ferme() {
        formulaire.hidden = true;
        document.querySelector('[data-rw="maint-nom"]').value = '';
    }

    /** Le choix de machine n'a de sens que si la portee est `machine`. */
    function ajusteMachine() {
        const bloc = document.querySelector('[data-rw="maint-machine-bloc"]');
        bloc.hidden = document.querySelector('[data-rw="maint-portee"]').value !== 'machine';
    }

    document.querySelector('[data-rw="maint-nouvelle"]').addEventListener('click', ouvre);
    document.querySelector('[data-rw="maint-annuler"]').addEventListener('click', ferme);
    document.querySelector('[data-rw="maint-portee"]').addEventListener('change', ajusteMachine);
    document.querySelector('[data-rw="maint-enregistrer"]')
        .addEventListener('click', (e) => enregistre(e.currentTarget));
    ajusteMachine();
    charge();
})();
