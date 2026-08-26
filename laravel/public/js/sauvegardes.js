/**
 * sauvegardes.js - Sauvegardes de la base : liste, creation, controle, restauration.
 *
 * Rendu par `textContent`, jamais par interpolation.
 *
 * TROIS DIFFERENCES VOULUES AVEC LE LEGACY :
 *
 * 1. La confirmation de restauration n'est PLUS un `prompt()`. Le legacy
 *    demande le nom du fichier dans une boite native, compare APRES coup, et
 *    reproche l'erreur une fois commise. Ici, la confirmation s'ouvre sous la
 *    ligne et le bouton reste INACTIF tant que la saisie ne correspond pas :
 *    on ne peut pas se tromper, plutot qu'on se fait reprendre.
 * 2. Le resultat d'un controle est ecrit dans une region d'annonce durable, et
 *    non dans une bulle qui s'efface. Un controle d'integrite dont le verdict
 *    disparait au bout de trois secondes ne sert a rien.
 * 3. Le verdict dit ce qu'il couvre. Le backend ne rejoue AUCUNE instruction :
 *    il compare l'empreinte et compte les tables. « Lisible et intacte » est
 *    donc la formulation juste ; « test de restauration » ne l'etait pas.
 *
 * Chargements SEQUENCES : chaque appel porte un numero, seul le dernier ecrit.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const corps = document.getElementById('backup-tbody');
    const annonce = document.getElementById('backup-annonce');
    const libelles = JSON.parse(document.getElementById('backup-libelles').textContent);
    const estSuperadmin = JSON.parse(document.getElementById('backup-superadmin').textContent) === true;

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
        const r = await fetch(PASSERELLE + chemin, parametres);
        let corpsJson = null;
        try { corpsJson = await r.json(); } catch (e) { /* reponse non JSON */ }
        return { ok: r.ok, statut: r.status, corps: corpsJson };
    }

    function dit(texte, ton) {
        annonce.textContent = texte || '';
        annonce.className = 'rw-annonce' + (ton ? ' rw-annonce--' + ton : '');
    }

    function message(texte, aide) {
        corps.replaceChildren();
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 4;
        td.className = 'rw-tableau__message';
        const titre = document.createElement('div');
        titre.className = 'rw-tableau__message-titre';
        titre.textContent = texte;
        td.appendChild(titre);
        if (aide) {
            const p = document.createElement('p');
            p.className = 'rw-tableau__message-aide';
            p.textContent = aide;
            td.appendChild(p);
        }
        tr.appendChild(td);
        corps.appendChild(tr);
    }

    function cellule(texte, classe) {
        const td = document.createElement('td');
        if (classe) td.className = classe;
        td.textContent = texte;
        return td;
    }

    /**
     * Confirmation de restauration, EN LIGNE, sous la sauvegarde concernee.
     *
     * Le bouton de confirmation naît desactive et ne s'active que lorsque la
     * saisie egale EXACTEMENT le nom du fichier. Le legacy laissait confirmer
     * puis annoncait « le nom ne correspond pas » : le geste avait deja ete
     * fait, et rien n'empechait de recommencer distraitement.
     */
    function ouvreRestauration(tr, sauvegarde) {
        if (tr.nextElementSibling?.dataset.rw === 'restauration-panneau') return;

        const ligne = document.createElement('tr');
        ligne.dataset.rw = 'restauration-panneau';
        const td = document.createElement('td');
        td.colSpan = 4;
        // `.rw-panneau-decision` porte `display: flex`. Pose SUR le `<td>`, il
        // ecrase `display: table-cell` : la cellule sort du modele de tableau et
        // son `colspan` est IGNORE — le panneau s'arrete a la largeur de la
        // premiere colonne, le reste de la ligne restant blanc. Aucune
        // assertion DOM ne l'attrape : `colSpan` vaut bien 6, c'est le RENDU
        // qui ment. Vu a l'image sur un portage voisin le 2026-08-26.
        //
        // Le conteneur flex va donc DANS la cellule, jamais sur elle.
        const cadre = document.createElement('div');
        cadre.className = 'rw-panneau-decision';
        td.appendChild(cadre);

        const bloc = document.createElement('div');
        bloc.className = 'rw-panneau-decision__texte';
        const titre = document.createElement('strong');
        titre.textContent = libelles.restore_titre;
        const aide = document.createElement('p');
        aide.className = 'rw-aide';
        aide.textContent = libelles.restore_aide;
        bloc.append(titre, aide);

        const etiquette = document.createElement('label');
        etiquette.className = 'rw-etiquette-champ';
        etiquette.textContent = libelles.restore_nom;

        const champ = document.createElement('input');
        champ.type = 'text';
        champ.className = 'rw-saisie rw-saisie--compacte';
        champ.dataset.rw = 'restauration-nom';
        champ.placeholder = sauvegarde.filename;
        champ.autocomplete = 'off';
        etiquette.appendChild(champ);

        const actions = document.createElement('div');
        actions.className = 'rw-panneau-decision__actions';

        const annuler = document.createElement('button');
        annuler.type = 'button';
        annuler.className = 'rw-bouton rw-bouton--discret';
        annuler.dataset.rw = 'restauration-annuler';
        annuler.textContent = libelles.restore_annuler;
        annuler.addEventListener('click', () => ligne.remove());

        const confirmer = document.createElement('button');
        confirmer.type = 'button';
        confirmer.className = 'rw-bouton rw-bouton--danger';
        confirmer.dataset.rw = 'restauration-confirmer';
        confirmer.textContent = libelles.restore_confirmer;
        confirmer.disabled = true;
        confirmer.addEventListener('click', () => restaure(sauvegarde.filename, confirmer, ligne));

        // Le seul moyen d'activer : taper le nom exact.
        champ.addEventListener('input', () => {
            confirmer.disabled = champ.value !== sauvegarde.filename;
        });

        actions.append(annuler, confirmer);
        cadre.append(bloc, etiquette, actions);
        ligne.appendChild(td);
        tr.after(ligne);
        champ.focus();
    }

    function rend(sauvegardes) {
        if (!sauvegardes.length) {
            message(libelles.empty, libelles.empty_aide);
            return;
        }

        corps.replaceChildren();
        for (const b of sauvegardes) {
            const tr = document.createElement('tr');

            const tdNom = document.createElement('td');
            const code = document.createElement('code');
            code.className = 'rw-code rw-code--fichier';
            code.textContent = b.filename || '';
            tdNom.appendChild(code);
            tr.appendChild(tdNom);

            tr.appendChild(cellule((b.size_mb != null ? b.size_mb : '?') + ' MB'));
            tr.appendChild(cellule(
                b.created_at ? new Date(b.created_at).toLocaleString() : '—',
                'rw-tableau__discret'));

            const tdActions = document.createElement('td');
            tdActions.className = 'rw-tableau__actions';

            const controler = document.createElement('button');
            controler.type = 'button';
            controler.className = 'rw-bouton rw-bouton--discret';
            controler.textContent = libelles.verify;
            controler.title = libelles.tip_verify;
            controler.dataset.rw = 'controler';
            controler.addEventListener('click', () => controle(b.filename, controler));
            tdActions.appendChild(controler);

            // Le backend reserve la restauration au role 3. Ne pas proposer ce
            // qui sera refuse — la garde reste la sienne, pas celle du bouton.
            if (estSuperadmin) {
                const restaurer = document.createElement('button');
                restaurer.type = 'button';
                restaurer.className = 'rw-bouton rw-bouton--danger';
                restaurer.textContent = libelles.restore;
                restaurer.title = libelles.tip_restore;
                restaurer.dataset.rw = 'restaurer';
                restaurer.addEventListener('click', () => ouvreRestauration(tr, b));
                tdActions.appendChild(restaurer);
            }

            tr.appendChild(tdActions);
            corps.appendChild(tr);
        }
    }

    async function charge() {
        const numero = ++dernierChargement;
        const res = await appelle('/admin/backups');

        if (numero !== dernierChargement) return;

        if (!res.ok || !res.corps || !res.corps.success) {
            message(libelles.err_load);
            dit(libelles.err_load, 'echec');
            return;
        }
        rend(res.corps.backups || []);
    }

    async function cree(bouton) {
        bouton.disabled = true;
        dit(libelles.creating);

        const res = await appelle('/admin/backups', { method: 'POST', body: '{}' });

        bouton.disabled = false;
        if (res.ok && res.corps && res.corps.success) {
            dit(libelles.created, 'ok');
        } else {
            dit((res.corps && res.corps.message) || libelles.err_create, 'echec');
        }
        await charge();
    }

    async function controle(fichier, bouton) {
        bouton.disabled = true;
        dit(libelles.verifying);

        const res = await appelle('/admin/backups/verify', {
            method: 'POST',
            body: JSON.stringify({ filename: fichier }),
        });

        bouton.disabled = false;
        const c = res.corps || {};

        if (!res.ok || !c.success || !c.valid) {
            dit(`${libelles.verify_fail} — ${c.error || c.message || ''}`.trim(), 'echec');
            return;
        }

        // Le verdict dit ce qu'il couvre : empreinte, lisibilite, nombre de
        // tables. Il ne dit pas que la sauvegarde se reappliquera.
        const empreinte = c.sha_ok === true ? libelles.sha_ok
            : (c.has_sidecar ? libelles.sha_ko : libelles.sha_absente);
        dit(`${libelles.verify_ok} — ${c.tables} ${libelles.tables}, `
            + `${c.statements} ${libelles.instructions}, ${empreinte}`,
            c.sha_ok === false ? 'echec' : 'ok');
    }

    async function restaure(fichier, bouton, ligne) {
        bouton.disabled = true;
        dit(libelles.restoring);

        const res = await appelle('/admin/backups/restore', {
            method: 'POST',
            body: JSON.stringify({ filename: fichier }),
        });

        if (res.ok && res.corps && res.corps.success) {
            dit(`${libelles.restore_ok} (${res.corps.statements || 0} ${libelles.instructions})`, 'ok');
            ligne.remove();
        } else {
            dit((res.corps && res.corps.message) || libelles.err_restore, 'echec');
            bouton.disabled = false;
        }
        await charge();
    }

    const boutonCreer = document.getElementById('create-btn');
    if (boutonCreer) boutonCreer.addEventListener('click', () => cree(boutonCreer));

    charge();
})();
