/**
 * derive-config.js - Detection de derive de configuration.
 *
 * Rendu par `textContent`, jamais par interpolation : le detail d'un ecart
 * vient de la base et cite des noms de fichiers et de comptes.
 *
 * DEUX DIFFERENCES VOULUES AVEC LE LEGACY :
 *
 * 1. Le detail de l'ecart est AFFICHE, pas cache dans une infobulle. C'est la
 *    seule information actionnable de la page — « Fail2ban installe mais
 *    arrete », « 3 politiques desirees, 1 deployee ». Une infobulle ne
 *    s'ouvre ni au doigt, ni au clavier, ni pour un lecteur d'ecran. Elle
 *    n'est montree que pour les categories EN ECART : une machine conforme
 *    n'a rien a lire.
 * 2. Les bulles fugaces (`toast`) sont remplacees par une region d'annonce
 *    persistante. Une bulle qui s'efface au bout de trois secondes n'informe
 *    personne d'un scan qui vient de modifier l'etat affiche.
 *
 * Chargements SEQUENCES : chaque appel porte un numero, seul le dernier ecrit.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const corps = document.getElementById('drift-tbody');
    const resume = document.getElementById('drift-summary');
    const annonce = document.getElementById('drift-annonce');
    const libelles = JSON.parse(document.getElementById('drift-libelles').textContent);

    let dernierChargement = 0;

    /** Classe de pastille par etat. Un etat inconnu reste neutre. */
    const PASTILLE = {
        ok: 'rw-pastille--ok',
        drift: 'rw-pastille--echec',
        unknown: 'rw-pastille--neutre',
    };
    const ETIQUETTE = {
        ok: libelles.status_ok,
        drift: libelles.status_drift,
        unknown: libelles.status_unknown,
    };

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
        td.colSpan = 6;
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

    /** Une cellule de categorie : la pastille, et le detail s'il y a un ecart. */
    function celluleCategorie(categorie) {
        const td = document.createElement('td');

        if (!categorie) {
            const vide = document.createElement('span');
            vide.className = 'rw-pastille rw-pastille--neutre';
            vide.textContent = libelles.status_absent;
            td.appendChild(vide);
            return td;
        }

        const pastille = document.createElement('span');
        pastille.className = 'rw-pastille ' + (PASTILLE[categorie.status] || 'rw-pastille--neutre');
        pastille.textContent = ETIQUETTE[categorie.status] || categorie.status;
        td.appendChild(pastille);

        // Le detail n'est montre que quand il y a quelque chose a faire.
        if (categorie.status !== 'ok' && categorie.detail) {
            const detail = document.createElement('p');
            detail.className = 'rw-detail-ecart';
            detail.textContent = categorie.detail;
            td.appendChild(detail);
        }
        return td;
    }

    function tuile(valeur, titre, aide, ton) {
        const div = document.createElement('div');
        div.className = 'rw-tuile';
        const v = document.createElement('div');
        v.className = 'rw-tuile__valeur' + (ton ? ' rw-tuile__valeur--' + ton : '');
        v.textContent = String(valeur);
        const t = document.createElement('div');
        t.className = 'rw-tuile__titre';
        t.textContent = titre;
        const a = document.createElement('p');
        a.className = 'rw-tuile__texte';
        a.textContent = aide;
        div.append(v, t, a);
        return div;
    }

    function rendResume(machines) {
        const total = machines.length;
        const enDerive = machines.filter(m => (m.drift_count || 0) > 0).length;
        const ecarts = machines.reduce((n, m) => n + (m.drift_count || 0), 0);
        const conformes = total - enDerive;

        resume.replaceChildren(
            tuile(total, libelles.sum_servers, libelles.sum_servers_aide),
            tuile(conformes, libelles.sum_clean, libelles.sum_clean_aide, conformes ? 'ok' : null),
            tuile(enDerive, libelles.sum_drifted, libelles.sum_drifted_aide, enDerive ? 'alerte' : null),
            tuile(ecarts, libelles.sum_findings, libelles.sum_findings_aide, ecarts ? 'alerte' : null),
        );
    }

    function rendTableau(machines) {
        if (!machines.length) {
            message(libelles.empty, libelles.empty_aide);
            return;
        }

        // Ce qui demande une action remonte en tete.
        machines.sort((a, b) => (b.drift_count || 0) - (a.drift_count || 0)
            || String(a.name || '').localeCompare(String(b.name || '')));

        corps.replaceChildren();
        for (const m of machines) {
            const tr = document.createElement('tr');

            const tdNom = document.createElement('td');
            tdNom.className = 'rw-tableau__fort';
            tdNom.textContent = m.name || ('#' + m.machine_id);
            tr.appendChild(tdNom);

            const cats = m.categories || {};
            tr.appendChild(celluleCategorie(cats.sudo));
            tr.appendChild(celluleCategorie(cats.sshd));
            tr.appendChild(celluleCategorie(cats.fail2ban));

            const tdQuand = document.createElement('td');
            tdQuand.className = 'rw-tableau__discret';
            tdQuand.textContent = m.checked_at
                ? new Date(m.checked_at).toLocaleString()
                : libelles.never;
            tr.appendChild(tdQuand);

            const tdAction = document.createElement('td');
            tdAction.className = 'rw-tableau__actions';
            const bouton = document.createElement('button');
            bouton.type = 'button';
            bouton.className = 'rw-bouton rw-bouton--discret';
            bouton.textContent = libelles.btn_rescan;
            bouton.title = libelles.tip_rescan;
            bouton.dataset.rw = 'rescan-' + m.machine_id;
            bouton.addEventListener('click', () => rescanne(m.machine_id, bouton));
            tdAction.appendChild(bouton);
            tr.appendChild(tdAction);

            corps.appendChild(tr);
        }
    }

    async function charge() {
        const numero = ++dernierChargement;
        const res = await appelle('/drift/results');

        // Une reponse depassee n'ecrit pas : un scan plus recent a ete lance.
        if (numero !== dernierChargement) return;

        if (!res.ok || !res.corps || !res.corps.success) {
            message(libelles.err_load);
            resume.replaceChildren();
            dit(libelles.err_load, 'echec');
            return;
        }
        const machines = res.corps.machines || [];
        rendResume(machines);
        rendTableau(machines);
    }

    async function rescanne(machineId, bouton) {
        const libelleInitial = bouton.textContent;
        bouton.disabled = true;
        bouton.textContent = libelles.scanning;
        dit(libelles.scanning);

        const res = await appelle('/drift/scan', {
            method: 'POST',
            body: JSON.stringify({ machine_id: machineId }),
        });

        bouton.disabled = false;
        bouton.textContent = libelleInitial;

        if (res.ok && res.corps && res.corps.success) {
            dit(libelles.scanned, 'ok');
        } else {
            dit((res.corps && res.corps.message) || libelles.err_scan, 'echec');
        }
        await charge();
    }

    async function scanneTout(bouton) {
        bouton.disabled = true;
        dit(libelles.scanning);

        const res = await appelle('/drift/scan_all', { method: 'POST', body: '{}' });

        bouton.disabled = false;

        if (res.ok && res.corps && res.corps.success) {
            dit(libelles.scan_done + ' (' + (res.corps.scanned || 0) + ')', 'ok');
        } else {
            dit((res.corps && res.corps.message) || libelles.err_scan, 'echec');
        }
        await charge();
    }

    const boutonTout = document.getElementById('scan-all-btn');
    if (boutonTout) boutonTout.addEventListener('click', () => scanneTout(boutonTout));

    charge();
})();
