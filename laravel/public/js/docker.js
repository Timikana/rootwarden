/**
 * docker.js - Inventaire et veille Docker.
 *
 * Deux differences avec `legacy/docker/js/main.js`, et les deux sont des
 * corrections :
 *
 *   1. **UNE PANNE RESEAU SE VOIT.** Le legacy fait `await fetch(...)` sans
 *      `try` dans son `api()` : quand le backend est injoignable, le rejet
 *      remonte hors du gestionnaire de clic, le message d'erreur prevu n'est
 *      JAMAIS affiche, et l'exploitant clique sans rien voir se passer. Ici
 *      chaque appel est enveloppe et rend un echec explicite.
 *   2. **Le rendu passe par `textContent`**, jamais par une interpolation de
 *      chaine : les noms d'images et les changelogs git contiennent par nature
 *      des caracteres de balisage.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const L = JSON.parse(document.getElementById('docker-libelles').textContent);
    const corps = document.querySelector('[data-rw="docker-corps"]');
    const synthese = document.querySelector('[data-rw="docker-synthese"]');
    const message = document.querySelector('[data-rw="docker-message"]');

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    function annonce(texte, type) {
        message.textContent = texte;
        message.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
    }

    /**
     * Un appel a la passerelle. TOUT echec — reseau compris — rend un objet,
     * jamais une exception : c'est precisement ce que le legacy oublie.
     */
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

    function cellule(texte, classe) {
        const td = document.createElement('td');
        td.textContent = texte == null ? '' : String(texte);
        if (classe) td.className = classe;

        return td;
    }

    function pastilleImage(c) {
        const span = document.createElement('span');
        if (c.image_update) {
            span.className = 'rw-pastille rw-pastille--attente';
            span.textContent = L.update_available;
            span.title = L.update_hint;
        } else if (c.remote_digest) {
            span.className = 'rw-pastille rw-pastille--ok';
            span.textContent = L.up_to_date;
        } else {
            span.className = 'rw-pastille rw-pastille--neutre';
            span.textContent = L.unknown;
        }

        return span;
    }

    /** La cellule git : un bouton qui deplie le changelog, sans `innerHTML`. */
    function celluleGit(c, index) {
        const td = document.createElement('td');
        const retard = c.git_behind || 0;
        if (! retard) { td.textContent = '—'; return td; }

        const bouton = document.createElement('button');
        bouton.type = 'button';
        bouton.className = 'rw-bouton rw-bouton--discret rw-bouton--minuscule';
        bouton.textContent = String(L.commits_behind).replace(':n', retard) + ' ▾';
        bouton.setAttribute('data-rw', 'docker-git-' + index);
        td.appendChild(bouton);

        if (c.git_changelog) {
            const pre = document.createElement('pre');
            pre.className = 'rw-journal';
            pre.hidden = true;
            pre.textContent = c.git_changelog;
            td.appendChild(pre);
            bouton.addEventListener('click', () => pre.hidden = ! pre.hidden);
        }

        return td;
    }

    function rendSynthese(lignes) {
        const machines = new Set(lignes.map((r) => r.machine_id)).size;
        const majImage = lignes.filter((r) => r.image_update).length;
        const majGit = lignes.filter((r) => (r.git_behind || 0) > 0).length;
        synthese.textContent = '';
        [[lignes.length, L.sum_containers], [machines, L.sum_machines],
            [majImage, L.sum_img_updates], [majGit, L.sum_git_updates]]
            .forEach(([valeur, libelle]) => {
                const carte = document.createElement('div');
                carte.className = 'rw-tuile';
                const v = document.createElement('div');
                v.className = 'rw-tuile__valeur';
                v.textContent = String(valeur);
                const l = document.createElement('div');
                l.className = 'rw-tuile__texte';
                l.textContent = libelle;
                carte.append(v, l);
                synthese.appendChild(carte);
            });
    }

    function rend(lignes) {
        corps.textContent = '';
        if (! lignes.length) {
            const tr = document.createElement('tr');
            const td = cellule(L.empty, 'rw-vide');
            td.colSpan = 7;
            tr.appendChild(td);
            corps.appendChild(tr);

            return;
        }
        lignes.forEach((c, i) => {
            const tr = document.createElement('tr');
            const quand = c.checked_at ? new Date(c.checked_at).toLocaleString() : '—';
            tr.appendChild(cellule(c.machine_name));
            const conteneur = cellule(c.container_name);
            if (c.compose_project) {
                const p = document.createElement('div');
                p.className = 'rw-aide';
                p.textContent = c.compose_project;
                conteneur.appendChild(p);
            }
            tr.appendChild(conteneur);
            tr.appendChild(cellule(c.image));
            tr.appendChild(cellule(c.status || c.state || ''));
            const tdImage = document.createElement('td');
            tdImage.appendChild(pastilleImage(c));
            tr.appendChild(tdImage);
            tr.appendChild(celluleGit(c, i));
            tr.appendChild(cellule(quand, 'rw-aide'));
            corps.appendChild(tr);
        });
    }

    async function charge() {
        const r = await appelle('/docker/results');
        if (! r.ok || ! r.corps || ! r.corps.success) {
            annonce(r.reseau ? L.err_reseau : L.err_load, 'echec');
            rend([]);

            return;
        }
        const lignes = r.corps.containers || [];
        rendSynthese(lignes);
        rend(lignes);
    }

    async function scanUne(bouton) {
        const select = document.querySelector('[data-rw="docker-machine"]');
        const id = select ? select.value : '';
        if (! id) return;
        bouton.disabled = true;
        annonce(L.scanning);
        const r = await appelle('/docker/scan', {
            method: 'POST',
            body: JSON.stringify({ machine_id: parseInt(id, 10) }),
        });
        bouton.disabled = false;
        if (r.ok && r.corps && r.corps.success) {
            annonce(r.corps.docker ? L.scan_done : L.no_docker, 'ok');
            charge();

            return;
        }
        /* LE MESSAGE PARAIT MEME SI RIEN N'A REPONDU. C'est la correction. */
        annonce(r.reseau ? L.err_reseau : ((r.corps && r.corps.message) || L.err_scan), 'echec');
    }

    async function scanTout(bouton) {
        bouton.disabled = true;
        annonce(L.scanning_all);
        const r = await appelle('/docker/scan_all', { method: 'POST', body: '{}' });
        bouton.disabled = false;
        if (r.ok) {
            annonce(L.scan_all_done_simple, 'ok');
        } else {
            annonce(r.reseau ? L.err_reseau : L.err_scan, 'echec');
        }
        charge();
    }

    document.querySelector('[data-rw="docker-scan-un"]')
        .addEventListener('click', (e) => scanUne(e.currentTarget));
    document.querySelector('[data-rw="docker-scan-tout"]')
        .addEventListener('click', (e) => scanTout(e.currentTarget));
    charge();
})();
