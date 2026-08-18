/**
 * taches.js - Centre de taches : historique de l'activite de fond.
 *
 * Rendu par `textContent`, jamais par interpolation.
 *
 * LA DIFFERENCE QUI COMPTE AVEC LE LEGACY : UNE ERREUR NE S'AVALE PAS.
 *
 * Le legacy n'ecrit le tableau que si l'appel a REUSSI ; sur echec il ne fait
 * rien, et les lignes precedentes restent affichees. Comme `/tasks/list?status=`
 * repond 500 pour TOUT statut (colonne `status` ambigue cote backend, voir
 * PARITE.md E-10), filtrer sur « Echec » laisse a l'ecran cent taches REUSSIES,
 * sans un mot. La page presente alors des donnees justes comme si elles
 * repondaient a une question qu'on n'a pas posee.
 *
 * Ici, un echec VIDE le tableau et le DIT. Montrer moins est preferable a
 * montrer faux.
 *
 * Chargements SEQUENCES : chaque appel porte un numero, seul le dernier ecrit.
 */
(function () {
    'use strict';

    const PASSERELLE = '/api/gateway';
    const PERIODE_MS = 5000;

    const corps = document.getElementById('task-tbody');
    const resume = document.getElementById('task-stats');
    const annonce = document.getElementById('task-annonce');
    const filtre = document.getElementById('task-filter');
    const auto = document.getElementById('task-autorefresh');
    const libelles = JSON.parse(document.getElementById('task-libelles').textContent);

    let dernierChargement = 0;
    let minuterie = null;

    const PASTILLE = {
        running: 'rw-pastille--info',
        success: 'rw-pastille--ok',
        error: 'rw-pastille--echec',
        pending: 'rw-pastille--attente',
    };
    const ETAT = {
        running: libelles.st_running,
        success: libelles.st_success,
        error: libelles.st_error,
        pending: libelles.st_pending,
    };

    async function appelle(chemin) {
        const r = await fetch(PASSERELLE + chemin, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin',
        });
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
        td.colSpan = 5;
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

    /** Duree lisible. Une tache en cours se mesure jusqu'a maintenant. */
    function duree(debut, fin) {
        if (!debut) return '—';
        const d = new Date(debut).getTime();
        const f = fin ? new Date(fin).getTime() : Date.now();
        const secondes = Math.max(0, Math.round((f - d) / 1000));
        if (secondes < 60) return secondes + 's';
        const m = Math.floor(secondes / 60);
        const r = secondes % 60;
        return m + 'm' + (r ? r + 's' : '');
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

    function rendResume(donnees) {
        const j = (donnees && donnees.last24h) || {};
        const enCours = donnees ? (donnees.running || 0) : 0;
        const reussies = j.success || 0;
        const echecs = j.error || 0;
        const total = (j.success || 0) + (j.error || 0) + (j.running || 0) + (j.pending || 0);

        resume.replaceChildren(
            tuile(enCours, libelles.sum_running_now, libelles.sum_running_aide, enCours ? 'ok' : null),
            tuile(reussies, libelles.sum_success_24h, libelles.sum_success_aide, reussies ? 'ok' : null),
            tuile(echecs, libelles.sum_error_24h, libelles.sum_error_aide, echecs ? 'alerte' : null),
            tuile(total, libelles.sum_total_24h, libelles.sum_total_aide),
        );
    }

    function cellule(texte, classe) {
        const td = document.createElement('td');
        if (classe) td.className = classe;
        td.textContent = texte;
        return td;
    }

    function rendTableau(taches, statutFiltre) {
        if (!taches.length) {
            if (statutFiltre) {
                const nom = ETAT[statutFiltre] || statutFiltre;
                message(libelles.empty_filtre.replace(':statut', nom), libelles.empty_filtre_aide);
            } else {
                message(libelles.empty, libelles.empty_aide);
            }
            return;
        }

        corps.replaceChildren();
        for (const t of taches) {
            const tr = document.createElement('tr');

            const tdEtat = document.createElement('td');
            const pastille = document.createElement('span');
            pastille.className = 'rw-pastille ' + (PASTILLE[t.status] || 'rw-pastille--attente');
            pastille.textContent = ETAT[t.status] || t.status || '—';
            tdEtat.appendChild(pastille);
            tr.appendChild(tdEtat);

            const tdType = document.createElement('td');
            const code = document.createElement('code');
            code.className = 'rw-code rw-code--fichier';
            code.textContent = t.task_type || '';
            tdType.appendChild(code);
            tr.appendChild(tdType);

            // Intitule, machine et detail : trois informations, trois lignes.
            const tdTache = document.createElement('td');
            const intitule = document.createElement('div');
            intitule.textContent = t.label || '';
            tdTache.appendChild(intitule);
            if (t.machine_name) {
                const m = document.createElement('div');
                m.className = 'rw-tableau__discret';
                m.textContent = t.machine_name;
                tdTache.appendChild(m);
            }
            if (t.detail) {
                const d = document.createElement('p');
                d.className = 'rw-detail-ecart';
                d.textContent = t.detail;
                tdTache.appendChild(d);
            }
            tr.appendChild(tdTache);

            tr.appendChild(cellule(
                t.started_at ? new Date(t.started_at).toLocaleString() : '—',
                'rw-tableau__discret'));
            tr.appendChild(cellule(duree(t.started_at, t.finished_at), 'rw-tableau__discret'));

            corps.appendChild(tr);
        }
    }

    function heure() {
        return new Date().toLocaleTimeString();
    }

    async function charge() {
        const numero = ++dernierChargement;
        const statut = filtre.value;
        const requete = '/tasks/list?limit=100' + (statut ? '&status=' + encodeURIComponent(statut) : '');

        const [liste, stats] = await Promise.all([appelle(requete), appelle('/tasks/stats')]);

        // Une reponse depassee n'ecrit pas : le filtre a change entre-temps.
        if (numero !== dernierChargement) return;

        if (liste.ok && liste.corps && liste.corps.success) {
            rendTableau(liste.corps.tasks || [], statut);
            dit(libelles.derniere_maj.replace(':heure', heure()));
        } else if (statut) {
            // L'echec vient du FILTRE. Vider et le dire : garder les lignes
            // precedentes les ferait passer pour le resultat du filtre.
            const nom = ETAT[statut] || statut;
            message(libelles.err_filtre.replace(':statut', nom));
            dit(libelles.err_filtre.replace(':statut', nom), 'echec');
        } else {
            message(libelles.err_load);
            dit(libelles.err_load, 'echec');
        }

        if (stats.ok && stats.corps && stats.corps.success) {
            rendResume(stats.corps);
        } else {
            resume.replaceChildren();
        }
    }

    function programme() {
        if (minuterie) { clearInterval(minuterie); minuterie = null; }
        if (auto.checked) minuterie = setInterval(charge, PERIODE_MS);
    }

    filtre.addEventListener('change', charge);
    auto.addEventListener('change', programme);

    charge();
    programme();
})();
