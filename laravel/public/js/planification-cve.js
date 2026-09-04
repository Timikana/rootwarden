/**
 * planification-cve.js - Planification des scans CVE (sous-lot S4).
 *
 * CE FICHIER N'EST CHARGE QU'AU-DELA DU ROLE 2, parce que le gabarit ne le rend
 * que la. Cote legacy, `loadSchedules` est branche sur `DOMContentLoaded` pour
 * TOUS les roles (`js/main.js:991`) alors que son bloc vit sous `$role >= 2` : un
 * role 1 emet donc un `GET /cve_schedules` a chaque affichage de page, refuse en
 * 403 et avale en silence par un `if (!d.success) return;`. Ne pas charger le
 * script est la seule facon de ne pas emettre l'appel.
 *
 * AUCUNE CHAINE EN DUR. Les vingt-six libelles du script legacy echappaient a la
 * parite FR/EN ; ici tout vient de `#planif-libelles`, et les compteurs portent un
 * marqueur `{nombre}` que l'on remplace — on ne fabrique pas un pluriel par
 * concatenation.
 *
 * AUCUNE BOITE NATIVE. Le legacy demande `confirm('Supprimer cette planification ?')`
 * (`js/main.js:865`). Ici la confirmation s'ouvre EN LIGNE, sous la ligne
 * concernee : la boite native recouvre precisement ce sur quoi on decide, ne se
 * style pas, et bloque Puppeteer.
 *
 * TOUT EST RENDU PAR `textContent`.
 */
(function () {
    'use strict';

    const L = lisJson('planif-libelles') || {};
    if (!document.getElementById('schedules-list')) return;

    function lisJson(id) {
        const n = document.getElementById(id);
        if (!n) return null;
        try { return JSON.parse(n.textContent); } catch { return null; }
    }

    const el = (id) => document.getElementById(id);
    const t = (cle, nombre) => String(L[cle] || '').replace('{nombre}', String(nombre ?? ''));

    function cellule(texte, classe) {
        const td = document.createElement('td');
        if (classe) td.className = classe;
        td.textContent = texte;
        return td;
    }

    function dateLocale(valeur) {
        if (!valeur) return L.jamais || '';
        const d = new Date(String(valeur).replace(' ', 'T'));
        if (isNaN(d.getTime())) return String(valeur);
        return d.toLocaleString(L.langue || undefined);
    }

    /** La cible, en clair. */
    function cible(p) {
        if (p.target_type === 'tag') return (L.cible_tag || 'tag') + ' : ' + (p.target_value || '');
        if (p.target_type === 'machines') {
            let n = 0;
            try { n = (JSON.parse(p.target_value || '[]') || []).length; } catch { n = 0; }
            return t('selection', n);
        }
        return L.cible_all || '';
    }

    function message(texte, classe) {
        const zone = el('planif-message') || (() => {
            const p = document.createElement('p');
            p.id = 'planif-message';
            el('schedules-list').closest('.rw-tableau-cadre').before(p);
            return p;
        })();
        zone.className = classe || 'rw-aide';
        zone.textContent = texte;
    }

    // ── Rendu de la liste : UN seul generateur de lignes ─────────────────────
    async function charge() {
        let d;
        try {
            const rep = await fetch(L.url_planifs, { credentials: 'same-origin' });
            if (!rep.ok) throw new Error(String(rep.status));
            d = await rep.json();
        } catch {
            // ON LE DIT A L'ECRAN : le chargeur du legacy n'ecrit que dans la
            // console, si bien qu'une panne laisse la liste vide sans un mot.
            message(L.err_reseau || '', 'rw-annonce rw-annonce--echec');
            return;
        }
        rend(d.planifications || []);
    }

    function rend(liste) {
        const corps = el('schedules-list');
        corps.replaceChildren();

        const actives = liste.filter((p) => Number(p.enabled) === 1).length;
        const compteur = el('schedule-count');
        if (compteur) compteur.textContent = t('actives', actives);

        if (liste.length === 0) {
            const tr = document.createElement('tr');
            const td = cellule(L.aucune || '', 'rw-tableau__message');
            td.colSpan = 8;
            tr.appendChild(td);
            corps.appendChild(tr);
            return;
        }

        for (const p of liste) {
            const tr = document.createElement('tr');
            tr.appendChild(cellule(p.name || '', 'rw-tableau__fort'));
            tr.appendChild(cellule(p.cron_expression || ''));
            tr.appendChild(cellule(cible(p), 'rw-colonne-secondaire'));
            tr.appendChild(cellule(dateLocale(p.next_run)));
            tr.appendChild(cellule(dateLocale(p.last_run), 'rw-colonne-secondaire'));
            tr.appendChild(cellule(p.auteur || L.auteur_inconnu || '', 'rw-colonne-secondaire'));

            const tdEtat = document.createElement('td');
            const badge = document.createElement('span');
            const active = Number(p.enabled) === 1;
            badge.className = active ? 'rw-badge rw-badge--ok' : 'rw-badge';
            badge.textContent = active ? (L.etat_active || '') : (L.etat_suspendue || '');
            tdEtat.appendChild(badge);
            tr.appendChild(tdEtat);

            const tdActions = document.createElement('td');
            const bascule = document.createElement('button');
            bascule.type = 'button';
            bascule.className = 'rw-bouton rw-bouton--minuscule';
            bascule.dataset.rw = 'planif-basculer-' + p.id;
            bascule.textContent = active ? (L.suspendre || '') : (L.activer || '');
            bascule.addEventListener('click', () => bascule_(p.id, active ? 0 : 1));
            const supprimer = document.createElement('button');
            supprimer.type = 'button';
            supprimer.className = 'rw-bouton rw-bouton--minuscule rw-bouton--danger';
            supprimer.dataset.rw = 'planif-supprimer-' + p.id;
            supprimer.textContent = L.supprimer || '';
            supprimer.addEventListener('click', () => demandeSuppression(tr, p));
            tdActions.append(bascule, supprimer);
            tr.appendChild(tdActions);

            corps.appendChild(tr);
        }
    }

    /** La confirmation s'ouvre EN LIGNE, sous la ligne concernee. */
    function demandeSuppression(ligne, p) {
        if (ligne.nextElementSibling?.dataset?.rw === 'planif-confirmation') return;

        const tr = document.createElement('tr');
        tr.dataset.rw = 'planif-confirmation';
        const td = document.createElement('td');
        td.colSpan = 8;
        const panneau = document.createElement('div');
        panneau.className = 'rw-panneau-decision';
        const texte = document.createElement('p');
        texte.className = 'rw-panneau-decision__texte';
        texte.textContent = (L.confirmer_suppression || '') + ' — ' + (p.name || '');
        const actions = document.createElement('div');
        actions.className = 'rw-panneau-decision__actions';
        const annuler = document.createElement('button');
        annuler.type = 'button';
        annuler.className = 'rw-bouton rw-bouton--discret';
        annuler.dataset.rw = 'planif-annuler';
        annuler.textContent = L.confirmer_non || '';
        annuler.addEventListener('click', () => tr.remove());
        const confirmer = document.createElement('button');
        confirmer.type = 'button';
        confirmer.className = 'rw-bouton rw-bouton--danger';
        confirmer.dataset.rw = 'planif-confirmer';
        confirmer.textContent = L.confirmer_oui || '';
        confirmer.addEventListener('click', () => supprime(p.id));
        actions.append(annuler, confirmer);
        panneau.append(texte, actions);
        td.appendChild(panneau);
        tr.appendChild(td);
        ligne.after(tr);
    }

    async function envoie(methode, url, corps) {
        try {
            const rep = await fetch(url, {
                method: methode,
                credentials: 'same-origin',
                headers: corps ? { 'Content-Type': 'application/json' } : {},
                body: corps ? JSON.stringify(corps) : undefined,
            });
            const d = await rep.json().catch(() => ({}));
            return { ok: rep.ok, statut: rep.status, d };
        } catch {
            return { ok: false, statut: 0, d: {} };
        }
    }

    async function supprime(id) {
        const r = await envoie('DELETE', L.url_planifs + '/' + id);
        message(r.ok ? (L.supprimee || '') : (r.d.message || L.err_reseau || ''),
                r.ok ? 'rw-annonce rw-annonce--ok' : 'rw-annonce rw-annonce--echec');
        await charge();
    }

    async function bascule_(id, actif) {
        const r = await envoie('PUT', L.url_planifs + '/' + id, { enabled: actif });
        message(r.ok ? (L.modifiee || '') : (r.d.message || L.err_reseau || ''),
                r.ok ? 'rw-annonce rw-annonce--ok' : 'rw-annonce rw-annonce--echec');
        await charge();
    }

    /** Ce que le formulaire va envoyer. */
    function saisie() {
        // AUCUN REPLI. Cette ligne portait `|| 'all'`, et mon correctif d'E-387
        // l'avait laissee en place : le commentaire qui suivait annoncait « le
        // repli ne vaut plus tout le parc » a DEUX LIGNES d'un repli intact.
        //
        // Il etait inerte — `'all'` ne correspond ni a `tag:` ni a `multi`, donc
        // `type` restait vide et le serveur refusait — mais **inerte n'est pas
        // ferme** : il se reveillait au premier commit qui rebrancherait `brut`
        // sur `type`. Et un selecteur pourvu d'options ne rend jamais une valeur
        // vide, donc ce repli ne protegeait de rien.
        const brut = el('sched-target').value;
        let type = '';
        let valeur = '';
        if (brut.startsWith('tag:')) { type = 'tag'; valeur = brut.slice(4); }
        else if (brut === 'multi') {
            type = 'machines';
            valeur = JSON.stringify([...document.querySelectorAll('.sched-multi-cb')]
                .filter((c) => c.checked).map((c) => Number(c.value)));
        }
        return {
            name: el('sched-name').value,
            cron_expression: el('sched-cron').value,
            min_cvss: Number(el('sched-cvss').value),
            scan_source: el('sched-source').value,
            target_type: type,
            target_value: valeur,
        };
    }

    async function ajoute() {
        const r = await envoie('POST', L.url_planifs, saisie());
        if (r.ok) {
            el('sched-name').value = '';
            message(L.creee || '', 'rw-annonce rw-annonce--ok');
        } else {
            // Le service nomme le champ refuse : on l'affiche tel quel plutot
            // qu'un « Erreur » generique.
            message(r.d.message || L.err_reseau || '', 'rw-annonce rw-annonce--echec');
        }
        await charge();
        return r.ok;
    }

    // ── Apercu de la recurrence, au fil de la saisie ─────────────────────────
    let minuteur = null;
    let sequence = 0;
    async function apercu() {
        const expr = el('sched-cron').value.trim();
        const zone = el('cron-preview');
        if (!zone) return;
        if (expr === '') { zone.textContent = ''; return; }

        // Un jeton de sequence, pas seulement un debounce : le debounce limite les
        // departs, il n'annule pas la requete en vol, et une reponse tardive
        // ecraserait une plus recente.
        const mien = ++sequence;
        const r = await envoie('GET', L.url_apercu + '?expr=' + encodeURIComponent(expr));
        if (mien !== sequence) return;

        if (!r.ok || r.d.valide !== true) {
            zone.className = 'rw-aide rw-erreur';
            zone.textContent = L.apercu_invalide || '';
            return;
        }
        if (r.d.trop_frequent) {
            zone.className = 'rw-aide rw-erreur';
            zone.textContent = L.apercu_trop_frequent || '';
            return;
        }
        zone.className = 'rw-aide';
        zone.textContent = (L.apercu_titre || '') + ' : ' +
            (r.d.prochaines || []).map(dateLocale).join(' · ');
    }

    // ── Cablage ─────────────────────────────────────────────────────────────
    el('sched-cron')?.addEventListener('input', () => {
        clearTimeout(minuteur);
        minuteur = setTimeout(apercu, 300);
    });

    el('sched-target')?.addEventListener('change', () => {
        const multi = el('sched-target').value === 'multi';
        const liste = el('sched-multi-list');
        if (liste) liste.hidden = !multi;
        compteSelection();
    });

    function compteSelection() {
        const n = [...document.querySelectorAll('.sched-multi-cb')].filter((c) => c.checked).length;
        const zone = el('sched-multi-count');
        if (zone) zone.textContent = t('selection', n);
    }
    document.querySelectorAll('.sched-multi-cb').forEach((c) =>
        c.addEventListener('change', compteSelection));
    document.querySelector('[data-rw="planif-tout-cocher"]')?.addEventListener('click', () => {
        document.querySelectorAll('.sched-multi-cb').forEach((c) => { c.checked = true; });
        compteSelection();
    });
    document.querySelector('[data-rw="planif-tout-decocher"]')?.addEventListener('click', () => {
        document.querySelectorAll('.sched-multi-cb').forEach((c) => { c.checked = false; });
        compteSelection();
    });

    document.querySelector('[data-rw="planif-presets"]')?.addEventListener('click', () => {
        const m = el('cron-presets-modal');
        if (m) m.hidden = false;
    });
    document.querySelector('[data-rw="planif-presets-fermer"]')?.addEventListener('click', () => {
        const m = el('cron-presets-modal');
        if (m) m.hidden = true;
    });
    document.querySelectorAll('#cron-presets-modal [data-cron]').forEach((b) =>
        b.addEventListener('click', () => {
            el('sched-cron').value = b.dataset.cron;
            el('cron-presets-modal').hidden = true;
            apercu();
        }));

    document.querySelector('[data-rw="planif-ajouter"]')?.addEventListener('click', ajoute);

    // Le CONTRAT partage avec la caracterisation, qui vise les deux portails : le
    // legacy expose `addSchedule()` en global, on expose la meme porte.
    window.addSchedule = ajoute;

    compteSelection();
    charge();
    apercu();
})();
