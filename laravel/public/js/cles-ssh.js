/**
 * cles-ssh.js - Module `ssh/`, sous-lot K1 : filtres, selection, et la decision
 * qui precede un deploiement.
 *
 * TROIS PROPRIETES QUE LE LEGACY NE TIENT PAS.
 *
 *  1. **Le bouton de deploiement nait DESACTIVE** et ne s'active que quand au
 *     moins une machine est cochee. Le legacy l'offre toujours actif : un clic
 *     sans selection partait vers le backend pour rien.
 *  2. **Il ouvre une DECISION**, il n'agit pas. Cote legacy,
 *     `onclick="deploySSH()"` declenche trois routes en cascade, sans reprise de
 *     main et sans confirmation d'aucune sorte. Ce que cela engage, sur CHAQUE
 *     machine cochee et en root : `apt-get install sudo`, `useradd`,
 *     l'ECRASEMENT d'`authorized_keys`, une politique sudoers — et la REVOCATION
 *     des cles de tout compte ayant perdu son habilitation. `srv-zabbix` est en
 *     PRODUCTION et figure dans la liste.
 *  3. **Le nombre de machines cochees est ANNONCE.** Decider d'un geste de cette
 *     portee sans savoir sur combien de machines il porte n'a pas de sens.
 *
 * « Cocher le filtre » ne coche que ce qui est VISIBLE. Le filtrage masque les
 * lignes plutot que de les retirer : la selection d'une machine masquee doit donc
 * etre levee, sinon on deploierait sur une machine qu'on ne voit plus.
 */
(function () {
    'use strict';

    const L = lisJson('ssh-libelles') || {};

    function lisJson(id) {
        const noeud = document.getElementById(id);
        if (!noeud) return null;
        try { return JSON.parse(noeud.textContent); } catch { return null; }
    }

    const lignes = () => [...document.querySelectorAll('.machine-item')];
    const caseDe = (ligne) => ligne.querySelector('input[name="selected_machines[]"]');
    const visible = (ligne) => ligne.hidden !== true;

    function appliqueFiltres() {
        const tag = document.getElementById('filter-tag')?.value || '';
        const env = document.getElementById('filter-env')?.value || '';
        for (const ligne of lignes()) {
            const sesTags = (ligne.dataset.tags || '').split(',').filter(Boolean);
            const garde = (!tag || sesTags.includes(tag))
                && (!env || (ligne.dataset.env || '') === env);
            ligne.hidden = !garde;
            // UNE MACHINE MASQUEE NE RESTE PAS COCHEE : on ne deploie pas sur ce
            // qu'on ne voit plus. Le legacy laissait la coche en place.
            if (!garde) {
                const c = caseDe(ligne);
                if (c) c.checked = false;
            }
        }
        annonceSelection();
    }

    function coche(seulementVisibles, etat) {
        for (const ligne of lignes()) {
            if (seulementVisibles && !visible(ligne)) continue;
            const c = caseDe(ligne);
            if (c) c.checked = etat;
        }
        annonceSelection();
    }

    function selection() {
        return lignes()
            .filter((l) => visible(l) && caseDe(l)?.checked)
            .map((l) => ({
                id: caseDe(l).value,
                // Element DEDIE au nom : `.rw-liste-selection__nom` englobe aussi
                // la pastille d'environnement, et la decision affichait
                // « OpenCVE-Test-OnPrem DEV » comme s'il s'agissait du nom.
                nom: (l.querySelector('[data-rw="ssh-nom"]')?.textContent || '')
                    .replace(/\s+/g, ' ').trim(),
            }));
    }

    function annonceSelection() {
        const n = selection().length;
        const zone = document.getElementById('ssh-compte-selection');
        if (zone) {
            zone.textContent = n === 0
                ? (L.aucune_selection || '')
                : (L.selection || '{nombre}').replace('{nombre}', String(n));
        }
        for (const id of ['deploy-btn', 'verifier-btn']) {
            const b = document.getElementById(id);
            if (b) b.disabled = n === 0;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  LE CONSTAT AVANT DEPLOIEMENT (sous-lot K2)
    // ════════════════════════════════════════════════════════════════════════
    //
    // IL NE DECLENCHE RIEN D'AUTRE. Cote legacy, `preflight_check` et `deploy`
    // sont dans la meme chaine `fetch` : le deploiement part des que le constat
    // passe, sans reprise de main. Verifier exposait donc a ecrire sur toutes les
    // machines cochees. Ici le constat est un geste a part.
    //
    // LE STATUT EST LU D'ABORD. Le legacy fait `.then(r => r.json())` sans
    // regarder `resp.ok` : un refus non-JSON tombe dans un `.catch` qui affiche
    // « Erreur pre-flight » sans jamais dire lequel.

    function texte(parent, classe, contenu) {
        const p = document.createElement('p');
        p.className = classe;
        p.textContent = contenu;
        parent.appendChild(p);
        return p;
    }

    function listeNommee(parent, titre, noms, classe) {
        if (!noms || noms.length === 0) return;
        texte(parent, 'rw-aide rw-preflight__titre', titre);
        const ul = document.createElement('ul');
        ul.className = classe;
        for (const nom of noms) {
            const li = document.createElement('li');
            li.textContent = String(nom);
            ul.appendChild(li);
        }
        parent.appendChild(ul);
    }

    function rendUneMachine(r) {
        const bloc = document.createElement('article');
        // PAS `.rw-carte` : elle est plafonnee a 420 px, et le rapport restait
        // etroit sur une page de 1400. Vu a l'image, invisible a toute assertion.
        bloc.className = 'rw-preflight__machine';
        bloc.dataset.rw = 'preflight-machine-' + r.machine_id;

        const enTete = document.createElement('p');
        enTete.className = 'rw-preflight__entete';
        const etat = document.createElement('span');
        etat.className = 'rw-badge ' + (r.ssh_ok ? 'rw-badge--ok' : 'rw-badge--alerte');
        etat.textContent = r.ssh_ok ? 'OK' : 'FAIL';
        const nom = document.createElement('strong');
        nom.textContent = `${r.name || ''} (${r.ip || ''})`;
        enTete.append(etat, nom);
        bloc.appendChild(enTete);

        for (const e of r.errors || []) {
            texte(bloc, 'rw-annonce rw-annonce--echec', String(e));
        }
        // LE PREREQUIS MANQUANT MENE A L'ENDROIT OU ON LE CORRIGE. `adm/` n'etant
        // pas porte, le lien est explicitement inter-portails.
        if (r.scan_required) {
            const a = document.createElement('a');
            a.className = 'rw-lien';
            a.href = L.url_comptes_distants || '#';
            a.target = '_blank';
            a.rel = 'noopener';
            a.textContent = (L.lien_comptes_distants || '') + ' \u2197';
            bloc.appendChild(a);
        }

        if (r.os_version) texte(bloc, 'rw-aide', String(r.os_version));
        if (r.disk_free) texte(bloc, 'rw-aide', String(r.disk_free));

        if (Array.isArray(r.user_impact) && r.user_impact.length) {
            texte(bloc, 'rw-aide', (L.inventaire || '{nombre}')
                .replace('{nombre}', String(r.user_impact.length)));
        }
        listeNommee(bloc, L.a_creer || '', r.users_to_create, 'rw-preflight__liste');
        // CE QUI VA ETRE REVOQUE EST LA LIGNE LA PLUS IMPORTANTE DU MODULE : elle
        // se distingue, au lieu de se perdre au milieu d'une fenetre de texte.
        listeNommee(bloc, L.a_revoquer || '', r.users_revoked,
            'rw-preflight__liste rw-preflight__liste--danger');

        return bloc;
    }

    async function verifie() {
        const cibles = selection().map((m) => Number(m.id));
        if (cibles.length === 0) return;
        const zone = document.getElementById('preflight-rapport');
        const machines = document.getElementById('preflight-machines');
        const cles = document.getElementById('preflight-cles');
        const bouton = document.getElementById('verifier-btn');
        const repos = bouton ? bouton.textContent : '';
        if (bouton) { bouton.disabled = true; bouton.textContent = L.verif_en_cours || '…'; }
        if (machines) machines.replaceChildren();
        if (zone) zone.hidden = false;
        if (cles) cles.textContent = L.verif_en_cours || '';

        try {
            const rep = await fetch(L.url_preflight, {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ machines: cibles }),
            });
            // LE STATUT D'ABORD, et le message du corps s'il en porte un.
            if (!rep.ok) {
                const brut = await rep.text();
                let message = '';
                try { message = String(JSON.parse(brut).message || ''); } catch { message = ''; }
                if (cles) {
                    cles.textContent = message
                        || (L.verif_echec || '').replace('{statut}', String(rep.status));
                    cles.className = 'rw-annonce rw-annonce--echec';
                }
                return;
            }
            const d = await rep.json();
            const resultats = d.results || [];
            for (const r of resultats) machines?.appendChild(rendUneMachine(r));

            // ZERO COMPTE PORTEUR D'UNE CLE veut dire qu'un deploiement ne
            // deploierait RIEN. C'est la moitie utile du constat, et elle vaut
            // pour tout le parc — pas machine par machine.
            const n = Number(d.users_with_keys ?? 0);
            const bloquantes = resultats.filter((r) => (r.errors || []).length > 0).length;
            if (cles) {
                const morceaux = [
                    n === 0 ? (L.cles_aucune || '')
                        : (L.cles_nombre || '{nombre}').replace('{nombre}', String(n)),
                    bloquantes > 0
                        ? (L.verif_bloque || '{nombre}').replace('{nombre}', String(bloquantes))
                        : (L.verif_pret || ''),
                ].filter(Boolean);
                cles.textContent = morceaux.join(' — ');
                cles.className = (n === 0 || bloquantes > 0)
                    ? 'rw-annonce rw-annonce--echec' : 'rw-annonce rw-annonce--ok';
            }
        } catch (e) {
            if (cles) {
                cles.textContent = (L.verif_echec || '{statut}')
                    .replace('{statut}', String(e && e.message ? e.message : e));
                cles.className = 'rw-annonce rw-annonce--echec';
            }
        } finally {
            if (bouton) { bouton.disabled = selection().length === 0; bouton.textContent = repos; }
        }
    }

    document.getElementById('verifier-btn')?.addEventListener('click', verifie);

    document.getElementById('filter-tag')?.addEventListener('change', appliqueFiltres);
    document.getElementById('filter-env')?.addEventListener('change', appliqueFiltres);
    document.querySelector('[data-rw="ssh-cocher-filtre"]')
        ?.addEventListener('click', () => coche(true, true));
    document.querySelector('[data-rw="ssh-cocher-tout"]')
        ?.addEventListener('click', () => coche(false, true));
    document.querySelector('[data-rw="ssh-decocher-tout"]')
        ?.addEventListener('click', () => coche(false, false));
    for (const c of document.querySelectorAll('input[name="selected_machines[]"]')) {
        c.addEventListener('change', annonceSelection);
    }

    document.getElementById('deploy-btn')?.addEventListener('click', () => {
        const panneau = document.getElementById('deploy-panneau');
        const cibles = document.getElementById('deploy-cibles');
        // LES MACHINES SONT NOMMEES. « Confirmer ? » sans objet fait cliquer sans
        // savoir sur quoi le geste porte.
        if (cibles) cibles.textContent = selection().map((m) => m.nom).join(' · ');
        if (panneau) panneau.hidden = false;
    });
    document.querySelector('[data-rw="ssh-annuler"]')?.addEventListener('click', () => {
        const panneau = document.getElementById('deploy-panneau');
        if (panneau) panneau.hidden = true;
    });

    annonceSelection();
})();
