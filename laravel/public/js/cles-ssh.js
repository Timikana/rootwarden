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
        const bouton = document.getElementById('deploy-btn');
        if (bouton) bouton.disabled = n === 0;
    }

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
