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

        /*
         * ══ E-190 : TROIS ETATS PAR MACHINE, PAS DEUX ════════════════════
         *
         * `user_impact`, `users_to_create` et `users_revoked` sont poses dans un
         * `try` IMBRIQUE de `preflight_check` (`ssh.py:448-487`) dont l'`except`
         * journalise **sans rien ajouter a `result['errors']`** — et `ssh_ok`
         * vaut deja `True` a ce moment-la. Un audit d'inventaire qui leve rend
         * donc une machine SANS ces trois cles, sans erreur, badge OK.
         *
         * Cote ecran, `listeNommee` sort en silence sur un champ absent : la
         * liste « Acces qui seront REVOQUES » ne s'affichait pas, exactement
         * comme si elle etait VIDE. **Une machine dont l'inventaire n'a pas pu
         * etre lu se presentait donc comme verifiee et sans revocation a
         * prevoir** — juste avant le geste qui revoque.
         *
         * Le discriminant est la PRESENCE de la cle, pas sa longueur : `[]` veut
         * dire « audite, rien a revoquer », absent veut dire « pas audite ». Les
         * confondre est la faute meme d'E-183, deplacee vers l'ecran.
         *
         * Et les trois libelles du badge passent en i18n : `'OK'` et `'FAIL'`
         * etaient ecrits EN DUR dans ce script, donc hors parite FR/EN.
         */
        const inventaireLu = Object.prototype.hasOwnProperty.call(r, 'users_revoked');
        const partiel = r.ssh_ok && ! inventaireLu;

        const enTete = document.createElement('p');
        enTete.className = 'rw-preflight__entete';
        const etat = document.createElement('span');
        etat.className = 'rw-badge ' + (! r.ssh_ok
            ? 'rw-badge--alerte'
            : (partiel ? 'rw-badge--attention' : 'rw-badge--ok'));
        etat.textContent = ! r.ssh_ok
            ? (L.badge_echec || 'FAIL')
            : (partiel ? (L.badge_partiel || '') : (L.badge_ok || 'OK'));
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
        // UNE ABSENCE DE LISTE N'EST PAS UNE LISTE VIDE : on le dit, et on le dit
        // AVANT les listes, pour que leur absence soit deja expliquee quand on y
        // arrive.
        if (partiel) {
            texte(bloc, 'rw-annonce rw-annonce--attention', L.inventaire_non_lu || '');
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
            /*
             * ══ E-189 : UN STATUT 200 N'EST PAS UN VERDICT ═══════════════════
             *
             * Ce bloc lisait `d.results` apres le seul controle de `rep.ok`. Ce
             * n'est pas un defaut aujourd'hui, et c'est verifie plutot que
             * suppose : `preflight_check` n'a que TROIS retours — 400 « aucune
             * machine », 403 « acces refuse », et le chemin 200 qui rend
             * `success: True` **inconditionnellement** (`ssh.py:494`). Les deux
             * controles coincident donc.
             *
             * **Mais c'est la coincidence qui tient, et trois routes voisines
             * viennent de la rompre** : E-184 sur les sondes de version, E-186,
             * E-187 sur le scan des comptes distants. Chacune rendait toujours
             * `success: True` et peut desormais rendre `false` avec un statut
             * 200. Le jour ou celle-ci suit, cet ecran presenterait des
             * resultats PARTIELS comme une verification reussie — juste avant le
             * geste qui revoque des acces, et sur un ecran ou le bouton de
             * deploiement ne depend PAS du verdict de la verification.
             *
             * On ne rend donc rien du tout dans ce cas : un rapport a moitie
             * peuple se lit comme un rapport. Et on relaie le `message` du
             * serveur s'il en porte un — c'est lui qui sait ce qui a manque.
             *
             * `--attention` et non `--echec` : ne pas savoir n'est pas un echec
             * de la verification, c'est une absence de verdict.
             */
            if (! d || d.success !== true) {
                if (cles) {
                    cles.textContent = String(d && d.message ? d.message : (L.verif_non_concluante || ''));
                    cles.className = 'rw-annonce rw-annonce--attention';
                }

                return;
            }
            const resultats = d.results || [];
            for (const r of resultats) machines?.appendChild(rendUneMachine(r));

            // ZERO COMPTE PORTEUR D'UNE CLE veut dire qu'un deploiement ne
            // deploierait RIEN. C'est la moitie utile du constat, et elle vaut
            // pour tout le parc — pas machine par machine.
            const n = Number(d.users_with_keys ?? 0);
            const bloquantes = resultats.filter((r) => (r.errors || []).length > 0).length;
            /*
             * CE QUI SERA REVOQUE ENTRE DANS LA SYNTHESE.
             *
             * L'ecran calculait deja ces noms, machine par machine, et ne les
             * mettait pas dans la seule phrase d'ensemble qu'il met en avant —
             * celle qui est jointe par un tiret a « Aucun prerequis manquant ».
             * Un operateur qui lit les deux ensemble conclut qu'il ne risque
             * rien. Ils sont dedoublonnes : un meme compte peut etre revoque sur
             * plusieurs machines, et le compter deux fois exagererait.
             */
            const revoques = [...new Set(
                resultats.flatMap((r) => Array.isArray(r.users_revoked) ? r.users_revoked : []),
            )].sort();
            /*
             * UNE MACHINE SANS RESULTAT N'EST NI BLOQUANTE NI PRETE.
             * `resultats.length` n'etait jamais compare a ce qu'on avait coche :
             * une machine absente de la reponse disparaissait du constat sans que
             * rien ne le dise.
             */
            const sansResultat = cibles.length - resultats.length;
            if (cles) {
                const morceaux = [
                    n === 0 ? (L.cles_aucune || '')
                        : (L.cles_nombre || '{nombre}').replace('{nombre}', String(n)),
                    revoques.length > 0
                        ? (L.revoques_synthese || '')
                            .replace('{nombre}', String(revoques.length))
                            .replace('{noms}', revoques.join(', '))
                        : '',
                    sansResultat > 0
                        ? (L.machines_sans_resultat || '').replace('{nombre}', String(sansResultat))
                        : '',
                    bloquantes > 0
                        ? (L.verif_bloque || '{nombre}').replace('{nombre}', String(bloquantes))
                        : (L.verif_pret || ''),
                ].filter(Boolean);
                cles.textContent = morceaux.join(' — ');
                // Un parc ou quelque chose sera REVOQUE, ou dont une machine
                // n'a pas repondu, ne se peint pas en vert.
                cles.className = (n === 0 || bloquantes > 0)
                    ? 'rw-annonce rw-annonce--echec'
                    : ((revoques.length > 0 || sansResultat > 0)
                        ? 'rw-annonce rw-annonce--attention'
                        : 'rw-annonce rw-annonce--ok');
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

    // ════════════════════════════════════════════════════════════════════════
    //  LE JOURNAL DU DEPLOIEMENT (sous-lot K3)
    // ════════════════════════════════════════════════════════════════════════
    //
    // TROIS DEFAUTS DU LEGACY SONT FERMES ICI.
    //
    //  1. **`innerHTML +=` FAISAIT DE CHAQUE LIGNE UN FRAGMENT DE DOCUMENT.** Le
    //     commentaire du legacy pretend « pas de donnees utilisateur non
    //     maitrisees » ; c'est faux, `configure_servers.py:112` injecte
    //     `machines.name` dans CHAQUE ligne sans validation, et `:785` journalise
    //     verbatim les noms d'utilisateur refuses. Mesure : une balise posee dans
    //     le journal devient un ELEMENT sur le legacy. Ici tout passe par
    //     `textContent`.
    //  2. **UN `EventSource` NE PEUT PAS LIRE UN STATUT HTTP.** `GET /logs` est
    //     `@require_role(2)` ; pour un role 1 il rend 403, ce qui declenche
    //     `onerror` — ou le legacy ecrit « [Fin du flux] », rend le bouton et ne
    //     dit RIEN. On lit donc le flux par `fetch`, dont le statut est lisible,
    //     et un refus est ANNONCE.
    //  3. **LES DEUX CHEMINS LAISSAIENT LA PAGE DANS DES ETATS DIFFERENTS** : le
    //     succes remettait « Deployer les cles », l'erreur « Lancer le
    //     Deploiement ». Ici un seul chemin de sortie remet le bouton.
    //
    // LE MARQUEUR DE FIN EST UN JETON DE PROTOCOLE, PAS UN LIBELLE. Il vient du
    // backend en dur et se compare litteralement : le traduire ferait que le flux
    // ne se termine JAMAIS. Il est donc pose en constante cote controleur, hors
    // des fichiers de langue.

    function ajouteLigne(zone, texte, classe) {
        const ligne = document.createElement('div');
        if (classe) ligne.className = classe;
        // `textContent` et jamais `innerHTML` : le contenu vient d'un journal ou
        // le nom d'une machine est recopie sans validation.
        ligne.textContent = texte;
        zone.appendChild(ligne);
        zone.scrollTop = zone.scrollHeight;
    }

    async function ouvreJournal() {
        const zone = document.getElementById('journal-flux');
        const bouton = document.getElementById('journal-btn');
        if (!zone) return;
        const repos = bouton ? bouton.textContent : '';
        if (bouton) { bouton.disabled = true; bouton.textContent = L.journal_ouverture || '…'; }
        zone.hidden = false;
        zone.replaceChildren();

        let recues = 0;
        try {
            const rep = await fetch(L.url_journal, { credentials: 'same-origin' });
            // LE STATUT D'ABORD — c'est tout l'interet de ne pas utiliser
            // `EventSource`, qui ne permet pas de le lire.
            if (!rep.ok) {
                ajouteLigne(zone, (L.journal_refus || '{statut}')
                    .replace('{statut}', String(rep.status)), 'rw-journal__erreur');
                return;
            }
            const lecteur = rep.body.getReader();
            const decodeur = new TextDecoder();
            let tampon = '';
            let fini = false;
            while (!fini) {
                const { done, value } = await lecteur.read();
                if (done) break;
                tampon += decodeur.decode(value, { stream: true });
                const morceaux = tampon.split('\n');
                tampon = morceaux.pop();
                for (const m of morceaux) {
                    if (!m.startsWith('data: ')) continue;
                    const donnee = m.slice(6);
                    // LE MARQUEUR PILOTE, IL NE S'AFFICHE PAS.
                    if (donnee === L.marqueur_fin) {
                        ajouteLigne(zone, L.journal_fin || '', 'rw-journal__fin');
                        fini = true;
                        break;
                    }
                    ajouteLigne(zone, donnee);
                    recues += 1;
                }
            }
            try { await lecteur.cancel(); } catch { /* deja ferme */ }
            if (!fini) {
                // Un flux qui s'arrete sans son marqueur n'est pas un succes.
                ajouteLigne(zone, L.journal_interrompu || '', 'rw-journal__erreur');
            } else if (recues === 0) {
                ajouteLigne(zone, L.journal_vide || '');
            }
        } catch (e) {
            ajouteLigne(zone, (L.journal_refus || '{statut}')
                .replace('{statut}', String(e && e.message ? e.message : e)), 'rw-journal__erreur');
        } finally {
            // UN SEUL chemin de sortie remet le bouton, donc un seul etat final.
            if (bouton) { bouton.disabled = false; bouton.textContent = repos; }
        }
    }

    document.getElementById('journal-btn')?.addEventListener('click', ouvreJournal);

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
