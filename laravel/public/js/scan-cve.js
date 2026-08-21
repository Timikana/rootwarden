/**
 * scan-cve.js - Consultation des resultats CVE (module `security/`, sous-lot S3).
 *
 * UN SEUL GENERATEUR DE LIGNES, et c'est la raison d'etre de ce fichier.
 *
 * Le script du legacy en porte QUATRE — le rendu initial, la pagination, la
 * recherche et le filtre — dont TROIS oublient la sixieme colonne. Mesure sur la
 * machine reellement scannee :
 *
 *     apres chargement     50 lignes, toutes a 6 cellules
 *     apres « Voir plus » 100 lignes : 50 a 6 cellules ET 50 a 5
 *     apres une recherche   9 lignes, toutes a 5
 *     apres un filtre     100 lignes, toutes a 5
 *
 * Le meme tableau melangeait donc les deux formes, l'en-tete ne correspondait
 * plus aux lignes, et la colonne de suivi disparaissait — sans aucune erreur JS.
 * Ici tous les gestes passent par `rendu()`, qui appelle `ligne()` : il n'existe
 * pas d'endroit ou une colonne puisse manquer.
 *
 * L'EN-TETE, LE COMPTEUR ET LE BOUTON SONT RENDUS PAR LE GABARIT. Le script ne
 * remplit que le corps du tableau. Consequence directe : le compteur existe meme
 * en dessous de 50 CVE, alors que le legacy ne le cree que s'il y a une page
 * suivante — et sa recherche s'en servait quand meme, sans effet visible.
 *
 * TOUT EST RENDU PAR `textContent`. Le legacy assemble ses lignes par
 * interpolation dans `innerHTML`, et son `esc()` n'echappe pas l'apostrophe alors
 * que son docblock affirme empecher l'XSS. Rien n'est interpole ici.
 *
 * AUCUN APPEL RESEAU POUR AFFICHER : les findings arrivent en donnees dans la
 * page. Le seul appel est la comparaison de deux scans, faite au clic.
 */
(function () {
    'use strict';

    const donnees = lisJson('cve-findings') || {};
    const L = lisJson('cve-libelles') || {};
    /** Le suivi stocke, par machine puis par identifiant de CVE — sous-lot S5. */
    const SUIVI = lisJson('cve-suivi') || {};
    const S = lisJson('suivi-libelles') || {};
    const PAR_PAGE = 50;

    /** L'etat d'affichage de chaque machine. Une seule source. */
    const etats = {};

    function lisJson(id) {
        const noeud = document.getElementById(id);
        if (!noeud) return null;
        try { return JSON.parse(noeud.textContent); } catch { return null; }
    }

    function etat(mid) {
        if (!etats[mid]) etats[mid] = { severite: 'ALL', annee: 'ALL', recherche: '', page: 1 };
        return etats[mid];
    }

    /** Les findings retenus par les filtres courants. */
    function retenus(mid) {
        const e = etat(mid);
        const tout = donnees[mid] || [];
        const q = e.recherche.trim().toLowerCase();
        return tout.filter((f) => {
            // KEV partage la dimension des severites sans en etre une : compare
            // a `f.s`, la valeur « KEV » ne correspondrait a aucune ligne et le
            // filtre viderait le tableau en silence.
            if (e.severite === 'KEV') {
                if (!f.k) return false;
            } else if (e.severite !== 'ALL' && (f.s || 'NONE') !== e.severite) return false;
            if (e.annee !== 'ALL') {
                const an = /^CVE-(\d{4})-/.exec(f.c || '');
                if ((an ? an[1] : '?') !== e.annee) return false;
            }
            if (q && !(f.c || '').toLowerCase().includes(q)
                  && !(f.p || '').toLowerCase().includes(q)
                  && !(f.r || '').toLowerCase().includes(q)) return false;
            return true;
        });
    }

    /** La severite abregee, pour les ecrans ou le mot entier ne tient pas. */
    const ABREGE_SEVERITE = {
        CRITICAL: 'CRIT', HIGH: 'HIGH', MEDIUM: 'MED', LOW: 'LOW', NONE: '—',
    };

    const CLASSE_SEVERITE = {
        CRITICAL: 'rw-badge rw-badge--alerte',
        HIGH: 'rw-badge rw-badge--attention',
        MEDIUM: 'rw-badge',
        LOW: 'rw-badge',
        NONE: 'rw-badge',
    };

    function cellule(texte, classe) {
        const td = document.createElement('td');
        if (classe) td.className = classe;
        td.textContent = texte;
        return td;
    }

    /**
     * LA ligne. Six cellules, une seule fois, pour tous les gestes.
     * Rien n'est interpole : le lien recoit son texte et son adresse par
     * propriete, jamais par une chaine de HTML.
     */
    function ligne(f, mid) {
        const tr = document.createElement('tr');

        const tdCve = document.createElement('td');
        tdCve.className = 'rw-cve-id';
        const lien = document.createElement('a');
        lien.className = 'rw-lien';
        lien.href = 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(f.c || '');
        lien.target = '_blank';
        lien.rel = 'noopener';
        // Le prefixe « CVE- » s'efface quand la place manque : il est le meme sur
        // toutes les lignes, donc il n'apprend rien, et il coute 35 px par ligne.
        const brut = String(f.c || '');
        const coupe = /^CVE-(.+)$/.exec(brut);
        if (coupe) {
            const prefixe = document.createElement('span');
            prefixe.className = 'rw-cve-prefixe';
            prefixe.textContent = 'CVE-';
            lien.append(prefixe, document.createTextNode(coupe[1]));
        } else {
            lien.textContent = brut;
        }
        tdCve.appendChild(lien);
        tr.appendChild(tdCve);

        tr.appendChild(cellule(f.p || '', 'rw-tableau__fort'));
        tr.appendChild(cellule(f.v || '', 'rw-colonne-secondaire rw-cve-version'));

        // LA SEVERITE EST LA DONNEE QUI DECIDE : elle ne doit jamais etre coupee.
        // A 390 px, « CRITICAL 9.8 » se tronquait en « CR… ». Le mot entier et son
        // abreviation sont donc rendus tous les deux, et les deux classes
        // complementaires n'en montrent qu'un seul a la fois.
        const tdSev = document.createElement('td');
        tdSev.className = 'rw-cve-severite';
        const badge = document.createElement('span');
        const sev = f.s || 'NONE';
        badge.className = CLASSE_SEVERITE[sev] || CLASSE_SEVERITE.NONE;
        const large = document.createElement('span');
        large.className = 'rw-colonne-secondaire';
        large.textContent = sev;
        const etroit = document.createElement('span');
        etroit.className = 'rw-etroit-seul--inline';
        etroit.textContent = ABREGE_SEVERITE[sev] || sev;
        badge.append(large, etroit, document.createTextNode(' ' + Number(f.n || 0).toFixed(1)));
        // Le `priority_label` etait calcule, stocke et jamais montre. Il explique
        // ici le RANG de la ligne, en infobulle : aucune colonne de plus.
        badge.title = f.pl
            ? sev + ' — ' + (L.priorite_aide || '').replace('{libelle}', String(f.pl))
            : sev;
        // Les marques vivent dans un conteneur, et non directement dans la
        // cellule : une `td` doit rester `table-cell`, la passer en `flex` la
        // sortirait de la disposition du tableau. Le conteneur, lui, peut etre
        // flexible — c'est lui qui permet de remettre KEV en tete quand la place
        // manque, sans dependre d'un ordre du DOM qui ne reagirait pas au
        // redimensionnement.
        const marques = document.createElement('span');
        marques.className = 'rw-cve-marques';
        marques.append(badge, ...marquesEnrichissement(f));
        tdSev.appendChild(marques);
        tr.appendChild(tdSev);

        // Le resume est une colonne D'APPOINT : il se tronque plutot que
        // d'elargir le tableau et de chasser la colonne de suivi hors du champ.
        // Le texte entier reste lisible en infobulle.
        const tdResume = cellule(f.r || '', 'rw-colonne-secondaire rw-tableau__discret rw-cve-resume');
        tdResume.title = f.r || '';
        tr.appendChild(tdResume);

        // Sixieme colonne — LE SUIVI (sous-lot S5). C'est precisement la colonne
        // que trois generateurs du legacy omettaient, et le seul generateur d'ici
        // la produit donc pour tous les gestes.
        tr.appendChild(celluleSuivi(f, mid));

        return tr;
    }

    /**
     * LA PASTILLE KEV ET LA PROBABILITE EPSS, accrochees a la severite.
     *
     * KEV = la faille est REELLEMENT exploitee (catalogue CISA). C'est le signal
     * le plus important de la page — et cote legacy il est ILLISIBLE : la
     * pastille y est peinte par `bg-rose-600`, une classe Tailwind absente du CSS
     * compile (PurgeCSS ne garde que ce qu'il a vu). Le fond n'est donc pas
     * peint, le texte est blanc, et le contraste mesure au navigateur vaut
     * 1,06:1 — invisible. Aucune assertion sur le DOM ne le voyait : la pastille
     * EST bien dans le HTML. Ici la classe est ecrite a la main, donc peinte.
     *
     * EPSS = probabilite d'exploitation a 30 jours. Elle est rendue en POURCENT
     * plutot qu'en decimales : 0,0008 et 0,9455 se distinguent mal d'un coup
     * d'oeil, « 0 % » et « 95 % » non. Un finding non enrichi le DIT, au lieu de
     * laisser une case vide qui se confond avec « aucun risque ».
     */
    function marquesEnrichissement(f) {
        const marques = [];

        if (f.k) {
            const kev = document.createElement('span');
            kev.className = 'rw-badge rw-badge--kev';
            kev.textContent = 'KEV';
            const depuis = f.kd
                ? ' — ' + (L.kev_depuis || '').replace('{date}', String(f.kd))
                : '';
            kev.title = (L.kev_aide || '') + depuis;
            marques.push(kev);
        }

        const epss = document.createElement('span');
        if (f.e === null || f.e === undefined) {
            epss.className = 'rw-cve-epss rw-cve-epss--absent';
            epss.textContent = L.non_enrichi || '';
            epss.title = L.epss_aide || '';
        } else {
            // Au-dela de 50 %, l'exploitation est plus probable qu'improbable :
            // la valeur se signale, au lieu de rester un chiffre parmi d'autres.
            const chaud = Number(f.e) >= 0.5;
            epss.className = 'rw-cve-epss' + (chaud ? ' rw-cve-epss--haut' : '');
            epss.textContent = 'EPSS ' + Math.round(Number(f.e) * 100) + '%';
            epss.title = L.epss_aide || '';
        }
        marques.push(epss);

        return marques;
    }

    /**
     * La cellule de suivi : l'etat STOCKE, et le bouton de ticket.
     *
     * L'ETAT STOCKE EST AFFICHE. Le legacy ne posait aucune option `selected` et
     * ne lisait jamais `cve_remediation` depuis la page : son selecteur montrait
     * un tiret meme quand une remediation existait, et le choix qu'on venait de
     * faire disparaissait au rechargement.
     *
     * `resolved` est AFFICHE mais pas PROPOSE : il est pose par le scanner seul,
     * quand une CVE disparait d'un scan suivant. Proposer a un humain de
     * « resoudre » ce que le scanner constate brouillerait les deux gestes — la
     * ligne concernee montre donc un libelle en clair, avec son explication, au
     * lieu d'un selecteur.
     */
    function celluleSuivi(f, mid) {
        const td = document.createElement('td');
        td.className = 'rw-cve-suivi';
        const cveId = String(f.c || '');
        const actuel = (SUIVI[mid] || {})[cveId] || '';

        if (actuel === 'resolved') {
            const badge = document.createElement('span');
            badge.className = 'rw-badge rw-badge--ok';
            badge.textContent = (S.statuts || {}).resolved || 'resolved';
            badge.title = S.resolved_aide || '';
            td.appendChild(badge);
            return td;
        }

        const select = document.createElement('select');
        select.className = 'rw-saisie rw-saisie--compacte';
        select.dataset.rw = 'cve-suivi-' + cveId;
        const vide = document.createElement('option');
        vide.value = '';
        vide.textContent = S.aucun || '';
        select.appendChild(vide);
        for (const st of (S.choisissables || [])) {
            const o = document.createElement('option');
            o.value = st;
            o.textContent = (S.statuts || {})[st] || st;
            if (st === actuel) o.selected = true;
            select.appendChild(o);
        }
        select.value = actuel;
        select.addEventListener('change', () => poseSuivi(mid, cveId, select));
        td.appendChild(select);

        const bouton = document.createElement('button');
        bouton.type = 'button';
        bouton.className = 'rw-bouton rw-bouton--minuscule';
        bouton.dataset.rw = 'cve-ticket-' + cveId;
        // Libelle COURT dans le bouton, libelle entier en infobulle : la colonne
        // doit tenir a cote du selecteur sans pousser le tableau hors du cadre.
        bouton.textContent = S.ticket_court || S.ticket || '';
        if (S.peut_ticket) {
            bouton.title = S.ticket_aide || '';
            bouton.addEventListener('click', () => creeTicket(mid, cveId, bouton));
        } else {
            // DESACTIVE, ET IL DIT POURQUOI. Le backend refuserait de toute facon :
            // offrir le geste serait mentir sur ce qui est possible.
            bouton.disabled = true;
            bouton.title = S.ticket_refuse || '';
        }
        td.appendChild(bouton);

        return td;
    }

    async function poseSuivi(mid, cveId, select) {
        const voulu = select.value;
        if (!voulu) return;
        let ok = false;
        try {
            const rep = await fetch(S.url_suivi, {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cve_id: cveId, machine_id: Number(mid), status: voulu }),
            });
            const d = await rep.json().catch(() => ({}));
            ok = rep.ok && d.success === true;
            if (ok) {
                // La source de verite locale suit la base : sans cela, un
                // re-rendu (pagination, filtre) reafficherait l'ancien etat.
                SUIVI[mid] = SUIVI[mid] || {};
                SUIVI[mid][cveId] = voulu;
            }
            annonce(ok ? (S.enregistre || '') : (d.message || S.err_reseau || ''), ok);
        } catch {
            annonce(S.err_reseau || '', false);
        }
        if (!ok) select.value = (SUIVI[mid] || {})[cveId] || '';
    }

    async function creeTicket(mid, cveId, bouton) {
        bouton.disabled = true;
        try {
            const rep = await fetch(S.url_ticket, {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source: 'cve', ref: cveId, machine_id: Number(mid) }),
            });
            const d = await rep.json().catch(() => ({}));
            if (rep.ok && d.success !== false) {
                annonce(d.deduped ? (S.ticket_existant || '') : (S.ticket_cree || ''), true);
            } else {
                annonce(d.message || S.ticket_echec || '', false);
            }
        } catch {
            annonce(S.ticket_echec || '', false);
        }
        bouton.disabled = false;
    }

    /**
     * LA RE-PRIORISATION, ET POURQUOI ELLE DEMANDE D'ABORD.
     *
     * `POST /cve_reprioritize` reecrit les SIX colonnes d'enrichissement de TOUS
     * les findings du dernier scan de la machine — 1458 lignes sur le parc mesure
     * — apres dix-neuf appels a FIRST.org et un au catalogue CISA. Il n'y a pas
     * de retour en arriere, et une coupure reseau en cours de route remet `kev` a
     * zero partout. Le legacy declenche cela sur un simple clic.
     *
     * Ici le clic OUVRE une decision, sous le bouton, qui nomme le nombre de
     * lignes concernees et l'absence de retour. Convention du portage : jamais de
     * `confirm()` — la boite native recouvre precisement ce sur quoi on decide,
     * ne se style pas, et bloque Puppeteer, donc empeche de mener l'action au
     * bout dans un test.
     */
    function ouvreDecisionReprio(mid) {
        const panneau = document.getElementById('reprio-panneau-' + mid);
        if (panneau) panneau.hidden = false;
    }

    function fermeDecisionReprio(mid) {
        const panneau = document.getElementById('reprio-panneau-' + mid);
        if (panneau) panneau.hidden = true;
    }

    async function reprioriseCve(mid) {
        const bouton = document.getElementById('reprio-btn-' + mid);
        fermeDecisionReprio(mid);
        if (bouton) bouton.disabled = true;
        annonce(L.reprio_encours || '', true);
        try {
            const rep = await fetch(L.url_reprio, {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ machine_id: Number(mid) }),
            });
            const d = await rep.json().catch(() => ({}));
            if (rep.ok && d.success !== false) {
                annonce((L.reprio_ok || '')
                    .replace('{kev}', String(d.kev ?? 0))
                    .replace('{epss}', String(d.epss ?? 0)), true);
                // Les donnees en memoire sont desormais PERIMEES : le tableau
                // afficherait un enrichissement que la base ne porte plus. Le
                // portage recharge la page plutot que de recoudre son etat —
                // l'ordre de tri vient du SQL, il ne se recalcule pas ici.
                window.location.reload();
            } else {
                annonce(d.message || L.reprio_echec || '', false);
            }
        } catch {
            annonce(L.reprio_echec || '', false);
        }
        if (bouton) bouton.disabled = false;
    }

    document.querySelectorAll('[id^="reprio-btn-"]').forEach((bouton) => {
        bouton.addEventListener('click', () => ouvreDecisionReprio(bouton.dataset.machine));
    });
    document.querySelectorAll('[data-reprio-annule]').forEach((b) => {
        b.addEventListener('click', () => fermeDecisionReprio(b.dataset.reprioAnnule));
    });
    document.querySelectorAll('[data-reprio-confirme]').forEach((b) => {
        b.addEventListener('click', () => reprioriseCve(b.dataset.reprioConfirme));
    });

    /** Un message a l'ecran, jamais seulement dans la console. */
    function annonce(texte, ok) {
        let zone = document.getElementById('cve-annonce');
        if (!zone) {
            zone = document.createElement('p');
            zone.id = 'cve-annonce';
            zone.setAttribute('aria-live', 'polite');
            document.querySelector('.rw-entete-page')?.after(zone);
        }
        zone.className = ok ? 'rw-annonce rw-annonce--ok' : 'rw-annonce rw-annonce--echec';
        zone.textContent = texte;
    }

    /** Le rendu, unique point d'ecriture du tableau. */
    function rendu(mid) {
        const corps = document.getElementById('findings-body-' + mid);
        if (!corps) return;

        const e = etat(mid);
        const liste = retenus(mid);
        const jusqua = Math.min(liste.length, e.page * PAR_PAGE);

        corps.replaceChildren();
        for (let i = 0; i < jusqua; i++) corps.appendChild(ligne(liste[i], mid));

        if (liste.length === 0) {
            const tr = document.createElement('tr');
            const td = cellule(L.aucun_resultat || '', 'rw-tableau__message');
            td.colSpan = 6;
            tr.appendChild(td);
            corps.appendChild(tr);
        }

        const compteur = document.getElementById('findings-count-' + mid);
        if (compteur) {
            compteur.textContent = (L.affiche_sur || '{montre} / {total}')
                .replace('{montre}', String(jusqua))
                .replace('{total}', String(liste.length));
        }

        // Le bouton se CACHE, il ne quitte pas le DOM : un element qui disparait
        // et reapparait fait perdre le focus et deroute un lecteur d'ecran.
        const plus = document.getElementById('load-more-' + mid);
        if (plus) plus.hidden = jusqua >= liste.length;
    }

    function activePuce(barre, bouton) {
        barre.querySelectorAll('.rw-onglet').forEach((b) => b.classList.remove('rw-onglet--actif'));
        bouton.classList.add('rw-onglet--actif');
    }

    // Le contrat que la suite de caracterisation vise sur LES DEUX portails :
    // la liste des machines rendues. Elle est DERIVEE DU DOM, pas repassee en
    // donnees — une seconde source finirait par contredire la premiere.
    window._cveConfig = {
        machineIds: Array.from(document.querySelectorAll('[id^="server-card-"]'))
            .map((c) => parseInt(c.id.replace('server-card-', ''), 10))
            .filter((n) => !isNaN(n)),
    };

    // ── Depli : le tableau n'est rendu qu'a la premiere ouverture ────────────
    document.querySelectorAll('.rw-repliable[data-cible]').forEach((bascule) => {
        bascule.addEventListener('click', () => {
            const detail = document.getElementById(bascule.dataset.cible);
            if (!detail) return;
            const ouvert = detail.hidden;
            detail.hidden = !ouvert;
            bascule.setAttribute('aria-expanded', ouvert ? 'true' : 'false');
            const aide = bascule.querySelector('.rw-repliable__aide');
            if (aide) aide.textContent = ouvert ? (L.replier || '') : (L.voir_details || '');
            // Pas de rendu ici : le tableau est deja peint (voir plus bas). Le
            // depli est PUREMENT visuel.
        });
    });

    // ── Filtres, recherche, pagination : tous passent par `rendu` ────────────
    document.querySelectorAll('.rw-barre-filtres[data-machine]').forEach((barre) => {
        const mid = barre.dataset.machine;
        barre.querySelectorAll('.rw-onglet').forEach((bouton) => {
            bouton.addEventListener('click', () => {
                const e = etat(mid);
                if (bouton.dataset.sev !== undefined) e.severite = bouton.dataset.sev;
                if (bouton.dataset.an !== undefined) e.annee = bouton.dataset.an;
                e.page = 1;
                activePuce(barre, bouton);
                rendu(mid);
            });
        });
    });

    document.querySelectorAll('input[type="text"][data-machine]').forEach((champ) => {
        const mid = champ.dataset.machine;
        let minuteur = null;
        champ.addEventListener('input', () => {
            // Un debounce, pas une attente fixe apres un geste : il n'y a aucun
            // appel reseau ici, seulement un rendu a ne pas refaire a chaque
            // frappe sur 1458 lignes.
            clearTimeout(minuteur);
            minuteur = setTimeout(() => {
                const e = etat(mid);
                e.recherche = champ.value;
                e.page = 1;
                rendu(mid);
            }, 120);
        });
    });

    document.querySelectorAll('[id^="load-more-"]').forEach((bouton) => {
        bouton.addEventListener('click', () => {
            const mid = bouton.id.replace('load-more-', '');
            etat(mid).page += 1;
            rendu(mid);
        });
    });

    // ── Premier rendu, des le chargement ────────────────────────────────────
    // Peindre au DEPLI seulement etait tentant — 50 lignes de moins par machine —
    // mais cela rendait faux, au chargement, le compteur que le tableau doit
    // accorder avec la base : la page annoncait un vide qui n'existait pas. Les
    // lignes sont donc peintes tout de suite, dans un bloc masque : c'est ce que
    // fait le legacy, et c'est la propriete que la caracterisation mesure sur les
    // deux portails.
    Object.keys(donnees).forEach((mid) => rendu(mid));

    // ── Comparaison des deux derniers scans, au clic ─────────────────────────
    function dateLocale(valeur) {
        if (!valeur) return '';
        const d = new Date(String(valeur).replace(' ', 'T'));
        if (isNaN(d.getTime())) return String(valeur);
        // La langue de la SESSION, jamais 'fr-FR' en dur.
        return d.toLocaleString(L.langue || undefined);
    }

    document.querySelectorAll('[data-machine][data-rw^="comparer-"]').forEach((bouton) => {
        bouton.addEventListener('click', async () => {
            const mid = bouton.dataset.machine;
            const panneau = document.getElementById('comparaison-' + mid);
            if (!panneau) return;

            panneau.hidden = false;
            panneau.replaceChildren(texte(L.comparaison_titre || '', 'rw-panneau-decision__texte'));

            let r;
            try {
                const rep = await fetch(L.url_comparaison + '?machine_id=' + encodeURIComponent(mid),
                                        { credentials: 'same-origin' });
                if (!rep.ok) throw new Error(String(rep.status));
                r = await rep.json();
            } catch (e) {
                // ON LE DIT A L'ECRAN. Le chargeur du legacy n'ecrit que dans la
                // console : quand le proxy tombait, la carte restait vide sans un
                // mot.
                panneau.replaceChildren(texte(L.erreur_comparaison || '', 'rw-annonce rw-annonce--echec'));
                return;
            }

            panneau.replaceChildren();
            panneau.appendChild(texte(L.comparaison_titre || '', 'rw-panneau-decision__texte'));

            if (!r.assez) {
                panneau.appendChild(texte(L.comparaison_insuffisante || '', 'rw-annonce rw-annonce--attention'));
            } else if (r.ajoutees.length === 0 && r.corrigees.length === 0) {
                panneau.appendChild(texte(L.comparaison_identique || '', 'rw-annonce rw-annonce--ok'));
            } else {
                panneau.appendChild(texte(
                    (L.comparaison_ajoutees || '') + ' : ' + r.ajoutees.length + ' · ' +
                    (L.comparaison_corrigees || '') + ' : ' + r.corrigees.length + ' · ' +
                    (L.comparaison_inchangees || '') + ' : ' + r.inchangees, 'rw-aide'));
                if (r.scan1 && r.scan2) {
                    panneau.appendChild(texte(dateLocale(r.scan1.date) + ' → ' + dateLocale(r.scan2.date), 'rw-aide'));
                }
            }

            const actions = document.createElement('div');
            actions.className = 'rw-panneau-decision__actions';
            const fermer = document.createElement('button');
            fermer.type = 'button';
            fermer.className = 'rw-bouton rw-bouton--discret';
            fermer.textContent = L.fermer || '';
            fermer.addEventListener('click', () => { panneau.hidden = true; });
            actions.appendChild(fermer);
            panneau.appendChild(actions);
        });
    });

    function texte(valeur, classe) {
        const p = document.createElement('p');
        if (classe) p.className = classe;
        p.textContent = valeur;
        return p;
    }
})();
