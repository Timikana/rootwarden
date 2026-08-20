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
            if (e.severite !== 'ALL' && (f.s || 'NONE') !== e.severite) return false;
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
    function ligne(f) {
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
        tr.appendChild(cellule(f.v || '', 'rw-colonne-secondaire'));

        // LA SEVERITE EST LA DONNEE QUI DECIDE : elle ne doit jamais etre coupee.
        // A 390 px, « CRITICAL 9.8 » se tronquait en « CR… ». Le mot entier et son
        // abreviation sont donc rendus tous les deux, et les deux classes
        // complementaires n'en montrent qu'un seul a la fois.
        const tdSev = document.createElement('td');
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
        badge.title = sev;
        tdSev.appendChild(badge);
        tr.appendChild(tdSev);

        // Le resume est une colonne D'APPOINT : il se tronque plutot que
        // d'elargir le tableau et de chasser la colonne de suivi hors du champ.
        // Le texte entier reste lisible en infobulle.
        const tdResume = cellule(f.r || '', 'rw-colonne-secondaire rw-tableau__discret rw-cve-resume');
        tdResume.title = f.r || '';
        tr.appendChild(tdResume);

        // Sixieme colonne — le SUIVI. Il appartient au sous-lot S5 : la cellule
        // dit ou il vit plutot que de disparaitre. C'est precisement la colonne
        // que trois generateurs du legacy omettaient.
        const tdSuivi = cellule('—', 'rw-tableau__discret');
        tdSuivi.title = L.suivi_a_venir || '';
        tr.appendChild(tdSuivi);

        return tr;
    }

    /** Le rendu, unique point d'ecriture du tableau. */
    function rendu(mid) {
        const corps = document.getElementById('findings-body-' + mid);
        if (!corps) return;

        const e = etat(mid);
        const liste = retenus(mid);
        const jusqua = Math.min(liste.length, e.page * PAR_PAGE);

        corps.replaceChildren();
        for (let i = 0; i < jusqua; i++) corps.appendChild(ligne(liste[i]));

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
