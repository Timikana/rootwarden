/**
 * journal-audit.js - Module `adm/`, sous-lot D1 : integrite du journal d'audit.
 *
 * Le tableau et les filtres sont rendus par Blade : cette page n'a rien a
 * charger. Ce fichier ne porte que les deux gestes d'integrite, reserves au
 * role 3.
 *
 * QUATRE DIFFERENCES AVEC `legacy/adm/audit_log.php`, TOUTES DES CORRECTIONS :
 *
 *   1. **UN SEUL VERDICT.** Le legacy interroge deux points d'API qui lisent la
 *      chaine differemment et se contredisent : « Verifier » annonce une chaine
 *      intacte pendant que « Sceller » annonce une desynchronisation et refuse
 *      d'ecrire (PARITE E-104). Ici les deux gestes appellent le meme parcours,
 *      cote serveur — ils ne PEUVENT plus diverger.
 *   2. **AUCUNE BOITE NATIVE.** Le legacy pose `confirm("Sceller les lignes
 *      orphelines dans la hash chain ?")`, en francais code en dur. La decision
 *      se prend ici dans la page, et la confirmation EMPECHE : le bouton naît
 *      desactive et ne s'active qu'a la saisie exacte du nombre de lignes.
 *   3. **TOUT LIBELLE VIENT DES DONNEES.** Les six verdicts du legacy sont ecrits
 *      en francais dans son JavaScript, dans un fichier par ailleurs bilingue
 *      (PARITE E-107).
 *   4. **UNE PANNE RESEAU SE VOIT**, et le bouton revient. Un `fetch` qui rejette
 *      laissait le legacy sur « en cours » pour toujours.
 *
 * Le rendu passe par `textContent` : une action journalisee contient par nature
 * des caracteres de balisage — c'est un journal d'audit.
 */
(function () {
    'use strict';

    const L = JSON.parse(document.getElementById('audit-libelles').textContent);
    const annonce = document.querySelector('[data-rw="audit-resultat"]');
    const btnVerifier = document.querySelector('[data-rw="audit-verifier"]');
    const btnSceller = document.querySelector('[data-rw="audit-sceller"]');
    const panneau = document.querySelector('[data-rw="audit-panneau-sceller"]');

    if (! annonce) return;

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    function dis(texte, type) {
        annonce.textContent = texte;
        annonce.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
    }

    /** Substitue `:cle` dans un libelle, comme le fait le serveur. */
    function garnis(modele, valeurs) {
        return Object.keys(valeurs).reduce(
            (t, c) => t.split(':' + c).join(String(valeurs[c])), String(modele)
        );
    }

    /**
     * TOUT echec rend un objet, jamais une exception. Corrige a la SOURCE :
     * cinq appelants du legacy laissaient leur bouton fige sur un rejet.
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
            const r = await fetch(chemin, parametres);
            let json = null;
            try { json = await r.json(); } catch (e) { /* reponse non JSON */ }

            return { ok: r.ok, statut: r.status, corps: json };
        } catch (e) {
            return { ok: false, statut: 0, corps: null, reseau: true };
        }
    }

    /** Le verdict d'integrite, en clair. Lecture seule cote serveur. */
    function rendVerdict(d) {
        if (d.integre) {
            dis(garnis(L.chaine_intacte, {
                scellees: d.scellees, orphelines: d.orphelines, tete: d.tete || '—',
            }), 'ok');

            return;
        }
        dis(garnis(L.chaine_rompue, {
            ligne: d.erreur ? d.erreur.id : '?',
            type: d.erreur ? d.erreur.type : '?',
            attendu: d.erreur ? d.erreur.attendu : '?',
            trouve: d.erreur ? d.erreur.trouve : '?',
        }), 'echec');
    }

    async function verifie() {
        btnVerifier.disabled = true;
        dis(L.verif_en_cours, '');
        const r = await appelle('/journal-audit/verifier');
        // Le bouton est reactive dans le MEME bloc synchrone que l'ecriture du
        // verdict : c'est LUI que la sonde d'un test peut attendre, pas la
        // premiere annonce — qui porte le message de travail.
        if (! r.ok || ! r.corps) {
            dis(garnis(L.err_reseau, { statut: r.statut }), 'echec');
            btnVerifier.disabled = false;

            return;
        }
        rendVerdict(r.corps);
        btnVerifier.disabled = false;
    }

    /* ── Le scellement : simulation, puis decision en page ─────────────────── */

    let aSceller = 0;

    function fermePanneau() {
        panneau.hidden = true;
        panneau.querySelector('[data-rw="audit-panneau-saisie"]').value = '';
        panneau.querySelector('[data-rw="audit-confirmer"]').disabled = true;
    }

    /**
     * Le clic sur « Sceller » n'ecrit RIEN : il demande d'abord la SIMULATION,
     * qui dit combien de lignes seraient scellees. C'est la branche que le
     * legacy possede et qu'aucun de ses elements n'emet.
     */
    async function ouvreScellement() {
        btnSceller.disabled = true;
        dis(L.sceller_en_cours, '');
        const r = await appelle('/journal-audit/sceller?simulation=1', { method: 'POST' });
        btnSceller.disabled = false;

        if (! r.ok || ! r.corps) {
            dis(garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        if (r.corps.arret_sur_incoherence) {
            rendVerdict({ integre: false, erreur: r.corps.erreur });

            return;
        }
        aSceller = r.corps.orphelines;
        if (aSceller === 0) {
            dis(L.sceller_rien, 'ok');

            return;
        }

        dis('', '');
        panneau.querySelector('[data-rw="audit-panneau-texte"]').textContent =
            garnis(L.sceller_titre, { nombre: aSceller });
        panneau.querySelector('[data-rw="audit-panneau-consigne"]').textContent =
            garnis(L.sceller_consigne, { nombre: aSceller });
        panneau.hidden = false;
        panneau.querySelector('[data-rw="audit-panneau-saisie"]').focus();
    }

    async function confirmeScellement() {
        const bouton = panneau.querySelector('[data-rw="audit-confirmer"]');
        bouton.disabled = true;
        dis(L.sceller_en_cours, '');
        const r = await appelle('/journal-audit/sceller', {
            method: 'POST',
            body: JSON.stringify({ confirmation: aSceller }),
        });
        fermePanneau();

        if (! r.corps) {
            dis(garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        if (! r.ok) {
            dis(r.corps.message || garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        dis(garnis(L.sceller_fait, {
            scellees: r.corps.scellees, sur: aSceller, tete: r.corps.tete || '—',
        }), r.corps.scellees === aSceller ? 'ok' : 'attention');
    }

    if (btnVerifier) btnVerifier.addEventListener('click', verifie);
    if (btnSceller) btnSceller.addEventListener('click', ouvreScellement);
    if (panneau) {
        const saisie = panneau.querySelector('[data-rw="audit-panneau-saisie"]');
        const confirmer = panneau.querySelector('[data-rw="audit-confirmer"]');
        // La confirmation EMPECHE : elle ne s'active qu'a l'egalite exacte. Le
        // legacy laissait confirmer puis reprochait — le geste etait deja fait.
        saisie.addEventListener('input', () => {
            confirmer.disabled = saisie.value.trim() !== String(aSceller);
        });
        confirmer.addEventListener('click', confirmeScellement);
        panneau.querySelector('[data-rw="audit-annuler"]').addEventListener('click', () => {
            fermePanneau();
            dis(L.sceller_refus, '');
        });
    }
})();
