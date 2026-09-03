/**
 * comptes.js - Module `adm/`, sous-lot D3 : comptes, roles, mots de passe.
 *
 * AUCUNE BOITE NATIVE, et ici ce n'est pas seulement une convention de style.
 * Le legacy place ses chaines traduites dans des litteraux JavaScript entre
 * apostrophes ; deux des trois chaines francaises en contiennent une, le
 * litteral se ferme, l'`onclick` ne s'analyse pas — et les deux actions
 * destructrices partent SANS confirmation, en francais seulement (E-114). Ici le
 * texte traduit est du CONTENU (`textContent`), jamais du code : le probleme ne
 * peut pas exister.
 *
 * LE MOT DE PASSE GENERE ne vient pas du HTML de la page : il arrive dans la
 * reponse du geste qui l'a demande, s'affiche une fois, et n'est jamais rendu
 * ailleurs. Le legacy le place dans la page — d'ou il part dans l'historique du
 * navigateur — et `strip_tags` l'ampute au passage (E-113).
 */
(function () {
    'use strict';

    const L = JSON.parse(document.getElementById('comptes-libelles').textContent);
    const annonce = document.querySelector('[data-rw="comptes-annonce"]');
    const secret = document.querySelector('[data-rw="comptes-secret"]');
    const panneauTotp = document.querySelector('[data-rw="comptes-panneau-totp"]');
    if (! annonce) return;

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    function dis(texte, type) {
        annonce.textContent = texte;
        annonce.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
    }

    function garnis(modele, valeurs) {
        return Object.keys(valeurs).reduce(
            (t, c) => t.split(':' + c).join(String(valeurs[c])), String(modele)
        );
    }

    /** TOUT echec rend un objet, jamais une exception : un bouton doit revenir. */
    async function appelle(chemin, corps, methode) {
        try {
            const r = await fetch(chemin, {
                method: methode || 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-TOKEN': jetonCsrf(),
                    'Content-Type': 'application/json',
                },
                body: (methode || 'POST') === 'GET' ? undefined : JSON.stringify(corps || {}),
            });
            let json = null;
            try { json = await r.json(); } catch (e) { /* reponse non JSON */ }

            return { ok: r.ok, statut: r.status, corps: json };
        } catch (e) {
            return { ok: false, statut: 0, corps: null };
        }
    }

    function montreLeSecret(valeur) {
        secret.querySelector('[data-rw="comptes-secret-valeur"]').textContent = valeur;
        secret.hidden = false;
    }

    /* ── Mot de passe ─────────────────────────────────────────────────────── */

    async function poseMotDePasse(bouton, generer) {
        const id = bouton.dataset.id;
        const champ = document.querySelector(`[data-rw="compte-mdp"][data-id="${id}"]`);
        const saisi = champ ? champ.value : '';
        if (! generer && saisi.trim() === '') {
            dis(L.mdp_vide, 'echec');

            return;
        }
        bouton.disabled = true;
        const r = await appelle(`/comptes/${id}/mot-de-passe`,
            generer ? { generer: true } : { mot_de_passe: saisi });
        // Le bouton revient AVANT toute decision d'affichage.
        bouton.disabled = false;

        if (! r.corps) {
            dis(garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        if (! r.ok || ! r.corps.success) {
            // Le refus de la politique arrive ici, avec son motif. Le legacy,
            // lui, accepte (E-112).
            dis(r.corps.message, 'echec');

            return;
        }
        if (champ) champ.value = '';
        if (r.corps.genere) montreLeSecret(r.corps.genere);
        dis(r.corps.message, 'ok');
    }

    /* ── Second facteur : decision EN PAGE ────────────────────────────────── */

    let cibleTotp = null;

    async function confirmeTotp() {
        if (cibleTotp === null) return;
        const bouton = panneauTotp.querySelector('[data-rw="comptes-totp-confirmer"]');
        bouton.disabled = true;
        const r = await appelle(`/comptes/${cibleTotp}/second-facteur`, {});
        bouton.disabled = false;
        panneauTotp.hidden = true;
        cibleTotp = null;

        if (! r.corps) {
            dis(garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        dis(r.corps.message, r.ok && r.corps.success ? 'ok' : 'echec');
        if (r.ok && r.corps.success) setTimeout(() => location.reload(), 1200);
    }

    /* ── Deverrouillage ───────────────────────────────────────────────────── */

    async function deverrouille(bouton) {
        bouton.disabled = true;
        const r = await appelle(`/comptes/${bouton.dataset.id}/deverrouiller`, {});
        bouton.disabled = false;
        if (! r.corps) {
            dis(garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        dis(r.corps.message, r.ok && r.corps.success ? 'ok' : 'echec');
        if (r.ok && r.corps.success) setTimeout(() => location.reload(), 1200);
    }

    /* ── Suppression / anonymisation, et le step-up qui les garde ────────── */

    const panneauSuppr = document.querySelector('[data-rw="comptes-panneau-suppression"]');
    const panneauStepUp = document.querySelector('[data-rw="comptes-panneau-stepup"]');
    /** Le geste en attente, remis en jeu apres un step-up reussi. */
    let enAttente = null;

    function fermeLesPanneaux() {
        if (panneauSuppr) panneauSuppr.hidden = true;
        if (panneauStepUp) panneauStepUp.hidden = true;
    }

    /**
     * Un 403 qui NOMME son action ouvre le panneau de step-up et met le geste en
     * attente. C'est la piece que le sous-lot A5 avait differee « a son premier
     * consommateur » : D4 est ce consommateur.
     */
    function demandeStepUp(action, rejouer) {
        enAttente = { action, rejouer };
        const champ = panneauStepUp.querySelector('[data-rw="comptes-stepup-code"]');
        champ.value = '';
        panneauSuppr.hidden = true;
        panneauStepUp.hidden = false;
        champ.focus();
    }

    async function valideStepUp() {
        if (! enAttente) return;
        const champ = panneauStepUp.querySelector('[data-rw="comptes-stepup-code"]');
        const bouton = panneauStepUp.querySelector('[data-rw="comptes-stepup-valider"]');
        bouton.disabled = true;
        const r = await appelle('/profil/step-up',
            { action: enAttente.action, code: champ.value.trim() });
        bouton.disabled = false;

        if (! r.corps || ! r.ok || ! r.corps.success) {
            dis((r.corps && r.corps.message) || garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        panneauStepUp.hidden = true;
        const rejouer = enAttente.rejouer;
        enAttente = null;
        // Le geste repart de lui-meme : sans cela, l'operateur devrait
        // recommencer, et une re-authentification qui ne sert a rien se
        // transforme en gene qu'on cherche a contourner.
        await rejouer();
    }

    /** Ouvre le panneau de suppression APRES avoir demande l'etat au serveur. */
    async function ouvreSuppression(bouton) {
        const id = bouton.dataset.id;
        const nom = bouton.dataset.nom || '';
        bouton.disabled = true;
        const r = await appelle(`/comptes/${id}/etat-suppression`, null, 'GET');
        bouton.disabled = false;
        if (! r.ok || ! r.corps || ! r.corps.success) {
            dis((r.corps && r.corps.message) || garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        if (r.corps.refus) { dis(r.corps.refus, 'echec'); return; }

        const journaux = r.corps.journaux;
        panneauSuppr.querySelector('[data-rw="comptes-suppression-texte"]').textContent =
            garnis(L.suppr_question, { nom });
        panneauSuppr.querySelector('[data-rw="comptes-suppression-detail"]').textContent =
            journaux === 0
                ? L.suppr_sans_journal
                : garnis(L.suppr_avec_journal, { nombre: journaux });
        panneauSuppr.querySelector('[data-rw="comptes-suppression-consigne"]').textContent =
            garnis(L.suppr_consigne, { nom });
        const saisie = panneauSuppr.querySelector('[data-rw="comptes-suppression-saisie"]');
        saisie.value = '';
        saisie.dataset.nom = nom;
        saisie.dataset.id = id;
        const confirmer = panneauSuppr.querySelector('[data-rw="comptes-suppression-confirmer"]');
        // La suppression n'est meme pas PROPOSEE quand le compte porte un
        // journal : c'est l'anonymisation qui l'est. Le legacy, lui, ne propose
        // que la suppression — et elle emporte le journal (E-116).
        confirmer.hidden = journaux !== 0;
        confirmer.disabled = true;
        const anon = panneauSuppr.querySelector('[data-rw="comptes-suppression-anonymiser"]');
        anon.hidden = false;
        anon.dataset.id = id;
        anon.dataset.nom = nom;
        panneauStepUp.hidden = true;
        panneauSuppr.hidden = false;
    }

    async function supprime(id, nom) {
        const r = await appelle(`/comptes/${id}`, null, 'DELETE');
        if (r.corps && r.corps.step_up_required) {
            return demandeStepUp(r.corps.action, () => supprime(id, nom));
        }
        fermeLesPanneaux();
        if (! r.corps) { dis(garnis(L.err_reseau, { statut: r.statut }), 'echec'); return; }
        dis(r.corps.message, r.ok && r.corps.success ? 'ok' : 'echec');
        if (r.ok && r.corps.success) setTimeout(() => location.reload(), 1200);
    }

    async function anonymise(id, nom) {
        const r = await appelle(`/comptes/${id}/anonymiser`, {});
        if (r.corps && r.corps.step_up_required) {
            return demandeStepUp(r.corps.action, () => anonymise(id, nom));
        }
        fermeLesPanneaux();
        if (! r.corps) { dis(garnis(L.err_reseau, { statut: r.statut }), 'echec'); return; }
        dis(r.corps.message, r.ok && r.corps.success ? 'ok' : 'echec');
        if (r.ok && r.corps.success) setTimeout(() => location.reload(), 1200);
    }

    if (panneauSuppr) {
        const saisie = panneauSuppr.querySelector('[data-rw="comptes-suppression-saisie"]');
        const confirmer = panneauSuppr.querySelector('[data-rw="comptes-suppression-confirmer"]');
        // Elle EMPECHE : le bouton ne s'active qu'a l'egalite exacte du nom.
        saisie.addEventListener('input', () => {
            confirmer.disabled = saisie.value.trim() !== (saisie.dataset.nom || '');
        });
    }

    document.addEventListener('click', (ev) => {
        const el = ev.target;
        if (! (el instanceof HTMLElement)) return;
        const rw = el.dataset.rw || '';

        if (rw.startsWith('compte-supprimer-')) return ouvreSuppression(el);
        if (rw.startsWith('compte-anonymiser-')) {
            panneauStepUp.hidden = true;
            panneauSuppr.querySelector('[data-rw="comptes-suppression-texte"]').textContent =
                garnis(L.anon_question, { nom: el.dataset.nom || '' });
            panneauSuppr.querySelector('[data-rw="comptes-suppression-detail"]').textContent = '';
            panneauSuppr.querySelector('[data-rw="comptes-suppression-consigne"]').textContent = '';
            panneauSuppr.querySelector('[data-rw="comptes-suppression-confirmer"]').hidden = true;
            const a = panneauSuppr.querySelector('[data-rw="comptes-suppression-anonymiser"]');
            a.hidden = false; a.dataset.id = el.dataset.id; a.dataset.nom = el.dataset.nom || '';
            panneauSuppr.hidden = false;

            return;
        }
        if (rw === 'comptes-suppression-annuler') { fermeLesPanneaux(); return; }
        if (rw === 'comptes-suppression-confirmer') {
            const s = panneauSuppr.querySelector('[data-rw="comptes-suppression-saisie"]');

            return supprime(s.dataset.id, s.dataset.nom);
        }
        if (rw === 'comptes-suppression-anonymiser') return anonymise(el.dataset.id, el.dataset.nom);
        if (rw === 'comptes-stepup-annuler') { fermeLesPanneaux(); enAttente = null; return; }
        if (rw === 'comptes-stepup-valider') return valideStepUp();
        if (rw.startsWith('compte-mdp-poser-')) return poseMotDePasse(el, false);
        if (rw.startsWith('compte-mdp-generer-')) return poseMotDePasse(el, true);
        if (rw.startsWith('compte-deverrouiller-')) return deverrouille(el);
        if (rw.startsWith('compte-totp-')) {
            cibleTotp = el.dataset.id;
            // Le texte est pose par `textContent` : une apostrophe y est un
            // caractere, pas un delimiteur.
            panneauTotp.querySelector('[data-rw="comptes-panneau-totp-texte"]').textContent =
                garnis(L.totp_question, { nom: el.dataset.nom || '' });
            panneauTotp.hidden = false;

            return;
        }
        if (rw === 'comptes-totp-annuler') { panneauTotp.hidden = true; cibleTotp = null; return; }
        if (rw === 'comptes-totp-confirmer') return confirmeTotp();
        if (rw === 'comptes-secret-fermer') {
            secret.querySelector('[data-rw="comptes-secret-valeur"]').textContent = '';
            secret.hidden = true;
        }
    });
})();
