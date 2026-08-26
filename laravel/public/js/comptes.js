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
    async function appelle(chemin, corps) {
        try {
            const r = await fetch(chemin, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-TOKEN': jetonCsrf(),
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(corps || {}),
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

    document.addEventListener('click', (ev) => {
        const el = ev.target;
        if (! (el instanceof HTMLElement)) return;
        const rw = el.dataset.rw || '';

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
