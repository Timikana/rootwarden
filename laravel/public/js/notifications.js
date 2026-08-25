/**
 * notifications.js - Module `adm/`, sous-lot D2.
 *
 * ══ L'ECRAN NE BOUGE QU'APRES LA REPONSE DU SERVEUR ════════════════════════
 *
 * C'est la seule regle de ce fichier, et elle vient d'une mesure. Le bouton du
 * legacy porte `onclick="… this.remove();"` (`notifications.php:141`) : il se
 * retire du DOM PENDANT l'evenement de clic, si bien que htmx — pourtant charge,
 * verifie — n'emet AUCUNE requete. Le surlignage disparait, le bouton aussi, et
 * la base ne bouge pas. L'utilisateur voit exactement ce qu'il verrait si
 * l'action avait abouti : ni erreur, ni journal, ni trace reseau. Voir E-108.
 *
 * Ici, rien n'est retire ni grise avant que la reponse ne soit lue. Un echec se
 * DIT, et l'etat affiche reste celui de la base.
 *
 * La pastille de l'en-tete est mise a jour depuis la MEME reponse, pas par un
 * second appel : deux appels peuvent se croiser, un seul ne le peut pas.
 */
(function () {
    'use strict';

    const L = JSON.parse(document.getElementById('notif-libelles').textContent);
    const annonce = document.querySelector('[data-rw="notif-annonce"]');
    const corps = document.querySelector('[data-rw="notif-corps"]');
    const btnToutLire = document.querySelector('[data-rw="notif-tout-lire"]');
    const pastille = document.querySelector('[data-rw="notif-pastille"]');

    if (! annonce || ! corps) return;

    function jetonCsrf() {
        const m = document.querySelector('meta[name="csrf-token"]');

        return m ? m.content : '';
    }

    function dis(texte, type) {
        annonce.textContent = texte;
        annonce.className = 'rw-annonce' + (type ? ' rw-annonce--' + type : '');
    }

    /** TOUT echec rend un objet, jamais une exception : un bouton doit revenir. */
    async function appelle(chemin, methode) {
        try {
            const r = await fetch(chemin, {
                method: methode || 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-TOKEN': jetonCsrf(),
                    'Content-Type': 'application/json',
                },
            });
            let json = null;
            try { json = await r.json(); } catch (e) { /* reponse non JSON */ }

            return { ok: r.ok, statut: r.status, corps: json };
        } catch (e) {
            return { ok: false, statut: 0, corps: null };
        }
    }

    /** La pastille de l'en-tete suit le compte rendu par le serveur. */
    function majPastille(nombre) {
        if (! pastille) return;
        pastille.textContent = String(nombre);
        pastille.hidden = nombre === 0;
    }

    /**
     * Une ligne passe LUE a l'ecran — et seulement quand le serveur l'a dit.
     * On ne retire pas la ligne : la faire disparaitre empecherait de verifier
     * ce qui vient d'etre fait.
     */
    function rendLue(id) {
        const etat = document.querySelector(`[data-rw="notif-etat-${id}"]`);
        if (etat) {
            etat.textContent = L.lue;
            etat.className = 'rw-pastille rw-pastille--neutre';
        }
        const ligne = document.querySelector(`[data-rw="notif-ligne-${id}"]`);
        if (ligne) ligne.classList.remove('rw-notif--non-lue');
        const bouton = document.querySelector(`[data-rw="notif-lire-${id}"]`);
        if (bouton) bouton.remove();
    }

    async function lire(bouton) {
        const id = bouton.dataset.id;
        bouton.disabled = true;
        const r = await appelle(`/notifications/${id}/lire`, 'POST');
        // Le bouton revient AVANT toute decision d'affichage : un echec ne doit
        // pas laisser un controle inerte a l'ecran.
        bouton.disabled = false;

        if (! r.corps) {
            dis(L.err_reseau.replace(':statut', r.statut), 'echec');

            return;
        }
        if (! r.ok || ! r.corps.success) {
            dis(r.corps.message || L.err_reseau.replace(':statut', r.statut), 'echec');

            return;
        }
        rendLue(id);
        majPastille(r.corps.nonLues);
        majBoutonToutLire(r.corps.nonLues);
        dis(r.corps.message, 'ok');
    }

    function majBoutonToutLire(nonLues) {
        if (btnToutLire) btnToutLire.disabled = nonLues === 0;
    }

    async function toutLire() {
        btnToutLire.disabled = true;
        const r = await appelle('/notifications/tout-lire', 'POST');
        btnToutLire.disabled = false;

        if (! r.corps || ! r.ok) {
            dis(L.err_reseau.replace(':statut', r.statut), 'echec');

            return;
        }
        if (r.corps.touchees === 0) {
            dis(L.rien_a_lire, '');
            majBoutonToutLire(0);

            return;
        }
        // Chaque ligne encore non lue passe lue — apres la reponse, jamais avant.
        corps.querySelectorAll('[data-rw^="notif-lire-"]').forEach((b) => rendLue(b.dataset.id));
        majPastille(r.corps.nonLues);
        majBoutonToutLire(r.corps.nonLues);
        dis(L.tout_lu.replace(':nombre', r.corps.touchees), 'ok');
    }

    corps.addEventListener('click', (ev) => {
        const bouton = ev.target.closest('[data-rw^="notif-lire-"]');
        if (bouton) lire(bouton);
    });
    if (btnToutLire) btnToutLire.addEventListener('click', toutLire);
})();
