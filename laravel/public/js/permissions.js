/**
 * permissions.js - Module `adm/`, sous-lot D5.
 *
 * LA CASE NE BOUGE QU'APRES LA REPONSE, et le refus de step-up OUVRE un panneau.
 *
 * Le legacy fait tout le contraire, sans le vouloir : sa case part en htmx, le
 * serveur repond 403 `step_up_required`, le modal qui permettrait d'y repondre
 * n'ecoute que `window.fetch`, et htmx ne remplace rien sur un 4xx. Resultat
 * mesure : le POST part, le refus revient, la base ne bouge pas, et l'ecran non
 * plus. Trois pieces correctes qui forment une impasse (PARITE E-119).
 */
(function () {
    'use strict';

    const L = JSON.parse(document.getElementById('perms-libelles').textContent);
    const annonce = document.querySelector('[data-rw="perms-annonce"]');
    const panneau = document.querySelector('[data-rw="perms-panneau-stepup"]');
    if (! annonce) return;

    let enAttente = null;

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

    /**
     * Le resume d'un compte se RECOMPTE dans la grille, apres chaque geste
     * confirme. Il est rendu au chargement : sans ce recompte, il dirait
     * « 3 machines » au-dessus d'une grille qui en ouvre quatre.
     */
    function recompte(id) {
        const carte = document.querySelector(`[data-rw="perms-carte-${id}"]`);
        if (! carte) return;
        const cases = carte.querySelectorAll('input[data-permission]');
        const droits = carte.querySelector('[data-rw="perms-resume-droits"]');
        // Sans cases, le compte a tous les droits par son role : le libelle
        // rendu par le serveur reste.
        if (droits && cases.length) {
            droits.textContent = garnis(L.resume_droits, {
                n: [...cases].filter((c) => c.checked).length, total: cases.length,
            });
        }
        const listes = carte.querySelectorAll('select[data-machine-id]');
        const machines = carte.querySelector('[data-rw="perms-resume-machines"]');
        if (machines) {
            machines.textContent = garnis(L.resume_machines, {
                n: [...listes].filter((l) => (l.dataset.actuel || '') !== '').length, total: listes.length,
            });
        }
    }

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

    function demandeStepUp(action, rejouer) {
        enAttente = { action, rejouer };
        const champ = panneau.querySelector('[data-rw="perms-stepup-code"]');
        champ.value = '';
        panneau.hidden = false;
        champ.focus();
    }

    async function valideStepUp() {
        if (! enAttente) return;
        const champ = panneau.querySelector('[data-rw="perms-stepup-code"]');
        const bouton = panneau.querySelector('[data-rw="perms-stepup-valider"]');
        // Un envoi en cours : le meme code renvoye serait refuse par l'anti-rejeu.
        if (bouton.disabled) return;
        bouton.disabled = true;
        const r = await appelle('/profil/step-up',
            { action: enAttente.action, code: champ.value.trim() });
        bouton.disabled = false;
        if (! r.ok || ! r.corps || ! r.corps.success) {
            dis((r.corps && r.corps.message) || garnis(L.err_reseau, { statut: r.statut }), 'echec');

            return;
        }
        panneau.hidden = true;
        const rejouer = enAttente.rejouer;
        enAttente = null;
        await rejouer();
    }

    /**
     * Une bascule. La case REPREND son etat d'avant tant que le serveur n'a pas
     * confirme : une case cochee qui ne l'est pas en base est un mensonge.
     */
    async function bascule(caseCible) {
        const voulu = caseCible.checked;
        caseCible.checked = ! voulu;
        caseCible.disabled = true;

        const id = caseCible.dataset.userId;
        const estAcces = !! caseCible.dataset.machineId;
        const chemin = estAcces ? `/permissions/${id}/acces` : `/permissions/${id}`;
        const corps = estAcces
            ? { machine_id: caseCible.dataset.machineId, value: voulu ? 1 : 0 }
            : { permission: caseCible.dataset.permission, value: voulu ? 1 : 0 };

        const r = await appelle(chemin, corps);
        caseCible.disabled = false;

        if (r.corps && r.corps.step_up_required) {
            // Le refus s'ANNONCE, et il ouvre le chemin pour y repondre.
            dis(r.corps.message, 'attention');

            return demandeStepUp(r.corps.action, async () => {
                caseCible.checked = voulu;
                await bascule(caseCible);
            });
        }
        if (! r.corps) { dis(garnis(L.err_reseau, { statut: r.statut }), 'echec'); return; }
        if (! r.ok || ! r.corps.success) { dis(r.corps.message, 'echec'); return; }

        caseCible.checked = r.corps.actif;
        recompte(id);
        dis(r.corps.message, 'ok');
    }

    /**
     * Le prereglage sudo d'un couple (compte, machine). UN seul controle porte
     * tout l'etat : chaine vide = pas d'acces, sinon un prereglage de la liste
     * fermee du serveur.
     *
     * LA LISTE REVIENT A SON ETAT CONFIRME tant que le serveur n'a pas repondu,
     * comme la case a cocher. Et elle affiche ensuite `r.corps.preset` — ce que
     * le serveur a ECRIT — jamais la valeur demandee : une liste qui montrerait
     * « sudo complet » alors que la base porte autre chose ferait decider la
     * suite sur une croyance fausse. Sur un ecran de privilege c'est le defaut
     * le plus couteux.
     */
    async function changePreset(liste) {
        const voulu = liste.value;
        const avant = liste.dataset.actuel || '';
        liste.value = avant;
        liste.disabled = true;

        const corps = { machine_id: liste.dataset.machineId, value: voulu ? 1 : 0 };
        if (voulu) { corps.preset = voulu; }

        const r = await appelle(`/permissions/${liste.dataset.userId}/acces`, corps);
        liste.disabled = false;

        if (r.corps && r.corps.step_up_required) {
            dis(r.corps.message, 'attention');

            return demandeStepUp(r.corps.action, async () => {
                liste.value = voulu;
                await changePreset(liste);
            });
        }
        if (! r.corps) { dis(garnis(L.err_reseau, { statut: r.statut }), 'echec'); return; }
        if (! r.ok || ! r.corps.success) { dis(r.corps.message, 'echec'); return; }

        const ecrit = typeof r.corps.preset === 'string' ? r.corps.preset : '';
        liste.value = ecrit;
        liste.dataset.actuel = ecrit;
        const ligne = liste.closest('[data-preset]');
        if (ligne) ligne.dataset.preset = ecrit;
        recompte(liste.dataset.userId);
        dis(r.corps.message, 'ok');
    }

    /**
     * Une cle d'un compte, posee ou retiree sur UNE machine. Meme discipline que
     * `bascule` : la case reprend son etat d'avant, et ne prend que celui que le
     * serveur a ECRIT (`r.corps.actif`).
     */
    async function basculeCle(caseCible) {
        const voulu = caseCible.checked;
        caseCible.checked = ! voulu;
        caseCible.disabled = true;

        const r = await appelle(`/permissions/${caseCible.dataset.userId}/cles/${caseCible.dataset.cleId}`,
            { machine_id: caseCible.dataset.cleMachine, value: voulu ? 1 : 0 });
        caseCible.disabled = false;

        if (! r.corps) { dis(garnis(L.err_reseau, { statut: r.statut }), 'echec'); return; }
        if (! r.ok || ! r.corps.success) { dis(r.corps.message, 'echec'); return; }

        caseCible.checked = r.corps.actif;
        const bloc = caseCible.closest('details');
        const resume = bloc ? bloc.querySelector('summary') : null;
        if (resume) {
            const cases = bloc.querySelectorAll('input[data-cle-id]');
            resume.textContent = garnis(L.cles_resume, {
                n: [...cases].filter((c) => c.checked).length, total: cases.length,
            });
        }
        dis(r.corps.message, 'ok');
    }

    document.addEventListener('change', (ev) => {
        const c = ev.target;
        if (c instanceof HTMLInputElement && c.type === 'checkbox' && c.dataset.cleId) {
            basculeCle(c);
        }
        // `dataset.machineId` a QUITTE les cases a cocher : les machines sont
        // desormais une liste de prereglages. Le laisser dans la condition
        // ci-dessous ferait croire qu'un chemin existe encore ici.
        if (c instanceof HTMLInputElement && c.type === 'checkbox' && c.dataset.permission) {
            bascule(c);
        }
        if (c instanceof HTMLSelectElement && c.dataset.machineId) {
            changePreset(c);
        }
    });
    document.addEventListener('click', (ev) => {
        const rw = ev.target instanceof HTMLElement ? (ev.target.dataset.rw || '') : '';
        if (rw === 'perms-stepup-annuler') { panneau.hidden = true; enAttente = null; }
        if (rw === 'perms-stepup-valider') valideStepUp();
    });
    // ENTREE VALIDE LE CODE. Le panneau n'est pas un formulaire : sans cet
    // ecouteur, Entree ne faisait rien et le geste restait en attente, muet.
    document.addEventListener('keydown', (ev) => {
        if (ev.key !== 'Enter' || ! ev.target.matches('[data-rw="perms-stepup-code"]')) return;
        ev.preventDefault();
        valideStepUp();
    });

    /* ═══ Permissions temporaires — sous-lot D5b ══════════════════════════
     *
     * L'OCTROI PASSE PAR LA PASSERELLE, et c'est la seule raison qui vaille :
     * `POST /admin/temp_permissions` NOTIFIE le compte concerne
     * (`admin.py:196`). Reecrire l'insertion cote portage priverait la personne
     * de son avertissement, sans que rien ne le signale.
     *
     * La REVOCATION, elle, est un formulaire : elle n'a aucun effet de bord, et
     * un formulaire n'a pas de plomberie a oublier. C'est la lecon de D6b, ou
     * QUATRE gestes mouraient sur un jeton que l'enrobage n'injectait pas.
     */
    const boutonTemp = document.querySelector('[data-rw="temp-accorder"]');
    if (boutonTemp) {
        const etatTemp = document.querySelector('[data-rw="temp-etat"]');
        const ditTemp = (t) => { if (etatTemp) etatTemp.textContent = t || ''; };
        const lisTemp = (sel) => {
            const e = document.querySelector(sel);

            return e ? e.value : '';
        };

        boutonTemp.addEventListener('click', async () => {
            const compte = parseInt(lisTemp('[data-rw="temp-compte"]'), 10);
            const permission = lisTemp('[data-rw="temp-permission"]');
            if (! compte || ! permission) return;

            boutonTemp.disabled = true;
            ditTemp(L.temp_en_cours);

            try {
                const r = await fetch('/api/gateway/admin/temp_permissions', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        user_id: compte,
                        permission,
                        hours: parseInt(lisTemp('[data-rw="temp-duree"]'), 10),
                        reason: lisTemp('[data-rw="temp-raison"]'),
                    }),
                });
                const d = await r.json().catch(() => null);
                /* FAIL-CLOSED : sans `success === true`, on annonce un echec.
                 * Un `undefined` affiche comme « accorde » ferait croire a un
                 * droit qui n'existe pas. */
                if (d && d.success === true) {
                    ditTemp(L.temp_accorde);
                    /* LA LISTE SE RELIT DU SERVEUR. La reconstruire ici
                     * dupliquerait la regle « non expire », qui vit dans le
                     * service — et deux versions d'une regle finissent par
                     * diverger. */
                    window.location.reload();

                    return;
                }
                ditTemp(L.temp_echec);
            } catch (e) {
                ditTemp(L.temp_echec);
            }
            boutonTemp.disabled = false;
        });
    }
})();
