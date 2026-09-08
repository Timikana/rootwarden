// utils.js - helpers JS partages entre toutes les pages.
// Charge depuis menu.php avant les scripts specifiques.

// ── Auto-injection CSRF token sur fetch() vers api_proxy.php ──────────────
// Defense-in-depth : api_proxy.php force checkCsrfToken() sur POST/PUT/DELETE/
// PATCH depuis v1.17.0. SameSite=Strict mitige deja le CSRF cross-site, mais
// si une XSS reflechie/stockee existe sur le meme origin, le token bloque
// le proxy (l'endpoint le plus puissant de l'app).
// On wrappe fetch() pour ajouter automatiquement le header sur les non-GET
// vers /api_proxy.php - aucune modif requise dans les callers existants.
(function() {
    if (window.__rwFetchPatched) return;
    window.__rwFetchPatched = true;
    const _origFetch = window.fetch.bind(window);
    function _csrfToken() {
        const m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.getAttribute('content') : '';
    }
    window.fetch = function(input, init) {
        try {
            const url = typeof input === 'string' ? input : (input && input.url) || '';
            const method = (init && init.method) || (input && input.method) || 'GET';
            if ((url.indexOf('api_proxy.php') !== -1 || url.indexOf('/adm/api/') !== -1 || url.indexOf('/auth/') !== -1)
                && method.toUpperCase() !== 'GET') {
                const token = _csrfToken();
                if (token) {
                    init = init || {};
                    const h = new Headers(init.headers || {});
                    if (!h.has('X-CSRF-TOKEN')) h.set('X-CSRF-TOKEN', token);
                    init.headers = h;
                }
            }
        } catch (_) { /* fail-open : ne casse jamais le fetch */ }

        // Patch A04-INSEC-N4 : wrapper qui catch les 403 step_up_required et
        // ouvre automatiquement le modal de re-authentification 2FA. Apres
        // verification reussie, on re-execute la requete originale.
        return _origFetch(input, init).then(resp => {
            if (resp.status !== 403) return resp;
            const clone = resp.clone();
            return clone.json().then(j => {
                if (j && j.step_up_required && j.action && window.rwOpenStepUpModal) {
                    return window.rwOpenStepUpModal(j.action).then(ok => {
                        if (ok) return _origFetch(input, init);  // retry
                        return resp;  // user annule : on rend la 403 originale
                    });
                }
                return resp;
            }).catch(() => resp);
        });
    };
})();

// ── Step-up 2FA modal (Patch A04-INSEC-N4) — RETIREE, voir E-456 ci-dessous ──
// Ce bloc DECRIVAIT le flux : window.fetch ouvrait la modale sur un 403 portant
// {step_up_required: true, action}, elle demandait le code TOTP, POSTait sur
// /auth/step_up_verify.php, puis rejouait la requete. Ce flux n'existe plus —
// son verificateur est archive. Le wrapper rend desormais la 403 telle quelle.
// ══ E-456 : LA MODALE DE STEP-UP EST RETIREE — le verificateur n'existe plus ══
//
// Cette fonction ouvrait une modale TOTP et POSTait sur
// `/auth/step_up_verify.php`. Ce fichier a ete ARCHIVE le 2026-09-05 a 12:46
// (`de9669c`, « vague 1 — 28 fichiers retires du service ») : le POST rendait
// donc 404, et l'utilisateur ne pouvait pas achever son geste.
//
// ⚠ L'archivage a emporte UNE MOITIE D'UNE PAIRE : le verificateur est parti,
// le poseur `legacy/auth/step_up.php` est reste servi, et `api_proxy.php:69`
// continue de repondre 403 + `step_up_required`. Le declencheur n'est pas un
// appel nomme — c'est le wrapper `window.fetch` ci-dessus, actif sur toute page
// qui charge `menu.php`. Aucun `grep` du nom de cette fonction ne l'aurait
// trouve.
//
// ══ POURQUOI RETIRER L'APPELANT PLUTOT QUE RESTAURER LE VERIFICATEUR ══
//
// 1. Le sens de la panne est FERME : les trois gestes gardes par le step-up
//    (`/policy/{sudo,sftp}/{deploy,remove}` et `/policy/rollback`, qui donnent
//    de facto root sur la machine cible) sont REFUSES. Ce n'est pas un trou.
//
// 2. Le PORTAGE porte la capacite : `politiques.js:237` compose
//    `/policy/sudo/<geste>` et `acces-sftp.js:216` compose `/policy/sftp/<geste>`
//    — en URL construite. Retirer d'ici ne perd rien au niveau du PRODUIT,
//    seulement au niveau d'un portail qu'on eteint.
//
// 3. ⚠ ET RESTAURER LE VERIFICATEUR RE-ARMERAIT UN GESTE DE PRODUCTION :
//    `tests/e2e/go-policies.mjs:131` POSTe `/api_proxy.php/policy/sudo/deploy`
//    avec `machine_id: 1` — `srv-zabbix`, la PRODUCTION. Ce POST n'est refuse
//    aujourd'hui que PAR EFFET DE L'ARCHIVAGE, pas par une garde. Restaurer le
//    verificateur le rendrait vivant, et cette suite n'est dans aucune liste du
//    runner : aucun lot ne le revelerait.
//
// Le wrapper ci-dessus teste `&& window.rwOpenStepUpModal` avant d'appeler : en
// l'absence de cette fonction il rend la 403 d'origine, inchangee. Le refus
// reste donc lisible, et il cesse d'etre un 404.

/**
 * Formate une date vers la timezone locale du navigateur.
 * - Accepte ISO 8601 avec Z (UTC) ou format MySQL "YYYY-MM-DD HH:MM:SS"
 *   qu'on interprete comme UTC (le backend tourne en UTC en Docker par defaut).
 * - Retourne `fallback` si l'input est vide / invalide.
 */
window.fmtLocalDate = function(v, fallback = '-') {
    if (!v) return fallback;
    let iso = String(v);
    if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(iso) && !/[zZ]$|[+-]\d{2}:?\d{2}$/.test(iso)) {
        iso = iso.replace(' ', 'T') + 'Z';
    }
    const d = new Date(iso);
    if (isNaN(d.getTime())) return fallback;
    return d.toLocaleString(navigator.language || 'fr-FR', {
        day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
    });
};
