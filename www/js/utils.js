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
            if (url.indexOf('api_proxy.php') !== -1 && method.toUpperCase() !== 'GET') {
                const token = _csrfToken();
                if (token) {
                    init = init || {};
                    const h = new Headers(init.headers || {});
                    if (!h.has('X-CSRF-TOKEN')) h.set('X-CSRF-TOKEN', token);
                    init.headers = h;
                }
            }
        } catch (_) { /* fail-open : ne casse jamais le fetch */ }
        return _origFetch(input, init);
    };
})();

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
