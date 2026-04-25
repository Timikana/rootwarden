// utils.js - helpers JS partages entre toutes les pages.
// Charge depuis menu.php avant les scripts specifiques.

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
