/**
 * @file admin.js
 * @description Fonctions JavaScript partagees pour l'administration.
 *
 * Fonctions :
 *   - escHtml()          — Echappe les caracteres HTML (prevention XSS)
 *   - deleteUser()       — Supprime un utilisateur via AJAX
 *   - updateUserStatus() — Met a jour un champ utilisateur (actif, sudo)
 *   - showNotification() — Affiche une notification temporaire
 */

/**
 * Echappe les caracteres HTML dangereux dans une chaine.
 * @param {string} str - Chaine a echapper
 * @returns {string} Chaine avec &, <, >, ", ' echappes
 */
function escHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

/**
 * Supprime un utilisateur apres confirmation.
 * POST /adm/api/delete_user.php
 * @param {number} userId
 * @param {string} userName
 */
function deleteUser(userId, userName) {
    if (!confirm(__('admin_confirm_delete_user', {name: userName}))) return;
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
    fetch('/adm/api/delete_user.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf_token: csrfToken, user_id: userId })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            toast(data.message || __('admin_user_deleted'), 'success');
            setTimeout(() => location.reload(), 800);
        } else {
            toast(data.message || __('error'), 'error');
        }
    })
    .catch(err => toast(__('network_error'), 'error'));
}

/**
 * Met a jour un champ boolean d'un utilisateur (actif, sudo).
 * POST /adm/api/update_user_status.php
 * @param {number} userId
 * @param {string} field
 * @param {boolean} value
 */
function updateUserStatus(userId, field, value) {
    fetch('/adm/api/update_user_status.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId, field: field, value: value ? 1 : 0 })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success !== false) {
            toast(data.message || __('admin_updated'), 'success');
            setTimeout(() => location.reload(), 800);
        } else toast(data.message, 'error');
    })
    .catch(err => toast(__('network_error'), 'error'));
}

/**
 * Affiche une notification temporaire (fallback si toast() n'existe pas).
 * @param {string} message
 * @param {string} type - 'success', 'error', 'info', 'warning'
 */
function showNotification(message, type = 'info') {
    if (typeof toast === 'function') {
        toast(message, type);
        return;
    }
    const el = document.createElement('div');
    el.className = `fixed top-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ${
        type === 'success' ? 'bg-green-600 text-white' :
        type === 'error' ? 'bg-red-600 text-white' :
        'bg-blue-600 text-white'
    }`;
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}
