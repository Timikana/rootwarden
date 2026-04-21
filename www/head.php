<?php
/**
 * head.php - Fragment <head> commun à toutes les pages de l'application
 *
 * Rôle       : Inclus par require_once dans le <head> de chaque page PHP.
 *              Charge Tailwind CSS (CDN), configure le dark mode, et injecte
 *              en JavaScript les variables d'environnement nécessaires au
 *              frontend (URL de l'API, branding white-label, etc.).
 *
 * Dépendances : includes/lang.php pour l'internationalisation (i18n).
 *               Les valeurs proviennent exclusivement des variables
 *               d'environnement Docker/système.
 *
 * Sécurité   : Toutes les valeurs exposées au JS sont passées par json_encode()
 *              qui échappe les caractères spéciaux (HTML et Unicode) - pas de
 *              risque d'injection XSS via les variables d'environnement.
 *
 * Variables d'environnement lues :
 *   API_URL      - URL de base de l'API Python backend
 *   URL_HTTP     - URL HTTP publique de l'application
 *   URL_HTTPS    - URL HTTPS publique de l'application
 *   API_KEY      - Clé d'authentification vers l'API backend
 *   APP_NAME     - Nom de l'application (white-label, défaut : RootWarden)
 *   APP_TAGLINE  - Accroche affichée sous le nom (white-label)
 *   APP_COMPANY  - Nom de l'entreprise cliente (white-label)
 */
require_once __DIR__ . '/includes/lang.php';
?>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/png" sizes="32x32" href="/img/favicon.png">
<link rel="apple-touch-icon" href="/img/favicon.png">
<meta name="theme-color" content="#ffffff">
<?php
// CSRF token expose en meta pour les fetch JS et les tests E2E.
// Utilise par htmx (via configRequest ligne 75), par les scripts des modules
// (bashrc.js, graylog.js, wazuh.js, etc.) et par les endpoints PHP appelant
// checkCsrfToken() qui supporte le header X-CSRF-TOKEN.
// Session garantie active car lang.php a appele session_start() en amont.
if (session_status() === PHP_SESSION_NONE) { session_start(); }
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
<link rel="stylesheet" href="/assets/css/tailwind.css?v=<?= filemtime(__DIR__ . '/assets/css/tailwind.css') ?>">
<script src="/js/htmx.min.js"></script>
<?php
// ── Variables d'environnement exposées au JavaScript ─────────────────────────
// Ces variables permettent au frontend de connaître les URLs et le branding
// sans avoir à dupliquer la configuration côté PHP et côté JS.
// APP_NAME, APP_COMPANY, APP_TAGLINE permettent le white-label complet.
// API_URL pointe vers le proxy PHP pour éviter les problèmes CORS
// entre le navigateur et le backend Python (Hypercorn ASGI).
// API_URL_DIRECT conserve l'URL directe pour usage côté serveur PHP.
$_headVars = [
    'API_URL'        => '/api_proxy.php',
    'API_URL_DIRECT' => getenv('API_URL')     ?: '',
    'URL_HTTP'       => getenv('URL_HTTP')    ?: '',
    'URL_HTTPS'      => getenv('URL_HTTPS')   ?: '',
    'API_KEY'        => '',  // Masquée côté client - le proxy PHP injecte la clé côté serveur
    'APP_NAME'       => getenv('APP_NAME')    ?: 'RootWarden',
    'APP_TAGLINE'    => getenv('APP_TAGLINE') ?: 'Gestion SSH centralisée',
    'APP_COMPANY'    => getenv('APP_COMPANY') ?: '',
];
// Injection sécurisée : json_encode() échappe les guillemets, balises et
// caractères Unicode - aucune valeur d'env ne peut injecter du JS arbitraire.
echo '<script>';
foreach ($_headVars as $k => $v) {
    echo "window.{$k} = " . json_encode((string) $v) . ";\n";
}
echo "window.LANG = " . json_encode(getLang()) . ";\n";
echo "window._i18n = " . json_encode(getJsTranslations('js.'), JSON_UNESCAPED_UNICODE) . ";\n";
echo "function __(key, params) {\n";
echo "    let s = window._i18n['js.' + key] || window._i18n[key] || key;\n";
echo "    if (params) Object.keys(params).forEach(k => { s = s.replace(':' + k, params[k]); });\n";
echo "    return s;\n";
echo "}\n";
echo '</script>';
?>
<script>
    // ── htmx : CSRF token global ──────────────────────────────────────────────
    // Injecte automatiquement le token CSRF dans tous les requests htmx.
    document.addEventListener('htmx:configRequest', function(evt) {
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content
                   || '<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>';
        if (csrf) evt.detail.parameters['csrf_token'] = csrf;
    });
    // Affiche un toast sur les reponses htmx avec header HX-Trigger contenant showToast
    document.addEventListener('showToast', function(evt) {
        const d = evt.detail || {};
        toast(d.message || 'OK', d.type || 'success');
    });

    // ── Application immédiate du thème (évite le flash blanc au chargement) ──
    // Le toggle complet est dans menu.php (bouton + localStorage).
    (function() {
        const s = localStorage.getItem('theme');
        const d = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (s === 'dark' || (!s && d)) document.documentElement.classList.add('dark');
    })();
</script>
<style>
/* ── Mise en page flexbox globale ──────────────────────────────────────────────
   Garantit que le footer reste toujours en bas de page, même si le contenu
   principal est court (layout "sticky footer" sans position: fixed). */
html {
    min-height: 100%;
    display: flex;
    flex-direction: column;
}

body {
    flex: 1;
    display: flex;
    flex-direction: column;
    margin: 0;
}

main {
    flex: 1; /* Le contenu prend tout l'espace disponible entre nav et footer */
}

footer {
    margin-top: auto;
}

/* ── Scrollbar discrete - global (sidebar, tableaux, modals, editeurs) ───── */
/* Webkit (Chrome, Edge, Safari) */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(128,128,128,0.3); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(128,128,128,0.5); }
/* Sidebar encore plus fin */
#sidebar ::-webkit-scrollbar { width: 4px; }
#sidebar ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); }
#sidebar ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.25); }
/* Firefox */
* { scrollbar-width: thin; scrollbar-color: rgba(128,128,128,0.3) transparent; }
#sidebar * { scrollbar-color: rgba(255,255,255,0.1) transparent; }

/* Toast notifications */
#toast-container { position: fixed; top: 4.5rem; right: 1rem; z-index: 9999; display: flex; flex-direction: column; gap: 0.5rem; pointer-events: none; }
.toast { pointer-events: auto; max-width: 24rem; padding: 0.75rem 1rem; border-radius: 0.5rem; box-shadow: 0 4px 12px rgba(0,0,0,0.15); font-size: 0.875rem; display: flex; align-items: center; gap: 0.5rem; animation: toast-in 0.3s ease-out; }
.toast.removing { animation: toast-out 0.3s ease-in forwards; }
.toast-success { background: #065f46; color: #d1fae5; }
.toast-error { background: #991b1b; color: #fee2e2; }
.toast-info { background: #1e40af; color: #dbeafe; }
.toast-warning { background: #92400e; color: #fef3c7; }
@keyframes toast-in { from { opacity: 0; transform: translateX(100%); } to { opacity: 1; transform: translateX(0); } }
@keyframes toast-out { from { opacity: 1; transform: translateX(0); } to { opacity: 0; transform: translateX(100%); } }
</style>

<!-- Toast container (global) -->
<div id="toast-container"></div>
<script>
/** Echappe les caracteres HTML pour empecher les injections XSS dans innerHTML. */
function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

/** Affiche une notification toast. Types: 'success', 'error', 'info', 'warning'. Duree en ms (defaut 4s). */
function toast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const icons = { success: '&#10003;', error: '&#10007;', info: '&#8505;', warning: '&#9888;' };
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span>${icons[type] || ''}</span><span>${escHtml(message)}</span>`;
    container.appendChild(el);
    setTimeout(() => { el.classList.add('removing'); setTimeout(() => el.remove(), 300); }, duration);
}
</script>
<script>
// Raccourcis clavier globaux (Ctrl+K = recherche, g+h = dashboard, g+s = SSH, g+u = MaJ, g+c = CVE, g+a = admin)
(function() {
    let gPressed = false, gTimer;
    document.addEventListener('keydown', function(e) {
        // Ignorer si on est dans un input/textarea
        if (['INPUT','TEXTAREA','SELECT'].includes(e.target.tagName)) {
            // Sauf Escape qui ferme la recherche
            if (e.key === 'Escape') {
                const sr = document.getElementById('search-results');
                if (sr) sr.classList.add('hidden');
                e.target.blur();
            }
            return;
        }

        // Ctrl+K ou / → focus recherche
        if ((e.ctrlKey && e.key === 'k') || e.key === '/') {
            e.preventDefault();
            const input = document.getElementById('global-search');
            if (input) { input.focus(); input.select(); }
            return;
        }

        // g + lettre = navigation rapide
        if (e.key === 'g' && !e.ctrlKey && !e.metaKey) {
            gPressed = true;
            clearTimeout(gTimer);
            gTimer = setTimeout(() => gPressed = false, 800);
            return;
        }
        if (gPressed) {
            gPressed = false;
            const routes = {h: '/', s: '/services/', S: '/ssh/', u: '/update/',
                           c: '/security/', a: '/adm/admin_page.php', A: '/ssh-audit/', i: '/iptables/',
                           d: '/documentation.php', p: '/profile.php', r: '/security/compliance_report.php',
                           k: '/adm/platform_keys.php', m: '/adm/server_users.php', v: '/supervision/'};
            if (routes[e.key]) { window.location.href = routes[e.key]; return; }
        }

        // ? = afficher l'aide raccourcis
        if (e.key === '?' && !e.ctrlKey) {
            e.preventDefault();
            const existing = document.getElementById('shortcuts-modal');
            if (existing) { existing.remove(); return; }
            const html = `<div id="shortcuts-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onclick="if(event.target===this)this.remove()">
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-bold text-gray-800 dark:text-gray-200">Raccourcis clavier</h3>
                        <button onclick="this.closest('#shortcuts-modal').remove()" class="text-gray-400 hover:text-gray-600 text-xl">&times;</button>
                    </div>
                    <div class="space-y-2 text-sm">
                        <div class="flex justify-between"><span class="text-gray-500">Recherche</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">Ctrl+K</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Dashboard</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g h</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Services</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g s</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Cles SSH</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g S</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Mises a jour</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g u</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Scan CVE</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g c</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Iptables</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g i</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Administration</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g a</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Audit SSH</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g A</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Supervision</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g v</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Profil</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g p</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Rapport conformite</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g r</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Users distants</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g m</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Cle SSH plateforme</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g k</span></div>
                        <div class="flex justify-between"><span class="text-gray-500">Documentation</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">g d</span></div>
                        <hr class="border-gray-200 dark:border-gray-700">
                        <div class="flex justify-between"><span class="text-gray-500">Aide raccourcis</span><span class="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">?</span></div>
                    </div>
                </div>
            </div>`;
            document.body.insertAdjacentHTML('beforeend', html);
        }
    });
})();
</script>
<?php if (!empty($_SESSION['password_warn_days'])): ?>
<div class="fixed top-0 left-0 right-0 z-[9998] bg-yellow-500 text-yellow-900 text-center text-sm py-1.5 font-medium">
    &#9888; Votre mot de passe expire dans <?= (int)$_SESSION['password_warn_days'] ?> jour<?= $_SESSION['password_warn_days'] > 1 ? 's' : '' ?>.
    <a href="/profile.php" class="underline font-bold ml-1">Changer maintenant</a>
</div>
<?php endif; ?>