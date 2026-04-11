<?php
// documentation.php — Documentation technique de RootWarden (accessible à tous les rôles connectés)
require_once __DIR__ . '/auth/verify.php';
require_once __DIR__ . '/auth/functions.php';
require_once __DIR__ . '/db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]); // Tous les utilisateurs connectés

$appVersion = trim(@file_get_contents(__DIR__ . '/version.txt') ?: '1.x');
$appName    = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$role       = (int) ($_SESSION['role_id'] ?? 1);
$isAdmin    = $role >= 2;
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/head.php'; ?>
    <title><?= $appName ?> — Documentation</title>
    <style>
        .doc-anchor { scroll-margin-top: 5rem; }
        .code-block  { background: #1e293b; color: #e2e8f0; border-radius: .5rem; padding: 1rem; font-size: .8rem; overflow-x: auto; white-space: pre; }
        .badge-get   { background: #16a34a; color: #fff; padding: 2px 8px; border-radius: 4px; font-size:.7rem; font-weight:700; }
        .badge-post  { background: #ca8a04; color: #fff; padding: 2px 8px; border-radius: 4px; font-size:.7rem; font-weight:700; }
        nav a:hover  { text-decoration: underline; }
    </style>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/menu.php'; ?>

    <!-- Mise en page 2 colonnes : sidebar + contenu -->
    <div class="flex min-h-screen">

        <!-- ── Sidebar navigation ─────────────────────────────────────────── -->
        <nav class="hidden xl:block fixed left-56 top-0 h-full w-52 bg-white dark:bg-gray-800 shadow-lg overflow-y-auto pt-4 pb-20 z-40">
            <div class="px-4 py-2 text-xs font-bold uppercase text-gray-400 tracking-wider">Navigation</div>
            <ul class="text-sm space-y-1 px-2">
                <li><a href="#intro"         class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Introduction</a></li>
                <li><a href="#architecture"  class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Architecture</a></li>
                <li><a href="#stack"         class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Stack technique</a></li>
                <li><a href="#auth"          class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Authentification & 2FA</a></li>
                <li><a href="#permissions"   class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Permissions & rôles</a></li>
                <li><a href="#ssh"           class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Gestion SSH</a></li>
                <li><a href="#ssh-keypair"   class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Keypair plateforme</a></li>
                <li><a href="#remote-users" class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Users distants</a></li>
                <li><a href="#updates"       class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Mises à jour Linux</a></li>
                <li><a href="#cve-schedules" class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Scans planifiés</a></li>
                <li><a href="#iptables"      class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Pare-feu iptables</a></li>
                <li><a href="#fail2ban"      class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Fail2ban</a></li>
                <li><a href="#cve"           class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Scan CVE</a></li>
                <li><a href="#webhooks"      class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Webhooks</a></li>
                <li><a href="#tags"          class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Tags serveurs</a></li>
                <li><a href="#audit"         class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Journal d'audit</a></li>
                <li><a href="#session"       class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Session & timeout</a></li>
                <li><a href="#crypto"        class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Chiffrement</a></li>
                <li><a href="#migrations"    class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Migrations DB</a></li>
                <li><a href="#ssl"           class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Mode SSL</a></li>
                <li><a href="#branding"      class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">White-label / Branding</a></li>
                <?php if ($isAdmin): ?>
                <li><a href="#api"           class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">API backend</a></li>
                <li><a href="#proxy"         class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Proxy API</a></li>
                <li><a href="#healthcheck"   class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Health Check</a></li>
                <li><a href="#preprod"       class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Env Preprod</a></li>
                <li><a href="#api-test"      class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Tester l'API</a></li>
                <?php endif; ?>
                <li><a href="#troubleshooting" class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Dépannage</a></li>
                <li><a href="#contribute"    class="block px-3 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-gray-700 text-blue-600 dark:text-blue-400">Contribuer</a></li>
            </ul>
        </nav>

        <!-- ── Contenu principal ───────────────────────────────────────────── -->
        <main class="xl:ml-52 flex-1 p-6 max-w-screen-xl mx-auto">

            <!-- En-tête -->
            <div class="bg-gradient-to-br from-blue-600 to-blue-800 dark:from-blue-800 dark:to-blue-950 text-white shadow-lg rounded-xl p-8 text-center mb-8">
                <h1 class="text-4xl font-extrabold">📚 Documentation Technique</h1>
                <p class="text-lg mt-2 text-blue-100">
                    <?= $appName ?> v<?= htmlspecialchars($appVersion) ?> · Comprenez et maîtrisez chaque module.
                </p>
            </div>

            <!-- ────────────────────────────────────────── -->
            <!-- 1. Introduction                           -->
            <!-- ────────────────────────────────────────── -->
            <section id="intro" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Introduction</h2>
                <p class="mb-3">
                    <strong><?= $appName ?></strong> est une plateforme web de gestion centralisée de serveurs Linux.
                    Elle permet à une équipe IT de déployer des clés SSH, lancer des mises à jour APT,
                    gérer les règles de pare-feu, scanner les vulnérabilités CVE et superviser via Zabbix —
                    le tout depuis une interface sécurisée, sans jamais stocker de mot de passe en clair.
                </p>
                <ul class="list-disc list-inside space-y-1 text-sm">
                    <li>Déploiement en 5 minutes avec Docker Compose</li>
                    <li>Chiffrement AES-256 + libsodium pour tous les secrets</li>
                    <li>Authentification multi-facteurs (2FA TOTP)</li>
                    <li>Contrôle d'accès granulaire par utilisateur et par permission (RBAC 3 rôles)</li>
                    <li>Scan CVE en temps réel via <a href="https://www.opencve.io" target="_blank" class="text-blue-500 hover:underline">OpenCVE</a> (cloud ou on-prem v2)</li>
                    <li>Webhooks Slack / Teams / Discord pour les alertes critiques</li>
                    <li>Journal d'audit complet avec export CSV</li>
                    <li>Tags personnalisés sur les serveurs pour filtrer par environnement</li>
                    <li>Session timeout configurable + alertes sécurité sur le dashboard</li>
                    <li>Suivi d'âge des clés SSH (alerte > 90 jours)</li>
                </ul>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 2. Architecture                           -->
            <!-- ────────────────────────────────────────── -->
            <section id="architecture" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Architecture</h2>
                <div class="code-block">┌──────────────────────────────────────────────────────────┐
│              Navigateur (HTTPS :<?= htmlspecialchars(getenv('HTTPS_PORT') ?: '8443') ?>)                    │
└───────────────────────┬──────────────────────────────────┘
                        │ HTTPS / HTTP
┌───────────────────────▼──────────────────────────────────┐
│  PHP 8.2 + Apache  (gestion_ssh_key_php)                │
│  www/ : auth/ adm/ security/ update/ ssh/ iptables/     │
│  Réseau interne Docker : gestion_ssh_key_network         │
└─────────────┬──────────────────────────┬─────────────────┘
              │ HTTP interne :5000        │ PDO / MySQL
┌─────────────▼────────────┐  ┌──────────▼──────────────────┐
│  Python 3.11 + Flask     │  │  MySQL 9.1                  │
│  (gestion_ssh_key_python) │  │  (gestion_ssh_key_db)       │
│  /api/* — non exposé     │  │  Port interne seulement     │
└─────────────┬────────────┘  └─────────────────────────────┘
              │ SSH (Paramiko)
              ▼
        Serveurs Linux gérés (Debian / Ubuntu)</div>
                <ul class="mt-4 space-y-1 text-sm">
                    <li>Le backend Python est <strong>uniquement accessible depuis le réseau Docker</strong> — non exposé sur l'hôte.</li>
                    <li>Toutes les routes Python exigent le header <code>X-API-KEY</code>.</li>
                    <li>MySQL est lui aussi interne — pas de port exposé en production.</li>
                    <li>Les mots de passe root SSH sont chiffrés en BDD avant tout stockage.</li>
                </ul>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 3. Stack technique                        -->
            <!-- ────────────────────────────────────────── -->
            <section id="stack" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Stack technique</h2>
                <div class="grid grid-cols-2 sm:grid-cols-3 gap-4 text-sm">
                    <?php
                    $stack = [
                        ['PHP 8.2', 'Frontend — sessions, CSRF, PDO', '/img/logos/new-php-logo.svg'],
                        ['Python 3.11', 'Backend Flask — SSH, CVE, iptables', '/img/logos/python-logo.png'],
                        ['MySQL 9.1', 'Base de données relationnelle', null],
                        ['TailwindCSS', 'UI responsive + dark mode', '/img/logos/Tailwind_CSS_Logo.svg'],
                        ['JavaScript', 'Streaming, dynamisme UI', '/img/logos/JavaScript-logo.png'],
                        ['Docker', 'Conteneurisation + Compose', '/img/logos/docker-logo-blue.svg'],
                        ['libsodium', 'Chiffrement XSalsa20-Poly1305', '/img/logos/sodium-logo.png'],
                        ['Paramiko', 'Client SSH Python', null],
                        ['OpenCVE', 'Base de données CVE (REST API)', null],
                    ];
                    foreach ($stack as [$name, $desc, $logo]):
                    ?>
                    <div class="flex items-center gap-3 bg-gray-50 dark:bg-gray-700 rounded-lg p-3">
                        <?php if ($logo): ?>
                        <img src="<?= $logo ?>" alt="<?= htmlspecialchars($name) ?>" class="h-8 w-8 object-contain flex-shrink-0">
                        <?php else: ?>
                        <div class="h-8 w-8 flex-shrink-0 bg-blue-100 dark:bg-blue-900 rounded flex items-center justify-center text-blue-600 font-bold text-xs"><?= substr($name,0,2) ?></div>
                        <?php endif; ?>
                        <div>
                            <div class="font-semibold"><?= htmlspecialchars($name) ?></div>
                            <div class="text-xs text-gray-500 dark:text-gray-400"><?= htmlspecialchars($desc) ?></div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 4. Authentification & 2FA                 -->
            <!-- ────────────────────────────────────────── -->
            <section id="auth" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Authentification & 2FA</h2>
                <h3 class="font-semibold mb-2">Flux de connexion</h3>
                <ol class="list-decimal list-inside space-y-1 text-sm mb-4">
                    <li>L'utilisateur soumet login + mot de passe sur <code>/auth/login.php</code></li>
                    <li>Le hash bcrypt stocké en BDD est vérifié avec <code>password_verify()</code></li>
                    <li>Si 2FA activé → redirection vers <code>/auth/verify_2fa.php</code> (code TOTP 6 chiffres)</li>
                    <li><code>initializeUserSession()</code> crée la session, régénère l'ID, génère un token CSRF, charge les permissions</li>
                    <li>"Se souvenir de moi" → token aléatoire hashé dans <code>remember_tokens</code>, cookie <code>HttpOnly + Secure + SameSite=Strict</code></li>
                </ol>
                <h3 class="font-semibold mb-2">2FA TOTP</h3>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li>Compatible Google Authenticator, Authy, Bitwarden Authenticator…</li>
                    <li>Activation : <strong>Profil → Activer le 2FA</strong> → scanner le QR code</li>
                    <li>Réinitialisation admin : <code>/auth/reset_totp.php</code> (admin/superadmin seulement)</li>
                    <li>Algorithme : TOTP-SHA1, fenêtre de 30 secondes</li>
                </ul>
                <h3 class="font-semibold mt-4 mb-2">Protection des sessions</h3>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li>Régénération de l'ID de session à chaque login (protection fixation de session)</li>
                    <li>CSRF token sur tous les formulaires POST — vérifié avec <code>hash_equals()</code></li>
                    <li>Rate limiting : max 5 tentatives / 10 min par IP (table <code>login_attempts</code>)</li>
                    <li>Session timeout : déconnexion automatique après inactivité (<code>SESSION_TIMEOUT</code>, défaut 30 min)</li>
                    <li>Headers de sécurité : CSP, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy</li>
                </ul>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 5. Permissions & rôles                    -->
            <!-- ────────────────────────────────────────── -->
            <section id="permissions" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Permissions & rôles</h2>
                <p class="text-sm mb-3">3 rôles + permissions fines stockées dans la table <code>permissions</code>.</p>
                <div class="overflow-x-auto">
                <table class="w-full text-sm border-collapse">
                    <thead class="bg-blue-800 text-white">
                        <tr>
                            <th class="p-2 text-left">Permission</th>
                            <th class="p-2 text-left">Description</th>
                            <th class="p-2 text-center">user (1)</th>
                            <th class="p-2 text-center">admin (2)</th>
                            <th class="p-2 text-center">superadmin (3)</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        <?php foreach ([
                            ['can_deploy_keys',         'si accorde', '✓', '✓', 'Deployer les cles SSH'],
                            ['can_update_linux',        'si accorde', '✓', '✓', 'MaJ APT, dry-run, paquets'],
                            ['can_manage_iptables',     'si accorde', '✓', '✓', 'Regles firewall'],
                            ['can_manage_fail2ban',     'si accorde', '✓', '✓', 'Gestion bans IP Fail2ban'],
                            ['can_admin_portal',        'si accorde', '✓', '✓', 'Page administration'],
                            ['can_scan_cve',            'si accorde', 'si accorde', '✓', 'Scan vulnerabilites'],
                            ['can_manage_remote_users', 'si accorde', 'si accorde', '✓', 'Supprimer cles/users distants'],
                            ['can_manage_platform_key', 'si accorde', 'si accorde', '✓', 'Keypair plateforme'],
                            ['can_view_compliance',     'si accorde', 'si accorde', '✓', 'Rapport de conformite'],
                            ['can_manage_backups',      'si accorde', 'si accorde', '✓', 'Backups BDD'],
                            ['can_schedule_cve',        'si accorde', 'si accorde', '✓', 'Planifier scans CVE'],
                        ] as [$perm, $u, $a, $sa, $desc]): ?>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td class="p-2 font-mono text-blue-700 dark:text-blue-300 text-xs"><?= $perm ?></td>
                            <td class="p-2 text-xs text-gray-500"><?= $desc ?></td>
                            <td class="p-2 text-center text-gray-500"><?= $u ?></td>
                            <td class="p-2 text-center text-green-600 font-bold"><?= $a ?></td>
                            <td class="p-2 text-center text-green-600 font-bold"><?= $sa ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                </div>
                <p class="text-xs text-gray-500 dark:text-gray-400 mt-3">
                    Le superadmin court-circuite toujours la verification de permissions.<br>
                    Gestion : <strong>Administration &rarr; Droits d'acces</strong> (10 permissions, checkboxes)<br>
                    PHP : <code>checkPermission('can_scan_cve')</code> — affiche une page 403 stylisee si refuse.<br>
                    <strong>Filtrage par machine</strong> : les users (role=1) ne voient que les serveurs
                    de <code>user_machine_access</code>. Les admins/superadmins voient tout.<br>
                    <strong>Proxy API securise</strong> : <code>api_proxy.php</code> transmet <code>X-User-ID</code>
                    et <code>X-User-Role</code> au backend Python. Le decorateur <code>@require_machine_access</code>
                    verifie l'acces machine cote backend.<br>
                    <strong>Permissions temporaires</strong> : un admin peut accorder une permission pour 1h a 30 jours.
                    L'acces expire automatiquement. Table <code>temporary_permissions</code>, purge automatique
                    par le scheduler. API : <code>GET/POST/DELETE /admin/temp_permissions</code>.
                </p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 6. Gestion SSH                            -->
            <!-- ────────────────────────────────────────── -->
            <section id="ssh" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Gestion SSH</h2>
                <h3 class="font-semibold mb-2">Déploiement de clés</h3>
                <ol class="list-decimal list-inside text-sm space-y-1 mb-3">
                    <li>Sélectionnez les machines cibles dans l'interface</li>
                    <li>Le frontend PHP appelle <code>POST /deploy_keys</code> sur le backend Python</li>
                    <li>Python se connecte en SSH avec les credentials chiffrés de la BDD</li>
                    <li>La clé publique est ajoutée à <code>~/.ssh/authorized_keys</code> pour chaque utilisateur autorisé</li>
                    <li>Les résultats sont streamés en temps réel (JSON-lines)</li>
                </ol>
                <h3 class="font-semibold mb-2">Connexion root</h3>
                <p class="text-sm">Le backend utilise <code>execute_as_root()</code> qui essaie d'abord <code>sudo -S</code> (recommandé),
                puis bascule automatiquement sur <code>su root -c</code> si sudo est absent.
                Le mot de passe est toujours transmis via stdin, jamais dans la commande.</p>
                <h3 class="font-semibold mt-3 mb-2">Suivi d'âge des clés (v1.6.0)</h3>
                <p class="text-sm mb-2">La colonne <code>ssh_key_updated_at</code> enregistre la date de dernière modification de la clé SSH.
                Un badge rouge apparaît dans l'administration quand une clé a plus de <strong>90 jours</strong>. Le dashboard affiche une alerte globale.</p>
                <h3 class="font-semibold mt-3 mb-2">Timeout SSH</h3>
                <p class="text-sm">Configurable via <code>SSH_TIMEOUT</code> (défaut : 360 secondes). Utile pour les mises à jour longues.</p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 6b. Keypair plateforme                    -->
            <!-- ────────────────────────────────────────── -->
            <section id="ssh-keypair" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Keypair plateforme (v1.7.0)</h2>
                <p class="text-sm mb-3">
                    RootWarden utilise une paire de cles Ed25519 pour s'authentifier aupres des serveurs distants
                    <strong>sans stocker de password SSH en BDD</strong>. La cle privee reste dans un volume Docker
                    nomme et n'est jamais exposee.
                </p>
                <h3 class="font-semibold mb-2">Architecture</h3>
                <div class="code-block mb-3">AVANT :  RootWarden --[password BDD]--> Serveur (risque si BDD compromise)
APRES :  RootWarden --[keypair Ed25519]--> Serveur (zero password en transit)
         Le root_password reste en BDD uniquement pour sudo -S</div>
                <h3 class="font-semibold mb-2">Cycle de migration</h3>
                <ol class="list-decimal list-inside text-sm space-y-1 mb-3">
                    <li>La keypair est generee au demarrage du backend Python (idempotent)</li>
                    <li>L'admin deploie la pubkey sur les serveurs via <strong>Administration → Cle SSH</strong></li>
                    <li>RootWarden teste la connexion en keypair automatiquement</li>
                    <li>Une fois validee, le password SSH peut etre supprime de la BDD</li>
                    <li>Toutes les operations futures utilisent la keypair (fallback password si echec)</li>
                </ol>
                <h3 class="font-semibold mb-2">Scan des utilisateurs distants</h3>
                <p class="text-sm mb-2">Le bouton "Users" dans la page Cle SSH permet de scanner les utilisateurs
                presents sur un serveur distant et de verifier quelles cles sont deployees.</p>
                <h3 class="font-semibold mb-2">API</h3>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li><code>GET /platform_key</code> — Recupere la pubkey de la plateforme</li>
                    <li><code>POST /deploy_platform_key</code> — Deploie la pubkey sur les serveurs selectionnes</li>
                    <li><code>POST /test_platform_key</code> — Teste la connexion keypair</li>
                    <li><code>POST /remove_ssh_password</code> — Supprime le password SSH de la BDD</li>
                    <li><code>POST /regenerate_platform_key</code> — Regenere la keypair (re-deploiement requis)</li>
                    <li><code>POST /scan_server_users</code> — Liste les utilisateurs distants avec leurs cles</li>
                </ul>
                <p class="text-xs text-gray-500 mt-3">
                    Page admin : <code>/adm/platform_keys.php</code> ·
                    Backend : <code>ssh_key_manager.py</code> ·
                    Volume : <code>platform_ssh_keys</code>
                </p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 6c. Gestion des utilisateurs distants     -->
            <!-- ────────────────────────────────────────── -->
            <section id="remote-users" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Utilisateurs distants</h2>
                <p class="text-sm mb-3">
                    La page <code>/adm/server_users.php</code> permet de gerer les utilisateurs Linux
                    presents sur chaque serveur distant. Elle scanne <code>/etc/passwd</code> via SSH
                    et affiche les cles SSH de chaque utilisateur.
                </p>
                <h3 class="font-semibold mb-2">Actions disponibles</h3>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li><strong>Supprimer les cles RootWarden</strong> — Retire uniquement les cles deployees
                        par RootWarden (<code>sed -i '/rootwarden/d' authorized_keys</code>)</li>
                    <li><strong>Supprimer toutes les cles</strong> — Vide completement le fichier
                        <code>authorized_keys</code> de l'utilisateur</li>
                    <li><strong>Supprimer l'utilisateur</strong> — Execute <code>userdel</code> sur le serveur
                        distant, avec option <code>-r</code> pour supprimer le home si demande</li>
                    <li><strong>Exclure</strong> — Ajoute l'utilisateur a la table <code>user_exclusions</code>
                        pour ne plus le cibler lors des synchronisations</li>
                </ul>
                <h3 class="font-semibold mb-2">Protections</h3>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li>Les utilisateurs systeme (root, daemon, www-data...) ne peuvent pas etre supprimes</li>
                    <li>L'utilisateur SSH de connexion au serveur ne peut pas etre supprime</li>
                    <li>La suppression d'un utilisateur Linux demande une double confirmation</li>
                </ul>
                <h3 class="font-semibold mb-2">API</h3>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li><code>POST /scan_server_users</code> — Scanne les users (avec champ <code>excluded</code>)</li>
                    <li><code>POST /remove_user_keys</code> — Supprime les cles (mode <code>all</code> ou <code>rootwarden_only</code>)</li>
                    <li><code>POST /delete_remote_user</code> — Supprime l'utilisateur Linux (<code>userdel</code>)</li>
                </ul>
                <p class="text-xs text-gray-500 mt-3">
                    Page admin : <code>/adm/server_users.php</code> · Backend : <code>routes/ssh.py</code>
                </p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 7. Mises à jour Linux                     -->
            <!-- ────────────────────────────────────────── -->
            <section id="updates" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Mises à jour Linux</h2>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li>Commandes exécutées : <code>apt-get update</code> + <code>apt-get upgrade -y</code> (en root via sudo/su)</li>
                    <li>Résultats streamés en temps réel ligne par ligne dans l'interface</li>
                    <li>Filtrage des serveurs par <strong>tags</strong> (dropdown) ou par environnement / criticité</li>
                    <li>Actions rapides : Versions OS, Statuts, Dernier boot, <strong>Dry-run</strong>, MàJ APT, MàJ Sécurité</li>
                    <li>Planification possible via la table <code>update_schedules</code> (<code>scheduling.php</code>)</li>
                    <li>Détection automatique de la version Linux et mise à jour en BDD (<code>linux_versions</code>)</li>
                    <li>Fallback <code>su -c</code> automatique si sudo absent sur le serveur cible</li>
                </ul>
                <h3 class="font-semibold mb-2">Zabbix</h3>
                <p class="text-sm">L'onglet Zabbix de la page mises à jour permet d'installer et configurer l'agent Zabbix sur les serveurs sélectionnés.
                La version installée est enregistrée dans <code>machines.zabbix_agent_version</code>.</p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 8. Pare-feu iptables                      -->
            <!-- ────────────────────────────────────────── -->
            <section id="iptables" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Pare-feu iptables</h2>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li><strong>Lecture</strong> : <code>iptables -L -v -n</code> + <code>ip6tables</code> + lecture des fichiers <code>rules.v4</code> / <code>rules.v6</code></li>
                    <li><strong>Écriture</strong> : les règles sont encodées en base64 et écrites via <code>printf | base64 -d ></code> (pas d'injection possible)</li>
                    <li><strong>Application</strong> : <code>iptables-restore &lt; rules.v4</code> — persistant au redémarrage</li>
                    <li>IPv4 et IPv6 supportés simultanément</li>
                    <li>Permissions requises : <code>can_manage_iptables</code></li>
                </ul>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 8b. Fail2ban                              -->
            <!-- ────────────────────────────────────────── -->
            <section id="fail2ban" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Fail2ban</h2>
                <p class="text-sm mb-3">Gestion centralisee de Fail2ban sur les serveurs distants. Detection automatique des services, activation de jails, monitoring des IPs bannies.</p>

                <h3 class="font-semibold mb-2">Services detectes</h3>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li><strong>SSH</strong> : jail <code>sshd</code></li>
                    <li><strong>FTP</strong> : jails <code>vsftpd</code>, <code>proftpd</code>, <code>pure-ftpd</code></li>
                    <li><strong>Apache</strong> : jails <code>apache-auth</code>, <code>apache-badbots</code>, <code>apache-noscript</code></li>
                    <li><strong>Nginx</strong> : jails <code>nginx-http-auth</code>, <code>nginx-botsearch</code>, <code>nginx-bad-request</code></li>
                    <li><strong>Mail</strong> : jails <code>postfix</code>, <code>postfix-sasl</code>, <code>dovecot</code></li>
                </ul>

                <h3 class="font-semibold mb-2">Actions disponibles</h3>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li><strong>Installer</strong> Fail2ban si absent (<code>apt-get install -y fail2ban</code>)</li>
                    <li><strong>Activer/desactiver</strong> un jail avec config personnalisee (maxretry, bantime, findtime)</li>
                    <li><strong>Ban/unban</strong> une IP manuellement dans un jail</li>
                    <li><strong>Voir la config</strong> : lecture de <code>/etc/fail2ban/jail.local</code></li>
                    <li><strong>Redemarrer</strong> le service apres modification</li>
                    <li><strong>Whitelist IP</strong> : ajouter/supprimer des IPs jamais bannies (ignoreip)</li>
                    <li><strong>Debannir tout</strong> : vider toutes les IPs bannies d'un jail en un clic</li>
                    <li><strong>Ban global</strong> : bannir une IP sur tous les serveurs simultanement</li>
                    <li><strong>Templates</strong> : presets Permissif / Modere / Strict pour la config des jails</li>
                    <li><strong>Logs</strong> : consulter /var/log/fail2ban.log en direct</li>
                    <li><strong>Stats</strong> : graphique des bans/unbans sur 30 jours</li>
                    <li><strong>GeoIP</strong> : pays d'origine des IPs bannies (drapeau + nom)</li>
                    <li><strong>Install global</strong> : installer Fail2ban sur tous les serveurs en un clic</li>
                </ul>

                <h3 class="font-semibold mb-2">API endpoints</h3>
                <div class="overflow-x-auto mb-3">
                    <table class="w-full text-xs">
                        <thead><tr class="border-b dark:border-gray-700"><th class="text-left py-1 px-2">Route</th><th class="text-left py-1 px-2">Methode</th><th class="text-left py-1 px-2">Description</th></tr></thead>
                        <tbody class="text-gray-600 dark:text-gray-400">
                            <tr><td class="py-1 px-2"><code>/fail2ban/status</code></td><td>POST</td><td>Statut global (installed, running, jails)</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/jail</code></td><td>POST</td><td>Detail jail (IPs bannies, config)</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/install</code></td><td>POST</td><td>Installer fail2ban</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/ban</code></td><td>POST</td><td>Bannir une IP</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/unban</code></td><td>POST</td><td>Debannir une IP</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/restart</code></td><td>POST</td><td>Redemarrer le service</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/config</code></td><td>POST</td><td>Lire jail.local</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/history</code></td><td>GET</td><td>Historique bans/unbans</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/services</code></td><td>POST</td><td>Detecter services + jails disponibles</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/enable_jail</code></td><td>POST</td><td>Activer un jail (+ config)</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/disable_jail</code></td><td>POST</td><td>Desactiver un jail</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/whitelist</code></td><td>POST</td><td>Gerer la whitelist ignoreip (list/add/remove)</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/unban_all</code></td><td>POST</td><td>Debannir toutes les IPs d'un jail</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/ban_all_servers</code></td><td>POST</td><td>Bannir une IP sur tous les serveurs (admin+)</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/templates</code></td><td>GET</td><td>Templates de config (permissif/modere/strict)</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/logs</code></td><td>POST</td><td>Lire /var/log/fail2ban.log</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/stats</code></td><td>GET</td><td>Stats bans/unbans par jour (timeline)</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/install_all</code></td><td>POST</td><td>Installer sur tous les serveurs sans F2B</td></tr>
                            <tr><td class="py-1 px-2"><code>/fail2ban/geoip</code></td><td>POST</td><td>Lookup pays d'une IP (GeoIP)</td></tr>
                        </tbody>
                    </table>
                </div>

                <h3 class="font-semibold mb-2">Securite</h3>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li>Validation stricte des noms de jails : regex <code>^[a-zA-Z0-9_-]+$</code> (anti-injection commande)</li>
                    <li>Validation IP via <code>ipaddress.ip_address()</code> Python (IPv4 + IPv6)</li>
                    <li>Ecriture config via base64 encode (pas d'interpolation shell directe)</li>
                    <li>Permission requise : <code>can_manage_fail2ban</code></li>
                    <li>Historique d'audit : chaque ban/unban enregistre en BDD avec auteur</li>
                </ul>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 9. Scan CVE                               -->
            <!-- ────────────────────────────────────────── -->
            <section id="cve" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Scan CVE (OpenCVE)</h2>
                <h3 class="font-semibold mb-2">Prérequis</h3>
                <p class="text-sm mb-3">Un compte <a href="https://www.opencve.io" target="_blank" class="text-blue-500 hover:underline">opencve.io</a> (gratuit) ou une instance on-prem v2.
                Renseignez <code>OPENCVE_URL</code> + authentification dans l'environnement :</p>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li><strong>Cloud (opencve.io)</strong> : <code>OPENCVE_USERNAME</code> + <code>OPENCVE_PASSWORD</code> (Basic Auth)</li>
                    <li><strong>On-prem v2</strong> : <code>OPENCVE_TOKEN</code> (Bearer token, prioritaire si défini)</li>
                </ul>

                <h3 class="font-semibold mb-2">Déroulement d'un scan</h3>
                <ol class="list-decimal list-inside text-sm space-y-1 mb-3">
                    <li>Connexion SSH au serveur cible</li>
                    <li>Listage des paquets : <code>dpkg-query -W -f='${Package} ${Version}\n'</code> (sans droits root)</li>
                    <li>Détection vendor OS (debian/ubuntu) via <code>/etc/os-release</code></li>
                    <li>Pour chaque paquet : requête OpenCVE API avec cache TTL (<code>CVE_CACHE_TTL</code>)</li>
                    <li>Filtrage par seuil CVSS (<code>CVE_MIN_CVSS</code> : 0 / 4 / 7 / 9)</li>
                    <li>Streaming temps réel vers le navigateur (JSON-lines)</li>
                    <li>Persistance en BDD (<code>cve_scans</code> + <code>cve_findings</code>)</li>
                    <li>Envoi email HTML si <code>MAIL_ENABLED=true</code></li>
                </ol>

                <h3 class="font-semibold mb-2">Format des événements streaming</h3>
                <div class="code-block">{"type": "start",    "machine_id": 1, "machine_name": "web01", "packages_total": 150}
{"type": "progress", "package": "openssl", "count": 42}
{"type": "finding",  "package": "openssl", "version": "1.1.1", "cve_id": "CVE-2023-...", "cvss": 9.8, "summary": "..."}
{"type": "done",     "machine_id": 1, "findings": 3, "packages_scanned": 150, "scan_id": 12}
{"type": "error",    "message": "..."}</div>

                <h3 class="font-semibold mt-3 mb-2">Interface (v1.6.0)</h3>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li><strong>Résumé global</strong> — Bandeau en haut de page avec total CRITICAL / HIGH / MEDIUM</li>
                    <li><strong>Cards collapsées</strong> — 1 ligne par serveur = résumé par année, cliquez pour détailler</li>
                    <li><strong>Filtres par année</strong> — Boutons cliquables qui reconstruisent le tableau depuis la mémoire</li>
                    <li><strong>Recherche</strong> — Par CVE-ID ou nom de paquet dans toutes les findings</li>
                    <li><strong>Pagination</strong> — 50 résultats par page + bouton "Voir plus"</li>
                    <li><strong>Export CSV</strong> — Bouton par serveur (<code>/security/cve_export.php</code>)</li>
                    <li><strong>Déduplication</strong> — Les paquets multiarch (ex: libc6:amd64 + libc6:i386) ne sont scannés qu'une fois</li>
                </ul>

                <h3 class="font-semibold mt-3 mb-2">Accès</h3>
                <p class="text-sm">Page : <code>/security/cve_scan.php</code> · Permission : <code>can_scan_cve</code> (ou superadmin)<br>
                Les utilisateurs de rôle <em>user</em> ne voient que leurs serveurs assignés dans <code>user_machine_access</code>.</p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 9a+. Scans planifies                      -->
            <!-- ────────────────────────────────────────── -->
            <section id="cve-schedules" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Scans CVE planifies</h2>
                <p class="text-sm mb-3">
                    Configurez des scans CVE automatiques via des expressions cron. Un thread daemon verifie
                    toutes les 60 secondes si un scan doit etre lance.
                </p>
                <h3 class="font-semibold mb-2">Expressions cron courantes</h3>
                <div class="overflow-x-auto">
                <table class="w-full text-sm border-collapse mb-4">
                    <thead class="bg-blue-800 text-white">
                        <tr><th class="p-2 text-left">Expression</th><th class="p-2 text-left">Frequence</th></tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        <tr><td class="p-2 font-mono">0 3 * * *</td><td class="p-2">Tous les jours a 3h00</td></tr>
                        <tr><td class="p-2 font-mono">0 2 * * 1</td><td class="p-2">Chaque lundi a 2h00</td></tr>
                        <tr><td class="p-2 font-mono">0 */6 * * *</td><td class="p-2">Toutes les 6 heures</td></tr>
                        <tr><td class="p-2 font-mono">0 0 1 * *</td><td class="p-2">Le 1er de chaque mois a minuit</td></tr>
                    </tbody>
                </table>
                </div>
                <h3 class="font-semibold mb-2">Ciblage</h3>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li><strong>Tous les serveurs</strong> — Scan global (defaut)</li>
                    <li><strong>Par tag</strong> — Ex: tag "production" pour ne scanner que les serveurs de prod</li>
                    <li><strong>Selection manuelle</strong> — Liste d'IDs de machines (JSON)</li>
                </ul>
                <p class="text-xs text-gray-500 mt-3">
                    API : <code>GET/POST/PUT/DELETE /cve_schedules</code> · Table : <code>cve_scan_schedules</code> · Backend : <code>scheduler.py</code>
                </p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 9b. Webhooks                              -->
            <!-- ────────────────────────────────────────── -->
            <section id="webhooks" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Webhooks (Slack / Teams / Discord)</h2>
                <p class="text-sm mb-3">
                    Recevez des alertes automatiques sur vos canaux de communication lorsqu'un événement important se produit.
                </p>
                <h3 class="font-semibold mb-2">Événements supportés</h3>
                <div class="overflow-x-auto">
                <table class="w-full text-sm border-collapse mb-4">
                    <thead class="bg-blue-800 text-white">
                        <tr>
                            <th class="p-2 text-left">Événement</th>
                            <th class="p-2 text-left">Déclencheur</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        <tr><td class="p-2 font-mono">cve_critical</td><td class="p-2">CVE critique (CVSS &ge; 9.0) détectée lors d'un scan</td></tr>
                        <tr><td class="p-2 font-mono">cve_high</td><td class="p-2">CVE haute (CVSS &ge; 7.0) détectée lors d'un scan</td></tr>
                        <tr><td class="p-2 font-mono">deploy_complete</td><td class="p-2">Déploiement de clés SSH terminé</td></tr>
                        <tr><td class="p-2 font-mono">server_offline</td><td class="p-2">Serveur détecté hors ligne lors d'un check status</td></tr>
                        <tr><td class="p-2 font-mono">update_complete</td><td class="p-2">Mise à jour APT terminée</td></tr>
                    </tbody>
                </table>
                </div>
                <h3 class="font-semibold mb-2">Configuration</h3>
                <div class="code-block mb-3"># srv-docker.env
WEBHOOK_ENABLED=true
WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
WEBHOOK_TYPE=slack          # slack | teams | discord | generic
WEBHOOK_EVENTS=cve_critical,cve_high,deploy_complete,server_offline</div>
                <p class="text-sm">Types supportés : <strong>Slack</strong> (Incoming Webhook), <strong>Microsoft Teams</strong> (Incoming Webhook),
                <strong>Discord</strong> (Webhook URL), <strong>Generic</strong> (POST JSON libre).</p>
                <p class="text-xs text-gray-500 mt-2">Code : <code>backend/webhooks.py</code></p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 9c. Tags serveurs                         -->
            <!-- ────────────────────────────────────────── -->
            <section id="tags" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Tags serveurs</h2>
                <p class="text-sm mb-3">
                    Étiquetez vos serveurs avec des tags personnalisés (ex: <em>web</em>, <em>bdd</em>, <em>production</em>, <em>dmz</em>)
                    pour les organiser et les filtrer facilement.
                </p>
                <h3 class="font-semibold mb-2">Utilisation</h3>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li><strong>Ajout / suppression</strong> — Dans chaque carte serveur de l'administration (badges indigo cliquables)</li>
                    <li><strong>Filtrage MàJ Linux</strong> — Dropdown de tags dans la barre de filtres pour ne cibler qu'un groupe</li>
                    <li><strong>API</strong> — <code>GET /filter_servers?tag=production</code> retourne les serveurs filtrés</li>
                </ul>
                <h3 class="font-semibold mb-2">Stockage</h3>
                <p class="text-sm">Table <code>machine_tags</code> (machine_id INT, tag VARCHAR(50)) avec clé unique <code>(machine_id, tag)</code>.
                Migration : <code>006_machine_tags.sql</code>.</p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 9d. Journal d'audit                       -->
            <!-- ────────────────────────────────────────── -->
            <section id="audit" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Journal d'audit</h2>
                <p class="text-sm mb-3">
                    Toutes les actions administratives sont enregistrées dans la table <code>user_logs</code>
                    et consultables depuis <strong>Administration &rarr; Journal d'audit</strong>.
                </p>
                <h3 class="font-semibold mb-2">Actions loguées</h3>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li>Connexion / déconnexion</li>
                    <li>Création / suppression d'utilisateur</li>
                    <li>Toggle actif / inactif, toggle sudo</li>
                    <li>Modification de clé SSH, modification de permissions</li>
                    <li>Ajout / suppression de serveur</li>
                </ul>
                <h3 class="font-semibold mb-2">Fonctionnalités</h3>
                <ul class="list-disc list-inside text-sm space-y-1 mb-3">
                    <li><strong>Filtres</strong> — Par utilisateur et par type d'action</li>
                    <li><strong>Pagination</strong> — 50 entrées par page</li>
                    <li><strong>Export CSV</strong> — Téléchargement complet du journal (<code>?export=csv</code>)</li>
                </ul>
                <p class="text-xs text-gray-500">
                    Page : <code>/adm/audit_log.php</code> · Fonction helper : <code>audit_log($action, $details)</code> dans <code>/adm/includes/audit_log.php</code>
                </p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 9e. Session & timeout                     -->
            <!-- ────────────────────────────────────────── -->
            <section id="session" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Session & timeout</h2>
                <p class="text-sm mb-3">
                    La session utilisateur expire automatiquement après une période d'inactivité.
                    L'utilisateur est redirigé vers la page de login avec un message "Session expirée".
                </p>
                <h3 class="font-semibold mb-2">Configuration</h3>
                <div class="code-block mb-3"># srv-docker.env
SESSION_TIMEOUT=30   # En minutes (défaut : 30)</div>
                <h3 class="font-semibold mb-2">Fonctionnement</h3>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li>Vérifié à chaque requête dans <code>verify.php</code> via <code>$_SESSION['last_activity']</code></li>
                    <li>Si le délai est dépassé : destruction de session + redirection vers <code>/auth/login.php?expired=1</code></li>
                    <li>Chaque page visitée remet le compteur à zéro</li>
                </ul>
                <h3 class="font-semibold mt-3 mb-2">Alertes sécurité (dashboard)</h3>
                <p class="text-sm">Le dashboard affiche 6 alertes automatiques :</p>
                <ul class="list-disc list-inside text-sm space-y-1 mt-1">
                    <li>Utilisateurs sans 2FA activé</li>
                    <li>Utilisateurs sans clé SSH</li>
                    <li>Serveurs hors ligne</li>
                    <li>CVE critiques détectées</li>
                    <li>Serveurs non vérifiés depuis 30+ jours</li>
                    <li>Clés SSH de plus de 90 jours</li>
                </ul>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 10. Chiffrement                           -->
            <!-- ────────────────────────────────────────── -->
            <section id="crypto" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Chiffrement</h2>
                <div class="overflow-x-auto">
                <table class="w-full text-sm border-collapse mb-4">
                    <thead class="bg-blue-800 text-white">
                        <tr>
                            <th class="p-2 text-left">Préfixe BDD</th>
                            <th class="p-2 text-left">Algorithme</th>
                            <th class="p-2 text-left">Quand ?</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        <tr><td class="p-2 font-mono">sodium:</td><td class="p-2">XSalsa20-Poly1305 (libsodium secretbox)</td><td class="p-2">Nouveau chiffrement si libsodium disponible</td></tr>
                        <tr><td class="p-2 font-mono">aes:</td><td class="p-2">AES-256-CBC + IV aléatoire + PKCS7</td><td class="p-2">Fallback ou migration depuis ancien format</td></tr>
                        <tr><td class="p-2 font-mono">(sans préfixe)</td><td class="p-2">AES-256-CBC (ancien format PHP)</td><td class="p-2">Données antérieures à v1.4</td></tr>
                    </tbody>
                </table>
                </div>
                <ul class="text-sm space-y-1">
                    <li>Clés configurées via <code>SECRET_KEY</code> (64 chars hex = 256 bits) et <code>ENCRYPTION_KEY</code></li>
                    <li>Migration de clé : renseignez l'ancienne clé dans <code>OLD_SECRET_KEY</code>, lancez <code>/auth/migrate_crypto.php</code></li>
                    <li>Sodium disponible : <strong><?= function_exists('sodium_crypto_secretbox') ? '✅ Oui' : '❌ Non (fallback AES)' ?></strong></li>
                </ul>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 11. Migrations DB                         -->
            <!-- ────────────────────────────────────────── -->
            <section id="migrations" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Migrations base de données</h2>
                <p class="text-sm mb-3">
                    Les fichiers SQL dans <code>mysql/migrations/</code> sont appliqués automatiquement au démarrage du backend Python.
                    La table <code>schema_migrations</code> enregistre chaque migration appliquée (numéro, checksum, date).
                </p>
                <?php if ($isAdmin): ?>
                <div class="code-block"># État des migrations
docker exec gestion_ssh_key_python python /app/db_migrate.py --status

# Simuler sans appliquer
docker exec gestion_ssh_key_python python /app/db_migrate.py --dry-run

# Appliquer (mode strict = arrêt à la 1ère erreur)
docker exec gestion_ssh_key_python python /app/db_migrate.py --strict</div>
                <?php endif; ?>
                <h3 class="font-semibold mt-4 mb-2">Convention de nommage</h3>
                <div class="code-block">NNN_description_courte.sql   ← numéro séquentiel 3 chiffres + snake_case

mysql/migrations/
├── 001_initial_schema.sql       ← marqueur (appliqué par init.sql)
├── 002_cve_tables.sql           ← tables cve_scans et cve_findings
├── 003_add_can_scan_cve.sql     ← colonne can_scan_cve dans permissions
├── 004_add_user_email.sql       ← colonne email dans users
├── 005_add_ssh_key_date.sql     ← colonne ssh_key_updated_at dans users
├── 006_machine_tags.sql         ← table machine_tags (tags serveurs)
└── 007_cve_scan_schedules.sql   ← scans planifies + historique iptables + whitelist CVE</div>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 12. Mode SSL                              -->
            <!-- ────────────────────────────────────────── -->
            <section id="ssl" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Mode SSL</h2>
                <div class="overflow-x-auto">
                <table class="w-full text-sm border-collapse">
                    <thead class="bg-blue-800 text-white">
                        <tr>
                            <th class="p-2">SSL_MODE</th>
                            <th class="p-2">Comportement</th>
                            <th class="p-2">Usage typique</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td class="p-2 font-mono font-bold">auto</td>
                            <td class="p-2">Certificat auto-signé généré au premier démarrage</td>
                            <td class="p-2">Tests, réseau interne</td>
                        </tr>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td class="p-2 font-mono font-bold">custom</td>
                            <td class="p-2">Vos certificats montés dans <code>./certs/</code></td>
                            <td class="p-2">Let's Encrypt, PKI entreprise</td>
                        </tr>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td class="p-2 font-mono font-bold">disabled</td>
                            <td class="p-2">HTTP uniquement — port 443 inactif</td>
                            <td class="p-2">Derrière Nginx / Traefik / Caddy</td>
                        </tr>
                    </tbody>
                </table>
                </div>
                <p class="text-xs text-gray-500 dark:text-gray-400 mt-3">
                    Mode actuel : <code><?= htmlspecialchars(getenv('SSL_MODE') ?: 'auto') ?></code> ·
                    La configuration Apache est générée dynamiquement par <code>php/entrypoint.sh</code> au démarrage du conteneur.
                </p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 13. White-label / Branding                -->
            <!-- ────────────────────────────────────────── -->
            <section id="branding" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">White-label / Branding</h2>
                <p class="text-sm mb-3">Personnalisez l'interface sans modifier le code — uniquement via les variables d'environnement :</p>
                <div class="overflow-x-auto">
                <table class="w-full text-sm border-collapse">
                    <thead class="bg-blue-800 text-white">
                        <tr>
                            <th class="p-2 text-left">Variable</th>
                            <th class="p-2 text-left">Valeur actuelle</th>
                            <th class="p-2 text-left">Affiché dans…</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        <?php foreach ([
                            ['APP_NAME',    'Nom de l\'application',  'Menu, titres, login'],
                            ['APP_TAGLINE', 'Sous-titre',             'Page de login'],
                            ['APP_COMPANY', 'Nom entreprise/client',  'Menu, footer, login'],
                        ] as [$var, $desc, $location]):
                            $val = getenv($var) ?: '(non défini)';
                        ?>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td class="p-2 font-mono text-blue-700 dark:text-blue-300"><?= $var ?></td>
                            <td class="p-2"><?= htmlspecialchars($val) ?></td>
                            <td class="p-2 text-gray-500"><?= $location ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                </div>
                <p class="text-xs text-gray-500 mt-2">Ces valeurs sont aussi disponibles côté JS via <code>window.APP_NAME</code>, <code>window.APP_TAGLINE</code>, <code>window.APP_COMPANY</code>.</p>
            </section>

            <?php if ($isAdmin): ?>
            <!-- ────────────────────────────────────────── -->
            <!-- 14. API backend (admins uniquement)       -->
            <!-- ────────────────────────────────────────── -->
            <section id="api" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">API backend Python</h2>
                <p class="text-sm text-gray-500 mb-4">
                    Base URL interne : <code>http://python:5000</code> ·
                    Toutes les routes nécessitent <code>X-API-KEY: &lt;API_KEY&gt;</code>
                </p>
                <div class="overflow-x-auto">
                <table class="w-full text-sm border-collapse">
                    <thead class="bg-blue-800 text-white">
                        <tr>
                            <th class="p-2">Méthode</th>
                            <th class="p-2 text-left">Route</th>
                            <th class="p-2 text-left">Description</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                        <?php foreach ([
                            ['GET',  '/list_machines',         'Liste tous les serveurs (JSON)'],
                            ['GET',  '/filter_servers',        'Filtre serveurs par tag (?tag=web)'],
                            ['POST', '/deploy_keys',           'Déploie les clés SSH sur les machines sélectionnées'],
                            ['POST', '/linux_updates',         'Lance apt update/upgrade en streaming'],
                            ['POST', '/linux_version',         'Détecte la version OS (cat /etc/os-release)'],
                            ['POST', '/last_reboot',           'Dernier boot du serveur (uptime -s)'],
                            ['POST', '/get_iptables',          'Lit les règles iptables IPv4 + IPv6'],
                            ['POST', '/apply_iptables',        'Applique de nouvelles règles iptables'],
                            ['POST', '/configure_servers',     'Déploie la config SSH en masse'],
                            ['POST', '/check_servers_status',  'Vérifie la connectivité SSH de plusieurs serveurs'],
                            ['POST', '/cve_scan',              'Scan CVE ciblé en streaming (JSON-lines)'],
                            ['POST', '/cve_scan_all',          'Scan CVE sur tous les serveurs autorisés'],
                            ['GET',  '/cve_results',           'Derniers résultats CVE pour un serveur'],
                            ['GET',  '/cve_history',           'Historique des scans CVE'],
                            ['GET',  '/cve_test_connection',   'Teste la connexion OpenCVE'],
                            ['GET',  '/cve_trends',             'Evolution CVE sur 30 jours (par jour)'],
                            ['GET',  '/cve_schedules',          'Liste les scans planifies'],
                            ['POST', '/cve_schedules',          'Cree une planification de scan'],
                            ['GET',  '/cve_whitelist',          'Liste les CVE en whitelist'],
                            ['POST', '/cve_whitelist',          'Ajoute une CVE en whitelist'],
                            ['POST', '/dry_run_update',         'Simule apt upgrade --dry-run (streaming)'],
                            ['POST', '/preflight_check',        'Checks pre-deploiement SSH (connectivite, disque)'],
                            ['GET',  '/iptables-history',       'Historique des modifications iptables'],
                            ['POST', '/iptables-rollback',      'Restaure une version anterieure des regles'],
                            ['POST', '/remove_user_keys',      'Supprime les cles SSH d\'un user (all/rootwarden_only)'],
                            ['POST', '/delete_remote_user',    'Supprime un utilisateur Linux (userdel)'],
                            ['POST', '/exclude_user',          'Exclut un user de la synchronisation'],
                            ['GET',  '/health',                'Health check (pas d\'auth)'],
                        ] as [$method, $route, $desc]): ?>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td class="p-2 text-center">
                                <span class="<?= $method === 'GET' ? 'badge-get' : 'badge-post' ?>"><?= $method ?></span>
                            </td>
                            <td class="p-2 font-mono text-blue-700 dark:text-blue-300"><?= htmlspecialchars($route) ?></td>
                            <td class="p-2 text-gray-600 dark:text-gray-400"><?= htmlspecialchars($desc) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                </div>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 14b. Proxy API                            -->
            <!-- ────────────────────────────────────────── -->
            <section id="proxy" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Proxy API</h2>
                <p class="mb-3">Depuis la v1.5.2, toutes les requetes JavaScript passent par <code class="bg-gray-100 dark:bg-gray-700 px-1.5 py-0.5 rounded text-sm">/api_proxy.php</code> au lieu d'appeler le backend Python directement.</p>
                <div class="code-block mb-4">Navigateur (JS)
  fetch('/api_proxy.php/deploy')
       |
  api_proxy.php (PHP)
       |  &larr; injecte X-API-KEY cote serveur
       |  &larr; supporte GET, GET SSE, POST, POST streaming
       &darr;
  https://python:5000/deploy (Flask/Hypercorn)</div>
                <p class="mb-2"><strong>Pourquoi ?</strong></p>
                <ul class="list-disc ml-5 space-y-1 text-sm">
                    <li>Elimine les problemes CORS entre le navigateur et Hypercorn (ASGI)</li>
                    <li>Masque la cle API cote serveur (pas exposee dans le JS client)</li>
                    <li>Supporte le streaming SSE (logs SSH, iptables) et JSON-lines (CVE scan, APT updates)</li>
                </ul>
                <p class="text-xs text-gray-500 mt-3">Configure dans <code>head.php</code> : <code>window.API_URL = '/api_proxy.php'</code></p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 14c. Health Check                         -->
            <!-- ────────────────────────────────────────── -->
            <section id="healthcheck" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Health Check</h2>
                <p class="mb-3">La page <code class="bg-gray-100 dark:bg-gray-700 px-1.5 py-0.5 rounded text-sm">/adm/health_check.php</code> teste les 11 routes backend et affiche un tableau de bord avec le statut, le code HTTP, le temps de reponse et un apercu JSON.</p>
                <p class="mb-2">Accessible depuis <strong>Administration &rarr; Diagnostic Backend</strong> (superadmin uniquement).</p>
                <p class="text-sm">Routes testees : <code>/cve_test_connection</code>, <code>/cve_results</code>, <code>/cve_history</code>, <code>/list_machines</code>, <code>/filter_servers</code>, <code>/server_status</code>, <code>/linux_version</code>, <code>/deploy</code>, <code>/iptables</code>, <code>/update</code>, <code>/cve_scan</code></p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 14d. Environnement Preprod                -->
            <!-- ────────────────────────────────────────── -->
            <section id="preprod" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Environnement Preprod</h2>
                <p class="mb-3">Le profil Docker <code>preprod</code> ajoute deux services pour tester en local sans serveurs reels :</p>
                <ul class="list-disc ml-5 space-y-1 text-sm mb-4">
                    <li><strong>test-server</strong> &mdash; Debian Bookworm + SSH + sudo + iptables (IP : 192.169.50.6)</li>
                    <li><strong>mock-opencve</strong> &mdash; API Flask simulant OpenCVE avec 13 CVE realistes</li>
                </ul>
                <div class="code-block mb-3"># Demarrer tout (preprod)
docker-compose --profile preprod up -d

# Arreter le preprod uniquement
docker-compose --profile preprod stop test-server mock-opencve</div>
                <p class="text-sm">Configuration dans <code>srv-docker.env</code> : <code>API_URL=https://localhost:5000</code>, <code>OPENCVE_URL=http://mock-opencve:9090</code>, <code>DEBUG_MODE=true</code></p>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 15. Tester l'API                          -->
            <!-- ────────────────────────────────────────── -->
            <section id="api-test" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Tester l'API</h2>
                <p class="text-sm text-gray-500 mb-4">Envoyez une requête test directement depuis votre navigateur (passe par le proxy PHP).</p>
                <div class="space-y-3">
                    <div>
                        <label class="block text-sm font-medium mb-1">Endpoint (ex: /cve_test_connection)</label>
                        <input type="text" id="api-endpoint" value="/cve_test_connection"
                               class="w-full border dark:border-gray-600 bg-gray-50 dark:bg-gray-700 rounded p-2 font-mono text-sm">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Méthode</label>
                        <select id="api-method" class="border dark:border-gray-600 bg-gray-50 dark:bg-gray-700 rounded p-2 text-sm">
                            <option>GET</option>
                            <option>POST</option>
                        </select>
                    </div>
                    <div id="api-payload-wrap">
                        <label class="block text-sm font-medium mb-1">Body JSON (POST uniquement)</label>
                        <textarea id="api-payload" rows="3"
                                  class="w-full border dark:border-gray-600 bg-gray-50 dark:bg-gray-700 rounded p-2 font-mono text-sm">{"machines": [1]}</textarea>
                    </div>
                    <button onclick="runApiTest()"
                            class="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg text-sm font-semibold">
                        Envoyer
                    </button>
                </div>
                <div id="api-response" class="mt-4 hidden">
                    <div class="text-xs font-semibold text-gray-500 mb-1">Réponse :</div>
                    <pre id="api-response-body" class="code-block max-h-64 overflow-y-auto"></pre>
                </div>
            </section>
            <?php endif; ?>

            <!-- ────────────────────────────────────────── -->
            <!-- 16. Dépannage                             -->
            <!-- ────────────────────────────────────────── -->
            <section id="troubleshooting" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Dépannage</h2>
                <div class="space-y-4 text-sm">
                    <div class="border-l-4 border-yellow-500 pl-4">
                        <p class="font-semibold">Impossible de se connecter en SSH à un serveur</p>
                        <p class="text-gray-600 dark:text-gray-400">Vérifiez que le port 22 est ouvert, que l'utilisateur SSH existe, et que le mot de passe stocké est correct.
                        Consultez les logs Python : <code>docker logs gestion_ssh_key_python</code></p>
                    </div>
                    <div class="border-l-4 border-yellow-500 pl-4">
                        <p class="font-semibold">Les règles iptables ne s'appliquent pas</p>
                        <p class="text-gray-600 dark:text-gray-400">Vérifiez que le backend Python tourne : <code>docker logs gestion_ssh_key_python</code>.
                        Vérifiez que l'utilisateur SSH possède les droits sudo ou que le mot de passe root est correct.</p>
                    </div>
                    <div class="border-l-4 border-yellow-500 pl-4">
                        <p class="font-semibold">Le scan CVE ne remonte rien</p>
                        <p class="text-gray-600 dark:text-gray-400">Testez la connexion OpenCVE depuis Administration → Docs → Tester l'API (endpoint <code>/cve_test_connection</code>).
                        Vérifiez le seuil <code>CVE_MIN_CVSS</code> (essayez 4.0). Vérifiez <code>OPENCVE_USERNAME</code> et <code>OPENCVE_PASSWORD</code>.</p>
                    </div>
                    <div class="border-l-4 border-yellow-500 pl-4">
                        <p class="font-semibold">Erreur de déchiffrement des mots de passe</p>
                        <p class="text-gray-600 dark:text-gray-400">Si vous avez changé la <code>SECRET_KEY</code>, renseignez l'ancienne dans <code>OLD_SECRET_KEY</code>
                        et lancez le script de migration : <code>docker exec gestion_ssh_key_php php /var/www/html/auth/migrate_crypto.php</code></p>
                    </div>
                    <div class="border-l-4 border-yellow-500 pl-4">
                        <p class="font-semibold">La base de données ne démarre pas</p>
                        <p class="text-gray-600 dark:text-gray-400">Attendez que le healthcheck MySQL passe (jusqu'à 60 s au premier démarrage).
                        Consultez : <code>docker logs gestion_ssh_key_db</code>.
                        En dernier recours : <code>docker-compose down -v && docker-compose up -d</code> (⚠ efface les données)</p>
                    </div>
                    <?php if ($isAdmin): ?>
                    <div class="border-l-4 border-blue-500 pl-4">
                        <p class="font-semibold">Activer les logs détaillés (debug)</p>
                        <div class="code-block mt-2"># Dans srv-docker.env
DEBUG_MODE=true
LOG_LEVEL=DEBUG
# Puis relancer : docker-compose up -d</div>
                        <p class="text-red-600 dark:text-red-400 mt-1 text-xs">⚠ Désactivez DEBUG_MODE=false avant la mise en production.</p>
                    </div>
                    <?php endif; ?>
                </div>
            </section>

            <!-- ────────────────────────────────────────── -->
            <!-- 17. Contribuer                            -->
            <!-- ────────────────────────────────────────── -->
            <section id="contribute" class="doc-anchor bg-white dark:bg-gray-800 shadow rounded-xl p-6 mb-6">
                <h2 class="text-2xl font-bold text-blue-800 dark:text-blue-400 mb-3">Contribuer au projet</h2>
                <p class="text-sm mb-3">
                    Les contributions sont les bienvenues ! Soumettez vos idées et correctifs via GitHub.
                </p>
                <ul class="list-disc list-inside text-sm space-y-1">
                    <li>Forkez le dépôt sur <a href="https://github.com/Timikana/Gestion_SSH_KEY" target="_blank" class="text-blue-500 hover:underline">github.com/Timikana/Gestion_SSH_KEY</a></li>
                    <li>Créez une branche : <code>git checkout -b feature/ma-fonctionnalite</code></li>
                    <li>Respectez les conventions de nommage des migrations SQL (<code>NNN_description.sql</code>)</li>
                    <li>Documentez toute nouvelle route API et toute nouvelle variable d'environnement</li>
                    <li>Ouvrez une Pull Request avec une description claire</li>
                </ul>
            </section>

            <p class="text-center text-xs text-gray-400 mt-4 mb-8">
                <?= $appName ?> v<?= htmlspecialchars($appVersion) ?> · Documentation mise à jour le <?= date('d/m/Y') ?>
            </p>

        </main>
    </div><!-- /flex -->

    <script>
    <?php if ($isAdmin): ?>
    document.getElementById('api-method').addEventListener('change', function() {
        document.getElementById('api-payload-wrap').style.display = this.value === 'POST' ? '' : 'none';
    });

    function runApiTest() {
        const endpoint = document.getElementById('api-endpoint').value.trim();
        const method   = document.getElementById('api-method').value;
        const payload  = document.getElementById('api-payload').value;
        const respDiv  = document.getElementById('api-response');
        const respBody = document.getElementById('api-response-body');

        respDiv.classList.remove('hidden');
        respBody.textContent = 'Envoi en cours…';

        const options = {
            method,
            headers: { 'Content-Type': 'application/json' }
        };
        if (method === 'POST') options.body = payload;

        // Passe par un proxy PHP pour ne pas exposer l'API_KEY en JS
        fetch('/api_proxy.php' + endpoint, options)
            .then(r => r.text())
            .then(text => {
                try { respBody.textContent = JSON.stringify(JSON.parse(text), null, 2); }
                catch(e) { respBody.textContent = text; }
            })
            .catch(err => { respBody.textContent = 'Erreur : ' + err; });
    }
    <?php endif; ?>
    </script>

    <?php require_once __DIR__ . '/footer.php'; ?>
</body>
</html>
