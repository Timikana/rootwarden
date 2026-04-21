<?php
/**
 * adm/includes/manage_users.php
 *
 * Interface de gestion des clés SSH et des utilisateurs SSH du portail.
 * Réservé aux rôles admin (2) et superadmin (3).
 *
 * Fonctionnalités :
 *   - Ajout d'un utilisateur SSH (name, company, ssh_key, active, sudo)
 *     avec génération automatique d'un mot de passe sécurisé (16 caractères hex)
 *     et création des permissions par défaut via transaction
 *   - Affichage du tableau de tous les utilisateurs SSH
 *   - Actions AJAX (fetch) pour : toggle actif/inactif, toggle sudo, suppression utilisateur
 *   - Validation des entrées via validateInputSSH()
 *
 * @package RootWarden\Admin
 */
// adm/includes/manage_users.php

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/crypto.php'; // On peut le laisser même si on n'utilise plus encryptPassword ici

// Autorise les utilisateurs ayant le rôle admin (2) ou superadmin (3)
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Valide et assainit une donnée d'entrée pour les utilisateurs SSH.
 *
 * Types supportés :
 *   - 'name'    : alphanumérique + tiret/underscore, 1–255 chars, encodé htmlspecialchars
 *   - 'company' : lettres Unicode, chiffres, espaces, tirets, underscores, 1–255 chars
 *   - 'ssh_key' : clé SSH non vide (contenu quelconque), encodé htmlspecialchars ; null si vide
 *   - 'bool'    : convertit en 1 (truthy) ou 0 (falsy)
 *
 * @param mixed  $data Donnée brute à valider.
 * @param string $type Type de validation ('name', 'company', 'ssh_key', 'bool').
 * @return mixed La donnée assainie, null pour une clé SSH vide, ou false si invalide.
 */
function validateInputSSH($data, $type) {
    switch ($type) {
        case 'name':
            // Autorise a-z, A-Z, 0-9, tiret, underscore. Ajustez si nécessaire
            return preg_match('/^[a-zA-Z0-9-_]{1,255}$/', $data)
                ? htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8')
                : false;

        case 'company':
            // On élargit la regex pour accepter lettres, chiffres, espaces, tirets, etc. 
            // Vous pouvez aussi enlever la regex si vous voulez autoriser (presque) tout.
            return preg_match('/^[\p{L}\p{N}\s\-_]{1,255}$/u', $data)
                ? htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8')
                : false;

        case 'ssh_key':
            // Clé SSH facultative, on ne fait pas de regex stricte ici
            return !empty(trim($data))
                ? htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8')
                : null;

        case 'bool':
            return $data ? 1 : 0;

        default:
            return false;
    }
}

// Ajouter un utilisateur
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_user') {
    checkCsrfToken();

    $name = validateInputSSH($_POST['name'], 'name');
    $company = validateInputSSH($_POST['company'] ?? '', 'company');
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL) ?: null;
    $ssh_key = validateInputSSH($_POST['ssh_key'] ?? '', 'ssh_key');
    $active = validateInputSSH(isset($_POST['active']), 'bool');
    $sudo = validateInputSSH(isset($_POST['sudo']), 'bool');
    $role_id = in_array((int)($_POST['role_id'] ?? 1), [1, 2, 3]) ? (int)$_POST['role_id'] : 1;

    // Placeholder password - impossible de se connecter avec (pas de mdp en clair)
    $password = password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT);

    if (!$name) {
        $error = t('users.error_invalid_name');
    } else {
        try {
            $pdo->beginTransaction();

            $stmt = $pdo->prepare("
                INSERT INTO users (name, company, email, password, ssh_key, active, sudo, role_id, force_password_change)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE)
            ");
            $stmt->execute([$name, $company, $email, $password, $ssh_key, $active, $sudo, $role_id]);

            $new_user_id = $pdo->lastInsertId();

            // On insère aussi des permissions par défaut
            $stmt = $pdo->prepare("
                INSERT INTO permissions (user_id, can_deploy_keys, can_update_linux, can_manage_iptables, can_admin_portal, can_scan_cve, can_manage_remote_users, can_manage_platform_key, can_view_compliance, can_manage_backups, can_schedule_cve, can_manage_fail2ban, can_manage_services, can_audit_ssh, can_manage_supervision)
                VALUES (?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            ");
            $stmt->execute([$new_user_id]);

            $pdo->commit();

            // Audit log
            require_once __DIR__ . '/audit_log.php';
            audit_log($pdo, "Creation utilisateur '$name' (role=$role_id)", $new_user_id);

            $successSSH = t('users.created_success');

            // Envoi du magic link d'activation si email renseigné et SMTP configuré
            $mailSent = false;
            if ($email) {
                try {
                    require_once __DIR__ . '/../../includes/mail_helper.php';

                    // Générer un token d'activation (24h)
                    $token = bin2hex(random_bytes(32));
                    $tokenHash = password_hash($token, PASSWORD_DEFAULT);
                    $expiresAt = date('Y-m-d H:i:s', strtotime('+24 hours'));
                    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

                    $stmtToken = $pdo->prepare(
                        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_address)
                         VALUES (?, ?, ?, ?)"
                    );
                    $stmtToken->execute([$new_user_id, $tokenHash, $expiresAt, $ip]);

                    $baseUrl = rtrim(getenv('URL_HTTPS') ?: 'https://localhost:8443', '/');
                    $activationUrl = "{$baseUrl}/auth/reset_password.php?uid={$new_user_id}&token={$token}";

                    $mailSent = sendActivationEmail($email, $activationUrl, $name);
                } catch (Exception $mailErr) {
                    error_log("[RootWarden] Mail activation echoue: " . $mailErr->getMessage());
                }
            }
        } catch (PDOException $e) {
            $pdo->rollBack();
            $error = t('users.error_sql') . ' ' . htmlspecialchars($e->getMessage());
        }
    }
}

// Récupérer les utilisateurs
$stmt = $pdo->query("SELECT u.id, u.name, u.company, u.email, u.ssh_key, u.ssh_key_updated_at, u.active, u.sudo, u.totp_secret, u.created_at, u.password_expiry_override, u.password_updated_at, u.failed_attempts, u.locked_until, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.id ORDER BY u.name");
// Role courant pour afficher/masquer le bouton de deverrouillage (superadmin only)
$_mu_isSA = (int)($_SESSION['role_id'] ?? 0) === 3;
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Récupérer les serveurs (si vous en avez besoin pour l'affichage)
$stmt_servers = $pdo->query("SELECT id, name FROM machines");
$all_servers = $stmt_servers->fetchAll(PDO::FETCH_ASSOC);
?>

<div>
    <div class="flex items-center justify-between mb-4">
        <h2 class="text-xl font-bold text-gray-800 dark:text-gray-100"><?= t('users.title') ?></h2>
        <span class="text-xs text-gray-400"><?= t('users.count', ['count' => count($users)]) ?></span>
    </div>
    <p class="text-xs text-gray-400 mt-0.5"><?= t('users.desc') ?></p>

    <?php if (isset($successSSH)): ?>
        <?php if (isset($plainPassword)): ?>
            <!-- Mot de passe généré - affiché dans un bandeau persistant -->
            <div class="mb-4 p-4 bg-green-50 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded-lg">
                <p class="text-sm text-green-700 dark:text-green-300"><?= t('users.created_success') ?></p>
                <div class="flex items-center gap-3 mt-2">
                    <span class="text-xs text-gray-500"><?= t('users.generated_password') ?></span>
                    <code id="generated-password" class="px-3 py-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded font-mono text-sm select-all"><?= htmlspecialchars($plainPassword) ?></code>
                    <button onclick="navigator.clipboard.writeText(document.getElementById('generated-password').textContent); toast(__('users.password_copied'), 'success', 2000);"
                            class="text-xs px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"><?= t('users.btn_copy') ?></button>
                </div>
                <p class="text-xs text-red-500 mt-2"><?= t('users.password_warning') ?></p>
            </div>
        <?php else: ?>
            <script>document.addEventListener('DOMContentLoaded', () => toast(__('users.action_done'), 'success'));</script>
        <?php endif; ?>
    <?php endif; ?>
    <?php if (isset($error)): ?>
        <script>document.addEventListener('DOMContentLoaded', () => toast(<?= json_encode($error) ?>, 'error'));</script>
    <?php endif; ?>

    <!-- Barre de recherche -->
    <div class="mb-4">
        <input type="text" id="search-users-ssh" placeholder="<?= t('users.search_placeholder') ?>"
               class="w-full px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
               oninput="filterUserCards(this.value)">
    </div>

    <!-- Liste des utilisateurs (cards collapsables) -->
    <div class="space-y-2 mb-6" id="user-cards-list">
        <?php foreach ($users as $user):
            $hasKey = !empty($user['ssh_key']);
            $keyAge = ($hasKey && $user['ssh_key_updated_at']) ? (int)((time() - strtotime($user['ssh_key_updated_at'])) / 86400) : 0;
            $keyOld = $keyAge > 90;
            $keyPreview = $hasKey ? substr($user['ssh_key'], 0, 30) . '...' : '';
        ?>
        <details class="user-card group bg-gray-50 dark:bg-gray-700/50 rounded-lg overflow-hidden" data-username="<?= htmlspecialchars(strtolower($user['name'])) ?>" data-company="<?= htmlspecialchars(strtolower($user['company'] ?? '')) ?>">
            <!-- Header (toujours visible) -->
            <summary class="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600/50 transition-colors select-none">
                <svg class="w-4 h-4 text-gray-400 transition-transform group-open:rotate-90 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
                <span class="font-semibold text-sm text-gray-800 dark:text-gray-200"><?= htmlspecialchars($user['name']) ?></span>
                <?php if (!empty($user['company'])): ?>
                    <span class="text-xs text-gray-400 hidden sm:inline"><?= htmlspecialchars($user['company']) ?></span>
                <?php endif; ?>
                <div class="flex gap-1.5 ml-auto flex-wrap justify-end">
                    <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-400"><?= htmlspecialchars($user['role_name'] ?? 'user') ?></span>
                    <span class="text-[10px] px-1.5 py-0.5 rounded-full <?= $user['active'] ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400' : 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400' ?>"><?= $user['active'] ? t('users.badge_active') : t('users.badge_inactive') ?></span>
                    <?php if ($user['sudo']): ?>
                        <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-400"><?= t('users.badge_sudo') ?></span>
                    <?php endif; ?>
                    <span class="text-[10px] px-1.5 py-0.5 rounded-full <?= !empty($user['totp_secret']) ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-400' ?>"><?= !empty($user['totp_secret']) ? t('users.badge_2fa') : t('users.badge_no_2fa') ?></span>
                    <?php if ($hasKey): ?>
                        <span class="text-[10px] px-1.5 py-0.5 rounded-full <?= $keyOld ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400' : 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-400' ?>"><?= $keyOld ? t('users.badge_ssh_key_old', ['days' => $keyAge]) : t('users.badge_ssh_key') ?></span>
                    <?php endif; ?>
                    <?php
                    // Badge compte verrouille (per-user lockout, migration 035)
                    $_lockedUntilTs = !empty($user['locked_until']) ? strtotime($user['locked_until']) : 0;
                    $_isLocked = $_lockedUntilTs > time();
                    if ($_isLocked):
                        $_lockMin = (int)ceil(($_lockedUntilTs - time()) / 60);
                    ?>
                        <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-red-200 text-red-800 dark:bg-red-900/60 dark:text-red-200" title="<?= t('users.locked_tooltip') ?>">🔒 <?= t('users.badge_locked', ['minutes' => $_lockMin]) ?></span>
                    <?php elseif ((int)($user['failed_attempts'] ?? 0) >= 3): ?>
                        <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300" title="<?= t('users.failed_tooltip') ?>"><?= (int)$user['failed_attempts'] ?> ⚠</span>
                    <?php endif; ?>
                </div>
            </summary>
            <!-- Detail (visible quand ouvert) -->
            <div class="px-4 pb-4 pt-1 border-t border-gray-200 dark:border-gray-600">
                <div class="flex items-start gap-3">
                    <!-- Cle SSH -->
                    <form method="POST" action="api/update_user.php" class="flex-1 flex gap-2">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="user_id" value="<?= (int)$user['id'] ?>">
                        <textarea name="ssh_key" rows="3" placeholder="<?= t('users.ssh_key_placeholder') ?>"
                                  class="flex-1 px-3 py-2 text-xs font-mono border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"><?= htmlspecialchars($user['ssh_key'] ?? '') ?></textarea>
                        <button type="submit" class="self-start px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded-lg transition-colors whitespace-nowrap"><?= t('users.btn_save') ?></button>
                    </form>
                    <!-- Actions -->
                    <div class="flex flex-col gap-1 flex-shrink-0">
                        <?php
                        $expiryVal = $user['password_expiry_override'];
                        $expiryLabel = $expiryVal === null ? 'Global' : ($expiryVal === 0 ? 'Exempt' : "{$expiryVal}j");
                        $expiryCls = $expiryVal === 0 ? 'text-green-600 bg-green-50 border-green-300 dark:bg-green-900/30 dark:border-green-700 dark:text-green-400' : ($expiryVal === null ? 'text-gray-500 bg-gray-50 border-gray-300 dark:bg-gray-700 dark:border-gray-600' : 'text-orange-600 bg-orange-50 border-orange-300 dark:bg-orange-900/30 dark:border-orange-700 dark:text-orange-400');
                        ?>
                        <select onchange="setPasswordExpiry(<?= (int)$user['id'] ?>, this.value)" class="text-[10px] px-2 py-1 rounded border <?= $expiryCls ?>" title="<?= t('users.password_expiry_title') ?>">
                            <option value="null" <?= $expiryVal === null ? 'selected' : '' ?>><?= t('users.pwd_global') ?></option>
                            <option value="0" <?= $expiryVal === 0 ? 'selected' : '' ?>><?= t('users.pwd_exempt') ?></option>
                            <option value="30" <?= $expiryVal === 30 ? 'selected' : '' ?>><?= t('users.pwd_30d') ?></option>
                            <option value="60" <?= $expiryVal === 60 ? 'selected' : '' ?>><?= t('users.pwd_60d') ?></option>
                            <option value="90" <?= $expiryVal === 90 ? 'selected' : '' ?>><?= t('users.pwd_90d') ?></option>
                            <option value="180" <?= $expiryVal === 180 ? 'selected' : '' ?>><?= t('users.pwd_180d') ?></option>
                            <option value="365" <?= $expiryVal === 365 ? 'selected' : '' ?>><?= t('users.pwd_365d') ?></option>
                        </select>
                        <button hx-post="api/toggle_user.php" hx-vals='{"user_id": <?= (int)$user['id'] ?>}' hx-swap="outerHTML" hx-confirm="<?= t('users.confirm_generic') ?>"
                                class="text-xs px-3 py-1 rounded border <?= $user['active'] ? 'border-red-300 text-red-600 hover:bg-red-50 dark:border-red-700 dark:text-red-400 dark:hover:bg-red-900/30' : 'border-green-300 text-green-600 hover:bg-green-50 dark:border-green-700 dark:text-green-400 dark:hover:bg-green-900/30' ?> transition-colors"><?= $user['active'] ? t('users.btn_deactivate') : t('users.btn_activate') ?></button>
                        <button hx-post="api/toggle_sudo.php" hx-vals='{"user_id": <?= (int)$user['id'] ?>}' hx-swap="outerHTML"
                                class="text-xs px-3 py-1 rounded border border-purple-300 text-purple-600 hover:bg-purple-50 dark:border-purple-700 dark:text-purple-400 dark:hover:bg-purple-900/30 transition-colors"><?= $user['sudo'] ? t('users.btn_remove_sudo') : t('users.btn_grant_sudo') ?></button>
                        <?php if ($_mu_isSA && ($_isLocked || (int)($user['failed_attempts'] ?? 0) > 0)): ?>
                        <button onclick="unlockUser(<?= (int)$user['id'] ?>, '<?= htmlspecialchars(addslashes($user['name'])) ?>')"
                                class="text-xs px-3 py-1 rounded border border-yellow-300 text-yellow-700 hover:bg-yellow-50 dark:border-yellow-700 dark:text-yellow-400 dark:hover:bg-yellow-900/30 transition-colors"
                                title="<?= t('users.btn_unlock_tip') ?>">🔓 <?= t('users.btn_unlock') ?></button>
                        <?php endif; ?>
                        <button onclick="deleteUser(<?= (int)$user['id'] ?>, '<?= htmlspecialchars(addslashes($user['name'])) ?>')" class="text-xs px-3 py-1 rounded border border-red-300 text-red-600 hover:bg-red-50 dark:border-red-700 dark:text-red-400 dark:hover:bg-red-900/30 transition-colors"><?= t('users.btn_delete') ?></button>
                    </div>
                </div>
            </div>
        </details>
        <?php endforeach; ?>
        <?php if (empty($users)): ?>
            <p class="text-sm text-gray-400 py-4"><?= t('users.empty_state') ?></p>
        <?php endif; ?>
    </div>

    <!-- Formulaire d'ajout -->
    <details class="bg-blue-50 dark:bg-blue-900/20 rounded-lg">
        <summary class="px-4 py-3 cursor-pointer text-sm font-medium text-blue-700 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/40 rounded-lg transition-colors">+ <?= t('users.add_user') ?></summary>
        <form method="POST" class="p-4 pt-2">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="action" value="add_user">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
                <div>
                    <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('users.field_name') ?><span class="text-red-500 ml-0.5">*</span></label>
                    <input type="text" name="name" required maxlength="255" placeholder="jean.dupont" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('users.field_email') ?></label>
                    <input type="email" name="email" maxlength="255" placeholder="jean@entreprise.fr" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('users.field_company') ?></label>
                    <input type="text" name="company" maxlength="255" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('users.field_ssh_key') ?></label>
                    <input type="text" name="ssh_key" class="w-full px-3 py-2 text-sm font-mono border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
            </div>
            <div class="flex items-center gap-6 mb-3">
                <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400"><input type="checkbox" name="active" checked class="form-checkbox h-4 w-4 text-green-600 rounded"> <?= t('users.field_active') ?></label>
                <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400"><input type="checkbox" name="sudo" class="form-checkbox h-4 w-4 text-purple-600 rounded"> <?= t('users.field_sudo') ?></label>
                <div class="flex items-center gap-2">
                    <span class="text-sm text-gray-600 dark:text-gray-400"><?= t('users.field_role') ?> :</span>
                    <select name="role_id" class="px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                        <option value="1" selected><?= t('users.role_user') ?></option>
                        <option value="2"><?= t('users.role_admin') ?></option>
                        <option value="3"><?= t('users.role_superadmin') ?></option>
                    </select>
                </div>
            </div>
            <button type="submit" class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-lg transition-colors"><?= t('users.btn_add_user') ?></button>
            <p class="text-[10px] text-gray-400 mt-1"><?= t('users.required_fields') ?></p>
        </form>
    </details>
</div>

<script>
/** Filtre les cards utilisateur par nom ou societe */
function filterUserCards(query) {
    const q = query.toLowerCase().trim();
    document.querySelectorAll('.user-card').forEach(card => {
        const name = card.dataset.username || '';
        const company = card.dataset.company || '';
        const match = !q || name.includes(q) || company.includes(q);
        card.style.display = match ? '' : 'none';
    });
}
</script>

<!-- Scripts -->
<script>
    async function setPasswordExpiry(userId, value) {
        const override = value === 'null' ? null : parseInt(value);
        try {
            const r = await fetch('api/update_user.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `csrf_token=${encodeURIComponent(document.querySelector('meta[name="csrf-token"]')?.content || '')}&user_id=${userId}&password_expiry_override=${value}`
            });
            const d = await r.json();
            if (d.success !== false) {
                const labels = {'null': 'global', '0': 'exempt'};
                toast(__('users.pwd_expiry_updated', {value: labels[value] || value + 'j'}), 'success');
            } else {
                toast(d.message || __('users.error_generic'), 'error');
            }
        } catch(e) { toast(__('users.error_network'), 'error'); }
    }

    // toggleUserStatus() et toggleSudo() sont maintenant geres par htmx
    // (hx-post sur les boutons dans le template PHP)

    async function unlockUser(userId, userName) {
        if (!confirm((__('users.confirm_unlock') || 'Deverrouiller ce compte et effacer le compteur d echecs ?') + '\n\n' + userName)) return;
        try {
            const res = await fetch('/adm/api/unlock_user.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    csrf_token: '<?= htmlspecialchars($_SESSION['csrf_token']) ?>',
                    user_id: userId
                })
            });
            const data = await res.json();
            if (data.success) {
                (typeof showNotification === 'function' ? showNotification : alert)(__('users.unlocked_success') || 'Compte deverrouille.', 'success');
                setTimeout(() => location.reload(), 600);
            } else {
                alert(data.message || 'Echec');
            }
        } catch (e) {
            alert('Erreur: ' + e.message);
        }
    }

    function deleteUser(userId, userName) {
        if (!confirm(__('users.confirm_delete_user', {name: userName}))) {
            return;
        }
        fetch('/adm/api/delete_user.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                csrf_token: '<?= htmlspecialchars($_SESSION['csrf_token']) ?>',
                user_id: userId
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(__('users.deleted_success'), 'success');
                const row = document.querySelector(`tr[data-user-id='${userId}']`);
                if (row) {
                    row.remove();
                }
            } else {
                showNotification(__('users.error_generic') + ' : ' + data.message, 'error');
            }
        })
        .catch(error => {
            console.error('Network/server error:', error);
            showNotification(__('users.error_network'), 'error');
        });
    }

    function showNotification(message, type = 'success') {
        const notifications = document.getElementById('notifications');
        const bgColor = (type === 'success')
            ? 'bg-green-100 dark:bg-green-700'
            : 'bg-red-100 dark:bg-red-700';
        const textColor = (type === 'success')
            ? 'text-green-700 dark:text-green-100'
            : 'text-red-700 dark:text-red-100';
        notifications.innerHTML = `
            <div class="flex items-center justify-between ${bgColor} ${textColor} px-4 py-3 rounded-lg shadow-md mb-4">
                <span>${message}</span>
                <button onclick="this.parentElement.style.display='none'" class="text-xl font-bold">&times;</button>
            </div>
        `;
        setTimeout(() => {
            notifications.innerHTML = "";
        }, 5000);
    }

    function copyToClipboard() {
        const password = document.getElementById('generated-password').innerText;
        navigator.clipboard.writeText(password)
        .then(() => {
            showNotification(__('users.password_copied'), 'success');
        })
        .catch(err => {
            console.error('Copy error:', err);
            showNotification(__('users.error_copy_password'), 'error');
        });
    }
</script>
