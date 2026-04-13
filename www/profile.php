<?php
/**
 * profile.php — Page de profil utilisateur
 *
 * Rôle       : Permet à un utilisateur connecté de :
 *                1. Mettre à jour sa clé SSH publique (validation de format)
 *                2. Changer son mot de passe (vérification ancien mdp + politique)
 *              Toutes les actions POST sont protégées par un jeton CSRF.
 *              Chaque modification réussie est enregistrée dans la table user_logs.
 *
 * Dépendances :
 *   - auth/verify.php : checkAuth(), checkCsrfToken() — authentification et CSRF
 *   - db.php          : $pdo — connexion PDO MySQL
 *   - head.php        : balises <head> communes
 *   - menu.php        : barre de navigation
 *   - footer.php      : pied de page
 *
 * Permissions requises : ROLE_USER (1), ROLE_ADMIN (2), ROLE_SUPERADMIN (3)
 *
 * Politique de mot de passe :
 *   - Minimum 15 caractères
 *   - Au moins une minuscule, une majuscule, un chiffre, un caractère spécial
 *
 * CSRF : le jeton est lu depuis $_SESSION['csrf_token'] et vérifié par
 *        checkCsrfToken() avant tout traitement POST.
 */

require_once __DIR__ . '/auth/verify.php';
require_once __DIR__ . '/db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Vérifie que l'utilisateur est authentifié avec un rôle valide
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);

// Récupération de l'identifiant utilisateur depuis la session (casté en int par sécurité)
$userId   = (int) $_SESSION['user_id'];
$username = htmlspecialchars($_SESSION['username']);

// ── Chargement des données utilisateur depuis la BDD ─────────────────────────
$stmt = $pdo->prepare("
    SELECT u.ssh_key, u.email, u.totp_secret, u.created_at, u.active, u.sudo,
           r.name AS role_name
    FROM users u
    JOIN roles r ON u.role_id = r.id
    WHERE u.id = ?
");
$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
$has2FA = !empty($user['totp_secret']);

// Variables de retour affichées dans la vue (null = pas de message)
$message = null;
$error   = null;

// ── Traitement des formulaires POST ──────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Vérification du jeton CSRF — stoppe l'exécution si invalide
    checkCsrfToken();

    // ── Revocation de session ──────────────────────────────────────────
    if (isset($_POST['revoke_session'])) {
        $revokeId = $_POST['revoke_session'];
        try {
            $pdo->prepare("DELETE FROM active_sessions WHERE session_id = ? AND user_id = ?")
                ->execute([$revokeId, $userId]);
            $message = t('profile.session_revoked');
        } catch (\Exception $e) {
            $error = t('profile.error_revoke');
        }
    }

    // ── Formulaire 0 : mise à jour de l'email ──────────────────────────
    if (isset($_POST['new_email'])) {
        $newEmail = filter_var(trim($_POST['new_email']), FILTER_VALIDATE_EMAIL) ?: null;
        if ($_POST['new_email'] && !$newEmail) {
            $error = t('profile.error_email_format');
        } else {
            $stmt = $pdo->prepare("UPDATE users SET email = ? WHERE id = ?");
            $stmt->execute([$newEmail, $userId]);
            $stmt = $pdo->prepare("INSERT INTO user_logs (user_id, action) VALUES (?, ?)");
            $stmt->execute([$userId, "Mise a jour de l'email"]);
            $user['email'] = $newEmail;
            $message = t('profile.email_updated');
        }
    }

    // ── Formulaire 1 : mise à jour de la clé SSH ──────────────────────────
    if (isset($_POST['new_ssh_key'])) {
        $newSshKey = trim($_POST['new_ssh_key']);

        // Validation du format de clé SSH publique (supporte rsa, ed25519, ecdsa)
        // Une valeur vide est acceptée (suppression de la clé)
        if (!empty($newSshKey) && !preg_match('/^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2-\S+)\s+\S+/', $newSshKey)) {
            $error = t('profile.error_ssh_format');
        } else {
            try {
                // Mise à jour de la clé SSH (NULL si champ vide = suppression)
                $stmt = $pdo->prepare("UPDATE users SET ssh_key = ?, ssh_key_updated_at = NOW() WHERE id = ?");
                $stmt->execute([$newSshKey ?: null, $userId]);

                // Journalisation de l'action dans user_logs
                $stmt = $pdo->prepare("INSERT INTO user_logs (user_id, action) VALUES (?, ?)");
                $stmt->execute([$userId, "Mise à jour de la clé SSH"]);

                $message = t('profile.ssh_updated');
                // Rafraîchit les données affichées sans recharger la page
                $user['ssh_key'] = $newSshKey;
            } catch (PDOException $e) {
                $error = t('profile.error_ssh_update');
            }
        }
    }

    // ── Formulaire 2 : changement de mot de passe ─────────────────────────
    if (isset($_POST['current_password'], $_POST['new_password'], $_POST['confirm_password'])) {
        $currentPassword = $_POST['current_password'];
        $newPassword     = $_POST['new_password'];
        $confirmPassword = $_POST['confirm_password'];

        try {
            // Récupère le hash bcrypt stocké en BDD pour vérification
            $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $storedPassword = $stmt->fetchColumn();

            // Étape 1 : vérification de l'ancien mot de passe (password_verify = timing-safe)
            if (!password_verify($currentPassword, $storedPassword)) {
                $error = t('profile.error_wrong_password');
            // Étape 2 : vérification de la correspondance nouveau/confirmation
            } elseif ($newPassword !== $confirmPassword) {
                $error = t('profile.error_password_mismatch');
            // Étape 3 : vérification de la politique de complexité du mot de passe
            } elseif (
                strlen($newPassword) < 15 ||              // Minimum 15 caractères
                !preg_match('/[a-z]/', $newPassword) ||   // Au moins une minuscule
                !preg_match('/[A-Z]/', $newPassword) ||   // Au moins une majuscule
                !preg_match('/[0-9]/', $newPassword) ||   // Au moins un chiffre
                !preg_match('/[^a-zA-Z0-9]/', $newPassword) // Au moins un caractère spécial
            ) {
                $error = t('profile.error_password_policy');
            } else {
                // Hachage bcrypt du nouveau mot de passe (PASSWORD_DEFAULT = bcrypt)
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                // Calcul de la date d'expiration (per-user override > global)
                $overrideStmt = $pdo->prepare("SELECT password_expiry_override FROM users WHERE id = ?");
                $overrideStmt->execute([$userId]);
                $override = $overrideStmt->fetchColumn();
                $globalDays = (int)(getenv('PASSWORD_EXPIRY_DAYS') ?: 0);
                if ($override === '0' || $override === 0) {
                    $effectiveDays = 0; // Exempt
                } elseif ($override !== null && (int)$override > 0) {
                    $effectiveDays = (int)$override; // Custom per-user
                } else {
                    $effectiveDays = $globalDays; // Global
                }
                $expiresAt = $effectiveDays > 0 ? date('Y-m-d', strtotime("+{$effectiveDays} days")) : null;
                $stmt = $pdo->prepare("UPDATE users SET password = ?, password_expires_at = ? WHERE id = ?");
                $stmt->execute([$hashedPassword, $expiresAt, $userId]);
                // Effacer le flag d'expiration en session
                unset($_SESSION['password_expired'], $_SESSION['password_warn_days']);

                // Journalisation de l'action dans user_logs
                $stmt = $pdo->prepare("INSERT INTO user_logs (user_id, action) VALUES (?, ?)");
                $stmt->execute([$userId, "Mise à jour du mot de passe"]);

                // Effacer le flag force_password_change
                $pdo->prepare("UPDATE users SET force_password_change = FALSE WHERE id = ?")->execute([$userId]);
                unset($_SESSION['force_password_change']);

                $message = t('profile.password_updated');

                // Si c'était un changement forcé, rediriger vers l'accueil
                if (isset($_GET['force_change'])) {
                    header("Location: /terms.php");
                    exit();
                }
            }
        } catch (PDOException $e) {
            $error = t('profile.error_password_update');
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/head.php'; ?>
    <title><?= t('profile.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <!-- Menu -->
    <?php require_once __DIR__ . '/menu.php'; ?>

    <div class="p-8 max-w-screen-xl mx-auto w-full">
        <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-1"><?= t('profile.title') ?></h1>
        <p class="text-xs text-gray-400 mt-0.5 mb-6"><?= t('profile.desc') ?></p>
<?php $tipId = 'profile'; $tipTitle = t('tip.profile_title'); $tipSteps = [t('tip.profile_step1'), t('tip.profile_step2'), t('tip.profile_step3')]; require __DIR__ . '/includes/howto_tip.php'; ?>

        <?php if (isset($_GET['force_change'])): ?>
            <div class="bg-amber-50 dark:bg-amber-900/30 border-2 border-amber-400 dark:border-amber-600 text-amber-800 dark:text-amber-200 p-5 rounded-xl mb-6 flex items-center gap-3">
                <svg class="w-6 h-6 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>
                <div>
                    <p class="font-bold text-lg"><?= t('profile.force_change') ?></p>
                    <p class="text-sm mt-1"><?= t('profile.force_change_desc') ?></p>
                </div>
            </div>
        <?php endif; ?>

        <!-- Messages de confirmation / erreur -->
        <?php if (isset($message)): ?>
            <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-300 p-4 rounded-lg mb-6"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        <?php if (isset($error)): ?>
            <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 p-4 rounded-lg mb-6"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <!-- Carte identité -->
        <div class="bg-white dark:bg-gray-800 p-6 rounded-xl shadow mb-6">
            <div class="flex items-center justify-between">
                <div>
                    <h2 class="text-xl font-bold text-gray-800 dark:text-gray-200"><?= $username ?></h2>
                    <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        <?= t('profile.role') ?> : <span class="font-semibold text-blue-600 dark:text-blue-400"><?= htmlspecialchars(ucfirst($user['role_name'] ?? 'inconnu')) ?></span>
                    </p>
                </div>
                <div class="text-right text-xs text-gray-400 dark:text-gray-500 space-y-1">
                    <div><?= t('profile.account_created') ?> <?= $user['created_at'] ? date('d/m/Y', strtotime($user['created_at'])) : '—' ?></div>
                    <div><?= t('profile.2fa') ?> : <?= $has2FA
                        ? '<span class="text-green-600 dark:text-green-400 font-semibold">' . t('profile.2fa_active') . '</span>'
                        : '<span class="text-red-500 font-semibold">' . t('profile.2fa_inactive') . '</span>' ?>
                    </div>
                    <div><?= t('profile.sudo') ?> : <?= $user['sudo']
                        ? '<span class="text-green-600 dark:text-green-400 font-semibold">' . t('common.yes') . '</span>'
                        : '<span class="text-gray-400">' . t('common.no') . '</span>' ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Email -->
        <div class="bg-white dark:bg-gray-800 p-6 rounded-xl shadow mb-6">
            <h2 class="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-3"><?= t('profile.email_title') ?></h2>
            <form method="POST" class="flex items-center gap-3">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                <input type="email" name="new_email" value="<?= htmlspecialchars($user['email'] ?? '') ?>" placeholder="votre@email.com"
                       class="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500">
                <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"><?= t('profile.save') ?></button>
            </form>
            <p class="text-xs text-gray-400 mt-2"><?= t('profile.email_hint') ?></p>
        </div>

        <!-- Modifier la clé SSH -->
        <div class="bg-white dark:bg-gray-800 p-6 rounded-xl shadow mb-6">
            <h2 class="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-3"><?= t('profile.ssh_title') ?></h2>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                <label for="new_ssh_key" class="block text-gray-700 dark:text-gray-300 mb-3"><?= t('profile.ssh_label') ?></label>
                <textarea id="new_ssh_key" name="new_ssh_key" class="w-full p-4 border rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-400" rows="6"><?= htmlspecialchars($user['ssh_key'] ?? '') ?></textarea>
                <button type="submit" class="mt-6 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 px-6 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 transition-colors">
                    <?= t('profile.ssh_update') ?>
                </button>
            </form>
        </div>

        <!-- Modifier le mot de passe -->
        <div class="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-sm mb-6">
            <h2 class="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4"><?= t('profile.password_title') ?></h2>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                <label for="current_password" class="block text-gray-700 dark:text-gray-300 mb-3"><?= t('profile.password_current') ?></label>
                <input type="password" id="current_password" name="current_password" class="w-full p-4 border rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-400">

                <label for="new_password" class="block text-gray-700 dark:text-gray-300 mt-6 mb-3"><?= t('profile.password_new') ?></label>
                <input type="password" id="new_password" name="new_password" class="w-full p-4 border rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-400">

                <label for="confirm_password" class="block text-gray-700 dark:text-gray-300 mt-6 mb-3"><?= t('profile.password_confirm') ?></label>
                <input type="password" id="confirm_password" name="confirm_password" class="w-full p-4 border rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-400">

                <button type="submit" class="mt-6 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 px-6 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 transition-colors">
                    <?= t('profile.password_submit') ?>
                </button>
            </form>
        </div>
        <!-- Mon activite recente -->
        <?php
        $activityStmt = $pdo->prepare("SELECT action, created_at FROM user_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 15");
        try {
            $activityStmt->execute([$userId]);
            $activities = $activityStmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (\Exception $e) { $activities = []; }
        ?>
        <?php if (!empty($activities)): ?>
        <div class="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
            <h2 class="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4"><?= t('profile.activity') ?></h2>
            <div class="space-y-2">
                <?php foreach ($activities as $act):
                    $icon = '&#8226;';
                    $color = 'text-gray-400';
                    $action = $act['action'];
                    if (stripos($action, 'connexion') !== false) { $icon = '&#128274;'; $color = 'text-green-500'; }
                    elseif (stripos($action, 'ssh') !== false || stripos($action, 'cle') !== false) { $icon = '&#128273;'; $color = 'text-blue-500'; }
                    elseif (stripos($action, 'mot de passe') !== false || stripos($action, 'password') !== false) { $icon = '&#128272;'; $color = 'text-orange-500'; }
                    elseif (stripos($action, 'supprim') !== false || stripos($action, 'delete') !== false) { $icon = '&#128465;'; $color = 'text-red-500'; }
                    elseif (stripos($action, 'creat') !== false || stripos($action, 'ajout') !== false || stripos($action, 'import') !== false) { $icon = '&#10010;'; $color = 'text-green-500'; }
                ?>
                <div class="flex items-center gap-3 text-sm">
                    <span class="text-xs text-gray-400 w-28 flex-shrink-0"><?= date('d/m H:i', strtotime($act['created_at'])) ?></span>
                    <span class="<?= $color ?> flex-shrink-0"><?= $icon ?></span>
                    <span class="text-gray-700 dark:text-gray-300"><?= htmlspecialchars($action) ?></span>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

    </div>
        <!-- Sessions actives -->
        <?php
        $sessionsStmt = $pdo->prepare("SELECT session_id, ip_address, user_agent, last_activity, created_at FROM active_sessions WHERE user_id = ? ORDER BY last_activity DESC LIMIT 10");
        try {
            $sessionsStmt->execute([$userId]);
            $sessions = $sessionsStmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (\Exception $e) { $sessions = []; }
        ?>
        <?php if (!empty($sessions)): ?>
        <div class="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
            <h2 class="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4"><?= t('profile.sessions') ?></h2>
            <div class="space-y-2">
                <?php foreach ($sessions as $sess):
                    $isCurrent = ($sess['session_id'] === session_id());
                    $ua = htmlspecialchars(substr($sess['user_agent'] ?? '', 0, 60));
                    $browser = t('profile.browser');
                    if (stripos($ua, 'chrome') !== false) $browser = 'Chrome';
                    elseif (stripos($ua, 'firefox') !== false) $browser = 'Firefox';
                    elseif (stripos($ua, 'safari') !== false) $browser = 'Safari';
                    elseif (stripos($ua, 'curl') !== false) $browser = 'curl';
                ?>
                <div class="flex items-center justify-between gap-3 px-3 py-2 rounded-lg <?= $isCurrent ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800' : 'bg-gray-50 dark:bg-gray-700/30' ?>">
                    <div class="flex-1 min-w-0">
                        <span class="text-sm font-medium"><?= $isCurrent ? t('profile.this_session') : htmlspecialchars($sess['ip_address']) ?></span>
                        <span class="text-xs text-gray-400 ml-2"><?= $browser ?></span>
                        <span class="text-xs text-gray-400 ml-2"><?= date('d/m H:i', strtotime($sess['last_activity'])) ?></span>
                        <?php if ($isCurrent): ?><span class="text-[10px] px-1.5 py-0.5 bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300 rounded-full ml-2">Active</span><?php endif; ?>
                    </div>
                    <?php if (!$isCurrent): ?>
                    <form method="POST" style="display:inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="revoke_session" value="<?= htmlspecialchars($sess['session_id']) ?>">
                        <button type="submit" class="text-xs text-red-500 hover:text-red-700 font-medium"><?= t('profile.revoke') ?></button>
                    </form>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- Historique de connexion -->
        <?php
        $historyStmt = $pdo->prepare("SELECT ip_address, user_agent, status, created_at FROM login_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 20");
        try {
            $historyStmt->execute([$userId]);
            $loginHistory = $historyStmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (\Exception $e) { $loginHistory = []; }
        ?>
        <?php if (!empty($loginHistory)): ?>
        <div class="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
            <h2 class="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4"><?= t('profile.login_history') ?></h2>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="text-xs text-gray-500 uppercase bg-gray-50 dark:bg-gray-700">
                        <tr>
                            <th class="px-3 py-2 text-left"><?= t('profile.th_date') ?></th>
                            <th class="px-3 py-2 text-left"><?= t('profile.th_ip') ?></th>
                            <th class="px-3 py-2 text-left"><?= t('profile.th_browser') ?></th>
                            <th class="px-3 py-2 text-left"><?= t('profile.th_status') ?></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                        <?php foreach ($loginHistory as $log):
                            $statusCls = match($log['status']) {
                                'success' => 'text-green-600 dark:text-green-400',
                                'failed_password' => 'text-red-500',
                                'failed_2fa' => 'text-orange-500',
                                'locked' => 'text-red-700 font-bold',
                                default => 'text-gray-500',
                            };
                            $statusLabel = match($log['status']) {
                                'success' => t('profile.login_success'),
                                'failed_password' => t('profile.login_failed_pwd'),
                                'failed_2fa' => t('profile.login_failed_2fa'),
                                'locked' => t('profile.login_locked'),
                                default => $log['status'],
                            };
                        ?>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/30">
                            <td class="px-3 py-2 text-xs text-gray-500"><?= date('d/m/Y H:i', strtotime($log['created_at'])) ?></td>
                            <td class="px-3 py-2 font-mono text-xs"><?= htmlspecialchars($log['ip_address']) ?></td>
                            <td class="px-3 py-2 text-xs text-gray-400 truncate max-w-[200px]"><?= htmlspecialchars(substr($log['user_agent'], 0, 60)) ?></td>
                            <td class="px-3 py-2 text-xs font-medium <?= $statusCls ?>"><?= $log['status'] === 'success' ? '&#10003;' : '&#10007;' ?> <?= $statusLabel ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php endif; ?>
    </div>
    <?php require_once __DIR__ . '/footer.php'; ?>
</body>
</html>
