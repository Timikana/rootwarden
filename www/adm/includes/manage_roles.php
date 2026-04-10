<?php
/**
 * adm/includes/manage_roles.php
 *
 * Interface de gestion des utilisateurs du portail RootWarden.
 * Réservé aux rôles admin (2) et superadmin (3).
 *
 * Fonctionnalités (toutes protégées par jeton CSRF) :
 *   - change_password : modifie ou réinitialise le mot de passe d'un utilisateur
 *     (génération automatique si le champ est vide) ; les admins ne peuvent pas
 *     modifier le mot de passe d'un superadmin
 *   - reset_2fa       : remet à NULL le secret TOTP d'un utilisateur
 *   - change_role     : modifie le rôle portail d'un utilisateur (contrôle hiérarchique)
 *   - Affichage du tableau des utilisateurs avec leur rôle (JOIN sur la table roles)
 *   - Suppression d'utilisateur via AJAX (delete_user.php)
 *
 * @package RootWarden\Admin
 */
// manage_roles.php

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/crypto.php'; // Peut être supprimé si non utilisé

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Autorise les utilisateurs ayant le rôle admin (2) ou superadmin (3)
checkAuth([2, 3]);

/**
 * Valide une donnée d'entrée pour la gestion des utilisateurs portail.
 *
 * Types supportés :
 *   - 'password' : chaîne d'au moins 8 caractères (retourne la valeur trimée, ou false)
 *   - 'role'     : entier positif (valide via FILTER_VALIDATE_INT min_range=1)
 *
 * @param mixed  $data Donnée brute à valider.
 * @param string $type Type de validation ('password' ou 'role').
 * @return mixed La donnée validée, ou false si invalide.
 */
function validateInputUsers($data, $type) {
    switch ($type) {
        case 'password':
            // Vérifie que le mot de passe a une longueur minimale
            return (strlen(trim($data)) >= 8) ? trim($data) : false;
        case 'role':
            // Vérifie que le rôle est un entier positif
            return filter_var($data, FILTER_VALIDATE_INT, ["options" => ["min_range" => 1]]);
        default:
            return false;
    }
}

// Réinitialisation ou définition du mot de passe
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    checkCsrfToken();
    $user_id = (int)$_POST['user_id'];
    $new_password = !empty(trim($_POST['new_password'])) 
        ? trim($_POST['new_password']) 
        : generateSecurePassword(); // Génère si vide

    // Validation du mot de passe
    if (!validateInputUsers($new_password, 'password')) {
        $error = t('roles.error_password_min_length');
    } else {
        try {
            // Récupérer le rôle de l'utilisateur
            $stmt = $pdo->prepare("SELECT role_id FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                throw new Exception(t('roles.error_user_not_found'));
            }

            // Vérifier les permissions
            if ($_SESSION['role_id'] === 2 && $user['role_id'] === 3) {
                throw new Exception(t('roles.error_cannot_edit_superadmin_password'));
            }

            // Hasher le nouveau mot de passe
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

            // Mettre à jour le mot de passe et forcer le changement à la prochaine connexion
            $stmt = $pdo->prepare("UPDATE users SET password = ?, force_password_change = TRUE WHERE id = ?");
            $stmt->execute([$hashed_password, $user_id]);

            $success = !empty($_POST['new_password'])
                ? t('roles.password_changed_success')
                : t('roles.password_reset_success') . " <br> " . t('roles.generated_password') . " : <strong>$new_password</strong>";
        } catch (Exception $e) {
            $error = htmlspecialchars($e->getMessage());
        }
    }
}

// Réinitialisation du 2FA
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_2fa'])) {
    checkCsrfToken();
    $user_id = (int)$_POST['user_id'];

    try {
        // Garde hierarchique : un admin ne peut pas reset le 2FA d'un superadmin
        $stmt = $pdo->prepare("SELECT role_id FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $targetUser = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$targetUser) throw new Exception(t('roles.error_user_not_found'));
        if ($_SESSION['role_id'] === 2 && (int)$targetUser['role_id'] === 3) {
            throw new Exception(t('roles.error_cannot_reset_superadmin_2fa'));
        }

        $stmt = $pdo->prepare("UPDATE users SET totp_secret = NULL WHERE id = ?");
        $stmt->execute([$user_id]);
        $success = t('roles.2fa_reset_success');
    } catch (Exception $e) {
        $error = t('roles.error_2fa_reset') . ' ' . htmlspecialchars($e->getMessage());
    }
}

// Modification du rôle
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_role'])) {
    checkCsrfToken();
    $user_id = (int)$_POST['user_id'];
    $new_role_id = (int)$_POST['new_role'];

    try {
        // Vérifier que le nouveau rôle existe
        $stmt = $pdo->prepare("SELECT id FROM roles WHERE id = ?");
        $stmt->execute([$new_role_id]);
        if (!$stmt->fetch()) {
            throw new Exception(t('roles.error_invalid_role'));
        }

        // Récupérer le rôle actuel de l'utilisateur
        $stmt = $pdo->prepare("SELECT role_id FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            throw new Exception(t('roles.error_user_not_found'));
        }

        // Vérifier les permissions — empecher l'escalade de privileges
        if ($_SESSION['role_id'] === 2 && $user['role_id'] === 3) {
            throw new Exception(t('roles.error_cannot_edit_superadmin_role'));
        }
        if ($new_role_id > $_SESSION['role_id']) {
            throw new Exception(t('roles.error_cannot_assign_higher_role'));
        }
        if ($user_id === (int)$_SESSION['user_id']) {
            throw new Exception(t('roles.error_cannot_edit_own_role'));
        }

        // Mettre à jour le rôle
        $stmt = $pdo->prepare("UPDATE users SET role_id = ? WHERE id = ?");
        $stmt->execute([$new_role_id, $user_id]);

        $success = t('roles.role_changed_success');
    } catch (Exception $e) {
        $error = htmlspecialchars($e->getMessage());
    }
}

// Récupération des utilisateurs avec leur rôle + dernière connexion
$stmt = $pdo->query("
    SELECT u.id, u.name, r.name AS role, u.active, u.totp_secret,
           (SELECT MAX(l.created_at) FROM user_logs l WHERE l.user_id = u.id AND l.action LIKE 'Connexion%') as last_login
    FROM users u
    INNER JOIN roles r ON u.role_id = r.id
    ORDER BY u.name
");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<div>
    <h2 class="text-xl font-bold text-gray-800 dark:text-gray-100 mb-4"><?= t('roles.title') ?></h2>
    <p class="text-xs text-gray-400 mt-0.5"><?= t('roles.desc') ?></p>
    <!-- Recherche -->
    <div class="mb-3">
        <input type="text" placeholder="<?= t('roles.filter_placeholder') ?>" class="w-full sm:w-64 px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500"
               oninput="document.querySelectorAll('#portail-users-table tbody tr').forEach(tr => { tr.style.display = tr.textContent.toLowerCase().includes(this.value.toLowerCase()) ? '' : 'none'; })">
    </div>

    <?php if (isset($success)): ?>
        <script>document.addEventListener('DOMContentLoaded', () => toast(<?= json_encode(strip_tags($success)) ?>, 'success', 8000));</script>
    <?php endif; ?>
    <?php if (isset($error)): ?>
        <script>document.addEventListener('DOMContentLoaded', () => toast(<?= json_encode($error) ?>, 'error'));</script>
    <?php endif; ?>

    <div class="overflow-x-auto">
        <table id="portail-users-table" class="min-w-full text-sm">
            <thead>
                <tr class="bg-gray-100 dark:bg-gray-700 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    <th class="py-3 px-4"><?= t('roles.th_user') ?></th>
                    <th class="py-3 px-4"><?= t('roles.th_role') ?></th>
                    <th class="py-3 px-4 text-center"><?= t('roles.th_status') ?></th>
                    <th class="py-3 px-4"><?= t('roles.th_last_login') ?></th>
                    <th class="py-3 px-4"><?= t('roles.th_change_role') ?></th>
                    <th class="py-3 px-4"><?= t('roles.th_password') ?></th>
                    <th class="py-3 px-4 text-center"><?= t('roles.th_2fa') ?></th>
                    <th class="py-3 px-4 text-center"><?= t('roles.th_actions') ?></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                <?php
                $roles = $pdo->query("SELECT id, name FROM roles ORDER BY id ASC")->fetchAll(PDO::FETCH_ASSOC);
                foreach ($users as $user): ?>
                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td class="py-3 px-4 font-medium text-gray-800 dark:text-gray-200"><?= htmlspecialchars($user['name']) ?></td>
                    <td class="py-3 px-4">
                        <span class="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-400"><?= htmlspecialchars($user['role']) ?></span>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <div class="flex items-center justify-center gap-1.5">
                            <span class="inline-block w-2 h-2 rounded-full <?= $user['active'] ? 'bg-green-500' : 'bg-red-500' ?>"></span>
                            <?php if (!empty($user['totp_secret'])): ?>
                                <span class="text-[10px] px-1 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400">2FA</span>
                            <?php endif; ?>
                        </div>
                    </td>
                    <td class="py-3 px-4 text-xs text-gray-400 whitespace-nowrap">
                        <?php if ($user['last_login']): ?>
                            <?= date('d/m/Y H:i', strtotime($user['last_login'])) ?>
                        <?php else: ?>
                            <span class="text-gray-300 dark:text-gray-600"><?= t('roles.never') ?></span>
                        <?php endif; ?>
                    </td>
                    <td class="py-3 px-4">
                        <form method="POST" class="flex items-center gap-1">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <input type="hidden" name="user_id" value="<?= (int)$user['id'] ?>">
                            <select name="new_role" class="text-xs px-2 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500">
                                <?php foreach ($roles as $ro): ?>
                                    <option value="<?= (int)$ro['id'] ?>" <?= ($user['role'] === $ro['name']) ? 'selected' : '' ?>><?= htmlspecialchars($ro['name']) ?></option>
                                <?php endforeach; ?>
                            </select>
                            <button type="submit" name="change_role" class="text-xs px-2 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors">OK</button>
                        </form>
                    </td>
                    <td class="py-3 px-4">
                        <form method="POST" class="flex items-center gap-1">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <input type="hidden" name="user_id" value="<?= (int)$user['id'] ?>">
                            <input type="password" name="new_password" placeholder="<?= t('roles.password_placeholder') ?>" class="w-36 text-xs px-2 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500">
                            <button type="submit" name="change_password" onclick="return confirm('<?= t('roles.confirm_reset_password', ['name' => htmlspecialchars(addslashes($user['name']))]) ?>')" class="text-xs px-2 py-1.5 bg-orange-500 hover:bg-orange-600 text-white rounded-lg transition-colors whitespace-nowrap"><?= t('roles.btn_reset_password') ?></button>
                        </form>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <input type="hidden" name="user_id" value="<?= (int)$user['id'] ?>">
                            <button type="submit" name="reset_2fa" onclick="return confirm('<?= t('roles.confirm_reset_2fa', ['name' => htmlspecialchars(addslashes($user['name']))]) ?>')" class="text-xs px-2 py-1.5 border border-red-300 text-red-600 hover:bg-red-50 dark:border-red-700 dark:text-red-400 dark:hover:bg-red-900/30 rounded-lg transition-colors"><?= t('roles.btn_reset_2fa') ?></button>
                        </form>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <button onclick="if(confirm('<?= t('roles.confirm_delete_user', ['name' => htmlspecialchars(addslashes($user['name']))]) ?>')) deleteUser(<?= (int)$user['id'] ?>, '<?= htmlspecialchars(addslashes($user['name'])) ?>')" class="text-xs px-2 py-1.5 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors"><?= t('roles.btn_delete') ?></button>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Notifications -->
    <div id="notifications" class="fixed bottom-4 right-4 z-50"></div>
</div>

<!-- Scripts -->
<script>
// deleteUser() est definie dans admin.js (avec toast + location.reload)

/**
 * Fonction pour afficher des notifications
 * @param {string} message - Message à afficher
 * @param {string} type - Type de notification ('success', 'error', 'info')
 */
function showNotification(message, type = 'success') {
    const notifications = document.getElementById('notifications');
    const bgColor = type === 'success' ? 'bg-green-100' :
                    type === 'error' ? 'bg-red-100' :
                    'bg-blue-100';
    const textColor = type === 'success' ? 'text-green-700' :
                      type === 'error' ? 'text-red-700' :
                      'text-blue-700';
    notifications.innerHTML = `
        <div class="flex items-center justify-between ${bgColor} ${textColor} px-4 py-3 rounded-lg shadow-md mb-4">
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.innerHTML = ''" class="text-xl font-bold">&times;</button>
        </div>
    `;
    // Auto-hide après 5 secondes
    setTimeout(() => {
        notifications.innerHTML = "";
    }, 5000);
}
</script>
