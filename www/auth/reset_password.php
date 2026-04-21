<?php
/**
 * auth/reset_password.php
 *
 * Page de reinitialisation du mot de passe via token email.
 * Valide le token (bcrypt), verifie l'expiration, puis permet
 * a l'utilisateur de definir un nouveau mot de passe.
 *
 * URL attendue : reset_password.php?uid=<user_id>&token=<hex_token>
 *
 * @package RootWarden\Auth
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/../includes/lang.php';

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = '';
$messageType = '';
$tokenValid = false;
$resetDone = false;

// ── Branding ────────────────────────────────────────────────────────────────
$appName    = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$appCompany = htmlspecialchars(getenv('APP_COMPANY') ?: '');

// ── Parametres URL ──────────────────────────────────────────────────────────
$uid   = filter_input(INPUT_GET, 'uid', FILTER_VALIDATE_INT);
$token = trim($_GET['token'] ?? '');

/**
 * Valide un token de reset pour un user_id donne.
 * Retourne le row du token si valide, null sinon.
 */
function validateResetToken(PDO $pdo, int $uid, string $token): ?array
{
    // Recuperer les tokens non utilises et non expires pour cet utilisateur
    $stmt = $pdo->prepare(
        "SELECT id, token_hash, expires_at FROM password_reset_tokens
         WHERE user_id = ? AND used_at IS NULL AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 5"
    );
    $stmt->execute([$uid]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($rows as $row) {
        if (password_verify($token, $row['token_hash'])) {
            return $row;
        }
    }
    return null;
}

// ── Validation initiale du token (GET) ──────────────────────────────────────
if (!$uid || !$token) {
    $message = t('reset.error_invalid');
    $messageType = 'error';
} else {
    try {
        $tokenRow = validateResetToken($pdo, $uid, $token);
        if ($tokenRow) {
            $tokenValid = true;
        } else {
            $message = t('reset.error_expired');
            $messageType = 'error';
        }
    } catch (PDOException $e) {
        $message = t('reset.error_technical');
        $messageType = 'error';
    }
}

// ── Traitement du formulaire (POST) ─────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tokenValid) {
    // CSRF
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $message = t('reset.error_csrf');
        $messageType = 'error';
        $tokenValid = false;
    } else {
        $newPassword     = $_POST['password'] ?? '';
        $confirmPassword = $_POST['password_confirm'] ?? '';

        // Politique centralisee : complexite (15 chars + 4 classes) + historique + HIBP
        require_once __DIR__ . '/password_policy.php';
        $policyError = null;
        if ($newPassword !== $confirmPassword) {
            $message = t('reset.error_mismatch');
            $messageType = 'error';
        } elseif (($policyError = passwordPolicyValidateAll($pdo, $uid, $newPassword)) !== null) {
            $message = t($policyError);
            $messageType = 'error';
        } else {
            try {
                // Re-valider le token (protection double-submit)
                $tokenRow = validateResetToken($pdo, $uid, $token);
                if (!$tokenRow) {
                    $message = t('reset.error_expired_interim');
                    $messageType = 'error';
                    $tokenValid = false;
                } else {
                    $pdo->beginTransaction();

                    // Enregistrer l'ANCIEN hash dans password_history avant l'UPDATE
                    $oldHashRow = $pdo->prepare("SELECT password FROM users WHERE id = ?");
                    $oldHashRow->execute([$uid]);
                    $oldHash = $oldHashRow->fetchColumn();
                    if ($oldHash) passwordPolicyRecordOld($pdo, (int)$uid, (string)$oldHash);

                    // Mettre a jour le mot de passe et effacer le flag force_password_change
                    $hash = password_hash($newPassword, PASSWORD_BCRYPT);
                    $stmt = $pdo->prepare("UPDATE users SET password = ?, force_password_change = FALSE, password_updated_at = NOW() WHERE id = ?");
                    $stmt->execute([$hash, $uid]);

                    // Mettre a jour password_expires_at si politique active
                    $expiryDays = (int)(getenv('PASSWORD_EXPIRY_DAYS') ?: 0);
                    if ($expiryDays > 0) {
                        $expiresAt = date('Y-m-d', strtotime("+{$expiryDays} days"));
                        $pdo->prepare("UPDATE users SET password_expires_at = ? WHERE id = ?")
                            ->execute([$expiresAt, $uid]);
                    }

                    // Marquer le token comme utilise
                    $pdo->prepare("UPDATE password_reset_tokens SET used_at = NOW() WHERE id = ?")
                        ->execute([$tokenRow['id']]);

                    // Invalider tous les autres tokens pour cet utilisateur
                    $pdo->prepare("UPDATE password_reset_tokens SET used_at = NOW() WHERE user_id = ? AND id != ? AND used_at IS NULL")
                        ->execute([$uid, $tokenRow['id']]);

                    $pdo->commit();

                    $resetDone = true;
                    $tokenValid = false;
                    $message = t('reset.success');
                    $messageType = 'success';
                }
            } catch (PDOException $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                $message = t('reset.error_update');
                $messageType = 'error';
                error_log("[RootWarden] Reset password error: " . $e->getMessage());
            }
        }
    }

    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= t('reset.title') ?> — <?= $appName ?></title>
    <link rel="stylesheet" href="/assets/css/tailwind.css">
    <link rel="icon" type="image/png" href="/img/favicon.png">
</head>
<body class="bg-gradient-to-br from-blue-900 to-blue-700 min-h-screen flex items-center justify-center px-4">
    <div class="w-full max-w-sm">

        <!-- ── Card ──────────────────────────────────────────────────────── -->
        <div class="bg-white rounded-2xl shadow-2xl p-8">

            <!-- Header -->
            <div class="text-center mb-6">
                <h1 class="text-2xl font-bold text-gray-800"><?= $appName ?></h1>
                <p class="text-gray-500 text-sm mt-1"><?= t('reset.title') ?></p>
            </div>

            <!-- Message -->
            <?php if ($message): ?>
                <div class="mb-4 p-3 rounded-lg text-sm
                    <?= $messageType === 'error'
                        ? 'bg-red-50 border border-red-200 text-red-700'
                        : 'bg-green-50 border border-green-200 text-green-700' ?>">
                    <?= htmlspecialchars($message) ?>
                </div>
            <?php endif; ?>

            <?php if ($resetDone): ?>
                <!-- Succes : lien vers login -->
                <div class="text-center mt-4">
                    <a href="login.php"
                       class="inline-block bg-blue-600 hover:bg-blue-700 text-white
                              font-semibold py-2.5 px-6 rounded-lg transition-colors">
                        <?= t('reset.sign_in') ?>
                    </a>
                </div>

            <?php elseif ($tokenValid): ?>
                <!-- Formulaire nouveau mot de passe -->
                <form method="POST" action="reset_password.php?uid=<?= (int)$uid ?>&token=<?= htmlspecialchars($token) ?>">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                    <div class="mb-4">
                        <label for="password" class="block text-sm font-medium text-gray-700 mb-1">
                            <?= t('reset.new_password') ?>
                        </label>
                        <input type="password" id="password" name="password"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg
                                      focus:outline-none focus:ring-2 focus:ring-blue-500
                                      focus:border-transparent transition-colors"
                               autocomplete="new-password" required minlength="8">
                    </div>

                    <div class="mb-4">
                        <label for="password_confirm" class="block text-sm font-medium text-gray-700 mb-1">
                            <?= t('reset.confirm_password') ?>
                        </label>
                        <input type="password" id="password_confirm" name="password_confirm"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg
                                      focus:outline-none focus:ring-2 focus:ring-blue-500
                                      focus:border-transparent transition-colors"
                               autocomplete="new-password" required minlength="8">
                    </div>

                    <p class="text-xs text-gray-500 mb-4">
                        <?= t('reset.min_chars') ?>
                    </p>

                    <button type="submit"
                            class="w-full bg-blue-600 hover:bg-blue-700 text-white
                                   font-semibold py-2.5 rounded-lg transition-colors
                                   focus:outline-none focus:ring-2 focus:ring-blue-400">
                        <?= t('reset.submit') ?>
                    </button>
                </form>

            <?php else: ?>
                <!-- Token invalide / expire -->
                <div class="text-center mt-2">
                    <a href="forgot_password.php"
                       class="text-sm text-blue-600 hover:text-blue-800 hover:underline">
                        <?= t('reset.request_new') ?>
                    </a>
                </div>
            <?php endif; ?>

            <!-- Retour connexion -->
            <div class="text-center mt-4">
                <a href="login.php" class="text-sm text-gray-500 hover:text-gray-700 hover:underline">
                    &larr; <?= t('forgot.back') ?>
                </a>
            </div>
        </div>

        <!-- ── Footer ────────────────────────────────────────────────────── -->
        <p class="text-center text-blue-300 text-xs mt-6 opacity-60">
            <?= $appName ?>
            <?php if ($appCompany): ?> &middot; <?= $appCompany ?><?php endif; ?>
        </p>
    </div>
</body>
</html>
