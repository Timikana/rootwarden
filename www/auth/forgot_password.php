<?php
/**
 * auth/forgot_password.php
 *
 * Page "Mot de passe oublie". Genere un token de reinitialisation
 * et envoie un email avec le lien de reset.
 *
 * Securite :
 *   - CSRF token
 *   - Rate limit : max 3 demandes par IP par heure
 *   - Meme message affiche que l'email existe ou non (anti-enumeration)
 *   - Token hache (bcrypt) en BDD, jamais stocke en clair
 *   - Expiration : 1 heure
 *
 * @package RootWarden\Auth
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/../includes/mail_helper.php';
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

// ── Rate limiting : max 3 demandes par IP par heure ─────────────────────────
function checkResetRateLimit(PDO $pdo): bool
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $maxRequests = 3;
    $windowSeconds = 3600; // 1 heure

    try {
        $stmt = $pdo->prepare(
            "SELECT COUNT(*) FROM password_reset_tokens
             WHERE ip_address = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? SECOND)"
        );
        $stmt->execute([$ip, $windowSeconds]);
        return (int)$stmt->fetchColumn() < $maxRequests;
    } catch (PDOException $e) {
        // Si la table n'existe pas encore (migration pas appliquee), autoriser
        return true;
    }
}

// ── Traitement du formulaire ────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $message = t('forgot.error_csrf');
        $messageType = 'error';
    } else {
        $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);

        if (!$email) {
            $message = t('forgot.error_email');
            $messageType = 'error';
        } elseif (!checkResetRateLimit($pdo)) {
            $message = t('forgot.error_rate_limit');
            $messageType = 'error';
        } else {
            // Lookup utilisateur par email (ne revele jamais si l'email existe)
            $stmt = $pdo->prepare("SELECT id, name, email FROM users WHERE email = ? AND active = TRUE LIMIT 1");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // Invalider les tokens precedents non utilises pour cet utilisateur
                $pdo->prepare("UPDATE password_reset_tokens SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL")
                    ->execute([$user['id']]);

                // Generer le token
                $token = bin2hex(random_bytes(32));
                $tokenHash = password_hash($token, PASSWORD_DEFAULT);
                $expiresAt = date('Y-m-d H:i:s', time() + 3600); // +1 heure
                $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

                $stmt = $pdo->prepare(
                    "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_address)
                     VALUES (?, ?, ?, ?)"
                );
                $stmt->execute([$user['id'], $tokenHash, $expiresAt, $ip]);

                // Construire l'URL de reset (URL_HTTPS = URL publique du serveur)
                $baseUrl = rtrim(getenv('URL_HTTPS') ?: 'https://localhost:8443', '/');
                $resetUrl = "{$baseUrl}/auth/reset_password.php?uid={$user['id']}&token={$token}";

                // Envoyer l'email
                sendPasswordResetEmail($user['email'], $resetUrl, $user['name']);
            }

            // Message identique dans tous les cas (anti-enumeration)
            $message = t('forgot.success');
            $messageType = 'success';
        }
    }

    // Regenerer le CSRF pour la prochaine soumission
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ── Branding ────────────────────────────────────────────────────────────────
$appName    = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$appCompany = htmlspecialchars(getenv('APP_COMPANY') ?: '');
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= t('forgot.title') ?> — <?= $appName ?></title>
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
                <p class="text-gray-500 text-sm mt-1"><?= t('forgot.title') ?></p>
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

            <p class="text-gray-600 text-sm mb-4">
                <?= t('forgot.instruction') ?>
            </p>

            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                <div class="mb-4">
                    <label for="email" class="block text-sm font-medium text-gray-700 mb-1">
                        <?= t('forgot.email_label') ?>
                    </label>
                    <input type="email" id="email" name="email"
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg
                                  focus:outline-none focus:ring-2 focus:ring-blue-500
                                  focus:border-transparent transition-colors"
                           autocomplete="email" required
                           placeholder="votre@email.com">
                </div>

                <button type="submit"
                        class="w-full bg-blue-600 hover:bg-blue-700 text-white
                               font-semibold py-2.5 rounded-lg transition-colors
                               focus:outline-none focus:ring-2 focus:ring-blue-400 mb-4">
                    <?= t('forgot.submit') ?>
                </button>
            </form>

            <div class="text-center">
                <a href="login.php" class="text-sm text-blue-600 hover:text-blue-800 hover:underline">
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
