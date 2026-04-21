<?php
/**
 * auth/login.php
 *
 * Page de connexion du portail RootWarden.
 * Gère :
 *   - La protection CSRF (jeton en session)
 *   - Le rate limiting par IP (table login_attempts, max 5 essais / 10 min)
 *   - L'authentification bcrypt via password_verify()
 *   - L'option "Se souvenir de moi" (token 30 jours, table remember_tokens)
 *   - La redirection vers verify_2fa.php ou enable_2fa.php selon la présence du secret TOTP
 *
 * @package RootWarden\Auth
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/../adm/includes/crypto.php';
require_once __DIR__ . '/../adm/includes/audit_log.php';
require_once __DIR__ . '/../includes/lang.php';

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Génération du jeton CSRF si inexistant
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Vérifie et met à jour le rate limiting de connexion (max 5 tentatives / 10 min par IP).
 * Retourne true si la tentative est autorisée, false si bloquée.
 */
function checkLoginRateLimit(PDO $pdo): bool {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $windowSeconds = 600; // 10 minutes
    $maxAttempts = 5;

    // Nettoyage des tentatives expirées (au-dela de 24h pour preserver l'analyse spraying)
    $pdo->prepare("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 86400 SECOND)")
        ->execute();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at >= DATE_SUB(NOW(), INTERVAL ? SECOND)");
    $stmt->execute([$ip, $windowSeconds]);
    $count = (int) $stmt->fetchColumn();

    return $count < $maxAttempts;
}

/**
 * Detection password spraying : meme IP teste plus de 5 usernames distincts en 10min.
 * Retourne le nombre de usernames testes (>= 5 = suspect).
 */
function detectPasswordSpraying(PDO $pdo): int {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $stmt = $pdo->prepare(
        "SELECT COUNT(DISTINCT username) FROM login_attempts
         WHERE ip_address = ? AND success = 0 AND username IS NOT NULL
         AND attempted_at >= DATE_SUB(NOW(), INTERVAL 600 SECOND)"
    );
    $stmt->execute([$ip]);
    return (int) $stmt->fetchColumn();
}

/**
 * Enregistre une tentative de connexion (succes ou echec) avec username.
 */
function recordLoginAttempt(PDO $pdo, ?string $username, bool $success): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $pdo->prepare("INSERT INTO login_attempts (ip_address, username, success, attempted_at) VALUES (?, ?, ?, NOW())")
        ->execute([$ip, $username ? substr($username, 0, 100) : null, $success ? 1 : 0]);
}

/** Backward-compat alias utilise ailleurs dans le code. */
function recordFailedLoginAttempt(PDO $pdo, ?string $username = null): void {
    recordLoginAttempt($pdo, $username, false);
}

/**
 * Calcule la duree de lockout per-user en fonction du nombre d'echecs consecutifs.
 * Progression : 1min → 5min → 15min → 60min → 240min (max).
 */
function computeUserLockoutSeconds(int $failedAttempts): int {
    if ($failedAttempts < 3) return 0;
    return match ($failedAttempts) {
        3 => 60,
        4 => 300,
        5 => 900,
        6 => 3600,
        default => 14400, // 4h pour 7+ echecs
    };
}

/**
 * Notifie le superadmin via user_logs d'une activite suspecte (password spraying detecte).
 */
function notifySpraying(PDO $pdo, string $ip, int $distinctUsers): void {
    try {
        audit_log_raw($pdo, 0, sprintf(
            "[security] Password spraying detecte — IP=%s usernames=%d/10min",
            $ip, $distinctUsers
        ));
    } catch (\Exception $e) {}
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkCsrfToken();

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $error    = null;

    if (!checkLoginRateLimit($pdo)) {
        // Detection password spraying : alerter si > 5 usernames distincts testes
        $sprayed = detectPasswordSpraying($pdo);
        if ($sprayed >= 5) {
            notifySpraying($pdo, $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', $sprayed);
        }
        $error = t('login.error_rate_limit');
    } else {
        $stmt = $pdo->prepare("SELECT id, name, password, role_id, totp_secret, active, failed_attempts, locked_until FROM users WHERE name = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Lockout per-user avec backoff progressif
        $isUserLocked = false;
        $userLockRemaining = 0;
        if ($user && !empty($user['locked_until'])) {
            $lockTs = strtotime($user['locked_until']);
            if ($lockTs > time()) {
                $isUserLocked = true;
                $userLockRemaining = $lockTs - time();
            }
        }

        if ($isUserLocked) {
            // On NE verifie PAS le password — evite oracle sur le lockout
            recordLoginAttempt($pdo, $username, false);
            $mins = max(1, (int)ceil($userLockRemaining / 60));
            $error = t('login.error_user_locked', ['minutes' => $mins]);
        } elseif ($user && (int)($user['active'] ?? 0) !== 1) {
            // Compte desactive — message generique (pas d'enumeration)
            recordLoginAttempt($pdo, $username, false);
            $error = t('login.error_credentials');
        } elseif ($user && password_verify($password, $user['password'])) {
            // Reset du compteur per-user au succes
            try {
                $pdo->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?")
                    ->execute([$user['id']]);
            } catch (\Exception $e) {}
            recordLoginAttempt($pdo, $username, true);

            // NE PAS initialiser la session complete avant le 2FA !
            // Seul temp_user est set ici. La session definitive est initialisee
            // dans verify_2fa.php apres verification du code TOTP.
            session_regenerate_id(true);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['2fa_required'] = true;

            // Gestion de "Se souvenir de moi"
            if (isset($_POST['remember_me']) && $_POST['remember_me'] === 'on') {
                $token      = bin2hex(random_bytes(32));
                $token_hash = password_hash($token, PASSWORD_DEFAULT);

                $stmt = $pdo->prepare("REPLACE INTO remember_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)");
                $stmt->execute([
                    $user['id'],
                    $token_hash,
                    date('Y-m-d H:i:s', strtotime('+30 days')),
                ]);

                setcookie('remember_token', "{$user['id']}:$token", [
                    'expires'  => time() + 2592000,
                    'path'     => '/',
                    'secure'   => true,
                    'httponly' => true,
                    'samesite' => 'Strict',
                ]);
            }

            // Audit log : connexion réussie (hash chain)
            try {
                audit_log_raw($pdo, (int)$user['id'], 'Connexion reussie');
            } catch (\Exception $e) {}

            // Historique de login (login_history)
            try {
                $pdo->prepare("INSERT INTO login_history (user_id, ip_address, user_agent, status) VALUES (?, ?, ?, 'success')")
                    ->execute([$user['id'], $_SERVER['REMOTE_ADDR'] ?? '', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500)]);
            } catch (\Exception $e) {}

            // Enregistrer la session active (active_sessions)
            try {
                $pdo->prepare("REPLACE INTO active_sessions (session_id, user_id, ip_address, user_agent) VALUES (?, ?, ?, ?)")
                    ->execute([session_id(), $user['id'], $_SERVER['REMOTE_ADDR'] ?? '', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500)]);
            } catch (\Exception $e) {}

            // Redirection selon TOTP
            $_SESSION['temp_user'] = [
                'id'       => $user['id'],
                'username' => $user['name'],
                'role_id'  => (int) $user['role_id'],
            ];

            if (empty($user['totp_secret'])) {
                header("Location: enable_2fa.php");
            } else {
                header("Location: verify_2fa.php");
            }
            exit();

        } else {
            recordLoginAttempt($pdo, $username, false);

            // Incrementer failed_attempts + calculer lockout per-user
            if ($user) {
                try {
                    $newFailed = (int)($user['failed_attempts'] ?? 0) + 1;
                    $lockSec = computeUserLockoutSeconds($newFailed);
                    if ($lockSec > 0) {
                        $pdo->prepare(
                            "UPDATE users SET failed_attempts = ?, locked_until = DATE_ADD(NOW(), INTERVAL ? SECOND), "
                            . "last_failed_login_at = NOW() WHERE id = ?"
                        )->execute([$newFailed, $lockSec, $user['id']]);
                        // Notification superadmin au 5eme echec consecutif (hash chain)
                        if ($newFailed === 5) {
                            audit_log_raw($pdo, (int)$user['id'], sprintf(
                                "[security] Compte verrouille apres %d echecs consecutifs — IP=%s",
                                $newFailed, $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
                            ));
                        }
                    } else {
                        $pdo->prepare(
                            "UPDATE users SET failed_attempts = ?, last_failed_login_at = NOW() WHERE id = ?"
                        )->execute([$newFailed, $user['id']]);
                    }
                } catch (\Exception $e) {}

                // Historique de login : echec
                try {
                    $pdo->prepare("INSERT INTO login_history (user_id, ip_address, user_agent, status) VALUES (?, ?, ?, 'failed_password')")
                        ->execute([$user['id'], $_SERVER['REMOTE_ADDR'] ?? '', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500)]);
                } catch (\Exception $e) {}
            }

            // Detection password spraying
            $sprayed = detectPasswordSpraying($pdo);
            if ($sprayed >= 5) {
                notifySpraying($pdo, $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', $sprayed);
            }

            // Message générique pour éviter l'énumération d'utilisateurs
            $error = t('login.error_credentials');
        }
    }
}
?>

<?php
// ── Branding depuis les variables d'environnement ─────────────────────────
$loginAppName    = htmlspecialchars(getenv('APP_NAME')    ?: 'RootWarden');
$loginAppTagline = htmlspecialchars(getenv('APP_TAGLINE') ?: 'Gestion SSH centralisée');
$loginAppCompany = htmlspecialchars(getenv('APP_COMPANY') ?: '');
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" sizes="32x32" href="../img/favicon.png">
    <link rel="apple-touch-icon" href="../img/favicon.png">
    <meta name="theme-color" content="#ffffff">
    <title><?= t('login.title') ?> — <?= $loginAppName ?></title>
    <link rel="stylesheet" href="/assets/css/tailwind.css">
</head>
<body class="bg-gradient-to-br from-blue-900 to-blue-700 min-h-screen
             flex items-center justify-center px-4">

    <div class="w-full max-w-sm">

        <!-- ── En-tête branding ──────────────────────────────────────────── -->
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-white tracking-tight">
                <?= $loginAppName ?>
            </h1>
            <?php if ($loginAppCompany): ?>
            <p class="text-blue-200 text-sm mt-1 font-medium"><?= $loginAppCompany ?></p>
            <?php endif; ?>
            <p class="text-blue-300 text-xs mt-1"><?= $loginAppTagline ?></p>
        </div>

        <!-- ── Formulaire ────────────────────────────────────────────────── -->
        <div class="bg-white rounded-2xl shadow-2xl p-8">
            <h2 class="text-xl font-bold text-blue-900 mb-6 text-center"><?= t('login.title') ?></h2>

            <?php if (isset($_GET['expired'])): ?>
            <div class="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-yellow-700 text-sm text-center">
                <?= t('login.session_expired') ?>
            </div>
            <?php endif; ?>

            <?php if (isset($_GET['password_expired'])): ?>
            <div class="mb-4 p-3 bg-orange-50 border border-orange-200 rounded-lg text-orange-700 text-sm text-center">
                &#9888; <?= t('login.password_expired') ?>
            </div>
            <?php endif; ?>

            <?php
            // Afficher le temps restant si l'IP est bloquee
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
            $lockStmt = $pdo->prepare("SELECT MAX(attempted_at) as last_attempt, COUNT(*) as cnt FROM login_attempts WHERE ip_address = ? AND attempted_at >= DATE_SUB(NOW(), INTERVAL 600 SECOND)");
            $lockStmt->execute([$ip]);
            $lockInfo = $lockStmt->fetch(PDO::FETCH_ASSOC);
            if (($lockInfo['cnt'] ?? 0) >= 5):
                $lastAttempt = strtotime($lockInfo['last_attempt']);
                $unlockAt = $lastAttempt + 600;
                $remaining = $unlockAt - time();
                if ($remaining > 0):
                    // Arrondi UP, minimum 1 (pour eviter "0 minute(s)" quand il reste < 60s)
                    $minutes = max(1, (int)ceil($remaining / 60));
            ?>
            <div class="mb-4 p-3 bg-red-50 border border-red-300 rounded-lg text-red-700 text-sm text-center">
                &#128274; <?= t('login.error_locked', ['minutes' => $minutes]) ?>
            </div>
            <?php
                endif;
            endif; ?>

            <?php if (isset($error)): ?>
            <div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg
                        text-red-600 text-sm text-center">
                <?= htmlspecialchars($error) ?>
            </div>
            <?php endif; ?>

            <form method="POST" class="space-y-4">
                <input type="hidden" name="csrf_token"
                       value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">

                <div>
                    <label for="username"
                           class="block text-sm font-medium text-gray-700 mb-1">
                        <?= t('login.username') ?>
                    </label>
                    <input type="text" id="username" name="username"
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg
                                  focus:outline-none focus:ring-2 focus:ring-blue-500
                                  focus:border-transparent transition-colors"
                           autocomplete="username" required>
                </div>

                <div>
                    <label for="password"
                           class="block text-sm font-medium text-gray-700 mb-1">
                        <?= t('login.password') ?>
                    </label>
                    <input type="password" id="password" name="password"
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg
                                  focus:outline-none focus:ring-2 focus:ring-blue-500
                                  focus:border-transparent transition-colors"
                           autocomplete="current-password" required>
                    <div class="text-right mt-1">
                        <a href="forgot_password.php"
                           class="text-xs text-blue-600 hover:text-blue-800 hover:underline">
                            <?= t('login.forgot_password') ?>
                        </a>
                    </div>
                </div>

                <div class="flex items-center">
                    <input type="checkbox" id="remember_me" name="remember_me"
                           class="h-4 w-4 text-blue-600 rounded border-gray-300
                                  focus:ring-blue-500">
                    <label for="remember_me" class="ml-2 text-sm text-gray-600">
                        <?= t('login.remember_me') ?>
                    </label>
                </div>

                <button type="submit"
                        class="w-full bg-blue-600 hover:bg-blue-700 text-white
                               font-semibold py-2.5 rounded-lg transition-colors
                               focus:outline-none focus:ring-2 focus:ring-orange-400">
                    <?= t('login.submit') ?>
                </button>
            </form>
        </div>

        <!-- ── Language toggle ────────────────────────────────────────────── -->
        <div class="flex justify-center gap-2 mt-4">
            <a href="?lang=fr" class="text-xs px-2 py-0.5 rounded <?= getLang()==='fr' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:text-white' ?>">FR</a>
            <a href="?lang=en" class="text-xs px-2 py-0.5 rounded <?= getLang()==='en' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:text-white' ?>">EN</a>
        </div>

        <!-- ── Footer discret ────────────────────────────────────────────── -->
        <p class="text-center text-blue-300 text-xs mt-6 opacity-60">
            <?= $loginAppName ?>
            <?php if ($loginAppCompany): ?> · <?= $loginAppCompany ?><?php endif; ?>
        </p>
    </div>
</body>
</html>
