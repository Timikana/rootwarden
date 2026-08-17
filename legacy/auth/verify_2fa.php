<?php
/**
 * auth/verify_2fa.php
 *
 * Étape de vérification TOTP lors de la connexion.
 * L'utilisateur doit saisir son code TOTP à 6 chiffres généré par son application
 * d'authentification. La vérification tolère une période de décalage (±1 fenêtre de 30 s)
 * via OTPHP\TOTP::verify($code, null, 1).
 *
 * Flux :
 *   - Requiert $_SESSION['temp_user'] (défini après la validation mot de passe dans login.php)
 *   - En cas de succès : initialise la session définitive et redirige vers terms.php
 *   - En cas d'échec : affiche un message d'erreur
 *
 * @package RootWarden\Auth
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/../includes/totp_crypto.php';
require_once __DIR__ . '/../includes/lang.php';
use OTPHP\TOTP;

// Vérifie si l'utilisateur temporaire est connecté
if (!isset($_SESSION['temp_user'])) {
    header("Location: login.php");
    exit();
}

$userid = $_SESSION['temp_user']['id'];

// Récupérer le secret TOTP de la base de données
$stmt = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ?");
$stmt->execute([$userid]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || empty($user['totp_secret'])) {
    die(t('2fa.error_no_secret'));
}

// Dechiffre le secret TOTP (retrocompatible plaintext legacy)
$totpPlain = decryptTotpSecret($user['totp_secret']);
$totp = TOTP::create($totpPlain);

// Vérification du code soumis
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['2fa_code'])) {
    checkCsrfToken();
    $code = $_POST['2fa_code'];

    // Rate limiting 2FA : max 5 tentatives / minute par SESSION + max 10 / 10 min par IP.
    // Patch A07-01 (chaine if/elseif/else) + A07-NEW-01 (compteur IP en DB).
    // Avant A07-NEW-01 : le rate-limit etait uniquement par session ; un attaquant
    // pouvait reset le compteur en rejetant son cookie de session et en se
    // re-logguant a chaque cycle. Maintenant on a un compteur IP-based en DB qui
    // resiste a la rotation de session.
    if (!isset($_SESSION['2fa_attempts'])) $_SESSION['2fa_attempts'] = [];
    $_SESSION['2fa_attempts'] = array_filter($_SESSION['2fa_attempts'], fn($t) => $t > time() - 60);
    $_SESSION['2fa_attempts'][] = time();

    $codeHash = hash('sha256', $code . floor(time() / 30));

    // Compteur IP-based via login_attempts (etape = '2fa')
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ipBlocked = false;
    $attemptId = null; // id de la ligne login_attempts, pour la repasser a success=1 si OK
    try {
        $stmtIp = $pdo->prepare(
            "SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? "
            . "AND attempted_at > (NOW() - INTERVAL 10 MINUTE) AND step = '2fa' AND success = 0"
        );
        $stmtIp->execute([$clientIp]);
        $ipBlocked = ((int)$stmtIp->fetchColumn()) >= 10;
        // On enregistre la tentative en cours (success=0, on update si OK plus bas)
        $pdo->prepare(
            "INSERT INTO login_attempts (ip_address, username, success, step, attempted_at) "
            . "VALUES (?, ?, 0, '2fa', NOW())"
        )->execute([$clientIp, $_SESSION['temp_user']['name'] ?? 'unknown']);
        $attemptId = (int)$pdo->lastInsertId();
    } catch (\Throwable $_e) {
        // Si la colonne 'step' n'existe pas dans la table (migration pas faite),
        // on continue avec le rate-limit session uniquement. Pas blocker.
    }

    if ($ipBlocked) {
        $error = t('2fa.error_rate_limit');
    } elseif (count($_SESSION['2fa_attempts']) > 5) {
        $error = t('2fa.error_rate_limit');
    } elseif (isset($_SESSION['last_totp_hash']) && $_SESSION['last_totp_hash'] === $codeHash) {
        // Anti-replay : rejeter un code deja utilise dans cette fenetre de temps
        $error = t('2fa.error_reused');
    } elseif ($totp->verify($code, null, 1)) { // null = heure actuelle, 1 = tolerance d'une periode
        $_SESSION['last_totp_hash'] = $codeHash;

        // Patch (bug) : repasser la tentative a success=1. Avant, la ligne
        // restait a success=0 -> une 2FA REUSSIE comptait comme un echec dans
        // le compteur IP ">=10 echecs/10min" et bloquait des users legitimes
        // (notamment plusieurs comptes derriere une meme IP/NAT).
        if ($attemptId) {
            try {
                $pdo->prepare("UPDATE login_attempts SET success = 1 WHERE id = ?")->execute([$attemptId]);
            } catch (\Throwable $_e) {}
        }

        // Verifier que l'utilisateur existe et est actif en DB (ZERO TRUST)
        $stmtUser = $pdo->prepare("SELECT id, name, role_id, active, force_password_change FROM users WHERE id = ? AND active = 1");
        $stmtUser->execute([$_SESSION['temp_user']['id']]);
        $userData = $stmtUser->fetch(PDO::FETCH_ASSOC);

        if (!$userData) {
            // Utilisateur desactive entre le login et le 2FA
            session_unset();
            session_destroy();
            header("Location: login.php");
            exit();
        }

        // Initialiser la session definitive avec les donnees verifiees en DB
        initializeUserSession($userData);

        // Nettoyer les variables temporaires
        unset($_SESSION['temp_user'], $_SESSION['2fa_required'], $_SESSION['2fa_pending'],
              $_SESSION['2fa_attempts'], $_SESSION['last_totp_hash']);

        // Verifier si l'utilisateur doit changer son mot de passe
        if ((int)($userData['force_password_change'] ?? 0) === 1) {
            $_SESSION['force_password_change'] = true;
            header("Location: ../profile.php?force_change=1");
            exit();
        }

        header("Location: ../terms.php");
        exit();
    } else {
        // Patch (bug) : la tentative est deja enregistree ligne ~62
        // ($_SESSION['2fa_attempts'][] = time()). Un second push ici la comptait
        // double -> lockout 2FA au bout de ~3 essais reels au lieu de 5.
        $error = t('2fa.error_invalid');
    }
}
?>

<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <meta charset="UTF-8">
    <link rel="icon" type="image/png" sizes="32x32" href="../img/favicon.png">
    <link rel="apple-touch-icon" href="img/favicon.png">
    <meta name="theme-color" content="#ffffff">
    <title><?= t('2fa.title') ?></title>
    <link rel="stylesheet" href="/assets/css/tailwind.css">
</head>
<body class="bg-gradient-to-br from-blue-900 to-blue-700 min-h-screen flex items-center justify-center px-4">
    <div class="w-full max-w-sm">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-white tracking-tight"><?= htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden') ?></h1>
            <p class="text-blue-300 text-xs mt-1"><?= t('2fa.title') ?></p>
        </div>
        <div class="bg-white rounded-2xl shadow-2xl p-8">
            <h2 class="text-xl font-bold text-blue-900 mb-2 text-center"><?= t('2fa.subtitle') ?></h2>
            <p class="text-sm text-gray-500 text-center mb-6"><?= t('2fa.instruction') ?></p>
            <?php if (isset($error)): ?>
                <div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm text-center"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                <input type="text" name="2fa_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"
                       class="w-full px-4 py-3 text-center text-2xl font-mono tracking-[0.5em] border border-gray-300 rounded-lg
                              focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                       placeholder="000000" required autofocus>
                <button type="submit"
                        class="w-full mt-6 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2.5 rounded-lg transition-colors
                               focus:outline-none focus:ring-2 focus:ring-blue-400">
                    <?= t('2fa.submit') ?>
                </button>
            </form>
        </div>
    </div>
</body>
</html>
