<?php
/**
 * auth/enable_2fa.php
 *
 * Page de configuration initiale du TOTP (2FA) pour un utilisateur qui n'en possède pas encore.
 * Flux :
 *   - Requiert $_SESSION['temp_user'] (défini après validation mot de passe dans login.php)
 *   - Génère un secret TOTP aléatoire via OTPHP\TOTP si aucun n'existe en BDD,
 *     ou réutilise le secret existant
 *   - Affiche un QR code (via BaconQrCode/ImagickImageBackEnd) et le secret en clair
 *     pour permettre l'ajout dans une application d'authentification
 *   - Valide le premier code saisi avant de considérer le TOTP comme activé
 *   - En cas de succès : initialise la session définitive et redirige vers terms.php
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
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Writer;

// Vérifie s'il existe un utilisateur temporaire
if (!isset($_SESSION['temp_user'])) {
    header("Location: login.php");
    exit();
}

$userid = $_SESSION['temp_user']['id'];

// Récupère ou génère le secret TOTP
$stmt = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ?");
$stmt->execute([$userid]);
$existingSecret = $stmt->fetchColumn();

if (!$existingSecret) {
    // Génère un nouveau secret si aucun n'existe
    $totp = TOTP::create();
    $secret = $totp->getSecret();

    // Sauvegarde le secret chiffre dans la base de données
    $stmt = $pdo->prepare("UPDATE users SET totp_secret = ? WHERE id = ?");
    $stmt->execute([encryptTotpSecret($secret), $userid]);
} else {
    // Dechiffre le secret existant (retrocompatible plaintext legacy)
    $secret = decryptTotpSecret($existingSecret);
    $totp = TOTP::create($secret);
}

// Configure le TOTP
$totp->setLabel('MAGILINE - ' . $_SESSION['temp_user']['username']);
$totp->setIssuer('MAGILINE');

// Génère l'URI de provisioning pour le QR code
$otpauth = $totp->getProvisioningUri();

// Prépare le QR code
$renderer = new ImageRenderer(
    new RendererStyle(300, 10),
    new ImagickImageBackEnd()
);
$writer = new Writer($renderer);
$dataUri = 'data:image/png;base64,' . base64_encode($writer->writeString($otpauth));

// Vérification du code TOTP soumis
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['2fa_code'])) {
    checkCsrfToken();
    $code = $_POST['2fa_code'];

    // Crée une nouvelle instance TOTP avec le secret enregistré
    $totpVerify = TOTP::create($secret);

    // Anti-replay : rejeter un code deja utilise dans cette fenetre de temps
    $codeHash = hash('sha256', $code . floor(time() / 30));
    if (isset($_SESSION['last_totp_hash']) && $_SESSION['last_totp_hash'] === $codeHash) {
        $error = t('2fa.error_reused');
    } elseif ($totpVerify->verify($code, null, 1)) {
        $_SESSION['last_totp_hash'] = $codeHash;
        // Connexion réussie, on active le TOTP
        // -------------------------------------------------------
        // 1) Récupérer les informations de l'utilisateur en base
        $stmtUser = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmtUser->execute([$userid]);
        $userData = $stmtUser->fetch(PDO::FETCH_ASSOC);

        if (!$userData) {
            $error = t('enable_2fa.error_user');
        } else {
            // 2) Initialiser la session avec les vraies infos
            //    (Fonction que vous avez peut-être déjà : initializeUserSession() )
            initializeUserSession($userData);

            // 3) Détruire la session temporaire
            unset($_SESSION['temp_user'], $_SESSION['2fa_required'], $_SESSION['2fa_pending']);

            // 4) Rediriger
            header("Location: ../terms.php");
            exit();
        }
    } else {
        $error = t('2fa.error_invalid');
    }
}
?>
<?php
$_appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$_appCompany = htmlspecialchars(getenv('APP_COMPANY') ?: '');
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= t('enable_2fa.title') ?> — <?= $_appName ?></title>
    <link rel="stylesheet" href="/assets/css/tailwind.css">
</head>
<body class="bg-gradient-to-br from-blue-900 to-blue-700 min-h-screen flex items-center justify-center px-4 py-8">
    <div class="w-full max-w-md">
        <div class="text-center mb-6">
            <h1 class="text-3xl font-bold text-white tracking-tight"><?= $_appName ?></h1>
            <p class="text-blue-300 text-xs mt-1"><?= t('enable_2fa.subtitle') ?></p>
        </div>

        <div class="bg-white rounded-2xl shadow-2xl p-8">
            <h2 class="text-xl font-bold text-blue-900 mb-2 text-center"><?= t('enable_2fa.title') ?></h2>
            <p class="text-sm text-gray-500 text-center mb-4"><?= t('enable_2fa.instruction') ?></p>

            <!-- QR Code -->
            <div class="flex justify-center mb-4">
                <img src="<?= $dataUri ?>" alt="QR Code 2FA" class="rounded-lg shadow">
            </div>

            <!-- Secret -->
            <details class="mb-4">
                <summary class="text-sm text-blue-600 cursor-pointer hover:underline"><?= t('enable_2fa.manual') ?></summary>
                <div class="mt-2 bg-gray-50 rounded-lg p-3 border border-gray-200">
                    <p class="text-xs text-gray-500 mb-1"><?= t('enable_2fa.secret_label') ?></p>
                    <p class="font-mono text-xs break-all select-all text-gray-700"><?= htmlspecialchars($secret) ?></p>
                    <p class="text-xs text-gray-500 mt-2"><?= t('enable_2fa.account') ?> <?= $_appName ?> - <?= htmlspecialchars($_SESSION['temp_user']['username']) ?></p>
                </div>
            </details>

            <?php if (isset($error)): ?>
                <div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm text-center"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                <label class="block text-sm font-medium text-gray-700 mb-2"><?= t('enable_2fa.code_label') ?></label>
                <input type="text" name="2fa_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"
                       class="w-full px-4 py-3 text-center text-2xl font-mono tracking-[0.5em] border border-gray-300 rounded-lg
                              focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                       placeholder="000000" required autofocus>
                <button type="submit"
                        class="w-full mt-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2.5 rounded-lg transition-colors">
                    <?= t('enable_2fa.submit') ?>
                </button>
            </form>
        </div>
    </div>
</body>
</html>
