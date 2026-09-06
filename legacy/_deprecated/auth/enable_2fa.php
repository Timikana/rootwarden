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

$stmt = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ?");
$stmt->execute([$userid]);
$existingSecret = $stmt->fetchColumn();

/*
 * LE SECOND FACTEUR N'EST PAS DERIVABLE DU PREMIER.
 *
 * `$_SESSION['temp_user']` est pose par `login.php` APRES le mot de passe et
 * AVANT le second facteur. Cette page n'exigeait rien de plus : avec le mot de
 * passe seul, un GET rendait 200 et 17 547 octets contenant le secret TOTP du
 * compte EN CLAIR, plus son QR code. Le second facteur etait donc derivable du
 * premier — mesure du 2026-08-20, reproduite le 2026-08-23, et le fichier etait
 * identique a l'octet a celui de `origin/main`, qui tourne en production.
 *
 * `login.php` renvoie certes vers `verify_2fa.php` quand un secret existe, mais
 * c'est une REDIRECTION, pas une garde : rien n'empechait d'appeler cette page
 * directement. Et `verify.php` l'autorise explicitement pendant que la 2FA est
 * en attente.
 *
 * Un compte qui possede DEJA un secret n'a rien a faire ici : sa place est sur
 * l'ecran de verification. Le renvoyer ferme la divulgation sans retirer aucune
 * capacite — il n'existe de toute facon aucun ecran de RE-enrolement pour un
 * compte authentifie (le lien d'onboarding est mort). Un administrateur qui
 * remet `totp_secret` a NULL rend l'enrolement de nouveau accessible.
 */
if (!empty($existingSecret)) {
    header("Location: verify_2fa.php");
    exit();
}

/*
 * UN GET NE DOIT RIEN ECRIRE. Le secret etait genere PUIS ecrit en base des
 * l'affichage, sans jeton CSRF et avant toute preuve que la personne sait
 * produire un code : une visite abandonnee laissait un secret enrole que
 * personne ne detenait. Il vit desormais en SESSION jusqu'a la validation du
 * premier code, et n'est ecrit qu'a ce moment-la.
 *
 * La session le conserve d'une requete a l'autre pour que le QR affiche et le
 * code attendu concordent : en regenerer un a chaque affichage rendrait
 * l'enrolement impossible.
 */
if (empty($_SESSION['enrol_totp_secret']) || ($_SESSION['enrol_totp_user'] ?? null) !== $userid) {
    $_SESSION['enrol_totp_secret'] = TOTP::create()->getSecret();
    $_SESSION['enrol_totp_user'] = $userid;
}
$secret = $_SESSION['enrol_totp_secret'];
$totp = TOTP::create($secret);

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

    // Crée une nouvelle instance TOTP avec le secret en cours d'enrolement
    $totpVerify = TOTP::create($secret);

    /*
     * MEME LIMITATION DE DEBIT QUE LES DEUX AUTRES PORTES 2FA — elle manquait
     * ici seule. `verify_2fa.php` et `confirm_2fa.php` bornent a 5 tentatives
     * par session sur 60 s ET 10 par IP sur 10 min (`login_attempts`, etape
     * '2fa'). Le compteur de session seul se remet a zero en rejetant le
     * cookie ; celui par IP resiste a la rotation de session.
     */
    if (!isset($_SESSION['enrol_attempts'])) { $_SESSION['enrol_attempts'] = []; }
    $_SESSION['enrol_attempts'] = array_filter($_SESSION['enrol_attempts'], fn($t) => $t > time() - 60);
    $_SESSION['enrol_attempts'][] = time();

    $codeHash = hash('sha256', $code . floor(time() / 30));

    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ipBlocked = false;
    try {
        $stmtIp = $pdo->prepare(
            "SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? "
            . "AND attempted_at > (NOW() - INTERVAL 10 MINUTE) AND step = '2fa' AND success = 0"
        );
        $stmtIp->execute([$clientIp]);
        $ipBlocked = ((int)$stmtIp->fetchColumn()) >= 10;
        $pdo->prepare(
            "INSERT INTO login_attempts (ip_address, username, success, step, attempted_at) "
            . "VALUES (?, ?, 0, '2fa', NOW())"
        )->execute([$clientIp, $_SESSION['temp_user']['username'] ?? 'unknown']);
    } catch (\Throwable $_e) {
        // Colonne 'step' absente (migration non appliquee) : on retombe sur le
        // compteur de session. Ne pas bloquer l'enrolement pour autant.
    }

    /*
     * ANTI-REJEU EFFECTIF. L'empreinte n'etait posee que dans la branche de
     * SUCCES puis supprimee dans la meme requete : le controle ne pouvait
     * jamais se declencher — motif E-01. Elle est desormais posee a CHAQUE
     * tentative, avant la verification, donc un meme code presente deux fois
     * dans la meme fenetre est refuse.
     */
    $dejaVu = isset($_SESSION['last_totp_hash']) && $_SESSION['last_totp_hash'] === $codeHash;
    $_SESSION['last_totp_hash'] = $codeHash;

    if ($ipBlocked || count($_SESSION['enrol_attempts']) > 5) {
        $error = t('2fa.error_rate_limit');
    } elseif ($dejaVu) {
        $error = t('2fa.error_reused');
    } elseif ($totpVerify->verify($code, null, 1)) {

        // Verifier que l'utilisateur existe et est actif en DB (ZERO TRUST)
        $stmtUser = $pdo->prepare("SELECT id, name, role_id, active, force_password_change FROM users WHERE id = ? AND active = 1");
        $stmtUser->execute([$userid]);
        $userData = $stmtUser->fetch(PDO::FETCH_ASSOC);

        if (!$userData) {
            $error = t('enable_2fa.error_user');
        } else {
            /*
             * LE SECRET EST ECRIT ICI, ET NULLE PART AVANT : la personne vient
             * de prouver qu'elle sait produire un code.
             */
            $stmtSave = $pdo->prepare("UPDATE users SET totp_secret = ? WHERE id = ?");
            $stmtSave->execute([encryptTotpSecret($secret), $userid]);

            // Initialiser la session definitive avec les donnees verifiees en DB
            initializeUserSession($userData);

            // Nettoyer les variables temporaires
            unset($_SESSION['temp_user'], $_SESSION['2fa_required'], $_SESSION['2fa_pending'],
                  $_SESSION['last_totp_hash'], $_SESSION['enrol_totp_secret'],
                  $_SESSION['enrol_totp_user'], $_SESSION['enrol_attempts']);

            // Verifier si l'utilisateur doit changer son mot de passe
            if ((int)($userData['force_password_change'] ?? 0) === 1) {
                $_SESSION['force_password_change'] = true;
                header("Location: ../profile.php?force_change=1");
                exit();
            }

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
    <title><?= t('enable_2fa.title') ?> - <?= $_appName ?></title>
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
