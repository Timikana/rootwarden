<?php
/**
 * includes/mail_helper.php
 *
 * Helper d'envoi d'emails via PHPMailer.
 * Lit la configuration SMTP depuis les variables d'environnement
 * (memes variables que le backend Python : MAIL_SMTP_HOST, etc.)
 *
 * @package RootWarden\Includes
 */

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * Verifie si l'envoi d'emails est configure et active.
 */
function isMailEnabled(): bool
{
    return strtolower(getenv('MAIL_ENABLED') ?: 'false') === 'true'
        && !empty(getenv('MAIL_SMTP_HOST'));
}

/**
 * Cree et configure une instance PHPMailer depuis les variables d'environnement.
 *
 * @return PHPMailer Instance configuree, prete a envoyer.
 * @throws Exception Si la configuration est incomplete.
 */
function createMailer(): PHPMailer
{
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host       = getenv('MAIL_SMTP_HOST');
    $mail->Port       = (int)(getenv('MAIL_SMTP_PORT') ?: 587);
    $mail->CharSet    = 'UTF-8';
    $mail->Timeout    = 15;

    // Debug SMTP (MAIL_DEBUG=true pour diagnostic)
    if (strtolower(getenv('MAIL_DEBUG') ?: 'false') === 'true') {
        $mail->SMTPDebug  = SMTP::DEBUG_CONNECTION;
        $mail->Debugoutput = function ($str, $level) {
            error_log("[RootWarden][SMTP] $str");
        };
    }

    // TLS / SSL
    $useTls = strtolower(getenv('MAIL_SMTP_TLS') ?: 'true') === 'true';
    $port = (int)(getenv('MAIL_SMTP_PORT') ?: 587);
    if ($useTls) {
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    } elseif ($port === 465) {
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    } else {
        $mail->SMTPSecure = '';
        $mail->SMTPAutoTLS = false;
    }

    // Auth SMTP (optionnel - si vide, envoie sans auth pour les relais IP-whitelistés)
    $user = getenv('MAIL_SMTP_USER');
    $pass = getenv('MAIL_SMTP_PASSWORD');
    if ($user && $pass) {
        $mail->SMTPAuth = true;
        $mail->Username = $user;
        $mail->Password = $pass;
    }

    $mail->setFrom(getenv('MAIL_FROM') ?: 'noreply@rootwarden.local', getenv('APP_NAME') ?: 'RootWarden');

    error_log("[RootWarden] SMTP config: host={$mail->Host}, port={$mail->Port}, "
        . "secure=" . ($mail->SMTPSecure ?: 'none') . ", auth=" . ($mail->SMTPAuth ? 'yes' : 'no'));

    return $mail;
}

/**
 * Envoie un email de reinitialisation de mot de passe.
 *
 * @param string $to       Adresse email du destinataire.
 * @param string $resetUrl URL complete de reinitialisation (avec token).
 * @param string $username Nom d'utilisateur (pour personnaliser le message).
 * @return bool true si l'email a ete envoye, false sinon.
 */
function sendPasswordResetEmail(string $to, string $resetUrl, string $username): bool
{
    if (!isMailEnabled()) {
        error_log("[RootWarden] Mail disabled - reset email not sent to {$to}");
        return false;
    }

    try {
        $mail = createMailer();
        $mail->addAddress($to);
        $mail->isHTML(true);
        $mail->Subject = '[' . (getenv('APP_NAME') ?: 'RootWarden') . '] Reinitialisation de mot de passe';

        $appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
        $safeUsername = htmlspecialchars($username);
        $safeUrl = htmlspecialchars($resetUrl);

        $mail->Body = <<<HTML
<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,sans-serif;">
  <div style="max-width:600px;margin:40px auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
    <!-- Header -->
    <div style="background:#1e3a8a;padding:24px 32px;">
      <h1 style="color:#ffffff;margin:0;font-size:20px;">{$appName}</h1>
      <p style="color:#93c5fd;margin:4px 0 0;font-size:13px;">Reinitialisation de mot de passe</p>
    </div>

    <!-- Body -->
    <div style="padding:32px;">
      <p style="color:#374151;font-size:15px;line-height:1.6;margin:0 0 16px;">
        Bonjour <strong>{$safeUsername}</strong>,
      </p>
      <p style="color:#374151;font-size:15px;line-height:1.6;margin:0 0 24px;">
        Une demande de reinitialisation de mot de passe a ete effectuee pour votre compte.
        Cliquez sur le bouton ci-dessous pour definir un nouveau mot de passe :
      </p>

      <div style="text-align:center;margin:32px 0;">
        <a href="{$safeUrl}"
           style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;
                  padding:12px 32px;border-radius:8px;font-weight:600;font-size:15px;">
          Reinitialiser mon mot de passe
        </a>
      </div>

      <p style="color:#6b7280;font-size:13px;line-height:1.5;margin:0 0 8px;">
        Ce lien est valable <strong>1 heure</strong> et ne peut etre utilise qu'une seule fois.
      </p>
      <p style="color:#6b7280;font-size:13px;line-height:1.5;margin:0 0 8px;">
        Si vous n'avez pas demande cette reinitialisation, ignorez cet email.
        Votre mot de passe restera inchange.
      </p>

      <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;">

      <p style="color:#9ca3af;font-size:11px;margin:0;">
        Lien direct : <a href="{$safeUrl}" style="color:#2563eb;word-break:break-all;">{$safeUrl}</a>
      </p>
    </div>

    <!-- Footer -->
    <div style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb;">
      <p style="color:#9ca3af;font-size:11px;margin:0;text-align:center;">
        {$appName} &mdash; Cet email a ete envoye automatiquement, merci de ne pas y repondre.
      </p>
    </div>
  </div>
</body>
</html>
HTML;

        $mail->AltBody = "Bonjour {$username},\n\n"
            . "Une demande de reinitialisation de mot de passe a ete effectuee.\n"
            . "Lien (valable 1h) : {$resetUrl}\n\n"
            . "Si vous n'avez pas fait cette demande, ignorez cet email.";

        return $mail->send();
    } catch (Exception $e) {
        error_log("[RootWarden] Erreur envoi email reset: " . $e->getMessage());
        return false;
    }
}

/**
 * Envoie un email de bienvenue a un nouvel utilisateur.
 *
 * @param string $to            Adresse email du destinataire.
 * @param string $username      Nom d'utilisateur (login).
 * @param string $plainPassword Mot de passe en clair (genere automatiquement).
 * @return bool true si l'email a ete envoye, false sinon.
 */
function sendWelcomeEmail(string $to, string $username, string $plainPassword): bool
{
    if (!isMailEnabled()) {
        error_log("[RootWarden] Mail disabled - welcome email not sent to {$to}");
        return false;
    }

    try {
        $mail = createMailer();
        $mail->addAddress($to);
        $mail->isHTML(true);
        $mail->Subject = '[' . (getenv('APP_NAME') ?: 'RootWarden') . '] Votre compte a ete cree';

        $appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
        $safeUser = htmlspecialchars($username);
        $safePass = htmlspecialchars($plainPassword);
        $loginUrl = htmlspecialchars(getenv('URL_HTTPS') ?: 'https://localhost:8443');

        $mail->Body = <<<HTML
<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,sans-serif;">
  <div style="max-width:600px;margin:40px auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
    <!-- Header -->
    <div style="background:#1e3a8a;padding:24px 32px;">
      <h1 style="color:#ffffff;margin:0;font-size:20px;">{$appName}</h1>
      <p style="color:#93c5fd;margin:4px 0 0;font-size:13px;">Bienvenue sur la plateforme</p>
    </div>

    <!-- Body -->
    <div style="padding:32px;">
      <p style="color:#374151;font-size:15px;line-height:1.6;margin:0 0 16px;">
        Bonjour <strong>{$safeUser}</strong>,
      </p>
      <p style="color:#374151;font-size:15px;line-height:1.6;margin:0 0 24px;">
        Votre compte a ete cree sur {$appName}. Voici vos identifiants de connexion :
      </p>

      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:20px;margin:0 0 24px;">
        <table style="width:100%;font-size:14px;color:#374151;">
          <tr><td style="padding:4px 0;font-weight:600;width:120px;">Identifiant</td><td style="padding:4px 0;">{$safeUser}</td></tr>
          <tr><td style="padding:4px 0;font-weight:600;">Mot de passe</td><td style="padding:4px 0;font-family:monospace;background:#fef3c7;padding:2px 8px;border-radius:4px;">{$safePass}</td></tr>
        </table>
      </div>

      <div style="text-align:center;margin:32px 0;">
        <a href="{$loginUrl}"
           style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;
                  padding:12px 32px;border-radius:8px;font-weight:600;font-size:15px;">
          Se connecter
        </a>
      </div>

      <p style="color:#dc2626;font-size:13px;line-height:1.5;margin:0 0 8px;font-weight:600;">
        Changez votre mot de passe des la premiere connexion.
      </p>
      <p style="color:#6b7280;font-size:13px;line-height:1.5;margin:0;">
        Vous devrez egalement configurer l'authentification a deux facteurs (2FA/TOTP)
        avec une application comme Google Authenticator ou Authy.
      </p>
    </div>

    <!-- Footer -->
    <div style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb;">
      <p style="color:#9ca3af;font-size:11px;margin:0;text-align:center;">
        {$appName} &mdash; Cet email a ete envoye automatiquement, merci de ne pas y repondre.
      </p>
    </div>
  </div>
</body>
</html>
HTML;

        $mail->AltBody = "Bonjour {$username},\n\n"
            . "Votre compte {$appName} a ete cree.\n\n"
            . "Identifiant : {$username}\n"
            . "Mot de passe : {$plainPassword}\n\n"
            . "Connexion : {$loginUrl}\n\n"
            . "Changez votre mot de passe apres la premiere connexion.\n"
            . "Vous devrez aussi configurer l'authentification 2FA (TOTP).";

        return $mail->send();
    } catch (Exception $e) {
        error_log("[RootWarden] Erreur envoi email bienvenue: " . $e->getMessage());
        return false;
    }
}

/**
 * Envoie un email d'activation de compte (magic link).
 *
 * @param string $to            Adresse email du destinataire.
 * @param string $activationUrl URL complete d'activation (avec token).
 * @param string $username      Nom d'utilisateur.
 * @return bool true si l'email a ete envoye, false sinon.
 */
function sendActivationEmail(string $to, string $activationUrl, string $username): bool
{
    if (!isMailEnabled()) {
        error_log("[RootWarden] Mail disabled - activation email not sent to {$to}");
        return false;
    }

    try {
        $mail = createMailer();
        $mail->addAddress($to);
        $mail->isHTML(true);
        $mail->Subject = '[' . (getenv('APP_NAME') ?: 'RootWarden') . '] Activation de votre compte';

        $appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
        $safeUsername = htmlspecialchars($username);
        $safeUrl = htmlspecialchars($activationUrl);

        $mail->Body = <<<HTML
<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,sans-serif;">
  <div style="max-width:600px;margin:40px auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
    <!-- Header -->
    <div style="background:#1e3a8a;padding:24px 32px;">
      <h1 style="color:#ffffff;margin:0;font-size:20px;">{$appName}</h1>
      <p style="color:#93c5fd;margin:4px 0 0;font-size:13px;">Activation de votre compte</p>
    </div>

    <!-- Body -->
    <div style="padding:32px;">
      <p style="color:#374151;font-size:15px;line-height:1.6;margin:0 0 16px;">
        Bonjour <strong>{$safeUsername}</strong>,
      </p>
      <p style="color:#374151;font-size:15px;line-height:1.6;margin:0 0 24px;">
        Un compte a ete cree pour vous sur {$appName}.
        Cliquez sur le bouton ci-dessous pour definir votre mot de passe et activer votre compte :
      </p>

      <div style="text-align:center;margin:32px 0;">
        <a href="{$safeUrl}"
           style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;
                  padding:14px 36px;border-radius:8px;font-weight:600;font-size:16px;">
          Activer mon compte
        </a>
      </div>

      <div style="background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;padding:16px;margin:24px 0;">
        <p style="color:#92400e;font-size:13px;margin:0 0 8px;font-weight:600;">Exigences du mot de passe :</p>
        <ul style="color:#92400e;font-size:13px;margin:0;padding-left:20px;">
          <li>Minimum <strong>15 caracteres</strong></li>
          <li>Au moins une <strong>majuscule</strong> et une <strong>minuscule</strong></li>
          <li>Au moins un <strong>chiffre</strong></li>
          <li>Au moins un <strong>caractere special</strong> (!@#\$%...)</li>
        </ul>
      </div>

      <p style="color:#6b7280;font-size:13px;line-height:1.5;margin:0 0 8px;">
        Ce lien est valable <strong>24 heures</strong> et ne peut etre utilise qu'une seule fois.
      </p>
      <p style="color:#6b7280;font-size:13px;line-height:1.5;margin:0;">
        Apres avoir defini votre mot de passe, vous devrez configurer l'authentification
        a deux facteurs (2FA/TOTP) avec une application comme Google Authenticator ou Authy.
      </p>

      <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;">

      <p style="color:#9ca3af;font-size:11px;margin:0;">
        Lien direct : <a href="{$safeUrl}" style="color:#2563eb;word-break:break-all;">{$safeUrl}</a>
      </p>
    </div>

    <!-- Footer -->
    <div style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb;">
      <p style="color:#9ca3af;font-size:11px;margin:0;text-align:center;">
        {$appName} &mdash; Cet email a ete envoye automatiquement, merci de ne pas y repondre.
      </p>
    </div>
  </div>
</body>
</html>
HTML;

        $mail->AltBody = "Bonjour {$username},\n\n"
            . "Un compte a ete cree pour vous sur " . (getenv('APP_NAME') ?: 'RootWarden') . ".\n\n"
            . "Cliquez sur ce lien pour activer votre compte et definir votre mot de passe :\n"
            . "{$activationUrl}\n\n"
            . "Ce lien est valable 24 heures.\n\n"
            . "Exigences : 15+ caracteres, majuscule, minuscule, chiffre, caractere special.\n"
            . "Vous devrez aussi configurer l'authentification 2FA (TOTP).";

        return $mail->send();
    } catch (Exception $e) {
        error_log("[RootWarden] Erreur envoi email activation: " . $e->getMessage());
        return false;
    }
}
