<?php
/**
 * chatops/webhook.php - Passthrough PUBLIC pour les commandes ChatOps entrantes.
 *
 * Slack/Teams ne peuvent pas s'authentifier par session : ce point d'entree est
 * volontairement SANS auth de session/CSRF. L'authentification reelle est faite
 * cote backend Python (/chatops/command) via la SIGNATURE Slack ou un JETON
 * partage. Ce fichier ne fait que relayer le corps brut + les en-tetes d'auth
 * chat vers le backend interne (non expose a Internet).
 *
 * Aucune donnee de session n'est lue ici, aucun privilege n'est accorde :
 * l'identite de l'acteur est resolue cote backend via le mapping chatops_users.
 */
$api_key    = getenv('API_KEY') ?: '';
$python_url = 'https://python:5000';
$target     = $python_url . '/chatops/command';

$raw = file_get_contents('php://input');

// En-tetes d'authentification chat a relayer telles quelles
$fwd = ["X-API-KEY: $api_key"];
$contentType = $_SERVER['CONTENT_TYPE'] ?? 'application/x-www-form-urlencoded';
$fwd[] = "Content-Type: $contentType";
foreach ([
    'HTTP_X_SLACK_SIGNATURE'         => 'X-Slack-Signature',
    'HTTP_X_SLACK_REQUEST_TIMESTAMP' => 'X-Slack-Request-Timestamp',
    'HTTP_X_CHATOPS_TOKEN'           => 'X-ChatOps-Token',
    'HTTP_X_CHATOPS_PLATFORM'        => 'X-ChatOps-Platform',
] as $src => $dst) {
    if (!empty($_SERVER[$src])) {
        $fwd[] = "$dst: " . $_SERVER[$src];
    }
}

$ch = curl_init($target);
curl_setopt_array($ch, [
    CURLOPT_CUSTOMREQUEST  => 'POST',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_HTTPHEADER     => $fwd,
    CURLOPT_POSTFIELDS     => $raw,
]);
$resp = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 502;
$err  = curl_error($ch);
curl_close($ch);

http_response_code($err ? 502 : $code);
header('Content-Type: application/json');
echo $err ? json_encode(['text' => 'Backend injoignable']) : $resp;
