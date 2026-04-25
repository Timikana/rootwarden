<?php
/**
 * api_proxy.php - Proxy PHP générique vers le backend Python.
 *
 * Relaie TOUTES les requêtes du navigateur vers le backend Python en interne Docker.
 * Élimine les problèmes CORS (Hypercorn ASGI) et masque l'API_KEY côté serveur.
 *
 * Supporte :
 *   - GET  JSON classique (ex: /list_machines, /cve_results)
 *   - GET  SSE streaming   (ex: /logs, /update-logs, /iptables-logs)
 *   - POST JSON classique  (ex: /server_status → réponse JSON)
 *   - POST streaming       (ex: /update, /cve_scan → réponse text/plain streaming)
 *
 * Détection du mode streaming :
 *   Le backend Python envoie un Content-Type `text/event-stream` ou `text/plain`
 *   pour les flux. Le proxy détecte ce header et passe en mode streaming (flush immédiat).
 *
 * Usage JS :  window.API_URL = '/api_proxy.php'  (défini dans head.php)
 *             fetch(`${API_URL}/deploy`, { method: 'POST', ... })
 *             new EventSource(`${API_URL}/logs`)
 */
require_once __DIR__ . '/auth/verify.php';
// checkAuth verifie en DB que l'user existe + active=1 + synchronise role_id en session
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);

// CSRF defense-in-depth : SameSite=Strict mitige le cross-site CSRF, mais
// une XSS sur le meme origin donnerait acces au proxy (l'endpoint le plus
// puissant : forward toutes les routes Python). Token injecte automatiquement
// par www/js/utils.js sur les fetch() non-GET vers api_proxy.php.
$_method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (in_array($_method, ['POST', 'PUT', 'DELETE', 'PATCH'], true)) {
    checkCsrfToken();
}

$api_key    = getenv('API_KEY') ?: '';
$python_url = 'https://python:5000';

// Role et permissions deja synchronises par checkAuth() - utiliser la session
$userId = (int) $_SESSION['user_id'];
$roleId = (int) $_SESSION['role_id'];

$userHeaders = [
    "X-API-KEY: $api_key",
    "X-User-ID: $userId",
    "X-User-Role: $roleId",
    "X-User-Permissions: " . json_encode($_SESSION['permissions'] ?? []),
];

// Liberer le lock de session AVANT le curl vers le backend.
// Sans cela, toute requete longue (scan CVE, apt update, iptables) bloque
// la navigation car PHP garde un verrou exclusif sur le fichier de session.
session_write_close();

// ── Extraction du path (ex: /api_proxy.php/deploy → /deploy) ───────────────
$path = $_SERVER['PATH_INFO'] ?? '';
if (!$path) {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $pos = strpos($uri, 'api_proxy.php');
    if ($pos !== false) {
        $path = substr($uri, $pos + strlen('api_proxy.php'));
        $path = strtok($path, '?');
    }
}

if (!$path || $path === '/') {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => 'No route specified']);
    exit;
}

$query  = $_SERVER['QUERY_STRING'] ?? '';
$target = $python_url . $path . ($query ? "?$query" : '');
$method = $_SERVER['REQUEST_METHOD'];

// ── Désactiver le output buffering PHP ─────────────────────────────────────
while (ob_get_level()) ob_end_clean();

// ── Variables partagées pour le HEADERFUNCTION ─────────────────────────────
$isStreaming  = false;
$contentType  = 'application/json';

$headerFn = function($ch, $header) use (&$isStreaming, &$contentType) {
    if (stripos($header, 'Content-Type:') === 0) {
        $contentType = trim(substr($header, 13));
        $isStreaming  = (
            stripos($contentType, 'text/event-stream') !== false ||
            stripos($contentType, 'text/plain') !== false
        );
    }
    return strlen($header);
};

$writeFn = function($ch, $data) {
    echo $data;
    flush();
    return strlen($data);
};

// ── GET ────────────────────────────────────────────────────────────────────
if ($method === 'GET') {
    // On ne sait pas à l'avance si c'est du JSON ou du SSE.
    // On stream dans tous les cas (pas de CURLOPT_RETURNTRANSFER).
    header('X-Accel-Buffering: no');
    header('Cache-Control: no-cache');

    $ch = curl_init($target);
    curl_setopt_array($ch, [
        CURLOPT_TIMEOUT        => 1800,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER     => $userHeaders,
        CURLOPT_HEADERFUNCTION => function($ch, $header) use (&$isStreaming, &$contentType) {
            if (stripos($header, 'Content-Type:') === 0) {
                $ct = trim(substr($header, 13));
                $contentType = $ct;
                $isStreaming = (stripos($ct, 'text/event-stream') !== false);
                header('Content-Type: ' . $ct);
            }
            return strlen($header);
        },
        CURLOPT_WRITEFUNCTION  => $writeFn,
    ]);
    curl_exec($ch);
    curl_close($ch);
    exit;
}

// ── POST / PUT / DELETE / PATCH ────────────────────────────────────────────
// On unifie le chemin pour tous les verbes qui portent (ou pas) un body JSON.
// Avant : seul POST etait supporte -> /cve_schedules/<id> en PUT retournait 405
// et l'UI ne pouvait ni toggle ni supprimer les scans planifies.
if (in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'], true)) {
    $body = file_get_contents('php://input');

    header('X-Accel-Buffering: no');
    header('Cache-Control: no-cache');

    $ch = curl_init($target);
    $opts = [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_TIMEOUT        => 1800,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER     => array_merge($userHeaders, [
            "Content-Type: application/json",
        ]),
        CURLOPT_HEADERFUNCTION => function($ch, $header) use (&$contentType) {
            if (stripos($header, 'Content-Type:') === 0) {
                $contentType = trim(substr($header, 13));
                header('Content-Type: ' . $contentType);
            }
            // Relaye le status HTTP du backend (sinon 405 DELETE devient 200).
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $m)) {
                http_response_code((int)$m[1]);
            }
            return strlen($header);
        },
        CURLOPT_WRITEFUNCTION  => $writeFn,
    ];
    // Body uniquement pour les methodes qui en ont un
    if ($body !== '' && $body !== false) {
        $opts[CURLOPT_POSTFIELDS] = $body;
    }
    curl_setopt_array($ch, $opts);
    curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);

    if ($err) {
        echo json_encode(['success' => false, 'message' => "Proxy error: $err"]);
    }
    exit;
}

http_response_code(405);
echo json_encode(['success' => false, 'message' => 'Method not allowed']);
