<?php
/**
 * step_up.php - Re-authentification (step-up) pour les actions destructrices.
 *
 * Patch A04-INSEC-N4 (OWASP A04 Insecure Design) :
 * Une session valide (cookie XSS vole / hijack) ne doit pas suffire pour
 * declencher des actions destructrices (delete user, change role, deploy/
 * revoke SSH key, regen platform key, etc.). On exige une re-verification
 * 2FA recente (15 minutes par defaut).
 *
 * Usage cote PHP (endpoint sensible) :
 *   require_once __DIR__ . '/../../auth/step_up.php';
 *   if (!stepUpVerify('delete_user')) {
 *       http_response_code(403);
 *       echo json_encode([
 *           'success' => false,
 *           'message' => 'Re-authentification requise',
 *           'step_up_required' => true,
 *           'action' => 'delete_user'
 *       ]);
 *       exit;
 *   }
 *
 * Cote frontend (JS) : si reponse contient step_up_required=true, ouvrir
 * un modal qui demande le code 2FA, POSTer sur step_up_verify.php avec
 * action=<x>, puis re-tenter l'action initiale.
 */

if (!function_exists('stepUpVerify')) {
    /**
     * Verifie qu'un step-up valide existe pour l'action demandee.
     * Retourne true si OK, false sinon.
     */
    function stepUpVerify(string $action, int $maxAgeSeconds = 900): bool {
        if (session_status() === PHP_SESSION_NONE) session_start();
        $key = '_step_up_' . preg_replace('/[^a-z0-9_]/i', '_', $action);
        $ts = $_SESSION[$key] ?? 0;
        return is_int($ts) && (time() - $ts) <= $maxAgeSeconds;
    }

    /**
     * Marque un step-up OK pour cette action (apres verification TOTP fraiche).
     */
    function stepUpMark(string $action): void {
        if (session_status() === PHP_SESSION_NONE) session_start();
        $key = '_step_up_' . preg_replace('/[^a-z0-9_]/i', '_', $action);
        $_SESSION[$key] = time();
    }

    /**
     * Helper pour endpoints API : si step-up manquant, repond 403 et exit.
     */
    function stepUpRequire(string $action): void {
        if (!stepUpVerify($action)) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'message' => 'Re-authentification 2FA requise pour cette action sensible',
                'step_up_required' => true,
                'action' => $action,
            ]);
            exit;
        }
    }
}
