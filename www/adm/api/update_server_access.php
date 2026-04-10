<?php
/**
 * update_server_access.php — Ajout ou suppression d'un accès utilisateur ↔ machine (endpoint AJAX)
 *
 * Rôle : gère la table de liaison `user_machine_access` pour accorder ou révoquer
 *        l'accès d'un utilisateur à une machine spécifique. Appelé depuis deux
 *        gestionnaires JavaScript dans admin_page.php :
 *          - L'écouteur générique sur '.server-checkbox' (data-machine-id)
 *          - La fonction updateAccess() (data-server-id mappé sur machine_id côté serveur)
 *
 * Accès requis : session valide (verify.php).
 *
 * Méthode HTTP : POST avec body JSON (Content-Type: application/json).
 *
 * Body JSON attendu :
 *   {
 *     "user_id":    int,           // identifiant de l'utilisateur
 *     "machine_id": int,           // identifiant de la machine (table `machines`)
 *     "action":     "add"|"remove" // opération à effectuer
 *   }
 *
 * Réponse JSON (succès) :
 *   { "success": true, "message": string }
 *
 * Réponse JSON (erreur) :
 *   { "success": false, "message": string }
 *
 * Table affectée : `user_machine_access` (colonnes : user_id, machine_id).
 *
 * Comportement selon l'action :
 *   - "add"    : INSERT IGNORE (idempotent — pas d'erreur si l'accès existe déjà)
 *   - "remove" : DELETE WHERE user_id = ? AND machine_id = ?
 *   - autre    : erreur JSON retournée, aucune modification en base
 */

require_once __DIR__ . '/../../auth/verify.php';
checkAuth([3]); // Superadmin uniquement
require_once __DIR__ . '/../../db.php';

// Toutes les réponses sont en JSON
header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- Validation CSRF (header OU body JSON OU POST form) ---
$csrfHeader = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
$rawBody = file_get_contents('php://input');
$bodyData = json_decode($rawBody, true) ?: [];
$csrfBody = $bodyData['csrf_token'] ?? $_POST['csrf_token'] ?? '';
$csrfSession = $_SESSION['csrf_token'] ?? '';
$csrf = $csrfHeader ?: $csrfBody;
if (empty($csrfSession) || $csrf !== $csrfSession) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Token CSRF invalide.']);
    exit;
}

// --- Lecture du body (deja decode plus haut pour CSRF) ---
$data = $bodyData;

// --- Validation de la présence des champs obligatoires ---
if (isset($data['user_id'], $data['machine_id'], $data['action'])) {
    // Typage strict pour éviter les injections de type sur les entiers
    $user_id    = (int)$data['user_id'];
    $machine_id = (int)$data['machine_id'];
    $action     = $data['action']; // Valeur contrôlée par le if/elseif ci-dessous

    try {
        if ($action === 'add') {
            // --- Ajout de l'accès ---
            // INSERT IGNORE : si la paire (user_id, machine_id) existe déjà,
            // la requête ne produit pas d'erreur (idempotent).
            $stmt = $pdo->prepare("INSERT IGNORE INTO user_machine_access (user_id, machine_id) VALUES (?, ?)");
            $stmt->execute([$user_id, $machine_id]);
            require_once __DIR__ . '/../includes/audit_log.php';
            audit_log($pdo, "Ajout acces machine #$machine_id pour user #$user_id");
            echo json_encode(['success' => true, 'message' => 'Serveur ajouté avec succès.']);

        } elseif ($action === 'remove') {
            // --- Suppression de l'accès ---
            // La condition sur les deux colonnes garantit qu'on ne supprime
            // que l'accès exact demandé (pas de suppression en cascade involontaire).
            $stmt = $pdo->prepare("DELETE FROM user_machine_access WHERE user_id = ? AND machine_id = ?");
            $stmt->execute([$user_id, $machine_id]);
            require_once __DIR__ . '/../includes/audit_log.php';
            audit_log($pdo, "Retrait acces machine #$machine_id pour user #$user_id");
            echo json_encode(['success' => true, 'message' => 'Serveur retiré avec succès.']);

        } else {
            // Action inconnue : rejeté sans modification en base
            echo json_encode(['success' => false, 'message' => 'Action non reconnue.']);
        }
    } catch (PDOException $e) {
        error_log("[RootWarden] Erreur SQL update_server_access: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Erreur interne']);
    }
} else {
    // Champs obligatoires manquants dans le body JSON
    echo json_encode(['success' => false, 'message' => 'Données invalides.']);
}
?>
