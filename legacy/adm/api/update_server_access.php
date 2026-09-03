<?php
/**
 * update_server_access.php - Ajout ou suppression d'un accès utilisateur ↔ machine (endpoint AJAX)
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
 *   - "add"    : INSERT IGNORE (idempotent - pas d'erreur si l'accès existe déjà)
 *   - "remove" : DELETE WHERE user_id = ? AND machine_id = ?
 *   - autre    : erreur JSON retournée, aucune modification en base
 */

require_once __DIR__ . '/../../auth/verify.php';
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
require_once __DIR__ . '/../../db.php';

// Toutes les réponses sont en JSON
header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- Validation CSRF (POST, header htmx, ou body JSON - timing-safe) ---
checkCsrfToken();

// --- Lecture du body JSON ---
$data = json_decode(file_get_contents('php://input'), true) ?: [];

// --- Validation de la présence des champs obligatoires ---
if (isset($data['user_id'], $data['machine_id'], $data['action'])) {
    // Typage strict pour eviter les injections de type sur les entiers
    $user_id    = (int)$data['user_id'];
    $machine_id = (int)$data['machine_id'];
    $action     = $data['action']; // Valeur controlee par le if/elseif ci-dessous

    // Patch A01-04 (OWASP A01) : un admin ne peut pas se self-grant un acces
    // machine. Le pouvoir d'accorder est reserve au superadmin OU a un admin
    // sur un OTHER user. Avant ce patch, un admin compromis se donnait
    // l'acces a toutes les machines en un appel.
    $currentUserId = (int)($_SESSION['user_id'] ?? 0);
    $currentRoleId = (int)($_SESSION['role_id'] ?? 0);
    if ($action === 'add' && $user_id === $currentUserId && $currentRoleId < 3) {
        echo json_encode([
            'success' => false,
            'message' => 'Un admin ne peut pas s\'attribuer l\'acces a une machine. Demandez au superadmin.'
        ]);
        exit;
    }

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

        } elseif ($action === 'update_sudo') {
            // --- v1.22.0 : mise a jour du preset sudo par couple (user, machine) ---
            // Necessite que l'access existe deja. Whitelist preset cote serveur.
            //
            // Patch A01 : l'octroi d'un preset sudo equivaut a accorder root
            // distant -> action superadmin-only, comme l'UI le restreint deja
            // (manage_access.php n'affiche le dropdown que si $isSuperAdmin).
            // Avant ce patch la branche n'avait AUCUN controle de role ni
            // anti-self : un admin (role 2) pouvait poser all_nopasswd sur
            // n'importe quel user disposant deja d'un acces machine.
            if ($currentRoleId < 3) {
                echo json_encode(['success' => false, 'message' => 'Action reservee au superadmin.']);
                exit;
            }
            $ALLOWED_PRESETS = ['none', 'all_nopasswd', 'restart_services', 'apt_only', 'read_logs', 'systemctl_specific', 'custom'];
            $preset = $data['sudo_preset'] ?? 'none';
            if (!in_array($preset, $ALLOWED_PRESETS, true)) {
                echo json_encode(['success' => false, 'message' => 'Preset sudo invalide.']);
                exit;
            }
            $nopasswd = !empty($data['sudo_nopasswd']) ? 1 : 0;
            $runas = (string)($data['sudo_runas'] ?? 'root');
            if (!preg_match('/^[a-z_][a-z0-9_-]{0,31}$/', $runas)) {
                echo json_encode(['success' => false, 'message' => 'Runas invalide.']);
                exit;
            }

            $stmt = $pdo->prepare(
                "UPDATE user_machine_access SET sudo_preset = ?, sudo_nopasswd = ?, sudo_runas = ? "
                . "WHERE user_id = ? AND machine_id = ?"
            );
            $stmt->execute([$preset, $nopasswd, $runas, $user_id, $machine_id]);
            if ($stmt->rowCount() === 0) {
                echo json_encode(['success' => false, 'message' => 'Aucun acces a mettre a jour (ajoute l\'acces d\'abord).']);
                exit;
            }
            require_once __DIR__ . '/../includes/audit_log.php';
            audit_log($pdo, "Update sudo preset=$preset nopasswd=$nopasswd machine #$machine_id pour user #$user_id");
            echo json_encode(['success' => true, 'message' => 'Preset sudo mis a jour.', 'preset' => $preset]);

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
