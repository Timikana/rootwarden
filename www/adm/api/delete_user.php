<?php
/**
 * delete_user.php — Suppression d'un compte utilisateur portail (endpoint AJAX)
 *
 * Rôle : supprime un utilisateur et toutes ses données associées (accès machines,
 *        permissions fonctionnelles). Opération destructive et irréversible.
 *
 * Accès requis : rôle admin (2) ou superadmin (3) — vérifié par checkAuth().
 *
 * Méthode HTTP : POST uniquement (toute autre méthode retourne une erreur JSON).
 *
 * Protection CSRF : jeton vérifié via checkCsrfToken() avant tout traitement.
 *
 * Paramètres POST attendus :
 *   - user_id (int) : identifiant de l'utilisateur à supprimer.
 *   - csrf_token     : jeton CSRF de session.
 *
 * Réponse JSON :
 *   { "success": bool, "message": string }
 *
 * Tables affectées (ordre d'exécution) :
 *   1. users              — suppression du compte principal
 *   2. user_machine_access — suppression des accès machines liés
 *   3. permissions         — suppression des droits fonctionnels liés
 *
 * Note : la suppression du compte dans `users` peut échouer si des contraintes
 *        de clé étrangère sont actives sur les tables enfants ; dans ce cas,
 *        supprimer d'abord user_machine_access et permissions.
 */

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/../includes/crypto.php';
require_once __DIR__ . "/../includes/audit_log.php";

// Toutes les réponses sont en JSON
header('Content-Type: application/json');

// --- Contrôle d'accès ---
// Seuls les admins et superadmins peuvent supprimer des comptes.
checkAuth([2, 3]);

// --- Vérification de la méthode HTTP ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Méthode HTTP non autorisée.']);
    exit;
}

// --- Validation du jeton CSRF ---
// Empêche les attaques Cross-Site Request Forgery sur cette action destructive.
checkCsrfToken();

// --- Validation de l'identifiant utilisateur ---
// intval() garantit un entier ; un ID ≤ 0 est rejeté immédiatement.
$user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;

if ($user_id <= 0) {
    echo json_encode(['success' => false, 'message' => 'ID utilisateur invalide.']);
    exit;
}

// --- Protection : un superadmin ne peut pas se supprimer lui-même ---
if ($user_id === (int)$_SESSION['user_id']) {
    echo json_encode(['success' => false, 'message' => 'Vous ne pouvez pas supprimer votre propre compte.']);
    exit;
}

// --- Protection hierarchique : un admin ne peut pas supprimer un superadmin ---
$stmtCheck = $pdo->prepare("SELECT role_id FROM users WHERE id = ?");
$stmtCheck->execute([$user_id]);
$targetRole = (int)$stmtCheck->fetchColumn();
if ($_SESSION['role_id'] === 2 && $targetRole === 3) {
    echo json_encode(['success' => false, 'message' => 'Un admin ne peut pas supprimer un superadmin.']);
    exit;
}
// --- Protection : on ne supprime pas le dernier superadmin ---
if ($targetRole === 3) {
    $superadminCount = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role_id = 3")->fetchColumn();
    if ($superadminCount <= 1) {
        echo json_encode(['success' => false, 'message' => 'Impossible de supprimer le dernier super-administrateur.']);
        exit;
    }
}

// --- Suppression en cascade ---
try {
    // 1. Suppression du compte utilisateur principal
    audit_log($pdo, "Suppression utilisateur #$user_id", $user_id);
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$user_id]);

    // 2. Suppression des accès machines associés à cet utilisateur
    $stmt = $pdo->prepare("DELETE FROM user_machine_access WHERE user_id = ?");
    $stmt->execute([$user_id]);

    // 3. Suppression des permissions fonctionnelles associées
    $stmt = $pdo->prepare("DELETE FROM permissions WHERE user_id = ?");
    $stmt->execute([$user_id]);

    echo json_encode(['success' => true, 'message' => 'Utilisateur supprimé avec succès.']);
} catch (PDOException $e) {
    // Retourne le message d'erreur SQL (échappé) sans exposer de données sensibles
    echo json_encode(['success' => false, 'message' => 'Erreur SQL : ' . htmlspecialchars($e->getMessage())]);
}
?>
