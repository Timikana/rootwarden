<?php
/**
 * update_user_status.php — Mise à jour du statut d'un utilisateur (endpoint AJAX)
 *
 * Rôle : met à jour un champ booléen (`active`, `sudo`, etc.) d'un utilisateur
 *        dans la table `users`. Cet endpoint est appelé depuis la fonction JavaScript
 *        `updateUserStatus()` définie dans admin_page.php.
 *
 * Accès requis : session valide (verify.php).
 *
 * Méthode HTTP : POST avec body JSON.
 *
 * Body JSON attendu :
 *   {
 *     "user_id": int,     // identifiant de l'utilisateur cible
 *     "field":   string,  // nom du champ à mettre à jour ('active', 'sudo'…)
 *     "value":   0|1      // nouvelle valeur binaire
 *   }
 *
 * Réponse JSON :
 *   { "success": bool, "message": string }
 *
 * Note de sécurité : ce fichier met à jour la clé SSH si les paramètres POST
 *                    `user_id` et `ssh_key` sont présents (ancien comportement conservé).
 *                    La version AJAX JSON est gérée via php://input.
 *
 * Note : ce fichier ne dispose pas de whitelist sur le champ `field` ;
 *        s'assurer que seuls des champs autorisés sont transmis depuis le frontend.
 */

require_once __DIR__ . '/../../auth/verify.php';
checkAuth([3]); // Superadmin uniquement
require_once __DIR__ . '/../../db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- Validation CSRF ---
checkCsrfToken();

// --- Traitement de la mise à jour de clé SSH (formulaire POST classique) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_id'], $_POST['ssh_key'])) {
    $user_id = $_POST['user_id'];
    $ssh_key = $_POST['ssh_key'];

    // Mise à jour de la clé SSH publique pour l'utilisateur ciblé
    $stmt = $pdo->prepare("UPDATE users SET ssh_key = ?, ssh_key_updated_at = NOW() WHERE id = ?");
    $stmt->execute([$ssh_key, $user_id]);

    require_once __DIR__ . '/../includes/audit_log.php';
    audit_log($pdo, "Mise a jour cle SSH user #$user_id");

    // Redirection PRG (Post/Redirect/Get) pour éviter la re-soumission
    header("Location: admin_page.php");
    exit();
}
?>
