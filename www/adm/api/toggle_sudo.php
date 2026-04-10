<?php
/**
 * toggle_sudo.php — Activation / désactivation des droits sudo d'un utilisateur (endpoint AJAX)
 *
 * Rôle : inverse la valeur du champ `sudo` dans la table `users` pour un
 *        utilisateur donné. Le droit sudo détermine si l'utilisateur peut exécuter
 *        des commandes en tant que root sur les machines auxquelles il a accès.
 *
 * Accès requis : session valide (verify.php).
 *
 * Méthode HTTP : POST.
 *
 * Paramètres POST attendus :
 *   - user_id (int) : identifiant de l'utilisateur à basculer.
 *
 * Réponse JSON :
 *   { "success": bool, "message": string, "new_sudo": 0|1 }
 *
 * Logique de bascule :
 *   - Lecture de `sudo` courant en base.
 *   - Inversion : 1 → 0 (révocation) ou 0 → 1 (octroi).
 *   - Mise à jour de `users.sudo`.
 */

require_once __DIR__ . '/../../auth/verify.php';
checkAuth([3]); // Superadmin uniquement
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . "/../includes/audit_log.php";

// Toutes les réponses sont en JSON
header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- Validation CSRF ---
checkCsrfToken();

// --- Traitement de la requête POST ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_id'])) {
    try {
        $user_id = $_POST['user_id'];

        // --- Lecture du statut sudo actuel ---
        $stmt = $pdo->prepare("SELECT sudo FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $current_sudo = $stmt->fetchColumn();

        // --- Inversion du droit sudo ---
        // 1 (sudo actif) → 0 (révocation) ; 0 (pas de sudo) → 1 (octroi)
        $new_sudo = $current_sudo ? 0 : 1;

        // --- Mise à jour en base ---
        $stmt = $pdo->prepare("UPDATE users SET sudo = ? WHERE id = ?");
        $stmt->execute([$new_sudo, $user_id]);
        audit_log($pdo, ($new_sudo ? 'Octroi' : 'Revocation') . " sudo utilisateur #$user_id", $user_id);

        // htmx : retourne le bouton HTML mis a jour
        if (!empty($_SERVER['HTTP_HX_REQUEST'])) {
            $label = $new_sudo ? 'Retirer sudo' : 'Donner sudo';
            header('HX-Trigger: ' . json_encode(['showToast' => ['message' => 'Sudo mis a jour', 'type' => 'success']]));
            echo "<button hx-post=\"api/toggle_sudo.php\" hx-vals='{\"user_id\": {$user_id}}' hx-swap=\"outerHTML\" class=\"text-xs px-3 py-1 rounded border border-purple-300 text-purple-600 hover:bg-purple-50 dark:border-purple-700 dark:text-purple-400 dark:hover:bg-purple-900/30 transition-colors\">{$label}</button>";
            exit;
        }
        echo json_encode([
            'success' => true,
            'message' => 'Statut sudo mis à jour.',
            'new_sudo' => $new_sudo
        ]);
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Erreur : ' . $e->getMessage()
        ]);
    }
}
?>
