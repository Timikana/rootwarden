<?php
/**
 * toggle_user.php - Activation / désactivation d'un compte utilisateur (endpoint AJAX)
 *
 * Rôle : inverse la valeur du champ `active` dans la table `users` pour un
 *        utilisateur donné. Un compte désactivé ne peut plus se connecter au portail.
 *
 * Accès requis : session valide (verify.php) - aucun contrôle de rôle supplémentaire
 *                dans ce fichier ; l'appelant (admin_page.php) est réservé aux admins.
 *
 * Méthode HTTP : POST.
 *
 * Paramètres POST attendus :
 *   - user_id (int) : identifiant de l'utilisateur à basculer.
 *
 * Réponse JSON :
 *   { "success": bool, "message": string, "new_status": 0|1 }
 *
 * Logique de bascule :
 *   - Lecture de `active` courant en base.
 *   - Inversion : 1 → 0 (désactivation) ou 0 → 1 (activation).
 *   - Mise à jour de `users.active`.
 */

require_once __DIR__ . '/../../auth/verify.php';
checkAuth([ROLE_SUPERADMIN]); // Superadmin uniquement
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/../includes/audit_log.php';

// Toutes les réponses sont en JSON
header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Trace d'exécution dans le journal d'erreurs PHP (utile en débogage)
file_put_contents('php://stderr', "toggle_user.php exécuté\n", FILE_APPEND);

// --- Validation CSRF ---
checkCsrfToken();

// --- Traitement de la requête POST ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_id'])) {
    try {
        $user_id = (int) $_POST['user_id'];

        // --- Anti-escalation : pas sur soi-meme ---
        if ($user_id === (int) $_SESSION['user_id']) {
            echo json_encode(['success' => false, 'message' => 'Impossible de desactiver votre propre compte']);
            exit();
        }

        // --- Lecture du statut actuel et du role ---
        $stmt = $pdo->prepare("SELECT active, role_id FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            echo json_encode(['success' => false, 'message' => 'Utilisateur introuvable']);
            exit();
        }

        $current_status = (int) $row['active'];
        $targetRoleId   = (int) $row['role_id'];

        // Inversion du statut : 1 -> 0 ou 0 -> 1
        $new_status = $current_status ? 0 : 1;

        // --- Protection : empecher la desactivation du dernier superadmin ---
        if ($new_status === 0 && $targetRoleId === 3) {
            $saCount = $pdo->prepare("SELECT COUNT(*) FROM users WHERE role_id = 3 AND active = 1");
            $saCount->execute();
            if ((int) $saCount->fetchColumn() <= 1) {
                echo json_encode(['success' => false, 'message' => 'Impossible de desactiver le dernier superadmin actif']);
                exit();
            }
        }

        // --- Mise à jour en base ---
        $stmt = $pdo->prepare("UPDATE users SET active = ? WHERE id = ?");
        $stmt->execute([$new_status, $user_id]);
        audit_log($pdo, ($new_status ? 'Activation' : 'Desactivation') . " utilisateur #$user_id", $user_id);

        // htmx : retourne le bouton HTML mis a jour
        if (!empty($_SERVER['HTTP_HX_REQUEST'])) {
            $label = $new_status ? 'Desactiver' : 'Activer';
            $cls = $new_status
                ? 'border-red-300 text-red-600 hover:bg-red-50 dark:border-red-700 dark:text-red-400 dark:hover:bg-red-900/30'
                : 'border-green-300 text-green-600 hover:bg-green-50 dark:border-green-700 dark:text-green-400 dark:hover:bg-green-900/30';
            header('HX-Trigger: ' . json_encode(['showToast' => ['message' => 'Statut mis a jour', 'type' => 'success']]));
            echo "<button hx-post=\"api/toggle_user.php\" hx-vals='{\"user_id\": {$user_id}}' hx-swap=\"outerHTML\" hx-confirm=\"Confirmer ?\" class=\"text-xs px-3 py-1 rounded border {$cls} transition-colors\">{$label}</button>";
            exit;
        }
        echo json_encode([
            'success' => true,
            'message' => 'Statut utilisateur mis à jour.',
            'new_status' => $new_status
        ]);
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Erreur : ' . $e->getMessage()
        ]);
    }
}
?>
