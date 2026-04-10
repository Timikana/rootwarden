<?php
/**
 * update_user.php — Mise à jour de la clé SSH publique d'un utilisateur
 *
 * Rôle : met à jour la colonne `ssh_key` dans la table `users` pour un utilisateur
 *        donné. Ce fichier est appelé depuis le formulaire de la section manage_users
 *        de la page d'administration.
 *
 * Accès requis : session valide (verify.php). La page appelante (admin_page.php)
 *                est réservée aux superadmins ; ce fichier ne répète pas le contrôle
 *                de rôle mais exige un jeton CSRF valide.
 *
 * Méthode HTTP : POST (soumission de formulaire classique, pas AJAX).
 *
 * Protection CSRF : jeton vérifié via checkCsrfToken() avant toute écriture en base.
 *
 * Paramètres POST attendus :
 *   - user_id  (int)    : identifiant de l'utilisateur cible.
 *   - ssh_key  (string) : nouvelle clé SSH publique (format OpenSSH attendu).
 *   - csrf_token        : jeton CSRF de session.
 *
 * Type de réponse : redirection HTTP 302 vers admin_page.php après succès.
 *
 * Note : aucune validation du format de la clé SSH n'est effectuée ici ;
 *        la validation devrait être ajoutée côté serveur si ce n'est pas fait
 *        dans le formulaire HTML.
 */

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
checkAuth([3]); // Superadmin uniquement
require_once __DIR__ . '/../../db.php';

// --- Traitement du formulaire POST ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_id'])) {

    // --- Validation du jeton CSRF ---
    checkCsrfToken();

    $user_id = (int)$_POST['user_id'];

    // --- Mise a jour de l'expiration mot de passe par utilisateur ---
    if (isset($_POST['password_expiry_override'])) {
        $val = $_POST['password_expiry_override'];
        $override = ($val === 'null' || $val === '') ? null : (int)$val;

        $stmt = $pdo->prepare("UPDATE users SET password_expiry_override = ? WHERE id = ?");
        $stmt->execute([$override, $user_id]);

        // Recalculer password_expires_at
        if ($override === 0) {
            // Exempt : pas d'expiration
            $pdo->prepare("UPDATE users SET password_expires_at = NULL WHERE id = ?")->execute([$user_id]);
        } elseif ($override !== null && $override > 0) {
            $pdo->prepare("UPDATE users SET password_expires_at = DATE_ADD(password_updated_at, INTERVAL ? DAY) WHERE id = ?")->execute([$override, $user_id]);
        } else {
            // Global : recalculer selon env var
            $globalDays = (int)(getenv('PASSWORD_EXPIRY_DAYS') ?: 0);
            if ($globalDays > 0) {
                $pdo->prepare("UPDATE users SET password_expires_at = DATE_ADD(password_updated_at, INTERVAL ? DAY) WHERE id = ?")->execute([$globalDays, $user_id]);
            } else {
                $pdo->prepare("UPDATE users SET password_expires_at = NULL WHERE id = ?")->execute([$user_id]);
            }
        }

        // Audit log
        try {
            $label = $override === null ? 'global' : ($override === 0 ? 'exempt' : "{$override}j");
            $pdo->prepare("INSERT INTO user_logs (user_id, action) VALUES (?, ?)")
                ->execute([$_SESSION['user_id'], "Password expiry pour user #{$user_id} : {$label}"]);
        } catch (\Exception $e) {}

        // Response JSON for AJAX
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'message' => 'Expiration mise a jour']);
        exit();
    }

    // --- Mise à jour de la clé SSH en base ---
    if (isset($_POST['ssh_key'])) {
        $ssh_key = $_POST['ssh_key'];
        $stmt = $pdo->prepare("UPDATE users SET ssh_key = ?, ssh_key_updated_at = NOW() WHERE id = ?");
        $stmt->execute([$ssh_key, $user_id]);

        header("Location: admin_page.php");
        exit();
    }
}
?>
