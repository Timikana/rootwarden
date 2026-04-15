<?php
/**
 * change_password.php — Changement de mot de passe de l'utilisateur connecté
 *
 * Rôle : permet à tout utilisateur authentifié de modifier son propre mot de passe
 *        depuis le portail. L'ancien mot de passe est vérifié avec password_verify()
 *        (bcrypt) avant d'accepter le nouveau.
 *
 * Accès requis : tout utilisateur avec une session valide ($_SESSION['user_id']).
 *
 * Type de réponse : HTML partiel (fragment inclus dans une page parente).
 *
 * Flux :
 *   1. Vérification de la session (redirection si absent).
 *   2. Validation des trois champs du formulaire (non-vide, correspondance).
 *   3. Vérification de l'ancien mot de passe en base via password_verify().
 *   4. Hachage du nouveau mot de passe avec PASSWORD_BCRYPT.
 *   5. Mise à jour de la colonne `password` dans la table `users`.
 *
 * Note : ce fichier ne gère pas de jeton CSRF explicite (le formulaire est servi
 *        depuis le même domaine et ne modifie que le compte de l'utilisateur connecté).
 */

// Ouverture de session si elle n'est pas encore démarrée
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Connexion PDO et vérification de l'authentification de session
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/../../auth/verify.php';

// --- Contrôle d'accès ---
// Si aucun utilisateur n'est connecté, on redirige vers la page de connexion.
if (!isset($_SESSION['user_id'])) {
    header("Location: /auth/login.php");
    exit();
}

// --- Traitement du formulaire (méthode POST uniquement) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // --- Validation CSRF ---
    checkCsrfToken();

    // Récupération brute des champs du formulaire
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];

    // --- Validation côté serveur ---
    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        // Tous les champs sont obligatoires
        $error = "Tous les champs sont obligatoires.";
    } elseif ($new_password !== $confirm_password) {
        // Le nouveau mot de passe et sa confirmation doivent être identiques
        $error = "Les nouveaux mots de passe ne correspondent pas.";
    } else {
        // --- Vérification de l'ancien mot de passe ---
        // Récupère le hash bcrypt stocké en base pour l'utilisateur connecté
        $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();

        // password_verify() compare l'entrée en clair avec le hash bcrypt stocké
        if (!$user || !password_verify($current_password, $user['password'])) {
            $error = "Le mot de passe actuel est incorrect.";
        } else {
            // --- Mise à jour du mot de passe ---
            // Hachage du nouveau mot de passe avec l'algorithme bcrypt (cost par défaut : 10)
            $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);

            // Mise à jour en base : seul le compte de l'utilisateur connecté est affecté
            $stmt = $pdo->prepare("UPDATE users SET password = ?, force_password_change = FALSE, password_updated_at = NOW() WHERE id = ?");
            $stmt->execute([$hashed_password, $_SESSION['user_id']]);
            unset($_SESSION['force_password_change']);
            require_once __DIR__ . '/../includes/audit_log.php';
            audit_log($pdo, "Changement mot de passe");
            $success = "Votre mot de passe a été mis à jour avec succès.";
        }
    }
}
?>
        <h1 class="text-2xl font-bold mb-4">Changer de mot de passe</h1>

        <?php if (isset($error)): ?>
            <div class="text-red-500 mb-4"><?= htmlspecialchars($error) ?></div>
        <?php elseif (isset($success)): ?>
            <div class="text-green-500 mb-4"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <form method="POST" action="change_password.php">
            <div class="mb-4">
                <label for="current_password" class="block">Mot de passe actuel</label>
                <input type="password" id="current_password" name="current_password" class="w-full border p-2 rounded" required>
            </div>
            <div class="mb-4">
                <label for="new_password" class="block">Nouveau mot de passe</label>
                <input type="password" id="new_password" name="new_password" class="w-full border p-2 rounded" required>
            </div>
            <div class="mb-4">
                <label for="confirm_password" class="block">Confirmer le mot de passe</label>
                <input type="password" id="confirm_password" name="confirm_password" class="w-full border p-2 rounded" required>
            </div>
            <button type="submit" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">Mettre à jour</button>
        </form>
