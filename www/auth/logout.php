<?php
/**
 * auth/logout.php
 *
 * Déconnecte l'utilisateur courant :
 *   1. Supprime le token "Se souvenir de moi" de la table remember_tokens (si présent)
 *   2. Expire le cookie remember_token côté navigateur
 *   3. Détruit la session PHP (session_unset + session_destroy)
 *   4. Redirige vers login.php
 *
 * @package RootWarden\Auth
 */
require_once __DIR__ . '/../db.php';
session_start();
if (isset($_COOKIE['remember_token'])) {
    list($user_id, $token) = explode(':', $_COOKIE['remember_token']);

    // Supprimer le token de la base
    $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE user_id = ?");
    $stmt->execute([$user_id]);

    // Supprimer le cookie
    setcookie('remember_token', '', time() - 3600, '/');
}
session_unset(); // Supprime toutes les variables de session
session_destroy(); // Détruit la session

header("Location: login.php"); // Redirige vers la page de connexion
exit();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
</head>
<body>
    <h1>Bienvenue, <?php echo htmlspecialchars($_SESSION['user_id'] ?? ''); ?></h1>
    <a href="logout.php" style="color: red; text-decoration: none; border: 1px solid red; padding: 5px 10px; border-radius: 5px;">Déconnexion</a>
</body>
</html>
