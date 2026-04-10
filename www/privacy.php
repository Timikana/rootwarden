<?php
/**
 * privacy.php — Politique de confidentialité
 *
 * Rôle       : Affiche la politique de confidentialité de la plateforme.
 *              Permet également à l'utilisateur connecté d'exercer ses droits RGPD :
 *                - "Demander mes données" : affiche les données BDD de l'utilisateur
 *                - "Demander suppression" : supprime le compte et détruit la session
 *
 * Dépendances :
 *   - auth/verify.php   : checkAuth() — vérification authentification et rôle
 *   - auth/functions.php: fonctions utilitaires de session
 *   - db.php            : $pdo — connexion PDO MySQL
 *   - head.php          : balises <head> communes
 *   - menu.php          : barre de navigation
 *   - footer.php        : pied de page
 *
 * Permissions requises : rôles 1 (user), 2 (admin), 3 (superadmin)
 *
 * Actions POST :
 *   request_data — récupère username, role_id, ssh_key de l'utilisateur
 *                  connecté et les affiche en JSON
 *   delete_data  — supprime définitivement le compte de l'utilisateur
 *                  connecté et détruit sa session
 *
 * Note sécurité : Les actions POST ne sont pas protégées par CSRF dans cette
 *                 version. Les données affichées sont échappées via htmlspecialchars.
 */

require_once __DIR__ . '/auth/verify.php';
require_once __DIR__ . '/auth/functions.php';
require_once __DIR__ . '/db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Vérifie que l'utilisateur est authentifié (tous rôles acceptés)
checkAuth(['1', '2', '3']);

// ── Traitement des actions RGPD (POST) ───────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Vérification CSRF obligatoire avant toute action destructive
    checkCsrfToken();

    // Action : afficher les données personnelles enregistrées
    if (isset($_POST['request_data'])) {
        $stmt = $pdo->prepare("SELECT name, role_id, ssh_key, created_at FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $userData = $stmt->fetch(PDO::FETCH_ASSOC);
        echo "<div class='alert alert-info'>Données enregistrées : <pre>" . htmlspecialchars(json_encode($userData, JSON_PRETTY_PRINT)) . "</pre></div>";
    }

    // Action : supprimer définitivement le compte et la session
    if (isset($_POST['delete_data'])) {
        // Protection : un superadmin ne peut pas se supprimer s'il est le dernier
        $roleId = (int)($_SESSION['role_id'] ?? 0);
        if ($roleId === 3) {
            $saCount = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role_id = 3")->fetchColumn();
            if ($saCount <= 1) {
                echo "<div class='alert alert-danger'>Impossible de supprimer le dernier super-administrateur.</div>";
                goto skip_delete;
            }
        }
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        echo "<div class='alert alert-success'>Votre compte a été supprimé.</div>";
        session_destroy();
        skip_delete:
    }
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/head.php'; ?>
    <title>Politique de Confidentialité</title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <!-- Menu -->
    <?php require_once __DIR__ . '/menu.php'; ?>

    <div class="max-w-4xl mx-auto px-6 py-8">
        <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-6 text-center">
            Politique de Confidentialite
        </h1>
        <div class="bg-white dark:bg-gray-800 shadow-sm rounded-xl p-8 text-sm leading-relaxed text-gray-600 dark:text-gray-300 space-y-4">
            <h2>Collecte des Données</h2>
            <ul class="list-disc pl-6">
                <li>Nom d'utilisateur, rôle et données de session nécessaires à l'authentification.</li>
                <li>Actions réalisées sur la plateforme, adresses IP et logs applicatifs pour le débogage et l'amélioration.</li>
                <li>Cookies pour la gestion des sessions et des préférences utilisateur.</li>
            </ul>

            <h2>Utilisation des Données</h2>
            <ul class="list-disc pl-6">
                <li>Offrir un accès aux fonctionnalités de l'application.</li>
                <li>Assurer la sécurité et prévenir les accès non autorisés.</li>
                <li>Améliorer la plateforme et corriger les bogues.</li>
            </ul>

            <h2>Stockage des Données</h2>
            <ul class="list-disc pl-6">
                <li>Toutes les données sont stockées de manière sécurisée dans des bases de données chiffrées.</li>
                <li>L'accès aux données est limité aux personnels autorisés.</li>
            </ul>

            <h2>Droits des Utilisateurs</h2>
            <p>Les utilisateurs peuvent demander l'accès, la modification ou la suppression de leurs données en contactant l'administrateur.</p>
        </div>

        <div class="bg-white dark:bg-gray-800 shadow-sm rounded-xl p-6 mt-6">
            <h2 class="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-2">Vos donnees personnelles (RGPD)</h2>
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">Vous pouvez demander un rapport de vos donnees ou supprimer votre compte.</p>
            <form method="POST" class="flex flex-wrap gap-3">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                <button type="submit" name="request_data" class="text-sm px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors">Demander mes donnees</button>
                <button type="submit" name="delete_data" class="text-sm px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors"
                        onclick="return confirm('Attention : cette action est irreversible. Voulez-vous vraiment supprimer votre compte ?')">
                    Supprimer mon compte
            </button>
        </form>

    </div>

    <?php require_once __DIR__ . '/footer.php'; ?>
</body>
</html>
