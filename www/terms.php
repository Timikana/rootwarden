<?php
/**
 * terms.php — Conditions Générales d'Utilisation (CGU)
 *
 * Rôle       : Affiche les conditions d'utilisation de la plateforme.
 *              Propose un bouton "J'accepte" qui marque la session comme ayant
 *              accepté les CGU ($_SESSION['terms_accepted'] = true) et redirige
 *              vers la page d'accueil.
 *
 * Dépendances :
 *   - auth/verify.php   : checkAuth() — vérification authentification et rôle
 *   - auth/functions.php: fonctions utilitaires de session
 *   - db.php            : $pdo — connexion PDO MySQL (inclus via verify.php chain)
 *   - head.php          : balises <head> communes
 *   - menu.php          : barre de navigation
 *   - footer.php        : pied de page
 *
 * Permissions requises : rôles 1 (user), 2 (admin), 3 (superadmin)
 *
 * Action POST :
 *   accept_terms — positionne $_SESSION['terms_accepted'] à true
 *                  et redirige vers index.php
 *
 * Contenu     : Statique (responsabilités, limites, activités interdites,
 *               protection des données, contact support).
 */

require_once __DIR__ . '/auth/verify.php';
require_once __DIR__ . '/auth/functions.php';
require_once __DIR__ . '/db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Vérifie que l'utilisateur est authentifié (tous rôles acceptés)
checkAuth(['1', '2', '3']);

// ── Traitement de l'acceptation des CGU ──────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['accept_terms'])) {
    // Marque l'acceptation dans la session et redirige vers le portail principal
    $_SESSION['terms_accepted'] = true;
    header("Location: index.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/head.php'; ?>
    <title>Conditions Générales d'Utilisation</title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <!-- Menu -->
    <?php require_once __DIR__ . '/menu.php'; ?>

    <div class="max-w-4xl mx-auto px-6 py-8">
        <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-6 text-center">
            Conditions Generales d'Utilisation
        </h1>
        <div class="bg-white dark:bg-gray-800 shadow-sm rounded-xl p-8 text-sm leading-relaxed text-gray-600 dark:text-gray-300 space-y-4">
            <h2>Responsabilités des Utilisateurs</h2>
            <ul class="list-disc pl-6">
                <li>Les utilisateurs doivent conserver leurs identifiants en sécurité et ne pas les partager.</li>
                <li>Les utilisateurs sont responsables de toutes les actions effectuées avec leurs comptes.</li>
            </ul>

            <h2>Limites de la Plateforme</h2>
            <ul class="list-disc pl-6">
                <li>L'application est fournie "en l'état" sans aucune garantie.</li>
                <li>L'équipe de développement n'est pas responsable des pertes de données ou des accès non autorisés causés par la négligence des utilisateurs.</li>
            </ul>

            <h2>Activités Interdites</h2>
            <ul class="list-disc pl-6">
                <li>Les accès non autorisés ou les tentatives de violation des mesures de sécurité de l'application.</li>
                <li>L'utilisation de la plateforme à des fins illégales.</li>
            </ul>

            <h2>Protection des Données Personnelles</h2>
            <p>
                Nous nous engageons à protéger les données personnelles des utilisateurs. 
                Aucune information ne sera partagée avec des tiers sans consentement.
            </p>

            <h2>Contact et Support</h2>
            <p>
                Pour toute question ou signalement, contactez notre support à 
                <a href="mailto:<?= htmlspecialchars(getenv('SERVER_ADMIN') ?: 'admin@localhost') ?>" class="text-blue-500 underline"><?= htmlspecialchars(getenv('SERVER_ADMIN') ?: 'admin@localhost') ?></a>.
            </p>
        </div>

        <div class="text-center mt-6">
            <form method="POST">
                <button type="submit" name="accept_terms" class="bg-blue-600 hover:bg-blue-700 text-white px-8 py-2.5 rounded-lg font-medium transition-colors">
                    J'accepte les conditions
                </button>
            </form>
        </div>
    </div>

    <?php require_once __DIR__ . '/footer.php'; ?>
</body>
</html>
