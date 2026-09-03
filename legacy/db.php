<?php
/**
 * db.php - Connexion PDO à la base de données MySQL
 *
 * Rôle       : Initialise et expose la variable $pdo utilisée par tous les
 *              scripts PHP qui ont besoin d'accéder à la base de données.
 *              Doit être inclus via require_once avant toute requête SQL.
 *
 * Dépendances : Aucune inclusion PHP. Repose uniquement sur les variables
 *               d'environnement définies dans srv-docker.env / docker-compose.yml.
 *
 * Variables d'environnement lues :
 *   DB_HOST     - Hôte MySQL (défaut : 'db', nom du service Docker)
 *   DB_NAME     - Nom de la base de données (défaut : 'rootwarden')
 *   DB_USER     - Utilisateur MySQL (défaut : 'rootwarden_user')
 *   DB_PASSWORD - Mot de passe MySQL (défaut : 'rootwarden_password')
 *   DB_PORT     - Port MySQL (non utilisé explicitement dans le DSN ici,
 *                 géré par le service Docker)
 *
 * Sécurité   : Le DSN inclut charset=utf8 pour forcer l'encodage des échanges
 *              et éviter certaines attaques d'encodage. PDO::ERRMODE_EXCEPTION
 *              est activé pour que toute erreur SQL lève une PDOException
 *              (capturée par les blocs try/catch des scripts appelants).
 *
 * Erreur     : En cas d'échec de connexion, die() arrête l'exécution. En
 *              production, envisager un log d'erreur sans exposer le message
 *              brut à l'utilisateur final.
 *
 * Variable exposée : $pdo (PDO) - instance de connexion partagée
 */

// ── Lecture des paramètres de connexion depuis les variables d'environnement ──
$host     = getenv('DB_HOST')     ?: 'db';                  // Service MySQL dans Docker
$dbname   = getenv('DB_NAME')     ?: 'rootwarden';          // Base de données cible
$username = getenv('DB_USER')     ?: 'rootwarden_user';     // Utilisateur MySQL applicatif
$password = getenv('DB_PASSWORD') ?: 'rootwarden_password'; // Mot de passe MySQL applicatif

$debugMode = getenv('DEBUG_MODE') === 'true';

// Patch A05 : refuser le mot de passe DB par defaut hors mode debug (valeur
// triviale connue, presente dans le depot). Coherent avec config.py backend.
if (!$debugMode && $password === 'rootwarden_password') {
    error_log('[db.php] DB_PASSWORD non defini (valeur par defaut) en mode non-debug');
    http_response_code(500);
    die("Configuration invalide. Contactez l'administrateur.");
}

try {
    // Connexion PDO avec charset utf8mb4 (Unicode complet, evite les troncatures
    // et certaines attaques d'encodage sur l'ancien utf8 3 octets).
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);

    // Active le mode exception : toute erreur SQL lèvera une PDOException
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // Désactive l'émulation des prepared statements - force les vrais prepared côté MySQL
    // (prévient certains bypass d'injection SQL avec les emulated prepares)
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
} catch (PDOException $e) {
    error_log("DB connection failed: " . $e->getMessage());
    if ($debugMode) {
        // Le hint (suggestion down -v) ne doit apparaitre qu'en debug : il revele
        // l'infra et une procedure destructive a un utilisateur non authentifie.
        $hint = '';
        if (strpos($e->getMessage(), 'Access denied') !== false) {
            $hint = '<br><small style="color:#999">Verifiez que DB_PASSWORD dans srv-docker.env correspond au mot de passe MySQL.<br>'
                  . 'Si vous avez change le mot de passe apres la premiere initialisation, supprimez le volume :<br>'
                  . '<code>docker-compose down -v && docker-compose up -d</code> (attention : efface les donnees)</small>';
        }
        die("Erreur DB : " . htmlspecialchars($e->getMessage()) . $hint);
    } else {
        die("Erreur de connexion a la base de donnees. Contactez l'administrateur.");
    }
}

