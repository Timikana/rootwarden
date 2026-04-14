<?php
/**
 * adm/includes/server_actions.php
 *
 * Endpoint AJAX (JSON) pour les actions CRUD sur les serveurs.
 * Réservé aux rôles admin (2) et superadmin (3).
 * Retourne toujours un objet JSON { success: bool, message: string }.
 *
 * Actions POST supportées (champ 'action') :
 *   - 'add_server'    : crée un nouveau serveur (chiffrement AES des mots de passe)
 *   - 'update_server' : met à jour un serveur existant (préserve les mots de passe si champs vides)
 *   - 'delete_server' : supprime un serveur par ID
 *
 * Sécurité :
 *   - Vérification manuelle du jeton CSRF ($_POST['csrf_token'] vs $_SESSION['csrf_token'])
 *   - Validation de tous les champs via validateInput() avant toute requête SQL
 *   - La clé RSA peut être vide : utilise la valeur de la variable d'env DEFAULT_RSA_KEY
 *
 * @package RootWarden\Admin
 */
// server_actions.php - Gestion des actions AJAX pour les serveurs

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once 'crypto.php';

// Autorise les utilisateurs ayant le rôle admin (2) ou superadmin (3)
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

header('Content-Type: application/json');
$response = ['success' => false, 'message' => 'Action non reconnue'];

/**
 * Vérifie que le nom d'un serveur est composé uniquement de caractères alphanumériques,
 * tirets et underscores, avec une longueur comprise entre 1 et 255 caractères.
 *
 * @param string $name Nom à valider.
 * @return int 1 si valide, 0 sinon.
 */
function validateServerName($name) {
    return preg_match('/^[a-zA-Z0-9-_]{1,255}$/', $name);
}

/**
 * Valide et assainit une donnée selon son type pour les actions serveur.
 *
 * Types supportés :
 *   - 'name'         : nom serveur alphanumérique
 *   - 'ip'           : adresse IP v4/v6 valide
 *   - 'port'         : entier entre 1 et 65535
 *   - 'string'       : chaîne encodée via htmlspecialchars
 *   - 'rsa_key'      : clé hex 64 chars, ou DEFAULT_RSA_KEY si vide
 *   - 'environment'  : parmi PROD, DEV, TEST, OTHER
 *   - 'criticality'  : parmi CRITIQUE, NON CRITIQUE
 *   - 'network_type' : parmi INTERNE, EXTERNE
 *
 * @param mixed  $data Donnée brute à valider.
 * @param string $type Type de validation à appliquer.
 * @return mixed La donnée assainie, ou false si invalide.
 */
function validateInput($data, $type) {
    $data = trim($data); // Supprime les espaces inutiles
    switch ($type) {
        case 'name':
            return validateServerName($data) ? $data : false;
        case 'ip':
            return filter_var($data, FILTER_VALIDATE_IP) ? $data : false;
        case 'port':
            return filter_var($data, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]) ? $data : false;
        case 'string':
            return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        case 'rsa_key': // Validation simple pour une clé RSA
            $data = trim($data);
            if (empty($data)) {
                // Utiliser la clé par défaut depuis la variable d'environnement
                return getenv('DEFAULT_RSA_KEY');
            }
            // Vérifier que la clé est une chaîne hexadécimale de 64 caractères
            return preg_match('/^[a-fA-F0-9]{64}$/', $data) ? $data : false;
        case 'environment':
            $valid_env = ['PROD', 'DEV', 'TEST', 'OTHER'];
            return in_array($data, $valid_env) ? $data : false;
        case 'criticality':
            $valid_crit = ['CRITIQUE', 'NON CRITIQUE'];
            return in_array($data, $valid_crit) ? $data : false;
        case 'network_type':
            $valid_net = ['INTERNE', 'EXTERNE'];
            return in_array($data, $valid_net) ? $data : false;
        default:
            return false;
    }
}

// Tags : requêtes JSON — vérification CSRF via header ou body
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
if (strpos($contentType, 'application/json') !== false) {
    $jsonInput = json_decode(file_get_contents('php://input'), true);
    // Vérifier le token CSRF (header X-CSRF-Token ou champ csrf_token dans le JSON)
    $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($jsonInput['csrf_token'] ?? '');
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], (string)$csrfToken)) {
        echo json_encode(['success' => false, 'message' => 'Token CSRF invalide']);
        exit;
    }
    if ($jsonInput && isset($jsonInput['action'])) {
        $tagAction = $jsonInput['action'];
        $machineId = (int)($jsonInput['machine_id'] ?? 0);
        $tag = trim($jsonInput['tag'] ?? '');

        if ($tagAction === 'add_tag' && $machineId > 0 && $tag) {
            $tag = preg_replace('/[^a-z0-9_-]/', '', strtolower($tag));
            $stmt = $pdo->prepare("INSERT IGNORE INTO machine_tags (machine_id, tag) VALUES (?, ?)");
            $stmt->execute([$machineId, $tag]);
            echo json_encode(['success' => true, 'message' => 'Tag ajoute']);
            exit;
        } elseif ($tagAction === 'remove_tag' && $machineId > 0 && $tag) {
            $stmt = $pdo->prepare("DELETE FROM machine_tags WHERE machine_id = ? AND tag = ?");
            $stmt->execute([$machineId, $tag]);
            echo json_encode(['success' => true, 'message' => 'Tag supprime']);
            exit;
        } elseif ($tagAction === 'add_note' && $machineId > 0) {
            $content = trim($jsonInput['content'] ?? '');
            if (!$content) {
                echo json_encode(['success' => false, 'message' => 'Contenu vide']);
                exit;
            }
            $author = $_SESSION['username'] ?? 'admin';
            $stmt = $pdo->prepare("INSERT INTO server_notes (machine_id, author, content) VALUES (?, ?, ?)");
            $stmt->execute([$machineId, $author, $content]);
            echo json_encode(['success' => true, 'message' => 'Note ajoutee']);
            exit;
        } elseif ($tagAction === 'delete_note') {
            $noteId = (int)($jsonInput['note_id'] ?? 0);
            if ($noteId > 0) {
                $stmt = $pdo->prepare("DELETE FROM server_notes WHERE id = ?");
                $stmt->execute([$noteId]);
                echo json_encode(['success' => true, 'message' => 'Note supprimee']);
                exit;
            }
        }
    }
}

// Vérification du jeton CSRF (formulaires classiques)
if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    $response['message'] = 'Token CSRF invalide';
    echo json_encode($response);
    exit;
}

// Ajouter un serveur
if (isset($_POST['action']) && $_POST['action'] === 'add_server') {
    $name = validateInput($_POST['name'], 'name');
    $ip = validateInput($_POST['ip'], 'ip');
    $user = validateInput($_POST['user'], 'string');
    $password = encryptPassword(trim($_POST['password']), false);
    $root_password = encryptPassword(trim($_POST['root_password']), false);
    $port = validateInput($_POST['port'], 'port');
    $environment = validateInput($_POST['environment'], 'environment');
    $criticality = validateInput($_POST['criticality'], 'criticality');
    $network_type = validateInput($_POST['network_type'], 'network_type');
    $zabbix_rsa_key = validateInput($_POST['zabbix_rsa_key'], 'rsa_key');

    if (!$name || !$ip || !$user || !$port || !$environment || !$criticality || !$network_type || !$zabbix_rsa_key) {
        $error_fields = [];
        if (!$name) $error_fields[] = "Nom";
        if (!$ip) $error_fields[] = "IP";
        if (!$user) $error_fields[] = "Utilisateur";
        if (!$port) $error_fields[] = "Port";
        if (!$environment) $error_fields[] = "Environnement";
        if (!$criticality) $error_fields[] = "Criticité";
        if (!$network_type) $error_fields[] = "Réseau";
        if (!$zabbix_rsa_key) $error_fields[] = "Clé RSA";
        
        $response['message'] = "Données invalides fournies. Vérifiez les champs suivants : " . implode(', ', $error_fields);
    } else {
        try {
            $stmt = $pdo->prepare("INSERT INTO machines (name, ip, user, password, root_password, port, environment, criticality, network_type, zabbix_rsa_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$name, $ip, $user, $password, $root_password, $port, $environment, $criticality, $network_type, $zabbix_rsa_key]);
            $response['success'] = true;
            $response['message'] = "Serveur ajouté avec succès.";
            $response['server_id'] = $pdo->lastInsertId();
        } catch (PDOException $e) {
            if ($e->getCode() == 23000) { // Violation de contrainte (par exemple, nom ou IP unique)
                $response['message'] = "Un serveur avec ce nom ou cette IP existe déjà.";
            } else {
                $response['message'] = "Erreur SQL : " . $e->getMessage();
            }
        }
    }
} 
// Mettre à jour un serveur
elseif (isset($_POST['action']) && $_POST['action'] === 'update_server') {
    $server_id = validateInput($_POST['server_id'], 'port');
    $name = validateInput($_POST['name'], 'name');
    $ip = validateInput($_POST['ip'], 'ip');
    $user = validateInput($_POST['user'], 'string');
    $port = validateInput($_POST['port'], 'port');
    $environment = validateInput($_POST['environment'], 'environment');
    $criticality = validateInput($_POST['criticality'], 'criticality');
    $network_type = validateInput($_POST['network_type'], 'network_type');
    $zabbix_rsa_key = validateInput($_POST['zabbix_rsa_key'], 'rsa_key');

    if (!$server_id || !$name || !$ip || !$user || !$port || !$environment || !$criticality || !$network_type || !$zabbix_rsa_key) {
        $error_fields = [];
        if (!$server_id) $error_fields[] = "ID Serveur";
        if (!$name) $error_fields[] = "Nom";
        if (!$ip) $error_fields[] = "IP";
        if (!$user) $error_fields[] = "Utilisateur";
        if (!$port) $error_fields[] = "Port";
        if (!$environment) $error_fields[] = "Environnement";
        if (!$criticality) $error_fields[] = "Criticité";
        if (!$network_type) $error_fields[] = "Réseau";
        if (!$zabbix_rsa_key) $error_fields[] = "Clé RSA";
        
        $response['message'] = "Données invalides fournies. Vérifiez les champs suivants : " . implode(', ', $error_fields);
    } else {
        $stmt = $pdo->prepare("SELECT password, root_password FROM machines WHERE id = ?");
        $stmt->execute([$server_id]);
        $current_passwords = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$current_passwords) {
            $response['message'] = "Serveur introuvable.";
        } else {
            $password = empty($_POST['password']) ? $current_passwords['password'] : encryptPassword(trim($_POST['password']), false);
            $root_password = empty($_POST['root_password']) ? $current_passwords['root_password'] : encryptPassword(trim($_POST['root_password']), false);

            try {
                $stmt = $pdo->prepare("UPDATE machines SET name = ?, ip = ?, user = ?, password = ?, root_password = ?, port = ?, environment = ?, criticality = ?, network_type = ?, zabbix_rsa_key = ? WHERE id = ?");
                $stmt->execute([$name, $ip, $user, $password, $root_password, $port, $environment, $criticality, $network_type, $zabbix_rsa_key, $server_id]);
                $response['success'] = true;
                $response['message'] = "Informations du serveur mises à jour.";
            } catch (PDOException $e) {
                if ($e->getCode() == 23000) {
                    $response['message'] = "Un serveur avec ce nom ou cette IP existe déjà.";
                } else {
                    $response['message'] = "Erreur SQL : " . $e->getMessage();
                }
            }
        }
    }
} 
// Supprimer un serveur
elseif (isset($_POST['action']) && $_POST['action'] === 'delete_server') {
    $server_id = validateInput($_POST['server_id'], 'port');
    if (!$server_id) {
        $response['message'] = "ID de serveur invalide.";
    } else {
        try {
            $stmt = $pdo->prepare("DELETE FROM machines WHERE id = ?");
            $stmt->execute([$server_id]);
            $response['success'] = true;
            $response['message'] = "Serveur supprimé avec succès.";
        } catch (PDOException $e) {
            $response['message'] = "Erreur SQL : " . $e->getMessage();
        }
    }
}

echo json_encode($response);
exit;