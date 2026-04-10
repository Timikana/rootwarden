<?php
/**
 * Script d'insertion du serveur de test en BDD.
 * À exécuter dans le conteneur PHP après le démarrage du test-server :
 *   docker exec gestion_ssh_key_php php /var/www/html/test-server/seed_test_machine.php
 *
 * Chiffre les mots de passe via crypto.php (compatible backend Python)
 * et attribue le serveur au superadmin + admin.
 */

// Bootstrap minimal
$_SESSION = ['user_id' => 2, 'username' => 'superadmin', 'role_id' => 3,
    'permissions' => ['can_deploy_keys'=>1,'can_update_linux'=>1,'can_manage_iptables'=>1,'can_admin_portal'=>1,'can_scan_cve'=>1]];

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../adm/includes/crypto.php';

$name          = 'Test-Server-Debian';
$ip            = '192.169.50.6';
$port          = 22;
$user          = 'testuser';
$password      = 'testpass';
$rootPassword  = 'rootpass';
$environment   = 'DEV';
$criticality   = 'NON CRITIQUE';
$networkType   = 'INTERNE';

// Vérifie si le serveur existe déjà
$check = $pdo->prepare("SELECT id FROM machines WHERE name = ? OR ip = ?");
$check->execute([$name, $ip]);
if ($check->fetch()) {
    echo "Le serveur '$name' ($ip) existe déjà en BDD.\n";
    exit(0);
}

// Chiffre les mots de passe
$encPassword     = encryptPassword($password);
$encRootPassword = encryptPassword($rootPassword);

echo "Chiffrement user: " . substr($encPassword, 0, 20) . "...\n";
echo "Chiffrement root: " . substr($encRootPassword, 0, 20) . "...\n";

// Insertion
$stmt = $pdo->prepare("
    INSERT INTO machines (name, ip, port, user, password, root_password, environment, criticality, network_type, status, online_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Actif', 'Inconnu')
");
$stmt->execute([$name, $ip, $port, $user, $encPassword, $encRootPassword, $environment, $criticality, $networkType]);
$machineId = $pdo->lastInsertId();

echo "Machine insérée avec ID=$machineId\n";

// Attribution du serveur aux users existants (admin=1, superadmin=2)
$stmt = $pdo->prepare("INSERT IGNORE INTO user_machine_access (user_id, machine_id) VALUES (?, ?)");
$stmt->execute([1, $machineId]); // admin
$stmt->execute([2, $machineId]); // superadmin

echo "Accès attribué à admin + superadmin.\n";
echo "Done! Serveur de test prêt.\n";
