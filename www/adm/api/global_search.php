<?php
/**
 * global_search.php — Recherche globale cross-entites (AJAX JSON)
 * Cherche dans : serveurs (name, ip), utilisateurs (name, email), CVE (cve_id)
 */
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
checkAuth([2, 3]); // Admin et superadmin uniquement

header('Content-Type: application/json');

$q = trim($_GET['q'] ?? '');
if (strlen($q) < 2) {
    echo json_encode(['results' => []]);
    exit;
}

$results = [];
$like = "%{$q}%";

// Serveurs
$stmt = $pdo->prepare("SELECT id, name, ip, environment, online_status FROM machines WHERE name LIKE ? OR ip LIKE ? LIMIT 5");
$stmt->execute([$like, $like]);
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $results[] = [
        'type' => 'server',
        'label' => $row['name'],
        'sub' => $row['ip'] . ' · ' . ($row['environment'] ?? ''),
        'url' => '/adm/admin_page.php#servers',
        'status' => strtolower($row['online_status'] ?? '') === 'online' ? 'online' : 'offline',
    ];
}

// Utilisateurs
$stmt = $pdo->prepare("SELECT u.id, u.name, u.email, u.active, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.name LIKE ? OR u.email LIKE ? LIMIT 5");
$stmt->execute([$like, $like]);
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $results[] = [
        'type' => 'user',
        'label' => $row['name'],
        'sub' => ($row['email'] ?? '') . ' · ' . $row['role_name'],
        'url' => '/adm/admin_page.php#users',
        'status' => $row['active'] ? 'active' : 'inactive',
    ];
}

// CVE
$stmt = $pdo->prepare("SELECT DISTINCT f.cve_id, f.severity, f.cvss_score, f.package_name FROM cve_findings f WHERE f.cve_id LIKE ? OR f.package_name LIKE ? ORDER BY f.cvss_score DESC LIMIT 5");
$stmt->execute([$like, $like]);
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $results[] = [
        'type' => 'cve',
        'label' => $row['cve_id'],
        'sub' => $row['package_name'] . ' · ' . $row['severity'] . ' ' . $row['cvss_score'],
        'url' => '/security/cve_scan.php',
        'status' => strtolower($row['severity']),
    ];
}

echo json_encode(['results' => $results]);
