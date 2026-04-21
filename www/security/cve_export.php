<?php
/**
 * security/cve_export.php - Export CSV des résultats CVE
 *
 * Paramètres GET :
 *   machine_id (int) - Exporte le dernier scan de cette machine
 *   scan_id (int)    - Exporte un scan spécifique (optionnel)
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_scan_cve');

$machineId = (int)($_GET['machine_id'] ?? 0);
$scanId    = (int)($_GET['scan_id'] ?? 0);

if (!$machineId && !$scanId) {
    http_response_code(400);
    header('Content-Type: application/json');
    die(json_encode(['error' => 'machine_id ou scan_id requis']));
}

// Récupère le scan
if ($scanId) {
    $stmt = $pdo->prepare("SELECT s.*, m.name as machine_name FROM cve_scans s JOIN machines m ON s.machine_id = m.id WHERE s.id = ?");
    $stmt->execute([$scanId]);
} else {
    $stmt = $pdo->prepare("SELECT s.*, m.name as machine_name FROM cve_scans s JOIN machines m ON s.machine_id = m.id WHERE s.machine_id = ? AND s.status = 'completed' ORDER BY s.scan_date DESC LIMIT 1");
    $stmt->execute([$machineId]);
}
$scan = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$scan) {
    http_response_code(404);
    header('Content-Type: application/json');
    die(json_encode(['error' => 'Aucun scan trouve']));
}

// Récupère les findings
$stmt = $pdo->prepare("SELECT cve_id, package_name, package_version, cvss_score, severity, summary FROM cve_findings WHERE scan_id = ? ORDER BY FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW','NONE'), cvss_score DESC");
$stmt->execute([$scan['id']]);
$findings = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Génère le CSV
$filename = 'cve_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $scan['machine_name']) . '_' . date('Y-m-d', strtotime($scan['scan_date'])) . '.csv';

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Pragma: no-cache');

$out = fopen('php://output', 'w');

// BOM UTF-8 pour Excel
fwrite($out, "\xEF\xBB\xBF");

// Metadata
fputcsv($out, ['# Rapport CVE - ' . $scan['machine_name']]);
fputcsv($out, ['# Date du scan : ' . $scan['scan_date']]);
fputcsv($out, ['# Paquets scannes : ' . $scan['packages_scanned']]);
fputcsv($out, ['# Seuil CVSS : ' . $scan['min_cvss']]);
fputcsv($out, ['# Critical : ' . $scan['critical_count'] . ' | High : ' . $scan['high_count'] . ' | Medium : ' . $scan['medium_count'] . ' | Low : ' . $scan['low_count']]);
fputcsv($out, []);

// Headers
fputcsv($out, ['CVE ID', 'Package', 'Version', 'CVSS', 'Severite', 'Resume']);

// Data
foreach ($findings as $f) {
    fputcsv($out, [
        $f['cve_id'],
        $f['package_name'],
        $f['package_version'],
        $f['cvss_score'],
        $f['severity'],
        $f['summary'],
    ]);
}

if (empty($findings)) {
    fputcsv($out, ['Aucune vulnerabilite trouvee au-dessus du seuil configure']);
}

fclose($out);
