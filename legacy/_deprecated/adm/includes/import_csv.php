<?php
/**
 * import_csv.php - Import CSV de serveurs et d'utilisateurs
 * Inclus dans admin_page.php via les onglets Serveurs et Utilisateurs.
 */

if (!isset($pdo) || !isset($_SESSION['csrf_token'])) return;

// Patch A03-CMD-01 : assure que validateServerName() est dispo (definie
// dans manage_servers.php). Si le fichier n'a pas ete inclus, on inline.
// v1.37.14 : regle IDENTIQUE a manage_servers.php (espaces, points, +,
// parentheses autorises ; metacaracteres shell/HTML interdits).
if (!function_exists('validateServerName')) {
    function validateServerName($name) {
        return is_string($name) && preg_match('/^[a-zA-Z0-9][a-zA-Z0-9 ._+()-]{0,254}$/', $name) === 1;
    }
}

$importResult = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['import_type'])) {
    checkCsrfToken();
    $importType = $_POST['import_type'];
    $skipDuplicates = isset($_POST['skip_duplicates']);
    $sendWelcome = isset($_POST['send_welcome']);

    if (!isset($_FILES['csv_file']) || $_FILES['csv_file']['error'] !== UPLOAD_ERR_OK) {
        $importResult = ['type' => 'error', 'msg' => 'Erreur upload du fichier CSV.'];
    } else {
        $file = fopen($_FILES['csv_file']['tmp_name'], 'r');
        $header = fgetcsv($file);
        if (!$header) {
            $importResult = ['type' => 'error', 'msg' => 'Fichier CSV vide ou invalide.'];
        } else {
            // Normaliser les noms de colonnes
            $header = array_map('trim', array_map('strtolower', $header));
            $results = ['ok' => 0, 'errors' => []];
            $lineNum = 1;

            if ($importType === 'servers') {
                $requiredCols = ['name', 'ip', 'user', 'password', 'root_password'];
                $missing = array_diff($requiredCols, $header);
                if (!empty($missing)) {
                    $importResult = ['type' => 'error', 'msg' => 'Colonnes manquantes : ' . implode(', ', $missing)];
                } else {
                    require_once __DIR__ . '/crypto.php';
                    while (($row = fgetcsv($file)) !== false) {
                        $lineNum++;
                        $data = array_combine($header, array_pad($row, count($header), ''));
                        $name = trim($data['name'] ?? '');
                        $ip = trim($data['ip'] ?? '');
                        if (!$name || !$ip) {
                            $results['errors'][] = "Ligne $lineNum : nom ou IP vide";
                            continue;
                        }
                        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                            $results['errors'][] = "Ligne $lineNum ($name) : IP invalide '$ip'";
                            continue;
                        }
                        // Patch A03-CMD-01 (OWASP A03) : valider le nom de machine
                        // contre la regex stricte (alphanum + - + _, 1-255 chars).
                        // Avant : un nom CSV "foo'; reboot; echo '" finissait dans
                        // les commandes shell (logger -t '...' 'ping ... \$name')
                        // via /graylog/test, RCE root distante.
                        if (!validateServerName($name)) {
                            $results['errors'][] = "Ligne $lineNum : nom de machine invalide (caracteres non autorises)";
                            continue;
                        }
                        // Refuse aussi IPs loopback/link-local (cf A10-01)
                        $ipReserved = (
                            strpos($ip, '127.') === 0 || strpos($ip, '169.254.') === 0 ||
                            strpos($ip, '0.') === 0 || $ip === '::1' || stripos($ip, 'fe80:') === 0
                        );
                        if ($ipReserved) {
                            $results['errors'][] = "Ligne $lineNum ($name) : IP reservee refusee ($ip)";
                            continue;
                        }
                        // Verifier doublon
                        if ($skipDuplicates) {
                            $chk = $pdo->prepare("SELECT COUNT(*) FROM machines WHERE name = ? OR ip = ?");
                            $chk->execute([$name, $ip]);
                            if ($chk->fetchColumn() > 0) {
                                $results['errors'][] = "Ligne $lineNum ($name) : doublon ignore";
                                continue;
                            }
                        }
                        try {
                            $port = (int)($data['port'] ?? 22) ?: 22;
                            $encPass = encryptPassword($data['password'] ?? '');
                            $encRoot = encryptPassword($data['root_password'] ?? '');
                            $env = strtoupper($data['environment'] ?? 'OTHER');
                            if (!in_array($env, ['PROD','DEV','TEST','OTHER'])) $env = 'OTHER';
                            $crit = strtoupper($data['criticality'] ?? 'NON CRITIQUE');
                            if (!in_array($crit, ['CRITIQUE','NON CRITIQUE'])) $crit = 'NON CRITIQUE';
                            $net = strtoupper($data['network_type'] ?? 'INTERNE');
                            if (!in_array($net, ['INTERNE','EXTERNE'])) $net = 'INTERNE';

                            $stmt = $pdo->prepare("INSERT INTO machines (name, ip, port, user, password, root_password, environment, criticality, network_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                            $stmt->execute([$name, $ip, $port, $data['user'], $encPass, $encRoot, $env, $crit, $net]);
                            $machineId = $pdo->lastInsertId();

                            // Tags
                            if (!empty($data['tags'])) {
                                $tags = array_filter(array_map('trim', explode(';', $data['tags'])));
                                foreach ($tags as $tag) {
                                    $pdo->prepare("INSERT IGNORE INTO machine_tags (machine_id, tag) VALUES (?, ?)")
                                        ->execute([$machineId, $tag]);
                                }
                            }
                            $results['ok']++;
                        } catch (\Exception $e) {
                            $results['errors'][] = "Ligne $lineNum ($name) : " . $e->getMessage();
                        }
                    }
                    $importResult = ['type' => empty($results['errors']) ? 'success' : 'warning',
                                     'msg' => "{$results['ok']} serveur(s) importe(s)." . (empty($results['errors']) ? '' : ' ' . count($results['errors']) . ' erreur(s).'),
                                     'details' => $results['errors']];
                    // Audit log
                    try {
                        $pdo->prepare("INSERT INTO user_logs (user_id, action) VALUES (?, ?)")
                            ->execute([$_SESSION['user_id'], "Import CSV: {$results['ok']} serveurs importes"]);
                    } catch (\Exception $e) {}
                }

            } elseif ($importType === 'users') {
                $requiredCols = ['name'];
                $missing = array_diff($requiredCols, $header);
                if (!empty($missing)) {
                    $importResult = ['type' => 'error', 'msg' => 'Colonne obligatoire manquante : name'];
                } else {
                    while (($row = fgetcsv($file)) !== false) {
                        $lineNum++;
                        $data = array_combine($header, array_pad($row, count($header), ''));
                        $name = trim($data['name'] ?? '');
                        if (!$name || !preg_match('/^[a-zA-Z0-9._-]+$/', $name)) {
                            $results['errors'][] = "Ligne $lineNum : nom invalide '$name'";
                            continue;
                        }
                        if ($skipDuplicates) {
                            $chk = $pdo->prepare("SELECT COUNT(*) FROM users WHERE name = ?");
                            $chk->execute([$name]);
                            if ($chk->fetchColumn() > 0) {
                                $results['errors'][] = "Ligne $lineNum ($name) : doublon ignore";
                                continue;
                            }
                        }
                        try {
                            $password = bin2hex(random_bytes(8)); // 16 chars hex
                            $hash = password_hash($password, PASSWORD_DEFAULT);
                            $roleMap = ['user' => 1, 'admin' => 2, 'superadmin' => 3];
                            $roleId = $roleMap[strtolower($data['role'] ?? 'user')] ?? 1;
                            // Patch A01/A07 : meme regle hierarchique que add_user.
                            // Un import par un non-superadmin ne peut creer un role
                            // superieur ou egal au sien.
                            $myRole = (int)($_SESSION['role_id'] ?? 1);
                            if ($myRole < 3 && $roleId >= $myRole) {
                                $roleId = 1;
                            }
                            $email = trim($data['email'] ?? '');
                            $sshKey = trim($data['ssh_key'] ?? '');
                            $active = (int)($data['active'] ?? 1);
                            $sudo = (int)($data['sudo'] ?? 0);

                            $pdo->beginTransaction();
                            $stmt = $pdo->prepare("INSERT INTO users (name, email, password, ssh_key, role_id, active, sudo) VALUES (?, ?, ?, ?, ?, ?, ?)");
                            $stmt->execute([$name, $email ?: null, $hash, $sshKey ?: null, $roleId, $active, $sudo]);
                            $userId = $pdo->lastInsertId();
                            $pdo->prepare("INSERT INTO permissions (user_id, can_deploy_keys, can_update_linux, can_manage_iptables, can_admin_portal, can_scan_cve, can_manage_remote_users, can_manage_platform_key, can_view_compliance, can_manage_backups, can_schedule_cve, can_manage_fail2ban, can_manage_services, can_audit_ssh, can_manage_supervision) VALUES (?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)")
                                ->execute([$userId]);
                            $pdo->commit();
                            $results['ok']++;
                        } catch (\Exception $e) {
                            if ($pdo->inTransaction()) $pdo->rollBack();
                            $results['errors'][] = "Ligne $lineNum ($name) : " . $e->getMessage();
                        }
                    }
                    $importResult = ['type' => empty($results['errors']) ? 'success' : 'warning',
                                     'msg' => "{$results['ok']} utilisateur(s) importe(s)." . (empty($results['errors']) ? '' : ' ' . count($results['errors']) . ' erreur(s).'),
                                     'details' => $results['errors']];
                    try {
                        $pdo->prepare("INSERT INTO user_logs (user_id, action) VALUES (?, ?)")
                            ->execute([$_SESSION['user_id'], "Import CSV: {$results['ok']} utilisateurs importes"]);
                    } catch (\Exception $e) {}
                }
            }
            fclose($file);
        }
    }
}
