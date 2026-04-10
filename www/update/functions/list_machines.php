<?php
/**
 * update/functions/list_machines.php
 *
 * Endpoint JSON qui retourne la liste complète des machines avec leurs informations
 * de version Linux et de statut en ligne.
 * Accessible aux rôles admin (2) et superadmin (3).
 *
 * Colonnes retournées par machine :
 *   id, name, ip, port, linux_version, last_checked, online_status,
 *   zabbix_agent_version, environment, criticality, network_type
 *
 * Réponse JSON (succès) : { "success": true, "machines": [ {...}, ... ] }
 * Réponse JSON (erreur) : { "success": false, "message": "..." }
 *
 * @package RootWarden\Update
 */
// list_machines.php
header('Content-Type: application/json');
require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';

// Démarre la session si nécessaire
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

checkAuth(['2','3']);

try {
  $stmt = $pdo->query("
      SELECT 
          id, name, ip, port, linux_version, last_checked, online_status,
          zabbix_agent_version, environment, criticality, network_type
      FROM machines
  ");
  $machines = $stmt->fetchAll(PDO::FETCH_ASSOC);

  echo json_encode(["success" => true, "machines" => $machines]);
} catch (Exception $e) {
  error_log("Erreur dans list_machines.php : " . $e->getMessage());
  echo json_encode(["success" => false, "message" => "Erreur lors de la récupération des machines."]);
}
exit;