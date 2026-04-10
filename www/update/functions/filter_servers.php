<?php
/**
 * update/functions/filter_servers.php
 *
 * Endpoint AJAX qui retourne en JSON la liste des serveurs filtrés.
 * Délègue la logique de filtrage à getFilteredServers() (filter.php).
 * Accessible aux rôles admin (2) et superadmin (3).
 *
 * Paramètres GET acceptés :
 *   - environment : filtre sur l'environnement (PROD, DEV, TEST, OTHER)
 *   - criticality : filtre sur la criticité (CRITIQUE, NON CRITIQUE)
 *   - networkType : filtre sur le type de réseau (INTERNE, EXTERNE)
 *
 * Réponse JSON : { "servers": [ {...}, ... ] }
 *
 * @package RootWarden\Update
 */
// filter_servers.php
require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/filter.php';



if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
checkAuth(['2','3']); // Autorise rôles admin, superadmin etc.

// Récupère les paramètres GET
$environment = $_GET['environment'] ?? '';
$criticality = $_GET['criticality'] ?? '';
$networkType = $_GET['networkType'] ?? '';

// On récupère les serveurs filtrés
$servers = getFilteredServers($environment, $criticality, $networkType);

// Réponse JSON
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['servers' => $servers]);
