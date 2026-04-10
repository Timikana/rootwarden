<?php
/**
 * update/functions/filter.php
 *
 * Fournit la fonction getFilteredServers() utilisée par filter_servers.php
 * pour retourner une liste de machines filtrée dynamiquement.
 * Chaque filtre est optionnel : si null ou vide, la condition correspondante
 * est omise de la requête SQL (clause WHERE 1=1 + AND dynamiques).
 *
 * @package RootWarden\Update
 */
// functions/filter.php

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';


/**
 * Récupère la liste des machines filtrées selon l'environnement, la criticité
 * et/ou le type de réseau. Chaque paramètre est optionnel : s'il est null ou vide,
 * le filtre correspondant est ignoré.
 *
 * @param string|null $environment  Filtre sur la colonne environment (ex: 'PROD', 'DEV').
 * @param string|null $criticality  Filtre sur la colonne criticality (ex: 'CRITIQUE').
 * @param string|null $networkType  Filtre sur la colonne network_type (ex: 'INTERNE').
 * @return array Tableau associatif de toutes les machines correspondantes.
 */
function getFilteredServers(?string $environment, ?string $criticality, ?string $networkType): array
{
    global $pdo;

    // Construire la requête dynamiquement
    $sql = "SELECT * FROM machines WHERE 1=1";
    $params = [];

    if (!empty($environment)) {
        $sql .= " AND environment = :env";
        $params[':env'] = $environment;
    }
    if (!empty($criticality)) {
        $sql .= " AND criticality = :crit";
        $params[':crit'] = $criticality;
    }
    if (!empty($networkType)) {
        $sql .= " AND network_type = :net";
        $params[':net'] = $networkType;
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
