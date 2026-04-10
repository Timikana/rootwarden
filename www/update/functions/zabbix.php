<?php
/**
 * update/functions/zabbix.php
 *
 * Fonctions de mise à jour des données Zabbix en base de données.
 * Utilisé par le backend Python (server.py) après interrogation de l'agent Zabbix
 * sur chaque machine.
 *
 * @package RootWarden\Update
 */
// functions/zabbix.php

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';


/**
 * Met à jour la version de l'agent Zabbix enregistrée pour une machine donnée
 * dans la colonne zabbix_agent_version de la table machines.
 *
 * @param int    $machineId      Identifiant de la machine concernée.
 * @param string $zabbixVersion  Version de l'agent Zabbix détectée (ex: "6.4.0").
 * @return bool true si la requête UPDATE a réussi, false sinon.
 */
function updateZabbixVersion(int $machineId, string $zabbixVersion): bool
{
    global $pdo;

    $sql = "UPDATE machines SET zabbix_agent_version = :zabbix_version WHERE id = :id";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':zabbix_version', $zabbixVersion);
    $stmt->bindValue(':id', $machineId);

    return $stmt->execute();
}

