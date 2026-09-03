<?php
/**
 * update/functions/machines.php
 *
 * Fonctions d'accès aux données des machines (table machines + linux_versions).
 * Ces fonctions sont utilisées par les scripts de mise à jour Linux et de monitoring.
 *
 * Fonctions exposées :
 *   - getAllMachines()              : récupère toutes les machines avec JOIN sur linux_versions
 *   - updateMachineOnlineStatus()  : met à jour online_status d'une machine
 *   - updateLinuxVersion()         : insère ou met à jour la version Linux (UPSERT)
 *
 * @package RootWarden\Update
 */
// functions/machines.php

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';

/**
 * Récupère toutes les machines avec leur version Linux courante via LEFT JOIN.
 * Inclut les credentials SSH (password, root_password) utilisés par le backend Python.
 *
 * @return array Tableau de tableaux associatifs, une entrée par machine, triées par id ASC.
 */
function getAllMachines(): array
{
    global $pdo;
    
    $sql = "
        SELECT 
            m.id,
            m.name,
            m.ip,
            m.port,
            m.user AS ssh_user,
            m.password AS ssh_password,
            m.root_password,
            m.status,
            m.online_status,
            m.environment,
            m.criticality,
            m.network_type,
            lv.version AS linux_version,
            lv.last_checked
        FROM machines m
        LEFT JOIN linux_versions lv ON m.id = lv.machine_id
        ORDER BY m.id ASC
    ";

    $stmt = $pdo->query($sql);
    return $stmt->fetchAll(); // Retourne un tableau associatif
}

/**
 * Met à jour la colonne online_status d'une machine dans la table machines.
 *
 * @param int    $machineId Identifiant de la machine à mettre à jour.
 * @param string $newStatus Nouveau statut ('online', 'offline', etc.).
 * @return bool true si la requête s'est exécutée sans erreur, false sinon.
 */
function updateMachineOnlineStatus(int $machineId, string $newStatus): bool
{
    global $pdo;

    $sql = "UPDATE machines SET online_status = :status WHERE id = :id";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':status', $newStatus);
    $stmt->bindValue(':id', $machineId);

    return $stmt->execute();
}

/**
 * Insère ou met à jour la version Linux d'une machine dans la table linux_versions (UPSERT).
 * Si un enregistrement existe déjà pour cette machine, la version et la date last_checked
 * sont mis à jour ; sinon une nouvelle ligne est insérée.
 *
 * @param int    $machineId Identifiant de la machine concernée.
 * @param string $version   Chaîne de version Linux (ex: "Ubuntu 22.04.3 LTS").
 * @return bool true si l'opération a réussi, false sinon.
 */
function updateLinuxVersion(int $machineId, string $version): bool
{
    global $pdo;

    $sql = "
        INSERT INTO linux_versions (machine_id, version, last_checked) 
        VALUES (:machine_id, :version, NOW())
        ON DUPLICATE KEY UPDATE 
            version = :version,
            last_checked = NOW()
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':machine_id', $machineId);
    $stmt->bindValue(':version', $version);

    return $stmt->execute();
}
