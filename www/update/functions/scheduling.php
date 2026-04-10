<?php
/**
 * update/functions/scheduling.php
 *
 * Fonctions de gestion des planifications de mise à jour automatique des machines.
 * Les planifications sont stockées dans la table update_schedules.
 *
 * Fonctions exposées :
 *   - scheduleMachineUpdate()  : crée ou met à jour une planification (UPSERT)
 *   - getScheduleForMachine()  : lit la planification existante d'une machine
 *
 * @package RootWarden\Update
 */
// functions/scheduling.php

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';


/**
 * Insère ou met à jour la planification de mise à jour automatique d'une machine (UPSERT).
 * Si une planification existe déjà pour cette machine, seul interval_minutes est mis à jour.
 * Les champs last_run et next_run sont initialisés à NULL lors de la première insertion.
 *
 * @param int $machineId        Identifiant de la machine à planifier.
 * @param int $intervalMinutes  Intervalle en minutes entre deux mises à jour automatiques.
 * @return bool true si l'opération a réussi, false sinon.
 */
function scheduleMachineUpdate(int $machineId, int $intervalMinutes): bool
{
    global $pdo;

    $sql = "
        INSERT INTO update_schedules (machine_id, interval_minutes, last_run, next_run, created_at)
        VALUES (:machine_id, :interval_minutes, NULL, NULL, NOW())
        ON DUPLICATE KEY UPDATE
            interval_minutes = :interval_minutes,
            updated_at = NOW()
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':machine_id', $machineId);
    $stmt->bindValue(':interval_minutes', $intervalMinutes);

    return $stmt->execute();
}

/**
 * Récupère la planification de mise à jour existante pour une machine donnée.
 * Retourne null si aucune planification n'a encore été définie pour cette machine.
 *
 * @param int $machineId Identifiant de la machine dont on souhaite lire la planification.
 * @return array|null Tableau associatif de la ligne update_schedules, ou null si inexistant.
 */
function getScheduleForMachine(int $machineId): ?array
{
    global $pdo;

    $sql = "SELECT * FROM update_schedules WHERE machine_id = :machineId";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':machineId', $machineId);
    $stmt->execute();

    $row = $stmt->fetch();
    return $row ?: null;
}
