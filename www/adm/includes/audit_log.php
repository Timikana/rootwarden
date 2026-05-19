<?php
/**
 * audit_log.php - Fonction centralisée de logging des actions admin.
 *
 * Insère une entrée dans la table user_logs avec l'IP et les détails.
 * À appeler après chaque action sensible.
 *
 * Hash chain (migration 036) :
 *   Chaque ligne inclut prev_hash + self_hash = SHA2-256(prev_hash | user_id | action | unix_ts).
 *   audit_log() calcule et renseigne les deux colonnes atomiquement
 *   (SELECT derniere self_hash FOR UPDATE puis INSERT dans la meme transaction).
 *   Les INSERTs legacy qui n'utilisent pas ce helper laissent self_hash NULL -
 *   /adm/api/audit_seal.php les seale en arriere-plan.
 */

/** Valeur initiale de prev_hash quand user_logs est vide. */
if (!defined('AUDIT_LOG_GENESIS')) {
    define('AUDIT_LOG_GENESIS', 'GENESIS');
}

/**
 * Calcule le self_hash HMAC-SHA256 d'une ligne user_logs.
 * IMPORTANT : la formule doit matcher /adm/api/audit_verify.php et audit_seal.php.
 *
 * Patch A08-02 (OWASP A08) : passage de SHA2-256 simple a HMAC-SHA256 avec
 * cle secrete dediee (AUDIT_HMAC_KEY) distincte de SECRET_KEY. Avant : un
 * attaquant connaissant le format (lisible dans le code) pouvait recalculer
 * la chaine apres modification d'une ligne via UPDATE direct (SQLi, vol
 * de credentials DBA). Maintenant : sans la cle dediee, impossible de
 * forger un hash valide -> tamper-evidence renforcee.
 *
 * La cle vient de AUDIT_HMAC_KEY (env var) ou tombe sur SECRET_KEY (fallback
 * pour la migration progressive). Idealement la cle est stockee hors BDD
 * (variable d'env Docker, secret manager) pour qu'un attaquant qui dump la
 * DB n'ait pas la cle qui signe les lignes.
 */
function audit_log_compute_hash(string $prevHash, int $userId, string $action, int $unixTs): string {
    static $hmacKey = null;
    static $warned  = false;
    if ($hmacKey === null) {
        $dedicated = (string)(getenv('AUDIT_HMAC_KEY') ?: '');
        if ($dedicated !== '') {
            $hmacKey = $dedicated;
        } else {
            // Fallback : SECRET_KEY puis default. Emet un warning une fois par
            // process pour signaler que la separation de cle n'est PAS active.
            if (!$warned) {
                error_log(
                    "[RootWarden] AUDIT_HMAC_KEY non configure - fallback sur SECRET_KEY. "
                    . "La tamper-evidence est affaiblie : configurez AUDIT_HMAC_KEY (openssl rand -hex 32) "
                    . "dans srv-docker.env pour separer la cle de signature de la cle de chiffrement."
                );
                $warned = true;
            }
            $hmacKey = (string)(getenv('SECRET_KEY') ?: 'rootwarden-audit-default');
        }
    }
    return hash_hmac('sha256', implode('|', [$prevHash, (string)$userId, $action, (string)$unixTs]), $hmacKey);
}

/**
 * Verifie un self_hash existant en acceptant le format legacy (SHA2-256 simple)
 * ou le nouveau format HMAC-SHA256. Necessaire pour la retrocompatibilite des
 * lignes scellees AVANT le patch A08-02 : sans ce double-check, audit_verify
 * marquerait toutes les anciennes lignes comme "tampered" alors qu'elles sont
 * juste signees avec l'ancien algorithme.
 *
 * Apres migration des donnees historiques (re-seal), ce fallback pourra etre
 * supprime.
 */
function audit_log_verify_hash(string $stored, string $prevHash, int $userId, string $action, int $unixTs): bool {
    $hmac = audit_log_compute_hash($prevHash, $userId, $action, $unixTs);
    if (hash_equals($stored, $hmac)) return true;
    // Fallback legacy : SHA2-256 sans HMAC (pre-A08-02)
    $legacy = hash('sha256', implode('|', [$prevHash, (string)$userId, $action, (string)$unixTs]));
    return hash_equals($stored, $legacy);
}

/**
 * @param PDO    $pdo    Connexion PDO
 * @param string $action Description de l'action (ex: "Création utilisateur marie.test")
 * @param int|null $targetId ID de l'objet cible (user_id, machine_id, null)
 * @param string $details Détails supplémentaires (optionnel)
 */
function audit_log(PDO $pdo, string $action, ?int $targetId = null, string $details = ''): void {
    $userId = (int)($_SESSION['user_id'] ?? 0);
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // Enrichir l'action avec le contexte (targetId, IP, details)
    $fullAction = $action;
    if ($targetId !== null) $fullAction .= " [cible=#$targetId]";
    if ($details) $fullAction .= " - $details";
    $fullAction .= " (IP: $ip)";
    $fullAction = substr($fullAction, 0, 255);

    audit_log_raw($pdo, $userId, $fullAction);
}

/**
 * Version bas-niveau : ecrit une ligne user_logs scellee avec hash chaine.
 * Utilisee par audit_log() + par les call sites qui precisent user_id manuellement
 * (login.php, unlock_user.php, etc.).
 */
function audit_log_raw(PDO $pdo, int $userId, string $action): void {
    $action = substr($action, 0, 255);
    try {
        $pdo->beginTransaction();
        $prevStmt = $pdo->query(
            "SELECT self_hash FROM user_logs
             WHERE self_hash IS NOT NULL
             ORDER BY id DESC LIMIT 1
             FOR UPDATE"
        );
        $prevHash = (string)($prevStmt->fetchColumn() ?: AUDIT_LOG_GENESIS);
        $unixTs = time();
        $selfHash = audit_log_compute_hash($prevHash, $userId, $action, $unixTs);
        $stmt = $pdo->prepare(
            "INSERT INTO user_logs (user_id, action, created_at, prev_hash, self_hash)
             VALUES (?, ?, FROM_UNIXTIME(?), ?, ?)"
        );
        $stmt->execute([$userId, $action, $unixTs, $prevHash, $selfHash]);
        $pdo->commit();
    } catch (\Exception $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        error_log("audit_log_raw failed: " . $e->getMessage());
    }
}
