-- ============================================================
-- Migration 057 - Workflow d'approbation 4-eyes (double validation)
-- Version : 1.30.0
-- ============================================================
-- Les actions les plus destructives (suppression d'utilisateur distant, reboot,
-- revocation de compte de service...) peuvent exiger l'approbation d'un SECOND
-- administrateur avant execution. Une demande est creee a la 1re tentative ;
-- une fois approuvee par un autre admin, le demandeur peut rejouer l'action.
--
-- status : pending puis approved/rejected, enfin executed quand l'action passe.
-- target : identifiant lisible de la cible (username, 'reboot'...) pour le
--          rapprochement demande <-> nouvelle tentative.
--
-- Idempotent : CREATE TABLE IF NOT EXISTS. Pas de point-virgule en commentaire.
-- ============================================================
SELECT 1;

CREATE TABLE IF NOT EXISTS approval_requests (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    action_type     VARCHAR(64) NOT NULL,
    machine_id      INT NULL,
    target          VARCHAR(255) NOT NULL DEFAULT '',
    payload         JSON NULL,
    status          ENUM('pending','approved','rejected','executed','expired') NOT NULL DEFAULT 'pending',
    requested_by    INT NULL,
    approved_by     INT NULL,
    decision_reason VARCHAR(500) NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at      TIMESTAMP NULL,
    expires_at      TIMESTAMP NULL,
    FOREIGN KEY (machine_id)   REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (requested_by) REFERENCES users(id)    ON DELETE SET NULL,
    FOREIGN KEY (approved_by)  REFERENCES users(id)    ON DELETE SET NULL,
    INDEX idx_approval_status (status),
    INDEX idx_approval_match (action_type, machine_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
