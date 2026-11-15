-- ============================================================
-- Migration 067 - plusieurs cles SSH par compte, chacune avec sa portee
-- ============================================================
-- Un compte n avait qu UNE cle publique (users.ssh_key), deployee sur toutes
-- les machines ou il a acces. Besoin d exploitation : une cle personnelle
-- valable partout, et des cles dediees a UN serveur.
--
-- user_ssh_keys            une ligne par cle
--   toutes_machines = 1    la cle est posee sur toutes les machines du compte
--   toutes_machines = 0    seulement sur celles de user_ssh_key_machines
--
-- La portee ne donne AUCUN acces : une cle n est posee sur une machine que si
-- le compte y a acces (user_machine_access). Elle ne fait que restreindre.
--
-- Reprise : la cle existante de chaque compte devient sa premiere cle, valable
-- sur toutes ses machines. Rien ne change pour un compte existant.
-- users.ssh_key est CONSERVEE pour un retour arriere, mais plus lue ni ecrite
-- par le code (garde dans les tests des deux cotes).

CREATE TABLE IF NOT EXISTS user_ssh_keys (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    user_id          INT          NOT NULL,
    libelle          VARCHAR(100) NOT NULL,
    cle              TEXT         NOT NULL,
    toutes_machines  TINYINT(1)   NOT NULL DEFAULT 1,
    created_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_ssh_keys_user (user_id)
);

CREATE TABLE IF NOT EXISTS user_ssh_key_machines (
    key_id      INT NOT NULL,
    machine_id  INT NOT NULL,
    PRIMARY KEY (key_id, machine_id),
    FOREIGN KEY (key_id)     REFERENCES user_ssh_keys(id) ON DELETE CASCADE,
    FOREIGN KEY (machine_id) REFERENCES machines(id)      ON DELETE CASCADE
);

-- Reprise idempotente : seulement pour un compte qui n a encore aucune cle
INSERT INTO user_ssh_keys (user_id, libelle, cle, toutes_machines, created_at)
SELECT u.id, 'cle principale', TRIM(u.ssh_key), 1, COALESCE(u.ssh_key_updated_at, CURRENT_TIMESTAMP)
FROM users u
WHERE u.ssh_key IS NOT NULL AND TRIM(u.ssh_key) <> ''
  AND NOT EXISTS (SELECT 1 FROM user_ssh_keys k WHERE k.user_id = u.id);
