SELECT 1;

-- Migration 032 : Table bashrc_templates — template editable via UI
-- Remplace la lecture figee du fichier backend/templates/bashrc_standard.sh

CREATE TABLE IF NOT EXISTS bashrc_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE COMMENT 'Identifiant logique (default, ...)',
    content MEDIUMTEXT NOT NULL COMMENT 'Contenu brut du .bashrc a deployer',
    updated_by INT DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_bashrc_template_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Seed initial : ligne 'default' vide (sera remplie au premier chargement par
-- le backend qui lit le fichier de template si la colonne content est vide).
INSERT IGNORE INTO bashrc_templates (name, content) VALUES ('default', '');
