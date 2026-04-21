SELECT 1;

-- Migration 039 : Profils de supervision (catalogue metadata + overrides pre-configures)
--
-- Objectif : eviter la saisie libre de HostMetadata/Server/ServerActive par machine.
-- Un admin cree un catalogue (LinuxInterne / LinuxExterne / WinInterne...) une fois,
-- les autres admins assignent chaque serveur au profil correspondant.
-- L'auto-registration cote Zabbix matche le HostMetadata du profil via regex.

CREATE TABLE IF NOT EXISTS supervision_metadata_profiles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    platform VARCHAR(32) NOT NULL DEFAULT 'zabbix',
    name VARCHAR(100) NOT NULL,
    description VARCHAR(255) DEFAULT NULL,
    host_metadata VARCHAR(255) DEFAULT NULL COMMENT 'Valeur poussee comme HostMetadata agent. Matche par regex cote Zabbix auto-registration.',
    zabbix_server VARCHAR(255) DEFAULT NULL COMMENT 'Override Server= (vide = config globale).',
    zabbix_server_active VARCHAR(255) DEFAULT NULL COMMENT 'Override ServerActive= (vide = config globale).',
    zabbix_proxy VARCHAR(255) DEFAULT NULL COMMENT 'Nom/IP du proxy Zabbix (informatif pour la doc, non injecte tel quel).',
    listen_port INT DEFAULT NULL,
    tls_connect VARCHAR(32) DEFAULT NULL,
    tls_accept VARCHAR(32) DEFAULT NULL,
    notes TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_platform_name (platform, name)
);

CREATE TABLE IF NOT EXISTS machine_supervision_profile (
    machine_id INT NOT NULL,
    platform VARCHAR(32) NOT NULL DEFAULT 'zabbix',
    profile_id INT NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (machine_id, platform),
    CONSTRAINT fk_msp_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    CONSTRAINT fk_msp_profile FOREIGN KEY (profile_id) REFERENCES supervision_metadata_profiles(id) ON DELETE CASCADE,
    INDEX idx_msp_profile (profile_id)
);

-- Seed : 2 profils Linux par defaut. L'admin les edite pour coller a son infra.
INSERT IGNORE INTO supervision_metadata_profiles
    (platform, name, description, host_metadata, notes)
VALUES
    ('zabbix', 'LinuxInterne',
     'Serveurs Linux en reseau interne, contact direct avec le serveur Zabbix.',
     'LinuxInterne',
     'Edite zabbix_server et zabbix_server_active pour pointer vers ton serveur Zabbix principal. Cote Zabbix, cree une action auto-registration avec la regex "^LinuxInterne$" sur Host metadata pour assigner templates + host groups automatiquement.'),
    ('zabbix', 'LinuxExterne',
     'Serveurs Linux en reseau externe, passant par un proxy Zabbix.',
     'LinuxExterne',
     'Renseigne zabbix_proxy avec l IP/hostname du zabbix-proxy. Server et ServerActive doivent pointer sur le proxy, pas le serveur principal. Cote Zabbix, cree une action auto-registration "^LinuxExterne$" qui force le host sur le proxy.');
