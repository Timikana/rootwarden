SELECT 1;

CREATE TABLE IF NOT EXISTS supervision_agents (
    machine_id INT NOT NULL,
    platform ENUM('zabbix','centreon','prometheus','telegraf') NOT NULL,
    agent_version VARCHAR(50) DEFAULT NULL,
    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    config_deployed BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (machine_id, platform),
    CONSTRAINT fk_supagent_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);

INSERT IGNORE INTO supervision_agents (machine_id, platform, agent_version)
SELECT id, 'zabbix', zabbix_agent_version FROM machines WHERE zabbix_agent_version IS NOT NULL AND zabbix_agent_version != '';
