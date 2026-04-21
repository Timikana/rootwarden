-- ============================================================
-- Migration 002 - Tables de scan CVE (module OpenCVE)
-- Version : 1.5.0
-- Date    : 2026-03-31
-- Auteur  : RootWarden
-- ============================================================
-- Ajoute les tables nécessaires au module de scan de
-- vulnérabilités CVE via l'API OpenCVE.
--
-- Tables créées :
--   cve_scans    → un enregistrement par scan (résumé statistique)
--   cve_findings → un enregistrement par CVE trouvée lors d'un scan
--
-- Prérequis : migration 001
-- ============================================================

-- Un enregistrement par scan (résumé statistique)
CREATE TABLE IF NOT EXISTS cve_scans (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    machine_id       INT NOT NULL,
    scan_date        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    packages_scanned INT     DEFAULT 0,
    cve_count        INT     DEFAULT 0,
    critical_count   INT     DEFAULT 0,
    high_count       INT     DEFAULT 0,
    medium_count     INT     DEFAULT 0,
    low_count        INT     DEFAULT 0,
    min_cvss         FLOAT   DEFAULT 0,
    status           ENUM('running', 'completed', 'failed') DEFAULT 'running',
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_cve_scans_machine_date (machine_id, scan_date)
);

-- Un enregistrement par CVE trouvée lors d'un scan
CREATE TABLE IF NOT EXISTS cve_findings (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT          NOT NULL,
    machine_id      INT          NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    package_version VARCHAR(255),
    cve_id          VARCHAR(50)  NOT NULL,
    cvss_score      FLOAT        DEFAULT 0,
    severity        ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE') DEFAULT 'NONE',
    summary         TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id)    REFERENCES cve_scans(id)  ON DELETE CASCADE,
    FOREIGN KEY (machine_id) REFERENCES machines(id)   ON DELETE CASCADE,
    INDEX idx_cve_findings_scan     (scan_id),
    INDEX idx_cve_findings_severity (severity),
    INDEX idx_cve_findings_cve_id   (cve_id)
);
