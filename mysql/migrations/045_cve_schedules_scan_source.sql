-- Migration 045 - Ajoute scan_source aux planifications de scan CVE
-- Permet a chaque schedule de choisir entre fast/hybrid/precise (cf v1.20.x).
-- Defaut 'hybrid' pour aligner avec le comportement par defaut de l'UI.

ALTER TABLE cve_scan_schedules ADD COLUMN scan_source VARCHAR(16) NOT NULL DEFAULT 'hybrid' AFTER min_cvss;
