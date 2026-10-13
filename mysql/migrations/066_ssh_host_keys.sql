-- ============================================================
-- Migration 066 - cles d hote SSH memorisees (TOFU)
-- ============================================================
-- Audit du 2026-10-13, H-3
--
-- Le backend se connectait avec paramiko AutoAddPolicy sur neuf sites
-- il acceptait SANS VERIFICATION la cle de n importe quel hote, puis lui
-- envoyait le mot de passe SSH et le mot de passe ROOT
-- Une usurpation ARP sur le LAN, ou la reprise de l IP d une machine
-- retiree, suffisait a recolter les mots de passe root du parc
--
-- Confiance au premier usage
--   premiere connexion   la cle est enregistree ici et acceptee
--   meme cle             acceptee, last_seen mis a jour
--   cle DIFFERENTE       connexion REFUSEE avant toute authentification
--
-- hote vaut le nom que paramiko presente a la politique
--   adresse          pour le port 22
--   [adresse]:port   pour un autre port
-- C est la cle de la table, et non machine_id, parce que les connexions de
-- test se font avant que la machine existe en base

CREATE TABLE IF NOT EXISTS ssh_host_keys (
    hote               VARCHAR(300) NOT NULL,
    key_type           VARCHAR(64)  NOT NULL,
    key_b64            TEXT         NOT NULL,
    fingerprint_sha256 CHAR(64)     NOT NULL,
    first_seen         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (hote)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
