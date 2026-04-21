---
type: vision
layer: L0
tags: [vision, stack]
last_reviewed: 2026-04-21
status: stable
---

# Stack technique

| Composant | Techno | Source |
|---|---|---|
| Frontend | PHP 8.4 + Apache (TLS) | [[04_Fichiers/docker/php-Dockerfile]] |
| CSS | Tailwind compilé localement (pas de CDN) | [[04_Fichiers/frontend-tailwind-config]] |
| JS | vanilla + htmx 2.0.4 | [[11_Glossaire/htmx]] |
| Backend API | Python 3.13 / Flask / Hypercorn ASGI | [[04_Fichiers/backend-server]] · [[04_Fichiers/backend-hypercorn_config]] |
| DB | MySQL 9.2 (réseau interne) | [[01_Architecture/network-zero-trust]] |
| Chiffrement | libsodium (PyNaCl) + AES-256-CBC | [[04_Fichiers/backend-encryption]] · [[06_Securite/hkdf]] |
| i18n | 1424 clés FR/EN × 19 modules | [[04_Fichiers/www-includes-lang]] |
| Tests backend | pytest (139 tests) + ruff | [[07_CI-CD/job-test-python]] |
| Tests E2E | Puppeteer | [[09_Tests/_MOC]] |
| CI/CD | GitHub Actions (11 jobs) | [[07_CI-CD/workflow-ci]] |
| Orchestration | Docker Compose | [[04_Fichiers/docker-compose]] |
| SMTP | STARTTLS / SSL direct | [[04_Fichiers/backend-mail_utils]] |
| CVE DB | OpenCVE cloud ou on-prem v2 | [[02_Domaines/cve]] |

## Voir aussi

- [[00_Vision/README]] · [[01_Architecture/containers-docker]] · [[01_Architecture/_MOC]]
