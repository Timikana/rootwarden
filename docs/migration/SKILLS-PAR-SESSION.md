# Skills disponibles, et laquelle sert quelle session

Rapatriement du **2026-08-27**. Douze collections tierces + six skills propres au projet.
**1 149 `SKILL.md`** au total. Ce document existe parce qu'une collection de skills qu'on ne sait pas
adresser ne sert à rien : 846 skills dans un seul dossier ne se découvrent pas au hasard.

Les collections tierces sont **ignorées par git** (`.gitignore:72` — `.claude/skills/*` sauf `rw-*`).
Seules les six `rw-*` sont versionnées avec le dépôt.

---

## 1. Ce que le rapatriement a changé

| | avant | après |
|---|---|---|
| collections | 10 (+2 locales) | **12** (+2 locales) |
| `SKILL.md` découvrables | 776 | **1 149** |
| collections à jour | **0 sur 10** | **12 sur 12** |

Les dix collections existantes étaient **toutes périmées**, certaines de quatre mois :
`alirezarezvani` avait **1 484 commits de retard**, `awesome-toolkit` 577, `pentest` 142.

### Pourquoi elles ne se mettaient plus à jour — et ce n'était pas un oubli

Tous les `git pull` échouaient sur des « modifications locales » : **1 947 fichiers modifiés** dans une
collection, 677 dans une autre, et **zéro fichier non suivi**.

Ce n'étaient pas des modifications humaines. Mesuré : les fichiers sur disque portaient des fins de
ligne **CRLF** quand le dépôt porte des **LF** — l'arbre entier avait été écrit depuis un hôte Windows.
S'y ajoutaient quelques translittérations de caractères (tirets cadratins `—` devenus `-`).

Rien de valeur n'a donc été écrasé. La vérification qui l'a établi : `file -b` sur un fichier
(« ASCII text, with CRLF line terminators »), `grep -c $'\r'` sur le disque contre `git show HEAD:`,
et **zéro fichier non suivi** dans les douze collections.

`pentest` était un cas à part : son amont avait **réécrit son histoire**, laissant en local un
`Merge pull request #15` que l'amont ne connaît plus. Ce n'était pas notre commit — aligné sur l'amont.

### Neuf skills étaient INVISIBLES, et c'est la trouvaille la plus utile

`cybersecurity` et une skill de `nobrainer` nomment leur fichier **`skill.md` en minuscules**. Sur un
système de fichiers sensible à la casse, la découverte ne les voit pas — **huit skills de sécurité
inutilisables**, alors que leur frontmatter est valide.

Réparé par lien symbolique `SKILL.md → skill.md`, ce qui survit à un `git pull` et reste réversible.

---

## 2. Les six skills du projet — à lire, pas seulement à invoquer

Elles sont versionnées avec le dépôt et portent ce qu'aucune skill tierce ne peut savoir.

| skill | ce qu'elle porte |
|---|---|
| `rw-laravel` | le portage : schéma partagé **sans migrations Laravel**, pilotes `file`/`sync`, `env()` hors `config/` qui rend `null`, navigation à source unique, passerelle et comparaison **par segment** |
| `rw-e2e` | le harnais des suites : connexion + TOTP, double cible, scripts auto-validants, nettoyage borné |
| `rw-lot` | les **six préalables** du rejeu, dont le relais `sudo docker`, le profil `preprod`, et l'attente du basculement TOTP |
| `rw-pre-commit` | la checklist obligatoire : version, CHANGELOG, parité FR/EN, OWASP |
| `rw-pieges` | le catalogue des pièges du dépôt : écho PTY, sudoers, ordonnanceur, migrations |
| `rw-inventaire` | le gabarit pour inventorier un module **avant** de le porter |

---

## 3. Cartographie par session

### SESSION 1 — LEAD
| skill | où |
|---|---|
| `rw-lot`, `rw-pre-commit`, `rw-pieges`, `rw-inventaire` | projet |
| `skill-creator` | `anthropic-officiel/skills/` — pour écrire une skill projet neuve |
| `nobrainer-team-builder` | `nobrainer/` — orchestration multi-agents |

### SESSION 2 — ANALYSTE LEGACY
| skill | où |
|---|---|
| `rw-inventaire`, `rw-pieges` | projet |
| `deep-audit`, `deep-rca` | `nobrainer/` |
| `legacy-modernizer` | `jeffallan/skills/` |
| `php-modernization` | `php-modern/` |

### SESSION 3 — BACKEND LARAVEL
| skill | où |
|---|---|
| `rw-laravel`, `rw-pre-commit`, `rw-pieges` | projet |
| **`laravel-specialist`** | `jeffallan/skills/` |
| `php-modernization` | `php-modern/` |
| `frontend-design` | `anthropic-officiel/skills/` |

### SESSION 4 — BASE & PERFORMANCE
| skill | où |
|---|---|
| **`database-optimizer`** | `jeffallan/skills/` |
| `database-optimization`, `perf-profiler`, `database-optimizer` | `awesome-toolkit/skills/` et `/plugins/` |
| `database-schema-designer`, `performance-profiler` | `alirezarezvani/engineering/` |

### SESSION 5 — SÉCURITÉ
| skill | où |
|---|---|
| **83 skills Trail of Bits** — CodeQL, Semgrep, analyse de variantes, audit de code | `trailofbits/` |
| **8 skills cybersécurité** — `secure-code-review`, `threat-modeling`, `vulnerability-triage`, `web-hacking`, `pentest-recon`, `poc-development`, `security-hardening`, `ctf-solver` | `cybersecurity/` — **rendues découvrables par ce rapatriement** |
| 50 skills pentest | `pentest/` |
| OWASP 2025-2026 | `owasp/` |

### SESSION 6 — QA & NON-RÉGRESSION
| skill | où |
|---|---|
| `rw-pre-commit`, `rw-pieges` | projet |
| **`webapp-testing`** (officielle Anthropic) | `anthropic-officiel/skills/` |
| `deep-test`, `test-stack` | `custom/` |
| `qa-expert`, `test-automator` | `jeffallan/skills/` |

### SESSION 7 — NAVIGATEUR & E2E
| skill | où |
|---|---|
| **`rw-e2e`, `rw-lot`** — d'abord, ils portent le harnais réel | projet |
| **`webapp-testing`** (officielle) — Playwright, captures, journaux navigateur | `anthropic-officiel/skills/` |
| **`playwright-skill`** v5 — scripts réutilisables, responsive, parcours de connexion | `playwright/skills/` |
| `playwright-expert` | `jeffallan/skills/` |
| `playwright-pro` | `alirezarezvani/engineering-team/` |
| `agent-browser` | `nobrainer/` |

**⚠ Pour la session 7 :** ces skills Playwright servent le travail **NEUF** (`tests/pw/`). Le LOT
existant est en **Puppeteer 23** — 103 suites, 40 898 lignes, harnais maison, doubles cibles,
77 références comptées à la main. **Ne pas le migrer** : ce serait plus gros que la migration restante.
`rw-e2e` et `rw-lot` restent la référence pour tout ce qui touche au LOT.

---

## 4. Comment maintenir

    cd .claude/skills
    for n in */; do [ -d "${n}.git" ] && git -C "${n%/}" fetch --quiet \
      && echo "${n%/} : $(git -C "${n%/}" rev-list --count HEAD..@{u}) de retard"; done

Deux pièges appris en le faisant :

- **comparer des hashes COURTS induit en erreur** — `f567c61` contre `f567c61d` est le même commit vu
  sur 7 puis 8 caractères, et un test naïf l'avait déclaré « mis à jour ». Comparer
  `rev-list --count HEAD..@{u}`, pas des chaînes ;
- **un `pull` qui affiche « Mise à jour X..Y » n'a pas forcément abouti** : c'est la ligne que git
  imprime *avant* d'appliquer. Vérifier le retard **après**, jamais le message.
