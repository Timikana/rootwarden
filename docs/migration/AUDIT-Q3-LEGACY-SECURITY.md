# AUDIT — Q3 sur `legacy/security/` : relevé par GESTE

**Session 5 (sécurité, lecture seule).** Relevé du **2026-09-05, 11:42 CEST**.
Aucun geste exercé, aucune machine jointe, aucun scan déclenché — *c'est le
module dont le scan abouti envoie un vrai courriel.*

**Résultat : 2 fichiers sur 3 sont archivables. Le troisième ne l'est pas, et son
bloquant est un arbitrage ouvert — comme `legacy/iptables/index.php`.**

---

## 1. ⚠ Le piège du chemin composé était LIVE dans ce module

`legacy/security/js/main.js:252` :

```js
const resp = await fetch(`${API_URL}/cve_${endpoint}`, { method: 'POST', … });
```

**Le nom du point d'entrée est une VARIABLE.** Un motif littéral sur `/cve_scan`
rend **zéro** alors que la capacité est entièrement présente. *C'est exactement
l'avertissement du DSI, et il portait.*

**Résolu à la main** : `runScan()` n'est appelé que **deux fois**, aux lignes 178
et 215, **toutes deux avec `'scan'`**. Le chemin composé vaut donc **`/cve_scan`
et rien d'autre** — jamais `/cve_scan_all`.

*Défaut de documentation relevé au passage : la docstring annonce
`@param endpoint - Chemin de l'endpoint (ex. '/cve_scan')`. Avec cette valeur la
composition donnerait `/cve_/cve_scan`. **La docstring décrit une forme que le
code ne peut pas recevoir.***

---

## 2. Le relevé, par geste

### 2.1 `cve_export.php` — **ARCHIVABLE**

| geste | verdict | artefact |
|---|---|---|
| export CSV d'un scan (`fputcsv`, `Content-Disposition`) | **PORTÉ** | route `/export-cve` (S1) |

*Un seul geste, aucune écriture de table, garde `can_scan_cve`.*

### 2.2 `compliance_report.php` — **ARCHIVABLE**

| geste | verdict | artefact |
|---|---|---|
| rapport de conformité à l'écran | **PORTÉ** | `/rapport-conformite` (S2a) |
| export CSV | **PORTÉ** | `/rapport-conformite/csv` (S2c) |
| export PDF | **PORTÉ** | `/rapport-conformite/pdf` (S2b) |

*Aucune écriture de table. Garde `can_view_compliance` — la seule des trois.*

### 2.3 `index.php` — **NON ARCHIVABLE**

**Le fichier ne porte AUCUN geste serveur** : ni `$_POST`, ni `switch`, ni
écriture SQL, ni en-tête d'export. *Tout passe par son JS.* **Un relevé par
fichier l'aurait déclaré vide.**

| geste (appelé par `main.js`) | verdict | artefact |
|---|---|---|
| `/cve_results` | **PORTÉ** | `/scan-cve` (S3) |
| `/cve_compare` | **PORTÉ** | `/scan-cve/comparaison` |
| `/cve_schedules` GET·POST·PUT·DELETE | **PORTÉ** | `/scan-cve/planifications` ×2 (S4) |
| `/cron_preview` | **PORTÉ** | `/scan-cve/apercu-cron` |
| `/cve_remediation` | **PORTÉ** | `/scan-cve/suivi` ×2 — `SuiviCveController` |
| `/cve_reprioritize` | **PORTÉ** | appelé par `scan-cve.js` (passerelle, service EXTERNE) |
| `/tickets` | **PORTÉ** | passerelle, service EXTERNE |
| **`/cve_scan`** *(chemin composé)* | **NON PORTÉ** | **S7b — bloqué par l'arbitrage : le scan abouti envoie un vrai courriel** |
| **`/cve_whitelist`** | **NON PORTÉ** | *délibéré — table sans lecteur côté portage* |

**Vérifié plutôt que remémoré** : les seules occurrences de `whitelist` dans le
portage appartiennent à **`fail2ban`**, module distinct. *La liste blanche CVE
n'a aucun artefact.*

**Et le portage fait PLUS que le legacy sur un point** : `SuiviCve` note que le
JS du legacy *« ne fait AUCUN `GET /cve_remediation` »* — la capacité existait au
backend sans être lue par la page qu'elle sert.

---

## 3. Réponse à Q3

**`cve_export.php` et `compliance_report.php` : le legacy n'est plus le seul
accès.** Ils peuvent partir.

**`index.php` : il l'est, pour DEUX gestes.**

> **Et les deux bloquants sont de natures différentes** — c'est ce qui manquait à
> un verdict par fichier :
>
> - **`/cve_scan`** est retenu par un **arbitrage ouvert** (l'effet sortant). *Il
>   se débloque par une décision.*
> - **`/cve_whitelist`** est **non porté par choix assumé** (une table que
>   personne ne lit). *Il se débloque par un portage — ou par la décision
>   explicite de perdre la capacité.*

**Le second est le plus discret** : rien ne le signale, aucune page ne le
réclame, et il ne produit aucun événement. *S'il part sans décision, la capacité
disparaît sans que personne ne l'ait tranché — et c'est la forme que ce chantier
paie le plus cher.*

---

## 4. Non mesuré, et dit

- **je n'ai ouvert aucune page au navigateur** et **déclenché aucun scan** —
  interdit du chantier, et c'est le module concerné ;
- je n'ai pas vérifié que `compliance_report.php` n'a **aucun** geste au-delà des
  trois relevés : le fichier fait 36 Ko et mon relevé porte sur les motifs
  d'export et d'écriture SQL. *Ce qui me réfuterait : un geste construit
  autrement — un `header()` calculé, ou un appel backend depuis un JS que je n'ai
  pas ouvert.* **`compliance_report.php` n'a pas de JS dédié ; `index.php` seul
  en a un.**
