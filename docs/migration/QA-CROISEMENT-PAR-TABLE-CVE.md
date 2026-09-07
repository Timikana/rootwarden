# QA — croisement par TABLE des sept gestes `security/` sans appelant

**Demandé par le DSI le 2026-09-07.** Sa sonde par CHEMIN trouve sept gestes « sans
appelant » ; elle est aveugle **par construction** à une réimplémentation en `DB::table`.
Ce document croise donc par **table**, pas par chemin.

    TEMOIN  tables reelles en base           63   (lues depuis MySQL, pas devinees)
            fonctions Python indexees       546
            fichiers laravel/app lus        101
            routes reperees dans cve.py      18

## ⚠ CE QUE CETTE MÉTHODE NE VOIT PAS — déclaré avant les résultats

**Un geste qui ne touche AUCUNE table lui est invisible**, exactement comme une
réimplémentation est invisible à la méthode par chemin. `/cron_preview` est dans ce cas : il
calcule les prochaines occurrences d'une expression cron, sans base. **Je ne l'ai pas trouvé
par le croisement — je l'ai trouvé en lisant les noms de méthodes.**

*Deux méthodes, deux angles morts complémentaires, et aucune des deux n'est complète seule.*

## Le croisement

| geste backend | tables (chaîne suivie) | service du portage | verdict |
|---|---|---|---|
| `/cron_preview` GET | **aucune** | `PlanificationsCve::apercu()` | **PORTÉ** — hors croisement |
| `/cve_compare` GET | `cve_findings`, `cve_scans` | `ScansCve::comparaison()` | **PORTÉ, mais RÉTRÉCI** ⚠ |
| `/cve_results` GET | `cve_findings`, `cve_scans` | `ScansCve::resultats()`, `findingsPourAffichage()` | **PORTÉ** |
| `/cve_remediation` GET | `cve_remediation`, `machines`, `users` | `SuiviCve::parMachine()` | **PORTÉ** |
| `/cve_remediation` POST | écrit `cve_remediation` | `SuiviCve::definirStatut()` (écrit) | **PORTÉ** |
| `/cve_schedules` GET | `cve_scan_schedules` | `PlanificationsCve::liste()` | **PORTÉ** |
| `/cve_schedules` POST | écrit `cve_scan_schedules` | `creer/modifier/supprimer` (écrit) | **PORTÉ** |
| `/cve_whitelist` GET·POST·DELETE | `cve_whitelist` | **AUCUN** | ⛔ **NON PORTÉ** |

    tables cve_* en base                    5
    tables cve_* touchees par le portage    4
    JAMAIS touchee                          cve_whitelist

**Six gestes sur sept sont réimplémentés en Laravel.** La sonde par chemin avait donc raison
sur la forme (« aucun appelant du backend ») et tort sur la conclusion qu'on en tirerait
(« capacité perdue »).

## ⚠ LA NUANCE QUI COMPTE — `/cve_compare` est porté et RÉTRÉCI

    backend   /cve_compare?machine_id=&scan1=&scan2=
              « Si scan1/scan2 absents, compare les 2 derniers scans. »
    portage   ScansCve::comparaison(int $machineId)
              ->orderByDesc('s.scan_date')->limit(2)
              seul appelant : ComparaisonCveController:52, avec $machineId SEUL

**Le portage ne peut comparer QUE les deux derniers scans.** Choisir deux scans arbitraires —
par exemple « avant/après une campagne de correctifs d'il y a trois mois » — n'existe plus.

*Ce n'est pas un oubli d'implémentation : la signature ne prend pas les paramètres.* Régression
ou simplification assumée est un arbitrage produit, pas une mesure. **Je le qualifie et je le
transmets.**

## ⛔ LE SEUL NON PORTÉ — `/cve_whitelist`, instruit pour l'arbitrage

    GET     /cve_whitelist                      24 lignes  @require_role(2)
    POST    /cve_whitelist                      31 lignes  @require_role(2)   ECRIT (upsert)
    DELETE  /cve_whitelist/<int:whitelist_id>   16 lignes  @require_role(2)   ECRIT

    total 71 lignes, trois routes — la DELETE ne figurait pas dans la liste de sept

    table `cve_whitelist`   id · cve_id · machine_id · reason · whitelisted_by ·
                            expires_at · created_at
    lignes en base          0
    appelant legacy         legacy/security/js/main.js:1017   (la capacite est
                            atteignable dans l'ecran actuel)

**Garde-fous ou commodité ?** — la question du DSI. **Garde-fous, sans ambiguïté** : trois des
sept colonnes n'existent que pour rendre l'oubli impossible — `reason` (pourquoi), 
`whitelisted_by` (qui), `expires_at` (jusqu'à quand). *Une liste blanche sans expiration ni
motif est une dette qui ne se rappelle jamais à personne ; celle-ci est construite pour
expirer et pour nommer son auteur.*

⚠ **Et le fait qui pèse contre** : **zéro ligne en base.** La capacité est atteignable depuis
l'écran du legacy et **personne ne s'en est jamais servi**. *Un garde-fou jamais employé ne
protège de rien — mais il ne coûte rien non plus tant qu'il n'est pas porté.*

**Ce que je ne tranche pas** : garder ou non en v2.0. C'est un arbitrage produit. Ma mesure
dit ce qu'il coûte (71 lignes, une table, trois routes, `role:2`), ce qu'il écrit, et que sa
valeur est structurelle et non pratique.

## Ce que ce document n'établit pas

- **La parité de COMPORTEMENT des six portés.** « Le même service touche la même table » ne
  dit pas qu'il calcule la même chose — `/cve_compare` en est la démonstration, trouvée en
  lisant la signature et non le croisement.
- **Les gardes.** Le backend pose `@require_role(2)` sur la liste blanche ; je n'ai pas
  confronté les gardes des six autres à celles de leurs routes portées.
- **S7b.** Le scan qui aboutit envoie un courriel réel : il n'est ni mesuré ni approché ici.
