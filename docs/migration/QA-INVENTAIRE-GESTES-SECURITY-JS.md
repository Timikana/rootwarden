# QA — inventaire des gestes de `legacy/security/js/main.js`, variables internes résolues

**Demandé par le DSI le 2026-09-07**, après qu'une liste transmise se soit révélée tronquée :
son extraction s'arrêtait au `${` et perdait les chemins portant une variable **au milieu**
(`/cve_${endpoint}`).

## Méthode — arbre syntaxique, et résolution par les SITES D'APPEL

Aucun motif textuel. `acorn` parse le fichier ; chaque `fetch()` est relevé, son premier
argument reconstruit (littéral, gabarit, concaténation, ternaire, membre), les constantes du
fichier repliées. **Puis la variable interne est résolue en remontant aux appelants de la
fonction qui la porte.**

    TEMOIN  appels `fetch` trouves        12   (non nul)
            constantes repliees            8

## Les douze appels

    ligne  verbe    chemin reconstruit
       89  POST     ${API_URL}/tickets
      123  GET      ${API_URL}/cve_results?machine_id=${id}
      147  POST     ${API_URL}/cve_reprioritize
      252  POST     ${API_URL}/cve_${endpoint}          <- LA TRONCATURE
      744  GET      ${window.API_URL}/cve_schedules
      839  POST     ${window.API_URL}/cve_schedules
      856  PUT      ${window.API_URL}/cve_schedules/${id}
      866  DELETE   ${window.API_URL}/cve_schedules/${id}
      888  GET      ${window.API_URL}/cron_preview?expr=…
      921  GET      ${window.API_URL}/cve_compare?machine_id=${machineId}
      997  POST     ${window.API_URL}/cve_remediation
     1017  POST     ${window.API_URL}/cve_whitelist

## ⛔ LA VARIABLE RÉSOLUE — et elle contredit ce qu'on en attendait

    fonction   runScan(endpoint, body, machineIds)     ligne 240
    appelants  ligne 178  endpoint = "scan"
               ligne 215  endpoint = "scan"
    valeurs DISTINCTES : "scan"    ->    /cve_scan, et RIEN D'AUTRE

**Ce fichier n'appelle pas `/cve_scan_all`.** La troncature cachait **un** chemin, pas deux.

Et `/cve_scan_all` n'est appelé **de nulle part dans le legacy vivant** : les seules
occurrences sont deux libellés i18n (`health.php`). *Une route backend que plus aucun client
n'atteint — la même famille que `cve_whitelist`, mais du côté serveur.*

## Le croisement complet — 10 couples (chemin, verbe)

| chemin | verbe | réimplémenté en Laravel | passerelle | verdict |
|---|---|---|---|---|
| `/tickets` | POST | non | OUI, **admin seul** | **exception passerelle** — service ITSM externe |
| `/cve_results` | GET | `ScansCve::resultats()` | OUI | **porté** |
| `/cve_reprioritize` | POST | **aucun service** | OUI | **exception passerelle** — service externe |
| `/cve_scan` | POST | non — **atteint PAR la passerelle** | OUI | ⚠ voir ci-dessous |
| `/cve_schedules` | GET·POST | `PlanificationsCve` | OUI | **porté** |
| `/cve_schedules/{id}` | PUT·DELETE | `modifier()`, `supprimer()` | OUI | **porté** |
| `/cron_preview` | GET | `PlanificationsCve::apercu()` | OUI | **porté** |
| `/cve_compare` | GET | `ScansCve::comparaison()` | OUI | **porté, RÉTRÉCI** |
| `/cve_remediation` | POST | `SuiviCve::definirStatut()` | OUI | **porté** |
| `/cve_whitelist` | POST | **aucun service** | OUI | **sans interface** |

    TEMOIN  RoutesBackend::autorisee('/zzz_temoin')  ->  non   (l'instrument discrimine)

**Aucun geste de ce fichier n'est perdu.** Sept sont réimplémentés, deux passent par la
passerelle **par décision** (services externes), un est atteignable sans écran.

## ⚠ `/cve_scan` — LE GESTE QUE LA TRONCATURE CACHAIT, ET IL A UN EFFET SORTANT

    ScanCveController.php:164   'url_scan' => url('/api/gateway/cve_scan')
    public/js/scan-cve.js:488   async function lanceScan(mid)
    public/js/groupes.js:540    « L'action groupee `cve_scan` ENVOIE DE VRAIS COURRIELS
                                  — un par machine »
    backend/routes/cve.py:10    from mail_utils import send_cve_report
    backend/routes/cve.py:76    « Envoyer rapport email via MAIL_TO global (legacy) »

**Le portage l'atteint déjà, par la passerelle, depuis deux écrans.** Ce n'est donc pas une
capacité à porter : elle est en service.

> ⛔ **Et c'est le geste à effet sortant.** Je ne l'ai ni déclenché ni approché : ce document
> est établi **par lecture de code seule, aucune route n'a été appelée.** Le périmètre S7b est
> tenu par l'exploitant, et il ne se délègue pas.

## Ce que cet inventaire n'établit pas

- **La parité de comportement.** « Le même service touche la même table » ne dit pas « il
  calcule la même chose » — `/cve_compare` en est la preuve, trouvée en lisant une signature.
- **Les gardes.** Je relève ce que la passerelle autorise (`autorisee`, `reserveeAdmin`), pas
  ce que chaque route porte comme décorateur côté backend, ni si les deux concordent.
- **Les autres fichiers de `security/`.** L'inventaire porte sur `main.js` seul, parce que
  c'est le fichier qui m'a été donné. *Une troisième méthode reste nécessaire pour les gestes
  construits ailleurs.*
