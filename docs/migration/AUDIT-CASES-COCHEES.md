# AUDIT — la chasse aux « cases cochées » : la méthode, son témoin, et son angle mort

**Session 5 (sécurité, lecture seule).** Relevé du **2026-09-05, 23:46 CEST**.
`docs/` seul, fenêtre 3 du LOT.

**Je ne publie PAS de compte de trous.** *Ma méthode en rend 53 ; elle en
sur-déclare une majorité, et je peux dire pourquoi.* **Ce que je livre : la
réponse de PROVENANCE, une méthode qui passe son témoin, et son angle mort
mesuré.**

---

## 1. ⚠ LA PROVENANCE — et elle explique le mécanisme, pas seulement les cas

Le DSI demande de poser la question de la **fabrication** avant celle du contenu.
**Elle se lit dans le format même des déclarations :**

```
I1 PORTÉ `3c3fe98`  — la consultation        F1 PORTÉ `v1.38.0`
I2 PORTÉ `f183f07`  — la copie en base       F2 PORTÉ `v1.38.2`
I3 PORTÉ `ef32870`  — l'historique           B3 PORTÉS  `v1.…`
I4 PORTÉ `c42fe48`  — la validation à blanc  G1 PORTÉ   `v1.…`
```

**Chaque déclaration cite un COMMIT ou une VERSION.** *Elle enregistre qu'un
commit a atterri — **pas** qu'un périmètre est complet.*

> **Le périmètre d'un sous-lot vit AILLEURS que sa déclaration de portage** : il
> est défini dans le découpage du module, souvent des jours plus tôt, par une
> autre session. **Et rien ne confronte les deux à la livraison.**

### 1.1 J'en ai la preuve de première main, et elle me met en cause

**C'est moi qui ai écrit le découpage A1–A4 de `ssh_audit`** — et mon §5 range
`/trends` **dans le périmètre d'A1**. A1 a ensuite été déclaré porté, en citant
un commit. **`/ssh-audit/trends` n'a jamais été câblé.**

> **Le trou est dans un sous-lot dont j'ai défini le périmètre, déclaré porté par
> quelqu'un qui citait un commit — et personne n'a repris ma liste item par item
> au moment de livrer.** *Ce n'est pas une négligence : c'est qu'aucun geste du
> processus ne le demande.*

**Prédiction que ça permet** : les trous ne sont pas répartis au hasard. **Ils
sont là où un découpage a énoncé un périmètre ET où un commit ultérieur a déclaré
le lot porté.** *Les modules sans découpage écrit n'ont pas ce mécanisme — ils en
ont d'autres.*

---

## 2. La méthode, et elle passe son témoin

**Pour chaque route du backend, existe-t-il un appelant dans le portage ?**
Commentaires retirés (JS, Blade), aucune troncature, chemins composés rattrapés
par préfixe.

```
routes backend                       203
fragments d'appel relevés            262
routes SANS appelant                  53
```

**Témoin positif, posé AVANT de conclure** — les deux trous connus :

| témoin | résultat |
|---|---|
| `/ssh-audit/backups` | **TROUVÉ** |
| `/ssh-audit/trends` | **TROUVÉ** |

*Sans eux, « 53 » aurait pu être « ma sonde ne lit pas les appels ».*

---

## 3. ⛔ ET SON ANGLE MORT — mesuré, ce qui m'interdit de publier 53

**Ma méthode ne détecte qu'UNE des cinq formes** : *« le portage APPELLE la route
backend »*. **Elle est aveugle à la forme n°4 — le portage RÉIMPLÉMENTE la
capacité en Laravel.**

**Mesuré sur `cve` :**

```
laravel/app/Services/PlanificationsCve.php   DB::table × 7   passerelle × 0
laravel/app/Services/ScansCve.php            DB::table × 6   passerelle × 2
laravel/app/Services/SuiviCve.php            DB::table × 5   passerelle × 2
```

**Le portage lit la base directement.** *Les 14 routes `/cve_*` sans appelant ne
sont donc pas des trous : la capacité est portée par une autre couche.*

> **Publier « 53 trous » serait l'erreur du côté qui ALARME**, celle que ce
> chantier corrige depuis deux jours. **Ce sont 53 CANDIDATS**, et ils tombent
> dans **quatre** catégories que la méthode ne distingue pas :

| catégorie | exemples | ce que ça demande |
|---|---|---|
| **réimplémenté en Laravel** (forme 4) | les 14 `/cve_*` | **rien** — faux positif de ma sonde |
| **retenu par arbitrage** | `/iptables-apply|restore|rollback` (I5) · `/ssh-audit/fix|reload|restore|save-config|toggle` (A3) · `/ssh-audit/scan-all` · `/cve_scan*` | **décider** |
| **orphelin par dépréciation** | `/policy/rollback|deployments|list` | **arbitrer ce qu'on garde** |
| **trou dans un sous-lot déclaré complet** | `/ssh-audit/backups` (A2) · `/ssh-audit/trends` (A1) | **finir, et corriger la déclaration** |

**Seule la quatrième est une « case cochée ».** *Et je n'en ai confirmé que deux
— les deux que le DSI m'a données comme témoins.*

---

## 4. Ce qu'il faudrait pour rendre un compte honnête

**Trier les 53 route par route** exige, pour chacune : *le portage
réimplémente-t-il la capacité ailleurs ?* — **et c'est de la lecture, pas du
motif.** *Ma sonde peut réduire l'espace de 203 à 53 ; elle ne peut pas trancher
les 53.*

**Ce qui rendrait la méthode complète** : détecter la forme 4 en croisant les
**tables** écrites/lues, et non les chemins. *Une capacité réimplémentée touche
la même table que la route qu'elle remplace.* **Non fait — et c'est un vrai
travail, pas un ajustement.**

---

## 5. Non mesuré, et dit

- **je n'ai pas trié les 53** : je livre la méthode, son témoin, son angle mort
  et la ventilation en quatre catégories — *pas un verdict par route* ;
- **la ventilation ci-dessus est fondée sur mes relevés antérieurs** (`iptables`,
  `security`, `ssh_audit`, `politiques`), pas sur une mesure neuve des 53. *Les
  catégories des modules que je n'ai pas audités — `admin`, `updates`, `ssh`,
  `monitoring` — sont **non tranchées**, et ce sont 23 des 53.*
- **aucune écriture hors `docs/`, aucun geste exercé.**

---

## 6. LES 23 NON TRANCHÉES — reprises le 2026-09-06, 00:44 CEST

**Résultat partiel et dit comme tel : 4 classées sur 22 distinctes, dont une
CINQUIÈME catégorie que la taxonomie ne portait pas.**

### 6.1 ⚠ Ma première sonde sur-matchait à l'échelle — corrigée par ancrage

Mon relevé initial cherchait les chemins **sans délimiteur** :

```
/test                    101 « occurrences »   <- « test » est partout
/deploy                   27
/list_machines            17
```

**Le piège de la sous-chaîne, à l'échelle.** *Chercher `/test` attrape `latest`,
`tests`, `test-server`…*

**Ancré** — le chemin doit être délimité par un guillemet, une parenthèse, une
espace ou une fin :

```
motif = ['"`( ] + chemin + (['"`)? ,]|$)
```

**Témoins de l'ancrage, posés avant de relire les chiffres :**

| témoin | attendu | obtenu |
|---|---|---|
| `/test` | doit **chuter** | **101 → 6** |
| `/server_users_inventory` | doit **rester à 0** | **0** |

*Les deux se comportent comme prévu — un témoin qui ne bouge pas et un qui
s'effondre qualifient l'ancrage mieux qu'un seul.*

### 6.2 Ce qui est classé

| route | verdict | fondement |
|---|---|---|
| `/admin/temp_permissions` ×2 | **FAUX POSITIF — forme 4** | `Services/Permissions.php` fait `DB::table('temporary_permissions')` ×3. *Le portage réimplémente en Laravel.* |
| `/cve_trends` | **trou connu**, promis par `openapi.yaml` | déjà relevé |
| `/server_users_inventory` | **⚠ JAMAIS CÂBLÉE** | n'apparaît que dans sa propre définition, la liste blanche, et **7 documents** |
| `/admin/notification_prefs` | **⚠ JAMAIS CÂBLÉE** | n'apparaît que dans sa définition et **5 documents** — dont `DOSSIER-21-LISTE-BLANCHE-ORPHELINE.md`, qui la nommait déjà |

### 6.3 ⚠ UNE CINQUIÈME CATÉGORIE : *jamais câblée*

**Ces deux routes n'ont d'appelant NULLE PART** — ni portage, ni legacy vivant,
ni `_deprecated/`, ni `tests/`. **Elles n'apparaissent que dans leur propre
définition et dans de la documentation.**

> **Ce n'est aucune des quatre.** Pas *orpheline par dépréciation* — **rien n'a
> jamais été déprécié, parce que rien n'a jamais été construit dessus.** Pas
> *retenue par arbitrage* — aucune décision ne la concerne. Pas un *trou dans un
> sous-lot déclaré complet* — aucun sous-lot ne l'a revendiquée. Pas un *témoin
> disparu* — aucune suite n'en dépend.
>
> **Elles ont été écrites, gardées, mises en liste blanche, documentées — et
> jamais appelées par personne.**

| mécanisme | trace laissée | remède |
|---|---|---|
| dépréciation | un `_deprecated/` | arbitrer ce qu'on garde |
| arbitrage | un dossier ouvert | décider |
| sous-lot déclaré complet | **une case cochée** | finir, et corriger la déclaration |
| témoin disparu | **une suite rouge sur un objet sain** | réoutiller |
| **jamais câblée** | **de la DOCUMENTATION, et rien d'autre** | **décider si on la garde ou on la retire** |

**La trace de la cinquième est la plus trompeuse des cinq** : *elle est
abondante, elle est écrite, elle est exacte* — **et elle décrit une capacité que
personne n'a jamais pu employer.** *Sept documents parlent de
`/server_users_inventory`. Aucun code ne l'appelle.*

### 6.4 Ce qui reste NON TRANCHÉ — 17 sur 22, et je ne le devine pas

`/apt_check_lock` · `/apt_update` · `/custom_update` · `/deploy` ·
`/exclude_user` · `/list_machines` · `/logs` · `/preflight_check` ·
`/schedule_update` · `/server_lifecycle` · `/server_user_keys` ·
`/server_user_remove_key` · `/test` · `/update-logs` ·
`/update_security_exec` · `/update_zabbix` · `/admin/user_inventory/classify{,_bulk}`

**Chacune exige une lecture** : le portage réimplémente-t-il la capacité
ailleurs ? une suite en dépend-elle comme étalon ? *Le comptage réduit l'espace ;
il ne tranche pas.*

**⚠ Et deux d'entre elles portent un indice à ne pas confondre avec un verdict** :
`/server_lifecycle` a **5** références dans `tests/`, `/deploy` en a **10**.
*Beaucoup de références de test peut signifier « étalon de mesure » — la
quatrième catégorie — ou simplement « capacité bien testée ».* **Le nombre ne
distingue pas les deux.**

---

## 7. LES 17 REPRISES — 2026-09-06, 09:03 CEST

**La méthode de tri par TABLE fonctionne**, et elle referme l'angle mort du §3.
*Pour chaque route : quelles tables touche-t-elle, et un service Laravel
touche-t-il les mêmes ?* **7 classées de plus. Il en reste 10.**

### 7.1 Trois de plus sont des FAUX POSITIFS — forme 4 confirmée par la route portée

| route backend | portée par | preuve |
|---|---|---|
| `/admin/user_inventory/classify` | `POST /comptes-distants/{machine}/classer` | `ComptesDistants.php:141` **écrit** `server_user_inventory` |
| `/admin/user_inventory/classify_bulk` | `POST /comptes-distants/{machine}/classer-en-attente` | idem |
| `/server_user_keys` | `GET /comptes-distants/{machine}/cles/{username}` | `:113` **lit** `server_user_ssh_keys` |

> **Toucher une table n'est pas implémenter le geste** — c'est pourquoi j'ai lu
> les routes portées et non seulement les services. *Le croisement par table
> DÉSIGNE le candidat ; la route portée le CONFIRME.*

### 7.2 Deux candidates isolées, et leurs natures diffèrent

**`/exclude_user`** — `user_exclusions` : **0 fichier Laravel**, et **0 ligne en
base**. *Ni portée, ni jamais employée.*

**`/server_user_remove_key`** — écrit `server_user_ssh_keys` + `audit_chain`.
**Le portage LIT cette table** (`/comptes-distants/…/cles/…`) **mais n'offre
aucune route de RETRAIT.** *La lecture est portée, l'écriture ne l'est pas.*

> **C'est un trou ASYMÉTRIQUE : un module dont on a porté la consultation sans le
> geste.** *Distinct des cinq mécanismes — ici le sous-lot n'est ni déclaré
> complet ni retenu : **la moitié lisible a été portée, et la moitié qui écrit
> attend.*** **À vérifier contre le découpage du module avant de conclure.**

### 7.3 ⑥ LA SIXIÈME QUESTION DU DSI — et elle change le remède, pas le constat

> *Avant de classer une route « trou à combler », demander si la câbler
> produirait quelque chose.*

Mesuré sur les trois tables discriminantes (témoin : `machines` = 3 lignes, la
base répond) :

```
server_user_inventory   72 lignes    -> de quoi montrer
server_user_ssh_keys    20 lignes    -> de quoi montrer
user_exclusions          0 ligne     -> RIEN
```

**Et le cas du DSI sur `/ssh-audit/trends`** : `ssh_audit_results` porte **1
ligne**, 0 sur 30 jours. *La route calcule une tendance sur trente jours et il n'y
a rien à montrer — parce que le scan récurrent qui la nourrirait est **sous
arbitrage**.*

> **Une case cochée par OUBLI se comble. Une case cochée par DÉPENDANCE se
> DATE.** *La sixième question ne change pas le constat — le trou est réel dans
> les deux cas — **elle change le remède et son moment**.*

**Et elle a une limite qu'il faut dire** : *une table vide ne prouve pas qu'une
route est inutile.* `user_exclusions` est vide **parce que personne n'a jamais
exclu d'utilisateur**, pas parce que la capacité serait sans objet. **Sur une
route qui ÉCRIT, la table vide mesure l'usage passé, pas l'utilité future.**

### 7.4 État du tri — 12 sur 22

| verdict | routes |
|---|---|
| **faux positif — forme 4** | `/admin/temp_permissions` ×2 · `/admin/user_inventory/classify{,_bulk}` · `/server_user_keys` |
| **jamais câblée** | `/server_users_inventory` · `/admin/notification_prefs` |
| **trou, par dépendance** | `/cve_trends` |
| **candidates à trancher** | `/exclude_user` · `/server_user_remove_key` |
| **NON TRANCHÉES — 10** | `/apt_check_lock` · `/apt_update` · `/custom_update` · `/schedule_update` · `/update-logs` · `/update_security_exec` · `/update_zabbix` · `/deploy` · `/logs` · `/preflight_check` · `/list_machines` · `/test` |

**⚠ Trois des non tranchées ne touchent AUCUNE table** — `/logs`, `/test`,
`/update-logs`. *Le tri par table ne peut rien en dire : ce sont des flux ou des
sondes de vie, et il faut les lire.* **La méthode a une seconde limite, et c'est
celle-là.**

---

## 8. TRI CLOS — 2026-09-06, 11:00 CEST. **22 sur 22, et AUCUNE n'est portable.**

### 8.1 Une septième catégorie : *pas une capacité*

**Trois routes n'ont pas d'appelant parce qu'elles n'ont jamais été destinées à
en avoir un dans une interface :**

| route | ce que c'est |
|---|---|
| `/update_security_exec` | **rappel machine-à-machine** — jeton HMAC `X-Update-Token`, appelé par un cron **sur la machine distante** |
| `/update_zabbix` | **redirection 307** vers `/supervision/zabbix/deploy` — un shim, aucun effet propre |
| `/test` | **sonde de vie** — rend une chaîne statique, ne lit rien, n'écrit rien |

> **Les chercher comme des capacités perdues était une erreur de catégorie de ma
> part**, pas un défaut du produit. *Une route sans appelant d'interface n'est
> une perte que si elle était censée en avoir un.*

### 8.2 Le tri complet des 22

| verdict | routes | ce que ça demande |
|---|---|---|
| **faux positif — forme 4** | `/admin/temp_permissions` ×2 · `classify{,_bulk}` · `/server_user_keys` · `/list_machines` (← `/serveurs`) | **rien** |
| **pas une capacité** | `/update_security_exec` · `/update_zabbix` · `/test` | **rien** |
| **supplantée par une route plus riche** | `/schedule_update` (← `/schedule_advanced_update`) · `/apt_update` (← `/update` + `/security_updates`) · `/update-logs` (← le flux de `/update`) | **rien** — *à confirmer contre l'inventaire du module* |
| **retenue par ARBITRAGE** | `/deploy` · `/logs` · `/preflight_check` — **le sous-lot K4**, bloqué sur `NOPASSWD: ALL` | **DÉCIDER** |
| **jamais câblée** | `/server_users_inventory` · `/admin/notification_prefs` | garder ou retirer |
| **trou par dépendance** | `/cve_trends` | **DATER** |
| **trou asymétrique** | `/server_user_remove_key` — lecture portée, écriture non | confronter au découpage |
| **candidates, touchent une MACHINE** | `/custom_update` · `/apt_check_lock` · `/exclude_user` | **arbitrage** |

### 8.3 ⛔ RÉPONSE À « PORTE CE QUI EST PORTABLE » : rien ne l'est

**Le critère posé est : lecture pure, aucune machine touchée, aucun geste de
masse. Aucune des 22 ne le satisfait.**

- **8 n'ont rien à porter** — déjà portées autrement, ou pas des capacités ;
- **3 sont le sous-lot K4**, bloqué sur un arbitrage nommé (`NOPASSWD: ALL`) ;
- **3 touchent une machine** (`/custom_update` installe des paquets,
  `/apt_check_lock` interroge le verrou apt en SSH, `/exclude_user` écrit une
  exclusion) ;
- **`/cve_trends`** est un trou **par dépendance** : le câbler afficherait une
  tendance sur trente jours d'une table à **1 ligne** ;
- **les 2 jamais câblées** demandent une décision, pas un portage ;
- **`/server_user_remove_key`** exige de savoir si le découpage a séparé lecture
  et écriture à dessein.

> **Ce n'est pas un refus de porter : c'est le résultat du tri.** *Les capacités
> portables sans arbitrage avaient déjà été portées — c'est précisément ce que
> les dix réfutations de la nuit établissaient, item par item.*

### 8.4 ⚠ Ma méthode a des faux NÉGATIFS, pas seulement des faux positifs

**J'avais déclaré un seul angle mort (la forme 4). Il y en a un second, et de
sens opposé.**

En reprenant `updates.py`, un `grep` **sans retrait des commentaires** m'a montré
`/apt_update`, `/custom_update` et `/schedule_update` comme « appelées par le
portage ». **Elles ne le sont pas : les trois n'apparaissent que dans des
commentaires.** *Seul `/update` est un appel réel.*

> **J'ai failli publier l'inverse de mon propre relevé**, et ce qui m'a arrêtée
> est la règle que j'avais posée douze heures plus tôt : **« cité » n'est pas
> « appelé »**. *Une méthode ne protège que si on l'applique à la mesure qui
> semble la confirmer.*

**Et le témoin de contrôle a servi une seconde fois** : j'ai interrogé ma sonde
sur `/cles-ssh` et `/serveurs`, **que je sais portés**. Elle les rend « absent »
— *parce qu'elle ne voit que les chemins **backend**, les routes du portage étant
appelées par `route('nom')`.* **Sans ces deux contrôles, j'aurais lu « absent »
comme « inexistant » sur les cinq dernières.**
