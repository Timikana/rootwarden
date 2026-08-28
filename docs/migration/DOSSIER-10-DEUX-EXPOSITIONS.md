# DOSSIER 10 — Deux expositions, et ce que chacune demande

**Remontée unique pour l'exploitant.** Session 8, **2026-08-28**, mesures de **13:49–14:00 UTC**
(15:49–16:00 CEST). Fusionne le `DOSSIER-09` et E-234 à la demande du Lead.

> **L'axe qui classe n'est pas la gravité de l'effet : c'est ce que l'exposition DEMANDE.** Un défaut
> qui exige une clé d'API et un défaut qui exige d'être connecté ne se traitent pas au même rythme, même
> si le second fait moins de dégâts.

---

## Le tableau qui décide

| | **A — le secret 2FA de la production** | **B — la console d'API du portail** |
|---|---|---|
| **ce qu'il faut pour l'atteindre** | **un mot de passe** | **un compte de rôle ≥ 2** |
| où | `origin/main` — **la production** | **le portail legacy seul** — le portage n'a pas de console |
| ce qu'on obtient | le **secret TOTP en clair** + le QR, codes valides indéfiniment | une **requête libre** vers le backend, dont un scan SSH de **toute la flotte** |
| combien de comptes concernés | **tout compte dont on connaît le mot de passe** | **5** (2 de rôle 2, 3 de rôle 3) |
| est-ce une escalade ? | **oui** — le second facteur devient dérivable du premier | **non** — un rôle 2 n'atteint rien de plus qu'en cliquant les pages |
| ce qui est en jeu | **l'authentification** | **l'intentionnalité** d'un geste de masse |
| correctif écrit ? | **oui, depuis le 2026-08-23** — il n'est pas déployé | non : c'est une décision de portage |

**A passe devant B**, et pas parce que son effet est plus large : parce que **son prérequis est plus
bas**. *Un mot de passe est ce que tout compte possède ; un rôle 2 est ce qu'on accorde.*

---

## A — Le secret TOTP de la production est lisible avec un mot de passe

**Détail complet, geste exact et contrôles : `DOSSIER-09-RETROPORTAGE-2FA-PRODUCTION.md`.** Résumé de ce
qui décide :

    git merge-base --is-ancestor 23a6063 origin/main   ->  NON
    origin/main:www/auth/enable_2fa.php:33-34          ->  if (!isset($_SESSION['temp_user'])) header("Location: login.php")

`temp_user` est l'état posé **après le mot de passe et avant le second facteur**. La page conçue pour
*établir* le second facteur est celle qui le **divulgue**.

**Le correctif existe depuis cinq jours** et n'a pas atteint la production. Deux mesures ont corrigé la
forme du rétroportage : `origin/main` **n'a aucun dossier `legacy/`** (le fichier y est sous `www/`), et
la production **appelle déjà** `checkCsrfToken()` — la transposition porte **trois** volets, pas quatre.

---

## B — E-234 : une console d'API sur la page qui promet de ne rien faire

### La chaîne, vérifiée maillon par maillon

    1. legacy/documentation.php:11    checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])
                                      -> TOUS les comptes connectes, des le ROLE 1.
                                         AUCUN checkPermission sur la page.
    2. :1624   <input type="text" id="api-endpoint" value="/cve_test_connection">   <- CHAMP LIBRE
       :1629   <select id="api-method">
       :1636   <textarea id="api-payload">{"machines": [1]}</textarea>
    3. :~1744  fetch('/api_proxy.php' + endpoint, options)
                                      -> le chemin est CONCATENE BRUT, aucune liste blanche cote page
    4. legacy/api_proxy.php:133        '/ssh-audit/'  est en liste blanche — un ESPACE DE NOMS,
                                         donc il couvre `/ssh-audit/scan-all`
    5. backend/routes/ssh_audit.py:237-241
                                      @require_api_key · @require_role(2) · @threaded_route
                                      -> ni permission, ni porte d approbation

### Ce que la route fait, et pourquoi elle est nommée dans la consigne permanente

`/ssh-audit/scan-all` sélectionne **tout le parc** (`WHERE lifecycle_status IS NULL OR != 'archived'`)
puis ouvre `ssh_session(...)` **par machine**. **Il n'y a aucun paramètre de portée à restreindre** —
c'est la route dont le plan écrit : *une fixture borne un argument ; elle ne borne pas une route dont la
portée est « tout le parc ».*

**Parc mesuré à 14:00Z** — les trois machines `active`, donc les trois visées :

    id 1  srv-zabbix            pk=1  sa=1   <- la PRODUCTION, et la session ABOUTIRAIT
    id 2  Test-Server-Debian    pk=0  sa=0
    id 3  OpenCVE-Test-OnPrem   pk=0  sa=0

**C'est la route que la consigne permanente du chantier interdit de lancer** — `go-ssh-audit-scanall.mjs`
est nommé dans la table des interdits depuis l'ouverture.

### ⚠ Le détail que le relevé initial n'avait pas, et il compte

    :1636   <textarea id="api-payload">{"machines": [1]}</textarea>

**Le corps par défaut de la console cible la machine 1 — `srv-zabbix`, la production.** Il est sans effet
sur `scan-all`, qui ignore le corps ; **il en a un sur toute route qui lit `machines`.** *Un formulaire
dont la valeur par défaut désigne la production n'est pas un formulaire neutre* — même famille que le
`SELECT id FROM machines LIMIT 1` d'E-227, en pré-rempli au lieu d'en implicite.

### Ce que ce n'est PAS, et le dire protège la décision

**Ce n'est pas une escalade de privilège.** Le proxy tient, les décorateurs tiennent : un rôle 2
n'atteint **rien** qu'il n'atteindrait par les pages — et E-226 établit que le scan de flotte est déjà
**à un clic** sur `legacy/ssh-audit/index.php:82`.

> **Ce qui est contourné n'est pas une garde : c'est l'INTERFACE.** Tous les panneaux de décision que ce
> chantier a posés — nommer la machine, nommer le nombre, exiger une recopie. *Un panneau de
> confirmation n'est pas une garde ; il n'en est pas moins la seule chose qui empêche un geste de masse
> d'être involontaire.*

**Et la portée réelle est de 5 comptes**, mesurée : 2 de rôle 2, 3 de rôle 3. Les **7** comptes de rôle 1
ouvrent la console et sont refusés par `@require_role(2)` — *la page est plus permissive que la route,
et c'est cette fois dans le bon sens.*

### Les deux décisions que B demande, et je n'en tranche qu'une

| # | question | qui |
|---|---|---|
| 1 | la console se porte-t-elle ? | **délégué — tranché ci-dessous** |
| 2 | le volume de prose en dur de la page | **hors de mon périmètre** : ce n'est plus un portage, c'est un projet de rédaction à chiffrer, et son coût appartient à l'exploitant |

**✅ DÉCISION sur la n°1 : la console NE SE PORTE PAS.**

Trois raisons, dans cet ordre :

1. **elle offre une entrée libre que le portage ne peut pas valider.** *Ne pas offrir d'entrée libre
   plutôt que la valider*, et *fermer par l'absence puis ASSÉRER l'absence* — c'est la règle que ce
   dépôt applique déjà aux motifs de portée, où le portage n'offre qu'une liste fermée écrite côté
   serveur ;
2. **elle contourne les panneaux de décision**, qui sont l'acquis le plus cher du portage. La reproduire
   derrière `role:3` + permission + panneau serait *reconstruire une porte dérobée avec une serrure* ;
3. **son seul usage légitime mesuré est déjà porté ailleurs** : la page dit elle-même *« Testez la
   connexion OpenCVE depuis Administration → Docs → Tester l'API (endpoint `/cve_test_connection`) »*.
   **Un test de connexion nommé, à une cible fixe, n'a pas besoin d'un champ libre.**

**Et la conséquence, qui est l'argument le plus fort pour la dépréciation complète du legacy** :
*tant que `documentation.php` est servi, cette console est joignable.* **Elle ne se ferme pas par un
correctif : elle se ferme par l'archivage.** Le Lead a raison de dire que l'argument ne se trouvait pas
dans le plan — il est sur la page dont le nom promet qu'elle ne fait rien.

---

## Ce que je recommande, dans cet ordre

1. **A — autoriser la transposition** du correctif 2FA vers `www/auth/enable_2fa.php`. Trois volets, un
   fichier, aucune réécriture d'historique. **`DOSSIER-09` porte le geste exact** ;
2. **B — porter `documentation` SANS la console**, et **archiver `legacy/documentation.php` dès que la
   page portée existe.** C'est ce qui ferme B ;
3. **et un dossier qui n'est ni A ni B mais qui les précède tous les deux dans le temps** : le
   `DOSSIER-01`, le redémarrage. Il ne ferme aucune de ces deux expositions, et il met en service **20
   modules** dont deux qui touchent la production (E-227, E-191).

---

## Ce qui se passe si on ne fait rien

**Sur A** : l'authentification à deux facteurs de la production n'en est pas une, et le correctif dort.
**Aucune dégradation dans le temps** — la vulnérabilité est ouverte depuis l'origine du fichier, pas
depuis une régression. *Il n'y a pas d'urgence de minutes ; il y a cinq jours de retard sur un correctif
écrit.*

**Sur B** : rien ne change, et c'est le point. **Cinq comptes peuvent, par curiosité, déclencher une
session SSH sur la production** depuis une page de documentation, sans qu'aucun écran ne nomme la
machine. *Le risque n'est pas l'attaque : c'est l'accident.* Et il croît avec le nombre de comptes de
rôle ≥ 2 — le `DOSSIER-02` en propose deux de plus.

---

## Ce qui n'est pas mesuré

- **si l'une des deux expositions a été exploitée ou déclenchée** — cela demanderait de lire les journaux
  de production, hors périmètre ;
- **le nombre de comptes de production concernés par A** : je lis `main` par `git`, je n'interroge pas la
  base de production ;
- **la console n'a PAS été exercée.** Ni son champ, ni son bouton, ni la route. La chaîne est établie
  **par lecture des cinq maillons** — et c'est délibéré : *la démontrer reviendrait à la commettre*, sur
  la machine que le chantier a l'interdiction de joindre ;
- **`/docker/scan_all` et `POST /groups/<id>/run`**, relevés par le Lead comme atteignables par la même
  console, ne sont pas revérifiés ici. **Je le dis plutôt que de les reprendre** : deux maillons vérifiés
  ne valident pas les trois autres lignes d'un tableau ;
- **le VOLUME de prose de la page.** Le relevé du Lead annonce **6 883 mots à 96,4 % en dur** ; je l'ai
  d'abord recopié dans ce dossier **sans le mesurer**. Ma propre mesure, grossière et déclarée comme
  telle — texte entre balises de plus de vingt caractères, compté par `wc -w` — rend **~3 861**, soit un
  **plancher** et non un compte comparable. *Deux méthodes différentes sur le même objet ne se
  départagent pas par le chiffre le plus gros.* **Le chiffre est retiré du corps du dossier** : la
  décision qu'il soutient — *ce n'est plus un portage, c'est un projet de rédaction* — ne dépend pas de
  savoir s'il vaut 3 861 ou 6 883.
