# DOSSIER-37 — la sonde de vie du portage ne mesure plus rien, et cinq replis attendent l'échange

**Session DSI. Écrit le 2026-09-06 à 18:36 CEST, après la fermeture du LOT 4**
(`runners : 0`, script temporaire effacé par son `trap EXIT`, arbre propre).
**Rien n'a été écrit pendant la fenêtre**, `docs/` compris.

**Objet.** Mon correctif TLS de 12:47 (`8862849`) a fermé une divulgation réelle
— le portail servait l'authentification et les codes TOTP en clair. *Il a aussi
deux conséquences que je n'avais pas mesurées, et une troisième famille de
défauts apparaît avec l'échange des ports que vous avez tranché.*

---

## ① 🔴 LA SONDE DE VIE DU PORTAGE REND « SAINE » SUR UN CHEMIN QUI N'EXISTE PAS

```
docker-compose.yml:106   test: ["CMD","curl","-fs","http://localhost:80/up","-o","/dev/null"]

mesuré sur le port publié de ce même port 80 :
  http://localhost:8444/up                       301   curl -fs -> exit 0   « SAINE »
  http://localhost:8444/zzz-inexistant-<epoch>   301   curl -fs -> exit 0   « SAINE »   <- TÉMOIN
  https://localhost:8446/up                      200   curl -fs -> exit 60  « MALADE » (certificat)
  /up en suivant -L -k                           200   url finale https://localhost:8446/up
```

**`curl -f` échoue sur ≥ 400, PAS sur une 301, et sans `-L` il ne suit pas.**

> **Depuis mon TLS, la sonde ne joint plus l'application : elle certifie
> qu'Apache redirige.** *Le conteneur se déclarerait SAIN avec le portail mort.*

**Le témoin est de la session 7 et c'est lui qui rend le cas irréfutable** : *un
« elle passe sur une 301 » se discute ; « elle rend le même verdict sur `/up` et
sur un chemin inventé à la seconde » ne se discute pas.*

⚠ **C'est le SYMÉTRIQUE du défaut corrigé ce matin sur le legacy** (`b1ec180`) :
sa sonde visait une page archivée et rendait un faux MALADE pendant 21 h. **Un
faux SAIN est le mauvais sens des deux.**

### ⚠ ET LA PRODUCTION EST CONCERNÉE — j'ai dit le contraire, c'était faux

*J'ai d'abord annoncé « la prod n'a aucune sonde ». J'avais compté les
occurrences dans `docker-compose.prod.yml` seul.*

```
CONTRIBUTING-SECURITY.md:45
    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

**`docker-compose.prod.yml` est une SURCHARGE** — ni `build:`, ni `ports:`, ni
`depends_on:`, ni `restart:`. **Elle hérite de la sonde du fichier de base, la
défectueuse comprise.**

**Ce qui borne la casse, mesuré** : *rien n'attend le portage en
`service_healthy`.* Les seules dépendances de santé sont `php→db`, `php→python`,
`laravel→db`, `python→db`. **Aucun ordre de démarrage n'est cassé** ; l'effet est
que `docker ps` affichera `healthy` pour un portail mort, et toute supervision
qui lit ce statut sera trompée.

### CORRECTIF — une ligne, et c'est déjà la forme des deux autres services

```
test: ["CMD", "curl", "-fsk", "https://localhost:443/up", "-o", "/dev/null"]
```

*Le python porte `-fsk https://localhost:5000/test` ; le legacy porte
`-fsk https://localhost:443/auth/login.php` depuis ce matin.* **Le portage est le
seul des trois resté en clair sur `-fs`.**

⛔ **Hors de mon périmètre d'écriture.** *La session 7 a refusé de le prendre, à
raison — `docker-compose.yml` n'est pas le sien non plus, et j'avais tenté de le
lui router en invoquant sa proximité du banc.* **La proximité n'est pas un
titre.**

---

## ② `fetch` CÔTÉ NODE NE PASSE PLUS — **UNE** suite, mesurée

**Puppeteer ignore le certificat auto-signé** (les suites qui lancent un
navigateur portent le drapeau). **Node ne l'ignore pas, et rien ne le lui
demande.**

```
node fetch  https://localhost:8446/connexion   ->  DEPTH_ZERO_SELF_SIGNED_CERT
node fetch  http://localhost:8444/connexion    ->  301, puis la même erreur
```

⚠ **J'avais écrit « trois suites ». La mesure en rend UNE.** *Le titre de
cette section disait « trois suites, cause connue » : c'était une exposition
POTENTIELLE tirée d'une lecture de code, présentée comme un coût constaté.*

```
LOT 4, verdict complet du 2026-09-06 18:27:58 :
  go-socle-passerelle       ECHEC                    <- fetch Node vers le PORTAIL
  go-adm-etiquettes-notes   PASS=18 FAIL=0  conforme
  go-auth-mot-de-passe      PASS=27 FAIL=0  conforme
```

**Les deux autres font bien un `fetch` côté Node, mais pas vers le portail** —
le chemin qui échoue est propre à `go-socle-passerelle`. *Rectification due à la
session 7, qui avait émis le « trois » et l'a mesuré ensuite.*

> **Le coût de mon correctif TLS est d'UNE suite.**

> **Ce n'est pas un coût, c'est une conséquence** *(formulation de la session
> 7)* : **le portage servait l'authentification en clair depuis le début de la
> migration.** *Trois suites à réparer contre ça.*

**Et la part qui n'est pas la mienne, dite par elle** : *ces suites supposaient
du HTTP en clair sans l'avoir jamais déclaré.* **La supposition était invisible
tant qu'elle était vraie.**

---

## ③ L'ÉCHANGE DES PORTS — cinq replis vivants, tous de la même famille

**Vous avez tranché : le portage reprend `8080/8443`, le legacy passe sur
`8444/8446`.** *Échange pur, aucun port neuf.* **Préparé par la session 4f, non
appliqué — le LOT tournait.**

**Aucun des points ci-dessous n'est faux aujourd'hui. Tous s'inversent le jour
où un conteneur démarre sans sa variable.**

| # | où | ce qui arrive sans la variable |
|---|---|---|
| 1 | `legacy/_sortie.php:32` | `getenv('LARAVEL_URL') ?: 'http://localhost:8444'` — **BOUCLE** : la page de sortie du legacy renverrait au legacy |
| 2 | `laravel/config/app.php` | `env('LEGACY_URL', 'https://localhost:8443')` — pointerait sur le portage |
| 3 | `legacy/menu.php` (×16), `head.php`, `mail_helper.php`, `auth/forgot_password.php` | mêmes replis en dur |
| 4 | **10 suites** codent leur base en dur sur `:8443` | frapperaient le portage en se déclarant legacy |

**Le ⑴ est le mien** — j'ai écrit cette page ce matin. *Sans message d'erreur, un
opérateur serait silencieusement déposé sur le portail qu'il croyait quitter.*

### ⚠ CE QUI N'EST PAS UN DÉFAUT, et qu'il ne faut pas « réparer »

**J'avais signalé la liste CORS du backend comme changeant de référent. C'est
faux, vérifié :**

```
srv-docker.env   URL_HTTPS=https://${SERVER_NAME}:${HTTPS_PORT}   HTTPS_PORT=8446
docker-compose.yml:22   php (LEGACY)   "${HTTPS_PORT:-8446}:443"
```

**Les deux entrées de `allowed_origins` dérivent de la variable qui publie le
legacy : elles bougent ensemble.**

> **Et le portage n'a JAMAIS été dans cette liste, ni avant ni après** — *il
> appelle le backend côté serveur par `PasserelleController`, donc sans préflight
> CORS.* **Écrit ici pour que personne ne « répare » en l'y ajoutant.**
> *(observation de la session 4f)*

---

## ④ CE QUI REVIENT À L'EXPLOITANT

| | |
|---|---|
| **le healthcheck ⑴** | une ligne, hors du périmètre de trois sessions — **il faut ouvrir un périmètre ou le poser vous-même** |
| **les replis ③** | à corriger dans le même geste que la recréation des conteneurs |
| **E-453** *(DOSSIER-36 §8-9)* | **toujours en attente** — la permission dont l'unique application possible est annulée |

⚠ **Non mesuré ici** : si le service `laravel` est effectivement déployé dans
votre production aujourd'hui — le défaut est dans la CONFIGURATION de prod, que
le portage y soit servi ou non ; `tests/pw/` (qui n'existe pas, vérifié par la
session 4f) ; et les sondes des autres sessions, je n'ai balayé que `scripts/`,
`tests/`, `backend/`, `laravel/`, `legacy/` et mes propres dossiers.


---

## ⑤ LE LOT 4 A CONCLU — zéro régression du produit sur 85 exécutions

```
85 executions   PASS=1722   FAIL=7
77 conformes · 6 ECHEC · 2 ECART · 0 FENETRE SALE · 0 GARDE INDISPO
fin 2026-09-06 18:27:58 CEST
fenetre PROPRE aux deux bouts : ecritureCode=false sur les trois cibles
```

**C'est la première fois que la moitié `laravel` est jouée en entier.**

*Les six ÉCHEC : `go-socle-passerelle` (mon TLS) · `go-page-search` (objet
revenu) · `go-page-documentation` · `go-page-wazuh` · `go-fail2ban-f1` (garde
E-152 réarmée par un redémarrage) · plus un rouge neuf, qui était un défaut de
SUITE et non de produit.* **Les deux ÉCART sont deux références périmées, toutes
deux dues à des correctifs du matin.**

> **L'échange des ports peut être demandé.**

⚠ **Ce que je n'ai pas vérifié moi-même** : la classification des six ÉCHEC et
des deux ÉCART. *Je relaie une mesure faite par la session 7, avec sa méthode et
son horodatage ; je n'ai reproduit que la fermeture du lot (trois façons) et
l'état des ports.*
