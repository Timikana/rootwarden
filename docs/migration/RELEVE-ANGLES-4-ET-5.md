# Angles 4 et 5 — la passerelle, et ce qu'un refus coûte

Relevé de session 4, 2026-09-04. Chaque chiffre porte sa commande de remesure.
Les deux angles sont clos ; les correctifs qui en découlent sont E-388
(`8a26a9c`) et E-389 (`07a530f`), plus **un défaut non corrigé qui appartient à
la session 3**.

---

## ANGLE 4 — le portail contient un forgeur de requêtes, au menu

### La chaîne, en lecture seule

| pièce | fichier | ce qu'elle établit |
|---|---|---|
| la garde de la page | `legacy/documentation.php:11` | `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` — **tout compte connecté** |
| l'accès | `legacy/menu.php:161` | la page est une **entrée du menu principal** |
| l'endpoint | `:1624` | `<input id="api-endpoint">` — champ **libre**, aucune validation |
| le corps | `:1636` | `<textarea id="api-payload">` pré-rempli `{"machines": [1]}` = **`srv-zabbix`, PRODUCTION** |
| l'envoi | `:1744` | `fetch('/api_proxy.php' + endpoint, options)` — concaténation **brute** |

    grep -n "checkAuth" legacy/documentation.php | head -1
    grep -n "api-endpoint\|api-payload\|api_proxy.php' +" legacy/documentation.php

### ⚠ Ceci CORRIGE une phrase de l'angle 1

L'angle 1 concluait : *« aucun chemin cliquable : c'est une requête forgée, pas
un parcours d'écran »*. **C'est faux, et dans le sens rassurant.** Les routes
orphelines de la liste blanche ne demandent pas `curl` — elles demandent trois
clics, depuis une entrée de menu ouverte à un rôle 1.

### Ce qui tient

- `legacy/api_proxy.php:110` refuse `..`, `//` et `\` → **pas de traversée**.
  Ce `//` ferme au passage la forme à schéma relatif ; et le préfixe fixe
  `/api_proxy.php` empêche de toute façon l'échappement d'autorité.
- Le backend **n'est pas publié sur l'hôte** : `rootwarden_python` expose
  `5000/tcp` sans liaison. Seuls `8080/8443` (legacy) et `8444` (portage) le sont.

      sudo -n docker ps --format '{{.Names}}\t{{.Ports}}'

- **`DOSSIER-10` tient** : aucune entrée libre équivalente côté portage.
  Témoin positif obligatoire — sans lui, un zéro ne se lit pas :

      grep -rniE "api-endpoint|api_endpoint|runApiTest" laravel/   # -> 0
      grep -rlE 'type="text"|<textarea' laravel/resources/views/ | wc -l   # -> 22

### La surface réelle

**39 des 63 préfixes** de `$ALLOWED_PROXY_PREFIXES` passent pour un rôle 1
(les 24 autres tombent dans `$ADMIN_ONLY_PREFIXES`).

    # les deux listes, ancrées sur les DECLARATIONS (voir le piège plus bas)
    sed -n '116,152p' legacy/api_proxy.php | grep -oE "'/[^']+'" | wc -l   # 63
    sed -n '173,180p' legacy/api_proxy.php | grep -oE "'/[^']+'" | wc -l   # 25

Et **`updates.py` n'avait aucune autorisation** : 13 routes POST sans rôle ni
permission → E-389. La borne qui empêchait le pire était
`check_machine_access` (`helpers.py:364` : `role_id >= 2` passe tout, un rôle 1
exige une ligne `user_machine_access`) — **et la mesure du DSI a montré qu'un
compte rôle 1 actif, sans `can_update_linux`, est assigné à la machine 1.**

---

## ANGLE 5 — l'anti-rejeu TOTP, et le coût d'un refus

### Le mécanisme (et une correction de relevé)

Le suivi disait « par compte et **en base** ». **Faux** : c'est le **cache**.

    laravel/app/Services/Totp.php   clé `totp:derniere_fenetre:<id>`
                                    rétention `totp.retention_rejeu` = 120 s

    # l'autorité est ce que le framework RAPPORTE, pas ce qu'on dérive :
    sudo -n docker exec rootwarden_laravel sh -c 'cd /var/www/html && \
      php artisan tinker --execute="echo config(\"cache.default\"), PHP_EOL;"'
    # -> file   (Illuminate\Cache\FileStore)

**Pourquoi la déduction menait à une fausse alarme** : `config/cache.php:18` lit
`env('CACHE_STORE', 'database')`, aucune variable `CACHE_*` n'existe ni dans
`laravel/.env` ni dans l'environnement des trois conteneurs, et la table `cache`
**n'existe pas** (témoin : `machines` = 1). On en conclut « garde inerte, ou
connexion cassée ». Une configuration mise en cache ne se lit pas dans le dépôt.

Le mécanisme est sain : refus par **numéro de fenêtre** (`<=`, donc le rejeu
*arrière* est couvert aussi), `hash_equals`. Le `^\d{6}$` laisserait passer un
saut de ligne final — c'est le `trim()` qui l'attrape, **pas l'ancre**.

Un cache fichier étant partagé entre requêtes, workers et sessions de travail,
**les conclusions opérationnelles du suivi ne bougent pas** : le garde traverse
les contextes de navigateur et les sessions. Seule nouveauté : `cache:clear` ou
une reconstruction de conteneur le remet à zéro.

### 🔴 Le défaut : un rejeu est journalisé comme un ÉCHEC, et le verrou est par IP

`laravel/app/Http/Controllers/Auth/SecondFacteurController.php`, sur les **deux**
chemins (connexion `:128`, step-up `:212`) :

    $verdict = $this->totp->verifie(...);
    $this->journalise($requete, ..., $verdict === 'ok');   // AVANT l'aiguillage
    if ($verdict === 'rejeu') { return back()->withErrors(...); }

Donc `login_attempts` reçoit `success = 0`. Et `ipBloquee()` (`:277`) compte les
échecs **par ADRESSE IP** sur 10 minutes, seuil `max_echecs_ip = 10`
(`config/rootwarden.php:60`).

> **Dix refus de rejeu en dix minutes bloquent l'étape 2FA pour tout le monde
> derrière la même adresse** — un bureau derrière un NAT, ou un banc de test.
> Et le rejeu est le cas légitime le plus banal : le même compte ouvre une
> session sur un second appareil dans la même fenêtre de 30 s.

**Ceci résout une énigme du catalogue.** Le suivi notait des refus observés
« sans qu'aucun compte ne soit verrouillé — la piste évidente ne mène nulle
part ». Évidemment : **le verrou n'est pas par compte, il est par IP.**

    SELECT COUNT(*) FROM login_attempts
     WHERE step='2fa' AND success=0 AND attempted_at > NOW() - INTERVAL 10 MINUTE;

Le correctif tient en une distinction — *un rejeu n'est pas un échec
d'identifiant, c'est une soumission en double d'un identifiant **valide*** — et
**`laravel/` appartient à la session 3 : rien n'a été modifié ici.**

Point mineur et réel : le message distingue `erreur_code_deja_utilise` de
`erreur_code_invalide`, donc l'écran confirme au soumetteur que son code était
cryptographiquement valide. Oracle faible : il faut déjà détenir un code valide
pour l'atteindre. Signalé, non priorisé.

Note : le compteur `tentatives_2fa` (`:167`, 5 sur 60 s) est **par session**,
donc remis à zéro par un cookie neuf. C'est le compteur **par IP** qui borne
réellement — la garde faible n'est pas celle qu'on lit en premier.

---

## Le piège de méthode que ces deux angles ont payé trois fois

Détaillé dans le catalogue (`feedback_ancre_de_sonde`). En une phrase :
**une ancre doit être une déclaration, pas un mot** — et chaque sonde doit
porter un garde-fou qui NIE.

| ancre | ce qu'elle a pris |
|---|---|
| `pt.index('ADMIN_SEULEMENT')` | une **prose de docblock** à l'intérieur de la liste blanche → les 13 routes étiquetées « ADMIN », deux fois dans le même fichier |
| `grep -rl '/update'` | `/adm/api/update_user_status.php` → un faux conflit avec une page admin |
| un extrait passé à `exec()` | **rien** : indenté de 16 espaces, `IndentationError` avalée → 7 cas annoncés « fermés » sans qu'une ligne tourne |

Les trois se sont trompées **du côté qui rassure**, et les trois ont rendu un
tableau bien formé. Ce qui les a attrapées : `assert … not in bloc`,
`compile()` avant `exec`, et un **témoin positif** systématique.
