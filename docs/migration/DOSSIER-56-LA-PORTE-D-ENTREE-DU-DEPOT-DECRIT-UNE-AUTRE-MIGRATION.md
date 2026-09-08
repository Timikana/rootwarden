# DOSSIER-56 — La porte d'entrée du dépôt décrit une autre migration

**Mesuré le 2026-09-08 entre 15:30 et 15:35 CEST.** Aucune écriture hors ce
dossier.

> Le filon de ces derniers tours n'est plus dans le produit : il est dans **ce
> qui le décrit ou l'outille**. `README.md` est le document le plus lu du dépôt.
> **Il décrit une migration achevée à 40 %, nomme les mauvais ports, et appelle
> le legacy éteint « la référence ».**

---

## 1. La version annoncée contre la version réelle

```
version reelle (legacy/version.txt)   2.0.183
dernier tag                           v2.0.22

README.md          annonce  v1.37.47
README.en.md       annonce  v1.37.47
ARCHITECTURE.md    annonce  v1.37.47
OPERATIONS.md      annonce  v1.37.16
```

**Une version MAJEURE de retard**, dans les quatre documents qu'on lit avant le
code.

---

## 2. ⛔ LE TABLEAU DES PORTS EST INVERSÉ, ET C'EST LE PLUS COÛTEUX

`README.md:14-17` :

```
| | port | rôle |
|---|---|---|
| **portage Laravel** (`laravel/`) | **8444** | la cible — reçoit les pages une par une |
| **ancien portail** (`legacy/`)   | **8443** | la référence, dépréciée partie par partie |
```

**Mesure au réseau, maintenant :**

```
:8443  /connexion -> 200  ·  titre « Connexion · RootWarden »   <- le PORTAGE
:8446  /connexion -> 404                                         <- le legacy, eteint
```

**Les deux lignes sont fausses**, et l'une est un piège actif :

- le **portage** n'est pas sur 8444 — 8444 est la **redirection** http→https
- le **legacy** n'est pas sur 8443 : **8443 est le port du portage** depuis
  l'échange du 2026-09-06
- et le legacy n'est plus « la référence » : il sert **zéro** `.php`

> **Un exploitant suivant ce tableau pour comparer l'ancien et le nouveau
> taperait DEUX FOIS sur le portage** — 8443 pour « l'ancien », 8444 pour « le
> nouveau » qui n'est qu'une redirection vers 8443. Il conclurait que les deux
> portails sont identiques.

*C'est la forme la plus coûteuse d'une doc périmée : elle ne se contente pas de
ne rien dire, elle mène une mesure au mauvais endroit et la rend cohérente.*

---

## 3. Une mesure datée, présentée comme l'état

`README.md:19-21` :

> *« **État mesuré au 2026-08-23** : **14 entrées de menu portées sur 33**, **9
> parties du legacy archivées**, deux modules entièrement dépréciés. »*

**Seize jours. Et l'état réel :** la migration est **achevée** — zéro `.php`
servi hors archive, **214** fichiers sous `legacy/_deprecated/`, aucun lien
composé vers le legacy par le portage.

⚠ **La phrase porte sa date, et c'est ce qui la sauve à moitié** : elle ne
prétend pas être actuelle. Mais elle est au premier écran, et *une mesure datée
placée là où on cherche l'état se lit comme l'état.*

---

## 4. Ce qui n'est PAS un défaut, et j'ai failli le dire

`README.md:336-346` explique, en dépannage, de faire `rm -f legacy/.installed`
après un `down -v`.

**J'allais signaler que le README demande de supprimer un fichier employé par du
code vivant** : `git grep '\.installed'` rend `backend/routes/fail2ban.py`,
`laravel/app/Services/Fail2ban.php`, `laravel/public/js/fail2ban.js`.

**C'est faux.** Ces correspondances portent sur une **colonne de base**
(`f.installed`) et un **champ JSON** (`d.installed`) — *textuellement identiques
à un nom de fichier terminant par `.installed`*. Le vrai fichier est
`php/install.sh:27` : `LEGACY_FLAG="${APP_DIR}/.installed"  # compat installs
anterieures`, un drapeau du service **php**, éteint.

> **Un nom de fichier et un accès de propriété peuvent être le même texte.**
> `\.installed` échappe bien le point, et il apparie quand même `f.installed`.

La section est donc **périmée, pas nuisible** : elle dit de supprimer un fichier
qui ne compte plus. Elle part avec `patch 07`.

---

## 5. Ce que je ne corrige pas, et pourquoi

**`README.md` n'est ni `DECISIONS-DSI.md` ni un `DOSSIER-*.md`.** C'est la face
publique du dépôt, lue par l'exploitant et par sept sessions ; l'éditer
unilatéralement est plus conséquent qu'un dossier.

**Le geste le plus urgent tient en deux lignes** : le tableau `README.md:16-17`.
Corriger les ports et retirer « la référence ». *C'est le seul des quatre points
qui fasse mesurer faux.*

Les trois autres sont de la mise à jour : la version dans quatre documents, la
mesure du 2026-08-23, et la section de dépannage qui part avec `patch 07`.


---

# 6. ⛔ LE RUNBOOK EST PIRE QUE LE README : il fait TAPER des commandes mortes

**Mesuré le 2026-09-08 15:55.** `OPERATIONS.md` — le document qui te fait
**agir** — annonce `v1.37.16` et porte **le même tableau de ports inversé** :

```
:14  | rootwarden_laravel | 8444 | le portage, la cible |
:15  | rootwarden_php     | 8443 | l'ancien portail, deprecie partie par partie |
```

## Trois commandes, trois 404

```
:183  curl -k -b cookies.txt https://localhost:8443/adm/api/audit_verify.php
:200  curl … -X POST https://localhost:8443/api_proxy.php/revoke_service_account
:209  curl … -X POST https://localhost:8443/api_proxy.php/regenerate_platform_key
:224  « si tu appelles /adm/api/delete_user.php sans step-up, tu reçois : »
```

**Les quatre points d'entrée sont ARCHIVÉS**, mesuré fichier par fichier :

```
adm/api/audit_verify.php    vivant 0  ·  archive 1
api_proxy.php               vivant 0  ·  archive 1
adm/api/delete_user.php     vivant 0  ·  archive 1

au reseau, sur :8443 (le PORTAGE) :
  /adm/api/audit_verify.php               -> 404
  /api_proxy.php/revoke_service_account   -> 404
```

*⛔ Les deux POST n'ont pas été envoyés : `revoke` et `regenerate` sont
destructeurs. Seuls les GET ont été mesurés.*

## ⚠ ET LES TROIS CAPACITÉS FONCTIONNENT

C'est ce qui rend ce défaut plus grave que celui du README :

```
① verifier un sceau d'audit
     /journal-audit                  web.php:1200
     journal-audit/verifier          TableDesGardes:112, role:3 + can_admin_portal
② revoquer un compte de service
     backend/routes/ssh.py:988       @bp.route('/revoke_service_account', POST)
     page du portage : /comptes-distants        web.php:1171
③ regenerer la cle de plateforme
     backend/routes/ssh.py:14 · ssh_key_manager.py:192
     page du portage : /cle-plateforme          web.php:1018
```

> **Le runbook fait taper trois commandes qui rendent 404, pour trois capacités
> qui MARCHENT — atteintes par un autre chemin.** C'est l'inverse d'une
> documentation qui sous-promet : **celle-ci fait paraître cassé un système qui
> fonctionne.** Un exploitant qui la suit conclut que la migration a perdu la
> vérification de sceau, la révocation de compte de service et la régénération de
> clé de plateforme.

## Ce que je n'écris PAS, et pourquoi

**Je ne fabrique pas les commandes de remplacement.** Les deux gestes d'API
passent désormais par la passerelle, dont l'accès porte session **et** jeton CSRF
— donc un code TOTP. Écrire un `curl` sans avoir mesuré cette chaîne
reproduirait exactement le défaut que ce dossier signale : *une commande fausse
dans un runbook se tape.*

**Ce qui est vérifié et suffit à corriger** : les trois **pages** du portage
(`/journal-audit`, `/comptes-distants`, `/cle-plateforme`) et le fait que les
deux points d'API vivent côté backend, atteints par la passerelle.

## Priorité, revue

Le geste le plus court de ce dossier n'est plus `README.md:16-17` seul :

```
1. OPERATIONS.md:183 :200 :209 :224   -> quatre commandes/renvois MORTS
                                          sur des capacites VIVANTES
2. OPERATIONS.md:14-15 + README.md:16-17  -> le meme tableau inverse, DEUX fois
3. la version annoncee dans quatre documents
4. README.md:19, la mesure du 2026-08-23
```

---

# 7. `ARCHITECTURE.md` — 1179 lignes qui décrivent l'arbre par des chemins morts

**Mesuré le 2026-09-08 à 16:05 CEST.** C'était le dernier gros document non
examiné du dépôt, et sa péremption n'est pas de la même espèce que celle du
runbook : **elle ne fait pas taper une commande fausse, elle fait chercher un
fichier qui n'existe pas.** C'est plus faible, et je le dis plutôt que de
l'aligner sur §6.

## 7.1 Les chemins : faux DEUX fois

Le document emploie la forme `www/…` — le nom du répertoire **avant la vague 0**
(`52251087 refactor(migration): vague 0 - www/ devient legacy/`).

```
chemins www/*.php distincts cites          43
  -> existent sous legacy/_deprecated/     39     <- prefixe faux ET fichier archive
  -> existent sous legacy/ (vivant)         0
  -> introuvables des deux cotes            4

TEMOIN  www/adm/health_check.php -> resolu   ✅   (l'instrument resout bien)
        www/zzz/inexistant.php   -> non      ✅   (et il discrimine)
```

**Zéro des 43 désigne un fichier vivant.** Le document décrit intégralement un
arbre archivé, par des chemins portant un préfixe retiré depuis deux renommages.

## 7.2 Les comptes, contre la mesure — et le témoin qui valide l'instrument

⛔ **RETRACTATION DU 2026-09-08 19:50 — « 63 tables » ETAIT JUSTE, ET C'EST MOI
QUI ME TROMPAIS.** La ligne barree ci-dessous est fausse ; je la garde visible
parce que je l'ai transmise trois fois a l'exploitant et publiee dans une PR
fusionnee.

```
~~:39   « Sur 63 tables »                 mesure  65 CREATE TABLE~~   <- FAUX

  base vivante (information_schema)        63 BASE TABLE, 0 vue
  schema, analyseur corrige                63
  migrations : 65 fichiers, 65 enregistrees, derniere appliquee 065

  mes deux « tables » en trop venaient de COMMENTAIRES :
    « ci »  033_graylog.sql:29
            -- … les colonnes existent deja via CREATE TABLE ci-dessus.
    « if »  055_machine_groups.sql:10
            -- Idempotent : CREATE TABLE IF NOT EXISTS. Pas de point-virgule…
```

*Quatrieme contamination par les commentaires du meme jour — les trois autres
etaient en JavaScript, celle-ci en SQL, quelques heures plus tard. Et les deux
commentaires coupables parlent de `CREATE TABLE` en expliquant l'idempotence.*

**La parade qui aurait suffi seule, et elle est structurelle plutot que
lexicale : EXIGER le `(` qui suit une declaration de table.** Un commentaire qui
cite `CREATE TABLE` ne le fait jamais suivre d'une parenthese ouvrante.
*S'ancrer sur la syntaxe qui DOIT suivre est plus fort que d'apparier le
mot-cle.*

⚠ **Et j'ai accuse le bon cote de la mesure** : `ARCHITECTURE.md:39`,
`SKILL.md:16`, `:25` et `:48` disent tous « 63 » et **ont raison**. Septieme
fausse alarme de la journee, toutes du cote qui accuse.

```
:414  « 77 routes en 8 modules »          mesure  229 @bp.route en 27 modules

  fail2ban.py   annonce 19  ·  mesure 19   ✅  <- LE TEMOIN
  updates.py    annonce 12  ·  mesure 14
  cve.py        annonce 16  ·  mesure 18
  ssh.py        annonce 10  ·  mesure 19
  wazuh.py      annonce 11  ·  mesure 15
```

⚠ **`fail2ban.py` à l'identique est ce qui rend le reste lisible.** Mon prédicat
`@bp.route` s'accorde avec celui de l'auteur du document sur un module ; les
écarts ailleurs sont donc de la **croissance réelle**, pas un désaccord
d'instrument. *Sans ce module-là, « 77 contre 229 » aurait tout aussi bien pu
signifier que je comptais autre chose que lui.*

## 7.3 ⛔ Et `health_check.php` : ma crainte, et pourquoi elle ne tient pas

`:843` présente `www/security/health_check.php` comme un *« dashboard diagnostic
des 11 routes backend »*. C'est le fichier que les consignes interdisent
d'ouvrir — il écrit sur `srv-zabbix`, la **production**, au chargement.

**Il n'y a pas de danger vivant, et pour trois raisons cumulées :**

```
① le fichier est ARCHIVE          legacy/_deprecated/adm/health_check.php
② le chemin annonce est FAUX      « security/ » ; il est sous « adm/ »
③ une requete sur l'archive       rend 404 (RedirectMatch sur _deprecated)
```

*Personne ne peut l'atteindre en suivant cette ligne.* **Je l'écris comme un
non-danger plutôt que comme une alarme** : une alarme de plus sur un document
périmé aurait fait ranger celle-ci par ressemblance avec les autres, et c'est
exactement le coût que `feedback_forme_de_ce_qu_on_transmet` mesure.

---

# 8. LE FAIT QUI COMPTE : un seul échange de ports a périmé SEPT porteurs

Le diagramme d'`ARCHITECTURE.md:12-17` dit `:8443 → legacy` / `:8444 → laravel`.
**Au réseau, redaté maintenant : `:8443/connexion` → 200 · `:8446/connexion` →
404.** Le document se date lui-même au **2026-08-23** (`:8`) — donc **il était
juste à l'écriture**, et il est devenu faux le **2026-09-06** sans que personne
n'y touche.

**C'est le même événement que `APP_URL=…:8444` de `DOSSIER-54`, et j'en compte
maintenant sept porteurs normatifs :**

```
ARCHITECTURE.md:12,17                        le diagramme
README.md:16-17     + :248,250               le tableau, PUIS une seconde fois
README.en.md:16-17  + :223,224               idem, en anglais
OPERATIONS.md:14-15                          le runbook (cf. §6)
.claude/skills/rw-laravel/SKILL.md:8-9       ⛔ une COMPETENCE de session
srv-docker.env.example:72                    ⛔ contredit sa propre ligne 102
obsidian…/containers-docker.md:17,39         le vault (miroir, 482 .md)
```

## 8.1 ⚠ Les deux porteurs qui ne sont pas de la simple documentation

**`.claude/skills/rw-laravel/SKILL.md:8-9`** — *« Le frontend Laravel (`laravel/`,
port 8444) tourne en parallèle du legacy (`legacy/`, port 8443). Le legacy reste
la référence. »* **Une compétence n'est pas lue, elle est suivie.** Une session
qui la charge reçoit le mapping inversé *et* « le legacy reste la référence »
comme cadre de travail — alors que le legacy sert zéro `.php`.

**`srv-docker.env.example` se contredit à trente lignes d'intervalle :**

```
:72    « le legacy (8443) reste la reference tant que la parite… »      FAUX
:101   « ⚠ LE PORT EST 8443, ET LE SENS DE 8444 S'EST INVERSE LE 2026-09-06. »
:104   « DATER avant d'interpreter une trace de 8444. »                 JUSTE
```

> **L'avertissement de `:101` a été écrit pour protéger le lecteur d'une trace de
> `8444`. La ligne `:72` est une telle trace, dans le même fichier, trente lignes
> plus haut, non protégée.** *On applique une règle en LISANT, jamais en
> écrivant — et ici c'est littéral et mesurable : l'auteur de l'avertissement n'a
> pas relu son propre fichier au-dessus de lui.*

## 8.2 Mon instrument a sur-collecté, et c'est instructif

Mon premier relevé rendait **24 fichiers**. Faux : `CHANGELOG.md:1119`,
`srv-docker.env.example:102`, `scripts/rejouer-lot.sh:95` et
`PLAN-DE-MIGRATION.md:308-309` décrivent l'échange **correctement**.

> **Une description juste et une affirmation fausse du même fait contiennent les
> mêmes jetons.** Un motif fondé sur la co-présence de `8443` et de `legacy` ne
> peut pas les séparer : il faut lire la ligne et juger sa POSITION — un tableau,
> un diagramme, un « va ici » sont normatifs ; un récit daté ne l'est pas.

## 8.3 ⛔ CE QUE JE TRANCHE — E-504

**Sept porteurs pour un fait, et la prose ne se garde pas par construction.**
Ma propre hiérarchie (*inexprimable > dérivé > exhaustif > contrôlé*) n'offre
ici que le rang le plus faible : un test qui grep un nombre dans un `.md`.

**Donc le remède n'est pas sept corrections plus une garde. C'est de réduire le
nombre de porteurs à UN.**

```
LE porteur : srv-docker.env.example:88-104
             il porte deja LARAVEL_HTTPS_PORT=8443 et l'avertissement DATE
les six autres : remplacer la valeur par un renvoi vers ce bloc
```

*Un fait qui vit à sept endroits se périme sept fois et se corrige une fois sur
sept. Un fait qui vit à un endroit avec sa date se périme une fois — et l'échange
du 06/09 l'aurait alors coûté un seul geste, pas sept documents faux pendant
deux jours.*

⚠ **Et l'ordre de priorité, dans ces sept :** `SKILL.md:8-9` d'abord — c'est le
seul qui **oriente le travail d'une session** au lieu d'informer un lecteur.
Puis `:72` de `srv-docker.env.example`, parce qu'un fichier qui se contredit
apprend à ses lecteurs à ne pas le croire, y compris là où il a raison.
