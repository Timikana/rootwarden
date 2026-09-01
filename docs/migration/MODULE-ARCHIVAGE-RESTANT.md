# Ce qui retient les vingt dossiers legacy encore servis

Relevé le **2026-09-01 entre 14:12 et 14:20 CEST**, en **lecture seule**. Chaque chiffre porte sa
commande. *Un fait sans heure est une opinion sur le passé* — et ce document en est un dans une heure.

---

## 0. Deux corrections d'entrée, mesurées

**« Aucun commit depuis le 2026-08-28 » est faux.** `git log -1` au moment du relevé rend
`bdbb284`, **2026-09-01 14:12:17 +0200** — dix-huit secondes avant ma mesure. Le chantier n'est pas à
l'arrêt : une autre session commite en ce moment. Le tableau porte 4 fichiers modifiés.

**Les « 20 dossiers » et les « 6 entrées » ne sont pas deux vues du même ensemble.**
`documentation` est l'une des six entrées, mais `legacy/documentation.php` est **un fichier à la
racine**, pas un des vingt dossiers. Inversement, quatorze des vingt dossiers **ne portent aucune
entrée de menu**. Croiser les deux comptes sans le dire fait croire à un recouvrement qui n'existe pas.

`ls -d legacy/*/ | grep -v _deprecated` → **20** ·
`Navigation::SECTIONS` lu par PHP → **26 route / 6 legacy / 0 ni = 32**, le total se reconstitue.

---

## 1. Les vingt, classés par CE QUI LES RETIENT

La question « qu'est-ce qui bloque l'archivage » n'a pas le même sens pour les vingt : **trois natures
différentes**, et seule la première se traite par un sous-lot.

### A. Modules à entrée de menu — **6 dossiers**, et c'est là que le travail vit

| dossier | entrée | ce qui retient | nature du blocage |
|---|---|---|---|
| `iptables` | **legacy** | I1→I4 portés, **la bascule attend I5** | **sous-lot** |
| `ssh-audit` | **legacy** | aucun sous-lot porté — inventaire fait (`MODULE-SSH-AUDIT.md`) | **sous-lot** |
| `wazuh` | **legacy** | idem — inventaire fait | **sous-lot** |
| `groups` | **legacy** | idem — inventaire fait (`MODULE-GROUPS.md`) | **sous-lot** |
| `adm` | 1 legacy (`remote_users`) + 5 portées | **quatre fichiers d'`adm/` appartiennent au SOCLE** — `includes/crypto.php` en tête, inclus par `auth/login.php`, `verify_2fa.php`, `enable_2fa.php`, `step_up_verify.php` | **arbitrage** — `adm/` ne peut pas être archivé comme une unité |
| `api` | **déjà basculée** | **E-232** : archiver retire toute référence d'API | **arbitrage DSI** |

### B. Modules PORTÉS dont le dossier traîne — **5 dossiers**

C'est le gisement que le Lead a mesuré à ~5 545 lignes. Aucun ne demande de portage : ils demandent un
**sous-lot final** puis un `git mv`.

| dossier | ce qui retient | nature |
|---|---|---|
| `security` | **S7b** — le scan CVE qui aboutit envoie un vrai courriel | **arbitrage exploitant** |
| `bashrc` | **B4** suspendu — deux arbitrages (`root` proposé, `srv-zabbix` dans les cibles) | **arbitrage** |
| `fail2ban` | **F7** — quatre capacités non portées | **sous-lot** |
| `graylog` | **G2** — les trois gestes qui mutent. **Archivage préparé** (`MODULE-GRAYLOG.md` §7, les neuf étapes) | **sous-lot** |
| `ssh` | **K4** — le déploiement de clés | **arbitrage** |

> **Aucun des cinq n'est bloqué par « rien ».** C'était le cas de `services/`, archivé le 2026-08-27
> après avoir attendu un `git mv` pendant que le dispatch allait ailleurs. **Ce cas ne se reproduit
> pas aujourd'hui** — et c'est une bonne nouvelle qui se dit aussi clairement qu'une mauvaise.

### C. Socle du portail legacy — **9 dossiers**, et ils ne s'archivent PAS un par un

`assets` (1 fichier : `css/tailwind.css`) · `img` · `js` · `lang` · `vendor` · `logs` · `includes`
(7 pages, dont `lang.php` et `onboarding.php` inclus par **toutes** les pages) · `auth` (15 pages —
`verify.php` est le garde central, l'équivalent du middleware du portage) · `profile`.

**Aucun ne porte d'entrée de menu** (`grep -cE "'(route|legacy)' *=> *'[^']*<dossier>"` → **0** pour
les neuf). Ils ne sont pas des modules en attente : **ils sont ce qui fait tourner les modules
restants.** Ils disparaissent quand la **dernière page** disparaît, pas avant, et pas séparément.

> **Le compte utile n'est donc pas « 20 dossiers à archiver ».** C'est **11 unités** — 6 modules à
> entrée + 5 modules portés — plus **un socle indivisible** qui tombe en une fois, à la fin.

---

## 2. ⚠ Une capacité LÉGALE qui disparaîtrait sans bruit

Trouvée en classant `profile/`, et elle n'est dans aucun inventaire.

`legacy/profile/export.php` — **l'export des données personnelles au format JSON**, garde
`checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])`, c'est-à-dire **tout compte connecté**.

**Elle est vivante et atteignable** : `legacy/profile.php:481` porte le lien, et
`legacy/documentation.php:887` la documente — « Route `/profile/export.php` : tout user télécharge ses
données personnelles au format JSON ». C'est la **portabilité RGPD (art. 20)**.

**Et le profil PORTÉ ne l'offre pas** :

```bash
grep -rniE "export|rgpd|portabilit|telecharg" laravel/resources/views/profil.blade.php   # rien
grep -c "profil.*export\|export.*profil" laravel/routes/web.php                          # 0
```

> **`/profile.php` est déjà traduit vers `profil` par `LiensLegacy`.** Un exploitant qui suit le
> portage arrive donc sur une page qui **n'a plus le bouton**, et rien ne le lui dit. Archiver
> `profile/` retirerait la capacité **définitivement**, et **sans qu'aucun test ne bouge** — aucune
> suite ne la couvre.
>
> Ce n'est pas un écart de confort : c'est une **obligation réglementaire** que le portage ne remplit
> pas encore. À porter **avant** l'archivage de `profile/`, pas après.

*Non mesuré* : ce que `export.php` met réellement dans son JSON. J'ai sa garde et son appelant, pas son
contenu — donc je ne peux pas dire si l'export est complet au sens de l'article 20.

---

## 3. Le graphe des six restantes — et **cinq arêtes sur six n'existent pas**

L'ordre d'archivage est un graphe, pas une liste. **Mesuré arête par arête**, et les absences sont
écrites :

| entrée | contrainte par | mesure |
|---|---|---|
| **`remote_users`** | **`ssh/`** | `legacy/ssh/js/main.js:133-136` injecte, **par `innerHTML`**, un lien « Ouvrir Utilisateurs distants » vers `/adm/server_users.php` **quand le préflight REFUSE un déploiement**. C'est la seule porte de sortie du refus. `LiensLegacy` ne s'y applique pas — elle traduit ce que le *portage* rend, pas ce que le *legacy* écrit chez lui |
| `iptables` | **rien** | aucun lien entrant hors menu |
| `ssh_audit` | **rien** | idem |
| `wazuh` | **rien** | idem |
| `groups` | **rien** *(mais voir ci-dessous)* | aucun lien entrant hors menu |
| `documentation` | **rien** | aucun lien entrant hors menu |

**Une seule arête, et elle est dirigée** : `ssh/` → `remote_users`. Comme `ssh/` est bloqué par K4
(arbitrage), **`remote_users` est contraint par un arbitrage qui ne le concerne pas**. La sortie est
soit d'attendre K4, soit de **réécrire le lien dans le legacy** au moment du `git mv` — ce qui n'est
plus un `git mv` simple.

**Une réserve à ne pas oublier sur `groups`** : il n'a pas d'arête d'archivage, mais
`tests/e2e/go-page-conformite.mjs:217-219` l'emploie comme **témoin de refus VIVANT** côté legacy et
exige `403`. L'archiver le ferait rendre 404 et **la suite échouerait en accusant une autre page**.
Témoin de remplacement identifié — `legacy/adm/audit_log.php:11-12`, couple de gardes identique — mais
**non sondé**. C'est une arête vers `tests/`, pas vers un module.

---

## 4. `documentation` remonte en tête — et je confirme pourquoi

**Accord, et la mesure le soutient.** C'est le seul des restants dont l'archivage **ferme une
exposition** plutôt que de solder un reste.

`legacy/documentation.php` (**1 756 lignes** — `INVENTAIRE.md` en annonce 1 646, relevé du 2026-08-17,
**périmé de 110**) porte une **console d'API** :

```
:1624  <input type="text" id="api-endpoint" value="/cve_test_connection">   <- CHAMP LIBRE
:1629  <select id="api-method">          :1636  <textarea id="api-payload">
:1743  fetch('/api_proxy.php' + endpoint, options)                         <- concatenation brute
```

**Une correction sur la garde, et elle va dans le sens rassurant** : le dossier annonce « ouverte à
tout compte connecté dès le rôle 1 ». **La page** l'est (`:11`, `checkAuth([1,2,3])`, aucun
`checkPermission`) — **la console, non** : elle est enclose dans `<?php if ($isAdmin): ?>` (`:1721`) et
`:16` pose `$isAdmin = $role >= 2`. **Le rôle 1 voit la page et n'a pas la console.**

Cela ne change **rien** à la décision — un rôle 2 sans aucune permission obtient un client HTTP
générique vers la passerelle — mais un dossier qui annonce « rôle 1 » se fait démolir sur ce point.
*Un interdit qui repose sur quatre fondements dont un est faux se fait démolir sur le faux.*

**Et ce que la console n'est PAS, à garder dans le dossier** : ce n'est **pas une élévation de
privilège**. Le proxy applique sa liste blanche et `$ADMIN_ONLY_PREFIXES`, le backend ses décorateurs.
Un rôle 2 n'atteint par la console rien qu'il n'atteindrait par les pages. **Ce qu'elle contourne,
c'est l'interface** : aucun panneau de décision, aucun nom de machine, aucun compte annoncé — pour des
gestes qui, sur leurs pages propres, en portent un.

---

## 5. Les deux parades, appliquées aux six

**Les quatre emplacements, comptés y compris à zéro** — relevé du 2026-09-01 :

| entrée | latérale | tiroir | raccourci | tuile |
|---|---|---|---|---|
| `iptables` | 1 | 1 | **1** (`g i`) | 1 |
| `ssh-audit` | 1 | 1 | **1** (`g A`) | 1 |
| `wazuh` | 1 | 1 | **0** | 1 |
| `groups` | 1 | **0** | **0** | **0** |
| `remote_users` | 1 | 1 | **1** (`g m`) | **0** |
| `documentation` | 1 | 1 | **1** (`g d`) | **1** (`index.php:385`) |

**`ssh-audit`, `iptables` et `documentation` portent les QUATRE.** Leur archivage sera le premier à
éprouver le cycle en entier. `groups` est à **1/0/0/0**, la couverture la plus faible du parc.

> **Deux lignes de ce tableau étaient fausses au premier jet, et la cause est instructive** : mon motif
> cherchait `sideLink('/groups/')` alors que l'entrée est déclarée `'/groups/index.php'`, et j'avais
> mis `documentation` à zéro sur la tuile alors qu'`index.php:385` la porte. **Le motif supposait une
> forme.** C'est la troisième fois de ce chantier que je mesure l'artefact voisin de celui qui porte la
> propriété — après la collision `tip.` / `tip_` et le `grep` sur les gabarits au lieu des catalogues.
> *Connaître une classe de faute n'immunise pas contre elle ; seule la question « où vit réellement ce
> que je mesure ? » le fait.* Les six lignes ci-dessus ont été remesurées une par une.

**Les clés `tip.*`** : le compte global reste **148 clés, FR = EN**, dont **52 (104 chaînes) déjà
orphelines** — appartenant à des parties archivées. Les six restantes portent chacune **5 clés × 2
langues**, sauf `documentation` : **à mesurer**, je ne l'ai pas fait pour ce dossier.

---

## 6. Ce que je n'ai PAS mesuré

- **le contenu du JSON de `profile/export.php`** — donc je ne peux pas dire si l'export satisfait
  l'article 20, seulement qu'il existe et qu'il n'est pas porté ;
- **les `tip.*` de `documentation`** — non comptées ;
- **le témoin de remplacement de `go-page-conformite`** (`adm/audit_log.php`) : identifié par lecture
  des gardes, **non sondé** ;
- **`assets/`, `img/`, `js/`, `vendor/`, `logs/`** : je les ai classés « socle » sur l'absence d'entrée
  de menu et leur contenu, **sans lire leurs consommateurs un par un.** Le classement est solide pour
  `vendor` et `logs` (aucun `.php` servi, `.htaccess` présent) ; il l'est moins pour `assets` et `img`,
  qui pourraient n'avoir plus aucun consommateur vivant. **Non vérifié** ;
- **rien n'a été archivé, déplacé ni modifié** hors de ce fichier.
