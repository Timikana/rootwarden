# AUDIT — `politiques` : la capacité EST portée, et il n'y a pas de fichier legacy à archiver

**Session 5 (sécurité, lecture seule).** Relevé du **2026-09-05, 22:42 CEST**.
`docs/` seul — la fenêtre du LOT est ouverte. **Aucun geste exercé.**

**Le DSI pose l'alternative : soit `sudo_preset` n'existe que dans le legacy —
et c'est un fichier non archivable — soit il est porté, et c'est la neuvième
fois. Mesuré : c'est la neuvième fois. ET il n'y avait de toute façon aucun
fichier legacy à archiver.**

---

## 1. Le lead qui a ouvert le relevé : une règle de step-up n'est pas écrite pour rien

`RoutesBackend::MOTIFS_STEP_UP` porte :

```
'#^/policy/(sudo|sftp)/(deploy|remove)$#'
'#^/policy/rollback$#'
```

> **On n'écrit pas une re-authentification pour un chemin que personne n'appelle.**
> *C'est l'artefact le plus fiable après les libellés — et il a désigné la
> capacité avant que je n'ouvre le JS.*

---

## 2. ⚠ `sudo_preset` à « 0 occurrence » était un COMPTE DE NOM

**Le geste est porté, et son chemin est COMPOSÉ** — forme n°3 des cinq :

```js
politiques.js:237   return appelle('/policy/sudo/' + geste, envoi)…
politiques.js:195   var estDeploiement = (geste === 'deploy');
```

**`geste` ∈ {`deploy`, `remove`}.** *Un motif littéral sur `/policy/sudo/deploy`
rend **zéro** sur une capacité entièrement présente* — exactement le piège que le
DSI décrit, et la seconde fois qu'il mord dans mes relevés.

**Et le préréglage est offert**, pas seulement supporté :

```
politiques.blade.php:65   <select name="preset" data-rw="politique-prereglage">
politiques.js:95          preset: choixPrereglage.value
```

### 2.1 Le portage a DURCI ce geste, il ne s'est pas contenté de le porter

```
:84  « `preset` PART TOUJOURS, et ce n'est pas une precaution de style :
      `sudo_deploy` fait `data.get('preset', 'apt_only')`. Une requete qui
      l'omet obtient donc le prereglage EQUIVALENT ROOT. Le repli dangereux
      n'est pas seulement a l'ecran, il est aussi dans le backend. »
```

**Et l'observation est juste** : `apt_only` autorise `apt` en root, donc
l'installation d'un paquet arbitraire — **root en pratique**. *Un repli qui
retombe du côté permissif, dans le backend, et le portage refuse de s'y exposer
en envoyant toujours la valeur.*

**Second durcissement mesuré** : le legacy laissait `deployPolicy()` partir au
premier clic et ne confirmait que `removePolicy()`. **Le portage confirme les
deux.**

---

## 3. ⚠ ET IL N'Y A PAS DE FICHIER LEGACY À ARCHIVER — la prémisse tombe deux fois

```
legacy/policies/        AUCUN repertoire
legacy/politiques/      AUCUN repertoire
legacy/lang/{fr,en}/policies.php   EXISTENT
  -> et AUCUNE page legacy n'emploie ces cles (hors lang/ et _deprecated/)
```

**La page n'existe plus.** *Il ne reste que deux fichiers de langue ORPHELINS.*

> **La question « ce fichier est-il le seul accès ? » n'avait pas d'objet : il
> n'y a pas de fichier.** *Ce que le relevé débloque n'est pas un archivage —
> c'est une entrée fausse dans le catalogue.*

---

## 4. ⚠ CORRECTION DU 2026-09-05 — j'avais TORT sur `sftp`, et mon témoin ne couvrait pas ce que j'affirmais

**`/policy/sftp/*` EST porté.** Signalé par le Lead, **vérifié par ma mesure** :

```
laravel/public/js/acces-sftp.js:216   appelle('/policy/sftp/' + geste, envoi)
                             :244   appelle('/policy/sftp/audit', {…})
laravel/routes/web.php:1096          Route::get('/acces-sftp')->middleware(['role:3'])
```

**Interface complète** — contrôleur, service, JS de 11 Ko, vue de 13 Ko, i18n FR+EN.
Le legacy correspondant est dans `_deprecated/adm/server_user_sftp.php`.

### 4.1 ⚠ LE MÉCANISME DE MON ERREUR — un témoin JUSTE sur une étendue FAUSSE

**J'avais posé un témoin, et il était bon :** `'deploy'` rend **7** dans
`politiques.js`, donc ma sonde n'était pas aveugle **à ce fichier**.

**Puis j'ai écrit : « `sftp` : zéro occurrence dans le module porté ».** *La
mesure portait sur UN fichier ; l'affirmation portait sur LE PORTAGE.*

> **Un témoin prouve que la sonde LIT. Il ne prouve pas que le PÉRIMÈTRE de
> recherche est le bon.** *J'ai vérifié le bon axe — « la sonde voit-elle ? » —
> sur la mauvaise ÉTENDUE.* **La capacité vivait dans un module voisin
> (`acces-sftp`), et aucun témoin posé DANS `politiques.js` ne pouvait le dire.**

**Et l'erreur va du côté qui ALARME** — j'annonçais une capacité perdue qui ne
l'était pas. *C'est le sens le moins coûteux, et c'est aussi celui que le Lead a
rouvert : personne n'aurait rouvert un « c'est porté ».*

### 4.2 Le remède du Lead, et il est par CONSTRUCTION

```
grep -ohE "/policy/[a-z0-9_/-]*" laravel/public/js/*.js laravel/resources/views/*.blade.php | sort -u
  -> /policy/sftp/  ·  /policy/sftp/audit
     /policy/sudo/  ·  /policy/sudo/audit  ·  /policy/sudo/deploy
```

**Relever les fragments SANS présumer du délimiteur, puis dédupliquer.** *Le
segment tronqué (`/policy/sftp/`) apparaît de lui-même et signale la
composition* — **là où un motif littéral rend zéro et se lit « absent ».**

*Le Lead range ma variante comme la cinquième du même piège : le segment variable
n'est ni un identifiant ni une chaîne de requête — **c'est le nom du geste
lui-même**. Et les cinq ratent du même côté : vers « c'est absent ». Le piège du
préfixe ne se trompe pas au hasard : **il alarme**.*

---

## 5. ⚠ `/policy/rollback` — MA TROUVAILLE TIENT, et elle est d'une TROISIÈME nature

**Vérifié après le signalement, par ma propre mesure :**

```
backend/routes/policies.py:496   POST · role:3 · require_machine_access · threaded_route
                        :548     'Erreur SSH'  ->  la route OUVRE une session

appelants reels :
  legacy/_deprecated/adm/js/server_user_policy.js:99   <- DEPRECIE
  laravel/tests/Feature/PasserelleTest.php:273,323     <- un TEST
  RoutesBackend.php:321 · legacy/api_proxy.php:58      <- deux regles de step-up

interface utilisateur : AUCUNE, sur AUCUN des deux portails
```

**Le relevé sans délimiteur le confirme** : `/policy/rollback` **n'apparaît nulle
part** dans les JS ni les vues du portage.

> **Ce n'est ni une règle morte ni une capacité « non portée » au sens
> ordinaire : c'est une capacité du BACKEND dont l'INTERFACE est morte avec la
> page qui la servait.** *Sa garde est vivante, elle reste appelable par clé
> d'API — mais aucun humain ne peut l'atteindre.*

**Le Lead la nomme `orpheline par dépréciation`, et le nom est juste** : une
capacité sort du périmètre non parce qu'on a décidé de ne pas la porter, **mais
parce que la page qui la servait a été dépréciée et que personne n'a regardé ce
qu'elle emportait.**

**Et ce qu'elle emporte ici** : la restauration d'un déploiement de politique
sudo **par SSH**. *Un geste qui écrit sur une machine.*

**⚠ À porter à l'exploitant sous cette forme** — non pas « une règle de step-up
sans interface », mais **« une capacité de restauration par SSH que la
dépréciation a rendue inatteignable sans que ce soit décidé »**. *Elle n'est
nommée par aucune liste ni aucun dossier.*

**Un détail qui la distingue d'une règle morte** : le portage porte un **test**
qui exerce le step-up sur ce chemin. *La règle n'est donc pas du code mort du
point de vue de la suite — elle est éprouvée, pour un chemin que personne ne peut
emprunter.*

---

## 6. ~~Deux résidus~~ — UN seul, et le troisième reste ouvert

Mon lead disait : *une règle de step-up désigne un chemin qu'on appelle.* **Vrai
pour `sudo/deploy|remove`. Faux pour les deux autres :**

| chemin | step-up armé | appelé par le portage |
|---|---|---|
| `/policy/sudo/deploy` · `remove` | oui | **oui** (composé) |
| `/policy/rollback` | **oui** | **NON** — seulement *mentionné* dans un docstring qui décrit ce que faisait le legacy |
| `/policy/sftp/deploy` · `remove` | **oui** | **NON** — `sftp` : **zéro occurrence** dans le module porté |

> **Deux chemins portent une re-authentification et ne sont atteignables depuis
> AUCUNE interface du portage.** *Le step-up y est donc armé pour une requête
> forgée — il mordrait, ce qui est bon — mais personne ne peut les employer
> légitimement.*

**Ce sont deux capacités non portées que rien ne déclare** : ni un libellé, ni un
bouton, ni une entrée de catalogue. **Seule la table de step-up en garde la
trace.** *C'est la forme la plus discrète du manque — et la table qui la porte
est une garde, pas un inventaire : personne ne la lit pour savoir ce qui existe.*

**Troisième résidu, mineur** : `legacy/lang/{fr,en}/policies.php` sont orphelins.

---

## 5. Le témoin, posé avant de conclure

    'deploy' dans politiques.js   7 occurrences   -> la sonde n'est pas aveugle
    'sftp'   dans politiques.js   0               -> c'est une MESURE, pas un silence
    'sftp'   dans la vue          0

*Sans le premier, « zéro `sftp` » et « ma sonde ne lit pas ce fichier » auraient
été indiscernables.*

---

## 6. Non mesuré, et dit

- **je n'ai exercé aucun geste** : ni déploiement, ni retrait, ni page ouverte ;
- je n'ai pas vérifié si `/policy/rollback` et `/policy/sftp/*` **existent** côté
  backend — mon relevé porte sur ce que le PORTAGE appelle. *S'ils n'existaient
  pas, les motifs de step-up seraient orphelins des deux côtés, ce qui serait un
  quatrième résidu et non un manque.* **Question ouverte, non tranchée.**

---

## 7. QUESTION FERMÉE — 2026-09-05, 23:24 CEST

**Ma question non tranchée était : `/policy/rollback` et `/policy/sftp/*`
existent-ils côté backend ? C'est elle qui décide entre « capacités perdues » et
« règles mortes ».** *Mesurée. Et elle rend trois orphelines, pas deux — dont
DEUX EN LECTURE.*

### 7.1 Les neuf routes du backend contre ce que le portage compose

```
backend/routes/policies.py
  /policy/sudo/deploy   /policy/sudo/audit   /policy/sudo/remove
  /policy/sftp/deploy   /policy/sftp/audit   /policy/sftp/remove
  /policy/rollback      /policy/deployments (GET)   /policy/list (GET)

le portage compose (releve sans delimiteur, JS + vues + app/) :
  /policy/sudo/{deploy,remove}   compose      politiques.js:237
  /policy/sudo/audit             litteral     politiques.js:265
  /policy/sftp/{deploy,remove}   compose      acces-sftp.js:216
  /policy/sftp/audit             litteral     acces-sftp.js:244
```

**⚠ Et toutes les occurrences trouvées dans `laravel/app/` sont des
COMMENTAIRES**, pas des appels — vérifié ligne à ligne. *« Cité » n'est pas
« appelé », et un relevé sans délimiteur ne fait pas la différence : c'est la
lecture qui la fait.*

### 7.2 ⛔ Trois orphelines, pas deux — et ce ne sont PAS des règles mortes

| route | méthode | interface historique | catégorie |
|---|---|---|---|
| `/policy/rollback` | POST — **ouvre une session SSH** | `_deprecated/adm/js/server_user_policy.js` | orpheline par dépréciation |
| `/policy/deployments` | **GET — lecture** | `_deprecated/…` (2 fichiers) | orpheline par dépréciation |
| `/policy/list` | **GET — lecture** | `_deprecated/adm/health_check.php` | orpheline par dépréciation |

> **Réponse à ma question : les routes EXISTENT et sont gardées. Ce ne sont donc
> pas des règles mortes à supprimer — ce sont des CAPACITÉS dont l'interface est
> morte.** *Le travail que ça demande est un arbitrage, pas une suppression.*

### 7.3 ⚠ ET ÇA RÉFUTE LA FRONTIÈRE — dans le module même où je la mesurais

Le Lead avance que *« ce qui reste non porté est exactement ce qui écrit sur une
machine »*, et j'avais posé la borne : **ce qui la réfuterait est un orphelin en
LECTURE seule.**

**Il y en a deux ici.** *Et le contre-exemple est STRUCTUREL, pas anecdotique :*

> **Une dépréciation ne retire pas un GESTE, elle retire une INTERFACE — et une
> interface sert des lectures autant que des écritures.** *`server_user_policy.js`
> emportait à la fois le retour arrière (qui écrit) et l'historique des
> déploiements (qui lit). La dépréciation n'a pas trié.*

**La frontière décrit donc une population, pas l'ensemble :**

| population | ce qu'elle contient | la frontière |
|---|---|---|
| **retenues par ARBITRAGE** | I5, S7b, `scan-all` — des gestes qu'on a **choisi** de ne pas ouvrir | **tient** : on ne retient que ce qui écrit |
| **orphelines par DÉPRÉCIATION** | ce que la page servait, sans tri | **ne s'applique pas** |

*La première est le produit d'une décision — donc elle sélectionne. La seconde est
le produit d'un effet de bord — donc elle ne sélectionne rien.* **Confondre les
deux fait chercher les orphelines là où elles ne sont pas.**

### 7.4 Mon témoin était MAL CHOISI, et je le dis

J'ai voulu qualifier ma sonde sur `_deprecated/` avec un témoin :
`/policy/sudo/deploy`. **Il a rendu ZÉRO** — et un témoin à zéro ne qualifie rien.

**Mais la cause n'est pas que la sonde est aveugle** : j'ai pris un chemin
**LITTÉRAL** comme témoin, dans un dépôt où **les chemins sont composés**. *Le
`_deprecated` compose probablement le sien aussi.* **J'ai commis, sur mon propre
témoin, l'erreur que je venais de documenter deux fois.**

**Le vrai témoin était déjà là** : la sonde rend **1, 2 et 1** fichiers pour les
trois routes cherchées. *Elle lit donc `_deprecated/` — les résultats positifs
sont leur propre témoin, et le mien était redondant en plus d'être faux.*

> **Un témoin doit être choisi dans la même FORME que ce qu'on cherche.** Un
> témoin littéral ne qualifie pas une sonde qui cherche des chemins composés.
