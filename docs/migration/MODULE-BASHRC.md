# `bashrc/` — inventaire avant portage

**Inventorié le 2026-08-26** (`v1.37.81`), en lecture seule, pendant que le banc était occupé par le
LOT complet d'une autre session. Aucune mesure au navigateur n'a été faite : tout ce qui suit est lu
dans le code et dans la base, et la §6 dit ce qui reste **à mesurer** avant de porter.

---

## 1. Périmètre réel

| fichier | lignes | rôle |
|---|---|---|
| `legacy/bashrc/index.php` | 352 | la page, trois onglets |
| `legacy/bashrc/js/bashrc.js` | 589 | tous les gestes |
| **total** | **941** | |

Côté backend : `backend/routes/bashrc.py`, **huit routes**. Le module déploie un `.bashrc` standardisé
sur les comptes d'une ou plusieurs machines — un fichier qui **s'exécute à chaque connexion**.

Trois onglets : `deploy`, `history`, `template`. 74 clés i18n.

---

## 2. Les huit routes, leurs décorateurs, et ce qu'elles font

Décorateurs relevés **dans l'ordre**, littéralement.

| route | décorateurs | effet | appelée par |
|---|---|---|---|
| `GET /bashrc/users` | `api_key`, `role(2)`, `perm`, `machine_access`, `threaded` | **LIT** — SSH, énumère les comptes | 3× |
| `POST /bashrc/prerequisites` | idem | **MODIFIE** — `apt-get install -y figlet`, en root | 1× |
| `POST /bashrc/preview` | idem | **LIT** — lit le `.bashrc` distant, construit un diff | 1× |
| `POST /bashrc/deploy` | idem | **MODIFIE** — écrit `.bashrc`, sauvegarde d'abord | 3× |
| `POST /bashrc/restore` | idem | **MODIFIE** — restaure la dernière sauvegarde | 1× |
| `GET /bashrc/template` | `api_key`, `role(2)`, `perm`, `threaded` | **LIT** — le gabarit, en base | 2× |
| `POST /bashrc/template` | idem | **MODIFIE la base** — pas la machine | 2× |
| `GET /bashrc/backups` | `api_key`, `role(2)`, `perm`, `machine_access`, `threaded` | **LIT** | **0×** |

La page porte `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` **et** `checkPermission('can_manage_bashrc')`.

> **L'en-tête du fichier dit VRAI.** Il annonce « Permissions : admin (2) + superadmin (3) +
> `can_manage_bashrc` », et c'est exactement ce que le code applique. Quatre autres modules du dépôt
> annoncent un accès plus strict qu'ils n'appliquent ; celui-ci, non. C'est le premier point à porter
> au crédit de ce module, et il n'est pas le dernier.

---

## 3. Ce que la mesure DÉDOUANE — et c'est l'essentiel de cet inventaire

Il faut le dire franchement : **`bashrc/` est le module le mieux construit rencontré jusqu'ici.**
Chercher des défauts n'est pas trouver des défauts, et un inventaire qui n'en rapporterait pas
sincèrement serait moins utile qu'un inventaire qui en rapporte.

### Les gardes sont complètes aux trois niveaux, et cohérentes entre elles

Les **huit** routes portent la pile complète. Et la question qui compte — le rôle 3 contourne-t-il la
permission de la même façon des deux côtés ? — a une réponse mesurée :

- `checkPermissionFromDB` (PHP) : contournement rôle 3 ;
- `require_permission` (Python, `helpers.py:280`) : `if role_id >= 3: return func(...)`.

**Les deux couches contournent identiquement.** Aucune divergence à porter.

### La valeur venant du client ne s'interpole jamais nue

- le **contenu** part en **base64** (`deploy`, ligne 89 : « Deploiement via base64 (pattern securise) ») ;
- le **nom de compte** est validé par `_USERNAME_RE = ^[a-z_][a-z0-9_-]{0,31}$` avant tout usage. Il est
  ensuite interpolé brut dans `chown {uname}:{uname}` — **et c'est sûr**, parce que la liste blanche
  n'admet aucun métacaractère de shell ;
- le **home**, qui vient du `/etc/passwd` **distant**, est validé par
  `_HOME_RE = ^/[A-Za-z0-9._/-]{1,128}$`, avec le pourquoi écrit juste à côté :

  > « Patch A03 (defense en profondeur) : home vient du /etc/passwd distant. Les commandes
  > l'interpolent entre quotes simples → un home contenant une quote simple permettrait un breakout. »

  C'est le contraire du « à moitié corrigé » : les **trois** fonctions qui touchent au home
  (`_inspect_bashrc`, `_read_remote_bashrc`, `deploy`) refusent un home non conforme.

### Le geste destructeur est encadré

`deploy` sauvegarde avant d'écraser (`cp -a` puis `chmod 600`), écrit, puis lance `bash -n` **sur le
fichier déployé**. `restore` relit la sauvegarde la plus récente. `_audit_log` enregistre après coup,
avec le SHA8 du gabarit, le nombre d'octets et un **résumé de diff** — une vraie trace de qui a changé
quoi.

### Tous les gestes qui écrivent demandent confirmation

Contrairement à D9a et D9b, où `deploy` partait au premier clic. Ici les quatre gestes destructeurs
confirment, et le déploiement multi-machines **énumère les machines par leur nom** dans sa boîte :

```js
confirm(`${label}\n\n${__('bashrc.servers')} (${machines.length}) :\n  • ${names}\n\n…`)
```

> **Piège de relevé, payé sur ce module.** Un premier `grep -oE "confirm\(__\('[^']+'\)"` n'a rendu
> que quatre clés et laissait croire que `deploy` n'en avait pas — parce que sa confirmation est
> construite par gabarit (`confirm(\`${label}…\`)`) et non par un appel direct. **Un motif qui suppose
> une forme d'appel ne mesure que cette forme.** Vérifié avant d'être rapporté ; ç'aurait été une
> accusation fausse, et la troisième du chantier.

---

## 4. Ce qui reste à décider, et c'est modeste

### 4.1 Les huit motifs de danger n'existent QUE dans le navigateur

`bashrcTemplateScanDanger()` teste le gabarit contre huit expressions — `rm -rf /`, fork bomb, `mkfs`,
`curl|sh`… — et ouvre un `confirm()` renforcé si l'une correspond. Le backend, lui, ne valide que la
**syntaxe** (`bash -n`) et la **taille** (512 Ko). Une requête forgée vers `POST /bashrc/template` ne
voit donc aucun de ces huit motifs.

**Ce n'est PAS une faille, et il faut le dire aussi nettement que le reste.** Quiconque atteint cette
route détient déjà `can_manage_bashrc` (ou le rôle 3) — c'est-à-dire l'autorisation explicite d'écrire
le fichier qui s'exécute à chaque connexion sur le parc. Le scan n'est pas un contrôle d'accès : c'est
un garde-fou pour la personne qui édite.

> **La décision de portage est donc de présentation, pas de sécurité** : le portage ne doit pas
> laisser croire que ce scan est une barrière. Un `confirm()` renforcé qui dit « voici ce que j'ai
> reconnu » est honnête ; un bandeau « contenu validé » ne le serait pas — il n'y a pas de validation
> de contenu, il y a une reconnaissance de huit motifs connus.

### 4.2 `GET /bashrc/backups` n'a AUCUN appelant

La route existe, elle est gardée, elle fonctionne — et rien dans les 589 lignes du JS ne l'appelle.
C'est une **capacité inatteignable**, comme `POST /supervision/overrides/<mid>` l'était.

La porter serait **concevoir**, pas migrer : il faudrait inventer l'écran qui la montre. La laisser
serait la laisser à un `fetch` de la réactivation. **À arbitrer** — mais c'est un arbitrage à faible
enjeu, la route ne fait que lire.

### 4.3 `@require_machine_access` est INERTE sur ces huit routes

`check_machine_access()` ouvre par « Admins (role >= 2) ont acces a tout ». Les huit routes exigeant
déjà le rôle 2, le décorateur ne peut jamais refuser. Il est **décoratif**, pas porteur.

Ce n'est pas un défaut de ce module — c'est une propriété du décorateur, déjà relevée ailleurs (inerte
sur 57 routes sur 114). Elle est notée ici pour que le portage ne lui prête pas une garde qu'il n'a
pas.

### 4.4 Aucune fenêtre de maintenance, aucune approbation à quatre yeux

Zéro occurrence sur les huit routes. Le déploiement multi-machines écrit donc sur plusieurs machines
d'un coup, hors de toute fenêtre, sans second regard. **À signaler à l'exploitant, sans le corriger en
silence** : d'autres modules du dépôt en ont, celui-ci pas, et rien ne dit si c'est délibéré.

### 4.5 « Fusionner » est le mode PAR DÉFAUT, et son terme-clé n'est défini nulle part

**Mesuré le 2026-08-26**, au second tour de lecture, en fermant les inconnues de la §6.

Le libellé est « Fusionner (conserver blocs custom) », et il est **`selected`** dans le `<select>`
(`index.php:109`). Il est **littéralement vrai** : `_extract_custom_blocks()` conserve bien les blocs.
Mais « bloc custom » a un sens technique précis —

```
# >>> USER CUSTOM >>>
…
# <<< USER CUSTOM <<<
```

— qui **n'apparaît dans aucune des 74 clés i18n du module**. Ni `USER CUSTOM`, ni `.bashrc.local` ne
sont mentionnés à l'écran. La lecture naturelle du libellé (« garde mes personnalisations ») est donc
fausse pour tout `.bashrc` que RootWarden n'a jamais géré : **sans marqueurs, « fusionner » se comporte
exactement comme « écraser »**, et c'est le cas de tout premier déploiement.

> Ce n'est ni E-142 (un texte qui dit faux) ni E-146 (un texte qui recommande l'inverse de ce qui est
> livré). C'est une **troisième variante** : un libellé vrai dont le terme porteur n'est défini nulle
> part. Il ne se corrige pas en le rendant « plus juste » — il l'est déjà — mais en **définissant son
> terme**.

#### Et l'interface JETTE la mesure qui lèverait l'ambiguïté

C'est la partie qui vaut d'être portée. Le backend calcule, dans la branche `dry_run` :

```python
'would_backup': bool(current),
'custom_detected': bool(custom),
```

`custom_detected` répond exactement à « est-ce que "fusionner" va préserver quoi que ce soit pour ce
compte ? ». Il est affiché dans l'**aperçu** (`bashrc.js:271`, clé `bashrc.has_custom`) — et **absent
du tableau de résultat du déploiement** (`bashrc.js:313-322`), qui rend User / OK / Backup / Syntaxe /
Détail. L'information est calculée, elle traverse le réseau, et elle est jetée au rendu.

**Forme inverse des défauts précédents** : pas un texte qui ment, mais une **mesure vraie que
l'interface abandonne**.

#### Gravité : faible, et il faut le dire aussi

Rien n'est perdu irrémédiablement. La sauvegarde est faite **dès que le fichier existe, dans les deux
modes**, et un échec de sauvegarde **avorte le déploiement pour ce compte** (`continue`) — fail-closed.
C'est un défaut d'**information**, pas de destruction. Le portage doit montrer `custom_detected` dans
le résultat et définir « bloc custom » ; il n'a pas à réécrire le geste.

### 4.6 `machine-select` : un vestige, et il est gardé

`bashrc.js:103` cherche `getElementById('machine-select')`, absent de la page. Le code le sait :

```js
if (sel) sel.value = String(m.id);  // sync ancien select si encore present
```

Vestige **sciemment** mort et protégé. À ne pas porter, et à ne pas compter comme un défaut.

---

## 4bis. Ce que les CAPTURES ont montré, et qu'aucune lecture n'aurait donné

**Mesuré le 2026-08-26**, B1 vert sur le legacy (16 PASS / 0 FAIL). Trois défauts qui ne se voient
qu'à l'image — aucune assertion DOM ne les attrape.

### `srv-zabbix` est une ligne comme les autres

La machine de **production** figure dans le tableau des cibles avec une case à cocher identique à
celle des deux machines d'essai. Rien ne la distingue : ni couleur, ni marqueur, ni avertissement.

Combiné à ce que la §6.4 a établi — **`root` est proposé au déploiement** (`UID == 0`) — la page
permet de cocher production + `root` et de déployer, en deux clics et une confirmation générique.

### « Déployer » est le bouton VERT

Cinq boutons sur une rangée, tous de même poids visuel : `Apercu (diff)` bleu, **`Deployer` VERT**,
`Dry run` gris, **`Deployer multi` violet**, `Dry-run multi` pâle.

> Le vert est la couleur la moins alarmante de la palette, et elle est donnée au geste qui **écrit un
> `.bashrc` sur toutes les machines cochées**. Le violet, encore moins lisible comme un danger, va au
> geste **multi-machines**. Les deux gestes sûrs — l'aperçu et les simulations — n'ont pas de code
> couleur qui les distingue comme sûrs.

Le codage n'est pas seulement arbitraire : il est **inversé** par rapport au risque.

### Un compteur à zéro s'affiche comme un chiffre

« Serveurs cibles **0** ». La convention du chantier veut qu'un compteur à zéro **s'énonce** — « aucun
serveur sélectionné, un déploiement ne déploierait rien » — plutôt que de s'afficher comme un `0`,
qui se lit comme une donnée et non comme un état.

### Ce que le portage doit en faire

Le module n'a **aucun** défaut de sécurité (§3) : ces trois points sont de **présentation**, et c'est
précisément le registre où ce chantier a trouvé ses défauts les plus coûteux. Le portage doit
distinguer la production, hiérarchiser les cinq gestes par leur effet, et énoncer le compteur.

## 5. Découpage proposé — lectures d'abord, écritures distantes en dernier

| sous-lot | contenu | pourquoi ce rang |
|---|---|---|
| **B1** ✅ | La page, les trois onglets, les gardes, l'i18n — *PORTÉ `v1.37.86`, `/bashrc`, **17 legacy / 18 portage**, 0 FAIL* | Rien ne part vers une machine. Et c'est ici que se mesure le **triple chemin de garde** (§6), désormais MESURÉ |
| **B2** | L'onglet Déploiement en LECTURE : `/bashrc/users`, `/bashrc/preview` | Ouvre une session SSH, mais ne modifie rien. Le diff est la pièce à porter fidèlement |
| **B3** | L'onglet Gabarit : `GET`/`POST /bashrc/template` | Écrit **en base**, jamais sur une machine. Porte la décision 4.1 |
| **B4** | Les écritures distantes : `deploy`, `multiDeploy`, `prerequisites`, `restore` | **MODIFIE** le parc. À exercer par interception avec avortement, comme D9a et D9b |

L'onglet Historique se lit dans `user_logs` : il tombe dans B1 (aucune route dédiée).

---

## 6. Ce dont cet inventaire n'est PAS sûr — la section la plus utile

**Rien de ce qui suit n'a été mesuré au navigateur.** Trois des cinq points ont été fermés le 2026-08-26 **par la lecture**, le banc étant toujours pris ; ils restent listés, barrés, avec leur réponse — un inventaire qui efface ses propres questions perd la trace de ce qui était incertain, et de ce qui a levé l'incertitude. Le banc était pris ; ces points sont *déduits du
code* et doivent être **mesurés** au premier sous-lot.

1. ~~**Le triple chemin de garde.**~~ **MESURÉ le 2026-08-26**, et conforme en tout point à la
   déduction — les trois lignes ci-dessous sont des relevés, pas des attentes :

   ```
   INFO  comptes d'epreuve detenant `can_manage_bashrc` : (aucun)
   PASS  rw-test-user  (role 1) est refuse  — statut 403
   PASS  rw-test-admin (role 2) est refuse  — statut 403      <- le chemin du milieu
   PASS  rw-test-super (role 3) est admis   — statut 200      <- contournement de role
   ```

   La précondition est vérifiée **avant** les trois : si un compte d'épreuve venait à recevoir la
   permission, l'attendu du milieu changerait sans que rien ne le signale.

   *Rédaction d'origine, conservée :* Déduit, non mesuré. La table `permissions` dit que
   **`rw-test-super` (rôle 3) n'a PAS `can_manage_bashrc`** — c'est donc lui qui exercera le
   *contournement par le rôle*, et `rw-test-admin` (rôle 2, sans la permission) qui doit être
   **refusé**. Trois chemins, dont celui du milieu qu'aucune suite du chantier n'exerce d'ordinaire :

   | compte | rôle | permission | attendu |
   |---|---|---|---|
   | `rw-test-user` | 1 | non | refusé |
   | `rw-test-admin` | 2 | **non** | **refusé** — le rôle 2 ne contourne pas |
   | `rw-test-super` | 3 | **non** | **admis** — le rôle 3 contourne |

   C'est la mesure la plus intéressante du module, et la seule qui distingue « la garde laisse passer
   parce que la permission est là » de « parce que le rôle l'emporte ».

2. ~~**Le comportement réel de `mode=merge`.**~~ **FERMÉ le 2026-08-26** — voir §4.5. Il ne préserve
   que les blocs entre marqueurs `USER CUSTOM` ; sans marqueurs, il équivaut à « écraser ». Les blocs
   extraits sont **ajoutés** à `~/.bashrc.local`, précédés d'un commentaire daté.

3. ~~**Ce que `preview` rend quand le compte n'a pas de `.bashrc`.**~~ **FERMÉ** — `_read_remote_bashrc`
   ouvre par `if [ -f '{home}/.bashrc' ]` et rend `""` sinon. Le diff est alors intégralement en
   ajout. Cas vide propre, aucune exception.

4. ~~**La liste des comptes exclus.**~~ **FERMÉ, et il en sort deux choses.** `_list_users` retient
   `UID == 0 || UID >= 1000`, en excluant les shells `nologin|false|sync|halt|shutdown`. Donc :
   - **`root` EST proposé au déploiement** (UID 0). C'est la cible la plus conséquente du parc, et
     l'écran ne la distingue en rien des autres. À trancher au portage : la marquer, ou non ;
   - `_USERNAME_RE` est **réappliqué aux lignes venues de la machine**, après le `awk`. Troisième
     endroit où ce module traite une donnée distante comme hostile, après `_HOME_RE` et la validation
     des noms reçus du client. C'est une constante de conception, pas un accident.

5. ~~**Le nombre d'assertions atteignables**~~ **MESURÉ côté legacy : 16.** La référence laravel
   reste inconnue tant que la page n'est pas portée.

---

## 7. Ce que ce module apporte au chantier, au-delà de son portage

Deux motifs à réutiliser ailleurs :

- **la validation d'une valeur venant de la MACHINE** (`_HOME_RE`) est traitée avec la même rigueur
  qu'une valeur venant du client. Le commentaire nomme le vecteur et la parade. C'est le seul endroit
  du dépôt rencontré jusqu'ici où une donnée *distante* est traitée comme hostile ;
- **la confirmation qui ÉNUMÈRE ce sur quoi elle porte** — le multi-déploiement liste les machines par
  leur nom. C'est exactement ce que D9a et D9b ont dû *ajouter* ; ici c'était déjà là.
