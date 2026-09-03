# Relecture de `security/backend-cve` — six correctifs, jamais fusionnés

Relevé le **2026-08-27** par la session 5 (sécurité), en **lecture seule**. La branche n'a pas été
sortie, l'arbre de travail n'a pas été touché, aucun `merge` n'a été fait — trois sessions écrivent
dans ce dépôt à cet instant.

**Verdict global : les six correctifs sont bons, la branche est saine, et la fusion est propre.
Trois réserves, dont une seule porte sur le code.**

---

## 1. La question qui décidait de tout : a-t-elle divergé ?

C'est la vraie raison pour laquelle une branche vieille de plusieurs jours fait peur. Mesuré :

```
git merge-base Migration-Laravel security/backend-cve
  -> 279f5fa  docs(skills): cinq lecons de S4
git rev-list --left-right --count Migration-Laravel...security/backend-cve
  -> 168   6
```

La branche est **6 commits en avant et 168 en retard**. Ce chiffre alarme, et il est trompeur. Ce qui
compte n'est pas le retard, c'est le **recoupement**. Mesuré fichier par fichier, sur les six fichiers
que la branche touche :

| fichier | commits sur le tronc depuis la séparation |
|---|---|
| `backend/cve_enrich.py` | **0** |
| `backend/routes/cve.py` | **0** |
| `backend/routes/helpers.py` | **0** |
| `backend/scheduler.py` | **0** |
| `backend/tests/test_cve.py` | **0** |
| `backend/tests/test_scheduler.py` | **0** |

**Aucun de ces six fichiers n'a bougé sur le tronc.** Fusion à blanc (`git merge-tree --write-tree`,
qui n'écrit rien dans l'arbre de travail) : **code de sortie 0, zéro conflit**.

> **La branche n'a pas divergé. Les 168 commits de retard ne la concernent en rien.** C'est la
> mesure qui lève la dette : ce qui la rendait coûteuse à fusionner n'existe pas.

Corollaire moins agréable : **les six failles sont donc toutes encore ouvertes sur le tronc**, puisque
rien ne les a corrigées entre-temps. Vérifié un par un au §3, sur le code d'aujourd'hui — pas sur la
foi du raisonnement ci-dessus.

### Recoupement avec le travail en vol — nul

Relevé à l'instant : les sessions en cours modifient `laravel/**`, `docs/**`, `legacy/version.txt`,
`tests/e2e/go-fail2ban-f2.mjs`, et créent `backend/tests/test_fail2ban.py`. **Aucune intersection**
avec les six fichiers de la branche. La fusion ne peut emporter le travail non commité de personne.

---

## 2. Les six correctifs, un par un

Ordre chronologique. Pour chacun : ce qu'il ferme, ce qu'il **ne** ferme pas, et qui l'occupe.

### 2.1 `3e65ad3` — le clamp anti-fréquence des scans planifiés était contournable

Validation côté API de la fréquence d'une planification. **Ferme l'écriture** d'une ligne abusive.
Ne répare pas les lignes déjà en base — et le commit suivant (`a345e65`) le dit lui-même, ce qui est
la bonne façon de livrer un correctif partiel : nommer sa moitié manquante.

**Occupation : aucune** — `cve_scan_schedules` est **vide** (0 ligne, mesuré).

### 2.2 `8043303` — une panne d'enrichissement effaçait le drapeau KEV

`enrich_findings` rattrape lui-même les échecs réseau EPSS/CISA, ne les journalise qu'en `debug`, et
rend un dict de stats normal. La branche « 503 » de `cve_reprioritize` était donc **inatteignable
pour une panne réseau**. L'`UPDATE` qui suit écrit `1 if f.get('kev') else 0` sans condition — donc
**0 partout** quand la carte KEV est vide.

Le correctif est en deux temps et **le partage des rôles est juste** : `enrich_findings` *signale*
(`epss_echoue`, `kev_echoue`, journalisés en WARNING), l'appelant *décide*. C'est correct parce que
la même fonction sert deux appelants aux besoins opposés — pendant un **scan**, des findings non
enrichis sont normaux et doivent s'écrire ; pendant une **re-priorisation**, écrire du vide est une
destruction. Une fonction ne peut pas trancher cela seule.

**Occupation : RÉELLE, et la donnée exposée est exactement celle qui existe.** Mesuré :
`cve_findings` porte **1458 lignes, toutes sur la machine 1 (`srv-zabbix`), dont 5 marquées KEV**.
Une panne réseau pendant une re-priorisation efface ces 5 drapeaux et réécrit 1458 lignes, sans
retour en arrière, en affichant « Re-priorisation terminée ».

### 2.3 `427306c` — `cve_reprioritize` était la seule écriture CVE sans aucune garde

`POST /cve_reprioritize` porte `@require_api_key` + `@require_machine_access` + `@threaded_route`, et
**ni rôle ni permission**, alors que la page qui porte le bouton exige `can_scan_cve`
(`legacy/security/index.php:38`). **Vérifié sur le tronc aujourd'hui : toujours le cas**
(`backend/routes/cve.py:227-231`).

C'est la même classe que SEC-001 et que `can_deploy_keys` — la garde sur la page, pas sur la requête.

**Ce que le commit fait de mieux, et qui mérite d'être relevé** : il explique **pourquoi seulement
cette route**. Les autres routes CVE figurent dans les scopes `readonly`/`monitoring` des clés d'API,
lesquelles n'ont pas de session — `get_current_user()` rendrait `(0,0)` et `require_permission`
refuserait en 403. **Aucune route du dépôt ne combine aujourd'hui un scope de clé d'API et une
permission.** Le commit signale la décision de conception au lieu de la prendre. C'est exactement la
discipline que ce chantier demande.

**Occupation : OUI, et l'alignement est frappant.** `opsuser` (id 2, rôle 1, actif) n'a **aucune**
permission — donc pas `can_scan_cve` — et sa **seule** machine est la machine 1. Or **la totalité des
1458 findings est sur la machine 1**. Le compte que la page refuse peut réécrire précisément les
données qui existent. Réserve déjà dite dans `AUDIT-INJECTION-FAIL2BAN.md` §5.2 : `opsuser` n'a pas
de second facteur et s'enrôlerait lui-même au premier accès ; c'est une étape, pas une barrière, et
je ne sais pas qui détient son mot de passe.

Occupé aussi, sans réserve, par tout compte de rôle ≥ 2 — `check_machine_access` rend vrai sans
condition.

### 2.4 `399931a` — le garde d'accès machine ne lisait pas le même paramètre que ses routes

**C'est le correctif le plus important de la branche, et il ferme un écart ouvert cette semaine.**

L'ancienne résolution enchaînait les sources par `or` et gardait donc la **première** trouvée. Le
correctif **collecte toutes les sources au lieu d'en choisir une**, et lit en plus les paramètres de
**chemin** :

```python
for source in (data, request.args, kwargs):
    for cle in ('machine_id', 'server_id', 'mid'):
        val = source.get(cle)
        if val not in (None, ''):
            ids.append(val)
```

**Ce correctif ferme E-175**, que j'ai relevé aujourd'hui indépendamment sans savoir qu'il était déjà
écrit : `/fail2ban/history` et `/iptables-history` lisent `server_id` là où le décorateur retenait
`machine_id`. Avec ce patch, les deux valeurs sont contrôlées, et une requête portant
`machine_id=<la mienne>&server_id=<celle d'autrui>` rend **403**. E-175 n'a donc pas besoin d'un
correctif propre : **il a le sien, il attend une fusion.**

**Ce qu'il ne ferme pas, et le commit le dit** : quand **aucun** identifiant n'est trouvé, la route
est appelée sans contrôle. Rendre l'absence bloquante casserait les routes qui n'ont légitimement pas
de machine (`/maintenance/check`, `/fail2ban/stats`, `/wazuh/options`, `/ssh-audit/policies`). Le
choix est écrit dans le docstring et non seulement dans le message — c'est la bonne place.

**Contrôle de non-régression que j'ai fait, et qui aurait pu mal tourner** : le patch lit désormais
les `kwargs`, donc tout paramètre de chemin nommé `machine_id`, `server_id` ou `mid`. Si une route
portait un paramètre de chemin **homonyme désignant autre chose**, elle se mettrait à refuser à tort.
Balayage des **34** routes à paramètre de chemin du backend : **4** portent un tel nom, et **les
quatre désignent réellement une machine** (`/supervision/overrides/<int:machine_id>` ×2,
`/supervision/agents/<int:machine_id>`, `/supervision/machines/<int:mid>/profile`). Les autres
paramètres — `pid`, `schedule_id`, `window_id`, `group_id`, `perm_id`, `whitelist_id`, `platform`,
`name` — ne sont **pas** dans la liste de clés lue. **Aucune fausse alarme possible.** La liste de
clés est étroite, et c'est ce qui la rend sûre.

**Occupation : aucune aujourd'hui.** Le contournement corps-contre-query est fermé **par accident** —
aucune des deux passerelles ne relaie le corps d'un GET (`AVEC_CORPS` du portage ne contient que
POST/PUT/PATCH ; le proxy legacy ne pose pas `CURLOPT_POSTFIELDS` sur un GET). Le commit le dit
lui-même, et c'est la bonne façon de le dire : **fermé par accident, pas par décision.**

> **RÉSERVE — la seule qui porte sur le code de cette branche, et c'est un message, pas un défaut.**
> Le commit affirme que `/supervision/machines/<int:mid>/profile` est « désormais **couverte**,
> vérifiée par test ». Le décorateur y trouve bien `mid` — mais cette route porte aussi
> `@require_role(2)`, et `check_machine_access` commence par `if role_id >= 2: return True`. **Aucun
> appelant capable d'atteindre cette route n'est contraint par le décorateur.** La couverture est
> vraie de la *mécanique* et fausse de la *protection effective* ; le test passe parce qu'il exerce
> un rôle 1, que la route réelle refuse avant. Le fichier lui-même le savait :
> `supervision.py:2440` porte le commentaire « *require_machine_access est un no-op sur le mid d'URL
> -> require_role indispensable* ». **Le correctif reste juste et souhaitable** — il ferme un piège
> pour toute route future — mais son message revendique un effet qu'il n'a pas.
>
> C'est la sixième occurrence du motif « le commentaire affirme plus que le code », et la première à
> se produire **dans une branche de sécurité**. Elle ne coûte rien tant qu'on ne s'y fie pas pour
> conclure qu'une route est protégée. **Correction demandée : au message de commit uniquement, pas
> au code.**

### 2.5 `a345e65` — les scans CVE se connectaient à des machines archivées

Deux défauts d'inégale gravité sous un seul titre, et le second est le vrai.

**Le premier** : `cve_scan_all` et les trois branches du scheduler ne filtrent pas
`lifecycle_status`. Une machine retirée du parc — masquée de l'interface — continuait d'être jointe
en SSH. **Vérifié encore ouvert sur le tronc** (`cve.py:43-44`, `scheduler.py:186-215`).

**Le second, et il est plus grave** : le repli **élargit le périmètre**.

```python
if ids:  ...  WHERE id IN (...)
else:    SELECT ... FROM machines      # <- TOUT le parc
```

Une planification restreinte à deux serveurs dont le `target_value` se vide ou se corrompt devient un
scan **complet**. Ce scan **ouvre une session SSH sur chaque machine** — et `base_cols` porte
`password, root_password`, déchiffrés dans la boucle : le repli ne fait donc pas « scanner les
mauvaises machines », il fait **s'authentifier en root sur tout le parc**.

> **⚠ CORRIGÉ le 2026-09-02.** Cette phrase disait *« et envoie un vrai courriel par machine — c'est
> précisément l'effet sortant que §7 réserve au mot de l'exploitant (S7b) »*. **Les deux clauses
> étaient fausses sur CE chemin**, et le DSI m'a donné le discriminant plutôt que la correction.
> Mesuré :
>
> | chemin | courriel | repli fail-open |
> |---|---|---|
> | route `/cve_scan` | **oui** (`send_cve_report`, `routes/cve.py:77`) | **non** — `machine_id` requis, 400 sur liste vide |
> | route `/cve_scan_all` | **oui** | **non** — passe `[]` **délibérément**, c'est son objet |
> | action groupée (`groups.py:278`) | **oui**, même stream | **non** — passe `[mid]`, jamais vide |
> | **scheduler (planifié)** | **NON** — `notify_cve_scan` → webhook | **OUI** |
>
> **Les deux faits ne se recouvrent pas.** Le courriel vit sur les chemins qu'un humain déclenche et
> regarde ; le repli vit sur le seul qui tourne sans personne. Ma phrase joignait deux vérités qui
> habitent des chemins différents — *et c'est la forme la plus difficile à repérer, parce que chaque
> moitié se vérifie séparément.*

**Et le chemin planifié est MUET**, ce qui aggrave au lieu d'atténuer : `notify_cve_scan` appelle
`send_webhook`, et `WEBHOOK_ENABLED` vaut `'false'` par défaut — mesuré **sans aucune variable
webhook définie dans le conteneur servi, et aucune table `%webhook%`** (mesure du DSI, pas la
mienne). Sa seule trace est un `_log.info` dans les journaux du conteneur.

> **Le repli élargit la portée ; le silence retire la détection.** Ce ne sont pas deux défauts, c'est
> un défaut **et l'absence de son garde-fou**. La formulation est du DSI et elle est meilleure que la
> mienne : je cherchais un effet sortant et j'ai trouvé un effet **muet**, ce qui est pire pour un
> geste qu'aucun humain ne regarde.

**C'est la cinquième forme du motif « un repli qui retombe du côté permissif »**, et la plus large :
les quatre autres (E-144, E-147, `preset`, `sudo`) ouvrent un **droit** ; celle-ci ouvre un
**périmètre**. Son effet n'est pas *sortant* au sens de §7 — **il est distant et irréversible** : les
sessions SSH ouvertes sur des machines qui n'auraient pas dû être jointes ne se défont pas.

Le correctif rend la branche `machines` **fail-closed** — une cible restreinte illisible ne scanne
**rien** — et journalise en WARNING avec la valeur fautive. La propriété testée est la bonne :
non pas « la requête est bornée » mais **« il n'y a pas de requête »**, sur cinq formes d'illisibilité
(`None`, chaîne vide, `[]`, texte libre, objet JSON), avec un curseur qui mémorise **toutes** les
requêtes et non la dernière.

**Occupation : aucune aujourd'hui, et ce n'est pas rassurant.** Mesuré : **0 planification CVE** et
**0 machine non active**. Les deux moitiés sont donc réelles et **sans porteur**. Mais la première
planification à cible `machines` que quelqu'un crée — geste d'exploitation ordinaire — arme le repli.
**L'absence de porteur ici tient à ce que la fonctionnalité n'est pas utilisée, pas à ce qu'une garde
la retienne.**

### 2.6 `9ac8456` — une CVE blanchie pouvait être signée du nom de n'importe qui

`whitelisted_by = (data.get('whitelisted_by') or 'admin').strip()` — le client choisit le nom sous
lequel une acceptation de risque est signée, et le repli **nomme quelqu'un d'autre**. **Vérifié
encore ouvert sur le tronc** (`cve.py:628`).

Le correctif prend l'auteur dans la **session**, comme `tickets.created_by` le fait déjà, ignore le
champ du client, et remplace le repli `'admin'` par l'identifiant numérique — *« un repli qui nomme
quelqu'un d'autre serait pire qu'un repli illisible »*. Le curseur est ouvert en `dictionary=True`
explicite et la colonne nommée, pour ne pas dépendre de la forme par défaut du curseur, qui diffère
entre le pilote et le double de test.

**Ce que le commit dit lui-même et qu'il faut garder** : `cve_whitelist` **n'a aucun lecteur**. Le
scanner ne la consulte jamais, `expires_at` n'est évalué nulle part. Le correctif rend l'attribution
honnête ; il ne rend pas la fonctionnalité opérante. **Quatrième occurrence** du motif « une colonne
écrite et lue par personne » (avec `password_expires_at`, `temporary_permissions.machine_id`, la
table de whitelist).

**Occupation : aucune** — `cve_whitelist` est **vide** (0 ligne), et sans lecteur, blanchir reste sans
effet observable. **C'est le moins urgent des six**, et le commit ne prétend pas le contraire.

---

## 3. Les six failles sont-elles encore ouvertes sur le tronc ? — oui, vérifié

Non pas déduit du §1, mais lu dans le code d'aujourd'hui :

| correctif | état sur `Migration-Laravel` aujourd'hui | porteur |
|---|---|---|
| `3e65ad3` clamp | ouvert | aucun (0 planification) |
| `8043303` KEV effacé | ouvert | **1458 lignes, 5 KEV, machine 1** |
| `427306c` garde `cve_reprioritize` | ouvert — `cve.py:227-231`, ni rôle ni permission | **`opsuser` + tout rôle ≥ 2** |
| `399931a` garde d'accès machine | ouvert — `helpers.py`, résolution par `or` | latent (fermé par accident) — **ferme E-175** |
| `a345e65` archivées + repli élargissant | ouvert — `cve.py:43`, `scheduler.py:210,213` | aucun, et à une planification près |
| `9ac8456` attribution | ouvert — `cve.py:628` | aucun (table vide, sans lecteur) |

---

## 4. Ce que je n'ai PAS mesuré, dit aussi clairement

- **Les 318 pytest annoncés ne sont pas vérifiés par moi.** Les exécuter demanderait de sortir la
  branche dans l'arbre de travail — que trois sessions modifient à cet instant — et le conteneur
  `rootwarden_python` sert la racine du dépôt par montage : un `git worktree` ne serait pas testable
  non plus. **Je ne l'ai donc pas fait, et je ne reconduis pas le chiffre.** C'est une mesure qui
  appartient à la session 6, après la fusion, sur le banc.
- **Je n'ai pas relu le diff ligne à ligne de `cve_enrich.py` ni de `scheduler.py`** : j'ai lu les
  intentions, les emplacements, et vérifié que les défauts décrits existent bien sur le tronc. Une
  relecture ligne à ligne du corps des correctifs reste à faire — elle est moins urgente que la
  décision de fusion, mais elle n'est pas faite.
- **Je n'ai pas mesuré l'effet du patch `399931a` sur les 114 routes** qui portent le décorateur.
  J'ai vérifié la seule classe de régression que le patch introduit (les paramètres de chemin
  homonymes, §2.4) et elle est vide. Les autres routes ne reçoivent **que des contrôles
  supplémentaires** sur des valeurs qu'elles fournissent déjà — un appel légitime n'en fournit
  qu'une, donc rien ne change pour lui. C'est un raisonnement, **pas une mesure au banc**.

---

## 5. Recommandation — et je ne fusionne pas

**Je recommande la fusion des six commits, telle quelle, sans rebase.**

Motifs, dans l'ordre :

1. **zéro divergence, zéro conflit, zéro recoupement** avec le travail en vol — la fusion ne coûte
   rien à personne et n'emporte le travail de personne ;
2. **les six failles sont ouvertes sur le tronc** et deux ont un porteur mesuré aujourd'hui
   (`8043303`, `427306c`) ;
3. **`399931a` ferme E-175 sans travail supplémentaire** ;
4. **ne pas rebaser** : réécrire l'historique d'une branche pendant que d'autres sessions travaillent
   est interdit par le protocole, et le merge propre rend le rebase inutile.

**Deux conditions avant, et elles ne sont pas de moi :**

- **le mot de l'exploitant.** `git merge` est interdit sans lui, et cela ne se contourne pas parce
  que le contenu est bon ;
- **corriger le message de `399931a`** sur `/supervision/machines/<int:mid>/profile` (§2.4). Au
  message, pas au code. Si le message reste tel quel, un lecteur futur conclura qu'une route est
  protégée alors que sa protection vient d'ailleurs.

**Une condition après :** les **318 pytest** doivent être remesurés par la session 6, sur le banc,
après la fusion — et le chiffre attendu n'est pas 318 mais **318 + ce que le tronc a ajouté depuis**
(341 annoncés au plan, à remesurer eux aussi). **Additionner les deux chiffres serait faux** : ils
sont mesurés sur des arbres différents et rien ne dit qu'ils sont disjoints.

**Je n'applique rien, je n'ouvre aucune branche, je n'ai pas fusionné.** Les deux contradictions du
plan (§3.2 contre §7, §3.1 contre §10 du protocole) sont portées à l'exploitant par le Lead et je ne
tranche ni l'une ni l'autre.

---

## 6. Ce que cette relecture apprend au chantier

- **Un retard de commits n'est pas une divergence.** 168 commits de retard, et zéro recoupement : la
  dette qui semblait la plus lourde du chantier est la moins chère à solder. Le chiffre qui décide
  n'est pas `rev-list --count`, c'est `rev-list --count -- <fichier>` **par fichier touché**.
- **Un correctif de sécurité peut porter, dans son message, la faute qu'il corrige ailleurs.**
  `399931a` ferme une garde qui ne gardait pas, et revendique une couverture qui ne couvre pas. Le
  motif ne s'arrête pas aux fichiers qu'on soupçonne.
- **Une faille sans porteur n'est pas une faille moins réelle** — elle est une faille dont
  l'absence de porteur tient parfois à ce que la fonctionnalité n'est pas encore utilisée
  (`a345e65` : 0 planification), et non à une garde. Distinguer les deux change la priorité.
- **Chercher qui a déjà écrit le correctif avant d'en écrire un.** E-175 a été relevé aujourd'hui
  et son correctif dormait depuis six jours sur une branche non fusionnée. Une trouvaille se
  confronte à ce qui existe, pas seulement au tronc.

---

## 7. Seconde relecture de `8043303` et `399931a` — 2026-09-03

**Demandée par le DSI**, qui les signalait comme non relus. **Ils l'étaient** :
§2.2 et §2.4 de ce document, du 2026-08-21. Cette section ne les remplace pas —
elle répond aux **questions neuves** posées avec la demande, et **une des deux
repose sur une prémisse fausse**.

Lecture seule : aucun geste, aucune fusion, aucune écriture hors `docs/`.

### 7.1 `8043303` — l'arbitrage produit demandé N'EXISTE PAS

Le DSI demande : *« le correctif REFUSE le scan entier quand l'enrichissement
échoue. Est-ce le bon choix ? […] refuser fait dépendre la détection de la
disponibilité d'un service TIERS. »* Et il demande de le mesurer sans le trancher.

**Mesuré : le refus ne porte pas sur le scan.**

```
git show 8043303 -- backend/routes/cve.py | grep '^@@'
   @@ -273,6 +273,32 @@ def cve_reprioritize():
```

**L'unique hunk côté routes est ajouté DANS `cve_reprioritize()`.** Le chemin de
scan n'est pas touché. Et il n'y a **qu'un seul lecteur** des deux drapeaux dans
tout le backend :

```
git grep -n "kev_echoue\|epss_echoue" security/backend-cve -- 'backend/*.py'
   cve_enrich.py   : les definitions et la production
   routes/cve.py:311 : LE SEUL LECTEUR
```

Et `cve_enrich.py:24` le documente en clair : *« le scan CVE n'échoue jamais à
cause de l'enrichissement »*.

> **Le correctif fait exactement la distinction que le DSI craignait qu'il
> écrase** : pendant un **scan**, des findings non enrichis s'écrivent ; pendant
> une **re-priorisation**, écrire du vide est refusé. §2.2 le disait déjà, et la
> mesure du hunk le confirme. **Il n'y a pas d'arbitrage à remonter à
> l'exploitant.**

### 7.2 `8043303` — ce qu'il ne ferme pas : deux observations, aucune bloquante

**a) Le refus est plus LARGE que le défaut.** Le défaut était l'effacement de
`kev` (`1 if f.get('kev') else 0` → 0 partout). Le refus, lui, se déclenche sur
`kev_echoue` **ou** `epss_echoue`. Une panne EPSS seule bloque donc une
re-priorisation dont les données KEV sont intactes.

**C'est un élargissement délibéré et défendable** — `priority_score` se recalcule
sur les deux — mais il vaut d'être dit : *le correctif est fail-closed sur un axe
que le défaut ne touchait pas.*

**b) Rien ne DATE les données conservées.** Le message dit *« les données
existantes ne sont pas écrasées »*, ce qui est juste. Mais ni la réponse ni
l'écran ne disent **de quand** date le dernier enrichissement réussi. Un
exploitant qui relit un tableau KEV après trois refus successifs ne peut pas
savoir s'il regarde des données d'hier ou de trois semaines. **Non bloquant, hors
périmètre de ce correctif** — c'est une capacité manquante, pas un défaut
introduit.

### 7.3 `399931a` — LA MOITIÉ « PARAMÈTRES DE CHEMIN » N'A AUCUN EFFET, ET PAS POUR LA RAISON ANNONCÉE

Le DSI classe ce correctif *« inerte par absence de porteur, compensé »* et me
demande de remesurer. **Mesuré : l'inertie est RÉELLE, et sa cause est
STRUCTURELLE — pas une absence de porteur.**

Relevé par AST sur les 230 routes de `backend/routes/` :

| mesure | valeur |
|---|---|
| routes portant `@require_machine_access` | **116** *(le DSI dit 114)* |
| routes avec un paramètre de chemin | 34 |
| … dont un paramètre nommé `machine_id`/`server_id`/`mid` | **4** |
| routes portant le décorateur **ET** un paramètre de chemin | **9** |
| … dont un nommé machine | **1** |

**Mon « 4 » de §2.4 et le « 1 » du DSI sont tous deux justes : ils répondent à
deux questions.** Le mien compte les routes dont le décorateur *lirait* le
paramètre s'il était appliqué ; le sien compte celles où il *est* appliqué.

Et voici la structure :

```
/supervision/overrides/<int:machine_id>   GET   role:2 + perm   PAS de decorateur
/supervision/overrides/<int:machine_id>   POST  role:2 + perm   PAS de decorateur
/supervision/agents/<int:machine_id>      GET   role:2 + perm   PAS de decorateur
/supervision/machines/<int:mid>/profile         role:2 + perm   decorateur PRESENT
```

**La seule route qui porte les deux exige `role:2`** — et
`check_machine_access` commence par `if role_id >= 2: return True`. **Le
décorateur y est donc inerte.** C'est la réserve de §2.4, désormais mesurée sur
la population entière plutôt que sur une route.

**Et l'ajouter aux trois autres ne changerait rien** : elles exigent aussi
`role:2`. **Aucune route ne peut bénéficier de la lecture des paramètres de
chemin, et aucun porteur futur ne l'activerait** — il faudrait un appelant de
rôle 1, que les quatre routes refusent avant le décorateur.

> **La distinction porte.** *« Inerte par absence de porteur »* se réveille au
> premier `UPDATE` sur `permissions` — c'est le porteur dormant d'E-236.
> *« Inerte par structure »* ne se réveille pas : il faudrait changer les gardes
> de rôle des quatre routes. **La seconde est stable, et c'est une meilleure
> nouvelle que ce que le DSI classait.** Mais elle rend le message de commit
> faux pour une raison plus profonde qu'une circonstance.

**Le correctif reste juste et souhaitable** : il ferme le piège pour toute route
future, et **son autre moitié — collecter TOUTES les sources au lieu de la
première — ferme réellement E-175.**

### 7.4 Le piège de la CONJONCTION, appliqué à `399931a` — et il paie

Le DSI prévient : *« une conjonction dont un membre devient faux se lit comme
entièrement vraie ; si un message annonce deux choses, vérifie les DEUX
séparément. »*

`399931a` annonce **deux** changements. Vérifiés séparément :

| moitié | verdict |
|---|---|
| collecter **toutes** les sources au lieu de la première | **ferme E-175**, réel, mesuré |
| lire les **paramètres de chemin** | **aucun effet, par structure** (§7.3) |

**Le message se lit comme entièrement vrai parce que sa première moitié l'est.**

### 7.5 Deux tentatives de CASSER `399931a` — les deux se sont refermées

**a) Faux positif par homonyme.** Le patch lit désormais les `kwargs` : une route
portant un paramètre de chemin **homonyme désignant autre chose** se mettrait à
refuser à tort. Balayage : les **4** noms trouvés désignent tous réellement une
machine. Les 8 autres paramètres sous le décorateur sont `<platform>`, hors de la
liste de clés. **Aucun homonyme. Fermé.**

**b) Garde sans objet.** Le docstring admet que sans identifiant, la route passe
sans contrôle. Balayage des 116 routes portant le décorateur, à la recherche de
celles où **aucune** clé lue n'apparaît : **1 résultat**, `/update_zabbix`.

**Lu plutôt qu'accepté** — cette sonde a déjà annoncé 24 gardes « sans objet »
là où il y en avait 1 :

```python
@bp.route('/update_zabbix', methods=['POST'])
@require_api_key
@require_machine_access
def update_zabbix():
    """Redirect temporaire vers le nouveau module supervision."""
    return redirect('/supervision/zabbix/deploy', code=307)
```

**Faux positif** : la route ne fait rien, et sa cible porte `role:2` +
`perm:can_manage_supervision` + `require_machine_access`. **Fermé.** *Troisième
fois que cette classe de sonde surdéclare, et toujours du côté qui alarme.*

### 7.6 Verdict sur ces deux commits

**Aucun des deux n'introduit de régression, de contournement ni de promesse
fausse sur le CODE.** `8043303` fait ce qu'il annonce, sans arbitrage produit à
remonter. `399931a` ferme E-175 par sa première moitié ; **sa seconde moitié est
structurellement inerte, et son message de commit revendique une couverture
qu'elle n'apporte pas.**

**Correction demandée : au message de `399931a` uniquement, pas au code.** C'est
la même demande qu'en §2.4, maintenant étayée par la population complète.

**Je ne fusionne rien** — la règle du dépôt exige un accord verbal explicite de
l'exploitant pour un patch de sécurité, et cet accord porte sur
`Migration-Laravel`, pas sur cette branche.
