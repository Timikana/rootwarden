# DOSSIER-66 — Le jeton Telegraf est stocké en clair, et son commentaire dit le contraire

**Mesuré le 2026-09-09 entre 09:15 et 09:35 CEST. Aucun geste exercé, aucune
valeur de secret imprimée nulle part — préfixe, longueur et forme seulement.**

> `DOSSIER-55` §⑨ portait le jeton Telegraf comme la seule des onze capacités
> **délibérément non portée**, *« bloquée sur la signature du `patch 03` — la
> porter ajouterait une entrée pour stocker un secret en clair »*. Cette phrase
> est juste. Ce dossier dit **pourquoi** elle est juste, ce que je n'avais pas
> mesuré, et ce que j'ai failli écrire de faux à sa place.

---

## 1. Le vis-à-vis, dans le MÊME fichier et la MÊME table

`supervision_config` porte deux secrets. `backend/routes/supervision.py` les
traite différemment :

| | `tls_psk_value` | `telegraf_output_token` |
|---|---|---|
| écrivain | `:718` `enc.encrypt_password(psk_value)` | **aucun chiffrement** |
| lecteur | `:895` et `:1242` `decrypt_password` | `:541` `global_cfg.get(…) or ''`, brut |
| commentaire | — | `:2464` *« Chiffrer le token Telegraf si fourni »* |

**Les deux côtés sont cohérents entre eux : le jeton est en clair par
CONSTRUCTION.** Ce n'est pas un chiffrement oublié à un endroit — c'est une
colonne dont ni l'écriture ni la lecture ne chiffrent, et dont le commentaire
affirme le contraire.

```
appels de decrypt_password dans supervision.py   4
  :227  mot de passe serveur          :228  mot de passe root
  :895  PSK                           :1242 PSK
  jeton                               0
```

*Le témoin est nécessaire : `4` prouve que l'instrument trouve bien les appels de
déchiffrement, donc que le `0` du jeton n'est pas l'artefact d'un motif trop
étroit.*

Les deux sites d'écriture sont `:2475` (UPDATE, via
`COALESCE(%s, telegraf_output_token)`) et `:2499` (INSERT), tous deux alimentés
par `telegraf_token` construit à `:2465`.

### Ce qui rend le défaut invisible

`:2434-2435` remplace la valeur par `'********'` dans la réponse de l'API.

> **Le masquage protège la RÉPONSE, pas la COLONNE.** Aucune lecture de
> l'interface — ni un relevé au réseau, ni la page de supervision — ne peut
> révéler que la base tient ce secret en clair. *Un gage se juge sur son PUITS et
> sur son DOMAINE, pas sur sa qualité : ce masquage est irréprochable, et son
> domaine est l'affichage.*

Et le portage a la même discipline, par un chemin différent :
`Supervision.php:297-298` ne lit que la **présence** des deux secrets
(`selectRaw("… IS NOT NULL AND … <> '' ")`), et son docblock `:250` l'écrit. **Le
portage ne fait donc pas sortir le secret de la base** — ce qui est correct, et
ce qui explique aussi pourquoi personne n'a vu le stockage.

---

## 2. ⛔ CE QUE J'AI FAILLI ÉCRIRE, ET QUI ÉTAIT FAUX

J'étais à un mot d'écrire : *« un secret est déjà stocké en clair, dans le
service »*. La table est **vide** :

```
SELECT COUNT(*), COUNT(DISTINCT platform) FROM supervision_config;   ->   0   0
```

**Le défaut est ARMÉ, pas exercé.** `patch 03` serait la **première** écriture
dans cette colonne. La formulation de `DOSSIER-55` — *« la porter ajouterait une
entrée pour stocker un secret en clair »* — était exacte, et la mienne l'aurait
contredite en la présentant comme une découverte plus grave.

> **Une alarme qui dépasse la mesure coûte la crédibilité de la mesure.** Le
> défaut de code est réel ; l'urgence que j'allais lui prêter ne l'était pas.

### Et le témoin qui a produit cette correction

Ma première lecture en base a rendu **aucune ligne, sans erreur**. J'ai failli la
lire comme « les valeurs ne sont pas mesurables ». Le témoin — un `COUNT(*)` sur
la même table, dans la même commande — a rendu `0 0`, et c'est lui qui a dit
*« la table est vide »* au lieu de *« la requête n'a pas abouti »*.

⚠ Et la cause de l'échec initial vaut d'être écrite parce qu'elle est
reproductible : `grep -oP '(?<=^MYSQL_ROOT_PASSWORD=).*'` a échoué **en
silence**. `grep` est ici une **fonction enveloppant ugrep**, où le lookbehind ne
passe pas. La forme juste garde en plus le secret hors de la ligne de commande :

```
sudo -n docker exec rootwarden_db sh -c 'mysql -u root -p"$MYSQL_ROOT_PASSWORD" …'
```

---

## 3. Quatre sites lisent la présence d'un secret en comparant des OCTETS

```
laravel/app/Services/ClePlateforme.php:65   password IS NOT NULL AND password <> ''
laravel/app/Services/ClePlateforme.php:66   root_password …
laravel/app/Services/Supervision.php:297    tls_psk_value …
laravel/app/Services/Supervision.php:298    telegraf_output_token …
```

**Ces quatre sites sont sûrs aujourd'hui, et ils le sont par CONTINGENCE.**
`encryption.py:184` rend `""` pour une entrée vide, donc un secret vide écrit par
Python laisse la colonne à `''` et le prédicat rend faux — correctement. Le
défaut n'apparaîtrait que si un écrivain **PHP** chiffrait `''` en une valeur non
vide : il y en a **zéro** pour ces quatre colonnes.

> **Un correctif de chiffrement doit préserver cette contingence.** Chiffrer le
> jeton sans conserver « vide ⟶ vide » rendrait `jeton_pose` vrai pour un secret
> absent, et le même piège attend les trois autres colonnes.

---

## 4. Ce qui revient à l'exploitant

**① Signer ou refuser `patch 03`, en sachant ceci** : le porter écrirait le
premier jeton de cette colonne, et la colonne n'est pas chiffrée. **L'ordre juste
est donc : chiffrer d'abord, porter ensuite.** L'inverse crée un secret en clair
qu'une migration devra rattraper.

**② Valider ou non le correctif de chiffrement**, assigné à
`gestion-ssh-key-0b` sur branche `security/`, PR ouverte et **non fusionnée** —
ce dépôt ne fusionne pas un correctif de sécurité sans mot explicite.

⚠ **Rien dans ce dossier n'est un geste** : aucune écriture en base, aucun
redémarrage, aucune migration. Le seul accès à la base est un `SELECT` de forme
qui n'a imprimé ni valeur ni fragment de valeur.

---

# RECTIFICATION du 2026-09-09 10:05 — ma spécification du correctif était incomplète, et son défaut était SILENCIEUX

Deux corrections de `gestion-ssh-key-0b`. **Je les ai rejouées avant de les
relayer** — la règle que je m'impose depuis qu'une correction reçue m'a eue
précisément parce qu'elle me chargeait. **Les deux tiennent.**

## ① `:541` n'est pas un lecteur : il alimente un DÉPLOIEMENT

Ma §1 le classait « lecteur ». C'est faux, et l'erreur est de conséquence :

```
def _build_agent_config_content(...)          :500     ← la fonction englobante
    output_token = global_cfg.get('telegraf_output_token') or ''    :541
    content += f'  token = "{output_token}"\n'                      :557
appelants                                     :1951  et  :2144
```

**Le jeton part dans le TOML déposé sur la machine cible.** Donc :

> **Chiffrer l'écriture sans déchiffrer à `:541` déploierait `sodium:…` comme
> jeton.** Telegraf démarre, sa configuration est syntaxiquement valide, et
> l'authentification échoue **à la sortie InfluxDB** — dans un agent distant,
> loin du geste, sans erreur côté produit.

C'est la jumelle du défaut de `working_dir` : là le gage **manquait**, ici le
gage serait **posé** et le puits est ailleurs. *Ma consigne « à l'image du PSK »
laissait déduire le déchiffrement sans le dire — et une spécification dont le
point critique doit être déduit est une spécification incomplète.*

**Mon rejeu, indépendant :** `def` à `:500`, interpolation à `:557`, deux
appelants. Confirmé au numéro de ligne.

## ② `VARCHAR(512)` borne le clair à 338 caractères

```
telegraf_output_token   varchar(512)   512
tls_psk_value           varchar(512)   512

clair  16 -> chiffre  83   sodium:   aller-retour identique
clair  88 -> chiffre 179   sodium:   aller-retour identique
clair 200 -> chiffre 327   sodium:   aller-retour identique
clair 338 -> chiffre 511   sodium:   TIENT
clair 339 -> chiffre 515   sodium:   DEPASSE
```

**Le chiffre de `0b` est exact au caractère.** Chiffrer rétrécit l'entrée
acceptée de 512 à 338 **sans qu'aucune ligne ne le dise**. Un jeton InfluxDB fait
~88 caractères, donc la borne n'est pas atteinte en pratique — mais elle devient
une limite tacite du produit.

**Et le mode d'échec est bénin** : `@@sql_mode` porte `STRICT_TRANS_TABLES`, donc
un dépassement **lève** au lieu de tronquer. *Une valeur indéchiffrable ne peut
pas s'installer en base par cette voie.*

## ③ Ce que `0b` a mesuré et qui FERME une piste plutôt que d'en ouvrir une

Le jeton est interpolé brut dans du TOML entre guillemets : une valeur portant
`"` ou un saut de ligne injecterait des directives Telegraf, `[[inputs.exec]]`
comprises. **Capacité marginale nulle** : `extra_config` est ajouté **verbatim**
au même contenu (`:519`, `:534`, `:570`), sur la **même route**, sous les **mêmes
gardes**. Le même acteur peut déjà écrire du TOML arbitraire, par conception.

> **Un défaut dont l'exploitation demande une capacité déjà détenue — et
> OFFERTE — n'est pas une élévation.** *C'est le genre de mesure qui retire un
> point de la liste, et elle vaut autant que celle qui en ajoute.*

## ④ L'entrée vide : la contingence est préservée

`encryption.py:183-184` rend `""` pour `''` **et** pour `None` — mesuré, longueur
0, sans préfixe. Les quatre sites du portage (`Supervision.php:297-298`,
`ClePlateforme.php:65-66`) restent justes. *Ils le sont parce qu'aucun écrivain
PHP n'existe pour ces colonnes, pas parce qu'ils sont corrects.*

## ⛔ ⑤ ET LE CORRECTIF N'A PAS D'EXÉCUTANT

**`0b` décline l'écriture : sa charge est l'analyse, en lecture seule sur le code.
C'est la cinquième assignation d'écriture qu'il décline aujourd'hui.** Il a fait
ce que je demandais explicitement — rejouer plutôt que croire — et il a rendu
deux corrections que je n'avais pas.

**Un pair ne peut pas élargir son propre périmètre, et je n'ai pas à le lui
demander.** Le mien, sur ce tour, est `DECISIONS-DSI.md` et les `DOSSIER-*.md`.

```
le correctif tient en DEUX gestes
    chiffrer a  :2465
    dechiffrer a :541          <- celui que ma specification omettait
```

**Ce qui manque n'est pas une spécification, c'est un exécutant.** Et c'est la
deuxième fois de la journée que le chantier bute sur ce mur — la garde de
`socle_avertissement` livrée par `gestion-ssh-key-c6` (`146886eb`, branche
`security/garde-socle-avertissement`) est dans le même cas : **elle n'a jamais
été exécutée**, parce qu'il n'y a pas de `php` sur l'hôte.

⚠ Et sur ce dernier point je mesure mieux que son auteur : **`php 8.4.25` existe
dans `rootwarden_laravel`.** L'exécuter ne demande donc aucun outil manquant — il
demande d'écrire le fichier dans `laravel/tests/`, qui est monté en bind. *Le
blocage n'est pas technique, il est de périmètre.*

---

# RECTIFICATION du 2026-09-09 10:25 — mon témoin comptait une SOUS-CHAÎNE, et deux fonctions

Le §1 de ce dossier écrivait :

```
appels de decrypt_password dans supervision.py   4
```

**Ce `4` compte une sous-chaîne, pas une fonction.** Mesuré en séparant :

```
`decrypt_password(`         4     <- ce que mon temoin comptait
`enc.decrypt_password(`     2     :895  :1242   les DEUX sur le PSK
`server_decrypt_password(`  2     :227  :228    une fonction DIFFERENTE
somme 2 + 2 = 4                   == le compte par sous-chaine : oui
```

Le corps du §1 nommait correctement les sites — `:227`/`:228` y sont annotés
« mot de passe serveur ». **Mais le nombre mis en avant était mon TÉMOIN**, celui
qui devait prouver que le `0` du jeton n'est pas l'artefact d'un motif trop
étroit. *Un témoin bâti sur une sous-chaîne est plus faible que je ne l'ai
présenté : il attestait la présence de deux fonctions homonymes, pas deux appels
de celle qui compte.*

**La conclusion ne bouge pas** — le témoin correct est `enc.decrypt_password` = 2,
les deux sur le PSK, zéro sur le jeton — **et le jeton est toujours en clair** :

```
chiffrement du jeton avant stockage       0 appel
TEMOIN : chiffrement du PSK dans le fichier  1 appel  (:718)
```

> **Le sens de mon erreur est celui qui dédouane MON INSTRUMENT** : un témoin
> gonflé fait paraître la preuve plus solide qu'elle n'est. Ce n'est pas le
> résultat qui était faux, c'est la force que je lui prêtais.

## Et `:2466-2467` n'est PAS un changement récent

`0b` m'annonce comme *« un vrai changement en revanche, et il est bon »* le garde
qui empêche le masque `'********'` d'écraser la valeur existante. **Daté :**

```
2464  # Chiffrer le token Telegraf si fourni
2465  telegraf_token = data.get('telegraf_output_token', '')
2466  if telegraf_token == '********':
2467      telegraf_token = None  # garder l'existant

dernier commit touchant ces lignes :
  2129a2cf   2026-04-11 18:30   feat: module supervision multi-agent
```

**Cinq mois, et c'est le commit d'origine du module.** C'est le miroir exact de
ses deux items périmés : il a rapporté comme un changement une chose
préexistante. *Et la direction est encore la rassurante — « un défaut réel
corrigé ».*

⚠ **Sa mise en garde reste juste, et elle vaut pour ce dossier** : le garde du
masque et le chiffrement *« se ressemblent assez pour être confondus par qui lit
vite »*. Ce sont deux propriétés distinctes de la même variable, et une seule des
deux existe.

---

# DURCISSEMENT du 2026-09-09 10:35 — le commentaire n'a JAMAIS été vrai, et l'asymétrie est native

Signalé par `0b`, **et mon `blame` va plus loin que le sien** :

```
2129a2cf3  2026-04-11 18:30  :2464   # Chiffrer le token Telegraf si fourni
2129a2cf3  2026-04-11 18:30  :2465   telegraf_token = data.get('telegraf_output_token', '')
2129a2cf3  2026-04-11 18:30  :2466   if telegraf_token == '********':
2129a2cf3  2026-04-11 18:30  :2467       telegraf_token = None
2129a2cf3  2026-04-11 18:30  :718    psk_encrypted = enc.encrypt_password(psk_value)   <- LE PSK
statut du fichier dans ce commit : A  (il le CREE)
TEMOIN : :369 rend 70aff91e7, 2026-08-22 — le blame discrimine bien
```

**Le commentaire, le code qui ne chiffre pas, ET le chiffrement du PSK sont tous
les trois du même commit — celui qui crée le fichier.**

> **Ce n'est donc pas « le jeton a été oublié quand le PSK a été durci plus
> tard ».** Les deux secrets ont été écrits dans le même geste, l'un
> correctement et l'autre pas, **avec un commentaire affirmant que le mauvais
> était bon.** Le commentaire n'a jamais été vrai : lui et son démenti sont nés
> ensemble.

**Conséquence de méthode, et c'est elle qui compte** : aucune bissection ne
l'aurait trouvé, aucun *« qu'est-ce qui a changé ? »* ne l'attrape, aucune chasse
à la régression n'y mène. **Un défaut natif est invisible à tout instrument qui
cherche une dérive** — et c'est la classe entière d'outils qu'on emploie par
réflexe sur un fichier de cinq mois.

## Et la nuance de `0b` sur mon témoin, qui m'aggrave

J'avais écrit que mon témoin gonflé de 2 à 4 « dédouanait mon instrument ». Il
ajoute, et c'est juste :

> **Un témoin gonflé ne rend pas seulement la preuve plus solide — il rend le
> `0` du jeton plus ÉTONNANT, donc plus crédible comme trouvaille.** Le témoin
> et la mesure ne se contrôlent pas séparément : c'est leur **RAPPORT** qui porte
> la conclusion.

*`0 sur 4` se lit comme une anomalie ; `0 sur 2` comme une possibilité. Le même
`0`, deux forces de conviction — et c'est le dénominateur que j'avais gonflé.*

Le témoin correct, consolidé :

```
enc.decrypt_password(       2    :895 :1242   les deux sur le PSK
server_decrypt_password(    2    :227 :228    fonction differente
encrypt_password(           1    :718         le PSK, cote ECRITURE
le jeton                    0 chiffrement · 0 dechiffrement
```
