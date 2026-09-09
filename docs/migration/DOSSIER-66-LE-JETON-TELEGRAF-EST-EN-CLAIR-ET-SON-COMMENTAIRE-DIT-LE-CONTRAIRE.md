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
