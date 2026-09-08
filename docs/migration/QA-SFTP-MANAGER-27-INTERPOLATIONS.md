# `backend/sftp_manager.py` — les interpolations en root, classées par ORIGINE

**Mesuré le 2026-09-08 entre 11:37 et 11:52 CEST**, en lecture seule. Aucune
annotation, aucun `shlex.quote` ajouté, aucun geste SFTP exercé.

> ## Le résultat en deux lignes
> **Aucune des interpolations signalées n'est une injection de shell.** Elles sont
> toutes gardées — mais par une **validation en liste blanche**, une forme que la règle
> ne sait pas reconnaître.
>
> **⛔ Et le vrai défaut du fichier n'est PAS dans les 27.** Il est à `:153`, et c'est
> une garde placée du mauvais côté de sa condition.

---

## 1. La protection de ce fichier n'est pas `shlex.quote` — c'est le REJET

    _USERNAME_RE = ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$
    _PATH_RE     = ^/[A-Za-z0-9._/-]{1,510}$   + refus explicite de `..`

**Mesuré caractère par caractère** : `;` `|` `&` `$` `` ` `` `"` `'` espace `\` `(` `)`
`>` `<` `*` `?` sont **tous refusés** par les deux classes.

⚠ **Un seul les traverse : `\n`** — et **ma première attribution était FAUSSE.**
Corrigée le 2026-09-08 12:05, sur la mesure d'un pair (`gestion-ssh-key-c1`) que j'ai
reproduite :

    valeur                       sans MULTILINE (l'actuel)   avec MULTILINE
    '/srv/data\n'   (final)       refuse par le `.strip()`    —
    '/srv\nPermitRootLogin yes'   REFUSE                      ACCEPTE  ⛔
    et apres .strip()             REFUSE                      ACCEPTE  ⛔

**Deux vecteurs, deux mécanismes différents :**
- un saut de ligne **terminal** est retiré par le `.strip()` (`:59`, `:66`) ;
- un saut de ligne **intérieur** est refusé parce que **`_PATH_RE` n'a pas
  `re.MULTILINE`** (`flags = 32`). Sans ce drapeau, `$` ne s'apparie pas en milieu de
  chaîne.

> **J'avais écrit « fermé par la ligne d'à côté ». C'est vrai du seul cas terminal.**
> Ce qui ferme le vecteur d'injection est **l'absence d'un drapeau**, pas la présence
> d'un `.strip()`.
>
> **Et cette fragilité est pire que celle que j'avais nommée** : ajouter
> `re.MULTILINE` un jour, pour une raison sans rapport, rouvrirait le trou **sans
> toucher à la garde ni au `.strip()`**. Un `.strip()` supprimé se voit dans un diff de
> la fonction de validation ; un drapeau ajouté se lit comme un détail de motif.

> **Une liste blanche qui rejette est plus forte qu'un échappement qui transforme** —
> et la règle `rw-shell-fstring-execute-as-root` ne cherche que le second.
> **106 signalements sur l'arbre pour une règle qui ne connaît qu'une forme de
> protection.**

---

## 2. Les 27, par classe

### Classe A — constante de module (sûre par construction)

    :76   SSHD_CONFIG_D_DIR · FILE_PREFIX · FILE_SUFFIX     littéraux en majuscules

### Classe B — déjà échappée / neutralisée en amont

**Aucune au sens de `shlex.quote`.** *Ce fichier n'emploie pas l'idiome `x_q =
shlex.quote(x)` — il n'y a donc pas ici les faux positifs que vous annoncez.*

**Mais une neutralisation d'une autre nature, et elle mérite la classe** :

    :188  marker  = f"RW_HEREDOC_{secrets.token_hex(6)}"
    :189  cmd     = f"cat > {target} <<'{marker}'\n{content}\n{marker}\n"

Le heredoc est **cité** (`<<'…'`) : `content` n'est pas interprété par le shell. Et le
marqueur est un **aléa de 6 octets**, donc `content` ne peut pas le deviner pour clore
le heredoc par avance. *Deux protections délibérées, ni l'une ni l'autre visible à une
règle qui cherche `shlex.quote`.*

### Classe C — calculée côté serveur (24 sites)

| valeur | origine | sites |
|---|---|---|
| `target` | `_target_path(username)` → constantes + `_validate_username` | `:189` `:227` `:231` `:240` `:243` `:259` `:262` `:302` `:307` `:349` `:353` `:360` `:363` |
| `path` | `_target_path(username)`, `:171` | `:172` (×2 dans la même commande) |
| `tmpfile` | `f"/tmp/rootwarden-sftp-{rand}.tmp"`, `rand = secrets.token_hex(8)` — **hexadécimal seul** | `:182` `:231` `:284` `:353` `:382` |
| `backup_in_place` | `f"{target}.rwbak"` — dérivée de `target` | `:227` `:240` `:259` `:273` `:302` `:307` `:320` `:349` `:360` `:373` |
| `marker` | `secrets.token_hex(6)` | `:189` |

### Classe D — venue d'une ENTRÉE ou de la BASE

    chroot_dir   policy.get('chroot_dir')   <- la BASE
                 -> VALIDE a :148, inconditionnellement, avant usage a :149
    working_dir  policy.get('working_dir')  <- la BASE
                 -> ⛔ VOIR §3

**`chroot_dir` est la seule classe D correctement gardée.** Sa validation précède son
unique usage, sans branche entre les deux.

---

## 3. ⛔ LE DÉFAUT — `:153`, une garde du mauvais côté de sa condition

    :127   working_dir = policy.get('working_dir')          # de la BASE, NON valide
    :147   if chroot_dir:
    :148       chroot_dir = _validate_path(chroot_dir, …)   # valide  ✅
    :151   if sftp_only:
    :153       "    ForceCommand internal-sftp" + (f" -d {working_dir}" if working_dir else "")
                                                  ↑ INTERPOLE SANS VALIDATION
    :157   elif working_dir:
    :158       working_dir = _validate_path(working_dir, …) # valide  ✅
    :162       lines.append(f"    # working_dir={working_dir} (informatif…)")
                             ↑ dans un COMMENTAIRE de configuration

> **La validation est présente exactement là où la valeur est inoffensive — une ligne
> de commentaire — et absente exactement là où elle est employée : une directive
> `ForceCommand`.**

### 3.1 Ce n'est PAS une injection de shell, et c'est important de le dire

Le contenu part par un heredoc **cité** (`:189`). Le shell ne l'interprète pas.
**C'est une injection dans `sshd_config`** : une valeur portant un saut de ligne écrit
des directives arbitraires dans le bloc `Match User`, puis `systemctl reload ssh` est
appelé (`:269` en lit le verdict).

*La règle signale une injection de shell qui n'existe pas, et ne voit pas l'injection
de configuration qui existe.*

### 3.2 La chaîne, mesurée de bout en bout

    backend/routes/policies.py:370   'working_dir': data.get('working_dir') or None
                                     -> BRUT, aucune validation a l'ecriture
    colonne                          varchar(512) — accepte un saut de ligne
    garde de la route                @require_role(3) + @require_machine_access
                                     -> il faut deja le role le PLUS HAUT

**La sévérité est bornée par le rôle 3** : ce n'est pas une élévation de privilège,
c'est un défaut de défense en profondeur. *Je le dis parce que l'inverse serait une
alarme fausse dans le sens qui effraie.*

### 3.3 ⚠ Et un commentaire du portage AFFIRME le contraire

`laravel/app/Services/AccesSftp.php:71` :

> *« Les chemins `chroot_dir` et `working_dir` passent par `_validate_path` : absolu,
> sans traversée. **C'est vérifié AU BACKEND, donc une requête forgée ne le contourne
> pas.** »*

**Vrai pour `chroot_dir`. Faux pour `working_dir` quand `sftp_only` est vrai** — c'est-
à-dire dans le seul cas où la valeur atteint une directive.

---

## 4. Le cas que la règle NE PEUT PAS voir — je n'en ai trouvé aucun ici

Vous demandiez de signaler un `f"cmd {shlex.quote(a)} {b}"` avec `b` nu, que l'exemption
de région laisserait passer. **`sftp_manager.py` n'emploie pas `shlex.quote` du tout :
ce fichier ne peut pas porter ce cas.** *À chercher dans les fichiers qui, eux, mêlent
les deux styles.*

---

## 5. Ce que je n'établis pas

- **je n'ai exercé aucun déploiement** : la chaîne est établie par lecture, du corps de
  la requête jusqu'à la ligne écrite. Qu'un saut de ligne survive effectivement au
  heredoc et au rechargement de `sshd` n'est **pas mesuré** ;
- je n'ai pas vérifié si le PORTAGE valide `working_dir` avant de l'envoyer au backend —
  et ça ne changerait rien : le commentaire cité affirme que la garde est **au backend**,
  précisément pour qu'une requête forgée ne la contourne pas ;
- les 79 autres signalements de la règle, hors de ce fichier, ne sont pas classés.
