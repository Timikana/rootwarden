# AUDIT — les quatre commandes root INDIRECTES de `backend/routes/ssh.py`

    Session   5 — securite, LECTURE SEULE. Aucune machine jointe, rien exerce.
    Mesure    2026-09-09. Lignes datees a l'arbre courant ; le TEXTE fait foi.
    Verdict   AUCUN des quatre n'est exploitable. Une reserve latente,
              une observation secondaire, et une reponse a la question posee.

---

## 0. La question posée : `sa_q` dort-il ?

**Non. Il est employé aux DEUX sites.**

```
:234   sa_q = shlex.quote(sa_name)
:245   awk -v u={sa_q}              <- patch_cmd
:283   grep -Fxq -- {sa_q}          <- atteste_cmd
```

*Le `--` de `grep -Fxq --` est en plus : il ferme l'analyse d'options même si la
valeur commençait par `-`.* **Ceinture et bretelles, et volontaire.**

---

## 1. Les quatre, avec l'origine de ce qui est interpolé

| site | interpolé | origine | protection | verdict |
|---|---|---|---|---|
| `:250` `patch_cmd` | `sa_q`, `fp_q` | `sa_name` **littéral** (`config.py:71`) · `file_path` = **sortie du `grep` DISTANT** | `shlex.quote` ×2 | **non exploitable** (§2) |
| `:287` `atteste_cmd` | `sa_q` | littéral | `shlex.quote` + `--` | sûr |
| `:872` `root_cmd` | `_key_b64` | `b64encode` **LOCAL** (`:854`) | **par CONSTRUCTION** (§3) | sûr |
| `:2881` `cmd` | `flag_str`, `username` | liste **fermée** · corps de requête **VALIDÉ** | liste + `quote` + validation | sûr, réserve §4 |

---

## 2. `:250` — le seul dont une valeur vient d'une machine

**`file_path` sort de `first_line.split(':', 1)`, où `first_line` est la sortie
d'un `grep` exécuté SUR LA MACHINE DISTANTE. Une machine hostile en dispose :
elle contrôle son `grep`.**

**`shlex.quote` protège le SHELL. Il ne protège pas l'USAGE :**

```
mv /tmp/sshd_rw_patch.tmp {fp_q}
```

*`shlex.quote('/etc/shadow')` rend `/etc/shadow` — parfaitement valide, aucune
évasion nécessaire.* **Une machine hostile pourrait donc faire écrire RootWarden
sur un chemin arbitraire, en root.**

> ⛔ **ET POURTANT CE N'EST PAS EXPLOITABLE : aucune frontière de confiance n'est
> franchie.** *L'attaquant qui contrôle le `grep` de la machine X a déjà root sur
> X — et l'écriture a lieu sur X. Il n'obtient rien qu'il n'ait déjà.*

**Ce qui me réfuterait, et je le dis pour que quelqu'un puisse le chercher :**

- *`file_path` atteignant une commande exécutée sur l'hôte RootWarden* — non
  mesuré ailleurs, tous les usages passent par `execute_as_root(client, …)` ;
- *`file_path` persisté puis rejoué contre une AUTRE machine* — non observé ;
- *un appelant de `_ensure_sshd_allows_user` qui passerait un `sa_name` non
  littéral* — `sa_name` vient de `Config.NOM_COMPTE_SERVICE`, une seule
  affectation dans le dépôt.

### 2.1 ⚠ Observation secondaire — la seule valeur qui SORT de la machine

`file_path` est réinjecté dans le message rendu à l'appelant (`:290-291`), donc
**il traverse la passerelle et atteint l'interface**.

*C'est le seul chemin par lequel une donnée d'une machine hostile quitte cette
machine.* **Le portage échappe par défaut (`{{ }}` en Blade), donc je ne le
classe pas en défaut — mais c'est la surface à regarder si quelqu'un rend ce
message en HTML brut un jour.**

---

## 3. `:872` — une garde PAR CONSTRUCTION, et c'est la meilleure des quatre

```
:854   _key_b64 = _b64.b64encode((pubkey + '\n').encode()).decode()
:867   printf '%s' '{_key_b64}' | base64 -d >> /root/.ssh/authorized_keys
```

**L'interpolation est entre apostrophes — donc une apostrophe dans la valeur
casserait tout. Elle est impossible : l'alphabet de `b64encode` est
`[A-Za-z0-9+/=]`, et l'encodage est fait EN LOCAL.**

> **Ce n'est ni du quoting ni une convention : la valeur dangereuse est
> INEXPRIMABLE.** *Le rang 1 de la hiérarchie du dépôt, atteint sans y penser.*

---

## 4. `:2881` — sûr, avec une réserve LATENTE qu'il faut nommer

**Chaîne complète mesurée :**

```
username = (data.get('username') or '').strip()
if not _validate_username(username):        <- la route VALIDE  (:2756 y mène)
  -> _valid_username_decouvert -> _motif_nom_invalide (configure_servers.py:83-94)
     vide · > 32 · nom.strip('.') == '' · ^[a-zA-Z0-9._-]{1,32}$
flag_str = ' '.join(['-f'[, '-r']])         <- LISTE FERMEE
cmd = f"/usr/sbin/userdel {flag_str} {shlex.quote(username)} 2>&1"
```

**Épreuve de la règle, cas forgés :**

```
'..' '.' '...' -> refuses    (strip('.') == '')
'a/b' '../../etc' 'a;id' 'a b' "a'b" 'a$(id)' -> refuses  (classe)
'--root=/tmp' -> refuse      (`/` et `=` hors classe)
'-R' '-rf'    -> ACCEPTES    <- le tiret initial passe
'Debian-exim' 'Timikana' -> ACCEPTES   (le cas normal du parc, deliberement)
```

> ⚠ **RÉSERVE LATENTE, pas défaut** : *un nom commençant par `-` est accepté et
> `shlex.quote` ne le protège pas — il n'ajoute aucun guillemet à `-R`.*
> **`userdel` le lira comme une OPTION.**

**Pourquoi ce n'est pas exploitable aujourd'hui** : *`userdel` prend UN opérande.
`userdel -f -R` consomme le nom comme option et se retrouve sans opérande →
erreur d'usage, code non nul, rien fait.* **Le `--` qui ferme l'analyse d'options
existe à `:283` pour `grep` ; il n'est pas ici.**

**Ce qui rendrait la réserve vivante** : *une option COURTE et SANS ARGUMENT qui
soit destructrice, ou une évolution de la commande vers deux opérandes.*
**Poser `--` avant le nom la fermerait par construction, et coûte deux
caractères.**

---

## 5. Ce que je n'ai pas mesuré

    NON MESURE   si un compte reel a emprunte l'un de ces chemins : les quatre
                 voies d'acces a la base me sont fermees
    NON EXERCE   aucune machine jointe, aucun `sshd_config` lu ni ecrit
    NON REPRIS   `deploy_service_account` n'appelle pas `_ensure_sshd_allows_user`
                 la ou `deploy_platform_key` l'appelle — c'est K4, dans les
                 interdits, et c'est un arbitrage deja remonte
