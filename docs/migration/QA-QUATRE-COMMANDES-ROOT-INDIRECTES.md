# QA — les 4 commandes root INDIRECTES restantes

**Mesuré le 2026-09-09, 02:39–03:10 CEST.** Lecture seule : aucun geste `wazuh`
exercé, aucune connexion SSH, aucune base touchée. L'instrument de référence
(`backend/tests/test_commandes_root_indirectes.py`) rendait au lancement
`227 appels · 37 INDIRECTES · 10 AVEUX`, référence tenue, `exit 0`.

## 0. Tableau

| site | valeurs interpolées | gage | PUITS | verdict |
|---|---|---|---|---|
| `wazuh.py:422` | `env_vars`, `pkg_deb` | `shlex.quote`×3 + `_GROUP_RE` + construction | shell root → XML `ossec.conf` | **SÛR**, une réserve nommée |
| `wazuh.py:638` | idem | idem (garde à `:569`) | idem | **SÛR**, même réserve |
| `sftp_manager.py:173` | `path` (×2) | `_validate_username` (rejet) | shell root | **SÛR** |
| `sftp_manager.py:195` | `target`, `marker`, `content` | heredoc **quoté**, marqueur 48 bits | **`sshd_config`** | ⛔ **gage sain, puits ouvert** |

---

## 1. `wazuh.py:422` et `:638` — SÛRS, et le puits a été regardé

Les deux sites sont structurellement identiques (`install()` / `install_all()`).
`install_cmd` est une f-string multi-ligne liée à un nom : d'où son invisibilité
à `rw-shell-fstring-execute-as-root`. **Ses trois entrées sont gardées deux fois.**

    manager   = cfg['manager_ip']       shlex.quote  ET  _IP_OR_FQDN_RE a l'ECRITURE
    group     = requete OU cfg          shlex.quote  ET  _GROUP_RE.fullmatch (:339 / :569)
    reg_pwd   = _dec(...)               shlex.quote  ET  ——  (aucune garde a l'ecriture)
    pkg_deb   = _wazuh_pkg_specs(...)   SUR PAR CONSTRUCTION

`_wazuh_pkg_specs` (`:159-172`) **ne peut rien rendre d'autre** que le littéral
`'wazuh-agent'` ou `f'wazuh-agent={chiffres.points-chiffres}'` : tout format non
conforme **retombe sur le littéral** au lieu de lever. *Il n'y a pas d'exception à
contourner — c'est une garde par construction, pas un contrôle.*

**Le puits, puisqu'il fallait le nommer.** `WAZUH_MANAGER` et `WAZUH_AGENT_GROUP`
sont consommés par le paquet et finissent dans le **XML de `/var/ossec/etc/ossec.conf`**,
lu par un service root. Le gage `shlex.quote` ne protège que le shell. **Mais les
deux valeurs sont validées À L'ÉCRITURE** (`save_config:246` et `:250`) par des
classes `^[a-zA-Z0-9._-]$` et `^[a-zA-Z0-9_-]$` : **aucun métacaractère XML n'y est
exprimable.** Le puits est couvert, par une garde qui n'a pas été posée pour lui.

⚠ **RÉSERVE NOMMÉE — `registration_password`.** C'est la **seule** valeur de
`wazuh_config` sans validation à l'écriture (`save_config:238`, chiffrée puis
stockée). Son gage shell est bon ; son puits XML est atteignable.
**Portée réelle : nulle en capacité marginale** — l'acteur requis (`role 2` +
`can_manage_wazuh`) peut déjà déclencher une installation root arbitraire sur les
machines désignées. *Un défaut dont l'exploitation demande une capacité qu'on a
déjà n'est pas une élévation.* Consigné, non classé exploitable.

### 1.1 Un fait d'accès, qui n'est PAS un trou

`install_all()` n'a pas `@require_machine_access` et sa docstring l'argumente :
`check_machine_access` rendrait `True` sans condition pour son public.
**Vérifié au code** (`helpers.py:364-365` : `if role_id >= 2: return True`) —
l'argument est exact.

> **Et le symétrique n'est pas dit** : `install()` PORTE ce décorateur **et**
> `@require_role(2)`. Il est donc **inerte pour son propre public**, exactement
> comme il le serait sur `install_all()`. Les deux routes ont le même contrôle
> d'accès effectif ; la différence est **décorative**. *Un lecteur qui compare les
> deux listes de décorateurs conclut l'inverse.*

---

## 2. `sftp_manager.py:173` — SÛR

    cmd = f"test -f {path} && cat {path} || echo __NOT_FOUND__"

`path` = `_target_path(username)` : trois constantes littérales encadrant un nom
passé par `_validate_username` — `.strip()` puis `fullmatch` sur
`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`. **C'est le REJET qui neutralise** : ni espace, ni
`/`, ni métacaractère n'est exprimable. Puits = le shell seul. **Qualifié.**

---

## 3. ⛔ `sftp_manager.py:195` — LE GAGE EST IRRÉPROCHABLE, LE PUITS EST OUVERT

    :193  marker = f"RW_HEREDOC_{secrets.token_hex(6)}"
    :194  cmd = f"cat > {target} <<'{marker}'\n{content}\n{marker}\n"
    :195  execute_as_root(client, cmd, root_password, timeout=15)

**Les trois interpolations sont saines pour le SHELL :**

- `marker` — 48 bits d'hexadécimal, imprévisible : le heredoc ne peut pas être
  terminé par le contenu ;
- `target` — **toujours `tmpfile`** aux deux appelants réels (alphabet hexadécimal) ;
- `content` — dans un heredoc **QUOTÉ** : aucune expansion shell.

**Mais le puits n'est pas le shell.** `content` est écrit dans `tmpfile`, puis
`mv` vers `/etc/ssh/sshd_config.d/rootwarden-<user>.conf`, `chown root:root`,
`chmod 0644`, et **chargé par sshd**. Le puits est **la grammaire de `sshd_config`**.

### 3.1 Et une valeur non validée y arrive

    policies.py:370   'working_dir': data.get('working_dir') or None      ← BRUT
    sftp_manager:151  if sftp_only:
    sftp_manager:153      "ForceCommand internal-sftp" + (f" -d {working_dir}" …)   ← BRUT
    sftp_manager:157  elif working_dir:
    sftp_manager:158      working_dir = _validate_path(working_dir, 'working_dir')  ← GARDE
    sftp_manager:162      lines.append(f"    # working_dir={working_dir} …")        ← un COMMENTAIRE

> **La garde est sur la branche qui écrit un COMMENTAIRE. La branche qui écrit une
> DIRECTIVE VIVANTE n'en a aucune.**

**Éprouvé par évaluation forgée de la fonction réelle** (import du module du dépôt,
`ssh_utils` neutralisé, aucun appel root — l'unique dépendance lève si elle est
touchée), trois témoins :

    ① valeur benigne   '/upload'                → rendu normal, 11 lignes
    ② valeur forgee    '/upload\n    <directive>' → RENDU SANS ERREUR, 12 lignes,
                                                    la directive apparait SEULE sur sa ligne
                                                    DANS le bloc `Match User`
    ③ MEME valeur, branche elif                 → ✅ REFUSEE par _validate_path

**Le témoin ③ est le cœur du constat** : la garde existe, elle mord, elle est
au mauvais endroit.

### 3.2 Ce que les durcissements récents ne changent pas

`_validate_path` a été renforcé **deux fois** — `fullmatch` remplace `match` (ferme
la fermeture par saut de ligne) et la seconde garde `'..' in path.split('/')`
(`:69`, confirmée) rattrape ce que `_PATH_RE` laisse passer.

> **Aucun des deux n'atteint `:153`, parce que le défaut n'est pas une garde faible :
> c'est un APPEL ABSENT.** On peut durcir `_validate_path` indéfiniment.

⚠ Et `sshd -t` (`:258`) **ne rattrape pas** : une directive injectée est
syntaxiquement valide. Le filet de sécurité valide la forme, pas l'intention.
La valeur est en outre **persistée** (`policies.py:389`), donc rejouable.

**Acteur requis** : `@require_role(3)` + `@require_machine_access`. Comme en §1, un
rôle 3 dispose déjà de gestes root sur la machine — *mais ici la valeur est
STOCKÉE et le fichier produit SURVIT au déploiement*, ce qui n'est pas le cas d'une
commande. **C'est une différence de persistance, pas de privilège.**

---

## 4. ⛔ CORRECTION D'UN FAIT RELAYÉ : `_write_to_remote` a DEUX appelants

Il m'a été transmis, comme correction établie d'une session tierce, que
`_write_to_remote` a **quatre** appelants et non deux. **Mesuré :**

    backend/sftp_manager.py:228 · :396   → sftp_manager._write_to_remote  (:192)
    backend/sudo_manager.py:293 · :366   → sudo_manager._write_to_remote  (:241)

**`sudo_manager.py` définit LE SIEN**, corps identique au caractère près, et
**aucun import ne relie les deux fichiers**. Ce sont **deux objets homonymes à deux
appelants chacun.** Le compte de 4 est un compte **par NOM**.

> La correction disait : *« j'avais attribué à cet objet le compte d'un autre ».*
> **Elle fait exactement cela.** Et son coût n'est pas le chiffre : les deux
> fonctions sont identiques dans le SHELL et **leurs PUITS diffèrent** —
> `sshd_config` ici, **`sudoers` là**. Les confondre fusionne les deux domaines
> sous une seule qualification, ce qui est précisément l'erreur que ce recensement
> existe pour empêcher.
