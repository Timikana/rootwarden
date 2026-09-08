# QA — Les 15 interpolations root, croisees ORIGINE x NEUTRALISATION

Lecture seule. Aucun `# nosemgrep`, aucun guillemet ajoute, aucun geste `updates`.
Mesure du 2026-09-08 sur `backend/services_manager.py` et `backend/routes/updates.py`.

Axes appliques : origine **1** litteral / **2** calcule serveur / **3** entree ou base ;
neutralisation **a** aucune / **b** `shlex.quote` / **c** rejet par liste blanche /
**d** typage-bornage / **e** confinement.

## 0. LA CLASSE INVISIBLE : zero ici, et l'instrument le prouve

Le motif `f'cmd {shlex.quote(a)} {b}'` avec `b` nu **n'existe dans aucun des deux
fichiers** : `shlex` y apparait 0 fois. Temoin que la sonde lit bien : 20 et 13
`^def ` trouves dans les memes fichiers ; contre-epreuve que le motif est trouvable :
`shlex` est present dans `scheduler.py`, `fail2ban_manager.py`, `docker_monitor.py`,
`iptables_manager.py`, `ssh_utils.py`. Le zero est un vrai zero.

## 1. LE DEFAUT : 3a, et le sink n'est pas le shell

`backend/routes/updates.py:666` et `:762`

    execute_as_root(client, f"printf '%s' '{encoded}' | base64 -d > {cron_file}", root_password)

`encoded` est du base64 : alphabet `[A-Za-z0-9+/=]`, donc **ni guillemet, ni `;`, ni
`$`, ni backtick**. Cote shell, l'encodage est une neutralisation par construction,
plus forte qu'un quote. **La regle semgrep a raison de se taire.**

Mais le sink n'est pas le shell : le flux decode est ecrit dans
`/etc/cron.d/auto_update_advanced` et `/etc/cron.d/auto_security_update_advanced`,
puis `chmod 0644` et cron redemarre. **Cron execute ce fichier en root.** Il n'y a
donc aucun metacaractere a faire passer : il suffit d'un **retour a la ligne**, que
le base64 transporte fidelement.

Origine, remontee jusqu'a l'affectation :

    :626  date  = data.get('date')      # aucune validation
    :627  time_ = data.get('time')      # aucune validation
    :653  cron_time = f"{time_.split(':')[1]} {time_.split(':')[0]} * * *"
    :662  cron_job  = f"{cron_time} root {apt_command}\n"
    :664  encoded   = base64.b64encode(cron_job.encode('utf-8'))...

Idem `:692` / `:693` pour la seconde route. Le seul garde de forme du fichier est
`strptime(date, "%Y-%m-%d")` en `:731` : il ne couvre **que** `date`, **que** dans la
branche `weekly`, et **jamais** `time_`. `time_` n'est controle nulle part.

Les deux routes : `POST /schedule_advanced_update` et
`POST /schedule_advanced_security_update`, toutes deux
`@require_api_key` + `@require_permission('can_update_linux')` + `@require_machine_access`.
Une ligne `cron.d` complete tient dans un seul champ, sans meme un retour a la ligne.

**Le voisin sain, dans le meme fichier et sur le meme sink :** `schedule_update`,
`:411-422`, n'interpole que `interval_minutes`, lu en `int(data.get(...))` — **3d**.
Meme auteur, meme cible, meme forme : une route type son entree, les deux
« advanced » ne la typent pas. L'ecart n'est pas d'architecture, il est d'oubli.

Classement : **3a**. Je ne corrige pas et je ne referme pas.

## 2. LES 15, reparties

`backend/services_manager.py` — 9 interpolations, dont **2 ne sont pas des commandes**

| ligne | variable | classe | fondement |
|---|---|---|---|
| :53 | `name` | **hors sink** | `raise ValueError(f"... {name!r}")` — message d'exception |
| :141 | `service` | **3c** | `_validate_service_name` en `:138` |
| :141 | `props` | **1** | litteral assigne en `:139` |
| :182 | `base` | **hors sink** | `raise ValueError(...)` — message d'exception |
| :190 | `service` | **3c** | validee en `:187` |
| :199 | `service` | **3c** | validee en `:196` |
| :208 | `service` | **3c** | validee en `:205` |
| :217 | `service` | **3c** | validee en `:214` |
| :226 | `service` | **3c** | validee en `:223` |
| :237 | `service` | **3c** | validee en `:234` |
| :237 | `lines` | **3d** | `lines = max(10, min(500, int(lines)))` |

Je ne gonfle pas le compte : `:53` et `:182` sont des libelles d'erreur, pas des
commandes root. Sept sites root, pas neuf.

Le rejet en `:20` est reel :

    _SERVICE_RE = re.compile(r'^[a-zA-Z0-9@_:][a-zA-Z0-9@._:-]*$')

Il refuse espace `;` `|` `&` `$` backtick `"` `'` `\` `(` `)` `>` `<` `*` `?`.

**⚠ CE QU'UN CHANGEMENT CASSE.** En Python, `$` accepte un `\n` **final**. Donc
`"nginx\n"` satisferait `_SERVICE_RE` — et un `\n` dans une commande shell est un
separateur. Ce qui l'en empeche est la ligne d'avant :

    :51      name = name.strip()

`.strip()` a l'air cosmetique ; il est **porteur**. Retire-le et les 7 sites
`3c` deviennent injectables. A dire dans le meme souffle que la validation.

`backend/routes/updates.py` — 6 interpolations

| ligne | variable | classe | fondement |
|---|---|---|---|
| :584 | `env_prefix` | **1** | litteral `:575` |
| :591 | `env_prefix` | **1** | litteral `:575` |
| :591 | `pkg_str` | **3c** | `' '.join(_validate_package_list(data.get('selected_packages')))` |
| :666 | `encoded` | **3a** | voir §1 — sain cote shell, ouvert cote cron |
| :666 | `cron_file` | **1** | litteral `:663` |
| :667 | `cron_file` | **1** | litteral `:663` |
| :762 | `encoded` | **3a** | voir §1 |
| :762 | `cron_file` | **1** | litteral `:757` |
| :763 | `cron_file` | **1** | litteral `:757` |

Hors des 15 annonces, meme fichier, meme famille : `:422` `encoded` → **3d** (le
voisin sain) ; `:498`, `:500`, `:503` `env_prefix` et `dpkg_opts` → **1** ;
`:503` `pkg_str` → **3c**.

`_SAFE_PKG` en `:439` — `^[a-zA-Z0-9][a-zA-Z0-9.+_\-]*$` — est un vrai rejet.

**Note de comportement, sans gravite mais a savoir :** `_validate_package_list`
(`:442-448`) **filtre en silence** au lieu de lever. Une entree invalide est
ecartee sans que l'appelant l'apprenne ; si toutes le sont, `pkg_str` est vide et
la commande devient `apt-get install -y <opts>` sans paquet. Pas une injection —
une divergence muette entre ce qui est demande et ce qui est fait.

## 3. Ce que ce releve dit de l'instrument

Sur ces deux fichiers, la regle semgrep se tromperait dans les deux sens :
elle signalerait 7 sites `3c` + 1 `3d` que le rejet et le typage protegent
mieux qu'un quote ne le ferait, et elle **se tairait sur les deux seuls vrais
defauts**, parce que la ou elle regarde — le shell — le base64 est irreprochable.
Le defaut est un cran plus loin, dans un fichier que cron executera en root.
