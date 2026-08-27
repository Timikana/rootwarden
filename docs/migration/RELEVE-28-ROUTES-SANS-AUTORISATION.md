# Les 28 routes sans autorisation au-delà de la clé d'API : risque ou inventaire ?

Mesuré le **2026-08-27**, session 4. Question du Lead : *« combien exercent un geste distant, et
combien ne sont qu'en lecture ? C'est ce qui décide si le chiffre est un risque ou un inventaire. »*

**Réponse : c'est un risque.** Dix des vingt-huit modifient une machine en root, dont quatre
installent des paquets et trois posent une tâche planifiée **récurrente**.

---

## 1. Ce qui manque exactement, et ce qui ne manque pas

Ces 28 routes portent `@require_api_key` et `@require_machine_access`, **sans** `@require_role` ni
`@require_permission`. Elles font partie des **54 où le décorateur mord** : le périmètre machine
**est** vérifié.

> Ce qui manque n'est pas le **périmètre**, c'est la **capacité**. Un compte de rôle 1 ayant une seule
> machine dans son périmètre peut y lancer un `apt-get full-upgrade -y` et y installer une tâche
> planifiée qui tourne en root — parce qu'aucune de ces routes ne demande davantage que d'avoir accès
> à la machine.

*« Avoir accès à une machine » et « avoir le droit de la mettre à jour » sont deux questions, et une
seule est posée.*

## 2. Le classement, mesuré

| | routes |
|---|---|
| **joignent une machine** | **19** |
| ne la joignent pas | 9 |

### Les 19, par ce que leur commande fait réellement

| effet | n | routes |
|---|---|---|
| ⚠ **installent / mettent à jour des paquets en root, tout de suite** | **4** | `apt_update`, `update_server`, `apply_security_updates`, `custom_update` |
| ⚠ **posent une tâche planifiée qui mettra à jour plus tard, en root** | **3** | `schedule_update`, `schedule_advanced_update`, `schedule_advanced_security_update` |
| modifient l'état sans installer de nouveau paquet | **3** | `dpkg_repair` (`killall -9` + `dpkg --configure -a`), `dry_run_update` et `pending_packages` (`apt-get update`, listes de paquets réécrites) |
| **lecture distante seule** | **9** | `cve_scan`, `docker_scan`, `check_linux_version`, `last_reboot`, `test_platform_key`, `ssh_audit_scan`, `ssh_audit_config`, `ssh_audit_backups`, `apt_check_lock` |

**Les trois de la deuxième ligne sont la catégorie la plus lourde**, et elle ne se voit pas dans un
décompte « écrit / lit » : elles n'écrivent qu'un fichier, mais ce fichier est un `/etc/cron.d/*` qui
**s'exécutera en root indéfiniment**. *Un geste ponctuel se rejoue ; un geste planifié se répète sans
que personne ne le redemande.*

### Les 9 qui ne joignent pas

| | n | |
|---|---|---|
| lecture en base | **7** | `cve_results`, `cve_history`, `cve_compare`, `docker_results`, `check_window`, `server_user_keys`, `ssh_audit_results` |
| **écrit en base** | **1** | `cve_reprioritize` (`UPDATE`) |
| redirection **307** vers une route gardée | **1** | `update_zabbix` — déjà dédouanée au relevé des gardes |

`19 + 9 = 28`. ✓

---

## 3. ⚠ Trois corrections de mes propres sondes, dans le même relevé

Je les écris parce qu'elles disent où ce document peut encore se tromper.

1. **J'ai d'abord annoncé 18 routes joignant une machine. C'est 19.** Erreur d'addition sur un relevé
   correct — la même que celle qui a produit le « 58 » de la veille, et elle coûte le même recoupement.
2. **Ma première classification lisait les docstrings.** « Vérifie si apt/dpkg est verrouillé » a été
   comptée comme une commande parce qu'elle contient `apt `. Sixième fois qu'une de mes sondes compte
   de la prose pour du code.
3. **Ma deuxième lisait le NOM de la variable, pas sa valeur.** `execute_as_root(client, command, …)`
   passait l'identifiant `command` ; la sonde a classé **`apt_update` en lecture seule** alors qu'elle
   exécute `apt-get full-upgrade -y` et `apt-get install -y`. **C'est la route la plus mutante des 28,
   et mon premier classement la disait inoffensive.**

> Cette fois l'erreur allait **dans le sens rassurant** — l'inverse du biais habituel de mes sondes.
> Rien ne m'a prévenue : aucun ordre de grandeur invraisemblable, aucun pair pour la relire. **Elle
> n'a été trouvée qu'en ouvrant les corps un par un**, ce qui est précisément ce que le relevé
> précédent avait conclu et que j'ai failli ne pas refaire.

---

## 4. Remesure

```bash
# la liste des 28
python3 - <<'EOF'
# ast.parse par fichier de routes ; retenir celles qui portent
# require_machine_access SANS require_role NI require_permission
EOF
```

Le classement des 19 a été fait **en lisant la commande envoyée**, pas par motif sur le fichier —
c'est ce qui a rattrapé `apt_update`. Toute remesure automatique doit résoudre les variables avant de
conclure, sans quoi elle refera l'erreur 3.
