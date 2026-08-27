# Balayage — l'état persisté qui ne suit pas le verdict du geste

Session 4, **2026-08-27**. Classe cherchée : **une fonction qui exécute une commande à distance,
puis écrit ou efface un état en base, sans qu'un code de retour soit comparé entre les deux.**

Méthode : parcours AST de tout `backend/` (hors `tests/`), puis **lecture de chaque candidate**.
Les deux temps comptent, et le second bien plus que le premier.

> **Le balayage seul s'est trompé sur 12 candidates sur 22 — dans le sens qui ALARME.**
> Sans la lecture une par une, ce document aurait annoncé « 22 occurrences », et ce chiffre serait
> entré dans le suivi, d'où il aurait été recopié. C'est la moitié du travail qui est dans la
> seconde colonne, pas dans la première.

---

## 1. Réelles — 5

| # | où | ce qui se passe | état |
|---|---|---|---|
| 1 | `routes/graylog.py` — `deploy` / `uninstall` | `forward_deployed=True` écrit sans regarder `syntax_ok` ni `restart_ok`, pendant que la réponse rendait `success: false` | **déjà fermé** avant ce balayage, et soigneusement — c'est la référence du dépôt pour la classe |
| 2 | `routes/supervision.py` — 4 routes de déploiement et de reconfiguration | tous les codes de retour jetés ; `_upsert_agent(config_deployed=True)` et `SUCCESS_MACHINE::` inconditionnels. `generic_reconfigure` annonçait « réussie » sans avoir écrit un octet | **fermé** `v1.38.11` (E-90) |
| 3 | `routes/wazuh.py:738` — `set_group` | le redémarrage **fait** le geste (« on redémarre pour ré-inscription ») et son résultat était jeté : la base affirmait un groupe que l'agent n'a pas | **fermé** `v1.38.14` |
| 4 | `routes/ssh.py:1088` — `scan_server_users` | **la forme destructrice.** Une lecture ratée vidait `server_user_inventory` (72 lignes), `server_user_ssh_keys` (20), et posait `users_scanned_at` — la précondition du préflight de K4 | **fermé** `v1.38.16` (E-183) |
| 5 | `routes/supervision.py` ×2 + `routes/monitoring.py` — sondes de version | une sonde qui n'a rien lu faisait `_remove_agent`, ou écrasait la version d'OS par « Inconnue » | **fermé** `v1.38.17` (E-184) |

**La n° 4 est d'une autre nature que les autres.** Les quatre premières écrivent un état *faux* —
réparable au geste suivant. Celle-là **efface un état vrai**, et le journal l'annonce comme un
nettoyage réussi.

---

## 2. Dédouanées par la lecture — 6

Un dédouanement se dit aussi nettement qu'une accusation. **Et ce qui referme doit être documenté
là où il referme** : sans cela, quelqu'un « simplifiera » un jour la pièce qui protège, et rouvrira
le trou sans qu'aucun test ne bouge.

| où | pourquoi ce n'en est pas un |
|---|---|
| `routes/monitoring.py:196` `reboot_server` | sa docstring **explique** l'absence : « la connexion SSH est coupée par le serveur dès l'exécution, donc on ne peut pas attendre un retour shell ». Absence documentée et justifiée |
| `routes/monitoring.py:156` `last_reboot` | ne lit pas le code de sortie, mais **valide la SORTIE** — un datetime parsable — avant d'écrire. Sur une lecture, c'est un contrôle **plus fort** qu'un code de retour : `uptime -s` peut rendre 0 et une ligne inutilisable. ⚠ **c'est ce parsing qui protège** ; le simplifier rouvrirait le trou |
| `routes/bashrc.py:174` `_ssh_exec` | rend le triplet `(out, err, code)` ; ses appelants comparent (`_list_users` fait `if code != 0: return []`) |
| `fail2ban_manager.py:94` `install_fail2ban` | rend le triplet, la décision appartient à l'appelant — lequel a été corrigé en `v1.38.13` |
| `routes/wazuh.py:617` `detect` | le contrôle **décisif** existe : `code` est testé et la fonction sort si l'agent n'est pas détecté. Les trois lectures d'enrichissement qui suivent jettent leur code, donc `agent_id` / `group` / `status` peuvent être vides en silence — signalé, ce n'est pas la classe |
| `cve_scanner.py` — l'usage d'`ipaddress` | l'**objet** sert à DÉCIDER (garde SSRF), pas à composer. Classe différente |

> **La règle qui en sort** : quand un garde laisse passer, chercher ce qui referme **en aval** avant
> de conclure au trou. Deux sessions l'ont établie séparément le même jour, par deux chemins.

---

## 3. Faux positifs de l'heuristique — 12

Le motif cherchait `INSERT|UPDATE|DELETE|REPLACE` dans **n'importe quelle chaîne** de la fonction. Il
a attrapé des noms de tables (`update_schedules`), des docstrings, et des messages de journal.

| où | mesure |
|---|---|
| `routes/updates.py` — 8 fonctions | **aucune écriture en base** dans leur corps |
| `routes/updates.py:638` | idem |
| `cve_scanner.py:697` `get_installed_packages` | lecture pure, rend une liste |
| `ssh_utils.py:864` et `:983` | helpers d'infrastructure, ne persistent rien |

---

## 4. Ce que ce document ne dit pas

- **il ne couvre que la classe cherchée.** Une fonction qui compare son code de retour mais en tire
  la mauvaise conclusion n'y figure pas ;
- **aucune des cinq corrections n'est mesurée EN EXÉCUTION.** Elles sont vérifiées structurellement
  et par `pytest` ; éprouver un scan raté ou un déploiement en échec demande une machine réelle. La
  session 6 tient les tests, la session 7 le navigateur ;
- **l'heuristique reste grossière.** Elle est reproductible mais elle ne remplace pas la lecture —
  c'est le sens du chiffre 12/22 en tête de document.

## 5. Remesure

```bash
# les cinq corrections
git log --oneline --grep='E-90\|E-183\|E-184\|set_group' -- backend/
# le code de sortie est desormais lu la ou il decide
grep -c "recv_exit_status" backend/routes/ssh.py      # etait 0 avant v1.38.16
grep -n "_sonde_concluante\|scan_concluant" backend/routes/*.py
```
