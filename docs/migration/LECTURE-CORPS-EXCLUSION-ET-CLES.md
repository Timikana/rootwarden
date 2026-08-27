# Quatre corps que personne n'avait lus

Lecture du **2026-08-27**, session 4, à la demande du Lead. **Rien n'a été exercé** : les quatre
routes joignent une machine ou décident d'une suppression. *Une route dont se tromper de sens coupe
l'accès SSH ne se sonde pas — elle se lit.*

---

## 1. `/exclude_user` — ce n'est PAS de la tenue de livres, et le retrait ferait perdre quelque chose

La session 3 propose de remplacer la table en ligne de `platform_key` par un lien vers
`comptes-distants`. La condition du Lead était : **rien ne doit être perdu.** Voici la réponse.

### Ce que la route fait

`admin.py:115` — `@require_api_key` + `@require_role(2)`. Un `INSERT IGNORE` dans
`user_exclusions (machine_id, username, reason)`. **Aucun effet distant.** Paramètres liés, pas
d'injection possible.

Vu seul, ce corps a l'air anodin. **Il ne l'est pas, et c'est son unique lecteur qui le dit.**

### Son unique lecteur est la décision de SUPPRESSION

`configure_servers.py:793`, dans le déploiement :

```python
cursor.execute("SELECT username FROM user_exclusions WHERE machine_id = %s", (machine_id,))
…
# 2. Ne pas supprimer les utilisateurs dans la liste d'exclusion
if username in excluded_usernames:
    continue
# 3. Supprimer tous les autres
execute_command_as_root(channel, f"userdel -r {username}", …)
```

> **`/exclude_user` est le seul moyen d'épargner à un compte non autorisé un `userdel -r` lors du
> prochain déploiement.** Pas une étiquette : un garde-fou contre une destruction irréversible avec
> son répertoire personnel.

### ⚠ ET IL Y A DEUX MAGASINS, QUI ONT DIVERGÉ

| | `user_exclusions` | `server_user_inventory.status='excluded'` |
|---|---|---|
| écrit par | `/exclude_user` **seule** | `/admin/user_inventory/classify`, `classify_bulk`, l'auto-classement du scan |
| lu par | `configure_servers.py:793` — **la décision de suppression** | `configure_servers.py:887` — mais **uniquement `status='managed'`**, pour la révocation de clés |
| interface | `legacy/adm/platform_keys.php:458` — **la page qu'on veut retirer** | `comptes-distants` (portée) et `legacy/adm/server_users.php` |

La migration `030` a copié `user_exclusions` dans l'inventaire **une fois**, au moment de la
migration. **Rien ne les a synchronisées depuis.**

**Conséquence, et c'est elle qui doit décider :**

> Classer un compte `excluded` dans `comptes-distants` **ne le protège PAS** du `userdel -r`. Le
> chemin de suppression ne lit jamais `server_user_inventory`.

Ce n'est donc pas « une écriture qui manque à la page portée ». C'est **une écriture manquante
remplacée par une sosie** : un statut nommé littéralement `excluded`, dans la page vers laquelle on
propose de renvoyer l'utilisateur, **qui n'a pas cet effet**. *Perdre un bouton se voit. Le remplacer
par un bouton qui a l'air de faire la même chose ne se voit pas.*

`ComptesDistants.php:29` écrit — **à juste titre** — que `classify` « ne fait qu'un `UPDATE` […]
aucun effet distant ». C'est exact et ce n'est pas le point : l'effet ne vient pas du classement, il
vient de ce que le **déploiement** lit, et il lit l'autre table.

### Verdict pour la décision du Lead

**Le retrait, tel que proposé, PERD une capacité** — et la perd silencieusement. Trois issues, par
ordre de coût :

1. **Unifier les deux magasins** (le déploiement lit aussi `status='excluded'`) — corrige le fond,
   mais **change le sens d'une décision de suppression** : c'est un arbitrage exploitant, pas un
   portage. Ne pas le faire à la légère : des lignes `excluded` existent déjà depuis 030.
2. **Porter `/exclude_user` dans `comptes-distants`** comme un geste distinct du classement.
3. **Ne pas retirer la table en ligne** tant que 1 ou 2 n'est pas fait.

**Ce n'est pas ma décision.** Elle change ce qui est détruit sur des machines réelles.

---

## 2. Les trois compositions de commande — la question d'E-174

*La valeur venue du client est-elle citée à l'intérieur de la commande ?*

| route | valeur client | citée ? | verdict |
|---|---|---|---|
| `sshd_allow_user` | `username` | **oui** — `shlex.quote` sur les 3 interpolations, + `_validate_username` en amont | **sain sur l'injection** |
| `server_user_remove_key` | `username`, `fingerprint` | **oui** — `shlex.quote` + `^[A-Za-z0-9+/]{40,64}$` sur l'empreinte | **sain sur l'injection**, une réserve ci-dessous |
| `remove_user_keys` | `username` | **oui** pour le `getent`, et le chemin est revalidé | **sain sur l'injection**, mais **deux défauts d'une autre famille** |

**Aucune des trois n'a le défaut E-174.** Le durcissement d'E-204 (`_validate_username` dérivée et non
recopiée) couvre les trois. C'est un dédouanement, et je l'écris aussi nettement que les défauts.

### ⚠ 2a. `sshd_allow_user` — le `|| true` neutralise la seule vérification du rechargement

```python
reload_cmd = "systemctl reload sshd 2>&1 || systemctl reload ssh 2>&1 || true"
_, err_r, code_r = execute_as_root(client, reload_cmd, …)
if code_r != 0:          # <-- INATTEIGNABLE
    …rollback…
```

`||` est associatif à gauche et de précédence égale : le `|| true` final rend **`code_r` toujours nul**.
La branche de rollback est **du code mort**, et la fonction retourne
`True, "AllowUsers patché"` **même si `sshd` n'a jamais rechargé**.

*Ce qui est démontrable sans rien exécuter* : c'est de la sémantique de shell, pas une hypothèse.

**Ce que ça coûte** : le fichier est correct sur le disque (`sshd -t` a validé) et le `sshd` en cours
tourne encore sur l'ancienne configuration. **Donc aucun accès n'est coupé** — la portée est étroite
et je le dis. Ce qui est faux, c'est l'**attestation** : on annonce à l'exploitant que le compte peut
se connecter, et il ne peut pas. C'est le motif du chantier : *une réussite annoncée n'est pas une
réussite vérifiée.*

**Question ouverte, NON MESURÉE** : le helper ne patche que la **première** ligne trouvée par `grep`,
et l'ordre des arguments met `/etc/ssh/sshd_config` avant `sshd_config.d/*.conf`. Si un `.conf` inclus
porte aussi `AllowUsers`, c'est lui qui devrait primer. **Je n'ai pas de machine où le vérifier et je
ne le compte pas comme un défaut** — je le signale pour qu'on le mesure.

### ⚠ 2b. `remove_user_keys` — E-192 est revenu, sur une révocation d'accès

```python
cmd = f"printf '' > {ak_path}"
execute_as_root(client, cmd, root_pass, logger=logger)      # <-- resultat JETE
return jsonify({'success': True, 'message': f"Toutes les cles de '{username}' supprimees"})
```

`execute_as_root` rend `(sortie, erreur, code)`. **Les trois sont jetés.** La route annonce
`success: True` **sans avoir rien vérifié**, sur les deux modes.

> C'est **exactement E-192**, corrigé le mois dernier dans `configure_servers.py`, réapparu ici. Et le
> commentaire d'E-192 dit déjà pourquoi c'est la pire forme : *« une FAUSSE ATTESTATION — personne ne
> rouvre un dossier de conformité clos. »* Ici la fausse attestation porte sur **le retrait de toutes
> les clés SSH d'un compte**.

**Et la comparaison avec sa voisine est accablante.** `server_user_remove_key`, deux fonctions plus
haut dans le **même fichier**, fait le travail correctement : elle recalcule chaque empreinte avec
`ssh-keygen -lf`, compte les lignes retirées, **et refuse avec `exit 2` si elle n'a rien trouvé**.

`remove_user_keys` en mode `rootwarden_only` fait, elle :

```python
cmd = f"sed -i '/rootwarden/d' {ak_path} 2>/dev/null; echo OK"
```

Deux défauts en une ligne :
- **`; echo OK`** rend le code de sortie toujours nul — même famille que le `|| true` ci-dessus, et
  quatrième occurrence de « le marqueur n'est pas le verdict » ;
- **la sélection se fait par sous-chaîne**, pas par empreinte. Toute ligne contenant `rootwarden`
  saute — y compris la clé légitime d'un utilisateur dont le **commentaire** contient ce mot
  (`sauvegarde-rootwarden`, `paul@rootwarden-adm`). **Une clé étrangère supprimée sans le dire, et une
  clé plateforme manquée si son commentaire a été réécrit.**

**Deux routes du même fichier font le même geste, l'une par empreinte et l'autre par `grep`.** C'est la
divergence que ce chantier compte maintenant cinq fois.

---

## 3. Ce que je n'ai pas fait

- **Rien exercé.** Ni `sshd_allow_user`, ni les deux routes de clés, ni `/exclude_user`.
- **Rien corrigé** en 2a et 2b : ce sont des **gestes distants** dont le correctif change ce qui est
  écrit sur des machines réelles. À qualifier par la session 5 avant d'y toucher.
- La question `sshd_config.d` reste **ouverte et non mesurée**.
