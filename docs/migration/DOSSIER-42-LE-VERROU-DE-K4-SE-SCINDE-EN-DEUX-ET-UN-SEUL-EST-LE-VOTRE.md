# DOSSIER-42 — le verrou de K4 se scinde en DEUX, et un seul est le vôtre

**Session DSI, 2026-09-07 vers 20:10 CEST.** *Écrit sur carte blanche pour finir
l'extinction. Rien n'a été porté ni exercé.*

**`NOPASSWD: ALL` était traité comme UN arbitrage depuis des jours. Il en
contient deux, et ils n'ont pas le même destinataire.**

---

## ① Les quatre chemins de `add_to_sudoers`, mesurés

```
backend/configure_servers.py

  l'APPELANT (:1044-1058)
    :1050  politique par machine, preset != 'none'  ->  add_to_sudoers(policy=…)   SÛR
    :1052  preset == 'none'                          ->  remove_from_sudoers        SÛR
    :1054  elif sudo:   le BOOLÉEN `users.sudo = 1`  ->  add_to_sudoers() SANS policy
    :1057  else                                      ->  remove_from_sudoers        SÛR

  l'APPELÉ (:338-380)
    :351  username invalide           ->  `logger.error` puis `return`     REFUSE
    :356  preset == 'none'            ->  supprime le fichier             SÛR
    :361  preset configuré            ->  render + `visudo -cf` + mv atomique  SÛR
    :375  render EN ÉCHEC             ->  « fallback NOPASSWD ALL », `policy = None`
    :379  policy absent OU sans preset ->  `ALL=(ALL:ALL) NOPASSWD: ALL`
```

---

## ② 🔴 **(B) — LE DÉFAUT : un ÉCHEC de rendu élargit le privilège. DÉCIDÉ.**

```
:373  except (ValueError, ImportError) as e:
:375      logger.error(f"[{username}] Render sudo policy invalide ({e}), fallback NOPASSWD ALL")
:376      policy = None          # Force fallback ci-dessous
:380  content = f"{username} ALL=(ALL:ALL) NOPASSWD: ALL\n"
```

> **Quelqu'un a demandé une politique PRÉCISE, son rendu a échoué, et le produit
> accorde root sans mot de passe sans restriction.** *Plus l'intention est
> étroite, plus le résultat est large — et précisément quand ça s'est mal
> passé.*

### ⚠ L'asymétrie est DANS LA MÊME FONCTION

| entrée invalide | conséquence |
|---|---|
| **username** invalide (`:351`) | `return`, **rien n'est écrit** |
| **policy** invalide (`:379`) | **`NOPASSWD: ALL` est écrit** |

*Deux modes d'échec, la même fonction, des directions opposées.*

### Et le repli n'offre RIEN que le produit ne sache déjà offrir

```
backend/sudo_manager.py:82    def render_preset_all_nopasswd(...)
backend/sudo_manager.py:160   'all_nopasswd': render_preset_all_nopasswd,
```

> **`all_nopasswd` EST un preset, choisissable explicitement.** *Le repli ne
> rend donc aucun pouvoir accessible qui ne le serait pas — il l'accorde **par
> accident**.*

### DÉCISION — l'échec doit ÉCHOUER

**Un rendu de politique en échec doit `return` sans écrire, exactement comme le
username invalide le fait déjà quinze lignes plus haut.** *Aucune capacité n'est
perdue : qui veut `NOPASSWD: ALL` le choisit par son preset.*

**C'est un arbitrage produit et je le rends : je n'ai pas besoin de votre mot
pour décider qu'un échec ne doit pas élargir un privilège.** *Le GESTE d'écrire
le correctif reste hors de mon périmètre.*

---

## ③ **(A) — LE VÔTRE, et il est étroit**

```
:1054  elif sudo:                     # le booleen `users.sudo = 1`
:1056      add_to_sudoers(channel, username, logger=self.logger)   # -> NOPASSWD: ALL
```

*Commentaire du dépôt : « Legacy : bool `users.sudo`=1 -> NOPASSWD ALL
(comportement v1.21.x) ».* **C'est une compatibilité assumée, pas un accident.**

> **La question, et elle est la vôtre : que doit signifier aujourd'hui
> `users.sudo = 1` sans politique par machine ?**

**Pourquoi je ne la tranche pas :** *toute réponse autre que « tout » RETIRE du
sudo à des comptes qui en ont aujourd'hui, sur vos machines.* **Ce n'est plus une
décision sur ce que le produit offre, c'est un changement d'état sur votre
parc.** *Ma carte blanche couvre le premier, pas le second.*

⚠ **NON MESURÉ** : combien de comptes portent `users.sudo = 1` sans politique
par machine — donc combien seraient concernés. *La base ne m'est pas
interrogeable (`docker.sock` refusé, client mysql absent, port 3306 non publié).*
**La requête :**

```sql
SELECT COUNT(*) FROM users u WHERE u.sudo = 1
  AND NOT EXISTS (SELECT 1 FROM user_machine_access a
                  WHERE a.user_id = u.id AND a.sudo_preset IS NOT NULL);
```

---

## ④ CE QUE ÇA CHANGE POUR L'EXTINCTION

**Le portage de `/deploy` (K4) n'attendait PAS (A). Il attendait qu'on regarde le
verrou** — et le verrou était deux choses empilées sous un seul nom.

| | |
|---|---|
| **(B)** | **décidé ici.** Reste à écrire : `return` au lieu du repli. Hors de mon périmètre d'écriture. |
| **(A)** | **le vôtre**, et il est étroit : une seule question, avec sa requête de mesure |
| `/deploy` | portable dès que (B) est écrit. *(A) ne le bloque pas : il décrit un comportement EXISTANT, pas une régression du portage.* |

⛔ **Rien n'a été porté ni exercé.** *Aucune machine n'a été joignée, aucune
politique rendue, aucun fichier sudoers écrit.*
