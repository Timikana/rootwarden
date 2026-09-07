# DOSSIER-40 — `iptables/` ne s'archive pas, et l'archiver retirerait la variante SÛRE

**Session DSI. Arbitrage rendu le 2026-09-07 à 20:1x CEST**, sur la mesure de la
session 5 (`d33e009`, `AUDIT-IPTABLES-CINQ-GESTES.md`), vérifiée ici point par
point.

**DÉCISION : `legacy/iptables/index.php` NE S'ARCHIVE PAS. Ses quatre gestes
sont à PORTER.** *Ce n'est pas le cas `fail2ban` (deux enveloppes de 26 lignes) :
c'est le cas `bashrc`, quatre fois.*

---

## ① ⚠ MA PRÉMISSE ÉTAIT FAUSSE, et c'est la huitième fois du même genre

**J'avais écrit à la session 5 : « le portage n'a AUCUNE table `iptables*` ni
`firewall*` — je l'ai mesuré ». Il en a deux.**

```
laravel/app/Services/Iptables.php
  :206  SELECT ... FROM iptables_rules
  :244  DELETE FROM iptables_rules WHERE server_id = ?
  :246  INSERT INTO iptables_rules (...)
  :260  SELECT COUNT(*) FROM iptables_history WHERE server_id = ?

ma sonde cherchait  DB::table('iptables*')     ->   0
ce fichier emploie  DB::select | insert | delete -> 10
```

> **Un motif qui teste UNE FORME D'EXPRESSION a conclu à l'absence de la
> CHOSE.** *Huitième instance de cette famille, et la première qui ne porte pas
> sur un chemin : ce n'est plus la composition de l'URL, c'est la forme de
> l'appel SQL.*

**Conséquence directe : `/iptables-history` est de la forme 4 et DÉJÀ PORTÉ**
(sous-lot I3, `PareFeuController::historique()`). **Il reste QUATRE gestes, pas
cinq.**

---

## ② ⛔ LE FAIT QUI RENVERSE L'ARBITRAGE

**`POST /iptables` — la route DÉJÀ portée, DÉJÀ en liste blanche — accepte
`action: "apply"` et appelle le même `apply_iptables_rules`.**

```
                          gardes                                    archive ?
/iptables-apply           require_api_key · can_manage_iptables      OUI  (4 mentions)
                          require_machine_access · threaded_route
/iptables action=apply    LES MÊMES QUATRE                           NON  (0)

le JS du portage construit `action:'apply'`   ->   0 fois
```

> **Archiver `/iptables-apply` retirerait la variante qui TRACE et laisserait
> vivante celle qui ne trace rien.** *C'est l'inverse de l'intention.*

**Ce n'est PAS un trou de contrôle d'accès** — les gardes sont identiques des
deux côtés. **Le défaut est qu'il existe DEUX chemins vers le même effet, dont un
seul laisse une version archivée.**

### ⚠ CORRECTION DU 2026-09-07 20:3x — mon MOTIF était faux

**J'avais écrit : « l'exposition est bornée aux porteurs de
`can_manage_iptables` PARCE QUE `require_machine_access` est présent des deux
côtés ».** *La conclusion tient ; le motif désigne le seul des deux gardes qui
ne la produit pas.* **Relevé par la session 5, vérifié ici :**

```
backend/routes/helpers.py
  check_machine_access(machine_id):
      if role_id >= 2:
          return True          <- INCONDITIONNEL

  require_permission(...):
      if role_id >= 3:
          return func(...)     <- superadmin court-circuite
```

**L'ensemble réellement habilité :**

| | |
|---|---|
| **rôle ≥ 3** | inconditionnel — ni permission, ni accès machine |
| **rôle 2 + `can_manage_iptables`** | **TOUTES** les machines |
| rôle 1 + `can_manage_iptables` | ses machines seulement |

> **`require_machine_access` ne mord qu'au rôle 1.** *La borne que j'annonçais
> vient entièrement de `require_permission` — et elle-même s'arrête au rôle 3.*

*C'est « un garde présent n'est pas un garde qui garde », sur une phrase que
j'avais écrite pour BORNER une alarme.* **La direction est celle qui rassure, et
c'est celle où je n'ai pas de contradicteur naturel.**

⚠ **Et la session 5 retire de son côté une formulation trop large** — *« tout
compte authentifié pouvait faire appliquer un jeu de règles à n'importe quelle
machine »* — qu'elle avait reprise **d'un docblock, sans la mesurer**. *« Cité »
n'est pas « vérifié », sur un texte qui allait dans son sens.*

⚠ **Et la liste blanche est un PRÉFIXE** (`RoutesBackend.php:114` =
`'/iptables', '/iptables-'`) : *les six `/iptables-*` sont déjà atteignables par
la passerelle.* **La page n'offre aucun bouton d'application, mais cela ne
protège que le navigateur.**

⚠ **NON MESURÉ** : si un compte emprunte AUJOURD'HUI le chemin
`action: "apply"`. *Il faudrait les journaux d'accès de la passerelle.* **Le
pouvoir est ATTEIGNABLE ; je ne dis pas qu'il est EMPRUNTÉ.** *(borne posée par
la session 5, reprise telle quelle)*

---

## ③ LES QUATRE GESTES, ET AUCUN N'EST UNE COMMODITÉ

| geste | lignes | écrit | sa valeur est dans |
|---|---|---|---|
| `/iptables-apply` | 78 | règles sur la MACHINE + `iptables_history` | **4 garde-fous** |
| `/iptables-rollback` | 60 | règles sur la MACHINE (version archivée) | **un CONTRÔLE D'ACCÈS** |
| `/iptables-restore` | 36 | règles sur la MACHINE (copie en base) | ses garde-fous |
| `/iptables-logs` | 39 | **rien** (SSE, lecture) | sa borne de 600 s |

### ⛔ `/iptables-rollback` porte un contrôle qu'aucun décorateur n'exprime

*Son corps ne porte que `history_id`* — donc `@require_machine_access` ne trouve
aucun identifiant, `ids` reste vide, **et il laisse passer.** *Le contrôle est
fait APRÈS résolution, sur la machine que la version désigne.*

> **L'archiver sans porter ce contrôle ne supprimerait pas le pouvoir — il est
> atteignable autrement — et recréerait exactement le trou qu'il a refermé.**

### ⚠ Et un trou asymétrique que l'extinction rendrait visible

**Le sous-lot I2, PORTÉ, ÉCRIT dans `iptables_rules`. `/iptables-restore` est le
SEUL chemin qui applique cette copie, et il n'a aucun appelant dans le portage.**

*Le portage produit déjà une donnée que seul le legacy sait employer.*
**Éteindre `legacy/iptables/` laisserait l'écran « enregistrer la copie » en
place et rendrait cette copie inapplicable.**

---

## ④ CE QUI VOUS REVIENT

| | |
|---|---|
| **porter les quatre gestes** | décidé ici. *Le geste d'écriture appartient à la session 5, sur VOTRE mot — pas sur le mien.* |
| **les deux chemins d'application** | `POST /iptables action=apply` applique sans archiver. *Indépendant de l'extinction : c'est vrai aujourd'hui.* |
| **le contrôle de `/iptables-rollback`** | à porter AVEC le geste, jamais après |

⛔ **Aucun de ces gestes n'a été porté ni exercé.** *La carte blanche que j'ai
reçue couvre les décisions et la publication ; elle ne transmet pas un périmètre
tenu de vous, et je ne peux pas l'accorder à un pair — y compris quand je suis
d'accord avec la décision.*
