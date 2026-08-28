# DOSSIER 01 — Redémarrer `rootwarden_python`

**Pour signature de l'exploitant.** Préparé par la session 8 le **2026-08-28**, mesures de 06:40–06:55
UTC. C'est le dossier le plus urgent : **six autres décisions n'ont d'effet qu'après lui.**

---

## 1. Recommandation

> ## ✅ RÉVISION DU 2026-08-28, 08:03 UTC — LE PRÉALABLE BLOQUANT EST LEVÉ
>
> Ce dossier a été écrit à 06:55 UTC avec **un** préalable bloquant : la divergence
> `temporary_permissions`. **Elle a été fermée à 07:59 UTC** — `72b0518`, commité, mesuré par moi :
>
>     helpers.py:264   SELECT permission FROM temporary_permissions WHERE user_id = %s AND expires_at > NOW()
>     :269             perms[nom] = True      # ajoute seulement, ne retire jamais
>     git status -- backend/routes/helpers.py   ->  vide (commite)
>
> **Le backend lit désormais la troisième source, comme les deux portails.** Il ne reste donc **aucun
> préalable bloquant** : la recommandation devient *redémarrer*, sous les seuls contrôles du §3.
>
> **Et deux sessions me l'ont annoncé en se contredisant** — l'une disant « le trou existe », l'autre
> « le remède n'est pas protégé ». **Les deux étaient vraies à leur instant et périmées au mien.**
> *Combinées telles quelles, elles auraient produit une exposition doublement fausse.* C'est ce qui a
> fait remesurer plutôt que relayer.

**Redémarrer.** Un seul préalable subsiste, et c'est une vérification, pas un travail.

| # | préalable | pourquoi | bloquant ? |
|---|---|---|---|
| ~~1~~ | ~~fermer la divergence `temporary_permissions`~~ | **FAIT** — `72b0518`, 2026-08-28 07:59 UTC | levé |
| 2 | contrôler l'**arbre de travail** à l'instant du geste | un redémarrage publie l'arbre, pas l'historique | oui, mais c'est une vérification |

**Un résiduel, non bloquant et qui doit être dit** : le repli du correctif, **sur erreur SQL**, dégrade
vers « les temporaires ne comptent pas » et journalise un avertissement. Le porteur perd alors son accès
**pendant l'incident**, et son 403 ne distingue pas *« vous ne l'avez pas »* de *« je n'ai pas pu lire
si vous l'aviez »* — **un refus d'accès déguisé en incapacité de lecture**, la classe exacte d'E-217.
*C'est un cas d'incident, pas un cas nominal*, et le repli qui n'ajoute jamais est le bon choix par
défaut : il ne peut pas accorder à tort.

**Ce que je n'ai PAS retenu, et il faut le dire** : *accorder les quatre permissions avant de
redémarrer.* C'était la tâche annoncée. **Mesuré, elle n'a pas d'objet** — voir `DECISIONS-DSI.md` §2 :
sur les deux portails, la page exige déjà la permission que la route s'apprête à demander. **Le
durcissement ne retire aucun chemin d'interface.**

---

## 2. Conséquence, mesurée

### Ce que le redémarrage met en service

    StartedAt rootwarden_python   2026-08-27T12:28:43Z        (inchange, remesure)
    maintenant                    2026-08-28T06:47Z
    commits touchant backend/     28
    fichiers .py hors tests modifies depuis   19
    fichiers de tests modifies                 5   (sans effet sur le service)

Les **19**, nommés — parce qu'un lot qu'on ne peut pas nommer ne s'observe pas :

    approvals · config · configure_servers · scheduler · server · services_manager
    sftp_manager · ssh_key_manager · ssh_utils · sudo_manager
    routes/ : fail2ban · helpers · iptables · monitoring · policies · services
              settings · ssh · ssh_audit

> Le compte de 19 est ici obtenu **par `mtime`** ; celui d'`AVANT-LE-REDEMARRAGE.md` l'était par
> **comparaison d'arbres syntaxiques**. **Deux moyens indépendants, le même nombre** — et les deux
> critères ne sont pas les mêmes (le mien compterait un fichier dont seule une docstring bouge ; l'autre
> a mesuré qu'il n'y en a aucun). *L'accord de deux mesures de nature différente vaut mieux qu'une
> mesure répétée.*

### Les routes qui gagnent une garde : **33**, et non 27

    module        en service   arbre    nouvelles
    iptables           1          7        +6
    fail2ban           1         19       +18
    services           0          8        +8
    ssh_audit          0          1        +1
                                          +33

Compté par **blocs de décorateurs** (un `require_permission` peut vivre ailleurs que sur une route), et
recoupé par un second comptage d'occurrences brutes. « En service » est reconstruit depuis `47e5f11`,
dernier commit de `backend/routes/` antérieur au `StartedAt` : **c'est un proxy** — un redémarrage
publie l'arbre, donc l'état servi n'est pas exactement l'état commité. **L'inertie, elle, est mesurée
sans proxy** : les quatre fichiers portent un `mtime` postérieur au `StartedAt`.

### ⚠ Le défaut que le redémarrage ARME, et qu'aucune permission accordée ne répare

    legacy/auth/verify.php:329-337    checkPermission lit `temporary_permissions`
    laravel/app/Services/Droits.php:64            idem
    laravel/app/Services/Permissions.php:155      idem
    backend/routes/helpers.py         SELECT * FROM permissions WHERE user_id = %s   <- UNE table

**Les deux pages acceptent une permission temporaire ; le backend ne la voit pas.** Après le
redémarrage, un compte porteur d'un `can_manage_fail2ban` temporaire **ouvre la page** et prend **403
sur les dix-huit routes** : une page qui s'affiche, des boutons qui échouent tous, rien à l'écran qui
l'explique.

**Le backend le sait, et l'a refusé une fois** — `backend/routes/ssh.py:422-431`, sur le choix de garder
`role(2)` plutôt qu'une permission sur `POST /deploy` : *« La permission serait le miroir exact de la
page — et elle CASSERAIT un chemin légitime (…) Un compte dont la permission est temporaire passerait la
page et serait refusé ici. »* **Les 33 routes reproduisent exactement ce que l'auteur de `/deploy` a
refusé de créer.**

**Porteur aujourd'hui : aucun.** `temporary_permissions` est **vide**. *Une propriété qui tient par
l'état du parc n'est pas une propriété* : l'écart s'ouvre au premier octroi temporaire, qui est un geste
d'administration ordinaire offert par l'interface.

### Ce qui NE casse pas, dit aussi nettement

- **aucun compte ne perd un chemin d'interface.** Les pages portent déjà la garde, sur les deux
  portails ;
- **la clé d'API seule** : une seule clé active, celle du proxy legacy, qui transmet toujours
  `X-User-ID`. Le fail-closed de `get_current_user()` n'a personne à refuser ;
- **la porte à quatre yeux devient interrogée** sur les deux gestes de flotte — et `APPROVAL_ENABLED`
  est déjà `true` dans l'environnement. **Mais voir le `DOSSIER-02` : il n'existe aucun approbateur
  éligible hors des comptes de rôle 3.**

### Le risque réel du lot, et ce n'est aucun des correctifs

> **Dix-neuf modules changent ensemble, et aucun n'a jamais été observé en fonctionnement.** *Un
> correctif inerte n'est pas un correctif en attente : c'est un correctif dont le comportement n'a
> jamais été vu.* C'est la seule phrase du dossier de la session 4 qu'aucune mesure n'a atténuée.

---

## 3. Le geste exact

```bash
cd /home/utilisateur/Documents/Gestion_SSH_KEY

# 1. l'arbre, pas le log — un redemarrage publie ce qui traine
git status --porcelain -- backend/          # doit etre VIDE
# mesure du 2026-08-28 06:50 UTC : vide. A REFAIRE a l'instant du geste.

# 2. le banc doit etre libre, et cela se DEMANDE, jamais ne se deduit d'un `ps`
#    (session 7 en priorite ; un rejeu en cours serait casse en plein vol)

# 3. le geste
sudo -n docker restart rootwarden_python
sleep 20
sudo -n docker inspect -f '{{.State.StartedAt}} {{.State.Health.Status}}' rootwarden_python

# 4. controler que le lot est bien en service, par la comparaison qui fait foi
#    StartedAt doit etre POSTERIEUR au mtime des 19 fichiers
```

**Puis observer les 19 modules, pas seulement le correctif attendu.** Le rejeu du LOT complet est la
mesure qui le fait — **après** le redémarrage, jamais pendant : `backend/**.py` est lu au démarrage, un
redémarrage en cours de suite invalide la mesure en vol.

**Contrôle de l'arbre au moment du geste — et la parade si l'arbre n'est pas propre :**

```bash
git diff > /tmp/patch          # PAS `git stash` : il passe par l'index, qui est PARTAGE
git checkout -- <chemin>
# … redemarrage sur un arbre propre …
git apply /tmp/patch
```

---

## 4. Ce qui se passe si on ne fait rien

**C'est la moitié qu'on oublie, et c'est celle qui décide ici.**

| ce qui reste inerte | conséquence de l'inaction |
|---|---|
| **33 routes sans rôle ni permission** — 8 de `services`, 18 de `fail2ban`, 6 d'`iptables`, 1 de `ssh_audit` | l'écart d'E-149 et E-152 reste **ouvert** : la page garde, la route non |
| **E-201 / E-205 — la porte à quatre yeux** | `APPROVAL_ENABLED=true` et `APPROVAL_ACTIONS` **nomment** les deux gestes de flotte, `gate()` n'est pas appelé sur eux. **La configuration affirme une protection que le code ne consulte pas** |
| **E-191 — `POST /deploy`** | la route qui écrit en root sur un parc entier **et révoque** reste sous `@require_api_key` **seule** : ni rôle, ni périmètre machine. Moins gardée que celle qui redémarre une machine |
| **E-218 / E-220 — le coupe-circuit du `NOPASSWD: ALL`** | le retrait du sudoers reste **en premier** dans la chaîne, donc un arrêt en cours de route laisse un état sans sortie |
| **E-174, E-197, E-199, E-204** | corrigés, **inertes** |

> **L'inaction n'est pas neutre et elle n'est pas non plus dangereuse d'un coup : elle est
> immobile.** Le service tourne depuis le 2026-08-27 12:28 UTC sur du code dont **28 commits** l'ont
> écarté. Chaque jour ajoute des correctifs au lot, donc **augmente la taille de ce qui prendra effet
> ensemble** — c'est-à-dire le seul risque réel du dossier. *Attendre ne réduit pas le risque du
> redémarrage : il le fait croître.*

**Et une chose que l'inaction rend fausse** : `docs/migration/RELEVE-GARDES-BACKEND.md` et toute page
qui **affirme des autorisations** — `api_docs` en est une — décrivent l'arbre et non le service. Plus
l'écart dure, plus ces documents mentent, et *la seule chose plus dangereuse qu'une garde absente est
une garde annoncée qui n'existe pas.*

---

## Ce qui n'est pas mesuré, et doit être dit

- **le comportement des 19 modules en service.** Personne ne l'a observé. C'est l'objet du geste, pas
  son préalable ;
- **l'état servi exactement au `StartedAt`** — reconstruit depuis l'historique, pas lu dans le
  processus. La comparaison `StartedAt` / `mtime` établit l'**inertie** ; elle n'établit pas le
  **contenu** ;
- **le nombre de routes qui, parmi les 33, sont atteintes par une page portée** — non compté.
