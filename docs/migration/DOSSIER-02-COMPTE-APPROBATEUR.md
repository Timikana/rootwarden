# DOSSIER 02 — Le compte approbateur

**Pour signature de l'exploitant.** Préparé par la session 8 le **2026-08-28**.
**Ce dossier a changé de nature en cours de mesure** : il devait dire *quel compte créer*. Le compte
existe déjà — et c'est ce qui rend l'arbitrage plus délicat, pas plus simple.

---

## 1. Recommandation

**Accorder `can_admin_portal` au compte `Broussier Gaudéric` (id 77, rôle 2) — SI et SEULEMENT SI ce
compte appartient à une autre personne que `Gaudéric Broussier` (id 78, rôle 3).**

**Si c'est la même personne : ne pas l'accorder, et désigner quelqu'un d'autre.** Un approbateur qui est
le demandeur sous un autre identifiant satisfait la règle et vide la porte de son sens.

**C'est la seule question de ce dossier que je ne peux pas mesurer**, et elle décide de tout le reste.

---

## 2. Conséquence, mesurée

### La bonne nouvelle tient, et elle est confirmée

    backend/routes/approvals.py:28-29    @require_role(2) + @require_permission('can_admin_portal')
    backend/routes/approvals.py:72       if decision == 'approved' and req.get('requested_by') == uid: -> refus

**Un compte de rôle 2 porteur de `can_admin_portal` peut approuver une action de rôle 3.** C'est une
séparation des tâches **sans escalade** : l'approbateur n'a pas besoin de pouvoir faire le geste qu'il
approuve. Rien à corriger de ce côté.

### L'état des comptes, mesuré

    id  role  can_admin_portal   2FA   changement de mdp force   cree le
     1     3        1             oui        oui                 2026-05-26   superadmin, mot de passe inconnu
    16     3        1             oui        non                 2026-08-15   rw-test-super, identifiants DANS LE DEPOT
    78     3     (aucune ligne)   NON        oui                 2026-08-27 16:50:45
    15     2        0             oui        non                 2026-08-15   rw-test-admin, compte d epreuve
    77     2     (aucune ligne)   NON        oui                 2026-08-27 16:50:37

**Aucun compte de rôle 2 ne porte `can_admin_portal`.** Les seuls approbateurs possibles aujourd'hui
sont donc les trois comptes de rôle 3 — dont `superadmin`, dont le mot de passe ne correspond plus, et
`rw-test-super`, **un compte d'épreuve dont les identifiants sont dans le dépôt.**

> **En l'état, l'approbation d'une rotation de clé de flotte reposerait sur un compte de test.**

### ⚠ Ce que la mesure fait apparaître, et qui n'était dans aucun document

**Les comptes 77 et 78 ont été créés à huit secondes d'intervalle**, le 2026-08-27 à 16:50, et portent
**le même nom dans les deux ordres** — `Broussier Gaudéric` (rôle 2) et `Gaudéric Broussier` (rôle 3).
Leurs adresses sont **distinctes** (mesuré : aucune adresse n'est partagée par deux comptes actifs).

    approvals.py:72    req.get('requested_by') == uid       <- compare des IDENTIFIANTS, pas des personnes

> **La règle des quatre yeux compare deux `user_id`. Deux comptes d'une même personne sont deux
> identifiants différents : la règle passe.** Si 77 et 78 sont la même personne, lui accorder
> `can_admin_portal` sur 77 lui permet de **demander depuis 78 et d'approuver depuis 77**, et la porte
> annonce une double validation qui n'a jamais eu lieu.

**Ce qui est mesuré** : deux comptes, deux rôles, huit secondes d'écart, noms inversés, adresses
distinctes. **Ce qui est une inférence, et je la marque comme telle** : qu'il s'agisse de la même
personne. La base ne peut pas le dire. *Un observable ne dit jamais par quel chemin il a été produit* —
et ici deux chemins existent : un exploitant qui se donne deux niveaux d'accès, ou deux personnes d'une
même famille de noms.

**C'est exactement la sixième forme du motif du chantier** : une garde présente qui ne garde pas. Elle
ne serait pas absente ni fausse — elle serait **satisfaite par construction**, ce qui est pire, parce
que le journal d'approbation porterait deux noms.

### Ce que le compte 77 ne peut pas faire aujourd'hui, même avec la permission

**Ni 77 ni 78 n'a de second facteur, et les deux portent `force_password_change = 1`.** Ils n'ont donc
jamais servi. **L'enrôlement du second facteur est porté depuis `v1.37.52`** et le blocage 2.0 est levé :
c'est un geste d'interface, pas un développement. Mais **tant qu'il n'est pas fait, désigner 77 comme
approbateur désigne un compte qui ne peut pas se connecter.**

---

## 3. Le geste exact

**Trois gestes, dans cet ordre, et le premier n'est pas technique.**

**1. Trancher l'identité.** *Le compte 77 appartient-il à quelqu'un d'autre que le compte 78 ?*
Si non : désigner une autre personne, et créer son compte en **rôle 2 + `can_admin_portal`** — pas en
rôle 3, le rôle 2 suffit et n'accorde pas le geste qu'il approuve.

**2. Rendre le compte utilisable** — depuis l'interface, par son titulaire : connexion, changement de
mot de passe imposé, **enrôlement du second facteur**.

**3. Accorder la permission** — *Administration → Comptes → Permissions*, case `can_admin_portal`.
`legacy/adm/includes/manage_permissions.php` la porte, `api/update_permissions.php:146` l'écrit, le
portage l'expose aussi. **Réversible d'un clic.**

    -- controle apres coup, en lecture
    SELECT u.id,u.name,u.role_id,p.can_admin_portal
      FROM users u LEFT JOIN permissions p ON p.user_id=u.id
     WHERE u.active=1 AND u.role_id=2

> **Ce geste n'est pas délégué**, et la raison n'est pas sa difficulté : *il désigne qui contrôle qui.*
> Aucune session ne choisit la personne qui valide les gestes de flotte.

---

## 4. Ce qui se passe si on ne fait rien

**Deux régimes, et ils basculent au redémarrage du `DOSSIER-01`.**

**Avant le redémarrage** — rien. `gate()` n'est pas appelé sur les deux gestes de flotte : la
configuration nomme `regenerate_platform_key` dans `APPROVAL_ACTIONS` et le code ne la consulte pas.
**La porte est annoncée et inexistante**, ce qui est le pire des deux états, mais il ne bloque personne.

**Après le redémarrage** — la porte devient réelle, et :

| | |
|---|---|
| les deux gestes de flotte | **impossibles** jusqu'à ce qu'un approbateur existe |
| le seul contournement | le **rôle 3**, journalisé (`approvals.py:148-151`) |
| donc, concrètement | la rotation et la révocation se feront **sous un compte de rôle 3 qui contourne la porte**, ou pas du tout |

> **C'est « l'épreuve gratuite du refus explicite »** : un blocage fonctionnel visible vaut mieux qu'un
> garde annoncé qui n'agit pas. **Mais il ne dure d'être gratuit que tant que personne n'a besoin du
> geste** — et le geste en question est celui qu'on emploie pendant un incident de clé.

**Et l'inaction laisse une chose de plus, qui ne se voit pas** : le contournement du rôle 3 sur ces deux
routes a été **levé** par arbitrage de l'exploitant le 2026-08-27, précisément parce que sans cela la
porte branchée aurait été « la garde présente qui ne garde pas ». **Le correctif est écrit et inerte.**
Redémarrer sans approbateur, c'est donc mettre en service une porte **sans le contournement qui la
rendait franchissable** — et les deux gestes de flotte deviennent **strictement impossibles**, pas
seulement gênés.

*Il faut le lire dans cet ordre : ce n'est pas ce dossier qui est urgent, c'est qu'il conditionne le
`DOSSIER-01`.*

---

---

# Second geste sur `/comptes` — un QUATRIÈME compte d'épreuve, rôle 2, zéro permission

**Ajouté le 2026-08-28, sur mesure de la session 6.** Même dossier parce que c'est le même geste : une
ligne dans `users`, et un enrôlement.

## La décision, et l'énoncé qui la commande

J'avais écrit à la session 6 que « les trois autres gardes restent inmesurables ». **C'est faux au
niveau du schéma, et elle l'a mesuré** : le compte **77** est rôle 2 et ne porte **aucune** des quatre
permissions. La fixture existe pour les quatre, pas seulement pour `iptables`.

**Sa conclusion opérationnelle tient, pour une autre raison — et la différence change l'action :**

| énoncé | ce qu'il appelle |
|---|---|
| ~~« le schéma n'a pas cette ligne »~~ | créer une ligne |
| **« la ligne existe, son compte est INUTILISABLE »** | **un quatrième compte d'épreuve** |

Le compte 77 est celui d'une personne réelle : **son secret TOTP est inconnu, et on n'invente jamais un
secret TOTP.** Aucune suite ne peut s'en servir.

> **DÉCIDÉ : un quatrième compte d'épreuve, rôle 2, ZÉRO permission.** Et non la seconde option que le
> plan proposait — *une révocation temporaire de `can_manage_fail2ban` sur `rw-test-admin`, restaurée
> dans le `finally`*.

**La raison du choix, et elle n'est pas le confort** : la révocation temporaire **mute une fixture
partagée pendant un rejeu**, et **treize suites dépendent de `rw-test-admin`**. Si le `finally` ne
tourne pas — interruption, exception qui emporte le journal, rejeu tué — le compte perd la permission
**définitivement**, et treize suites cassent d'un coup, avec un symptôme qui ressemble à une régression
de l'application. *Une fixture qui échoue ouvert sur un état partagé coûte plus cher que l'identité
qu'elle économise.* Un compte stable ne peut pas échouer ainsi.

**Et ce que le quatrième compte rend, qui est plus que ce qu'on demandait** : les **quatre** gardes
deviennent mesurables — `can_manage_iptables`, `can_manage_fail2ban`, `can_manage_services`,
`can_audit_ssh` — là où `rw-test-admin` n'en laisse mesurer qu'une.

## ⚠ La réserve, et elle est réelle

**Un compte de rôle 2 atteint TOUTES les machines, `srv-zabbix` comprise** — `check_machine_access`
rend `True` sans condition dès `role_id >= 2`. C'est déjà vrai de `rw-test-admin` (E-174 le mesure), et
un quatrième compte ajoute **une quatrième identité qui atteint la production**.

**Trois bornes, en conséquence, et elles ne sont pas négociables :**

1. **zéro permission, en permanence.** La ligne `permissions` existe et toutes ses colonnes valent 0 —
   *pas d'absence de ligne* : le compte 77 n'en a aucune, et c'est ce qui a rendu mon relevé ambigu ;
2. **aucune machine dans `user_machine_access`** — inutile au rôle 2, mais qui rend l'intention
   lisible ;
3. **il ne sert QU'À mesurer une garde.** Jamais aux captures, jamais à un geste de parc.

## Ce que la session 6 dit et qu'il faut garder

> **« Je ne peux PAS protéger cette fixture par un test. »** Ses deux suites sont **hermétiques** —
> SQLite vide et base mockée — et aucune ne lit la base du banc. Elle refuse de perdre cette propriété :
> *un test qui lirait le banc accuserait la page pour un état du banc, et il faudrait le jeton de banc
> pour le jouer.*

**La protection de `rw-test-admin` est donc ORGANISATIONNELLE, pas mécanique**, et elle est dite plutôt
que laissée croire. C'est exactement la forme qu'exige le §8 : *un « aucun défaut » n'est éprouvable que
si l'instrument peut nommer la raison de son silence.*

## Le geste exact

    Administration > Comptes > Ajouter
      nom      rw-test-admin-nu   (ou equivalent : le nom dit qu il ne porte RIEN)
      role     2
      permissions   AUCUNE — la ligne existe, toutes les colonnes a 0
    puis, par son titulaire : changement de mot de passe impose + ENROLEMENT 2FA

**L'enrôlement est le seul point qui ne peut pas être automatisé** : on ne demande jamais de coller un
secret, et on n'en invente jamais un. C'est ce qui fait de ce geste un dossier et non une décision.

## Ce qui se passe si on ne fait rien

**Les quatre gardes restent inmesurables**, et c'est le défaut qu'E-152 a nommé sur cinq suites d'un
coup : *elles resteraient vertes si le correctif n'était jamais appliqué, ET si on l'appliquait de
travers.* Le redémarrage va poser **33** de ces gardes. **Sans ce compte, aucune suite ne pourra dire si
l'une d'elles mord.**

---

## Ce qui n'est pas mesuré

- **si 77 et 78 sont la même personne.** La base ne le dit pas, et je ne l'ai pas demandé : c'est la
  question du dossier ;
- **si le contournement du rôle 3 est effectivement levé dans l'arbre.** J'ai lu la décision au §7 du
  plan, pas le code de `approvals.py` ligne à ligne après correctif — `backend/` n'est pas mon
  périmètre et la session 4 y écrivait ce matin ;
- **le nombre de gestes réellement soumis à la porte** une fois `gate()` branché sur les deux routes.
