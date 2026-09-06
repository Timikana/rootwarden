# ⚠ DOSSIER 29 — Le portage ARME un relevé SSH récurrent et ne peut pas le DÉSARMER

**Mesuré le 2026-09-05 à 07:35. Trouvé en réappliquant à `ssh_audit` l'instrument qui avait montré que
« les 9 gestes de wazuh sont interdits » en valait SIX.**

---

## 1. L'ASYMÉTRIE, MESURÉE

    le PORTAGE cree une planification
      `laravel/public/js/audit-ssh.js:583`   ecris('/ssh-audit/schedules', corps)

    le PORTAGE ne peut ni la SUPPRIMER ni la BASCULER
      appels a `DELETE /schedules/<id>`      0
      appels a `POST /schedules/<id>/toggle` 0
      et c'est DELIBERE, ecrit a `audit-ssh.js:12` :
        « Ni `DELETE /schedules/<id>`, ni `POST /schedules/<id>/toggle`, ni … »
      et a `:72` : « un helper generique ouvrirait DELETE et les deux toggle
        sans qu'aucun code les demande »

    le LEGACY fait les deux
      `legacy/ssh-audit/js/main.js:767`  POST …/schedules/<id>/toggle
                              :775       DELETE …/schedules/<id>

> **On peut armer depuis le portail neuf, et on ne peut désarmer que depuis celui qu'on éteint.**

## 2. POURQUOI ÇA COMPTE PLUS QU'UNE CAPACITÉ MANQUANTE

    l'ordonnanceur tourne dans un fil INVISIBLE a `ps`
    une planification est RECURRENTE : elle ne demande la permission de
      personne a son echeance
    et son objet est une SESSION SSH sur les machines de sa portee

**Une capacité manquante gêne. Celle-ci laisse un geste ACTIF sans son interrupteur** — *et le jour où le
legacy est éteint, l'interrupteur disparaît avec lui pendant que la planification, elle, reste en base.*

    ssh_audit_schedules : 0 ligne aujourd'hui
    -> le defaut est LATENT, et il le reste tant que personne n'a cree
       de planification depuis le portage.

**⚠ C'est exactement l'inverse de l'ordre de sûreté** : *le geste qui ARME est porté, celui qui DÉSARME ne
l'est pas.* **La même forme que l'asymétrie de `fail2ban` — l'installation sur tout le parc portée, celle
sur une machine non — mais avec une conséquence qui persiste dans le temps.**

## 3. ✅ CE QUE JE TRANCHE

**PORTER `DELETE /schedules/<id>` et `POST /schedules/<id>/toggle`, avant l'extinction du legacy.**

    ⛔ et NON par un helper generique : la raison ecrite dans le portage est
       juste — « un `envoie(methode, chemin)` ouvrirait DELETE et PATCH sans
       qu'aucun code les demande ». Deux helpers NOMMES, comme `supprime()`
       l'est deja dans `groupes.js`.
    ✅ la suppression VISE la planification affichee, jamais un identifiant
       repris d'un champ de saisie — c'est le defaut que le portage de
       `wazuh` vient de corriger sur les regles, et le legacy le porte ici
       aussi.
    ✅ et le panneau de confirmation NOMME la planification : son intitule,
       sa portee, et sa prochaine echeance.

**Ces deux routes n'ouvrent AUCUNE session SSH et n'écrivent qu'en base — elles ne sont sur aucune liste
d'interdits.**

## 4. 🔴 ET UNE SECONDE TROUVAILLE, DE LA FAMILLE DU `DOSSIER-21`

    GET  /ssh-audit/policies   @require_api_key
                               @require_permission('can_audit_ssh')
                               @require_machine_access
    POST /ssh-audit/policies   @require_api_key
                               @require_role(2)   SEUL

> **La LECTURE exige la permission ET le bornage par machine. L'ÉCRITURE n'exige qu'un rôle.**

**Un compte de rôle 2 SANS `can_audit_ssh` peut donc ÉCRIRE une politique SSH qu'il n'a pas le droit de
LIRE — et sans aucun bornage par machine.**

**C'est E-390 à l'envers** : *là, la lecture était nue et l'écriture gardée ; ici c'est l'écriture qui est
la moins gardée des deux.* **Et le forgeur de requêtes du menu (`DOSSIER-21`) la rend atteignable en trois
clics.**

    le portage ne la compose NULLE PART (SEC-013, delibere et ecrit)
    -> l'exposition passe par le legacy et par la passerelle

**✅ Correctif AUTORISÉ, même forme que E-389/E-390/E-391 : `@require_permission('can_audit_ssh')` et
`@require_machine_access`, miroir exact de son jumeau en lecture.** *Il ne casse aucun appelant légitime :
le portage ne l'appelle pas, et le legacy l'appelle depuis une page qui exige déjà `can_audit_ssh`.*

## 5. CE QUI VOUS REVIENT

    ✅ le correctif du §4          autorise, il ne demande rien de vous
    ✅ le portage du §3            route, aucune session SSH, aucun interdit
    📌 et RIEN d'autre — sauf de savoir que tant que le legacy est servi,
       l'interrupteur existe. C'est l'extinction qui rend le §3 urgent,
       pas son absence aujourd'hui.

---

# ⛔ CORRECTION DU §4 — mon « miroir exact » ÉLARGISSAIT l'écriture à un rôle 1

**Vérifié après réfutation. Le correctif est posé (`356caea`, E-392) mais PAS sous la forme que j'avais
prescrite, et la différence est mesurée.**

    ce que j'ecrivais   « @require_permission('can_audit_ssh') +
                          @require_machine_access, miroir exact du jumeau
                          en LECTURE »
    le jumeau en LECTURE ne porte AUCUN role.
    -> un miroir STRICT retirait `@require_role(2)`

    et la page legacy admet un ROLE 1 porteur de la permission :
      `legacy/ssh-audit/index.php:12-13`
        checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])
        + checkPermission('can_audit_ssh')

> **Mon « miroir » aurait ouvert l'ÉCRITURE d'une politique SSH à un rôle 1. Sur un geste d'écriture, la
> symétrie avec la lecture n'est pas la bonne cible.**

    can_audit_ssh, comptes ACTIFS :  role 3 -> 1  ·  role 2 -> 1  ·  role 1 -> 0
    (temoin : 12 comptes actifs)

**⚠ ZÉRO rôle 1 la porte aujourd'hui — donc l'élargissement aurait été INVISIBLE à la mesure et effectif au
premier octroi.** *C'est la forme la plus désagréable d'un défaut : correct au moment où on l'écrit, faux au
moment où quelqu'un l'emploie.*

**✅ La forme retenue est ADDITIVE** : `role(2)` **ET** permission **ET** `machine_access` — strictement plus
serré que les deux états antérieurs, sans aucune ouverture nouvelle.

## ⚠ ET `@require_machine_access` NE PEUT REFUSER PERSONNE ICI — c'est écrit au site

    `helpers.py:364`   `if role_id >= 2: return True`   SANS CONDITION
    et la ligne au-dessus exige justement `role(2)`.
    `machine_id` est de plus OPTIONNEL ici (`None` = politique GLOBALE).

**Il ne mordra que si le rôle venait à être relâché.** *Posé sans commentaire, c'était « un contrôle qui ne
commande pas l'action » à côté d'un contrôle qui commande — l'entrée exacte du catalogue. Il porte
désormais sa propre borne.*

## ✅ ET MON CRITÈRE, BALAYÉ SUR TOUT LE BACKEND, REND UN NÉGATIF GLOBAL

    27 chemins portent plusieurs methodes
     3 ont des gardes divergentes entre jumelles :
       /admin/notification_prefs   GET role(2) · POST role(3)   ecriture PLUS STRICTE ✔
       /admin/temp_permissions     GET role(2) · POST role(3)   ecriture PLUS STRICTE ✔
       /ssh-audit/policies         desormais fermee

> **Après ce correctif, AUCUNE route du backend n'a d'écriture moins gardée que sa lecture.**

**Et la nature du critère mérite d'être notée** : *« ni rôle ni permission » est une classe ABSOLUE ; ce
défaut-ci est RELATIONNEL — il n'existe que par comparaison entre deux routes du même chemin.* **Aucun
élargissement du critère absolu ne l'aurait rendu.**
