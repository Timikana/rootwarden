# DOSSIER 22 — Dans le service qui tourne, AUCUN contrôle ne lie un compte de rôle 3

**Pour signature de l'exploitant.** *Trouvé par la session 4 (pentest, angle 2) le 2026-09-03 ; les trois
affirmations qui portent la conclusion revérifiées par moi à 15:10 CEST.*

> **Ce dossier ne dénonce pas le court-circuit du rôle 3 : c'est une décision de conception assumée.** *Il
> dit ce qu'elle implique aujourd'hui, dans le processus en service — et ce que l'écran laisse croire du
> contraire.*

---

## 1. Ce qu'un rôle 3 SANS ligne de permissions atteint, chiffré

    sur 230 routes du BACKEND PYTHON (les decorateurs de `backend/routes/*.py`)
    ⚠ NE PAS additionner ni comparer avec les 91 routes AUTHENTIFIEES du PORTAGE :
       deux objets distincts, releves par deux sessions


     14   exigent `require_role(3)` SANS permission
          -> DECIDEES par le role. Poser `role_id = 3` est une decision, et elle est inscrite.

    124   ⚠ ont une PERMISSION pour SEUL discriminant
          -> franchies SANS AUCUN OCTROI
          -> et ZERO d'entre elles n'exige aussi le role 3 :
             la couche permission est INTEGRALEMENT inerte pour ce compte

    ------
    138   routes de delta sur un role 2 portant la MEME ligne vide

**Ce que ces 124 font une fois la permission franchie :**

    59  joignent une MACHINE par SSH
    54  ECRIVENT en base
    39  lecture pure

**Par permission** : `can_manage_supervision` 31 · `can_admin_portal` 22 · `can_manage_fail2ban` 19 ·
`can_manage_wazuh` 15 · `can_manage_graylog` 10 · `can_manage_bashrc` 8 · `can_manage_services` 8 ·
`can_manage_iptables` 7 · `can_view_compliance` 3 · `can_audit_ssh` 1.

---

## 2. ⚠ La ligne de permissions n'est pas vide : elle est ILLISIBLE

    backend/routes/helpers.py, require_permission :
      :19   if role_id >= 3:
      :20       return func(*args, **kwargs)
      :21   perms = get_user_permissions()      <- APRES le court-circuit

**Le court-circuit rend AVANT de consulter la table.**

> **Écrire une ligne de permissions pour un compte de rôle 3 ne changerait RIEN — ni en accordant, ni en
> refusant.**

**Conséquence opérationnelle** : *un exploitant qui voudrait **restreindre** un compte de rôle 3 ne peut
pas le faire par les permissions.* **Le seul levier est le rôle lui-même.**

### Et c'est ce qui rend l'absence de ligne TROMPEUSE

> **Un lecteur de la table `permissions` voit « rien accordé » et lit « ce compte ne peut rien faire de
> granulaire ». La réalité est l'inverse exact.**

**Le `DOSSIER-12` porte deux comptes dans ce cas** — *`id 77` (rôle 2) et `id 78` (rôle 3), créés à huit
secondes d'intervalle le 27/08 à 16:50, noms inversés, **aucun des deux n'a de ligne de permissions**, et
zéro sur douze tables (témoin : `id 1` porte 869 `user_logs`).*

---

## 3. ✅ Le court-circuit N'EST PAS un défaut, et le dire protège le reste

    ExigePermission.php:35   if ($roleId >= 3) { return $suite($requete); }
    helpers.py:19            le MEME court-circuit

**Deux implémentations indépendantes qui s'accordent sont une preuve d'INTENTION, pas un accident.**

> **Le défaut n'est pas le court-circuit : c'est qu'aucune trace ne distingue « rôle 3 DÉCIDÉ » de « rôle 3
> HÉRITÉ ».** *Et `id 78` n'a ni connexion, ni trace, ni ligne de permissions.*

---

## 4. Le SEUL contrôle du produit qui lie un rôle 3

    backend/approvals.py:68    ACTIONS_SANS_REPLI = frozenset({
                                 'regenerate_platform_key', 'revoke_service_account' })
                     :156-157  if role >= ROLE_SUPERADMIN
                                  and action_type not in ACTIONS_SANS_REPLI:  -> repli

    et `_compte_approbateurs_eligibles` : "WHERE u.active = 1 AND u.id <> %s"
      -> exclut le DEMANDEUR, et leve `AucunApprobateur` si personne d'autre

**La porte à quatre yeux sur ces deux actions est le seul contrôle qui ne cède pas au rôle 3.** *Tout le
reste — les 124 permissions et les 14 routes `role(3)` — il le franchit.*

---

## 5. ⛔⛔ ET CE SEUL CONTRÔLE N'EST PAS EN SERVICE

    backend/approvals.py   modifie le  2026-08-27 18:22:53 CEST
    le processus servi a demarre le    2026-08-27 14:28 CEST  (12:28 UTC)
    -> le fichier est 3 h 55 PLUS RECENT que le processus qui le sert

**`approvals.py` figure parmi les 20 modules commités et INERTES** (`DOSSIER-01`). *Et le geste qui fait
interroger `gate()` sur ces deux actions est **E-201**, écrit cette semaine.*

> **Donc, dans le service qui tourne aujourd'hui, il n'existe AUCUN contrôle qui lie un compte de rôle 3.**
> *Le seul qui existe est dans l'arbre, et il attend le redémarrage.*

**C'est le fait le plus net de ce dossier, et il ne demande aucune interprétation.**

---

## 6. Ce que ça change à trois dossiers déjà ouverts

    DOSSIER-01  le redemarrage       -> il ne « met pas en service 20 modules » :
                                        il met en service LE SEUL CONTROLE qui lie un role 3
    DOSSIER-12  les deux comptes     -> `id 78` n'est pas « un compte de trop » :
                                        c'est un compte que RIEN ne borne aujourd'hui
    DOSSIER-02  le compte approbateur -> il ajoute des comptes de role >= 2 ; a lire
                                        avec le present dossier avant d'etre signe

**Ordre recommandé** : *`DOSSIER-01` (le redémarrage) AVANT `DOSSIER-02` (l'ajout de comptes).* **Ajouter
des comptes privilégiés dans un service où le seul garde du rôle 3 est inerte est l'ordre inverse de celui
qu'il faut.**

---

## Ce qui n'est pas mesuré

- **rien n'a été exercé, et aucun compte de rôle 3 n'a été employé** ;
- **ce que les 59 routes SSH font réellement sur une machine** — *seulement qu'elles en joignent une. Les
  classer par effet demanderait de résoudre leurs commandes, et la sonde de son autrice s'est trompée deux
  fois aujourd'hui sur ce genre d'extraction* ;
- **une TROISIÈME couche de contrôle, s'il en existe une.** *La recherche est bornée aux décorateurs et à
  `approvals.py`, et son autrice le déclare :* **`/update_security_exec` a déjà montré qu'une route peut
  s'authentifier dans son corps.** *Un contrôle hors décorateur bornant un rôle 3 échapperait à ce
  relevé.*


---

## ⚠ PRÉCISION 22:50 — ce chiffre porte sur le BACKEND, pas sur le portage

**Relevé par la session 5, et c'est la faute que je corrige chez les autres depuis ce matin.**

    mes 124   routes du BACKEND PYTHON dont une PERMISSION est le seul discriminant
    ses 15    routes du PORTAGE LARAVEL dans le meme cas

**Deux objets distincts, relevés par deux sessions.** *Ne pas les additionner, ne pas les comparer.*

> **C'est le cinquième faux désaccord de la semaine, et toujours la même cause : l'objet non nommé.**
> *J'avais écrit « sur 230 routes » sans dire lesquelles — et le mot « backend » figurait ailleurs dans
> le fichier, jamais à côté du chiffre.*

### Et son relevé du portage, pour mémoire — 91 routes authentifiées

    41  permission + role:2        17  permission + role:3
    15  permission SEULE           <- le meme motif que mes 124, cote portage
     8  aucune garde au-dela de l'authentification
     5  role:1 seul   ·   3  role:3 seul   ·   2  role:2 seul

**Les 8 « sans garde » ont été regardées une à une et sont légitimes** : *`accueil`, `cgu` (GET+POST),
`profil`, le mot de passe, les deux `step-up`, et le relais de passerelle.* **Aucune n'a d'objet à
protéger au-delà de l'authentification.**
