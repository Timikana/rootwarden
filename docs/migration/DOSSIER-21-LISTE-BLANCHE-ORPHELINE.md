# DOSSIER 21 — Une liste blanche a survécu aux pages qu'elle servait : `apt-get full-upgrade` en root par requête forgée

**Trouvé par la session 4 (pentest, angle 1) le 2026-09-03. Chaîne revérifiée par moi maillon par maillon
à 11:55 CEST.** *Établie par LECTURE — non exercée, et délibérément.*

> **Une entrée de liste blanche ne se retire pas toute seule quand la page qu'elle servait meurt.**

---

## 1. La chaîne, vérifiée

    1. legacy/api_proxy.php:24
         checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])
         -> une session de ROLE 1 est acceptee

    2. POST forge   /api_proxy.php/apt_update   {"machine_id": N}

    3. $ALLOWED_PROXY_PREFIXES   63 entrees, `/apt_update` PRESENT   -> passe
    4. $ADMIN_ONLY_PREFIXES      25 entrees, `/apt_update` ABSENT    -> passe

    5. backend/routes/updates.py:409-412
         @require_api_key           (la cle est fournie PAR le proxy)
         @require_machine_access
         @threaded_route
         -> AUCUN @require_role, AUCUN @require_permission

    6. `apt-get update && apt-get full-upgrade -y` EN ROOT sur la machine N

**23 des 58 routes concernées n'ont AUCUNE autorisation au-delà de la clé d'API. 13 MUTENT** —
*`apt_update` (`full-upgrade`), `custom_update` (`install -y`), et les trois `schedule_*` qui **écrivent
un `/etc/cron.d/*` tournant en root**.*

---

## 2. La cause, et elle n'est ni la méthode-aveugle ni le `roleId < 2`

    legacy/_deprecated/update/   EXISTE  ->  la page est PORTEE et ARCHIVEE
    ... et `api_proxy.php` liste TOUJOURS ses routes

> **La liste blanche a survécu aux pages qu'elle servait.** *Aucune page vivante n'expose ces routes ; le
> portage les refuse à sa passerelle ; le proxy legacy les laisse passer.*

**Et c'est l'inverse exact de la doctrine SEC-013** : *là, l'absence de page était invoquée comme une
fermeture.* **Ici, l'absence de page a laissé une entrée ORPHELINE.**

---

## 3. Les bornes, et elles réduisent la gravité — mesurées par son autrice

    session AUTHENTIFIEE requise      -> pas d'anonyme
    role 1 suffit MAIS               `check_machine_access` MORD a ce role
                                      -> la portee est les machines ATTRIBUEES au compte,
                                         PAS le parc
    aucun chemin cliquable            la page est deprecee, le portage ne l'expose pas
                                      -> c'est une REQUETE FORGEE, pas un parcours d'ecran

**Non mesuré** : *combien de comptes de rôle 1 ont des machines attribuées.* **Donc le chemin EXISTE ; son
exploitabilité aujourd'hui n'est pas établie.**

---

## 4. ✅ Et voici le premier point où « full Laravel » AIDE au lieu de coûter

> **Démonter `legacy/` FERME cette exposition** — *`api_proxy.php` disparaît avec lui, et le portage
> refuse déjà ces routes à sa propre passerelle.*

**C'est le seul élément de la série des dossiers dont la bascule soit le remède plutôt que le risque.**
*Tous les autres — la réinitialisation de mot de passe, l'octroi sudo, l'export RGPD — sont des capacités
que le démontage SUPPRIME.*

**Correctif immédiat, si le démontage tarde** : *retirer de `$ALLOWED_PROXY_PREFIXES` les entrées dont la
page est dans `_deprecated/`.* **C'est un geste de liste, pas de logique — et il se contrôle par
énumération.**

---

## 5. ⚠ Et une méthode à retenir : les DEUX portails n'ont pas la même liste

    legacy   $ADMIN_ONLY_PREFIXES   25 entrees
    portage  ADMIN_SEULEMENT        44 entrees
    communes                        16

    9 fermes par le LEGACY seul    -> ne coutent RIEN : les neuf portent role(2)+
                                      au backend, et la passerelle ne refuse
                                      qu'en dessous de 2.  ⚠ dedouanement MESURE,
                                      et son autrice allait l'annoncer comme un trou
    28 fermes par le PORTAGE seul  -> les 58 routes ci-dessus

**Deux listes pour une même règle finissent par diverger. Ici la divergence est de 28 entrées, et c'est le
portage qui est le plus strict.**

---

## 6. La méthode-aveugle de `correspond()` : mesurée, et elle ne coûte qu'une fois

**Sur 28 chemins servant plusieurs méthodes, 3 ont des gardes qui diffèrent selon la méthode :**

    /admin/notification_prefs   GET role(2)  ·  POST role(3)
    /admin/temp_permissions     GET role(2)  ·  POST role(3)
    /ssh-audit/policies         GET permission+machine_access  ·  POST role(2)

**Et `ROLE_ADMIN = 2` (`verify.php:45`), comme le `roleId < 2` du portage : les deux passerelles refusent
au même seuil.** *Donc sur `/admin/*` les couches se COMPOSENT — passerelle grossière, backend fin — et il
n'y a aucune divergence.*

**Le seul coût réel** : *`/ssh-audit/policies` est infixable à la passerelle, son GET devant rester
ouvert.* **C'est pourquoi E-236 ne peut être fermé qu'au backend.**

---

## Ce qui n'est pas mesuré

- **la chaîne n'a PAS été exercée.** *L'exercer installerait des paquets sur une machine réelle — la
  démontrer serait la commettre* ;
- **combien de comptes de rôle 1 ont des machines attribuées** — *la seule mesure qui dirait si c'est
  exploitable aujourd'hui* ;
- **les 63 entrées de `$ALLOWED_PROXY_PREFIXES` une par une** : *seules les 58 sans `role >= 2` ont été
  classées, et 23 d'entre elles sans aucune autorisation.* **Il peut en rester.**
