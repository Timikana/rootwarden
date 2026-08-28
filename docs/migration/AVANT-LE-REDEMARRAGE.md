# Ce que le redémarrage de `rootwarden_python` fera prendre effet

> **Toutes les heures de ce document sont en UTC, avec leur équivalent CEST entre parenthèses.**
> Les conteneurs sont en UTC, l'hôte en CEST (**UTC+2**), et E-73 a déjà fait décider de travers sur
> ces deux heures d'écart. *Une heure sans fuseau dans un document de décision est une heure fausse
> pour la moitié de ses lecteurs.*

Mesuré le **2026-08-27 vers 16:50 UTC** (18:50 CEST), session 4. Le Lead remonte à l'exploitant la **priorité du redémarrage**.
Ce document dit ce qui changera **au moment où il aura lieu** — pas la liste des correctifs, mais
**ce qui cessera de fonctionner pour des comptes réels**.

---

## 0. Le service ne tourne sur aucun de ces correctifs

```
StartedAt du conteneur   2026-08-27T12:28:43Z
commit servi             6663e83
fichiers modifies depuis 18:10 -> 18:40
```

**Aucun redémarrage n'a eu lieu.** C'est la comparaison qui fait foi — `docker inspect StartedAt`
contre le `mtime` des fichiers — et non une introspection du processus, qui décrirait le fichier et
non le serveur.

| | **2026-08-27 · 16:50 UTC** (18:50 CEST) | **2026-08-28 · 08:14 UTC** (10:14 CEST) |
|---|---|---|
| commits touchant `backend/` depuis le démarrage | 23 | **36** |
| fichiers source dont le **code** change (docstrings et commentaires exclus) | 19 | **20** |
| fichiers où **seule la prose** change | 0 | **0** |
| fichiers de test (sans effet sur le service) | 2 | 2 |

**Le `StartedAt` n'a pas bougé entre les deux relevés** — c'est le lot qui grossit, pas la référence
qui glisse. **+13 commits et +1 module en 15 h 24** (16:50 UTC → 08:14 UTC), et le module ajouté est `wazuh.py` : **le mien**.

> **Attendre ne réduit pas le risque de ce redémarrage : ça l'augmente.** Le seul risque réel de ce
> lot est sa **taille** — vingt modules qui prendront effet ensemble sans qu'aucun n'ait jamais été
> observé en fonctionnement. *Chaque livraison qui « prépare » le redémarrage agrandit ce qu'il faudra
> observer d'un coup.* Je l'écris en sachant que j'y contribue.

Le classement code/prose est fait par comparaison d'**arbres syntaxiques normalisés**, pas par
`git diff` : un fichier dont seule une docstring bouge rendrait le même arbre. **Aucun n'est dans ce
cas** — les 19 changent réellement de comportement.

> **Le risque n'est pas qu'un correctif soit faux. C'est que dix-neuf modules changent ensemble, et
> qu'aucun n'ait jamais été observé en fonctionnement.** *Un correctif inerte n'est pas un correctif
> en attente : c'est un correctif dont le comportement n'a jamais été vu.*

---

## 1. ⚠ CE QUI CESSERA DE FONCTIONNER, ET POUR QUI

Vingt-six routes gagnent une permission (E-149, E-152), une en gagne une autre (E-211). Ces gardes
**court-circuitent au rôle ≥ 3** : les comptes d'administration ne voient rien changer. **Les autres,
si.**

| | comptes actifs |
|---|---|
| total | **12** |
| rôle ≥ 3 — **aucun changement pour eux** | 3 |
| rôle < 3 — **concernés** | **9** |

Parmi ces neuf, combien détiennent déjà la permission qui deviendra nécessaire :

| permission | routes concernées | détiennent |
|---|---|---|
| `can_manage_services` | 8 | **1 / 9** |
| `can_manage_fail2ban` | 15 | **1 / 9** |
| `can_manage_iptables` | 5 | **0 / 9** ⚠ |
| `can_audit_ssh` | 1 | **1 / 9** |

> **Aucun compte non-administrateur ne peut plus toucher au pare-feu après le redémarrage.** Ce n'est
> pas un défaut du correctif — c'est son effet voulu, et c'est exactement pourquoi il doit être
> annoncé avant et non constaté après. *Un durcissement non annoncé est indiscernable d'une panne.*

### ⚠⚠ DEUX CORRECTIONS SUCCESSIVES, ET LA PREMIERE ETAIT FAUSSE DU COTE QUI FAIT AGIR

**Première correction (2026-08-28 · 08:14 UTC, soit 10:14 CEST) — et elle était FAUSSE.** Elle affirmait, sur un décompte
de `user_logs`, que `fail2ban` et `services` avaient **30 actions historiques** d'un compte de rôle < 3
et que « le redémarrage retire une capacité à un compte qui s'en servait la veille ». Elle en tirait
une recommandation : **attribuer deux permissions à ce compte avant le redémarrage.**

**Ce que disent réellement ces 30 lignes, lues et non comptées :**

```
Permission refusee : can_manage_fail2ban    22
Permission refusee : can_manage_services     8
```

**Ce sont 30 REFUS.** Pas une seule action réussie. Ce sont les lignes que le contrôle de permission
écrit **quand il refuse**. Et le compte est **`rw-test-user` (id 14)** — rôle 1, aucune permission,
**la fixture que le plan interdit de toucher** : celle dont la privation de droits *est* le dispositif
de mesure, employée par plusieurs suites pour vérifier qu'un rôle 1 reçoit bien un 403.

> **La recommandation aurait fait accorder deux permissions à la fixture qui sert à mesurer leur
> absence.** Les suites seraient restées vertes en cessant de mesurer quoi que ce soit — le faux vert
> exact que ce chantier combat.

**Le mécanisme de la faute** : un `COUNT(*)` sur des lignes contenant « fail2ban » **ne distingue pas
un geste d'un refus**. *Un observable ne dit jamais par quel chemin il a été produit.* Et il s'est
trompé **du côté qui alarme, c'est-à-dire du côté qui fait agir** — une erreur dans un compte rendu se
corrige au tour suivant ; celle-ci proposait un geste sur un compte protégé.

### Ce que la même méthode donne sur la BONNE donnée

En excluant les refus, sur les comptes de rôle < 3 :

| page | usages RÉELS |
|---|---|
| `iptables` | **0** |
| `fail2ban` | **0** |
| `services` | **0** |
| `ssh-audit` | **0** |

**Zéro sur les quatre.** C'est plus fort que ce que la première correction annonçait, et dans l'autre
sens : **le durcissement ne retire aucun usage.** Il déplace un refus déjà en vigueur de la page vers
la route.

> Et les 30 lignes, une fois lues, **prouvent que la garde fonctionne** au lieu de la contredire.

*Le classement par usage réel restait la bonne méthode. C'est sa donnée d'entrée qui était fausse.*

### Et un précédent qui rassure, mesuré aussi

`can_manage_wazuh` est exigé par les **15** routes de `wazuh.py` **dans le code qui tourne
aujourd'hui**, et **0 compte non-administrateur ne le détient**. La situation « une permission que
personne ne porte » existe donc **déjà en production, sans incident** — parce que personne n'utilise
cette page. C'est ce qui rend crédible que `iptables` et `ssh-audit` passent de même.

### Et le point qui dédouane, dit aussi nettement

**Ce n'est pas un verrouillage.** Les quatre permissions sont **accordables par l'interface** :
`legacy/adm/includes/manage_permissions.php:25` porte leur libellé, `api/update_permissions.php:146`
écrit, et le portage les expose aussi. Un administrateur les attribue en quelques clics.

**C'est donc une tâche de configuration à faire — de préférence avant le redémarrage, pas après.**

---

## 2. Ce qui change aussi, et qui ne bloque personne ici

| changement | effet sur cette installation |
|---|---|
| approbation à quatre yeux réellement interrogée sur les deux gestes de flotte (E-201, E-205) | **workable** : `APPROVAL_ENABLED=true` était **déjà** dans l'environnement, et **3 approbateurs éligibles** existent — un demandeur a toujours au moins deux autres comptes pour approuver |
| `POST /deploy` gagne `role(2)` + `machine_access` (E-191) | seuls les rôles ≥ 2 déploient des clés ; c'était `@require_api_key` **seule** |
| `deploy_service_account` et `revoke_service_account` passent par le compte de service quand il existe (E-218) | change le **chemin de connexion** de deux routes |
| `service_account_deployed` mis à 0 sur une révocation partielle (E-220) | fait **exécuter** `ensure_sudo_installed` au déploiement suivant (`configure_servers.py:758`) |
| rotation de clé plateforme : archive au lieu de détruire | un répertoire d'archive apparaît, purge à 30 jours |

**Le défaut de mon changement de valeur par défaut d'`APPROVAL_ENABLED` est nul ici** : la variable
est posée explicitement dans `srv-docker.env`. Je l'écris parce que je l'avais annoncé comme une
conséquence, et qu'il n'en est pas une **sur cette installation**.

---

## 3. Ce que je recommande, et ce qui ne m'appartient pas

1. **N'attribuer aucune permission au titre de ce redémarrage.** ⚠ Ce point disait l'inverse —
   *« attribuer les quatre permissions avant le redémarrage, sinon neuf comptes perdront des pages »*.
   **La mesure ne le soutient pas** : aucun compte de rôle < 3 n'a jamais exercé ces quatre
   capacités, et le seul candidat apparent était la fixture de test. Une permission accordée « au cas
   où » sur un compte qu'on n'a pas identifié est une élévation sans demandeur.
2. **Redémarrer hors d'un rejeu du LOT** — `backend/**.py` est lu au démarrage, un redémarrage en
   cours de suite invalide la mesure en cours.
3. **Observer ensuite les 20 modules**, pas seulement le correctif qu'on attendait.
4. **Ne pas attendre pour réduire le risque : attendre l'augmente.** C'est la seule chose que les deux
   relevés du §0 démontrent, et elle n'a pas bougé sous les deux corrections ci-dessus.

**La décision de redémarrer n'est pas la mienne**, et le moment non plus. Ce document existe pour
qu'elle soit prise en sachant ce qu'elle déclenche.
