# Ce que le redémarrage de `rootwarden_python` fera prendre effet

Mesuré le **2026-08-27**, session 4. Le Lead remonte à l'exploitant la **priorité du redémarrage**.
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

| | 2026-08-27 soir | **2026-08-28 · 08:14Z** |
|---|---|---|
| commits touchant `backend/` depuis le démarrage | 23 | **36** |
| fichiers source dont le **code** change (docstrings et commentaires exclus) | 19 | **20** |
| fichiers où **seule la prose** change | 0 | **0** |
| fichiers de test (sans effet sur le service) | 2 | 2 |

**Le `StartedAt` n'a pas bougé entre les deux relevés** — c'est le lot qui grossit, pas la référence
qui glisse. **+13 commits et +1 module en une nuit**, et le module ajouté est `wazuh.py` : **le mien**.

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

### ⚠ CORRECTION — CETTE LIGNE EST LA PLUS SPECTACULAIRE ET LA MOINS COÛTEUSE

Le tableau ci-dessus classe le risque par **l'écart de permission**. Mesuré le 2026-08-28 sur
`user_logs` — **2855 lignes** émises par des comptes de rôle < 3 — le classement par **usage réel**
l'inverse :

| page | détenteurs | actions historiques d'un compte rôle < 3 |
|---|---|---|
| `iptables` | **0 / 9** | **0** ← personne ne s'en est jamais servi |
| `ssh-audit` | 1 / 9 | **0** |
| `fail2ban` | 1 / 9 | **22** |
| `services` | 1 / 9 | **8** |

Et les 30 actions `fail2ban` + `services` viennent d'**un seul compte, qui ne détient ni l'une ni
l'autre permission** — sa dernière action de ce type date du **2026-08-27 à 16 h 23**.

> **Le redémarrage retire donc une capacité à un compte qui s'en servait la veille.** Ce n'est pas le
> pare-feu, dont le chiffre alarmant décrit une capacité que personne n'a jamais exercée. *Un écart se
> classe par ce qu'il coûte, pas par l'ampleur du nombre qui le décrit.*

**Deux permissions attribuées avant le redémarrage suffisent à supprimer tout l'impact observable** —
`can_manage_fail2ban` et `can_manage_services`, sur ce compte. Les deux autres restent à faire, mais
elles ne rattrapent aucun usage.

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

1. **Attribuer les quatre permissions aux comptes qui en ont l'usage, AVANT le redémarrage.** Sinon
   neuf comptes perdront des pages du jour au lendemain, et `iptables` pour la totalité d'entre eux.
2. **Redémarrer hors d'un rejeu du LOT** — `backend/**.py` est lu au démarrage, un redémarrage en
   cours de suite invalide la mesure en cours.
3. **Observer ensuite les 19 modules**, pas seulement le correctif qu'on attendait.

**La décision de redémarrer n'est pas la mienne**, et le moment non plus. Ce document existe pour
qu'elle soit prise en sachant ce qu'elle déclenche.
