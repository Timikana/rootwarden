# ⚠ DOSSIER 27 — `/wazuh/group` redémarre un agent de production et rend un verdict sur autre chose

**Trouvé par la session 4 le 2026-09-04 à 19:30, et **RECADRÉ par moi** : sa version était plus grave que
la réalité sur un point, et exacte sur celui qui compte.**

---

## 1. ⛔ D'ABORD CE QUI EST FAUX DANS L'ALERTE QUI M'EST ARRIVÉE

**On m'a écrit : « il rend `success: true` pour un changement qu'il n'a pas fait ». Ce n'est plus vrai.**

    wazuh.py:947-952, le commentaire :
      « Ce bloc JETAIT le resultat du redemarrage, ecrivait `group_name` en
        base et rendait `success: True` quoi qu'il arrive. »

**C'est la description d'un défaut DÉJÀ CORRIGÉ.** *Le code actuel refuse (`success: False`) quand le code
de retour est non nul, journalise `set_group_fail`, et n'écrit `group_name` en base qu'après un
redémarrage réussi.*

> **Un commentaire qui décrit le défaut qu'il corrige se lit comme une description du comportement
> actuel.** *C'est le piège que ce chantier a payé plusieurs fois, et il vient de coûter une alerte de plus
> — la mienne s'arrête ici plutôt que d'aller jusqu'à vous.*

## 2. ✅ ET CE QUI RESTE VRAI, MESURÉ LIGNE À LIGNE

    la SEULE commande executee :
      execute_as_root(client, "systemctl restart wazuh-agent", …)

    et les commentaires du site nomment TROIS mecanismes, dont AUCUN n'est
    dans le corps :
      :936  « Ecrit le groupe dans /var/ossec/etc/ossec.conf »
      :937  « update via agent-auth au prochain restart, ou via API manager »
      :941  « Update /var/ossec/etc/shared/agent.conf ou marquer dans client.keys »
      et le docstring : « via API manager OU FICHIER LOCAL »

    ce que le corps fait : un redemarrage. Rien d'autre sur la machine.
    ce qu'il ecrit : `group_name` EN BASE.

> **Le geste repose sur une hypothèse que le code n'établit jamais : que l'agent, en redémarrant, se
> ré-inscrive dans le nouveau groupe.** *Or rien ici n'écrit ce groupe où l'agent le lirait.*

**Conséquence exacte, et elle est différente de l'alerte :**

    ✅ le verdict sur le REDEMARRAGE est honnete depuis le correctif
    ⛔ il n'y a AUCUN verdict sur le GROUPE, et c'est le groupe qu'on demandait
    ⛔ et le geste REDEMARRE un agent de supervision sur une machine de
       production pour obtenir cet effet non verifie

## 3. CE QUE ÇA COÛTE, ET À QUI

    atteignable   `legacy/wazuh/index.php:275` porte `wazuh.btn_setgroup`
                  le legacy est SERVI -> le bouton existe aujourd'hui
    garde         les 15 routes backend portent TOUTES `@require_role(2)` ET
                  `@require_permission('can_manage_wazuh')`. 0 route nue.
                  -> ce n'est pas un trou d'acces : c'est un geste legitime
                     qui ne fait pas ce qu'il annonce
    effet         un redemarrage d'agent Wazuh sur la machine visee, et une
                  base qui affirme un groupe dont rien ne confirme
                  l'application

**Le portage, lui, ne câble AUCUN des six gestes d'écriture** — `btn_install`, `btn_install_all`,
`btn_uninstall`, `btn_restart`, `btn_detect`, `btn_setgroup` : *0 occurrence dans la vue et dans le JS,
avec témoin positif (`np_titre` 1, `np_liste` 1, `title` 4).* **Le portage LIT et n'ÉCRIT jamais.**

## 4. ✅ L'ARBITRAGE QUE JE RENDS — ne PAS le porter tel quel

> **Porter `set_group` reproduirait une promesse que le code ne tient pas, avec un bouton neuf et un
> libellé qui y croit.** *(formulation de la session 4, et elle est juste)*

    ⛔ ne pas TRANSCRIRE : le portage heriterait d'un geste dont l'effet
       n'est pas verifie, et il l'annoncerait a un ecran neuf
    ✅ deux issues, et elles sont a vous parce qu'elles touchent une machine :
       (a) l'IMPLEMENTER — ecrire le groupe la ou l'agent le lit, puis
           redemarrer, puis VERIFIER ; c'est un geste d'ECRITURE distante
       (b) le RETIRER — et dire dans le portage que l'assignation de groupe
           se fait cote manager Wazuh, pas depuis ce portail

**Ma recommandation : (b), et pour une raison de périmètre.** *RootWarden supervise ; l'appartenance d'un
agent à un groupe est une donnée du manager Wazuh. Reproduire ici un chemin d'écriture non vérifié vers un
outil qui a le sien est le mauvais côté du rapport utilité/exposition.*

## 5. ⛔ CE QUE JE NE FAIS PAS, ET NE FERAI PAS SANS VOTRE MOT

    aucun des SIX gestes d'ecriture de `wazuh` n'est exerce — ils installent,
    desinstallent ou redemarrent sur des machines reelles, et ils sont sur
    la liste des interdits permanents de ce chantier.

**Rien n'a été exercé pour écrire ce dossier : l'appariement est une lecture de code et de libellés.**

## 6. SI RIEN N'EST FAIT

**Le bouton reste dans le legacy tant qu'il est servi, et il continue de redémarrer un agent pour un effet
que personne ne vérifie.** *Le portage, lui, n'offre rien — donc l'extinction du legacy ferme le geste
d'elle-même, sans décision.*

> **C'est le cas inverse de la classe 3 : ici l'archivage silencieux ferait le BON geste par accident.**
> *Je le signale quand même, parce qu'une capacité qu'on croit avoir n'est pas la même chose qu'une
> capacité qu'on a décidé de ne pas avoir.*
