# QA — le champ `archive` doit être LU : critères, et pourquoi ils visent I5

**Le backend rend le champ depuis le 2026-09-08** (`1a5dbf32`, rectifié `7a59a445`) :

    {"success": true, …, "archive": true}
    {"success": true, …, "archive": false, "archive_motif": "echec_archivage"}
    {"success": true, …, "archive": false, "archive_motif": "etat_precedent_vide"}

## ⛔ LA MOITIÉ ÉCRAN N'A PAS D'OBJET DANS LE PORTAGE AUJOURD'HUI

Mesuré à l'AST sur `laravel/public/js/pare-feu.js` — **7 appels**, aucun n'applique :

    :307  /iptables  action=get      lecture
    :710  /iptables-validate         essai a blanc
    :395 · :475 · :548               trois routes DU PORTAGE (copie, historique)

    TEMOIN  geste-porte.py : /iptables APPELE · /iptables-apply, -restore,
            -rollback ABSENTS · /zzz-temoin ABSENT

Et le routeur le déclare lui-même — `web.php:1033` : *« garde `'legacy' => '/iptables/'`
**jusqu'à I5** : la page portée ne rend que… »*

**Les quatre routes qui appliquent ne sont appelées que par le legacy**
(`legacy/iptables/js/main.js` — apply `:135`, restore `:171`, rollback `:475`).

> **Le portage ne peut pas afficher `archive: false` : il ne reçoit jamais cette réponse.**
> Ce n'est pas un oubli d'affichage, c'est un geste qui n'est pas porté.

### Pourquoi je n'écris pas l'affichage dans le legacy

C'est la seule interface qui applique aujourd'hui, donc le défaut y est **vivant**. Mais I5 est
en cours d'écriture : le code d'affichage posé dans `legacy/iptables/js/main.js` serait **jeté
avec la page, dans les heures qui viennent**. *Porter n'est pas reproduire — et réparer ce qui
s'éteint coûte le même travail deux fois.*

**Si l'exploitant juge que la fenêtre d'ici I5 doit être couverte, c'est sa décision et elle
change ma réponse.** Elle n'est pas mienne : le legacy est du code applicatif en extinction.

---

## Les critères, à tenir par I5

### A1 — le champ se voit QUAND LE GESTE RÉUSSIT

**C'est le cas dangereux, et le seul qui compte.** `success: true`, l'écran vert, et la trace
manque. *Un avertissement rangé dans un panneau replié ne le dit pas* — il doit être dans le
flot principal du retour, au même endroit que le succès qu'il nuance.

⛔ **Ce qui ne satisfait PAS A1** : un badge dans un onglet, une ligne de journal, un
`console.warn`, un message qui n'apparaît qu'au survol.

### A2 — les deux motifs se disent DIFFÉREMMENT

    etat_precedent_vide   une INFORMATION : il n'y avait rien a archiver
    echec_archivage       un INCIDENT : la base n'a pas repondu

**Les fondre annulerait ce que la séparation vient d'obtenir.** *Un verdict unique pour deux
causes fait chercher au mauvais endroit* — et ici les réactions sont opposées : la première ne
demande rien, la seconde demande d'aller voir la base avant le prochain geste.

### A3 — le message dit CE QUI MANQUE, pas seulement qu'il manque

Sur `echec_archivage` après un **rollback**, la conséquence est précise et doit être écrite :
*l'état que vous venez de quitter n'est plus archivé — un retour en avant n'est plus possible.*

### A4 — la mesure ne dépend pas du service

**Construire les trois réponses soi-même**, sans appeler le backend. Un test qui exige un
service redémarré n'est pas un test, c'est une attente.

### A5 — un témoin positif, en premier

Le cas `archive: true` doit être exercé **avant** les deux autres. *Sans lui, « le message ne
s'affiche pas » et « l'écran ne sait pas afficher ce message » sont la même sortie.*

---

## Ce que ces critères n'établissent pas

- **Que le backend rend bien le champ en service.** Il le rend **sur le disque** ; le process
  n'a pas été redémarré. *Aucune lecture ne peut attester ce qu'un service exécute.*
- **Le cas des routes appelées hors portage.** Un porteur de clé d'API lit la réponse lui-même
  ou l'ignore ; aucun écran ne le couvre, et ce n'est pas le rôle d'un écran.
