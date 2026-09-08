# DOSSIER-50 — Le dernier fil : le retour arrière est le SEUL geste sans garde, et il est resté sur le legacy

**Écrit le 2026-09-08, ~04:5x, après la livraison d'I5.** *Le legacy n'existe plus que
pour une capacité.*

---

## L'ÉTAT, MESURÉ

I5 est porté : relevé, copie en base, validation à blanc, **et l'application**. Les quatre
propriétés obligatoires sont mesurées, aucune machine jointe. Mes quatre contrôles passent :

```
q3-retour-visible        0    les 8 titres ont leurs 3 destinataires (99=99, 89 curatees)
q1-gabarits              0
q2-ssh-ouvert            0
ports-des-deux-portails  0
```

**Il reste UN geste, et un seul :**

```
pare-feu.js, code depouille   iptables-apply     1 occurrence
                              iptables-rollback  0   <- la seule mention est un commentaire
pare-feu.blade.php:257        href = url_legacy . '/iptables/'
lang/fr/pare-feu.php:86       « Seul le retour arriere … reste sur l'ancien portail »
```

> **Le legacy tout entier — ses 11 racines, son vhost, sa chaîne d'auth, ses deux endpoints
> même-origine, son document 404 — n'existe plus que pour un bouton.**

---

## 🔴 ET CE BOUTON EST LE SEUL DES QUATRE QUI N'A AUCUNE GARDE

Relevé dans `legacy/iptables/js/main.js`, code dépouillé :

```js
async function rollbackRules(historyId) {
    if (!confirm(__('ipt_confirm_rollback'))) return;
    const r = await fetch(`${window.API_URL}/iptables-rollback`, { … });
```

**Un `confirm()` de navigateur, puis la requête.** Pas de Q1, pas de Q2, rien qui regarde
ce que le jeu de règles restauré fait du port SSH. *Les 13 `dport` et 34 `ACCEPT` du même
fichier sont les cinq gabarits figés à 22 — le défaut de Q1, pas une garde.*

### La répartition qu'on s'apprêtait à laisser en place

```
                     ou           garde
relever              portage      lecture seule
copier en base       portage      PDO local
valider a blanc      portage      Q3 (quatre issues, le statut discrimine)
APPLIQUER            portage      Q1 + Q2 + Q3 + Q4
RETOUR ARRIERE       LEGACY       confirm()
```

> **Laisser le retour arrière sur le legacy n'est pas de la prudence : c'est laisser le
> geste le plus dangereux des cinq sans aucune garde, pendant que le portail gardé prend
> les quatre plus sûrs.** *L'attente protège le portage, pas la machine.*

---

## 🔴 L'ASYMÉTRIE QUI DÉCIDE : ON NE VOIT PAS CE QU'ON RESTAURE

```
APPLIQUER        l'operateur ECRIT les regles. Il les a sous les yeux.
RETOUR ARRIERE   l'operateur choisit une DATE.
```

Mesuré sur le backend :

```
iptables_history garde   server_id · rules_v4 · rules_v6 · changed_by
                         change_reason · created_at
                         ⛔ AUCUN PORT
/iptables-history:354    SELECT id, changed_by, change_reason, created_at
                         ⛔ PAS LES REGLES
/iptables-rollback:396    SELECT … les regles, pour le seul id restaure
```

**La liste ne rend pas les règles.** L'opérateur choisit par date et par motif, sans voir
le contenu. *Q2 compte donc PLUS pour le retour arrière que pour l'application* — c'est le
seul des deux gestes où l'humain ne peut pas se relire.

### Et le piège est armé par la bonne pratique qu'on prescrit

L'archive ne garde pas le port. Une version archivée était **valide le jour où elle a été
archivée**. Si le port SSH de la machine a changé depuis — *c'est-à-dire si quelqu'un a
suivi le durcissement qu'on recommande par ailleurs* — la restaurer ferme l'accès.

> **Un jeu de règles archivé n'est pas un état sûr : c'est un état sûr POUR UNE
> CONFIGURATION QUI N'EST PLUS FORCÉMENT CELLE DE LA MACHINE.**

Et la reprise passe par `/iptables-rollback`, **qui passe aussi par SSH** : reprise =
console physique. *Même chaîne que pour l'application, mais déclenchée par un geste qu'on
croyait défensif.*

---

## ✅ CE QUE JE TRANCHE

**Le retour arrière se porte, avec Q1–Q4, et `iptables/index.php` s'éteint avec lui.**

La forme, et elle est disponible sans rien inventer :

```
1  recuperer le texte archive           /iptables-rollback:396 le SELECT deja
2  le passer a Q2 avec le port ACTUEL   rwLaisseLeSshOuvert(texte, port_machine)
   de la machine, jamais celui de
   l'archive — qui n'est pas garde
3  true   -> proposer le geste, et MONTRER le texte avant de le proposer
   false  -> refuser, en nommant le port qui n'est pas ouvert
   null   -> refuser, en disant qu'on ne peut pas conclure
4  Q4 : aucune requete avant consentement
```

**Le point 3 « montrer le texte » n'est pas un confort : c'est ce qui referme
l'asymétrie.** *Un geste dont on ne voit pas l'objet ne se consent pas, il s'accepte.*

**Ce que je ne demande pas :** enregistrer le port dans `iptables_history`. *Ça
n'aiderait qu'à expliquer un refus après coup ; Q2 sur le port actuel suffit à le
prévenir, et une colonne de plus est une migration de plus pour un renseignement que
personne ne lira.*

---

## CE QUE « PLUS DE LEGACY » DEMANDE, MAINTENANT — LA LISTE EST COURTE

```
1  porter le retour arriere avec Q1-Q4        session qui tient pare-feu.js
2  retirer pare-feu.blade.php:257             le dernier lien fonctionnel
   et corriger `pare-feu.suite`
3  ⛔ docker compose up -d                    L'EXPLOITANT — applique l'echange
                                              des ports, deja ecrit partout
4  les 11 racines s'eteignent ENSEMBLE        elles ne s'eteignent pas une par une :
                                              menu.php appelle ses deux endpoints
                                              en MEME ORIGINE
```

**Rien d'autre.** *Les 7 racines de la chaîne d'auth sont portées et relayées, les 2
endpoints meurent avec le vhost, `_sortie.php` est le document 404 du vhost lui-même.*

---

## ⚠ ET UNE CHOSE QUE JE N'AI PAS MESURÉE, DITE PLUTÔT QUE COMBLÉE

**Je n'ai pas vérifié au réseau que la page portée rend bien les cinq gestes à un compte
réel.** Les quatre contrôles que je cite sont des épreuves de MODULE : elles jugent du
texte et des retours, jamais une page servie. *Le vert de mes quatre contrôles ne dit pas
« la page marche » — il dit « ces propriétés tiennent sur ces modules ».*

Et la session qui tient le banc a mesuré deux fois cette nuit qu'**un défaut peut n'exister
qu'à l'image** : un panneau de consentement rendu hors de l'écran, `hidden = false`,
correctement rempli, invisible. **Quatrième occurrence dans ce chantier.** *Aucune de mes
assertions n'aurait pu le voir.*

---

# AMENDEMENT — la pré-relecture sécurité améliore l'arbitrage sur deux points

**2026-09-08, ~05:0x, après `e64fe070`.** *Ma conclusion tient ; deux de mes arguments sont
remplacés par de meilleurs, et un trou que je n'avais pas nommé est comblé.*

## ① MON ARGUMENT « Q2 COMPTE PLUS ICI » EST FAIBLE. LE BON EST : **Q2 MARCHE MIEUX ICI**

J'avais écrit que Q2 *compte* davantage pour le retour arrière, parce que l'opérateur ne
peut pas se relire. **La pré-relecture donne l'argument fort :**

> **C'est le geste où Q2 fonctionne LE MIEUX. Les règles sont connues À L'AVANCE — elles
> sont en base, `iptables_history.rules_v4`. Q2 peut donc tourner AVANT qu'aucune session
> SSH ne soit ouverte, sur le contenu exact qui partira.** *Sur `apply` l'opérateur compose ;
> ici l'objet existe déjà et se laisse inspecter.*

*Le mien décrivait un besoin ; celui-là décrit une possibilité.* **Un argument qui nomme ce
qu'on PEUT faire est plus fort qu'un argument qui nomme ce qu'on RISQUE.**

## ② ET MON REMÈDE EST REMPLACÉ

J'avais proposé : *« montrer le texte avant de proposer le geste »*. C'était le remède le
plus faible des deux possibles.

```
mon remede    rendre `rules_v4` avec chaque version, et l'afficher
LE REMEDE     executer Q2 sur CHAQUE version au moment ou la liste se
              construit, et PASTILLER chaque ligne
```

**Le second transforme un refus en un CHOIX** — *l'opérateur voit laquelle le couperait
**avant** de cliquer, au lieu de le découvrir après.* **Et il ne coûte rien de plus** : la
propriété est écrite, les données sont en base, la liste est déjà construite côté serveur.

### Et il comble un trou que je n'avais pas nommé

Mesuré **dans les deux portails** :

```
backend  /iptables-history          id · created_at · changed_by · change_reason
portage  PareFeuController:279-282  'id' · 'date' · 'auteur' · 'motif'
```

**L'historique ne rend pas les règles, des DEUX côtés.** *J'avais mesuré le backend et pas le
portage — donc je décrivais comme un manque du legacy ce qui est un manque des deux.*

Et la conséquence est celle-ci :

> ⛔ **Un refus qu'on ne peut pas instruire est un refus qu'on contourne.** *Q2 dirait « je ne
> peux pas prouver que cette version laisse le port ouvert » sur une ligne qui n'affiche
> qu'une date et un motif. L'opérateur qui sait que sa version est bonne apprend que le
> garde se trompe — donc à passer outre.*

*C'est ma propre règle sur les gardes qui accusent à tort, appliquée là où je ne l'avais pas
vue : je l'avais écrite pour `apply`, où l'opérateur a ses règles sous les yeux. **Ici il ne
les a pas, et je n'avais pas refait le raisonnement.***

## 🔴 ③ ET UNE MESURE QUI DOIT VOYAGER AVEC I5, PARCE QU'ELLE CONTREDIT CE QU'ON EN DIRA

```
--dport dans TOUT le code backend (docstrings et commentaires retires) :  0
temoin+ : occurrences de « iptables » dans le meme perimetre :          121
```

**Ce n'est pas « cette route n'inspecte pas les règles » : AUCUN module du backend ne lit le
contenu d'un jeu de règles.**

> ⛔ **La phrase qui doit accompagner Q2 partout où elle voyage : elle est la SEULE chose
> entre un opérateur et son propre verrouillage, et elle s'exécute dans le NAVIGATEUR.**

**Et le crible effectif n'est pas celui que « trois décorateurs » laisse croire :**

```
check_machine_access   helpers.py:364   `if role_id >= 2: return True`   INCONDITIONNEL
require_permission     helpers.py:323   superadmin (role >= 3) COURT-CIRCUITE

crible REEL :
  role >= 3                      AUCUNE garde
  role 2 + can_manage_iptables   TOUT le parc, production comprise
  role 1 + can_manage_iptables   ses machines seulement
```

**« C'est gardé par trois décorateurs » ne doit pas voyager avec I5.** *Trois décorateurs, un
seul crible réel.* **Ce n'est pas un défaut d'I5 — c'est le socle — mais I5 est le premier
écran qui OFFRE ce geste**, et une assurance fausse est plus dangereuse sur l'écran qui offre
que dans le module qui exécute.

*Ce que la pré-relecture confirme par ailleurs et qui est bon* : `resolve_ssh_creds` lit les
identifiants **en base** depuis `machine_id` et refuse de travailler sans lui — les
`server_ip` / `ssh_password` du corps sont **ignorés**. **L'objet contrôlé et l'objet atteint
sont donc le même** : ce n'est pas une garde sans objet.

## CE QUE L'ARBITRAGE DEVIENT

**Le retour arrière se porte avec Q1–Q4, et le point 3 change** :

```
1  recuperer le texte archive                       inchange
2  Q2 avec le port ACTUEL de la machine             inchange
3  ⬅ REMPLACE : executer Q2 sur CHAQUE version AU MOMENT OU LA LISTE SE
   CONSTRUIT, et pastiller chaque ligne — l'operateur voit AVANT de cliquer
   laquelle le couperait. Un refus non instruit se contourne.
4  Q4 : aucune requete avant consentement           inchange
```

**Et je retire ce que j'avais écrit sur la colonne de port** : je disais qu'enregistrer le
port dans `iptables_history` n'aiderait qu'à expliquer un refus après coup. *C'est encore
vrai — mais le remède ② rend la question sans objet, puisque le refus n'arrive plus après.*
