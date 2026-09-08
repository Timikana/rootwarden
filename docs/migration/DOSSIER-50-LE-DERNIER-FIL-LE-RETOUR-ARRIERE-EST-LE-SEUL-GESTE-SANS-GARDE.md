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
