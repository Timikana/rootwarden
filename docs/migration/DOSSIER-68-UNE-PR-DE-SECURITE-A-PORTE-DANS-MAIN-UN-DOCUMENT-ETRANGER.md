# DOSSIER-68 — Une PR de sécurité a porté dans `main` un document étranger, et c'est ma fusion

**Mesuré le 2026-09-09 entre 10:00 et 10:15 CEST. Aucun geste exercé : aucune
réécriture d'historique, aucune fusion, aucun déplacement de commit.**

> Signalé par `gestion-ssh-key-0b` après un audit de ses 99 commits. **Je l'ai
> rejoué, et le fait est exact.** Il porte sur une fusion que j'ai faite, et il
> révèle un défaut de mon propre geste que je n'avais pas vu en le corrigeant une
> première fois.

---

## 1. Le fait, vérifié

```
9603e6da  docs(qa): qualification des 4 commandes root indirectes
          fichier : docs/migration/QA-QUATRE-COMMANDES-ROOT-INDIRECTES.md
          dans origin/main : OUI
          fusion porteuse  : 6a4faba5  Merge pull request #70
                             from Timikana/security/tls-ca-path-injecte-dans-rsyslog
```

**Une PR de sécurité sur `tls_ca_path` et la grammaire rsyslog a porté dans
`main` un document de qualification de 155 lignes qui n'a rien à voir avec
elle.** Personne relisant #70 ne pouvait s'y attendre.

### Ce que mes sept fusions ont réellement porté

```
PR #70   3 commits : 2 sur graylog (le sujet) + 1 document QA de 0b   <- ETRANGER
PR #71   2 commits : 1 sur sftp   (le sujet)  + 1 fix de test a moi   <- NON ANNONCE
PR #68 #64 #74 #85 #86   1 commit chacune, conforme au titre
```

**Deux fusions sur sept ont porté un commit que leur titre n'annonçait pas.**
Celui de #71 est de moi et il est légitime — c'était le correctif de mon propre
fichier de test qui empoisonnait la session pytest — *mais il n'était pas
annoncé, et la différence entre « légitime » et « annoncé » est exactement ce que
ce dossier mesure.*

---

## 2. ⛔ LE DÉFAUT EST LE MIEN, ET IL EST PIRE QUE CE QUE J'ALLAIS ÉCRIRE

J'ai commencé à écrire que le relevé manquait — que `gh pr merge` ne montre pas
la liste des commits, que `gh pr view --json files` ne montre que les fichiers, et
que le seul relevé capable de l'attraper serait `git log --no-merges M^1..M^2`.

**C'était une fausse exculpation de mon propre procédé, et une mesure l'a
arrêtée :**

```
gh pr view 70 --json commits
    e605d7e5  docs(securite): tls_ca_path atteint la grammaire rsyslog …
    633a0e3b  fix(noms): `escaped_key` promettait un echappement de shell …
    9603e6da  docs(qa): qualification des 4 commandes root indirectes …    <- LISTE
    6e0ee5b8  fix(graylog): `tls_ca_path` atteignait la grammaire rsyslog …
    4504be3d  fix(graylog): `fullmatch` est PORTEUR …
```

**L'information était disponible avant la fusion, par une commande à un drapeau
près de celle que je lançais.** Je ne l'ai pas lancée — ni pour #70, ni pour les
six suivantes.

> **Ce n'est pas un outil qui manque : c'est un relevé que je n'ai pas fait.**
> *Et j'allais l'écrire dans l'autre sens — la forme d'erreur qui dédouane, sur
> mon propre geste, dans le document qui l'examine.*

⚠ **Et c'est le second défaut de la MÊME fusion.** J'avais déjà consigné avoir
fusionné #70 **sans lire ses contrôles** — elle était rouge, et `main` l'est
devenue. *J'ai corrigé la lecture des contrôles pour les six PR suivantes, et je
n'ai pas pensé une seule fois à lire ce qu'elles PORTAIENT.* **Corriger un
manquement sur un objet ne fait pas regarder les autres propriétés du même
geste.**

---

## 3. La cause, et elle est systémique

`0b` a audité ses 99 commits : **97 sur `Migration-Laravel`, 3 égarés** sur trois
branches `security/` différentes, les 04/09, 09/09 à 02:46 et 09/09 à 09:15.

Le reflog de `HEAD`, qui est le même pour toutes les sessions :

```
28 entrees `checkout: moving`, sur 11 cibles distinctes
   15 vers Migration-Laravel
   13 vers 10 branches `security/` differentes
```

**Le basculement de `HEAD` dans l'arbre partagé est le régime NORMAL de ce
chantier, pas un accident.** La collision de `0b` n'est pas la première : c'est
la première **vue**, et elle ne l'a été que parce qu'un reste inexpliqué — un
commit manquant dans son propre compte de ratio — l'a fait regarder.

### Le remède par construction existe déjà, et il est dans mon scratchpad

```
git worktree list
  /home/utilisateur/Documents/Gestion_SSH_KEY                 c783c609 [Migration-Laravel]
  /tmp/claude-1000/…/55d6fd67-…/scratchpad/wt-main            f405766b [main]
```

**Le second arbre est celui de MA session, et il est sur `main`.** Un worktree a
son **propre `HEAD`** : c'est le remède par construction, là où
`git rev-parse --abbrev-ref HEAD` avant chaque commit n'est qu'un contrôle.

*Je l'avais donc sous la main et je n'y ai pas pensé une seule fois pour les
commits de ce chantier.* Ordre de préférence, celui du dépôt : **inexprimable >
dérivé > exhaustif > contrôlé.** Un worktree place le problème dans la première
catégorie ; relever `HEAD` avant de committer le laisse dans la dernière.

---

## 4. Ce qui est en péril, et ce qui ne l'est pas

```
QA-JETON-TELEGRAF          arbre ABSENT · ML ABSENT · main ABSENT   ⛔ 113 lignes a risque
QA-QUATRE-COMMANDES        arbre · ML · main : PRESENT              (porte par #70)
QA-APPARIEMENT-CATALOGUES  arbre · ML · main : PRESENT              contenu PLUS COMPLET sur ML
                             branche 9326 o  <  Migration-Laravel 17506 o
```

**Un seul contenu est réellement en péril**, et `0b` se borne correctement : le
troisième est un état **antérieur** enrichi plus tard, donc son commit est échoué
et son contenu ne l'est pas.

**Rien dans `main` n'est faux.** Les neuf commits portés par mes sept fusions
sont tous du contenu légitime. **Le dommage est de traçabilité, pas
d'intégrité** : l'historique de `main` attribue un document de qualification à
une PR sur rsyslog.

---

## 5. Ce qui revient à l'exploitant

**① Fusionner `security/garde-socle-avertissement` telle quelle.** Le document de
`0b` (113 lignes, blob `655a8b0d…` vérifié identique) arrive avec, sans aucune
écriture dans l'arbre partagé. C'est aussi la seule option qui ne crée pas de
doublon si la branche est fusionnée ensuite.

**② ⛔ NE PAS réécrire l'historique de `main` pour en sortir `9603e6da`.** Le
contenu est légitime et présent ; une réécriture d'un `main` que huit sessions
suivent échangerait un défaut de traçabilité contre un risque de perte. *Le
dommage est déjà fait et il est bénin ; le remède serait plus coûteux que lui.*

**③ Décider du régime de travail, et c'est le seul point qui empêche la
récidive.** Un worktree par session — le mécanisme est déjà en place dans au
moins une — ou l'interdiction de basculer `HEAD` dans l'arbre partagé. *Le
contrôle « relever `HEAD` avant de committer » ne suffira pas : trois sessions
récitaient déjà « committer par chemins » et aucune n'a relevé sa branche une
seule fois aujourd'hui.*

⚠ **Et la portée de la décision a changé.** Ce n'est plus *« une branche porte un
document étranger »* : c'est **« les PR de ce dépôt portent des commits
étrangers, et une l'a déjà fait jusque dans `main` »**.
