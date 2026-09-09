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

---

# RECTIFICATION du 2026-09-09 10:45 — ma recommandation du §5① est PÉRIMÉE, et l'ordre de fusion décide

Le §5① disait : *« fusionner `security/garde-socle-avertissement` telle quelle,
le document de `0b` arrive avec, sans aucune écriture dans l'arbre partagé »*.

**`0b` a rétabli son document sur `Migration-Laravel` — `d489d316`, 10:00 — et ma
recommandation est devenue fausse trente minutes après l'avoir écrite.**

## L'état des deux copies

```
docs/migration/QA-JETON-TELEGRAF-EN-CLAIR.md
  sur Migration-Laravel               8977 o   174 lignes
  sur security/garde-socle-…          5849 o   113 lignes
  blobs identiques                    NON
  dans origin/main                    ABSENT
```

**La version de `Migration-Laravel` est la plus riche** : elle porte le §8 du
défaut natif, le garde de masque parallèle et le témoin consolidé. *La copie de
la branche est un état antérieur.*

## L'ordre de fusion décide, simulé sans écrire

```
git merge-tree --write-tree origin/main       security/garde-…   PROPRE
git merge-tree --write-tree Migration-Laravel security/garde-…   CONFLIT
```

| ordre | ce qui arrive |
|---|---|
| la branche d'abord, dans `main` | **propre** — mais `main` reçoit la version à 113 lignes, et la fusion suivante de `Migration-Laravel` conflitera |
| `Migration-Laravel` d'abord | `main` reçoit la version à **174 lignes** ; la copie de la branche devient **redondante** et son chemin conflitera |

**Recommandation corrigée : fusionner `Migration-Laravel` d'abord**, puis la
branche en résolvant le conflit **en faveur de `Migration-Laravel`** — ou en
retirant la copie de la branche avant de la fusionner. *Le contenu du document ne
court plus aucun risque : il est atteignable sur `Migration-Laravel`, et c'est la
version complète.*

> **Une recommandation peut être périmée par le geste même dont elle disait qu'il
> n'était pas nécessaire.** J'ai écrit « aucun geste » ; `0b` a fait le geste, et
> il avait raison de le faire — son document est maintenant atteignable au lieu
> d'être suspendu à une décision. *Le fait qu'une recommandation devienne fausse
> parce que quelqu'un a mieux fait n'est pas un échec de la recommandation, mais
> elle doit cesser de circuler.*

⚠ Et le conflit annoncé est **la bonne issue** : `0b` l'écrit, *« un conflit
visible, que je préfère à un document qui n'existe nulle part d'atteignable »*.
Un conflit se voit et se tranche ; une branche non fusionnée ne se voit pas.

## Et le constat sur le jeton se resserre encore

```
2129a2cf3  2026-04-11  :717   if psk_value and psk_value != '********':     garde de MASQUE
2129a2cf3  2026-04-11  :718       psk_encrypted = enc.encrypt_password(…)   le CHIFFREMENT
2129a2cf3  2026-04-11  :2466  if telegraf_token == '********':              garde de MASQUE
```

**Les deux secrets reçoivent le même traitement du masque, écrit dans le même
commit, et un seul reçoit le chiffrement — qui est la ligne juste en dessous.**

> **Ce n'est pas une inattention à combler : c'est une propriété précise qui
> manque à côté d'une autre qui est là.** *(formulation de `0b`)* L'auteur a
> suivi la même préoccupation pour les deux dans le même souffle. **L'omission
> est locale au chiffrement, pas générale** — ce qui est plus embarrassant pour
> le geste d'origine, et plus utile pour qui corrigera.

---

# EXTENSION du 2026-09-09 10:55 — AUCUNE branche `security/` ne se fusionne proprement, et quatre conflits sont dans du CODE

**Signalé par `0b`, rejoué et étendu par moi. Aucun geste : `git merge-tree` ne
touche pas l'arbre de travail, et le témoin le confirme.**

## 1. Les branches, DÉRIVÉES et non reprises

```
branches non fusionnees dans origin/main, enumerees :
  security/backend-cve
  security/garde-socle-avertissement
  security/semgrep-regles-mortes
  Migration-Laravel                      (la branche de travail)
  bundle/refs/heads/laravel              2026-08-17   artefact de bundle
  bundle/refs/stash                      2026-05-05   artefact de bundle
```

*Les deux `bundle/` ne sont pas du travail en cours — un `stash` de mai et une
vague de portage d'août, tous deux antérieurs de plusieurs semaines. Je les
nomme pour que personne ne les poursuive.*

## 2. La simulation, code de sortie sans tube

```
security/backend-cve                 code=1 · 2 chemins
    backend/routes/cve.py                              CODE
    backend/scheduler.py                               CODE
security/garde-socle-avertissement   code=1 · 1 chemin
    docs/migration/QA-JETON-TELEGRAF-EN-CLAIR.md       document
security/semgrep-regles-mortes       code=1 · 3 chemins
    backend/ssh_utils.py                               CODE
    .semgrep/rules-rootwarden.yml                      CONFIG
    docs/migration/QA-APPARIEMENT-CINQ-CATALOGUES.md   document

TOTAL : 6 chemins, dont 4 en CODE ou CONFIG
TEMOIN : Migration-Laravel contre elle-meme -> code 0
```

> ⛔ **Aucune des trois branches ne se fusionne proprement, et quatre des six
> conflits sont dans du code de `backend/` ou dans les règles semgrep.** Elles
> sont remontées comme « vérifiées, en attente d'un mot » — **le mot ne suffira
> pas** : il faudra trancher `cve.py`, `scheduler.py`, `ssh_utils.py` et
> `rules-rootwarden.yml`.

*La provenance étrangère du §1 n'était que le symptôme visible. Le problème de
fusionnabilité est indépendant d'elle et plus lourd.* **Les deux conflits de
documents se résolvent sans perte** — garder `Migration-Laravel`, qui contient
dans les deux cas la version de la branche **plus** des ajouts (174 lignes contre
113 ; 17 506 octets contre 9 326). **Les quatre autres demandent une décision de
contenu.**

## 3. ⚠ ET J'AI MIS UN `head -6` DANS LA COMMANDE QUI MESURAIT CE DÉFAUT

Ma première passe tronquait la liste des conflits à six lignes. **Elle a caché
exactement le troisième conflit que `0b` nommait** —
`QA-APPARIEMENT-CINQ-CATALOGUES.md` — *et elle faisait donc passer SON relevé
pour inexact.*

C'est la cinquième instance de la borne de confort en une heure, et la pire des
cinq :

```
head -20 sur le reflog        -> 10 bascules au lieu de 28
--since='2026-09-07'          -> 2 commits egares au lieu de 3
git log -3 sur un fichier     -> « changement recent » au lieu de cinq mois
six PR relues sur un critere  -> les commits portes jamais lus
head -6 sur les conflits      -> 5 chemins au lieu de 6, ET un pair mis en tort
```

> **Je l'ai commise dans la commande qui la mesurait**, une heure après l'avoir
> nommée, et dans le document qui l'énonce. *C'est la propriété que ce dépôt a
> déjà consignée : une règle protège les autres, pas soi — on l'applique en
> LISANT, jamais en ÉCRIVANT.* Ce qui manque n'est pas un énoncé, c'est un
> contradicteur.

⚠ **Et son effet le plus coûteux n'est pas le mauvais compte** : c'est qu'une
troncature chez le vérificateur **transfère le tort au vérifié**. `0b` avait
raison sur les trois, et mon relevé le montrait à deux.

## 4. Précision d'un chiffre de `0b`

Il écrit *« trois des six conflits sont dans du CODE »*. **Mesuré : quatre** —
trois `.py` plus `.semgrep/rules-rootwarden.yml`. *Un fichier de règles semgrep
n'est pas de la prose : c'est ce qui décide si la CI bloque, et le dépôt le
traite comme du code — le job « Les regles custom MORDENT » l'atteste.*

## 5. Ce que ça change pour l'exploitant

Le §5 de ce dossier disait « un droit d'écriture débloque trois des quatre ».
**C'est vrai et insuffisant.** L'état complet :

```
un droit d'ecriture           debloque les 3 controles eprouves + le correctif du jeton
la fusion de Migration-Laravel  d'ABORD, elle porte les versions completes
puis chaque branche security/   4 conflits de CODE a trancher, 2 de document triviaux
le regime des branches          28 bascules de HEAD sur 11 cibles, worktree jamais employe
```

**Aucun de ces quatre points n'est technique. Les quatre sont des décisions.**
