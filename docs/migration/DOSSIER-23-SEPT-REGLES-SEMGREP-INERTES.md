# DOSSIER 23 — Sept des dix règles de sécurité maison sont INERTES, par deux mécanismes

**Pour signature de l'exploitant.** *Trouvé par la session 5 le 2026-09-03 après que la session 4 ait
relevé trois erreurs de parsing ; les deux mécanismes revérifiés par moi à 21:15 CEST.*

> **La convention `CONTRIBUTING-SECURITY.md` annonce dix règles OWASP maison. Trois n'ont JAMAIS
> fonctionné, quatre sont exclues avant l'analyse. Il en reste trois en état de parler.**

---

## 1. Le bilan, mesuré

    10 regles declarees dans `.semgrep/rules-rootwarden.yml`

     3 MORTES     erreur de motif — elles ne parsent pas
     4 FILTREES   declarees WARNING, exclues par `--severity=ERROR`
     3 vivantes   rw-sql-fstring-execute · rw-decode-errors-ignore · rw-aes-cbc-encrypt

---

## 2. Mécanisme 1 — trois règles ne parsent pas, et elles n'ont JAMAIS parsé

    [ERROR] Rule parse error : rw-shell-fstring-execute-as-root  — Invalid pattern for Python
    [ERROR] Rule parse error : rw-php-echo-unescaped-var         — Invalid pattern for PHP
    [ERROR] Rule parse error : rw-flask-route-without-api-key    — Invalid pattern for Python

**Ce qu'elles devaient garder** : *une f-string shell exécutée en root · un `echo` PHP non échappé · une
route Flask sans clé d'API.*

**Trois causes distinctes, diagnostiquées** : *semgrep ne substitue pas de métavariable dans le champ de
remplacement d'une f-string* · *`<?= $X ?>` sont des balises, pas un fragment de code* · *un `...` seul
entre deux décorateurs et le `def` — Python n'admet là que des lignes en `@`.*

### ⚠ Et elles n'ont jamais fonctionné une seule fois

    les trois blocs sont BYTE-IDENTIQUES a leur creation (cc0220e, 2026-05-19)
      empreintes comparees : c15d116fe431 · 08ccba5c0cbd · 764669c63c61, inchangees

    19 executions de `ci.yml` depuis le 2026-06-16 :
      13 failure · 1 cancelled · 5 le job n'existait pas · 0 SUCCESS
      -> le job n'a JAMAIS ete vert

> **La convention annonce trois protections qui ne sont pas « tombées » : elles ne sont jamais nées.**

*Et ça réfute l'hypothèse que j'avais posée — « une version de semgrep les a tuées, et les sept autres
sont au bord ». **Aucune version n'est en cause.*** *(Reste vrai séparément : `pip install semgrep` n'est
pas épinglé, donc le comportement peut changer d'une exécution à l'autre sans qu'aucun commit ne
l'explique.)*

---

## 3. ⚠ Mécanisme 2 — QUATRE règles sont exclues AVANT l'analyse, et personne ne le voyait

    ci.yml:327   semgrep --config=.semgrep/rules-rootwarden.yml --error --metrics=off --severity=ERROR .
    ci.yml:305   le MEME filtre sur le job semgrep STANDARD

    severites declarees : 6 ERROR · 4 WARNING
      rw-subprocess-shell-true   WARNING   <- `subprocess` avec shell=True
      rw-php-equals-on-hash      WARNING
      rw-php-weak-random         WARNING
      rw-php-debug-leak          WARNING

**`--severity=ERROR` ne retient que les règles `ERROR`. Les quatre `WARNING` n'ont pas l'occasion de
matcher.**

> **Et ce mécanisme est plus insidieux que le premier : une règle MORTE produit une erreur VISIBLE au
> journal. Une règle FILTRÉE ne produit RIEN.** *Une règle absente du rapport et une règle qui n'a rien
> trouvé sont la même sortie.*

**C'est la règle du témoin appliquée à l'outil d'analyse lui-même** — *zéro sur la sonde et zéro sur le
témoin veut dire que la mesure n'a pas eu lieu.* **Ici il n'y avait même pas de témoin possible.**

**⚠ Et `rw-subprocess-shell-true` classée `WARNING`, c'est de l'exécution de commande rangée sous
« avis ».**

---

## 4. ⛔ L'ORDRE DES CORRECTIFS, et il n'est pas indifférent

> **Rendre ce job bloquant sans régler le §3 d'abord le rendrait rouge pour une TROISIÈME raison** —
> *encore différente des deux premières : les trois règles vivantes trouveraient alors de vraies
> occurrences à trier.*

```
1. retirer `--severity=ERROR` (ou relever les 4 WARNING)
   -> le moins cher et le plus rentable : le filtre annule 40 % du jeu EN SILENCE
2. reecrire les trois motifs
3. epingler la version de semgrep
4. un FIXTURE par regle + l'assertion « chaque regle rapporte au moins une fois »
   -> une regle qui ne mord pas son propre fixture est morte, quel que soit
      son statut de parsing.  C'est le TEMOIN, porte par l'outil.
5. SEULEMENT ENSUITE : rendre le job bloquant
```

**Le point 4 est celui qui empêche que ça recommence.** *Sans lui, une onzième règle écrite demain peut ne
jamais mordre sans que rien ne le dise.*

---

## Ce qui n'est pas mesuré

- **si les trois règles vivantes MORDENT réellement.** *`semgrep` n'est disponible nulle part — ni sur
  l'hôte, ni dans aucun des trois conteneurs, ni comme module Python. L'installer demande du réseau
  sortant.* **Sa session le déclare plutôt que de raisonner dessus, et c'est la bonne conduite** ;
- **ce que les trois vivantes trouveraient** sur le dépôt actuel — *donc l'ampleur du tri du point 5* ;
- **rien n'a été écrit** dans `.github/` ni `.semgrep/`. *Un workflow est un effet sortant : il tourne sur
  l'infrastructure de GitHub avec un `GITHUB_TOKEN`, et `auto-tag` porte `contents: write`.*

---

# ✅ 2026-09-04, 16:10 — LES TROIS MOTIFS SONT RÉPARÉS, ET DEUX NE SONT PAS LIVRABLES

**Et la raison n'est pas que le motif résiste : c'est que la propriété visée n'est pas exprimable par un
moteur de motifs.** *Branche `security/semgrep-regles-mortes` (`5590e9d` + `2cad24c`), non fusionnée, non
poussée.*

## 1. CE QUE J'AI MESURÉ MOI-MÊME, ET QUI BORNE LE DÉGÂT

    run 33803915986 (2026-09-03 20:43, le dernier VERT) :
      « SAST cross-langue (semgrep) »                          SUCCESS
      « SAST regles custom RootWarden (semgrep, advisory) »     FAILURE

**Ce sont DEUX jobs distincts. Le jeu semgrep générique tourne et passe ; seul le jeu CUSTOM est mort.**
*La couverture semgrep du dépôt n'est donc pas nulle — c'est la couche maison qui l'est.*

**⛔ Et je ne peux PAS répondre à la question qui reste** : *`semgrep-core rule validation failed`
abortait-il TOUTE la passe custom, ou seulement les trois règles fautives ?* **Les journaux des exécutions
ne sont plus récupérables (`gh run view --log` rend 0 ligne — témoin d'instrument posé).**

> **Si c'est toute la passe, les trois règles dites « vivantes » n'ont jamais tourné non plus, et le jeu
> custom a produit ZÉRO analyse depuis le 2026-05-19.** *La première exécution après le correctif y
> répondra. C'est l'information la plus précieuse des deux changements en cours.*

## 2. ✅ LES TROIS ARBITRAGES, RENDUS

| règle | état | décision |
|---|---|---|
| `rw-php-echo-unescaped-var` | 0 occurrence dans `legacy/`, sous les deux formes | ✅ **ACTIVER** — aucun bruit, et son office est de rougir le jour où une occurrence apparaît |
| `rw-shell-fstring-execute-as-root` | **84** candidats, presque tous validés en amont | ⛔ **NE PAS ACTIVER** — réparation syntaxique conservée, règle désactivée AVEC sa raison |
| `rw-flask-route-without-api-key` | **3** faux positifs PERMANENTS sur 230 routes | ⛔ **NE PAS ACTIVER** en semgrep — **convertir en invariant AST** |

**Pourquoi refuser la règle 1, et c'est l'argument de la session 5 que je reprends :**

> **Une règle qui compile et trouve TOUT est aussi inutile qu'une qui ne trouve rien — et elle redevient du
> décor PLUS VITE, parce que 84 lignes rouges se scrollent alors qu'une erreur de compilation se lit.**

*« Y a-t-il une interpolation ? » n'est pas « la valeur est-elle sûre ? », et l'idiome NORMAL de ce dépôt
est l'interpolation VALIDÉE (`_validate_service_name`, `_valid_username`, un chemin littéral). La propriété
visée est un flux source → sink : elle demande `mode: taint`, que personne ici ne peut valider.*

**Pourquoi convertir la règle 3 plutôt que la supprimer** : *ses 3 exceptions sont légitimes et DOCUMENTÉES
à leur site — un jeton HMAC borné au `machine_id` pour un cron distant, une signature Slack, une sonde de
vie statique.* **La propriété reste vraie et vaut d'être gardée ; c'est l'INSTRUMENT qui est faux.**

> **Et le dépôt possède déjà l'instrument juste, qui marche** : `test_invariant_machine_id.py` mesure une
> classe entière contre une liste d'exceptions ARGUMENTÉES et n'assère que l'ÉCART. *C'est exactement ce
> que `--severity=ERROR` ne sait pas faire.*

## 3. ✅ ET LE VRAI LIVRABLE N'EST AUCUNE DES TROIS RÈGLES

**`backend/tests/test_invariant_semgrep_motifs.py` (163 lignes) : tout motif Python du fichier de règles
DOIT compiler.**

    il aurait attrape les trois a l'ECRITURE, le 2026-05-19
    et il porte les deux moities : les 3 motifs fautifs REELS doivent etre
    REJETES, et 3 formes idiomatiques doivent PASSER

> **Trois règles de sécurité ont vécu 3 mois et demi sans jamais compiler, dans un job toléré par
> `continue-on-error`. Le correctif durable n'est pas de meilleurs motifs : c'est un contrôle qui refuse un
> motif qui ne compile pas.**

## 4. ⚠ DEUX FAUX PAS DE L'INSTRUMENT, ET LE PREMIER EST DU MÊME GENRE QUE LE DÉFAUT

    1. le harnais substituait les metavariables PARTOUT, f-strings comprises
       -> il ACCEPTAIT le motif de la regle 1
       = un faux PASS sur le defaut meme que le test existe pour trouver
    2. il remplacait le `...` d'argument par un identifiant
       -> il accusait `rw-subprocess-shell-true` d'une faute inexistante

**Ce qui a servi de vérité terrain : le compte du journal CI — TROIS erreurs rapportées, quatre annoncées
par le harnais.** *Sans ce chiffre, une règle SAINE aurait été « réparée ».*

## 5. CE QUI VOUS REVIENT

    ✅ les trois arbitrages ci-dessus            rendus, rien a signer
    📌 la FUSION de `security/semgrep-regles-mortes`   votre regle
    📌 sa POUSSEE                                 meme cran : la branche
       n'existe que localement, comme `security/backend-cve`
    📌 et la reponse au §1 arrive avec la premiere execution de CI apres
       la fusion — c'est elle qui dira si le jeu custom a produit
       QUELQUE CHOSE depuis le 19 mai

**SI RIEN N'EST FAIT** : *le job reste rouge en permanence et toléré — donc une garde qui alarme toujours,
c'est-à-dire une garde qui n'attrape plus rien. Et on ne saura pas si les trois règles « vivantes »
tournent.*
