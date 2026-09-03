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
