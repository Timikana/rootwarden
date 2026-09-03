# AUDIT — sept des dix règles OWASP de notre convention n'ont jamais rien gardé

**Session 5 (sécurité, lecture seule).** Mesuré le **2026-09-03**. Rien écrit
dans `.github/` ni dans `.semgrep/`. Aucun geste sortant hors lectures `gh`.

Le DSI signale trois règles qui ne parsent pas. **Mesuré : elles n'ont jamais
parsé — et quatre AUTRES sont inertes par un second mécanisme que personne
n'avait vu.**

---

## 1. Pourquoi les trois ne parsent pas — trois erreurs de MOTIF, distinctes

Diagnostic par lecture. Ce sont des erreurs de **syntaxe de motif**, pas de
logique, comme le DSI le supposait.

### `rw-shell-fstring-execute-as-root`

```yaml
- pattern: execute_as_root($CLIENT, f"...{$VAR}...", ...)
- pattern-not: execute_as_root($CLIENT, f"...{shlex.quote($VAR)}...", ...)
- pattern-not: execute_as_root($CLIENT, f"...{base64...}...", ...)
```

Un motif semgrep pour Python doit être du **Python syntaxiquement valide**. Or
`$VAR` et `shlex.quote($VAR)` sont placés dans le **champ de remplacement** d'une
f-string, et `base64...` n'est une expression Python dans aucun contexte.
**Semgrep ne substitue pas de métavariable à l'intérieur d'une f-string** ; le
motif est rejeté au parsing.

### `rw-php-echo-unescaped-var`

```yaml
- pattern-either:
    - pattern: echo $X;
    - pattern: <?= $X ?>
```

`echo $X;` est valide. **`<?= $X ?>` ne l'est pas** : ce sont des **balises
d'ouverture/fermeture PHP**, pas un fragment de code. Un motif est une
**expression ou une instruction**, jamais un document avec ses délimiteurs.

### `rw-flask-route-without-api-key`

```yaml
- pattern-not: |
    @bp.route(...)
    @require_api_key
    ...
    def $F(...):
      ...
```

**Le `...` seul entre deux décorateurs et un `def`.** En Python, la zone des
décorateurs n'admet que des lignes commençant par `@` ; un `...` isolé y est une
instruction d'expression, interdite à cet endroit. **L'ellipse de semgrep ne
franchit pas cette position.**

---

## 2. ⚠ DEPUIS QUAND — jamais. Mesuré, pas déduit

Le DSI pose l'alternative : *ont-elles parsé puis cessé (une version de semgrep
les a tuées), ou n'ont-elles jamais parsé ?* **La seconde, et c'est mesuré deux
fois.**

**a) Les trois motifs sont IDENTIQUES à leur création.** Empreinte du bloc de
chaque règle, `cc0220e` (2026-05-19) contre `HEAD` :

| règle | création | HEAD | |
|---|---|---|---|
| `rw-shell-fstring-execute-as-root` | `c15d116fe431` | `c15d116fe431` | **identique** |
| `rw-php-echo-unescaped-var` | `08ccba5c0cbd` | `08ccba5c0cbd` | **identique** |
| `rw-flask-route-without-api-key` | `764669c63c61` | `764669c63c61` | **identique** |

Le fichier n'a été touché depuis que par le renommage `www/` → `legacy/`
(`5225108`).

**b) Le job n'a JAMAIS été vert.** Balayage de toutes les exécutions de `ci.yml`
depuis la première apparition du job :

```
19 executions examinees depuis 2026-06-16
   13  failure
    1  cancelled
    5  ABSENT (le job n'existait pas encore)
    0  success        <- aucun, jamais
```

Première apparition **2026-06-16**, dernière **2026-09-03**. *Le job a été rouge
à chaque exécution où il a existé.*

> **La convention `CONTRIBUTING-SECURITY.md` annonce trois protections qui n'ont
> jamais existé** : une f-string shell exécutée en root, un `echo` PHP non
> échappé, une route Flask sans clé d'API. **Non pas « tombées » — jamais nées.**

**Et cela RÉFUTE l'hypothèse de la version.** Le DSI craignait qu'un changement de
semgrep les ait tuées, *« et les SEPT autres pourraient être au bord »*. **Non :
elles n'ont jamais fonctionné, donc aucune version n'est en cause, et les sept
autres ne sont pas menacées par ce mécanisme-là.** Elles le sont par un autre —
§3.

**Une remarque de configuration qui reste vraie** : le job fait `pip install semgrep`
**sans version épinglée**. Ce n'est pas la cause ici, mais cela signifie que
n'importe quelle publication de semgrep peut changer le comportement des règles
d'une exécution à l'autre, sans qu'aucun commit ne l'explique.

---

## 3. ⚠ LE RÉSULTAT PRINCIPAL — quatre AUTRES règles sont filtrées avant de pouvoir parler

La commande du job :

```
semgrep --config=.semgrep/rules-rootwarden.yml --error --metrics=off --severity=ERROR .
```

**`--severity=ERROR` ne retient que les règles de sévérité `ERROR`.** Or :

| règle | sévérité | état |
|---|---|---|
| `rw-sql-fstring-execute` | ERROR | **peut rapporter** |
| `rw-shell-fstring-execute-as-root` | ERROR | **morte** (parse) |
| `rw-subprocess-shell-true` | **WARNING** | **filtrée** |
| `rw-decode-errors-ignore` | ERROR | **peut rapporter** |
| `rw-php-equals-on-hash` | **WARNING** | **filtrée** |
| `rw-php-weak-random` | **WARNING** | **filtrée** |
| `rw-php-echo-unescaped-var` | ERROR | **morte** (parse) |
| `rw-php-debug-leak` | **WARNING** | **filtrée** |
| `rw-flask-route-without-api-key` | ERROR | **morte** (parse) |
| `rw-aes-cbc-encrypt` | ERROR | **peut rapporter** |

> **Sept des dix règles ne peuvent rien rapporter**, par **deux mécanismes
> indépendants** : trois par erreur de motif, **quatre par le filtre de sévérité**.
> **Seules trois** sont en état de parler : `rw-sql-fstring-execute`,
> `rw-decode-errors-ignore`, `rw-aes-cbc-encrypt`.

**Ce second mécanisme est plus insidieux que le premier** : les règles mortes
produisent une **erreur visible** dans le journal ; les règles filtrées ne
produisent **rien du tout**. Une règle absente du rapport et une règle qui
n'a rien trouvé sont **la même sortie**. *C'est la première moitié de la règle du
témoin, appliquée à un outil d'analyse.*

Et `rw-subprocess-shell-true` — `subprocess` avec `shell=True` — est classée
WARNING alors que c'est de l'exécution de commande.

---

## 4. Ce que je NE peux PAS mesurer, et ce qui le règlerait

**Les trois règles survivantes MORDENT-elles ?** *Je ne peux pas le dire.*

`semgrep` n'est disponible **nulle part** : ni sur l'hôte, ni dans
`rootwarden_python`, `rootwarden_php`, `rootwarden_laravel`, ni comme module
Python. L'installer demande un accès réseau sortant, hors de mon périmètre de
lecture.

> **C'est exactement la distinction que le DSI pose** : *une règle qui parse et ne
> matche jamais est indiscernable d'une règle qui parse et n'a rien à matcher.*
> **§3 en dissout une partie** — quatre des sept n'ont même pas l'occasion de
> matcher, et cela se lit. **Pour les trois survivantes, la question reste
> entière et exige une exécution.**

**Ce qui la réglerait** — et c'est une proposition, pas un geste : un **fichier
d'épreuve** par règle, contenant une occurrence que la règle DOIT signaler, et
une assertion en CI que chaque règle rapporte **au moins une fois** sur son
épreuve. **Une règle qui ne mord pas son propre fixture est morte, quel que soit
son statut de parsing.** C'est le témoin, porté par l'outil lui-même.

---

## 5. Ce que je propose — non appliqué

**Je n'écris rien dans `.github/` ni dans `.semgrep/`.** Un workflow tourne sur
l'infrastructure de GitHub avec un jeton, et `auto-tag` porte `contents: write`.
**Ces quatre points vont à l'exploitant par le DSI.**

1. **Retirer `--severity=ERROR`** ou relever les quatre WARNING — le filtre annule
   40 % du jeu de règles en silence. *C'est le correctif le moins cher et le plus
   rentable des quatre.*
2. **Réécrire les trois motifs** — pas de métavariable en f-string, pas de balise
   `<?=` dans un motif, pas de `...` entre décorateurs.
3. **Épingler la version de semgrep** (`pip install semgrep==X.Y.Z`) — pour que le
   comportement des règles ne change pas sans commit.
4. **Un fixture par règle**, avec l'assertion « chaque règle rapporte au moins une
   fois » — le seul moyen de distinguer une règle qui garde d'une règle qui se
   tait.

**Et une remarque sur le statut `advisory`** : le DSI écrit qu'*un rouge toléré
devient une propriété du décor*. Mesuré ici, c'est pire — **le rouge ne disait pas
que le contrôle échouait, il disait que le contrôle n'existait pas.** Rendre le
job bloquant sans d'abord régler §3 le rendrait rouge pour une **troisième**
raison, encore différente.
