# Qualification des validateurs signalés par l'inventaire — INV-002

Relevé le **2026-08-27** par la session 5 (sécurité), en **lecture seule**. Aucune machine jointe,
aucun shell distant, aucun outil offensif. Les mesures sont en Python pur dans le conteneur
`rootwarden_python`.

La session 2 a relevé trois motifs et en a qualifié un. Ce document qualifie les deux qu'elle a
laissés, **et le fait dans les deux sens** : ce qui est exploitable et ce qui ne l'est pas.

**Verdict d'ensemble : aucun des deux n'est exploitable aujourd'hui. Un troisième point, que
personne n'avait relevé, l'est peut-être — et il n'est pas établi.**

---

## 1. `_SAFE_VALUE_RE` (supervision) — NON exploitable, et voici pourquoi

`backend/routes/supervision.py:67` : `re.compile(r'^[^\x00-\x1f\x7f]*$')`, appliqué par `.match()`
à deux endroits (`:324` relecture, `:1386` écriture).

Le contexte est le pire possible et c'est ce qui justifiait la question : **la valeur devient une
ligne d'un fichier de configuration Zabbix**, et une ligne de ce fichier peut être un
`UserParameter` — donc l'exécution d'une commande arbitraire par l'agent. C'est E-85, et V10a a
déjà rencontré exactement ce chemin.

### Le commentaire affirme plus que le code — septième occurrence

`supervision.py:63-65` :

> *« Une valeur de configuration agent tient sur UNE ligne : le motif refuse donc tout caractère de
> contrôle, saut de ligne compris. »*

**Il ne le refuse pas.** En Python, `$` correspond aussi juste avant un saut de ligne final, et
`.match()` n'exige rien au-delà. Mesuré :

| valeur | `.match()` | `.fullmatch()` |
|---|---|---|
| `'foo'` | ✅ | ✅ |
| `'foo\n'` | **✅ accepté** | ❌ |
| `'foo\nUserParameter=x,id'` | ❌ | ❌ |
| `'foo\n\n'` | ❌ | ❌ |
| `'foo\rid'` | ❌ | ❌ |

### Ce qui referme le trou, et ce n'est PAS le validateur

**Deux propriétés indépendantes, mesurées, et chacune suffirait :**

1. **`$` n'admet qu'UN saut de ligne, en toute fin, et rien après.** Une charge utile ne peut donc
   rien faire suivre son saut de ligne — c'est la mesure de la session 2, que je confirme :
   `'foo\nUserParameter=x,id'` est **refusé**. Une valeur acceptée qui se termine par `\n` produit
   `Key=foo\n` + `\n`, c'est-à-dire **une ligne vide**. Une ligne vide n'est pas une directive.
2. **Le rendu passe par base64.** `_write_config_stream` (`supervision.py:363-366`) compose
   `line = f"{key}={value}\n"`, l'encode, et écrit
   `printf '%s' '<base64>' | base64 -d >> {file_path}`. **Aucun caractère de la valeur n'atteint le
   shell.** C'est la technique que `CONTRIBUTING-SECURITY.md` §3 recommande, correctement appliquée.

> **Conclusion : l'imprécision est réelle, le défaut de commentaire est réel, le trou n'existe pas.**
> Je le dis aussi nettement qu'une accusation, parce que c'est la règle de ce chantier.

### Un point de plus, que la session 2 n'avait pas mesuré

La classe `[^\x00-\x1f\x7f]` exclut les caractères de contrôle **ASCII seulement**. Mesuré :

| valeur | verdict |
|---|---|
| `'foo\x85id'` (U+0085, NEL) | **accepté** |
| `'foo id'` (U+2028, LINE SEPARATOR) | **accepté** |

Ces deux points de code sont des **séparateurs de ligne Unicode**. **Ils ne sont pas exploitables
ici** : en UTF-8 ils s'encodent `\xc2\x85` et `\xe2\x80\xa8`, aucun ne contient l'octet `0x0A`, et le
lecteur de configuration de l'agent Zabbix découpe sur `\n`. Le fichier ne gagne aucune ligne.

Je le note parce que **le raisonnement qui dédouane ici est propre au consommateur**, pas au
validateur : un futur lecteur de cette valeur qui découperait en Unicode (`str.splitlines()` de
Python découpe sur U+0085 **et** U+2028) verrait, lui, deux lignes. C'est une propriété à ne pas
perdre le jour où quelqu'un relit cette configuration côté portail.

### Correctif proposé — cosmétique, et il vaut quand même

`.fullmatch()` au lieu de `.match()`, aux deux points d'appel. Coût nul, aucun appelant légitime
n'envoie de valeur terminée par un saut de ligne. **Et surtout : corriger le commentaire**, qui
promet aujourd'hui une garantie que le code ne donne pas. Le second geste vaut plus que le premier.

**Ce que le correctif casserait : rien.** Une valeur terminée par `\n` est aujourd'hui écrite comme
une ligne vide ; après correctif elle est refusée et **nommée** dans la réponse (le mécanisme de
refus explicite de `:1386` existe déjà).

---

## 2. `_SERVICE_RE` (services) — pas d'injection, et pas de contournement non plus

`backend/services_manager.py:14` : `^[a-zA-Z0-9@._:-]+$`.

### Ce qui est établi

**Aucune injection de commande.** La classe exclut tout métacaractère de shell — mesuré :
`'a;id'`, `'a b'`, `"a'"`, `'a$(id)'`, `'a\nid'` sont tous **refusés**. La conclusion de l'inventaire
tenait sur ce point, et elle tient toujours.

**L'injection d'ARGUMENT est réelle en forme** : `-` appartient à la classe, **y compris en tête**, et
la valeur part nue dans six f-strings (`services_manager.py:135, 161, 170, 179, 188, 197`). `'--now'`
et `'-Mfoo'` franchissent la classe **et** `_check_protected`.

### Ce qui la rend sans effet — et c'est un raisonnement en deux temps, pas une intuition

**Premier temps : le privilège n'est pas en jeu.** Ces six fonctions passent par `execute_as_root`.
**Qui atteint la route est déjà root sur cette machine.** Une option `systemctl` acceptée ne fait donc
franchir aucune frontière de privilège. La seule chose qu'une injection d'argument pourrait apporter
est de **contourner `_check_protected`** — c'est-à-dire d'agir sur une unité protégée.

**Second temps : elle ne le peut pas.** Un seul jeton est passé par commande, et la classe exclut `=`
et l'espace. Il est donc impossible de fournir **à la fois** une option et un nom d'unité, ni de
donner une valeur à une option qui en attend une. Or agir sur `sshd` exige de le **nommer**, et c'est
précisément ce que `_check_protected` regarde. `systemctl stop --now` ne désigne aucune unité : c'est
une erreur d'usage.

> **Non établi et je refuse de le présenter autrement**, comme la session 2 : je n'ai pas montré
> d'option produisant un effet nuisible, et je n'ai pas d'hôte systemd pour trancher — le banc est un
> conteneur sans systemd. Mais **la charge de la preuve est ici du bon côté** : pour être grave, il
> faudrait exhiber une option qui agisse sur une unité protégée **sans la nommer**, en un seul jeton,
> sans `=` ni espace. Je n'en connais pas, et la forme de la contrainte rend son existence peu
> plausible.

### Le contournement RÉEL de `_check_protected` n'a besoin d'aucune injection d'argument

Mesuré, en recopiant `_check_protected` à l'identique :

| valeur | classe | `_check_protected` |
|---|---|---|
| `'sshd'` | ✅ | **BLOQUE** |
| `'ssh.service'` | ✅ | **BLOQUE** |
| `'ssh.service.service'` | ✅ | **BLOQUE** (`replace` est global) |
| `'ssh.socket'` | ✅ | **PASSE** |
| `'sshd.socket'` | ✅ | **PASSE** |
| `'ssh@.service'` | ✅ | **PASSE** |
| `'SSH.service'` | ✅ | **PASSE** — mais les noms d'unité sont sensibles à la casse, donc sans effet |

**C'est E-150, déjà ouvert**, et c'est le seul contournement établi : sur un hôte à activation par
socket — le défaut sur Debian récente — `systemctl stop ssh.socket` couperait l'accès SSH, **y
compris celui de RootWarden**. Il ne demande **aucune** injection d'argument, juste un nom d'unité
ordinaire.

**Priorité, donc :** E-150 d'abord ; l'injection d'argument est une imprécision à refermer au passage,
pas un motif de correctif à elle seule.

### Chaînage avec E-149 — la session 2 a raison de le poser

`services.py` : les huit routes n'ont **ni rôle ni permission**, et `/services/` n'est dans aucune des
deux listes « admin ». Vérifié aujourd'hui. Un rôle 1 disposant d'une machine peut donc arrêter des
services sur cette machine — dont, via E-150, `ssh.socket`. **`opsuser` est ce compte, et sa seule
machine est `srv-zabbix`, la production.** Les deux écarts se lisaient séparément ; ils sont chaînés,
comme E-130 et K4.

---

## 3. CE QUE PERSONNE N'AVAIT RELEVÉ — non établi, et à ne pas essayer sur une machine réelle

En mesurant `_check_protected`, un cas est apparu qui ne vient d'aucune des deux pistes reçues :

| valeur | classe | `_check_protected` |
|---|---|---|
| `'-.mount'` | ✅ | **PASSE** |
| `'-.slice'` | ✅ | **PASSE** |

`-.mount` est, dans systemd, **le nom de l'unité du système de fichiers RACINE**. `-.slice` est la
tranche racine de la hiérarchie de ressources. Leurs noms **commencent littéralement par un tiret**,
et tous leurs caractères appartiennent à `[a-zA-Z0-9@._:-]`. Ni l'un ni l'autre ne figure dans
`PROTECTED_SERVICES`, qui ne connaît que six noms de services.

**Ce qui reste à trancher, et que je n'ai PAS tranché** : `systemctl` reçoit-il `-.mount` comme un
**nom d'unité** ou comme une **suite d'options courtes invalides** ? L'analyse d'options de systemd
consommerait vraisemblablement `-.` avant tout — auquel cas la commande échoue et il n'y a rien. La
convention documentée pour désigner ces unités est d'ailleurs `systemctl status -- -.mount`, avec le
`--` séparateur, ce qui **suggère** que sans lui elles ne sont pas atteintes.

**Pourquoi je m'arrête là :**
- le banc est un conteneur **sans systemd** (`command -v systemctl` absent, mesuré par
  `MODULE-GRAYLOG.md` §6) : il ne peut pas trancher ;
- les seules machines qui le pourraient sont **réelles**, et l'une est la production ;
- **le geste à tester serait `systemctl stop` sur la racine.** Si l'hypothèse est fausse il ne se
  passe rien ; si elle est juste, on démonte le système de fichiers racine d'une machine de
  production. **Un défaut irréversible s'établit sans se provoquer** — c'est une règle de ce
  chantier, et c'est exactement le cas.

> **À NE PAS TESTER SUR UNE MACHINE RÉELLE, ni sur `srv-zabbix`, ni sur aucune autre.** Si
> l'exploitant veut trancher, cela se fait sur une machine jetable dotée de systemd, avec `stop`
> remplacé par `show` — qui ne fait rien mais révèle si l'unité est **résolue**. C'est la mesure
> équivalente sans le geste.

**Correctif qui rend la question sans objet, et il est plus simple que la réponse :** refuser un nom
d'unité commençant par `-`. Aucune unité systemd légitime n'en a besoin, et cela ferme du même coup
toute l'injection d'argument du §2 :

```python
_SERVICE_RE = re.compile(r'^[a-zA-Z0-9@._:][a-zA-Z0-9@._:-]*$')
```

Le premier caractère ne peut plus être un tiret ; les suivants gardent la classe d'origine. **Ce que
ça casserait : rien** — aucun nom d'unité systemd ordinaire ne commence par un tiret, et les deux qui
le font sont précisément ceux qu'on ne veut pas voir passer.

---

## 4. Les 33 validateurs ancrés — la mesure de la session 2 tient, et je la borne

`.match()` sur un motif `^…$` accepte une valeur terminée par un saut de ligne ; `.fullmatch()` ne
l'accepte pas. **51 appels à `.match()`, zéro à `.fullmatch()`** dans le backend.

**La conclusion « aucun n'est exploitable par ce seul écart » est juste**, et pour une raison que je
formule en une phrase parce qu'elle est réutilisable :

> **Un `$` qui laisse passer un saut de ligne FINAL ne laisse rien passer APRÈS lui.** Une charge
> utile qui ne peut rien écrire après son saut de ligne ne peut créer aucune directive, aucune
> commande, aucune ligne de configuration.

Le seul contexte où cela cesserait d'être vrai est celui où **le saut de ligne lui-même** suffit à
produire un effet — c'est-à-dire là où la valeur n'est pas le dernier élément de sa ligne. La session
2 a eu raison de désigner `_SAFE_VALUE_RE` comme le candidat : c'est le seul des 33 dont la valeur
atterrit dans un fichier multiligne. **Vérifié au §1 : elle y est le dernier élément de sa ligne
(`f"{key}={value}\n"`), donc même là, non.**

**Passer les 33 à `.fullmatch()` reste recommandé** — c'est un remplacement mécanique, sans coût, et
il supprime une classe entière de raisonnement à refaire à chaque relecture. *Une règle qu'on doit se
rappeler est une propriété qu'on n'a pas encore construite.*

---

## 5. La règle que ces trois qualifications partagent

La session 2 l'a formulée et je la reprends parce que mes trois mesures la confirment :

> **Un validateur se mesure par ce qu'il ACCEPTE, jamais par ce qu'il appelle, ni par ce que son
> motif prétend interdire, ni par ce que son commentaire promet.**

Trois preuves dans une seule journée : `ipaddress.ip_address` **appelée** pour valider et qui accepte
`;id;` (E-174) ; `^[^\x00-\x1f\x7f]*$` dont le **motif** vise les caractères de contrôle et qui admet
celui qu'il vise le plus ; et `^[a-zA-Z0-9@._:-]+$` dont le **commentaire** dit « systemd unit names »
et qui admet `--now` et `-.mount`.

Et une seconde, propre à cet audit :

> **Quand un validateur laisse passer, chercher ce qui referme EN AVAL avant de conclure au trou.**
> Ici, base64 referme `_SAFE_VALUE_RE`, et « un seul jeton sans `=` ni espace » referme `_SERVICE_RE`.
> Deux fois, le validateur n'était pas ce qui protégeait — et deux fois, ce qui protégeait n'était
> écrit nulle part.
