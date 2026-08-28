# Pré-relecture de `iptables/` — le contrat de sécurité du portage (I1 → I5)

Écrit le **2026-08-27** par la session 5 (sécurité), en **lecture seule**. Aucune machine jointe,
aucune suite lancée, banc jamais demandé. Les trois mesures demandées par le Lead avant portage sont
faites, **et deux d'entre elles sont liées par une cause commune qu'il n'avait pas nommée.**

---

## 1. MESURE 1 & 2 — elles n'en font qu'une : l'écho PTY rend la troncature ATTEIGNABLE

### 1.1 La détection cherche dans des FRAGMENTS, pas dans la sortie

`backend/routes/iptables.py:113-116` :

```python
test_cmd = f"… iptables-restore --test /tmp/_ipt_test.rules 2>&1; echo EXIT_CODE=$?"
output_lines = list(execute_as_root_stream(client, test_cmd, root_password, logger=logger))
output = '\n'.join(output_lines)
exit_code = 0 if any('EXIT_CODE=0' in l for l in output_lines) else 1
```

`execute_as_root_stream` **ne rend pas des lignes** : il rend `stdout.channel.recv(4096)`, c'est-à-dire
des fragments de **4096 octets**. La variable s'appelle `output_lines` et ne contient pas des lignes.

**Reproduit, sans SSH, en recomposant le découpage à l'identique :**

| longueur de la sortie | verdict rendu | verdict juste |
|---|---|---|
| 12 octets | 0 | 0 |
| 4097 | 0 | 0 |
| **4102** | **1** | 0 ⟵ **valide déclaré INVALIDE** |
| **4104** | **1** | 0 |
| **4107** | **1** | 0 |

`EXIT_CODE=0` fait 11 caractères : dès qu'il chevauche une frontière de fragment, **aucun** fragment
ne le contient, et un jeu de règles **valide** est déclaré invalide.

### 1.2 Et le `join` insère des sauts de ligne qui n'existent pas

`output = '\n'.join(output_lines)` recolle des fragments **contigus** avec un séparateur. Mesuré :
une sortie réelle de 4106 octets sans aucun saut de ligne est affichée avec **un saut de ligne
inséré**, à l'octet 4096. Défaut **déterministe**, à chaque frontière.

*(S'y ajoute `if text.strip(): yield text` : un fragment entièrement blanc est **jeté**. La sortie
affichée n'est donc pas seulement décalée, elle peut être amputée.)*

### 1.3 ⚠ CE QUI REND LE DÉFAUT VIVANT — et c'est la mesure 2

Sur un jeu de règles valide, `iptables-restore --test` n'écrit **rien** : la sortie vaut
`EXIT_CODE=0\n`, douze octets, un seul fragment. **Le chevauchement serait donc inatteignable… si la
sortie ne contenait que le résultat.**

Or `execute_as_root_stream` ouvre `client.exec_command(root_cmd, get_pty=True)` sur le chemin mot de
passe. **Un PTY ÉCHOTE la commande** — et la commande contient
`printf '%s' '<base64 de tout le jeu de règles>'`. Un jeu de règles de 3 Ko produit ~4 Ko de base64,
donc **l'écho seul dépasse un fragment**.

> **L'écho PTY n'est pas seulement une nuisance d'affichage : c'est lui qui fait franchir la
> frontière des 4096 octets. Sans lui, la troncature ne serait jamais atteinte ; avec lui, elle l'est
> à chaque jeu de règles un peu long.** Les deux défauts que le Lead m'a donnés séparément n'en font
> qu'un.

**Le mot de passe, lui, EST filtré** — `filtre_echo_mot_de_passe` est appliqué (`ssh_utils.py:766`),
et c'est correct. Mais il retire les **lignes qui SONT le secret** ; il ne retire pas l'écho de la
commande. Le blob base64 arrive donc à l'écran.

### 1.4 Le correctif est d'une ligne, et il ferme les trois

```python
output = ''.join(output_lines)                    # concatener, pas joindre
exit_code = 0 if 'EXIT_CODE=0' in output else 1   # chercher dans la SORTIE
```

Chercher dans la sortie **recomposée** au lieu de chaque fragment ferme le chevauchement ; concaténer
au lieu de joindre supprime les sauts insérés. **Ce que ça casserait : rien** — la valeur cherchée
est la même, l'ensemble balayé est un sur-ensemble strict.

> **Règle générale, et elle vaut au-delà de ce module : ne jamais chercher un marqueur dans les
> FRAGMENTS d'un flux. Un marqueur se cherche dans le flux recomposé, ou par un automate qui garde le
> chevauchement.** C'est le pendant, sur un flux, de « le marqueur n'est pas le verdict » : ici le
> marqueur est juste, c'est le découpage qui le perd.

### 1.5 Ce que le portage devra faire de l'écho

`output` est **affiché tel quel**. Le portage doit :

- **échapper** (`textContent`, jamais `innerHTML`) — le champ contient du texte distant ;
- **ne jamais placer un marqueur d'échec en clair** dans la commande. C'est le piège de `v1.37.11` :
  le PTY échote la commande, donc un marqueur littéral apparaît dans la sortie **avant** que la
  commande ne s'exécute, et un test de présence rend un faux positif permanent. Ici la commande porte
  `EXIT_CODE=$?` — **`$?` n'est pas `0`**, donc l'écho ne contient pas `EXIT_CODE=0` et la détection
  n'est pas empoisonnée. **C'est de la chance, pas une précaution** : un jour où quelqu'un écrirait
  `echo EXIT_CODE=0` dans une branche, l'écho suffirait à déclarer le succès ;
- **ne pas afficher le blob base64.** Il n'apprend rien et il noie le message. À couper, ou à replier.

---

## 2. MESURE 3 — `min-w-[6px]` : dédouané pour ce module

`min-w-[6px]` est **absent de tous les CSS livrés** (`tailwind.css`, `rw.css`, `app.css` : 0
occurrence). Quatrième occurrence confirmée de la classe purgée.

**Mais elle n'appartient pas à `iptables/`** : son unique usage est
`legacy/fail2ban/js/main.js:577`, et la frise de fail2ban est **déjà portée** (F2, dessinée en
pixels). **Rien à porter, rien à corriger ici.** Le dire évite de refaire le travail.

*(La règle reste vraie pour tout le portage : mesurer le style **calculé**, jamais la présence de la
classe dans le DOM.)*

---

## 3. LE CONTRAT DE SÉCURITÉ — ce que le portage devra respecter

### 3.1 Ce que la session 4 vient de fermer, à NE PAS défaire

`POST /iptables-apply` porte désormais `@require_permission('can_manage_iptables')`
(`iptables.py:129`, E-152). **Vérifié.** Le portage ne doit pas « harmoniser » en sens inverse.

Conséquence d'écran, et c'est la règle du chantier : `can_manage_iptables` n'est détenue que par
`superadmin` (mesuré). Un rôle 2 sans la permission verra la page et sera **refusé par la requête** —
le bouton doit donc être désactivé **avec son motif**, et l'état désactivé doit être la
**conjonction** « le backend refuserait ET la condition est réunie ».

### 3.2 ⚠ LE DANGER PROPRE DU MODULE : se couper la patte

`MODULE-FILTRAGE.md` §2, remesuré : `iptables-restore` **remplace atomiquement toutes les tables**.
Un fichier avec `INPUT DROP` sans `ACCEPT` sur le port SSH ferme la session en cours **et toutes les
suivantes**. Le seul canal de RootWarden vers la machine est SSH, et `/iptables-rollback` **passe
aussi par SSH**.

Deux défauts s'additionnent, et ils sont toujours là :

- les cinq gabarits codent **`--dport 22` en dur**, alors que le port SSH de chaque machine est en
  base et disponible côté JS. Le gabarit `deny_all` porte même le commentaire « seul SSH est ouvert
  pour ne pas perdre l'acces » : **l'intention est écrite, l'implémentation suppose 22** ;
- `showNotification` vise `#notifications`, **qui n'existe pas sur la page** — ses huit points d'appel
  lèvent une `TypeError`, **y compris dans le `catch`**. Donc : appliquer un jeu de règles **réussit
  sur la machine et l'écran ne dit rien**. Ni succès, ni erreur.

**Propriétés que le portage doit satisfaire** :

| # | propriété | mesurable comment |
|---|---|---|
| **Q1** | le gabarit emploie le **port SSH de la machine**, lu en base, jamais `22` en dur | dériver le port de la base et le chercher dans le texte du gabarit rendu — **ne pas coder `22`**, les trois machines écoutent sur 22 et la suite mesurerait son presse-papier |
| **Q2** | un jeu de règles qui **ne contient pas** d'`ACCEPT` sur ce port est **refusé avant l'envoi**, et la raison est nommée | requête forgée depuis la page + `page.on('request')` : **aucune requête ne part** |
| **Q3** | tout retour d'`/iptables-apply` produit un message **visible**, succès comme échec | `page.on('response')` puis lecture du porte-messages dédié — jamais `[class*="text-red"]` |
| **Q4** | avant consentement, **aucune requête n'est émise** | au **réseau**, pas au DOM |

**Q2 est la propriété qui compte.** Elle est la seule qui empêche le geste irréversible, et elle se
mesure **sans jamais l'émettre**.

### 3.3 La cible sûre, et elle n'est pas évidente

> **Aucun `iptables-apply` ne doit être émis vers une machine réelle pendant les mesures.**
> `Test-Server-Debian` (id 2) est un **conteneur** : il n'a pas de systemd, et son réseau est celui
> de Docker. Y appliquer un jeu de règles n'est pas « sans danger » — c'est **sans signification**, et
> un test qui passe pour cette raison est un faux PASS.

Le régime est celui de F5 : **les écritures sont servies par la suite**, et le motif est écrit dans
le fichier. Ce qui se mesure est le **refus** et l'**absence de requête**, jamais l'effet distant.

`/iptables-validate` est le seul geste de ce module qui pourrait être joué pour de vrai — il écrit
dans `/tmp` et ne modifie aucune table. **Mais il ouvre quand même une session SSH**, donc jamais vers
la machine 1.

### 3.4 Ce qui reste vrai de mes qualifications antérieures

- **aucune valeur utilisateur n'est interpolée brute** dans `iptables_manager.py` — règles en base64,
  chemins littéraux. **L'en-tête du fichier le revendique et c'est vrai.** Rien à durcir ;
- **réserve maintenue** : `_write_rules_safe` est sûre **par ses deux appelants**, pas par
  construction — `dest_path` n'est pas validé. **Un troisième appelant rouvrirait le trou**, et le
  portage ne doit pas en devenir un ;
- `/iptables-rollback` porte `@require_permission('can_manage_iptables')` et fait son contrôle
  d'accès **sur l'objet résolu** (`iptables.py:296`, `check_machine_access(row['server_id'])`).
  **C'est le bon motif, et il est déjà là** — le portage doit s'y adosser, pas le refaire ;
- **`/iptables-history` lit `server_id` là où le décorateur retient `machine_id`** (E-175). Le
  correctif dort sur `security/backend-cve`, commit `399931a`, **jamais fusionnée**. Les deux tables
  d'historique sont vides : réel, sans porteur.

### 3.5 Hors lot, et il faut le dire au lieu de le porter

`/iptables-logs` **diffuse un fichier que personne n'écrit** : `/app/logs/iptables.log` est créé vide
au démarrage et **aucun writer n'existe**. L'utilisateur voit un flux qui n'émet que des pings pendant
dix minutes. **Ne pas le porter**, ou le brancher sur ce qui écrit réellement — mais ne pas reproduire
un flux vide qui a l'air vivant.

---

## 4. Ce que je n'ai PAS mesuré

- **je n'ai exécuté aucun geste de ce module**, ni validation, ni application, ni retour arrière.
  Tout ce qui précède est établi par lecture, plus **une recomposition locale du découpage** qui ne
  joint aucune machine ;
- **je n'ai pas relu les trois handlers AJAX PDO locaux** d'`iptables/index.php` (`MODULE-FILTRAGE.md`
  les signale, I2 les porte). Ils ne sont pas dédouanés ;
- **je n'ai pas vérifié le contenu des cinq gabarits ligne à ligne** — seulement le `--dport 22` en
  dur, déjà mesuré par l'inventaire ;
- **je n'ai pas mesuré si `iptables_rules` admet des lignes multiples** faute de contrainte
  d'unicité (`MODULE-FILTRAGE.md` §7). C'est une question de schéma, elle appartient à la session 4.

---

# 6. E-240 — LE DIFF, PRÉPARÉ ET NON APPLIQUÉ (2026-08-28)

Pour la session 4. **Rien n'est appliqué** : `backend/` est le sien, et le process en service date
d'hier (E-238) — un correctif posé aujourd'hui serait inerte, et un écran qui annoncerait la
protection mentirait sur l'état réel.

## 6.1 L'état actuel

`backend/routes/iptables.py:77-80` :

```python
test_cmd = f"… iptables-restore --test /tmp/_ipt_test.rules 2>&1; echo EXIT_CODE=$?"
output_lines = list(execute_as_root_stream(client, test_cmd, root_password, logger=logger))
output = '\n'.join(output_lines)
exit_code = 0 if any('EXIT_CODE=0' in l for l in output_lines) else 1
```

`execute_as_root_stream` rend des **fragments de 4096 octets**, pas des lignes. Trois défauts en
quatre lignes :

1. **le marqueur est cherché dans chaque FRAGMENT** — à cheval sur une frontière, aucun ne le
   contient, et un jeu de règles **valide** est déclaré invalide ;
2. **`'\n'.join` insère un saut de ligne** tous les 4096 octets dans la sortie affichée ;
3. **le marqueur est cherché par INCLUSION** — `'EXIT_CODE=0' in l`. L'écho PTY renvoie la commande,
   qui porte `echo EXIT_CODE=$?` : le littéral `$?` ne correspond pas aujourd'hui, mais la protection
   tient à ce détail. Le jour où une branche écrirait `echo EXIT_CODE=0`, **l'écho suffirait à
   déclarer le succès**. C'est le piège de `v1.37.11`, sous une troisième forme.

## 6.2 Le diff

**Un helper, à poser près des autres en tête de module :**

```python
_MARQUEUR_CODE = re.compile(r'^EXIT_CODE=(\d+)\s*$', re.M)


def _code_de_sortie(sortie: str):
    """Le code de sortie porté par le flux, ou `None` s'il n'y en a pas.

    ══ RECOMPOSER D'ABORD, PARSER ENSUITE, ET PAR LIGNE ═════════════════

    `execute_as_root_stream` rend des fragments de 4096 octets, pas des lignes.
    Chercher le marqueur DANS chaque fragment le perd des qu'il chevauche une
    frontiere — et un jeu de regles VALIDE est alors declare invalide. Reproduit
    hors SSH : a 4102, 4104 et 4107 octets de sortie, le verdict s'inverse.

    ══ ET LA COMPARAISON EST D'EGALITE DE LIGNE, PAS D'INCLUSION ════════

    Le canal echote la commande. Chercher `'EXIT_CODE=0' in …` ferait donc du
    TEXTE ENVOYE une source de verdict le jour ou une branche ecrirait
    `echo EXIT_CODE=0` en clair — troisieme forme du piege de l'echo PTY, apres
    le faux « visudo refuse » permanent et le `isdigit()` global.
    Une ligne qui EST le marqueur ne peut pas etre l'echo d'une commande.

    ══ LE DERNIER, ET `None` PLUTOT QU'UN REPLI ════════════════════════

    Le dernier marqueur gagne : ce qui suit la commande la decrit, ce qui la
    precede peut l'echoter. Et l'absence rend `None` — « je n'ai pas pu lire le
    verdict » n'est pas « le verdict est mauvais », et l'appelant doit pouvoir
    les distinguer. Rendre 1 par defaut ferait passer une incertitude pour un
    refus.
    """
    trouves = _MARQUEUR_CODE.findall(sortie or '')
    return int(trouves[-1]) if trouves else None
```

**Et les quatre lignes de la route :**

```python
            fragments = list(execute_as_root_stream(client, test_cmd, root_password, logger=logger))
            # Concatener, PAS joindre : les fragments sont contigus, et `'\n'.join`
            # inserait un saut de ligne tous les 4096 octets dans ce qui est affiche.
            output = ''.join(fragments)
            exit_code = _code_de_sortie(output)
            if exit_code is None:
                return jsonify({
                    "success": False,
                    "verdict_illisible": True,
                    "message": "Le verdict de validation n'a pas pu etre lu. "
                               "Ce n'est PAS « les regles sont invalides » : "
                               "la commande n'a pas rendu son code de sortie.",
                    "output": output,
                })
            if exit_code == 0:
                return jsonify({"success": True, "message": "Regles valides.", "output": output})
            return jsonify({"success": False, "message": "Erreur de syntaxe.",
                            "exit_code": exit_code, "output": output})
```

## 6.3 Ce que le correctif ferme, et ce qu'il n'ouvre pas

**Ferme** : le chevauchement, les sauts de ligne insérés, et la dépendance à l'écho.

**Ce qu'il CASSERAIT : rien.** La valeur cherchée est la même, l'ensemble balayé est un sur-ensemble
strict, et le champ `verdict_illisible` est **additif** — un appelant qui ne le lit pas voit
exactement ce qu'il voyait, `success: false`.

**Et il n'arme aucun geste** — c'est la question que ce chantier pose à chaque correctif. Cette route
écrit dans `/tmp` et n'applique **rien** : `iptables-restore --test` ne modifie aucune table. Le
correctif ne rend donc pas un geste plus efficace ; **il rend un verdict plus juste**. Il ne
rencontre pas le piège d'E-215.

## 6.4 Un résidu que ce diff ne traite pas

`execute_as_root_stream` fait `if text.strip(): yield text` : **un fragment entièrement blanc est
jeté**. La sortie affichée peut donc être amputée d'une portion d'espaces, quelle que soit la
recomposition. Sans conséquence sur le verdict — le marqueur n'est pas blanc — mais la sortie
affichée n'est pas *exactement* celle de la machine. **C'est dans `ssh_utils.py`, hors du périmètre
de ce diff, et je ne le corrige pas dans le même geste** : ce fichier sert des dizaines d'appelants.

---

## 7. Ce que I4 a rendu lisible, et ce qu'il n'a pas fermé

I4 est porté (`c42fe48`). Ce sous-lot n'applique aucun correctif : il rend
visible un défaut du backend que le legacy présentait comme un verdict.

### 7.1 SEC-011 — le verdict de `/iptables-validate` est faillible, et il alarme

**GRAVITÉ** — moyenne. Pas d'élévation de privilège, pas de fuite. Un faux
négatif qui **fait corriger des règles saines**.

**SURFACE** — `backend/routes/iptables.py:78-79`.

```python
output_lines = list(execute_as_root_stream(client, test_cmd, root_password, logger=logger))
exit_code = 0 if any('EXIT_CODE=0' in l for l in output_lines) else 1
```

**PRÉCONDITIONS EXACTES** — `execute_as_root_stream` rend des fragments de
**4096 octets**, pas des lignes. Le marqueur `EXIT_CODE=0` fait 12 octets. Il
suffit qu'il chevauche une frontière de fragment pour n'être présent dans
**aucun** des deux : `any(...)` rend `False`, et un jeu de règles **valide**
est déclaré invalide.

La probabilité croît avec la longueur de la sortie. `iptables-restore --test`
est silencieux quand tout va bien — c'est ce qui rend le défaut rare, donc
durable : il ne s'arme que sur les sorties longues, c'est-à-dire précisément
quand il y a beaucoup de règles à lire.

**UN COMPTE RÉEL L'OCCUPE-T-IL AUJOURD'HUI** — non, et c'est mesuré : la route
n'était atteignable que depuis le legacy, dont la page ne l'appelle que sur le
contenu de sa zone d'édition. Aucun compte du parc ne détient
`can_manage_iptables` hors `superadmin` (§3). Le défaut n'a jamais été observé
en exploitation.

**CHEMIN DE REPRODUCTION** — sans toucher aucune machine : le calcul est local.
Un `execute_as_root_stream` dont les fragments coupent la chaîne à l'octet 4090
suffit à le démontrer sur banc. **Non exécuté** : la route ouvre une vraie
session SSH.

**CORRECTIF PROPOSÉ — il n'appartient pas à ce portage.** Accumuler le flux puis
chercher le marqueur dans la chaîne **reconstituée**, ou parser le nombre après
`EXIT_CODE=` plutôt que tester l'appartenance d'une phrase. C'est la même classe
qu'E-183 (« le marqueur n'est pas le verdict ») : lire le flux entier, parser le
nombre, jamais la phrase. **La session 4 (`backend/`) applique ; je ne me
valide pas moi-même.**

**CE QUE LE CORRECTIF CASSERAIT** — rien à l'appelant : la forme de la réponse
ne bouge pas. Il ferait basculer en `success: true` des validations qui rendent
aujourd'hui `false` à tort — ce qui est l'objet.

**CE QUE I4 A FAIT À LA PLACE** — le cas « déclarées invalides » est rendu en
`attention` et non en `echec`, avec la sortie brute et la consigne de la lire.
Peindre en rouge un verdict qui peut être faux ferait corriger des règles
saines. *Le portage ne répare pas le backend ; il cesse de présenter une
incertitude comme un verdict.*

### 7.2 SEC-012 — `/iptables-` est une entrée à PRÉFIXE de la liste blanche

**GRAVITÉ** — à qualifier, pas encore fermée. **Aucun compte ne l'occupe.**

**SURFACE** — `laravel/app/Support/RoutesBackend.php`, `LISTE_BLANCHE` porte
`'/iptables'` **et** `'/iptables-'`. Dans `correspond()`, un dernier caractère
`/`, `_` ou `-` déclenche `str_starts_with` :

```php
if ($derniere === '/' || $derniere === '_' || $derniere === '-') {
    if (str_starts_with($chemin, $entree)) { return true; }
}
```

Le même préfixe ouvre donc `/iptables-validate`, `/iptables-apply` et
`/iptables-rollback` **sans les distinguer**. La passerelle ne peut pas être
l'endroit où l'application se referme.

**UN COMPTE RÉEL L'OCCUPE-T-IL AUJOURD'HUI** — **non.** Ce qui tient :

1. le backend garde les trois routes par `@require_permission('can_manage_iptables')`
   **et** `@require_machine_access` — mesuré sur les trois ;
2. `can_manage_iptables` n'est détenue par aucun compte hors `superadmin`
   (§3, et la décision du plan de **ne pas** l'accorder à `rw-test-admin`) ;
3. le portage ne compose **aucune** requête vers `-apply` ni `-rollback` :
   la fermeture reste **par l'absence**, comme en I1.

Ce n'est donc pas une faille occupée. C'est une **borne mal placée** : elle
repose entièrement sur la garde du backend, alors que le reste du portage
suppose que la passerelle est une seconde barrière.

**CORRECTIF PROPOSÉ** — **aucun, pour l'instant, et délibérément.** Remplacer le
préfixe par des entrées exactes ferme `-apply` et `-rollback`… et casserait I5,
qui est précisément le sous-lot en attente d'arbitrage. Le fermer maintenant
déciderait de I5 par un effet de bord de liste blanche, ce qui est le contraire
d'un arbitrage. **C'est un point à trancher AVEC I5, pas avant.**

C'est le même raisonnement que celui déjà tenu sur `/cve_` (§ liste blanche du
plan) : *fermer un préfixe une route à la fois sans arbitrage refait en petit
le défaut qu'on veut éviter.*

### 7.3 Ce que I4 n'a PAS couvert, et qui est écrit sur la page

`/iptables-validate` lit `rules_v4` et **rien d'autre**. `rules_v6` n'est ni
envoyé ni examiné. Une copie dont l'IPv6 est mal formé **passe** la validation
et échouerait à l'application.

Ce n'est pas un défaut du portage : c'est le contrat de la route. Le portage
l'**écrit sur la page**, avant le geste, plutôt que de laisser croire qu'une
validation réussie couvre les deux familles.

### 7.4 Deux clés servies au JS et jamais employées — hors périmètre de I4

`copie_absente` et `releve_le` sont dans la table `$textes` du contrôleur et
aucun `t()` ne les appelle. `copie_absente` est redondante — le contrôleur la
rend déjà comme `message` dans la réponse JSON. `releve_le` (« Relevé le
:date ») **n'est affichée nulle part** : I1 annonce le nom de la machine et
pas la date.

Aucune conséquence de sécurité, aucune sur le rendu. **Signalé, non corrigé** :
ce sont des résidus d'I1 et d'I2, et les toucher depuis I4 mélangerait les
sous-lots. À la session qui reprendra ce module.
