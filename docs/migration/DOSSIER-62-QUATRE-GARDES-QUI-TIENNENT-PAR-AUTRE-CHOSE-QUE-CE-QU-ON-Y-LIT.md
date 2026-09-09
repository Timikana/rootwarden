# DOSSIER-62 — Quatre gardes qui tiennent par autre chose que ce qu'on y lit

**Mesuré le 2026-09-09 entre 01:20 et 03:10 CEST**, par cinq sessions en
parallèle. Aucune machine jointe, aucun geste exercé. Un correctif écrit, sur
branche `security/`, **non fusionné**.

> Ce dossier ne rapporte pas des failles. Il rapporte quatre endroits où **le
> code est correct et où la RAISON de sa correction n'est pas celle qu'il
> affiche**. C'est une catégorie distincte, et elle a un coût propre : ce qui
> tient par accident se casse au premier refactor qui a l'air anodin.

---

## 1. Ce qui a été cherché, et pourquoi

Le cliquet semgrep est à **zéro** depuis le 2026-09-09 : les 106 interpolations
de commande root du dépôt portent chacune une justification nommant son
mécanisme. **Mais la règle n'apparie que la f-string écrite EN LIGNE dans
l'appel.** Un zéro qui ne dit pas sa moitié est plus trompeur qu'un compte.

Quatre sessions ont donc qualifié, fichier par fichier, la provenance de chaque
commande root construite dans une variable. **Aucun des sites assignés n'était
exploitable.** Ce qui suit a été trouvé *à côté*.

---

## 2. Le recensement, refait par invariant

```
227  appels `execute_as_root*` dans backend/ hors tests
113  ① f-string EN LIGNE       gardée par le cliquet semgrep (à ZÉRO)
 49  ③ littéral                inerte
 37  ④ INDIRECTE               invisible à la règle
 18  ⑤ nom lié à une valeur non interpolée
  5  ⑦ AVEU : nom jamais lié dans la portée
  5  ⑧ AVEU : forme non résolue
───  somme = 227, vérifiée par un comptage INDÉPENDANT du recenseur
```

**Deux relevés indépendants convergent sur 227**, avec `113` et `49` identiques
au chiffre près.

⚠ **Les `execute_as_root_stream` exécutent des commandes root comme les
autres, et mon premier instrument les écartait** en filtrant sur le nom exact.
Deux chiffres circulent, tous deux justes, avec des dénominateurs différents —
`gestion-ssh-key-5f` a corrigé mon amalgame avant qu'il voyage :

```
14  appels `execute_as_root_stream` au TOTAL
 4  deja tenus par le cliquet semgrep (f-string EN LIGNE)
10  dans la population de PERSONNE       <- le chiffre qui compte ici
```

*« Si tu inscris l'un, nomme lequel — sinon le prochain lecteur soustraira 14
d'un total qui n'en compte que 10. »*

### Le dessin qui rend une omission impossible à perdre

Il vient de `gestion-ssh-key-5f`, et il corrige une faute de conception à moi :
j'avais posé un « aveu » — *rendre « je n'ai pas résolu » plutôt que rien* — mais
**en aval de trois filtres qui écartaient en silence**.

> **Un aveu placé après un filtre silencieux n'avoue que ce que le filtre a
> laissé passer. La règle était bonne ; c'est sa POSITION qui la neutralisait.**

D'où : compter d'abord *tous* les appels, écarter ensuite avec une raison
**nommée**, et exiger que **la somme des catégories égale le nombre d'appels**.
Deux cliquets — `INDIRECTES = 37`, `AVEUX = 10`. *Le second est le plus
important : c'est le seul endroit où « je ne sais pas » a un compte, donc le seul
où l'ignorance ne peut pas se dissoudre.*

---

## 3. LES QUATRE GARDES

### ⓐ `re.escape` employé comme s'il échappait le shell — 3 appels, 6 usages

Trouvé **séparément** par `gestion-ssh-key-c1` (`routes/supervision.py:368`) et
par moi (`ssh_audit.py:317` et `:411`). *C'est le recoupement qui le qualifie
comme classe, pas l'une ou l'autre mesure.*

```
sed -i 's/^\s*\({escaped_key}\b\)/# \1/' /etc/ssh/sshd_config
                  ↑ entre APOSTROPHES de shell, et dans un s///
```

`re.escape` échappe pour une **regex Python**. Mesuré, Python 3.13 :

```
'    ->  '     INTACT      ferme l'apostrophe du shell
/    ->  /     INTACT      sort du s///
"    ->  "     INTACT
`    ->  `     INTACT
$    ->  \$    echappe
&  |  (  .  *  \n  espace  ->  echappes
```

**Les quatre caractères qui comptent ici sont exactement ceux que `re.escape` ne
touche pas.**

**Ce qui protège réellement**, dans les deux fichiers, est une **liste blanche
située ailleurs** :

| site | garde effective | où |
|---|---|---|
| `ssh_audit.py:414 :417` | `_validate_directive` contre `ALLOWED_DIRECTIVES` | `:243`, 1re instruction |
| `supervision.py:369` | `_SAFE_PARAM_RE` | `:337`, trente lignes plus haut |

`ALLOWED_DIRECTIVES` est **dérivé** (`{rule['key'] for rule in AUDIT_RULES}`),
16 clés, toutes `[A-Za-z0-9]+`. La garde est la première instruction exécutable
de `toggle_directive` **et** de `apply_fix`, donc elle domine tous leurs
`return`.

⚠ **Élargir `_SAFE_PARAM_RE` — pour accepter les directives d'un nouvel agent,
par exemple — rendrait `supervision.py:369` injectable SANS toucher à cette
ligne, et `re.escape` continuerait d'y donner l'apparence d'une protection.**
*(formulation de `c1`)*

**Mon arbitrage : renommer d'abord, changer la parade ensuite.** Un
`escaped_key` qui n'échappe pas le shell n'est pas seulement rassurant à tort —
**il se propage** : le prochain qui écrira une commande à côté réutilisera la
variable en la croyant sûre. ⚠ Et le renommage doit porter sur les **six
interpolations**, pas sur les trois affectations.

### ⓑ Le gage qui vaut sur le SHELL et pas sur le PUITS — un cas réel, corrigé

Trouvé par `gestion-ssh-key-94` dans `sudo_manager.py`. **Le seul défaut
exploitable de la nuit.**

`_write_to_remote` emploie un heredoc **quoté** avec un marqueur aléatoire
(`RW_HEREDOC_` + `token_hex(6)`). Côté shell, c'est irréprochable : aucun
métacaractère ne s'en échappe.

> **Mais le puits n'est pas un shell. C'est `/etc/sudoers.d/`, et sa grammaire
> n'est pas celle du shell.** Le gage est parfait dans son domaine, et son
> domaine n'est pas celui du danger.

Le défaut concret : `render_policy` interpole `runas` dans l'**en-tête** du
fichier sur tous les chemins, mais ne le valide que sur ceux qui ont besoin de le
**mettre en forme**. La branche `custom` ne lui passe pas `runas` — elle perdait
donc la validation *avec* le format.

```
écrit à  :195
lu à     :200   <- l'en-tete, sur TOUS les chemins : le site du defaut
         :207   <- systemctl_specific, qui valide
         :209   <- PRESET_RENDERERS, qui valident
_runas_spec appele dans render_policy : 0 fois

RENDU MESURE, branche custom
  runas legitime                  ->  1 directive
  runas portant un saut de ligne  ->  2, dont une NON DEMANDEE
  et l'en-tete affiche toujours la valeur attendue
CONTRE-EPREUVE
  les 5 branches appelant _runas_spec refusent deja la meme valeur
```

**Corrigé** sur `security/runas-non-valide-sur-la-branche-custom`, PR 64,
**non fusionnée**. Le correctif sépare la validation du formatage et pose la
garde en première instruction, où elle domine tout ce qui suit — *un `if` dans
la branche `custom` aurait fermé ce chemin en laissant la cause*.

⚠ **Ce que ça ajoute n'est pas le pouvoir** : un rôle 3 peut déjà octroyer root
par `all_nopasswd`, dont la docstring dit « ÉQUIVALENT ROOT ». **Ça ajoute
l'invisibilité** — l'octroi vise un username arbitraire, hors de tout
`_validate_username`, pendant que l'en-tête et le journal affichent la valeur
attendue. *Ce qui tombe d'abord est la piste d'audit, pas la frontière.*

⚠ **Non mesuré, et dit plutôt que comblé** : que `visudo -cf` accepte la ligne
injectée. Aucune machine n'a été jointe. *Ça ne change pas le verdict, puisque le
défaut est que la valeur ARRIVE dans le fichier.*

### ⓒ Une garde qui tient par contingence de ses appelants

Relevé par `gestion-ssh-key-5f`. Les 5 sites `Subscript` du recensement lisent
tous `AGENT_REGISTRY` (`supervision.py:125`). Ses huit clés `*_cmd` : quatre
littérales, quatre construites par un appel **au niveau module**,
`_commande_desinstallation([…], […])`, arguments littéraux. **Origine littérale,
donc sains.**

Mais :

```
_commande_desinstallation  n'a AUCUNE garde
                           cite ses paquets naivement  f"'{p}'"  (pas shlex.quote)
                           ne cite PAS ses services     systemctl stop {s}
                           accepte n'importe quelle liste
```

> **La sûreté vient de l'APPELANT, pas de la fonction.** *(formulation de `5f`)*

Et le chemin explique pourquoi personne ne le verrait changer : la commande est
bâtie **au niveau module**, rangée dans un **dict**, relue par **indice**, et
exécutée **trois indirections plus loin**.

**Mon arbitrage : à durcir dans la fonction, pas chez ses appelants.** Ce n'est
pas urgent — aucun appel ne passe de valeur non littérale aujourd'hui — mais
c'est la forme exacte d'un défaut qui reviendra sans bruit.

### ⓓ Une garde effective que le motif seul ne montre pas — et où j'ai failli me tromper

`gestion-ssh-key-94` avait laissé un adjacent non revendiqué :
`sftp_manager._PATH_RE` (`^/[A-Za-z0-9._/-]{1,510}$`) accepte
`/home/../../etc/ssh/sshd_config`, et la valeur atterrit dans
`ChrootDirectory` (`:149`).

**Le motif l'accepte. La FONCTION le refuse.** `_validate_path` porte une
seconde garde, séparée, à `:70` :

```
                                   motif      fonction
/srv/sftp/sftpuser                 ACCEPTE    ACCEPTE     <- temoin positif
/home/../../etc/ssh/sshd_config    ACCEPTE    REFUSE      <- `'..' in path.split('/')`
/a/../b                            ACCEPTE    REFUSE
/home/x..y                         ACCEPTE    ACCEPTE     <- correct : pas un segment
```

**`94` a eu raison de ne pas le revendiquer** — « accepté par le motif » n'est pas
« exploité ». **Et j'ai eu tort de sonder le MOTIF plutôt que la FONCTION**, ce
qui est ma propre règle, payée une fois de plus ce soir.

---

## 3bis. DEUX AJOUTS DE `gestion-ssh-key-c6`, rejoués avant d'être portés

### ⓔ Un nom d'utilisateur qui commence par un tiret devient une OPTION

`routes/ssh.py:2881` — la route la plus destructrice du fichier :

```
cmd = f"/usr/sbin/userdel {flag_str} {shlex.quote(username)} 2>&1"
```

**`shlex.quote` n'entoure de guillemets que ce qui en a besoin.** Un nom sans
métacaractère en sort *nu* :

```
'sftpuser'      ->  sftpuser        aucun guillemet
'-R'            ->  -R              aucun guillemet   <- lu comme une OPTION
'-rf'           ->  -rf             aucun guillemet
'--root=/tmp'   ->  --root=/tmp     mais REFUSE en amont (le `/` et le `=`)
```

Et `_motif_nom_invalide` (`configure_servers.py:70`) les **accepte** — mesuré :

```
'sftpuser' 'Debian-exim' '-R' '-rf' 'root'   ->  ACCEPTES
'--root=/tmp' '..' 'a/b' 'a;id' "a'b"        ->  REFUSES
```

**Ce n'est pas exploitable aujourd'hui, et la raison est du bon grain** : *`userdel`
prend UN opérande. Consommé comme option, il se retrouve sans opérande et rend
une erreur d'usage.* **Ce qui la rendrait vivante : une option courte et sans
argument qui soit destructrice, ou une évolution vers deux opérandes.**

> C'est un défaut **DORMANT** au sens strict : inerte aujourd'hui, effectif au
> premier changement d'un tiers — et le tiers en question n'aurait aucune raison
> de venir lire cette ligne.

**Le remède est du rang 1 — inexprimable, pas contrôlé** : poser `--` avant le
nom ferme l'analyse d'options *par construction*, et coûte deux caractères.
**`:283` du même fichier le fait déjà pour `grep -Fxq --`.** *La parade existe
dans le fichier ; elle n'a pas voyagé jusqu'ici.*

### ⓕ La seule valeur qui SORT d'une machine distante

`file_path`, tiré du `grep` distant à `:205`, est réinjecté dans le message rendu
à l'appelant (`:290-291`) — il traverse donc la passerelle et atteint
l'interface.

**Ce n'est pas classé en défaut** : le portage échappe par défaut. C'est la
surface à regarder si ce message est un jour rendu en HTML brut.

⚠ **Et c6 a démoli une inquiétude que j'avais laissée debout.** J'avais noté que
`file_path` vient d'une machine distante, donc qu'« une cible hostile la
choisit » — vrai, et sans conséquence :

> *L'attaquant qui contrôle le `grep` de la machine X a déjà root sur X — et
> l'écriture a lieu sur X. Il n'obtient rien qu'il n'ait déjà.* **Aucune
> frontière de confiance n'est franchie.**

Et elle écrit ce qui la réfuterait, ce qui rend le négatif utilisable au lieu de
rassurant : `file_path` atteignant une commande sur l'hôte RootWarden · persisté
puis rejoué contre une AUTRE machine · un appelant passant un `sa_name` non
littéral. **Les trois sont non observés, et le troisième est mesuré.**

---

## 4. ⛔ CE QUE LE ZÉRO DU CLIQUET NE DIT PAS

Trois limites, écrites ici pour qu'elles voyagent avec le chiffre rond.

**① La moitié invisible.** La règle ne voit que la f-string en ligne. 37 sites
indirects, tenus par un second cliquet.

**② Le domaine du gage.** Le cliquet demande *« la valeur interpolée est-elle
injectable ? »*. Pour `sudo_manager`, la réponse est **non** sur les quatre sites,
et un site était exploitable quand même. *Un gage se juge sur son **domaine** et
sur son **puits**, pas sur sa qualité.*

**③ Les aveux.** 10 appels root que l'instrument ne résout pas. **Ils ne sont pas
déclarés sûrs — ils sont déclarés non classés**, et c'est le cliquet des aveux
qui empêche cette distinction de s'effacer.

---

## 5. Ce qui revient à l'exploitant

**① Fusionner la PR 64**, ou dire de ne pas la fusionner. C'est un correctif de
sécurité sur une branche `security/` : il attend un mot, par règle et non par
prudence excessive.

**② Trancher le renommage de `escaped_key` / `grep_regex`** (six interpolations,
trois fichiers). Coût faible, gain : une exemption qui cesse de se recopier.

**③ Durcir `_commande_desinstallation`** — `shlex.quote` sur les paquets, citer
les services. Non urgent, et il touche l'installation d'agents : donc après un
redémarrage, éprouvé sur la machine 3 (OpenCVE-Test-OnPrem, 192.168.0.2).

**④ Poser `--` avant le nom dans `userdel`** (`routes/ssh.py:2881`). Deux
caractères, garde par construction, et la parade existe déjà trois lignes plus
haut dans le même fichier. *Le geste touche la route la plus destructrice du
module : donc après un redémarrage, éprouvé sur la 3.*

**⑤ Vérifier `visudo -cf`** sur la ligne injectée, si la gravité de ⓑ doit être
tranchée finement. Demande une machine, donc pas nous.

⚠ **Et le rappel qui gouverne les trois derniers** : `use_reloader = False`,
`workers = 4`. **Le service ne recharge pas le code de l'arbre.** Aucun de ces
correctifs n'est en service avant un redémarrage, et le redémarrage n'est pas à
nous.

---

## 6. Comment ces quatre choses ont été trouvées

Aucune par relecture.

```
ⓐ  par RECOUPEMENT de deux mesures independantes sur deux fichiers
ⓑ  en QUALIFIANT des sites qui se sont tous reveles sains
ⓒ  en corrigeant un compte, pas en cherchant un defaut
ⓓ  par un pair qui a REFUSE de conclure, et laisse le puits a tracer
```

Et trois défauts de mes **instruments** ont été trouvés par des pairs, jamais par
moi : la forme `IfExp`, la cible de `for`, et la position de l'aveu. **Les trois
faisaient baisser un compte.**

> **Un chiffre plus bas ressemble à un progrès, et personne — moi comprise — ne
> redemande la preuve d'une bonne nouvelle.**

### Et la répartition n'est pas due au hasard

`gestion-ssh-key-5f` l'a relevée, et elle est plus nette que ma propre lecture :

```
fenetre de 3 lignes     20/18    GONFLE     trouvee par moi
portee MODULE           31/27    GONFLE     trouvee par moi
portees imbriquees     250/227   GONFLE     trouvee par moi, en une heure
JoinedStr seul          27/33    DEDOUANE   trouvee par un TIERS
cible de boucle         33/34    DEDOUANE   trouvee par un TIERS
filtres en amont        34/37    DEDOUANE   trouvee par un TIERS
```

**Les trois qui gonflent, je les ai toutes trouvées seule. Les trois qui
dédouanent, aucune.**

> Ce n'est pas une différence de vigilance : **un compte qui monte provoque un
> « pourquoi ? », un compte qui descend provoque un hochement de tête.**
> L'erreur qui gonfle a un contradicteur naturel — le lecteur agacé. L'erreur
> qui dédouane n'en a aucun.
> **Une mesure qui vous arrange est celle qu'il faut refaire avec l'instrument
> de quelqu'un d'autre.** *(formulation de `5f`)*

Et la convergence des deux recensements vaut par sa forme, pas par son résultat :
**quatre seaux, quatre accords exacts, aucun instrument partagé** — mon
recenseur descend explicitement les portées, le sien fait un `ast.walk` global
et classe par `type(arg).__name__`. *Deux comptages avec le même code auraient pu
partager le même angle mort.*
