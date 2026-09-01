# AUDIT — `wazuh` : le catalogue des validateurs, et la question XXE

**Session 5 (sécurité, lecture seule).** Mesuré le **2026-09-01**. Aucune
écriture de code, aucun outil lancé contre une machine du parc — les mesures de
parseur tournent dans `rootwarden_python`, sur des fichiers temporaires.

Deux questions posées par le DSI. **La première a une réponse plus étroite que
l'énoncé, y compris pour son propre cas. La seconde se referme sur un négatif
vérifié, mais avec une fragilité qu'il faut nommer.**

---

## 1. Le catalogue : ce que ces validateurs acceptent, mesuré

### 1.1 D'abord, deux chiffres à corriger

Le suivi porte *« 33 validateurs, `fullmatch` nulle part »*. Remesuré par AST sur
`backend/` (hors `tests/`, `logs/`, `venv/`) :

| mesure | valeur |
|---|---|
| appels `.match()` | **61** |
| appels `.fullmatch()` | **1** — donc « nulle part » est faux |
| appels `.search()` | 14 |
| **`.match()` sur un motif ancré par `$`** — le piège exact | **58**, dans 17 fichiers |

**Le « 33 » était un chiffre hérité.** Je le portais moi aussi dans mes notes ;
je le corrige des deux côtés.

### 1.2 Ce que le piège accepte : exactement un `\n` final, rien après

Mesuré sur les trois familles de motifs du catalogue :

| valeur | `.match()` | `.fullmatch()` |
|---|---|---|
| `'4.14.5'` | OUI | OUI |
| `'4.14.5\n'` | **OUI** | non |
| `'4.14.5\nrm -rf /'` | non | non |
| `'4.14.5\n\n'` | non | non |

Et `re.MULTILINE` n'est posé sur **aucun** de ces motifs (vérifié sur les cinq
fichiers les plus chargés). **Le bornage du DSI est exact** : l'appelant peut
ajouter un saut de ligne, il ne peut rien mettre après.

> **Conséquence : le mal ne dépend pas du validateur, il dépend de ce qui SUIT la
> valeur dans la chaîne composée.** Valeur en fin de ligne → une ligne vide,
> inoffensive. Valeur suivie de texte → une seconde ligne parasite.

### 1.3 Le tri, en trois filtres

**Filtre 1 — 28 des 58 sont `.strip()`és avant la validation.** Le `\n` final ne
survit pas jusqu'au motif. Le piège ne peut pas s'armer.

**Filtre 2 — parmi les 30 restants, la valeur doit être suivie de texte dans une
chaîne EXÉCUTÉE.** Le relevé automatique sort 21 chaînes ; à la lecture, **10
sont des messages de journal, d'erreur ou d'affichage** (`ssh_audit.py:248/251/463`,
`bashrc.py:421/570/643`, `wazuh.py:1166`…), où un `\n` final est cosmétique.

**Filtre 3 — parmi les commandes réelles, le quoting.** C'est lui qui referme la
majorité :

- `bashrc.py:615-631` — `home_q`, `uname_q`, `backup_q`, `target_q` sont des
  `shlex.quote` (patch CMD-INJ-02). Fermé.
- `bashrc.py:518` — `'{bashrc}' '{home}/{backup_name}'` en **guillemets simples
  shell** : un `\n` y est littéral, aucune seconde ligne. Fermé.
- `wazuh.py:346` et `:576` — `shlex.quote(group)`. Fermé.
- `ssh.py:892-904` — `sa_name` vaut `Config.NOM_COMPTE_SERVICE`, une **constante
  de configuration**, pas un champ de requête. Le porteur serait l'exploitant qui
  pose la variable d'environnement, pas un appelant.

### 1.4 Ce qui SURVIT aux trois filtres : deux sites, aucune injection

**a) `bashrc.py:528` — `chown {uname}:{uname} '{bashrc}'`, `uname` NON quoté.**
Validé `bashrc.py:456` par `^[a-z_][a-z0-9_-]{0,31}$` en `.match()`, non
`.strip()`é. Un `uname` à `\n` final produit `chown bob` puis une ligne parasite
`:bob '…'`. Les chemins voisins étant en guillemets simples, le fichier visé
n'existe pas : **le déploiement échoue**. Défaut réel, effet = échec.

**b) `graylog.py:334` — `path` NON quoté, et c'est le plus conséquent.**

```python
path = f"{_RW_CONF_PREFIX}{tpl['name']}.conf"
execute_as_root(client, f"printf '%s' '{b}' | base64 -d > {path} && chmod 644 {path}", …)
```

Un nom à `\n` final scinde la commande : l'écriture aboutit dans un fichier
**sans le suffixe `.conf`**, et `.conf && chmod 644 …` devient une ligne parasite.
Or le nettoyage du module est `rm -f {_RW_CONF_PREFIX}*.conf` (ligne 327) :
**le fichier écrit échappe définitivement au nettoyage.**

**Non atteignable aujourd'hui** : la route d'enregistrement (`graylog.py:522`)
`.strip()` le nom, un tel nom ne peut donc pas être créé par le chemin normal.
C'est un écart **de cohérence entre l'écriture et la relecture** — la même forme
qu'un correctif posé d'un seul côté.

### 1.5 Verdict : une passe, pas un correctif

**Aucun site n'est à la fois atteignable par requête, non protégé, et
conséquent.** Le chiffre que le DSI cherchait — « combien composent une ligne de
commande » — vaut **2 après vérification**, contre 10 au relevé automatique et 58
au relevé par motif.

Mais la passe a une forme précise, et ce n'est **pas** « remplacer 58 `.match()` » :

1. `fullmatch` partout où le motif est ancré — les ancres deviennent redondantes,
   jamais fausses, et le geste est mécanique ;
2. **quoter les deux interpolations nues** (`bashrc.py:528`, `graylog.py:334`) —
   c'est là qu'est le seul effet mesurable ;
3. aligner `graylog.py:334` sur le `.strip()` que `:522` applique déjà.

> **Et je le dis dans les deux sens** : mon propre relevé automatique s'est trompé
> **des deux côtés**. Il a sorti 10 candidats dont 8 étaient du journal ou du
> quoting, et il a **manqué le cas du DSI** — la validation vivant dans un helper
> et l'exécution chez l'appelant. *L'ordre de grandeur est le dernier filet, pas
> le premier.*

---

## 2. ⚠ Le cas du DSI est un faux positif — et son vrai défaut est ailleurs

Le DSI mesure, à raison, que `re.match(r'^[0-9]+(\.[0-9]+){1,3}(-[0-9]+)?$',
'4.14.5\n')` accepte. **Mais il a mesuré le motif, pas la fonction.**

`wazuh.py:173`, première instruction de `_wazuh_pkg_specs` :

```python
version = (version or '').strip()
```

**Le `.strip()` précède le regex.** Exécution de la fonction réelle :

| entrée | `pkg_deb` | ligne composée | `\n` dans la commande |
|---|---|---|---|
| `'4.14.5'` | `wazuh-agent=4.14.5-1` | `apt-get install -y wazuh-agent=4.14.5-1` | **NON** |
| `'4.14.5\n'` | `wazuh-agent=4.14.5-1` | idem | **NON** |
| `'4.14.5\n-1'` | `wazuh-agent` | `apt-get install -y wazuh-agent` | NON |
| `'4.14.5; id'` | `wazuh-agent` | `apt-get install -y wazuh-agent` | NON |

**Aucun saut de ligne ne peut atteindre la ligne de commande.** Et son
illustration se trompait sur un second point : le `-1` n'est pas une ligne
parasite, c'est le suffixe de build que le code **ajoute lui-même**
(`ver_with_build = version if '-' in version else f'{version}-1'`).

### Mais son inquiétude non mesurée, elle, est réelle

Le DSI écrit que le seul effet qui l'intéresse est *« un paquet installé sans
épinglage de version »*, et qu'il ne l'a pas mesuré. **Il existe** — et il n'a
rien à voir avec le saut de ligne :

```python
if not re.match(…, version):
    return ('wazuh-agent', 'wazuh-agent')   # <- pas d'epinglage, SILENCIEUX
```

**Toute** version invalide — faute de frappe, format inattendu, valeur héritée —
fait installer le dernier paquet du dépôt **sans que rien ne le dise**. Le
docstring l'assume (*« Si 'latest' ou format invalide -> pas de pinning »*), donc
c'est une décision, pas un bug. Mais c'est un **repli silencieux vers le côté
permissif**, et l'appelant reçoit une réussite sans savoir qu'il n'a pas obtenu
la version demandée.

C'est la même forme que le défaut déjà refermé dans `save_overrides` : *« UN
REFUS SILENCIEUX N'EST PAS UN REFUS »*. Ici il n'est pas refermé. **C'est le
vrai point de cette fonction**, et il mérite d'être nommé dans l'inventaire.

**Porteur** : `agent_version` s'écrit au rôle 2 + `can_manage_wazuh`, et
`wazuh_agents` porte **0 ligne** — le module n'a jamais servi. D'accord pour ne
pas le sortir du gel.

---

## 3. La question XXE : posée, et refermée sur un négatif vérifié

### 3.1 L'exposition, d'abord

```python
res = subprocess.run(['xmllint', '--noout', p], capture_output=True, text=True, timeout=10)
if res.returncode != 0:
    return False, (res.stderr or 'XML invalide').strip()[:500]
```

`content` vient du **corps de la requête** (`wazuh.py:1122`,
`data.get('content','')`), route `POST /wazuh/rules`, gardes
`require_api_key` + `require_role(2)` + `require_permission('can_manage_wazuh')`,
plafond 512 Ko. **Et jusqu'à 500 octets de la stderr de `xmllint` repartent vers
l'appelant** — c'est le canal qui compte pour la suite.

Drapeaux : `--noout` seul. **Ni `--nonet`, ni `--noent`, ni `--loaddtd`, ni
`--valid`, ni `--xinclude`.** `xmllint` est bien présent dans le conteneur
(libxml 2.9.14, **compilé avec HTTP et FTP**).

### 3.2 Première barrière : le parseur ne résout rien

Mesuré avec l'invocation exacte, sur trois cibles :

| entité `SYSTEM` | rc | stderr |
|---|---|---|
| `file:///NEXISTE-PAS-MARQUEUR-AUDIT` | 0 | *(vide)* |
| `http://127.0.0.1:1/marqueur` (boucle locale, port fermé) | 0 | *(vide)* |
| `file:///etc/hostname` (existant) | 0 | *(vide)* |

**Aucune tentative de chargement, dans aucun des trois cas.** Le chemin
inexistant est le témoin décisif : s'il y avait tentative, elle échouerait
bruyamment. Ni lecture de fichier, ni requête sortante.

### 3.3 Seconde barrière, accidentelle : l'enrobage `<root>`

```python
tmp.write(f"<root>\n{content}\n</root>\n")
```

Un `<!DOCTYPE` se retrouve **à l'intérieur** de l'élément racine — XML invalide.
Mesuré, quatre tentatives d'échappement, l'attaquant contrôlant tout le contenu :

| tentative | verdict |
|---|---|
| fermer `</root>` puis déclarer le DOCTYPE | **refusé** (rc=1) |
| sortir d'un `CDATA` puis déclarer | **refusé** (rc=1) |
| DOCTYPE précédé d'un saut de ligne | **refusé** (rc=1) |
| entité référencée sans DOCTYPE | **refusé** (rc=1) |
| DOCTYPE dans un commentaire | accepté — mais **inerte**, c'est un commentaire |
| `xi:include` (libxml compilé avec XInclude) | accepté comme XML valide, **aucun fichier lu** |

**Deux barrières indépendantes.** La question est refermée.

### 3.4 ⚠ Mais aucune des deux n'est intentionnelle — et une seule suffit à tomber

L'enrobage existe *« pour autoriser multiple top-level elements »* ; l'absence de
drapeaux est un défaut de `xmllint`. **Personne n'a décidé cette sécurité.**

Mesuré, ce qu'**un seul drapeau** changerait :

| drapeaux | `xi:include href="file:///NEXISTE-PAS-AUDIT"` |
|---|---|
| `['--noout']` — ceux du code | rc=0, aucune tentative |
| `['--noout','--xinclude']` | **rc=1**, `failed to load external entity "file:///NEXISTE-PAS-AUDIT"` |

**`--xinclude` seul ouvre la lecture de fichier local** — et le message d'erreur
**recopie le chemin**, donc il repartirait par le canal des 500 octets de §3.1.
*(`--noent` seul ne suffit pas : mesuré rc=0, sans tentative.)*

**Recommandation, défense en profondeur, coût nul** : passer `--nonet`
explicitement, et poser un commentaire disant **pourquoi** `--xinclude` et
`--noent` sont absents. Aujourd'hui rien ne le dit, et le prochain qui voudra une
validation « plus complète » ajoutera le drapeau qui ouvre la lecture.

**Je n'écris pas ce correctif** : `backend/` est gelé, et de toute façon
c'est session 4 qui applique. *Qui écrit le code ne valide pas seul son
correctif.*

---

## 4. Sur la leçon du DSI, qui me concerne effectivement

> *« Une mesure qui ne vit que dans un compte rendu ne vit nulle part. Et une
> clôture est pire qu'un constat faux : elle retire l'objet du champ de ce qu'on
> vérifie encore. »*

Retenu, et ce document existe pour cette raison. J'ajoute le corollaire que ma
propre mesure vient d'illustrer deux fois aujourd'hui :

> **Un chiffre hérité se comporte comme une clôture.** Le « 33 validateurs,
> `fullmatch` nulle part » était faux sur les deux moitiés, et je le relayais.
> Il a survécu parce qu'il *ressemblait* à une mesure — et personne, moi compris,
> ne le remesurait avant de s'appuyer dessus.
