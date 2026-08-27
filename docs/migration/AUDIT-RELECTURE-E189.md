# Relecture croisée d'E-189 — la chaîne de décision de K4

Relecture demandée par le Lead, faite le **2026-08-27** par la session 5 (sécurité), en **lecture
seule**. Aucun code touché, aucune branche, banc jamais demandé, aucune machine jointe.

La question posée n'était pas « E-189 est-il un défaut » — le Lead a déjà établi que non, aujourd'hui.
Elle était : **quelles autres valeurs cet écran, et le préflight lui-même, tiennent-ils pour
constantes ?** Réponse : **cinq**, et **l'une d'elles rend une phrase de l'écran fausse aujourd'hui.**

---

## 0. E-189 tel que numéroté — confirmé, et sa qualification tient

`cles-ssh.js` teste `rep.ok` et lit `d.results` **sans jamais lire `d.success`**. Vérifié.

Et la qualification du Lead est juste : ce n'est **pas** un défaut aujourd'hui. `preflight_check`
rend `{'success': True, …}` **inconditionnellement** sur son chemin 200 (`ssh.py:495`), et ses deux
refus sortent en **400** (`Aucune machine specifiee`) et **403** (`Acces refuse a la machine …`),
donc attrapés par `if (!rep.ok)`.

**C'est une fragilité, et elle est couplée à une coïncidence** : *aucun refus de cette route ne porte
aujourd'hui un statut 200*. Trois routes voisines viennent pourtant de gagner un `200 + success:
false` (E-165, sur `/fail2ban/ban`, `/unban`, `/unban_all`). Le jour où `preflight_check` suit, cet
écran présentera des résultats partiels comme une vérification réussie.

---

## 1. ⚠ CE QUI EST FAUX AUJOURD'HUI — la phrase de tête de l'écran

`laravel/lang/fr/ssh.php:43` :

> « ATTENTION : aucun compte actif ne porte de cle SSH — **un deploiement ne deploierait rien** »

Et le commentaire du code qui la pose (`cles-ssh.js:210-212`) :

> *« ZERO COMPTE PORTEUR D'UNE CLE veut dire qu'un deploiement ne deploierait RIEN. C'est la moitie
> utile du constat »*

**Mesuré en base le 2026-08-27 : `users_with_keys = 0`.** Cette phrase s'affiche donc **maintenant**,
sur l'écran qui décide de K4.

### Elle est vraie du déploiement et fausse du GESTE

`configure_users` (`configure_servers.py:723-763`) fait **deux** choses, et la seconde ne dépend
d'aucune clé :

```python
for user in self.all_users:                       # 1. deployer — ne fait rien si personne n'a de cle
    if mid in user.get('allowed_servers', []): …
…
revoked = managed_users - authorized_names         # 2. REVOQUER — s'exécute quoi qu'il arrive
for uname in revoked:
    execute_command_as_root(channel, f"rm -f /home/{uname}/.ssh/authorized_keys", …)
    remove_from_sudoers(channel, uname, …)
```

> **« Ne déploierait rien » se lit « ne ferait rien ». C'est la moitié rassurante d'un constat dont
> l'autre moitié est destructrice.** Un déploiement lancé aujourd'hui, avec zéro compte porteur de
> clé, ne déploierait effectivement rien — **et supprimerait quand même les `authorized_keys` de
> `claude-agent` et de `Timikana` sur `srv-zabbix`** (mesure : `AUDIT-RELECTURE-E183.md`, addendum
> §C).

Ce n'est pas un texte approximatif : c'est la **seule** phrase de synthèse que l'écran met en avant,
en `rw-annonce--echec`, au moment de décider. Et elle est jointe à `verif_pret` — « Aucun prerequis
manquant » — par un tiret.

### Correctif proposé

La phrase doit dire ce qu'elle constate **et ce qu'elle ne constate pas** :

```php
'cles_aucune' => "ATTENTION : aucun compte actif ne porte de cle SSH — un deploiement "
    . "n'installerait aucune cle. Il REVOQUERAIT malgre tout les acces listes ci-dessous, "
    . "s'il y en a : la revocation ne depend pas des cles.",
```

Parité FR/EN dans le même commit. **Ce que ça casserait : rien** — aucune suite ne teste cette
chaîne (vérifié : `cles_aucune` n'apparaît dans aucun fichier de `tests/e2e/`).

---

## 2. ⚠ « JE N'AI PAS PU REGARDER » RENDU COMME « IL N'Y A RIEN » — la forme d'E-183, sur cet écran

C'est la constante la plus dangereuse des cinq, parce qu'elle porte sur **la ligne que le module
appelle lui-même la plus importante**.

### Le champ peut être absent, et son absence est silencieuse

`users_revoked`, `users_to_create` et `user_impact` ne sont posés **que** dans un bloc `try` imbriqué
(`ssh.py:446-487`), lui-même **à l'intérieur** du `try` de la session SSH. Deux chemins les laissent
absents :

1. la connexion SSH échoue → on n'atteint jamais l'audit d'inventaire ;
2. l'audit d'inventaire lève → `except Exception as ex: logger.warning(…)`. **Rien n'est ajouté à
   `result['errors']`**, et `result['ssh_ok']` vaut déjà `True`.

Côté écran, `listeNommee` (`cles-ssh.js:113`) :

```js
function listeNommee(parent, titre, noms, classe) {
    if (!noms || noms.length === 0) return;   // <- sort en SILENCE
```

**Un champ absent et une liste vide produisent exactement le même écran : rien.**

### Le rendu composite, sur le second chemin

| ce que l'écran montre | d'où ça vient |
|---|---|
| badge **OK** | `ssh_ok = True` — la connexion a bien eu lieu |
| **aucune** erreur | l'`except` de l'audit n'écrit pas dans `errors` |
| **aucune** liste « Accès qui seront RÉVOQUÉS » | `listeNommee` sort en silence |
| synthèse : « Aucun prerequis manquant » | `bloquantes === 0` |

> **Une machine dont l'inventaire n'a pas pu être lu est présentée comme vérifiée et sans
> révocation à prévoir.** C'est exactement la classe d'E-183 — « je n'ai rien vu » signifiant « il
> n'y a rien » — déplacée de la base de données vers l'écran de décision.

### Correctif proposé, en deux moitiés qui vont ensemble

**Backend** — l'audit d'inventaire doit dire qu'il a échoué, au lieu d'être seulement journalisé :

```python
                except Exception as ex:
                    logger.warning("Preflight inventory audit (%s): %s", m['name'], ex)
                    # E-189 bis : l'absence de `users_revoked` est INDISCERNABLE
                    # d'une liste vide cote ecran. « Je n'ai pas pu regarder »
                    # doit se dire, sinon il se lit « il n'y a rien a revoquer ».
                    result['errors'].append(
                        "Inventaire des comptes illisible : la liste des acces revoques "
                        "n'a PAS pu etre etablie pour cette machine.")
                    result['inventaire_lu'] = False
```

et poser `result['inventaire_lu'] = True` sur le chemin nominal.

**Écran** — distinguer les trois états au lieu de deux : *lu et vide*, *lu et non vide*, *non lu*.
Aujourd'hui `listeNommee` n'en connaît que deux, et fait tomber le troisième dans le premier.

**Ce que ça casserait :** une machine dont l'audit échoue passerait de « prête » à « bloquante ».
C'est le comportement voulu, et c'est **la même asymétrie déjà arbitrée pour E-183** : au pire on
refuse un déploiement légitime, ce qui se corrige au geste suivant ; sans cela, on en autorise un sur
une information qu'on n'a pas.

---

## 3. Les deux différences d'ensembles ne portent PAS sur les mêmes opérandes

Le préflight **calcule lui-même** la révocation qu'annoncera le déploiement — deux implémentations de
la même règle, dans deux fichiers, en deux langages de requête :

| | opérande « autorisés » | filtre `active` |
|---|---|---|
| **préflight** `ssh.py:459-464` | `SELECT u.name … JOIN user_machine_access … WHERE machine_id = %s **AND u.active = 1**` | **oui** |
| **déploiement** `configure_servers.py:735-737` | `for user in self.all_users: if mid in user.get('allowed_servers', [])` | **non** |

**Et la fonction VOISINE du même fichier filtre, elle** — `cleanup_users`,
`configure_servers.py:658-661` : `… and user['active']`. Deux fonctions du même fichier traitent la
même notion différemment, sans qu'aucun commentaire ne le dise.

### Le sens de l'écart, et il dédouane — pour l'instant

`autorisés_préflight ⊆ autorisés_déploiement`, donc `révoqués_préflight ⊇ révoqués_déploiement` :
**le préflight sur-annonce, il ne sous-annonce jamais.** C'est la bonne direction.

**Mais elle est accidentelle**, et deux choses la rendent fragile :

- rien n'écrit que les deux ensembles doivent coïncider, ni dans quel sens ils peuvent diverger ;
- **il suffirait d'ajouter un filtre au préflight que le déploiement n'a pas** pour inverser
  l'inclusion — et le préflight deviendrait alors un écran qui **sous-annonce** ce qui va être
  détruit.

**Mesuré : 0 compte inactif dans le parc aujourd'hui.** L'écart n'a donc **aucun porteur**, et je le
dis aussi nettement que le reste. Le correctif juste n'est pas d'aligner les deux copies mais de
**n'en garder qu'une** — *« une règle appliquée ailleurs se remonte de là et s'affiche ; on ne la
recalcule jamais »*, la leçon déjà écrite pour `maintenance/`.

---

## 4. Deux constantes de moindre gravité, dites pour être complètes

### 4.1 `d.results` absent rend un écran « prêt » vide

```js
const resultats = d.results || [];
const bloquantes = resultats.filter((r) => (r.errors || []).length > 0).length;
```

`results` absent → `resultats = []` → `bloquantes = 0` → **« Aucun prerequis manquant »**, avec zéro
machine affichée. C'est E-189 vu par son effet : le jour où la route rend `200 + success:false` sans
`results`, l'écran annonce que tout est prêt. **Lire `d.success` ferme les deux.**

### 4.2 Une machine absente de `results` n'est comptée nulle part

`preflight_check` fait `SELECT … WHERE id IN (…)` : un identifiant qui ne correspond à aucune ligne
ne produit **aucun** résultat, sans erreur. L'écran ne compare jamais `resultats.length` à
`cibles.length` — la machine disparaît, et `bloquantes` ne la compte ni comme bloquante ni comme
prête.

**Faible portée aujourd'hui** : `cibles` vient de cases à cocher réelles, donc d'identifiants qui
existent. C'est une fragilité, pas un trou — mais elle est de la même famille que les quatre autres :
**un ensemble plus petit que demandé, lu comme un ensemble complet.**

---

## 5. Le point positif, et il faut le préserver

Le Lead a raison et je le confirme par lecture : **`preflight_check` ne porte aucun décorateur
d'accès machine, et ce n'est pas un trou.** Il appelle `check_machine_access(mid)` dans une
**boucle**, sur chaque identifiant de la liste (`ssh.py:342-345`), et **refuse en 403 dès le
premier** qui échoue. Un décorateur ne saurait pas faire cela : `require_machine_access` lit bien
`machine_ids`/`server_ids`, mais cette route reçoit `machines` — un **troisième** nom, qu'aucune
version du décorateur ne lit.

> C'est la première garde absente du chantier qui soit absente **pour une bonne raison**, après
> cinquante-sept présentes pour rien. Et c'est le contrôle **en corps** qui travaille, sur l'objet
> réellement visé — exactement ce que la leçon « un garde sans objet ne garde rien » demande.

**À ne pas « corriger » : ajouter le décorateur serait inerte** (il ne lit pas `machines`) et
donnerait l'apparence d'une protection que le corps assure déjà seul.

---

## 6. Récapitulatif — ce que la chaîne tient pour constant

| # | ce qui est tenu pour constant | vrai aujourd'hui ? | gravité |
|---|---|---|---|
| 1 | « zéro clé » ⇒ « le déploiement ne fait rien » | **NON — faux, et affiché maintenant** | **haute** |
| 2 | `users_revoked` absent ⇔ rien à révoquer | oui, par coïncidence (l'audit n'échoue pas) | **haute** |
| 3 | les deux différences d'ensembles s'accordent | oui — 0 compte inactif | moyenne |
| 4 | `d.success` est toujours `true` sur un 200 | oui — E-189, la coïncidence nommée par le Lead | moyenne |
| 5 | `results` couvre toutes les machines demandées | oui — les cibles viennent de cases réelles | faible |

**Les cinq sont la même faute** : *un ensemble ou un constat partiel lu comme complet*. Et sur cet
écran précis, la conséquence n'est pas un affichage faux — c'est un **arbitrage pris sur une
information qu'on croit avoir**.

## 7. Ce que je n'ai pas mesuré

- **je n'ai pas exécuté le préflight**, ni contre `Test-Server-Debian` ni contre quoi que ce soit :
  la route ouvre des sessions SSH réelles. Tout ce qui précède est établi par lecture et par mesure
  **en base** ;
- **je n'ai pas vérifié que `remove_from_sudoers` lit son code de retour** — signalé au passage dans
  la relecture d'E-183, toujours non fait ;
- **je n'ai pas relu le chemin de déploiement lui-même** (`/deploy`, `ssh.py:246`), seulement le
  préflight et son écran. La question portait sur la chaîne de **décision** ; le geste n'est pas
  dédouané, il n'est pas mesuré.

## 8. Recommandation

| # | geste | urgence |
|---|---|---|
| 1 | corriger `cles_aucune` FR/EN (§1) — **la phrase est fausse en service** | **haute**, et sans risque |
| 2 | faire dire à l'audit d'inventaire qu'il a échoué (§2), backend **et** écran | **haute** |
| 3 | lire `d.success` (E-189) — ferme aussi §4.1 | moyenne |
| 4 | n'avoir qu'une seule implémentation de la règle de révocation (§3) | moyenne |

**Et le geste qui les rend tous secondaires reste celui déjà proposé** : que le préflight **nomme**
ce qu'il va révoquer avant que le déploiement ne parte. Il le calcule déjà, il l'affiche déjà — il
faut seulement qu'il ne puisse pas se taire quand il n'a pas su regarder.
