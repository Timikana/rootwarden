# Les routes au `success` calculé — atteignabilité mesurée

Session 4, **2026-08-28**. Question posée : *parmi les 20 routes `conditionnel`, combien rendent
`200 + success:false` sur un chemin qu'un appelant peut atteindre ?*

---

## 1. ⚠ ELLES SONT 21, ET LA VINGT-ET-UNIÈME EST DE MOI

Le classificateur de la session 6 rejoué sur l'arbre actuel donne **21**, pas 20. L'écart est
`/sshd_allow_user`, qui rendait `'success': True` **en dur** et rend désormais `'success': atteste`
depuis **E-214, ce soir**.

> **Mon correctif a ajouté une route à cette famille**, et c'est exactement ce que la session 6 avait
> annoncé quelques heures plus tôt : *« quand tu fais rendre `200 + success:false` à une route qui
> rendait toujours `true`, tu changes un contrat. »* Sa liste figée est donc périmée d'une entrée,
> **dans le sens qu'elle avait prédit**.

C'est un cas où deux mesures justes divergent sans qu'aucune soit fausse : elles décrivent deux états
du dépôt à quelques heures d'intervalle. *Un inventaire daté n'est pas un inventaire faux — mais il
doit porter sa date.*

---

## 2. La réponse : **20 sur 21 sont atteignables**

Leur `success` dépend d'un code de retour, d'un compte, ou d'un état distant — tous obtenus au moment
de la requête :

| forme du verdict | routes | le faux survient quand |
|---|---|---|
| `rc == 0` / `code == 0` | 8 | la commande distante échoue |
| `all_ok` / `all(...)` | 4 | une machine du lot échoue |
| `ok == len(results) and len(results) > 0` | 2 | échec partiel **ou lot vide** |
| `deleted > 0` | 2 | le nom visé n'existe pas |
| `restart_ok and syntax_ok` | 1 | configuration refusée |
| `atteste` | 1 | `sshd -T` ne confirme pas l'effet (**E-214**) |
| `ok`, `success` | 2 | connexion refusée / installation échouée |

**Aucune n'est structurellement inatteignable — sauf une.**

## 3. ⚠ LA VINGT-ET-UNIÈME EST INATTEIGNABLE, ET ELLE LE DOIT À UN DÉFAUT

`/wazuh/install_all` ne rend **jamais** son `jsonify` : sa requête porte `AND a.id IS NULL` sur une
table sans colonne `id`, l'`execute()` n'est protégé par aucun `try`, et la route **rend 500 avant
d'atteindre son verdict**.

> **Elle redeviendra atteignable au moment exact où E-224 sera corrigé.** Troisième occurrence du
> motif : *un défaut qui protège par accident cesse de protéger quand on le corrige.*

C'est un argument de plus pour la borne proposée en `528cbe0` : le correctif d'E-224 n'ouvre pas
seulement une route de parc vers la production, **il ouvre aussi un verdict `200 + success:false` que
personne n'a jamais vu se produire.**

---

## 4. Une note, et je la donne comme une note et non comme un défaut

`/fail2ban/install` calcule :

```python
success = rc == 0 or 'is already the newest version' in out
```

La commande sous-jacente pose `DEBIAN_FRONTEND=noninteractive` **mais pas `LC_ALL`**, alors que ses
homologues de `updates.py` posent `LC_ALL=C.UTF-8 LANG=C.UTF-8`. La sous-chaîne est donc
**dépendante de la locale** du serveur distant.

**Ce n'est pas un défaut aujourd'hui** : `apt-get install -y` rend `rc = 0` quand le paquet est déjà
installé, donc le premier terme du `or` couvre déjà ce cas et la sous-chaîne est un filet redondant.
**Elle le deviendrait le jour où ce second terme porterait seul un verdict.**

Ce qui mérite d'être signalé, c'est **l'incohérence avec les commandes voisines** — même famille que
les cinq `_resolve_ssh_creds` : des copies d'accord entre elles jusqu'à ce que l'une bouge.

---

## 5. Ce que cette mesure ne dit pas

Elle mesure **l'atteignabilité du faux**, pas le **danger**. Un `200 + success:false` n'est dangereux
que si un appelant ne lit pas le verdict — et **cette moitié-là a déjà été mesurée par la session 6** :
71 % de couverture appelant → route, **aucun appelant à risque**, annoncé comme un dédouanement sur
71 % et non comme un « zéro défaut ».

**Les deux mesures ensemble disent : la famille est nombreuse et lisible, pas silencieuse.** Ce n'est
pas le cas de `remove_user_keys` avant E-215, qui rendait `success: True` **sans jamais calculer quoi
que ce soit**.
