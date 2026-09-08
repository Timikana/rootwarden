# ATTESTATION — un seul chemin d'application (`be5a30ef`, `211afd37`)

    Session   5 — securite. Attestation INDEPENDANTE : je n'ai ecrit ni le
              correctif ni ses tests.
    Mesure    2026-09-07, statique. Aucune requete, aucune machine jointe.
    Verdict   ✅ les quatre proprietes tiennent — ET deux angles morts,
              tous deux du meme cote.

---

## 1. Les quatre propriétés — ATTESTÉES

### ① Les quatre routes passent bien par le délégué

*Le comptage d'un `INSERT` unique ne prouve qu'un chemin, pas quatre passages.*
**J'ai donc mesuré les sites d'appel, pas l'unicité :**

```
_archive_puis_applique     appele en  :167  (/iptables action=apply)
                                      :228  (/iptables-apply)
                                      :268  (/iptables-restore)
                                      :365  (/iptables-rollback)
apply_iptables_rules(      1 seule occurrence   -> :138, DANS le delegue
INSERT INTO iptables_history  1 seule (code)    -> :123, DANS le delegue
```

**Quatre portes, un chemin, et le seul point d'application est en aval de
l'archivage.** ✔

### ② C'est l'état QUITTÉ qui est archivé

`get_iptables_rules(client, …)` lit **la machine** avant `apply_iptables_rules`.
*Sur `rollback`, c'est donc l'état d'où l'on part.* ✔

**Et les tests l'asservissent par le CONTENU, pas par le compte** :
`assert inserts[0][1] == self.ETAT_COURANT`, avec le message qui nomme le défaut
inverse. *Un `assert len(inserts) == 1` seul aurait laissé passer l'archivage de
l'état restauré.* ✔

### ③ Une version vide n'est jamais archivée

`if ancien_v4.strip():` … `else: logger.warning(…)`. ✔

### ④ Le témoin positif existe

`assert len(appliques) == 1, "le harnais n'a vu aucune application"`. **Sans lui,
« zéro archive » et « zéro mesure » rendraient la même sortie.** ✔

*Les deux call sites explicites passent bien `rules_v4` ET `rules_v6` — la
lecture par défaut ne peut pas laisser `rules_v6` à `None`.* ✔

---

## 2. ⚠ ANGLE MORT — l'échec d'archivage est INVISIBLE À L'APPELANT

```python
except Exception as hist_err:
    logger.warning("Iptables history save failed: %s", hist_err)
apply_iptables_rules(client, root_password, rules_v4, rules_v6)
return jsonify({"success": True, "message": message})
```

**Si la base est injoignable, l'archivage échoue, l'application a LIEU, et la
réponse est OCTET POUR OCTET celle du succès.** *Aucun champ d'archivage dans
aucune réponse du fichier — mesuré.* **Et aucun test ne couvre ce chemin.**

> ⛔ **C'est le défaut que ce correctif a été écrit pour fermer, atteignable par
> un hoquet de la base.** *Son propre docblock le dit :* « une archive avec un
> trou est plus dangereuse qu'une archive absente : l'absence se voit, **le trou
> se lit comme une continuité** ». **Le chemin d'exception fabrique exactement un
> tel trou, en silence.**

**Et c'est sur `rollback` que ça coûte le plus** : *la route dont tout l'argument
est « elle est réversible ».* **Un rollback dont l'archivage a échoué redevient
une porte à sens unique — et l'écran annonce « Regles restaurees ».**

*Le choix de ne pas bloquer l'application est défendable — disponibilité contre
traçabilité. **Ce qui ne l'est pas, c'est que l'appelant ne puisse pas le
savoir.*** **Un `archive: false` dans la réponse suffirait ; c'est un champ, pas
une refonte.**

---

## 3. ⚠ ANGLE MORT SECONDAIRE — la garde de vacuité est par CONVENTION

```python
if rules_v4 is None:              # <- la garde de vacuite est SOUS cette condition
    rules_v4 = data.get('rules_v4')
    rules_v6 = data.get('rules_v6')
    if not rules_v4:
        return jsonify({... "Regles IPv4 manquantes."}), 400
```

**Un appelant qui passe `rules_v4=''` EXPLICITEMENT saute le contrôle de vacuité
et applique un jeu vide** — *ce qui viderait le pare-feu de la machine.*

**Les deux appelants actuels contrôlent en amont** (409 « Copie enregistree vide »
et « Version vide »). ✔ *Donc le défaut n'est pas atteignable aujourd'hui.*

> **Mais c'est une garde par CONVENTION, pas par CONSTRUCTION** — la même forme
> que `dest_path` en SEC-015. *Une cinquième porte ajoutée plus tard ne serait
> forcée par rien.* **Un `if not (rules_v4 or '').strip(): return 400` en tête du
> délégué le rendrait inexprimable.**

---

## 4. Ce que cette attestation confirme de la MÉTHODE

**Le fait le plus instructif du lot n'est pas l'archive** : *le premier jet levait
`NameError` sur les deux portes, et 672 tests restaient verts.* **Seize
touchaient `iptables` — les gardes, les paramètres absents. Le chemin nominal
n'était joué par personne.**

> **La couverture ne manquait pas : elle regardait ailleurs.** *« Les tests
> passent » ne dit rien tant qu'on ne sait pas ce qui reste vert quand on casse.*

**Les tests ajoutés corrigent précisément cela** — ils exercent le chemin
nominal, portent leur témoin positif, et asservissent le CONTENU de l'archive.
*C'est la bonne forme, et je l'atteste comme telle.*

---

## 5. Bornes de cette attestation

    STATIQUE      lecture du code et des tests. Je n'ai execute NI le service,
                  NI la suite — pytest lit le disque, le service execute encore
                  l'ancien code (process demarre a 14:53, commits a 23:44 et 00:0x).
    NON EXERCE    aucune requete vers les quatre routes, aucune machine jointe,
                  aucune regle appliquee.
    NON MESURE    si un compte reel emprunte l'une de ces routes aujourd'hui —
                  les quatre voies d'acces a la base me sont fermees.

**Ce que j'atteste : le code sur le DISQUE porte les quatre propriétés.**
*Ce qu'aucune lecture ne peut attester : que le service les exécute — cela
demande la recréation du conteneur, et elle appartient à l'exploitant.*
