# SEC-017 — `apply_iptables_rules()` annonce un succès qu'elle n'a pas vérifié

    Session   5 — securite, LECTURE SEULE. `backend/` n'est pas mon perimetre.
    Mesure    2026-09-08. Rien exerce, aucune machine jointe.
    Origine   une phrase que j'avais ecrite en passant ; `94` l'a etendue,
              et ma verification l'etend encore.

---

## SEC-017

    GRAVITE    ELEVEE — pas une elevation, mais une REUSSITE FAUSSE sur le
               geste le plus destructeur du produit
    SURFACE    backend/iptables_manager.py::apply_iptables_rules()
               en aval des QUATRE routes qui appliquent des regles

### PRÉCONDITIONS EXACTES

**Aucune.** *Le défaut est dans le chemin nominal. Il suffit qu'`iptables-restore`
rende un code non nul — jeu illisible, module noyau absent, `iptables` de la
machine changé depuis l'archivage.*

### LE DÉFAUT — trois étages, et le troisième est le pire

**⚠ Cité par son TEXTE, pas par sa ligne** — *voir §5 : mes premières citations
étaient périmées vingt minutes après publication.*

```
touch {path} && chmod 640 {path}                   valeur JETEE
_write_rules_safe(… "/etc/iptables/rules.v4")      ← le fichier de DEMARRAGE est ecrit
execute_as_root(… "iptables-restore < …")          valeur JETEE
execute_as_root(… "ip6tables-restore < …")         valeur JETEE
_log.info("Règles iptables appliquées avec succès.")   ⛔ INCONDITIONNEL
except Exception                                    → ne rattrape que du PYTHON
```

*Lignes `183` · `187` · `189` · `190` **à `d1fb406b` (2026-09-08 11:41:42)**. Elles
bougent ; le texte, non.*

**Remesure :**

```
grep -nE "iptables-restore <|appliquées avec succès" backend/iptables_manager.py
grep -cE "\bcode\b" backend/iptables_manager.py        # attendu : 0
```

**`execute_as_root()` rend `(sortie, erreur, CODE)` — `ssh_utils.py:559` et `:586`.
Le code de sortie est disponible et il est jeté.**

> ⛔ **Enchaînement : le fichier de démarrage est écrasé · le chargement échoue ·
> personne ne regarde · la fonction journalise un SUCCÈS · la route rend
> `{"success": true}` · l'opérateur lit « Règles appliquées ».**
>
> **Le noyau garde ses anciennes règles : la machine a l'air SAINE.**

**Et le défaut se manifeste AU PROCHAIN REDÉMARRAGE**, sur un jeu qui ne charge
pas — *sans rien qui relie l'incident à un changement fait des semaines plus tôt.*

### UN COMPTE RÉEL L'OCCUPE-T-IL AUJOURD'HUI ?

**Non mesurable, et pour une raison qui aggrave le défaut :** *un échec de
chargement ne laisse aucune trace distincte d'un succès.* **Le journal dit
« succès » dans les deux cas. Il n'y a rien à chercher.**

*Les quatre voies d'accès à la base me sont fermées ; mais même avec elles, la
table `iptables_history` enregistre l'état QUITTÉ, pas le résultat du
chargement.*

---

## ⚠ CORRECTION DE L'ARGUMENT QUI M'A ÉTÉ TRANSMIS

**On m'a écrit** : *« 5 appels à `execute_as_root` inspectent leur code, 4 le
jettent — ce n'est pas une convention du dépôt, c'est une exception locale. Le
fichier sait faire. »*

**Mesuré, c'est faux, et dans le sens qui compte :**

```
valeur AFFECTEE  4   :89 :90 :92 :94   ->  `rules_v4, _, _ = …`  la SORTIE, le code jete
valeur JETEE     4   :147 :176 :179 :183
appels qui INSPECTENT le CODE de sortie   ->  0
   temoin : `if code`, `code != 0`, `code == 0` dans ce fichier  ->  AUCUNE occurrence
```

> **Les quatre « inspectants » lisent `stdout` et jettent le code par `_, _`.
> AUCUN appel de ce fichier n'a jamais regardé un code de sortie.**

**Ce n'est donc pas une exception locale : c'est uniforme.** *Et la conséquence
pratique s'inverse — **il n'y a aucun motif correct à recopier dans ce fichier.**
Le traitement juste doit être introduit, pas imité.*

---

## LA FORME SÛRE — proposée, non écrite

```
1. ecrire dans un fichier TEMPORAIRE
2. `iptables-restore --test <temp>`   ->  INSPECTER le code
3. si 0 seulement : deplacer temp -> /etc/iptables/rules.v4, puis charger
4. inspecter CE code aussi ; ne journaliser un succes que s'il vaut 0,
   et rendre l'echec a l'appelant
```

**Ça rend la classe inoffensive** : *le fichier de démarrage n'est jamais
empoisonné, et un échec est rapporté.* **`--test` existe déjà — c'est ce
qu'emploie `/iptables-validate`.**

### ⛔ POURQUOI PERSONNE NE L'ÉCRIT

    `backend/` n'est pas mon perimetre.
    L'eprouver demanderait d'appliquer un jeu de regles sur une machine reelle.
    Une correction NON EPROUVEE sur ce chemin est pire que le defaut : le
      defaut, lui, est connu et borne.

**C'est une décision de l'exploitant, sur un chemin vivant qui écrit en root.**

---

## ⚠ ET CE QUE ÇA FAIT À MON PROPRE CORRECTIF (`09cd2c41`)

**Ma validation côté écran attrape la cause la plus probable — un jeu illisible —
AVANT l'envoi. Elle réduit donc la fréquence de SEC-017 sans le fermer.**

> ⛔ **Et elle le rend plus difficile à soupçonner.** *« On valide maintenant,
> donc un succès annoncé est un vrai succès » sera un raisonnement naturel, et
> faux.*

**Une garde partielle en amont d'un échec silencieux en aval déplace le défaut
vers le haut de l'échelle de surprise.** *Ce n'est pas une raison de retirer ma
validation — c'en est une de ne pas laisser SEC-017 ouvert derrière elle.*


---

## 5. ⚠ MES PROPRES CITATIONS ÉTAIENT PÉRIMÉES EN VINGT MINUTES

**Ce document citait `:178`, `:179`, `:183`, `:185`, `:186`. Les lignes réelles
sont `182`, `183`, `187`, `189`, `190`.**

```
e64792dd   2026-09-08 ~11:2x   publication de SEC-017, citant :178/:179/:185
d1fb406b   2026-09-08 11:41:42 ci(semgrep) — AJOUTE 4 lignes de commentaire
                               (un `nosemgrep` motive, +4 sur tout ce qui suit)
```

**Le défaut est INTACT** — `d1fb406b` n'a ajouté qu'un commentaire justifié.
*Vérifié : les deux `restore` jettent toujours leur valeur, le succès est
toujours inconditionnel, et le mot `code` reste à **zéro** occurrence.*

> ⛔ **Mais un constat de sécurité dont toute la valeur est qu'on retrouve le
> code citait des lignes fausses vingt minutes après sa publication.**

**TROISIÈME fois sur ce chantier que ma propre mesure se périme dans l'heure** —
*8 minutes, 76 minutes, 20 minutes.* **Ce n'est plus un accident, c'est le
régime : huit sessions écrivent, et un numéro de ligne est la donnée la plus
volatile qu'un audit puisse contenir.**

**Corrigé par la forme, pas par la vigilance** : *le défaut est désormais cité par
son TEXTE — qui ne bouge pas — la ligne n'est donnée qu'avec le commit qui
l'ancre, et la commande de remesure est écrite à côté.* **C'est la règle du
chantier (« chaque chiffre porte sa commande de remesure ») appliquée à un chiffre
que je n'avais pas vu comme un chiffre.**
