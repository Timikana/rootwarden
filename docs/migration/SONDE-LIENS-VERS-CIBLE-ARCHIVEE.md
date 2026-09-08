# SONDE — quels appelants SERVIS dépendent d'une cible ARCHIVÉE ?

    Session   5 — sécurité. LECTURE SEULE.
    Mesure    2026-09-07, sur l'arbre courant
    Origine   `showNotification` — 12 appels vers un conteneur qui vit
              dans `legacy/_deprecated/`. Personne n'a eu tort en les
              écrivant : le tort est né d'un archivage, ailleurs, en silence.

> **L'étage 2 archivera vingt-deux fichiers d'un coup. Cette sonde est ce qui
> rendra ce jour-là MESURABLE au lieu de DÉCOUVRABLE.**

---

## 1. Résultat

```
(3) TEMOIN POSITIF — cibles VIVANTES              537
(1) CIBLE ARCHIVEE ou SUPPRIMEE (lien mort)         0
(1) CIBLE QUI N'A JAMAIS EXISTE                     0
VERDICT                              mesure effectuee
```

**Aucun lien mort par archivage aujourd'hui, sur l'espèce que cet instrument
voit.** *Le témoin à 537 dit que l'instrument regarde ; sans lui, ce zéro serait
indistinguable d'une sonde cassée.*

---

## 2. ⛔ CE QU'ELLE NE VOIT PAS — et le cas qui l'a inspirée en fait partie

    VU      require / require_once / include / include_once, chemin litteral

    AVEUGLE fetch() / hx-post vers une ROUTE (pas un fichier)
            href rendu dynamiquement
            chemin construit par glob() ou concatenation
            ErrorDocument / rewrite dans .htaccess
            URL partie par COURRIEL — aucune trace dans le depot

> ⚠⚠ **`showNotification` N'EST PAS COUVERTE PAR CETTE SONDE.** *Ce n'est pas une
> dépendance de FICHIER : c'est une fonction JS qui dépend d'un ÉLÉMENT DU DOM
> (`#notifications`).* **L'instrument que le cas a inspiré ne voit pas le cas.**

**Le dire est la moitié de la livraison** : *son zéro parle d'une espèce, pas du
parc.* **Une seconde sonde est nécessaire pour les dépendances au DOM, et une
troisième pour les routes. Elles ne se remplacent pas.**

---

## 3. Les trois propriétés, posées AVANT d'écrire

### ① Séparer « archivée » de « n'a jamais existé » — la même absence, deux causes opposées

**Le disque rend `absent` dans les deux cas. La distinction se DÉRIVE de `git`,
pas du système de fichiers :**

    la cible existe sous `legacy/_deprecated/`   -> ARCHIVEE
    absente du disque MAIS trace dans `git log`  -> supprimee ou deplacee
    absente ET aucune trace git                  -> n'a jamais existe a ce chemin

*Garde par DÉRIVATION, pas par contrôle : rien à maintenir à jour.*

### ② Déclarer les espèces vues — sinon le zéro est un zéro d'instrument

**La sortie IMPRIME les deux listes, à chaque exécution.** *Un lecteur ne peut
pas prendre ce zéro pour un zéro du parc, parce que l'instrument dit lui-même de
quoi il parle.*

### ③ Rendre le cas SAIN — le témoin positif

**Une sonde qui ne rend que des liens morts est indiscernable d'une sonde qui ne
trouve rien.** *Ici le témoin coûte zéro (c'est la majorité des cas) et prouve
tout.* **Le verdict est NON CONCLUANT si le témoin est à zéro — pas PASS.**

---

## 4. ⚠ LES DEUX DÉFAUTS QU'ELLE A EUS — la partie la plus utile de ce document

**Les deux ont produit un résultat PROPRE et FAUX. Aucun n'aurait été visible
sans le témoin.**

### 4.1 `/` initial : séparateur en PHP, RACINE ABSOLUE en `pathlib`

```php
require_once __DIR__ . '/../head.php';
```

```python
pathlib.Path("legacy/iptables") / "/../head.php"   ->   /../head.php   ->   /head.php
```

**Le `/` initial est un SÉPARATEUR pour la concaténation PHP et une RACINE pour
`pathlib`.** *Toutes les cibles se résolvaient hors du dépôt.* **Sortie :
`0 vivantes, 0 mortes, 0 jamais` — un zéro parfaitement propre.**

> **C'est le témoin ③ qui l'a attrapé, et lui seul** : *`0 vivante` a rendu
> `NON CONCLUANT` au lieu de « aucun lien mort ».* **Sans lui je publiais un
> parc sain mesuré par un instrument qui ne lisait rien.**

### 4.2 « Cité » n'est pas « appelé » — et j'ai commis ma propre règle

**Après correction, la sonde rendait DEUX cibles « qui n'ont jamais existé » :**

```
legacy/auth/step_up.php:12       -> auth/step_up.php
legacy/includes/howto_tip.php:10 -> legacy/includes/includes/howto_tip.php
```

**Les deux sont des lignes de DOCBLOCK qui montrent l'usage en exemple** (`*   require_once …`),
**et leurs cibles réelles sont bien VIVANTES.**

> ⚠ **J'ai écrit cette règle il y a deux jours, et je l'ai enfreinte dans
> l'instrument conçu pour éviter cette classe d'erreur.** *Deux trouvailles sur
> cinq cent quarante : l'ordre de grandeur est ce qui m'a fait regarder — c'est
> le dernier filet, pas le premier.*

**Le filtre de commentaires est désormais dans la sonde, avec son motif.**

---

## 5. Le script

*Il vit dans le répertoire de travail de la session, hors du dépôt : `scripts/`
n'est pas mon périmètre.* **Il est reproductible depuis ce document — les trois
propriétés et les deux défauts sont ce qui compte, pas les quarante lignes.**

**Pour qui le reprendra :**

- lire `MOTIF` **hors commentaires** (§4.2) ;
- `lstrip("/")` sur le fragment capturé (§4.1) ;
- **le verdict est NON CONCLUANT tant que le témoin est à zéro** ;
- et **imprimer les espèces aveugles** — sans elles, le zéro ment par omission.
