# DOSSIER 06 — Appliquer la migration d'E-222

**Pour signature de l'exploitant.** Préparé par la session 8 le **2026-08-28**.
La décision d'**écrire** la migration est déléguée et prise (`DECISIONS-DSI.md` §7). **Celle de
l'appliquer ne l'est pas** : c'est le schéma de production.

---

## 1. Recommandation

**Appliquer — et tôt.** C'est le seul dossier de la série dont l'urgence vienne d'une **fenêtre qui se
ferme** plutôt que d'un risque qui grandit.

**Et l'appliquer AVEC l'`UPSERT`, pas avant.** La contrainte seule ne referme pas E-222 ; elle rend
seulement l'`UPSERT` possible.

---

## 2. Conséquence, mesurée

### La fenêtre

    SELECT COUNT(*) AS lignes, COUNT(DISTINCT server_id) FROM iptables_rules   ->  0, 0
    SHOW INDEX FROM iptables_rules   ->  PRIMARY(id) + `server_id` (Non_unique = 1)

**La table est vide.** Poser une contrainte d'unicité sur une table vide ne peut pas échouer sur des
données existantes, ne demande aucune reprise, ne verrouille rien de significatif. **C'est le moment le
moins coûteux de l'histoire du produit** — et il dure jusqu'à la **première copie de règles
enregistrée**, c'est-à-dire jusqu'au premier usage de la page que la session 5 est en train de porter
(I1→I5).

> **Après la première ligne, la même migration devient une opération à risque** : il faudra d'abord
> établir qu'aucun `server_id` n'est dupliqué, et si l'un l'est, **décider laquelle des deux copies de
> règles de pare-feu on détruit.** *Une contrainte posée sur une table vide est une décision technique ;
> posée sur une table peuplée, c'est un arbitrage sur des données.*

### Le défaut qu'elle referme, et celui qu'elle ne referme pas

E-222 a **deux bouts, qui sont un seul défaut** :

| bout | ce qui se passe | probabilité |
|---|---|---|
| pas d'`UNIQUE` | deux lignes pour une machine ⇒ la lecture (`SELECT … WHERE server_id = ?`, **ni `ORDER BY` ni `LIMIT`**) rend une ligne **indéterminée** | **faible** — demande un entrelacement concurrent |
| `DELETE` puis `INSERT` **sans transaction** | si l'`INSERT` échoue après un `DELETE` réussi, **la copie est perdue** — il n'en reste aucune | **c'est le cas probable** |

Et l'écran annonce alors *« Erreur lors de la sauvegarde des règles »* — **exact sur l'écriture qui a
échoué, muet sur la destruction qui a réussi.**

> **Un « enregistrer » qui détruit avant d'écrire, sans transaction, n'est pas une sauvegarde risquée :
> c'est une suppression suivie d'une tentative.** *Le message décrit le geste qui a échoué, jamais celui
> qui a réussi.*

**L'absence d'`UNIQUE` est la cause de la FORME** — pas d'`UPSERT` possible sans elle, le commentaire du
code le dit lui-même. **Poser la contrainte sans écrire l'`UPSERT` ne referme donc rien** : le
`DELETE`/`INSERT` reste, et le cas probable avec lui.

### Ce que le portage a déjà fait, et qui ne remplace pas la migration

**I2 est livré** : la lecture prend la ligne **la plus récente** et **annonce s'il y en a plusieurs**,
au lieu de lire une ligne indéterminée en silence. **C'est une mitigation d'affichage, pas une
correction** — elle rend le désordre visible, elle ne l'empêche pas, et elle ne dit rien du cas
probable.

---

## 3. Le geste exact

**La migration, écrite par la session 4** (`mysql/migrations/` est son périmètre). Forme imposée par
trois contraintes du dépôt — idempotence (le runner tolère `1061`), `ALTER TABLE` **à plat**, et
**aucun `;` nulle part, commentaires compris** (le runner découpe sur `;` **avant** de retirer les
commentaires ; un `;` dans un en-tête a déjà coupé la migration 062 en deux) :

```sql
-- 063 contrainte d unicite sur iptables_rules
-- une seule copie de regles par machine, prealable a l UPSERT
ALTER TABLE iptables_rules ADD UNIQUE KEY uq_iptables_rules_server (server_id)
```

**L'index non unique existant n'est pas supprimé** : il devient redondant, et le retirer demanderait de
vérifier que la clé étrangère trouve un autre index. *Sur une table vide, le gain est nul et le risque
ne l'est pas.*

**L'`UPSERT`, dans le même lot** — `legacy/iptables/index.php:142-151` :

```
remplacer   DELETE FROM iptables_rules WHERE server_id = ?
            INSERT INTO iptables_rules (server_id, rules_v4, rules_v6) VALUES (?, ?, ?)

par         INSERT INTO iptables_rules (server_id, rules_v4, rules_v6) VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE rules_v4 = VALUES(rules_v4), rules_v6 = VALUES(rules_v6)
```

**⚠ Ce fichier est du `legacy/`, relu à CHAQUE requête** — donc pas d'écriture pendant un rejeu, et le
jeton de banc s'applique.

**L'application, geste de l'exploitant :**

```bash
# controle AVANT : la fenetre est-elle encore ouverte ?
#   la table doit etre VIDE, ou sans server_id duplique
SELECT server_id, COUNT(*) FROM iptables_rules GROUP BY server_id HAVING COUNT(*) > 1

# puis le runner de migrations
sudo -n docker exec rootwarden_python sh -c "cd /app && python db_migrate.py"

# controle APRES
SHOW INDEX FROM iptables_rules      -- uq_iptables_rules_server, Non_unique = 0
```

**État du runner, mesuré : 62 fichiers de migration, 62 appliquées, aucune en attente.** Cette
migration serait donc la **seule** du lot — elle ne traîne rien d'autre derrière elle. C'est ce qui rend
son application peu coûteuse à contrôler.

---

## 4. Ce qui se passe si on ne fait rien

**À court terme : rien, et c'est trompeur.** La table est vide, personne n'enregistre de copie de
règles, aucun porteur n'existe. *Une propriété qui tient par l'état du parc n'est pas une propriété.*

**Au premier enregistrement d'une copie de règles** — c'est-à-dire dès qu'un exploitant se sert de la
page que la session 5 achève :

1. **la fenêtre se ferme.** La migration cesse d'être gratuite et devient un arbitrage sur des données ;
2. **le cas probable s'ouvre** : un `INSERT` qui échoue après un `DELETE` réussi laisse la machine
   **sans aucune copie de ses règles de pare-feu**, et l'écran dit « erreur lors de la sauvegarde »,
   ce qui se lit « rien n'a changé » ;
3. **et le cas improbable devient atteignable** : deux enregistrements concurrents sur la même machine
   laissent deux lignes, et la lecture en rend une **indéterminée**. I2 l'annonce désormais — mais
   *annoncer un désordre n'est pas l'empêcher, et l'exploitant devra alors choisir lequel de ses deux
   jeux de règles est le bon.*

> **L'objet sauvegardé est une configuration de pare-feu.** C'est la donnée dont la perte se découvre
> au moment où l'on veut la restaurer, c'est-à-dire au pire moment. *Le coût de l'inaction n'est pas
> le défaut : c'est que la fenêtre pour le corriger sans arbitrage se referme au premier usage
> légitime de la fonctionnalité qu'on vient de porter.*

---

## Ce qui n'est pas mesuré

- **le comportement du runner sur cette migration précise.** Elle n'est pas écrite ; la forme proposée
  suit les trois contraintes connues, elle n'a pas été exécutée ;
- **si `ON DUPLICATE KEY UPDATE` convient à tous les appelants** de la table — un seul chemin d'écriture
  a été lu (`legacy/iptables/index.php`), le portage I2 n'a pas été relu pour ce point ;
- **la borne des colonnes** : `TEXT` tient 65 535 **octets** et **MySQL tronque en silence** en mode
  permissif. I2 contrôle la borne avant l'écriture ; le chemin legacy n'a pas été vérifié sur ce point.
