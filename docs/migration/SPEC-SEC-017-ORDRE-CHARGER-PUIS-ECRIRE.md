# SPEC — inverser l'ordre dans `apply_iptables_rules()` (SEC-017)

    Session   5 — securite. SPECIFICATION, pas correctif : `backend/` n'est
              pas mon perimetre d'ecriture.
    Mesure    2026-09-08. Rien exerce, aucune machine jointe.

---

## 1. ⛔ POURQUOI JE NE L'ÉCRIS PAS, ET LES DEUX RAISONS SONT DISTINCTES

### 1.1 Le périmètre

**Le mandat de l'exploitant dit : *« Tu proposes ; la session 3 (`laravel/`) ou 4
(`backend/`) applique. »*** *L'ouverture qui m'a été faite porte sur `iptables`
côté PORTAGE — c'est là que tout mon code de cette session a été écrit.*
**`backend/iptables_manager.py` est le module backend, et il a un titulaire.**

### 1.2 Et la raison de fond, qui vaut même si le périmètre s'ouvrait

**« Les `.py` sont lus au DÉMARRAGE, donc ton correctif est inerte jusqu'à une
recréation, donc sûr à écrire » est un argument RETOURNÉ.**

> ⛔ **C'est précisément ce qui le rend dangereux : il deviendrait vivant à la
> prochaine recréation, sans avoir JAMAIS été exercé — armé par un déploiement
> que personne ne relierait à lui.**

**C'est la forme exacte de SEC-017 lui-même** : *un défaut qui se manifeste au
prochain redémarrage, disconnecté du changement qui l'a causé.* **Réécrire la
fonction la plus dangereuse du produit avec ce profil de mise en service, sans
l'avoir jouée une fois, échange un défaut connu et borné contre un défaut
inconnu.**

*Deux sessions ont refusé ce geste indépendamment, pour ce motif, avant que je ne
sois sollicitée.*

---

## 2. LE MODÈLE INVOQUÉ EXISTE, ET IL EST BON — vérifié

**On me dit de reprendre le dessin de `sudo_manager` plutôt que d'en inventer un.
Mesuré : il est là, et il est juste.**

```
_make_tmpfile        install -m 0600 -o root -g root /dev/null <tmp>
                       -> cree DEJA avec le bon proprietaire et le bon mode
_write_to_remote     cat > <tmp> <<'MARQUEUR_ALEATOIRE'
validate_sudoers     visudo -cf <tmp>   ->  (ok, sortie)
si NON ok            return + cleanup du tmpfile, la cible n'est JAMAIS touchee
si ok                mv <tmp> <cible> && chown root:root && chmod 0440
```

### 2.1 ⚠ ET IL INSPECTE BIEN LE CODE DE SORTIE — je corrige ma propre phrase

```python
out, err, code = execute_as_root(client, f"visudo -cf {path} 2>&1 || echo __VISUDO_KO__", …)
if '__VISUDO_KO__' in out or code != 0:
```

**J'avais écrit au relecteur : *« il n'y a aucun motif correct à recopier »*. C'est
vrai de `iptables_manager.py` — zéro occurrence du mot `code` — et j'ai laissé
entendre que le dépôt n'en avait aucun.** *Il en a un, ici, et il fait CEINTURE
ET BRETELLES : le marqueur **et** le code de sortie.* **Ma phrase était juste sur
son objet et trompeuse sur sa portée.**

### 2.2 ⛔ MAIS UNE PIÈCE DU MODÈLE NE DOIT PAS ÊTRE COPIÉE

```python
def _write_to_remote(…):
    execute_as_root(client, cmd, root_password, timeout=15)   # ⛔ valeur JETEE
```

**L'écriture dans le fichier temporaire ne vérifie pas qu'elle a réussi.** *Si
elle échoue partiellement, la validation porte sur un temporaire tronqué — et
`visudo -cf` sur un fichier VIDE réussit.* **Le `mv` installerait alors une
politique vide.**

> **Le modèle est bon dans son ORDRE et incomplet dans son PREMIER PAS.**
> *Reprendre le dessin, oui ; reprendre cette ligne, non.*

---

## 3. LA FORME, ET SES CINQ CONTRÔLES

    1. tmp = install -m 0640 -o root -g root /dev/null /tmp/rootwarden-ipt-<alea>
       -> le mode et le proprietaire sont poses A LA CREATION, pas apres
    2. ecrire les regles dans tmp        -> INSPECTER le code (ce que le modele omet)
    3. iptables-restore --test < tmp     -> INSPECTER le code
       si != 0 : supprimer tmp, RENDRE L'ECHEC. `/etc/iptables/rules.v4` intact.
    4. mv tmp /etc/iptables/rules.v4 && chown root:root && chmod 0640
       -> INSPECTER le code
    5. iptables-restore < /etc/iptables/rules.v4   -> INSPECTER le code
       et ne journaliser un succes QUE s'il vaut 0

**⚠ Le mode : `0640` et non `0440`.** *`rules.v4` est à `0640` aujourd'hui
(`touch {path} && chmod 640 {path}`). `sudo_manager` emploie `0440` parce que
`sudoers` l'exige. **Copier le mode du modèle changerait les droits du fichier
en croyant copier son dessin.***

**Et l'idempotence du `mv`** : *`mv` sur un même système de fichiers est
atomique ; `/tmp` et `/etc` peuvent être des montages distincts, et le `mv`
dégénère alors en copie non atomique.* **Le temporaire doit vivre dans
`/etc/iptables/`, pas dans `/tmp`.**

---

## 4. LE TÉMOIN — et un seul des deux sens prouve quelque chose

    jeu VALIDE     doit etre charge ET ecrit
    jeu INVALIDE   doit echouer SANS AVOIR TOUCHE /etc/iptables/rules.v4

> **Le second est le seul qui prouve la propriété, et il se mesure sur
> l'EMPREINTE DU FICHIER — avant et après — jamais sur le code de retour.**
> *Un correctif qui rendrait `False` en ayant quand même écrit passerait un test
> qui lit le code de retour.*

    md5sum /etc/iptables/rules.v4   AVANT
    appliquer un jeu illisible      -> attendu : echec RENDU a l'appelant
    md5sum /etc/iptables/rules.v4   APRES   -> DOIT etre identique

**⛔ Et ce témoin exige une machine réelle.** *C'est pourquoi le correctif n'est
pas éprouvable aujourd'hui, et pourquoi je le déclare NON ÉPROUVÉ plutôt que de
le poser.*

---

## 5. Ce que je livre, et ce que je ne livre pas

    LIVRE        cette specification · les cinq controles · le temoin · les
                 deux pieges du modele (le mode 0440, `_write_to_remote`)
    NON LIVRE    le correctif. Perimetre, et refus motive au §1.2.
    NON EPROUVE  rien de tout ceci n'a ete joue : aucune machine jointe.
