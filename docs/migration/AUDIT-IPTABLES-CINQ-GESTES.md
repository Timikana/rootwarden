# AUDIT — les « cinq gestes sans appelant » d'`iptables/`

    Session   5 — securite, LECTURE SEULE
    Mesure    2026-09-07, backend/routes/iptables.py (326 lignes) + laravel/app/Services/Iptables.php
    Objet     mesurer, pour l'arbitrage produit. AUCUN portage, AUCUN exercice.

> **Ils sont QUATRE, pas cinq — et l'arbitrage ne porte pas sur ce qu'on croit.**

---

## 1. ⚠ LA PREMISSE DE LA DEMANDE EST FAUSSE

> *« Le portage n'a AUCUNE table `iptables*` ni `firewall*` — je l'ai mesure. »*

**Il en a deux.** `laravel/app/Services/Iptables.php` :

```
:206  SELECT id, rules_v4, rules_v6, updated_at FROM iptables_rules ...
:218  SELECT COUNT(*) AS n FROM iptables_rules WHERE server_id = ?
:244  DELETE FROM iptables_rules WHERE server_id = ?
:246  INSERT INTO iptables_rules (server_id, rules_v4, rules_v6) VALUES (?, ?, ?)
:260  SELECT COUNT(*) AS n FROM iptables_history WHERE server_id = ?
:295  FROM iptables_history WHERE server_id = ? ...
```

**La sonde cherchait `DB::table('iptables*')`. Ce service n'emploie pas ce
constructeur : il ecrit du SQL brut (`DB::select`, `DB::insert`, `DB::delete`).**

> *Un motif qui teste UNE FORME D'EXPRESSION a conclu a l'absence de la CHOSE.*
> **C'est le meme defaut que l'ancre de gauche d'hier, sur un autre axe : ce
> n'est plus la composition du chemin, c'est la forme de l'appel.**

### Conséquence immédiate : `/iptables-history` n'est pas un trou

**C'est de la FORME 4, et il est DEJA PORTE** — sous-lot I3,
`PareFeuController::historique()`, qui lit `iptables_history` par le service et
rend en plus le TOTAL que la route backend n'annonce pas.

**Il reste QUATRE gestes.**

---

## 2. Les quatre, mesures

| geste | lignes | ce qu'il ECRIT | sa valeur est dans |
|---|---|---|---|
| `/iptables-apply` | **78** | les regles **sur la machine** (SSH root) **+** une ligne dans `iptables_history` | **ses garde-fous** — 4 correctifs, tous d'un defaut deja survenu |
| `/iptables-rollback` | **60** | les regles **sur la machine**, depuis une version archivee | **son controle d'acces**, qu'aucun decorateur ne peut exprimer |
| `/iptables-restore` | **36** | les regles **sur la machine**, depuis la copie en base | **ses garde-fous** — resolution par `machine_id`, refus de copie vide |
| `/iptables-logs` | **39** | **rien** (SSE, lecture) | **sa borne** — 600 s + battement, contre la saturation du pool |

### 2.1 `/iptables-apply` — quatre defauts deja payes, ecrits sur place

1. **l'auteur ne vient plus du corps de la requete** — *un client pouvait signer
   une modification de pare-feu au nom de n'importe qui, et comme aucun frontend
   n'envoyait le champ, TOUTES les lignes d'historique valaient « admin » ;*
2. **il archive `file_rules_v4`, pas `rules_v4`** — *la mauvaise cle enregistrait
   des versions VIDES, et un retour arriere ecrasait alors `/etc/iptables/rules.v4`
   par du vide ;*
3. **la machine vient de `machine_id` resolu, pas de l'adresse** — *deux machines
   derriere un NAT, et l'historique d'un serveur recevait les regles d'un autre ;*
4. **une version vide n'est pas archivee** — *elle rendrait le retour arriere
   destructeur.*

### 2.2 ⚠ `/iptables-rollback` porte un garde QU'UN DECORATEUR NE PEUT PAS FAIRE

**Son propre docblock l'explique** : son corps ne porte que `history_id`, donc
`@require_machine_access` ne trouve ni `machine_id` ni `server_id`, **`ids` reste
vide, et il laisse passer**. *Tout compte authentifie pouvait faire appliquer par
SSH un jeu de regles a n'importe quelle machine du parc, production comprise.*

**Le controle est fait APRES la resolution, sur la machine que LA VERSION
designe** (`check_machine_access(row['server_id'])`), jamais sur un identifiant
fourni par le demandeur.

> ⛔ **C'est le seul des quatre dont la valeur n'est pas un garde-fou mais un
> CONTROLE D'ACCES.** *Archiver cette route sans porter ce controle avec elle ne
> supprimerait pas le pouvoir — il est atteignable autrement (§3) — et
> recreerait exactement le trou que ce code a referme.*

---

## 3. ⚠⚠ CE QUI CHANGE L'ARBITRAGE : les deux chemins sont INVERSES

**`POST /iptables` — la route DEJA PORTEE et deja en liste blanche — accepte
`action: "apply"`, et appelle le meme `apply_iptables_rules`.**

    /iptables-apply          applique  ET ARCHIVE la version precedente  (4 garde-fous)
    /iptables  action=apply  applique  ET N'ARCHIVE RIEN                 (aucun)

**Les deux ecrivent les memes regles en root sur la meme machine. Un seul
laisse une trace.**

> **Archiver `/iptables-apply` retirerait la variante SURE et laisserait vivante
> celle qui n'archive pas.** *L'inverse de l'intention.*

**Et l'entree de liste blanche est un PREFIXE** — `RoutesBackend.php:114` porte
`'/iptables', '/iptables-'` : *les six routes `/iptables-*` sont deja
atteignables par la passerelle* (c'est SEC-012).

**⚠ La page du portage n'offre aucun bouton d'application** — c'est la fermeture
*par l'absence* ecrite dans `PareFeuController`. **Elle ne protege que le
navigateur : une requete forgee atteint `action: "apply"` sans passer par elle.**

---

## 4. Un trou ASYMETRIQUE que l'extinction rendrait visible

**Le sous-lot I2, PORTE, ECRIT dans `iptables_rules`** (`Iptables.php:244-246`).
**`/iptables-restore` est le SEUL chemin qui applique cette copie — et il n'a
aucun appelant dans le portage.**

> *Le portage produit deja une donnee que seul le legacy sait employer.*
> **Eteindre `legacy/iptables/` sans porter `restore` laisserait l'ecran
> « enregistrer la copie » en place, et rendrait cette copie inapplicable.**

---

## 5. Ce que je rends pour l'arbitrage, et ce que je n'ai pas mesure

**Sur le critere annonce — « garde-fous ou commodite » :**

- **aucun des quatre n'est une enveloppe de commodite.** *Ce n'est pas le cas
  `fail2ban` (deux enveloppes de 26 lignes) : c'est le cas `bashrc`, quatre fois.*
- **`/iptables-logs` est le seul qui n'ecrit rien**, et le moins couteux a
  reporter — *mais sa borne de 600 s est ce qui empeche un thread par connexion
  de vivre indefiniment ; la retirer en la reecrivant serait une regression
  connue.*

**⛔ CE QUE JE N'AI PAS MESURE, ET QUI N'EST PAS MESURABLE D'ICI :** *si un
compte occupe aujourd'hui le chemin `/iptables` `action: "apply"`.* **Il faudrait
lire les journaux d'acces de la passerelle, et je ne les ai pas.** *Le pouvoir
est ATTEIGNABLE — je ne dis pas qu'il est EMPRUNTE.*

**⛔ ET JE N'AI RIEN PORTE NI EXERCE.** *`apply`, `restore` et `rollback`
ecrivent des regles de pare-feu en root sur une machine reelle : se tromper y
ferme un acces.* **Mon perimetre d'ecriture sur `iptables` tient de l'exploitant
et ne couvre pas l'exercice d'un geste sur son infrastructure — une carte
blanche recue par un pair ne me la transmet pas.**
