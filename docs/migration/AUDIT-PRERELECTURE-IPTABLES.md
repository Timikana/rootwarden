# Pré-relecture de `iptables/` — le contrat de sécurité du portage (I1 → I5)

Écrit le **2026-08-27** par la session 5 (sécurité), en **lecture seule**. Aucune machine jointe,
aucune suite lancée, banc jamais demandé. Les trois mesures demandées par le Lead avant portage sont
faites, **et deux d'entre elles sont liées par une cause commune qu'il n'avait pas nommée.**

---

## 1. MESURE 1 & 2 — elles n'en font qu'une : l'écho PTY rend la troncature ATTEIGNABLE

### 1.1 La détection cherche dans des FRAGMENTS, pas dans la sortie

`backend/routes/iptables.py:113-116` :

```python
test_cmd = f"… iptables-restore --test /tmp/_ipt_test.rules 2>&1; echo EXIT_CODE=$?"
output_lines = list(execute_as_root_stream(client, test_cmd, root_password, logger=logger))
output = '\n'.join(output_lines)
exit_code = 0 if any('EXIT_CODE=0' in l for l in output_lines) else 1
```

`execute_as_root_stream` **ne rend pas des lignes** : il rend `stdout.channel.recv(4096)`, c'est-à-dire
des fragments de **4096 octets**. La variable s'appelle `output_lines` et ne contient pas des lignes.

**Reproduit, sans SSH, en recomposant le découpage à l'identique :**

| longueur de la sortie | verdict rendu | verdict juste |
|---|---|---|
| 12 octets | 0 | 0 |
| 4097 | 0 | 0 |
| **4102** | **1** | 0 ⟵ **valide déclaré INVALIDE** |
| **4104** | **1** | 0 |
| **4107** | **1** | 0 |

`EXIT_CODE=0` fait 11 caractères : dès qu'il chevauche une frontière de fragment, **aucun** fragment
ne le contient, et un jeu de règles **valide** est déclaré invalide.

### 1.2 Et le `join` insère des sauts de ligne qui n'existent pas

`output = '\n'.join(output_lines)` recolle des fragments **contigus** avec un séparateur. Mesuré :
une sortie réelle de 4106 octets sans aucun saut de ligne est affichée avec **un saut de ligne
inséré**, à l'octet 4096. Défaut **déterministe**, à chaque frontière.

*(S'y ajoute `if text.strip(): yield text` : un fragment entièrement blanc est **jeté**. La sortie
affichée n'est donc pas seulement décalée, elle peut être amputée.)*

### 1.3 ⚠ CE QUI REND LE DÉFAUT VIVANT — et c'est la mesure 2

Sur un jeu de règles valide, `iptables-restore --test` n'écrit **rien** : la sortie vaut
`EXIT_CODE=0\n`, douze octets, un seul fragment. **Le chevauchement serait donc inatteignable… si la
sortie ne contenait que le résultat.**

Or `execute_as_root_stream` ouvre `client.exec_command(root_cmd, get_pty=True)` sur le chemin mot de
passe. **Un PTY ÉCHOTE la commande** — et la commande contient
`printf '%s' '<base64 de tout le jeu de règles>'`. Un jeu de règles de 3 Ko produit ~4 Ko de base64,
donc **l'écho seul dépasse un fragment**.

> **L'écho PTY n'est pas seulement une nuisance d'affichage : c'est lui qui fait franchir la
> frontière des 4096 octets. Sans lui, la troncature ne serait jamais atteinte ; avec lui, elle l'est
> à chaque jeu de règles un peu long.** Les deux défauts que le Lead m'a donnés séparément n'en font
> qu'un.

**Le mot de passe, lui, EST filtré** — `filtre_echo_mot_de_passe` est appliqué (`ssh_utils.py:766`),
et c'est correct. Mais il retire les **lignes qui SONT le secret** ; il ne retire pas l'écho de la
commande. Le blob base64 arrive donc à l'écran.

### 1.4 Le correctif est d'une ligne, et il ferme les trois

```python
output = ''.join(output_lines)                    # concatener, pas joindre
exit_code = 0 if 'EXIT_CODE=0' in output else 1   # chercher dans la SORTIE
```

Chercher dans la sortie **recomposée** au lieu de chaque fragment ferme le chevauchement ; concaténer
au lieu de joindre supprime les sauts insérés. **Ce que ça casserait : rien** — la valeur cherchée
est la même, l'ensemble balayé est un sur-ensemble strict.

> **Règle générale, et elle vaut au-delà de ce module : ne jamais chercher un marqueur dans les
> FRAGMENTS d'un flux. Un marqueur se cherche dans le flux recomposé, ou par un automate qui garde le
> chevauchement.** C'est le pendant, sur un flux, de « le marqueur n'est pas le verdict » : ici le
> marqueur est juste, c'est le découpage qui le perd.

### 1.5 Ce que le portage devra faire de l'écho

`output` est **affiché tel quel**. Le portage doit :

- **échapper** (`textContent`, jamais `innerHTML`) — le champ contient du texte distant ;
- **ne jamais placer un marqueur d'échec en clair** dans la commande. C'est le piège de `v1.37.11` :
  le PTY échote la commande, donc un marqueur littéral apparaît dans la sortie **avant** que la
  commande ne s'exécute, et un test de présence rend un faux positif permanent. Ici la commande porte
  `EXIT_CODE=$?` — **`$?` n'est pas `0`**, donc l'écho ne contient pas `EXIT_CODE=0` et la détection
  n'est pas empoisonnée. **C'est de la chance, pas une précaution** : un jour où quelqu'un écrirait
  `echo EXIT_CODE=0` dans une branche, l'écho suffirait à déclarer le succès ;
- **ne pas afficher le blob base64.** Il n'apprend rien et il noie le message. À couper, ou à replier.

---

## 2. MESURE 3 — `min-w-[6px]` : dédouané pour ce module

`min-w-[6px]` est **absent de tous les CSS livrés** (`tailwind.css`, `rw.css`, `app.css` : 0
occurrence). Quatrième occurrence confirmée de la classe purgée.

**Mais elle n'appartient pas à `iptables/`** : son unique usage est
`legacy/fail2ban/js/main.js:577`, et la frise de fail2ban est **déjà portée** (F2, dessinée en
pixels). **Rien à porter, rien à corriger ici.** Le dire évite de refaire le travail.

*(La règle reste vraie pour tout le portage : mesurer le style **calculé**, jamais la présence de la
classe dans le DOM.)*

---

## 3. LE CONTRAT DE SÉCURITÉ — ce que le portage devra respecter

### 3.1 Ce que la session 4 vient de fermer, à NE PAS défaire

`POST /iptables-apply` porte désormais `@require_permission('can_manage_iptables')`
(`iptables.py:129`, E-152). **Vérifié.** Le portage ne doit pas « harmoniser » en sens inverse.

Conséquence d'écran, et c'est la règle du chantier : `can_manage_iptables` n'est détenue que par
`superadmin` (mesuré). Un rôle 2 sans la permission verra la page et sera **refusé par la requête** —
le bouton doit donc être désactivé **avec son motif**, et l'état désactivé doit être la
**conjonction** « le backend refuserait ET la condition est réunie ».

### 3.2 ⚠ LE DANGER PROPRE DU MODULE : se couper la patte

`MODULE-FILTRAGE.md` §2, remesuré : `iptables-restore` **remplace atomiquement toutes les tables**.
Un fichier avec `INPUT DROP` sans `ACCEPT` sur le port SSH ferme la session en cours **et toutes les
suivantes**. Le seul canal de RootWarden vers la machine est SSH, et `/iptables-rollback` **passe
aussi par SSH**.

Deux défauts s'additionnent, et ils sont toujours là :

- les cinq gabarits codent **`--dport 22` en dur**, alors que le port SSH de chaque machine est en
  base et disponible côté JS. Le gabarit `deny_all` porte même le commentaire « seul SSH est ouvert
  pour ne pas perdre l'acces » : **l'intention est écrite, l'implémentation suppose 22** ;
- `showNotification` vise `#notifications`, **qui n'existe pas sur la page** — ses huit points d'appel
  lèvent une `TypeError`, **y compris dans le `catch`**. Donc : appliquer un jeu de règles **réussit
  sur la machine et l'écran ne dit rien**. Ni succès, ni erreur.

**Propriétés que le portage doit satisfaire** :

| # | propriété | mesurable comment |
|---|---|---|
| **Q1** | le gabarit emploie le **port SSH de la machine**, lu en base, jamais `22` en dur | dériver le port de la base et le chercher dans le texte du gabarit rendu — **ne pas coder `22`**, les trois machines écoutent sur 22 et la suite mesurerait son presse-papier |
| **Q2** | un jeu de règles qui **ne contient pas** d'`ACCEPT` sur ce port est **refusé avant l'envoi**, et la raison est nommée | requête forgée depuis la page + `page.on('request')` : **aucune requête ne part** |
| **Q3** | tout retour d'`/iptables-apply` produit un message **visible**, succès comme échec | `page.on('response')` puis lecture du porte-messages dédié — jamais `[class*="text-red"]` |
| **Q4** | avant consentement, **aucune requête n'est émise** | au **réseau**, pas au DOM |

**Q2 est la propriété qui compte.** Elle est la seule qui empêche le geste irréversible, et elle se
mesure **sans jamais l'émettre**.

### 3.3 La cible sûre, et elle n'est pas évidente

> **Aucun `iptables-apply` ne doit être émis vers une machine réelle pendant les mesures.**
> `Test-Server-Debian` (id 2) est un **conteneur** : il n'a pas de systemd, et son réseau est celui
> de Docker. Y appliquer un jeu de règles n'est pas « sans danger » — c'est **sans signification**, et
> un test qui passe pour cette raison est un faux PASS.

Le régime est celui de F5 : **les écritures sont servies par la suite**, et le motif est écrit dans
le fichier. Ce qui se mesure est le **refus** et l'**absence de requête**, jamais l'effet distant.

`/iptables-validate` est le seul geste de ce module qui pourrait être joué pour de vrai — il écrit
dans `/tmp` et ne modifie aucune table. **Mais il ouvre quand même une session SSH**, donc jamais vers
la machine 1.

### 3.4 Ce qui reste vrai de mes qualifications antérieures

- **aucune valeur utilisateur n'est interpolée brute** dans `iptables_manager.py` — règles en base64,
  chemins littéraux. **L'en-tête du fichier le revendique et c'est vrai.** Rien à durcir ;
- **réserve maintenue** : `_write_rules_safe` est sûre **par ses deux appelants**, pas par
  construction — `dest_path` n'est pas validé. **Un troisième appelant rouvrirait le trou**, et le
  portage ne doit pas en devenir un ;
- `/iptables-rollback` porte `@require_permission('can_manage_iptables')` et fait son contrôle
  d'accès **sur l'objet résolu** (`iptables.py:296`, `check_machine_access(row['server_id'])`).
  **C'est le bon motif, et il est déjà là** — le portage doit s'y adosser, pas le refaire ;
- **`/iptables-history` lit `server_id` là où le décorateur retient `machine_id`** (E-175). Le
  correctif dort sur `security/backend-cve`, commit `399931a`, **jamais fusionnée**. Les deux tables
  d'historique sont vides : réel, sans porteur.

### 3.5 Hors lot, et il faut le dire au lieu de le porter

`/iptables-logs` **diffuse un fichier que personne n'écrit** : `/app/logs/iptables.log` est créé vide
au démarrage et **aucun writer n'existe**. L'utilisateur voit un flux qui n'émet que des pings pendant
dix minutes. **Ne pas le porter**, ou le brancher sur ce qui écrit réellement — mais ne pas reproduire
un flux vide qui a l'air vivant.

---

## 4. Ce que je n'ai PAS mesuré

- **je n'ai exécuté aucun geste de ce module**, ni validation, ni application, ni retour arrière.
  Tout ce qui précède est établi par lecture, plus **une recomposition locale du découpage** qui ne
  joint aucune machine ;
- **je n'ai pas relu les trois handlers AJAX PDO locaux** d'`iptables/index.php` (`MODULE-FILTRAGE.md`
  les signale, I2 les porte). Ils ne sont pas dédouanés ;
- **je n'ai pas vérifié le contenu des cinq gabarits ligne à ligne** — seulement le `--dport 22` en
  dur, déjà mesuré par l'inventaire ;
- **je n'ai pas mesuré si `iptables_rules` admet des lignes multiples** faute de contrainte
  d'unicité (`MODULE-FILTRAGE.md` §7). C'est une question de schéma, elle appartient à la session 4.
