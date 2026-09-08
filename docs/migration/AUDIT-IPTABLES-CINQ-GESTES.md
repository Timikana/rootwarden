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

---

## 6. ⚠ CORRECTION DE MA §2.2 — j'ai repris une surestimation, et la borne n'est pas celle qu'on croit

**Le DSI a raison de borner la gravite. Mais sa borne s'appuie sur un garde qui
ne garde pas, et ma §2.2 reprenait une phrase trop large.**

### 6.1 `require_machine_access` ne borne RIEN au-dessus du role 1

`backend/routes/helpers.py` :

```
check_machine_access(machine_id):
    user_id, role_id = get_current_user()
    if role_id >= 2:
        return True          # <- inconditionnel
```

> **« `require_machine_access` est present des DEUX cotes, donc l'exposition est
> bornee » est vrai de la CONCLUSION et faux du MOTIF.** *Ce decorateur ne mord
> qu'au role 1. La borne vient entierement de `require_permission`, pas de lui.*

**C'est « un garde present n'est pas un garde qui garde », applique a une phrase
que j'aurais pu ecrire moi-meme.**

### 6.2 Et `require_permission` est court-circuite au role ≥ 3

```
if role_id >= 3:
    return func(*args, **kwargs)   # superadmin bypass, aucune permission requise
```

**L'ensemble reellement habilite sur les deux chemins d'application est donc :**

    role >= 3                     inconditionnel — ni permission, ni acces machine
    role 2  + can_manage_iptables toutes les machines (acces machine automatique)
    role 1  + can_manage_iptables les machines de `user_machine_access` seulement

### 6.3 Ma §2.2 citait le docblock sans le controler

**J'ai repris : *« Tout compte authentifie pouvait faire appliquer par SSH un jeu
de regles a n'importe quelle machine du parc »*. C'est trop large deux fois :**

- il fallait **`can_manage_iptables`** (ou le role 3), pas seulement etre
  authentifie ;
- et le controle ajoute dans le corps **ne restreint que le role 1**, puisque
  `check_machine_access` rend `True` des le role 2.

> **Je l'ai cite comme une mesure alors que c'etait une affirmation.** *« Cite »
> n'est pas « verifie » — ma propre regle, appliquee a un docblock qui allait
> dans mon sens.* ⚠ **Et cette correction RETRECIT ma trouvaille : c'est la
> categorie que personne ne corrige a ma place.**

### 6.4 Ce qui ne bouge pas

**Le point structurel tient entier, et c'est le seul qui commande l'arbitrage :**

> **Ce garde vit dans le CORPS de la fonction, pas dans son annotation. Aucun
> inventaire fonde sur les decorateurs ne le voit** — et le mien, hier, ne l'a
> pas vu non plus. **L'archiver sans le porter perdrait un controle qu'aucune
> relecture des annotations ne signalerait manquant.**

*Et le defaut de TRACE des deux chemins d'application est confirme sans reserve :
memes quatre gardes, un seul archive.*

### 6.5 ⛔ « Un compte reel l'occupe-t-il » — je ne peux PAS le mesurer d'ici

    client mysql          absent
    connecteur python     absent
    port 3306             non publie (docker-compose.yml)
    socket docker         permission refusee

**Les quatre voies sont fermees. Ce n'est pas une reserve de style : la question
centrale de mon mandat reste SANS REPONSE sur ce module.** *La requete qui y
repond, pour qui a l'acces :*

```sql
SELECT u.id, u.name, u.role_id
FROM users u
LEFT JOIN permissions p ON p.user_id = u.id AND p.can_manage_iptables = 1
WHERE u.role_id >= 3 OR p.user_id IS NOT NULL;
```

**Tant qu'elle n'a pas ete passee, « le pouvoir est atteignable » est etabli et
« quelqu'un l'occupe » ne l'est pas.**

---

## 7. ⛔ POURQUOI JE NE PORTE PAS — et ce n'est pas mon périmètre qui le dit

**On m'a écrit que le portage de ces gestes « n'attend pas l'exploitant », que
son mot concerne *« l'exercice d'un geste, pas son portage »*, et qu'un pair
l'avait décidé. J'ai vérifié. Le document qui gouverne ce sous-lot dit le
contraire, en toutes lettres.**

`docs/migration/MODULE-FILTRAGE.md:268-269` :

> *« `I5` application et retour arrière — **ne se porte pas avant que la décision
> sur le port SSH soit tranchée**. »*

**« Ne se porte pas » est une condition sur le PORTAGE, pas sur l'exercice.**
*La distinction proposée est réelle en général ; elle ne s'applique pas ici,
parce que la condition écrite porte explicitement sur le geste d'écrire.*

### 7.1 Et l'arbitrage n'a pas été rendu — le dossier des arbitrages RENDUS le dit

    DOSSIER-35 (« arbitrages RENDUS »):133   le port SSH d'`iptables` — « joint des
                                             machines de son infrastructure »
    DOSSIER-38:16                            I5 · iptables/index.php · le port SSH
                                             pour iptables-restore   -> EN ATTENTE
    DOSSIER-34:53                            bloqué sur l'arbitrage du PORT SSH

> **Le dossier qui recense ce qui A été tranché range celui-ci parmi ce qui ne
> l'a pas été, et pour un motif nommé : il touche l'infrastructure de
> l'exploitant.** *Une décision prise depuis par un pair ne referme pas un
> arbitrage qui avait été mis de côté précisément parce qu'il ne lui appartenait
> pas.*

**`/iptables-apply`, `/iptables-restore` et `/iptables-rollback` SONT I5.**
Les porter, c'est porter I5.

### 7.2 ⚠ ET LE QUATRIÈME NE DOIT PAS ÊTRE PORTÉ DU TOUT

`MODULE-FILTRAGE.md:272-275`, **hors lot** :

> *« `/iptables-logs` — le flux **diffuse un fichier que personne n'écrit**.
> `/app/logs/iptables.log` est créé vide au démarrage et aucun writer n'existe.
> L'utilisateur voit un flux qui n'émet que des pings pendant dix minutes.
> **Ne pas le porter**, ou le brancher sur ce qui écrit réellement. »*

**Vérifié :**

```
backend/Dockerfile:63   touch /app/logs/iptables.log        <- créé vide
backend/server.py:231   for _lf in [... 'iptables.log' ...]  <- créé vide
open(... 'iptables.log' ... , 'w'|'a')                       <- 0 occurrence
```

> ⚠ **Ma propre §2 disait : « `/iptables-logs`, 39 lignes, n'écrit rien, sa
> valeur est dans sa borne de 600 s ».** *C'est exact et ça passe à côté :
> j'ai mesuré la qualité du garde-fou d'un flux qui n'a rien à diffuser.*
> **C'est la sixième question — « le câbler produirait-il quelque chose ? » —
> que j'avais appliquée à `/cve_trends` et pas à celui-ci.**

### 7.3 Ce qui reste vrai, et qui ne dépend d'aucun arbitrage

**Les deux constats qui commandent l'écriture tiennent entiers, et ils sont vrais
AUJOURD'HUI, indépendamment de l'extinction :**

1. **le contrôle d'accès de `/iptables-rollback` vit dans le CORPS** — invisible
   à tout inventaire par décorateurs ; à porter AVEC le geste, jamais après ;
2. **les deux chemins d'application sont inversés** — `/iptables` `action:apply`
   applique sans archiver, et il est déjà porté et déjà en liste blanche.

**Le second est un défaut de trace du portage ACTUEL. Il ne demande ni I5 ni
l'extinction : il demande une décision sur `action: "apply"`.**

---

## 8. Les deux prémisses du cahier des charges I5 — mesurées

**Un cahier des charges Q1–Q4 m'a été transmis pour I5. Je n'écris pas (§8.3),
mais ses deux prémisses portantes se vérifient sans autorisation, et elles
tiennent toutes les deux.**

### 8.1 Q1 — `--dport 22` est bien codé en dur, et il y a bien CINQ gabarits

```
legacy/iptables/js/main.js:368  -A INPUT -p tcp --dport 22 -j ACCEPT
                          :382  idem
                          :398  idem
                          :408  idem
                          :417  idem
```

**Cinq occurrences, un seul fichier, aucune dérivation.** *Et le portage le SAIT
déjà* — `Iptables.php:111` et `pare-feu.js:37` le documentent tous les deux.
**La connaissance est portée ; la correction est I5.**

> ⚠ **Le piège de mesure signalé est réel et je le confirme** : les machines du
> parc écoutent sur 22. *Une suite qui cherche `22` dans le gabarit rendu
> passerait au vert sans rien mesurer.* **Il faut dériver le port depuis la base
> et chercher CETTE valeur** — sinon la mesure est vraie et vide.

### 8.2 ~~SEC-015 est toujours OUVERT~~ — ⛔ FERMÉ 76 MINUTES APRÈS CETTE LIGNE

`backend/iptables_manager.py:126` :

```python
f"printf '%s' '{encoded}' | base64 -d > {dest_path}",
```

**`rules` est sûr par CONSTRUCTION (base64). `dest_path` est interpolé BRUT dans
une commande exécutée en root, et n'est sûr que par CONVENTION — tous les
appelants actuels passent un littéral.**

> **I5 est précisément le sous-lot qui ajoute des appelants.** *Porter le chemin
> sans poser `shlex.quote(dest_path)` ouvrirait la fonctionnalité et retirerait
> la seule chose qui tenait lieu de barrière : l'absence d'appelant dérivant une
> destination.*

#### ⛔ RECTIFICATION (2026-09-08) — ce paragraphe est PÉRIMÉ, et de 76 minutes

```
d636e70d   2026-09-07 22:15:09   cette ligne : « SEC-015 est toujours OUVERT »
266f21a2   2026-09-07 23:31:56   fix(iptables): SEC-015 — `dest_path` etait
                                 interpole BRUT dans une commande root
```

**`shlex.quote(dest_path)` est en place. `shlex` est importé.**

⛔ **ET C'EST FERMÉ DANS L'ARBRE SEULEMENT — rectification du 2026-09-08.**

```
backend/hypercorn_config.py:14   workers = 4
                          :17   use_reloader = False       <- verifie par moi
266f21a2                        2026-09-07 21:31:56 UTC    <- verifie par moi
demarrage des workers           2026-09-07 12:53:00 UTC    <- RELAYE, PAS verifie
                                (socket docker : permission refusee)
```

**Un `.py` est lu au DÉMARRAGE. Si l'heure relayée est juste, le correctif a été
écrit 8 h 39 après, donc `dest_path` est TOUJOURS interpolé brut dans le processus
qui tourne.**

> ⚠ **« SEC-015 est FERMÉ » était une affirmation SANS SON RÉGIME** — et j'ai
> cette règle en mémoire depuis des jours : *« arbre, service, ou moteur de base :
> nommer le régime ; une affirmation sans son régime est invérifiable ».*
> **Je l'ai enfreinte le jour même où je corrigeais des tiers pour des faits
> périmés.**

⛔ **Et le piège de vérification est réel** : *`backend/` est monté en BIND sur
`/app`. Un `grep` DANS le conteneur trouve le correctif à l'identique de l'arbre
— et rend le MAUVAIS verdict.* **Un fichier partagé ne fait pas un code partagé :
le montage synchronise l'octet, pas la mémoire du processus qui l'a lu.** *Un
`docker exec … python -c` ne sert pas davantage : il ouvre un nouveau processus.*

⚠ **Deux horloges, et elles sont armées sur cette mesure** : *les `mtime` sont en
CEST, `StartedAt` en UTC.* **Comparés naïvement, `12:16 < 12:53` conclut « le
fichier précède le démarrage » — l'inverse du vrai. J'ai ramené les deux en UTC
dans la même commande.**

### 8.2 bis ⚠ CE QUE ÇA FAIT À SEC-017

**Si le service tourne sur le code d'avant `266f21a2`, alors le processus porte
AUJOURD'HUI les deux défauts à la fois** : *`dest_path` interpolé brut **et** le
succès annoncé sans vérification.* **SEC-017 n'est donc pas seulement ouvert dans
l'arbre : dans le service, il coexiste avec un défaut que j'ai publié comme
fermé.**

> **J'avais raison en l'écrivant, et ma note est fausse 76 minutes plus tard.**
> *Le pire est que je l'ai RECITÉE aujourd'hui comme un fait courant, pour fonder
> un argument — en lisant le DOCSTRING de la fonction, qui décrit l'état passé au
> passé et disait donc vrai.*

**Troisième fois sur ce chantier qu'une prose est prise pour du code — et la
première où la prose était exacte.** *« Il n'a jamais protégé `dest_path`, qui
ÉTAIT interpolé brut » est une phrase juste : c'est moi qui l'ai lue au présent.*

⚠ **Et c'est la deuxième fois que MA propre mesure se périme dans l'heure qui
suit** (la §3.2 de l'audit des gardes croisées était tombée en 8 minutes). *Sur
un dépôt où huit sessions écrivent, un audit daté à la minute n'est pas une
précaution de style : c'est la seule chose qui distingue « j'ai mesuré » de « je
me souviens ».*

### 8.3 ⛔ POURQUOI JE N'ÉCRIS PAS ENCORE

**L'arbitrage du port SSH m'est rapporté comme rendu par un pair. Je ne peux pas
le tenir pour rendu sur cette base — et ce n'est pas de la défiance, c'est le
coût asymétrique.**

*Il y a quatre heures, le même canal m'a transmis une autorisation qui n'existait
pas : une décision parquée chez l'exploitant, reprise par un pair, puis citée
comme acquise. Elle était partie vers deux sessions.* **Le mécanisme est
documenté, il est récent, et rien dans un message ne le distingue d'un relais
fidèle.**

    si j'attends et l'autorisation existe   -> quelques heures perdues
    si j'écris et elle n'existe pas         -> un bouton capable de couper
                                               RootWarden d'une machine
                                               DEFINITIVEMENT, bati sur rien

**J'ai posé la question à l'exploitant au tour précédent. J'attends SA réponse,
dans cette session.** *Une phrase lui suffit.*

**Ce que je peux faire sans elle, et que je fais : mesurer.** *Les §8.1 et §8.2
sont utiles à quiconque écrira I5, y compris si ce n'est pas moi.*
