# DOSSIER-59 — La séquence d'extinction est ÉPUISÉE : ce qui reste tient en quatre gestes

**Mesuré le 2026-09-08 entre 17:00 et 17:20 CEST.** Tout est vérifié par moi, y
compris ce qu'un pair avait mesuré avant. Aucun geste exercé, aucun processus
arrêté, aucune écriture hors ce dossier.

> La question posée est *« finir la migration et ne plus avoir de legacy »*. La
> réponse mesurée : **la séquence d'extinction n'a plus rien à faire — elle rend
> six fois « déjà archivée » et sort en 0.** Ce qui reste n'est plus un ORDRE,
> c'est une LISTE de quatre gestes, dont un seul est une signature.

---

## 1. Le verdict du script d'extinction, lancé normalement

```
bash scripts/eteindre-le-legacy.sh          ->  exit 0

  controle 1  le fichier monte dans le portage    ✅
  controle 2  les sept epreuves sans navigateur   ✅ x7
  controle 3  l'arbre                             ✅ arbre propre
  controle 4  le banc                             ✅ (temoin : 645 captures sur 30 j)
  controle 5  la sonde de vie                     ⚠  (voir §3)
  ✅ les quatre controles passent.
       ✅ deja archivee   x6      <- les SIX etapes
```

**Les six étapes de la séquence portent sur des chemins déjà vides ou déjà
archivés.** Mesure du pair `gestion-ssh-key-0b`, recoupée : sept chemins
absents, cinq répertoires vides, et **les 12 fichiers encore suivis sous
`legacy/` ne sont nommés par aucune étape** — recoupement zéro.

> **Une séquence dont toutes les étapes ont abouti se lit exactement comme une
> séquence qui attend.** *Sixième forme de péremption : ni devenue fausse, ni
> changée de sens, ni revenue — **épuisée**.* (formulation de `0b`)

---

## 2. ⛔ DEUX ARTEFACTS DE MA PROPRE MESURE, retirés

**Ils sont ici parce que chacun m'a fait publier un faux, et qu'ils ne se
ressemblent pas.**

### ⓐ J'ai lu les sorties d'un script que j'avais moi-même déplacé

Pour extraire ses étapes, je l'ai chargé par `bash -c 'source …'`. Il m'a rendu
*« le montage n'est plus déclaré »* et **sept épreuves ABSENTES**. J'allais
signaler un script d'extinction inopérant.

```
scripts/eteindre-le-legacy.sh:60   cd "$(dirname "$0")/.." || exit 2
  source via `bash -c`  ->  $0 vaut « bash »  ->  dirname = "."  ->  cd ..
  => le script a tourne dans le PARENT du depot
```

**Tout était « absent » pour cette seule raison.** *Un script qui calcule sa
racine depuis `$0` change de sujet quand on change sa manière de l'appeler — et
il ne le signale pas : il mesure très correctement un autre arbre.*

### ⓑ J'ai alarmé sur mon propre correctif, trompé par ma propre documentation

`docker-compose.yml:130-144` porte un long commentaire : *« CETTE SONDE A
CERTIFIÉ UNE APPLICATION MORTE […] elle certifiait qu'Apache REDIRIGE, jamais que
l'application RÉPOND. »* J'ai lu ça et cru le portage certifié par une sonde
vide.

**Le défaut est corrigé, à la ligne suivante, et c'est moi qui l'ai corrigé :**

```
:145  test: ["CMD","curl","-fsk","https://localhost:443/up","-o","/dev/null"]
      -> depuis le conteneur : /up rend 200 · un chemin invente rend 404
      -> la sonde DISCRIMINE
:144  « Releve par la session 8, temoin du chemin invente par la session 7 »
```

> **Un commentaire qui narre le défaut qu'il a corrigé se lit comme un défaut
> vivant.** Troisième occurrence de cette forme aujourd'hui — et celle-ci est la
> plus instructive : *j'ai été trompé par ma propre documentation de mon propre
> correctif, quelques heures après l'avoir écrite.*

---

## 3. Le seul signal de santé réellement faux, et il est borné

```
docker-compose.yml:48   test: curl -fsk https://localhost:443/auth/login.php
depuis rootwarden_php   /auth/login.php  ->  404
legacy/auth/login.php   absent     ·     legacy/_deprecated/auth/login.php  PRESENT
docker ps               rootwarden_php   Up 45 hours (UNHEALTHY)
```

**C'est la récidive du faux UNHEALTHY qui a coûté 21 heures le 2026-09-05**, pour
la même cause : l'étape ⑤ a archivé la cible de la sonde.

**⚠ Et il ne bloque rien — mesuré, avec témoin :**

```
sur la configuration FUSIONNEE (-f base -f prod), rendue en JSON par compose
lui-meme et lue par un analyseur — PAS au motif :

  services            4 : db, laravel, php, python
  blocs depends_on    3 : laravel -> db · php -> db, python · python -> db
  « php » CIBLE d'un depends_on   NON
  « php » SERVICE declare         OUI
  TEMOIN : service inexistant rendu ?  NON  (l'instrument sait rendre le vide)
```

⚠ **DEUXIEME RECTIFICATION DE CE §, et elle porte sur ma premiere.** Mon
enumeration disait `laravel -> db, resources` et `php -> db, python, resources`.
**`resources` n'est pas un service** : c'est `deploy.resources` (limites CPU et
memoire), present dans les quatre services. Releve par `0b`, verifie ici par
analyseur. *Et c'est indiscernable de toute sonde par fenetre ou indentation :*

```
:33  indent=4   depends_on:          :53  indent=4   deploy:
:34  indent=6     db:                :54  indent=6     resources:
```

**Meme profondeur, meme forme.** Ma sonde collectait les cles a l'indentation 6
dans une fenetre de 400 caracteres apres `depends_on:` — elle ramassait
`deploy.resources` des que les deux blocs se suivaient.

⛔ **Et le point qui porte sur ma RETRACTATION elle-meme.** J'avais signale que
la commande ayant produit cette mesure etait corrompue (mes backticks avaient
execute `config`). **J'ai retire le code de sortie et GARDE l'enumeration.**

> **Quand on retire une mesure comme cassee, tout ce qu'elle a produit est
> suspect — pas seulement la partie ou la casse etait VISIBLE.** *Le code de
> sortie etait manifestement faux, donc retracte ; l'enumeration etait
> plausible, donc conservee. La retractation s'est arretee la ou le defaut
> cessait de se voir.* (formulation de `0b`)

*Precision qui ne m'excuse pas mais situe le mecanisme : la sortie de `compose
config` etait valide — c'est mon LECTEUR qui sur-collectait. Le defaut etait donc
independant de la commande cassee, ce qui rend la lecon plus large, pas plus
etroite : deux defauts distincts dans une meme mesure, et j'en avais retire un
seul.*

⚠ **Et une borne que je dois à `0b` (`131e886c`), parce qu'elle change ce que la
mesure PROUVE sans changer la conclusion.** Mon premier relevé disait « 0
`depends_on php` » en s'appuyant sur un témoin (`db` -> 3) pris dans le SEUL
`docker-compose.yml`. Or **`docker-compose.prod.yml` ne contient AUCUN
`depends_on`, toutes cibles confondues** : l'affirmation y était vraie **à vide**,
et un lecteur l'aurait prise pour une garantie sur la production.

*C'est l'universelle négative vraie à vide, appliquée à ma propre mesure.* **La
forme qui referme est celle ci-dessus : mesurer la configuration FUSIONNÉE**, où
`depends_on` est conservé et le témoin réel — l'énoncé ne dépend plus de quel
fichier déclare quoi. `prod.yml` est un calque, pas un fichier autonome.

> **Donc `./maj.sh` et tout redémarrage démarreraient.** *Un `unhealthy` qui ne
> gouverne aucune dépendance coûte de l'attention, pas de la disponibilité — et
> l'attention est ce qui a coûté 21 heures la première fois.*

**Il se résout avec `patch 07`, qui supprime le service.** Aucun geste séparé.

---

## 4. RECTIFICATION de E-507 : ma précondition gardait le mauvais geste

J'ai écrit que le montage de `legacy/version.txt` est une précondition à
**`patch 07`**. **C'est faux, et le patch le montre :**

```
patch 07  ->  docker-compose.yml + docker-compose.prod.yml, 95 lignes retirees
              retire le service `php`, ses ports, ses volumes, ses depends_on
              retire  - ./legacy:/var/www/html
  mention de version.txt dans le patch :  AUCUNE
```

**Après `patch 07`, le portage garde son montage et `legacy/` existe toujours :
le pied de page continue d'afficher `2.0.183`.** La précondition garde le geste
**suivant** — celui qui retirera le répertoire `legacy/`, `_deprecated/` ou le
vhost. *Nommer le mauvais geste aurait fait classer la précondition « déjà
satisfaite » par le prochain lecteur* (le point est de `0b`, et il est juste).

**Et une correction que je dois à `0b` en retour** : `patch 07` **a** encore un
objet — `php:` est déclaré à `docker-compose.yml:8` et
`docker-compose.prod.yml:58`.

---

## 5. LES QUATRE GESTES QUI RESTENT, dans l'ordre

```
① SIGNER ET APPLIQUER patch 07
     supprime le service php (2 fichiers compose, 95 lignes)
     -> supprime AUSSI le faux UNHEALTHY de §3, sans geste separe
     -> apres lui : plus aucun conteneur ne sert le legacy

② PLACER LE NUMERO DE VERSION           precondition au geste ③
     ecrire le numero cote portage, le faire suivre ou produire au demarrage,
     PUIS basculer le montage. L'ordre n'est pas commutatif :
       laravel/version.txt = 0 octet, NON suivi (.gitignore:144)
       legacy/version.txt  = 8 octets, NON suivi (.gitignore:162)
     repli garde par construction : /^\d+\.\d+\.\d+$/ sinon null
       -> « version inconnue », jamais du contenu brut. Casse GRACIEUSE.

③ RETIRER LE REPERTOIRE ET LE VHOST     l'etape ⑥ dit « EN DERNIER »
     12 fichiers suivis, orphelins : 2 .htaccess, openapi.yaml, tailwind.css,
     htmx.min.js, utils.js, favicon, 3 logos, composer.json/.lock
     + 214 sous _deprecated/  + 767 sous vendor/ (« Require all denied »)
     l'ErrorDocument `_sortie.php` part avec le vhost

④ CORRIGER LE GARDE DU CONTROLE 1       ne bloque rien, mais il MENT
     voir §6
```

---

## 6. Le garde du contrôle 1 : deux défauts, d'inégale gravité

Relevé par `0b` (`b18ed8a5`), vérifié ligne à ligne par moi. **Ce n'est pas mon
fichier** — je n'écris que dans `docs/migration/`.

```
:102   if git ls-files "$p" | grep -qx 'legacy/version.txt'; then
```

**ⓐ Le prédicat est mort, et c'est le fail-open.** `git ls-files` ne liste que les
fichiers **suivis**, et `.gitignore:162` nomme `legacy/version.txt`
explicitement. Mesuré : `git ls-files legacy` rend 227 fichiers, **0** nommant
`version.txt`. **La boucle ne peut jamais refuser.**

> **La décision qui protège le fichier — ne pas le suivre, parce qu'il est
> dérivé — est exactement celle qui aveugle le garde écrit pour le protéger.**
> (`0b`) *Le prédicat juste ne passe pas par git : le fichier existe sur DISQUE
> et pas dans l'index.*

**ⓑ Le `✅` de `:108` est hors de la boucle**, donc inconditionnel : si le refus
se déclenchait, la sortie porterait `⛔ … REFUS` **et** `✅ aucune étape ne
l'emporte`. *Corriger ⓐ seul produirait un script qui se contredit.*

⚠ **Mais ⓑ n'est pas un fail-open, et je le dis plutôt que de l'aligner sur
ⓐ** : `ko` est bien consulté à `:202` (`⛔ $ko contrôle(s) refusent … exit 1`).
Le verdict agrégé reste juste ; c'est le message local qui mentirait. *Septième
occurrence du détail affiché du mauvais côté de sa condition, et la première dans
un garde — où le rôle est précisément de rester juste quand les portées
changent.*

---

## 7. Ce que ce dossier ne dit pas

**Aucun des quatre gestes n'est à moi.** Périmètre d'écriture :
`docs/migration/DECISIONS-DSI.md` et `docs/migration/DOSSIER-*.md`.

**Et aucun n'a été exercé** : `patch 07` est une signature, ② et ③ touchent le
socle, ④ est un script d'une autre session. *Le produit est fini ; ce qui reste
est de l'outillage et un répertoire à retirer.*
