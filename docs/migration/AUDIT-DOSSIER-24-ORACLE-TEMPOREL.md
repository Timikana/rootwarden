# AUDIT — DOSSIER-24 : l'oracle temporel de `/mot-de-passe-oublie`

    Session      5 — securite, LECTURE SEULE
    Mesures      2026-09-06, entre 11:10 et 11:20 CEST
    Perimetre    aucune ecriture dans `laravel/`, aucune sonde reseau
    Statut       QUALIFIE — deux constats remontes a l'exploitant, un refus de perimetre

> **Ce document ne pose pas le correctif.** *Il dit ce qui est arme, ce qui ne
> l'est pas, ce que je n'ai pas pu mesurer, et pourquoi le `Dockerfile` ne
> m'appartient pas.*

---

## 1. Ce qui a change AUJOURD'HUI, et que le dossier ne disait pas

    srv-docker.env        modifie  2026-09-06 11:05:49 +0200
    ligne 242             MAIL_MAILER=smtp

**Le dossier DOSSIER-24 decrit un oracle conditionne a l'armement du SMTP.
L'armement a eu lieu ce matin.** *Le fichier porte, juste au-dessus de la
ligne, un commentaire qui cite DOSSIER-24 et accepte l'oracle en connaissance
de cause :* « le legacy, lui, ENVOYAIT DEJA ».

⚠ **Cet arbitrage est un effet SORTANT vers un service externe.** *C'est la
meme classe que S7b, et par la regle du depot il appartient a l'exploitant.*
**Je ne conteste pas la decision ; je constate qu'elle est prise et je verifie
que l'exploitant la connaisse, parce que je ne l'ai pas vu la rendre.**

### 1.1 Les destinataires ne sont pas de test

    MAIL_FROM   test@timikana-heero.fr
    MAIL_TO     timi.du.10@gmail.com      <- boite personnelle reelle
    MAIL_SMTP_HOST  ssl0.ovh.net          <- fournisseur externe reel

**Une page PUBLIQUE (`/mot-de-passe-oublie`, liee depuis l'ecran de connexion)
peut desormais declencher un envoi vers une adresse reelle, par un fournisseur
reel, sans aucune session.** *La limite de debit existe (`jetons->autorise()`
par IP, controlee AVANT de savoir si l'adresse existe — c'est bien fait), mais
elle borne le volume, pas la nature de l'effet.*

---

## 2. SEC-016 — l'oracle d'enumeration de comptes

    GRAVITE    MOYENNE  (divulgation ; ni execution, ni elevation)
    SURFACE    POST /mot-de-passe-oublie — page PUBLIQUE, aucune session

### PRECONDITIONS EXACTES

    1. `config('mail.default')` hors de TRANSPORTS_LOCAUX   -> ARME depuis 11:05:49
    2. SAPI sans `fastcgi_finish_request()`                 -> mod_php, VRAI cote fichiers
    3. le cadrage de la reponse HTTP se termine APRES le travail differe  -> NON MESURE

**(1) et (2) sont mesures. (3) ne l'est pas, et (3) est ce qui fait la
difference entre un defaut structurel et un oracle exploitable.**

### CE QUE J'AI MESURE, ET COMMENT

**(1)** `srv-docker.env:242` = `smtp` ; `docker-compose.yml:86-87` passe ce
fichier au service `laravel` en `env_file` ; `laravel/bootstrap/cache/` ne
contient **pas** de `config.php` et `laravel/docker-entrypoint.sh:41-44` refuse
deliberement `config:cache`. *Donc `env('MAIL_MAILER')` lit l'environnement du
PROCESSUS a chaque requete, et `.env` (qui porte `log`) perd — exactement comme
`ReinitialisationController` le documente.*

**(2)** `laravel/Dockerfile:15` = `FROM php:8.4-apache`. **Zero occurrence** de
`fpm`, `proxy_fcgi` ou `fastcgi` dans le `Dockerfile` et les deux `compose`.
*Sous `apache2handler`, `Response::send()` tombe sur la branche
`closeOutputBuffers(0, true) + flush()` : les tampons sont vides, la connexion
reste OUVERTE, puis `terminate()` execute les rappels `app()->terminating()`.*
**La poignee TLS vers OVH part donc a l'interieur du cycle de la requete. Ce
point du dossier est exact.**

### ⚠ CE QUE JE N'AI PAS MESURE — ET POURQUOI CA COMPTE

**Que le travail parte AVANT la fin du cycle ne prouve pas que le client puisse
le voir.** *Si Apache a deja emis un `Content-Length` et pousse le corps
complet, un client qui lit ce nombre d'octets rend la main avant la poignee
SMTP : l'ecart existe dans le processus et pas au chronometre de l'attaquant.
S'il n'y a pas de `Content-Length` (cadrage decoupe), le client attend la
fermeture, et l'ecart devient lisible.*

**Je ne peux pas trancher sans une mesure au reseau, et une mesure au reseau est
interdite ici pour la bonne raison** : *la branche « adresse connue » exige une
adresse REELLE — donc un courriel reel vers une personne reelle.* **Sonder cet
oracle, c'est l'actionner.**

> **C'est la regle du temoin capable de temoigner, appliquee contre moi :**
> *tant que personne n'a montre l'ecart, « il n'y a pas d'ecart » et « je ne sais
> pas mesurer l'ecart » rendent la meme sortie.* **Je ne classe donc pas
> SEC-016 « exploitable ». Je le classe « arme, cadrage non mesure ».**

### UN COMPTE REEL L'OCCUPE-T-IL AUJOURD'HUI ?

**Non — aucune trace d'exploitation, et je n'ai pas les moyens d'en chercher
une : l'oracle ne laisse par construction aucune trace distincte d'une demande
de reinitialisation ordinaire.** *La limite par IP journalise les demandes ;
c'est la seule piste, et elle ne distingue pas un balayage d'un usage.*

⚠ **ET IL Y A UNE INCONNUE QUE SEUL L'EXPLOITANT PEUT LEVER :** *le conteneur
`rootwarden_laravel` a-t-il ete RECREE depuis 11:05:49 ?* **`env_file` n'agit
qu'a la creation. Je n'ai pas acces au socket docker (permission refusee), donc
je ne sais pas si l'etat opere correspond au fichier.** Une commande le dit :

    docker inspect rootwarden_laravel --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^MAIL_MAILER='

    absent ou `log`  -> le repli s'applique, SEC-016 est INERTE aujourd'hui
    `smtp`           -> SEC-016 est ARME, et (3) reste la seule inconnue

---

## 3. Le correctif : je confirme le choix, je refuse d'ecrire le fichier

### 3.1 La hierarchie tient

    accepter        laisse l'oracle sur une page publique
    desarmer        retire la reinitialisation a qui a perdu son mot de passe
    poser php-fpm   rend l'ecart INEXPRIMABLE, ne coute aucune capacite

**`fastcgi_finish_request()` termine la reponse — cadrage compris — avant que
`terminate()` ne parte.** *L'inconnue (3) disparait alors, au lieu d'etre
bornee : c'est la difference entre fermer et controler, et c'est pourquoi
`php-fpm` est la bonne issue et pas seulement la plus confortable.*

⚠ **Et « desarmer » a bien le faux remede annonce :** *modifier `.env` ne
changerait rien, il perd contre l'environnement du processus.* **Le seul levier
est `srv-docker.env` PUIS la recreation du conteneur.** *Le controle qui le dit
existe deja et produit un evenement (`Log::warning`) au lieu de dormir dans un
commentaire — c'est bien fait, et c'est ce qui m'a permis de dater l'armement.*

### 3.2 ⛔ POURQUOI CE N'EST PAS MOI QUI POSE LE `Dockerfile`

**Mon perimetre d'ecriture tient de l'exploitant, et il en tient UN SEUL :
`iptables`.** *Aucune session ne peut l'etendre — pas meme celle qui coordonne,
pas meme pour un correctif que je juge bon.* **« Tu poses le fichier, tu ne
reconstruis pas » deplace le geste, pas le perimetre : ecrire `laravel/Dockerfile`
sur `Migration-Laravel`, c'est modifier la branche.**

*Et la regle de fond est la meme que celle qui protege ce depot depuis le
debut :* **une session ne valide pas seule une modification de securite qu'elle
vient d'ecrire.** `5f` certifierait — mais c'est la moitie relecture du probleme,
pas la moitie perimetre.

**Ce que je livre a la place : la specification, mesuree, ci-dessous.**

---

## 4. Specification pour la session qui detient `laravel/`

### 4.1 La forme

**Mesurer plutot que supposer, sur trois points qui ont chacun un cout :**

    a) php:8.4-fpm + un Apache separe (proxy_fcgi)
       -> deux services, deux images ; le vhost TLS que `c1` prepare
          change alors de conteneur. COLLISION A ARBITRER AVANT D'ECRIRE.

    b) image apache actuelle + php-fpm dans le MEME conteneur
       -> un seul service, `compose` inchange, `c1` garde son vhost.
          Coute un superviseur de processus, ce que l'image officielle
          n'offre pas.

    c) php:8.4-fpm + serveur web deja present ailleurs
       -> ne s'applique pas : le service est autonome par conception.

⚠ **Le `read_only: true` de `docker-compose.prod.yml:126` et les sept `tmpfs`
qui le suivent sont ecrits pour Apache.** *`php-fpm` ecrit ailleurs
(`/var/run/php`, son socket, son pid) : les chemins doivent etre revus dans la
meme passe, sinon la production ne demarre pas — et le defaut se manifestera
comme un 500 generique, exactement comme les 28 `Utime failed` du 2026-09-03.*

### 4.2 Le temoin — STRUCTUREL, jamais reseau

**Ce qu'il faut prouver n'est pas « la reponse est rapide » : c'est « le travail
differe s'execute APRES que la reponse soit terminee ».**

    ce qui le mesure     `function_exists('fastcgi_finish_request')` dans le SAPI SERVI
    ce qui le REFUTE     la fonction absente -> le rappel `terminating()` reste
                         dans le cycle, quelle que soit l'image declaree

> **« Toucher une table n'est pas implementer le geste », applique ici :**
> *changer `FROM` n'est pas poser `php-fpm`.* **Le temoin doit interroger ce que
> le conteneur SERT — `php_sapi_name()` et la presence de la fonction — et non
> lire le `Dockerfile`.** *Une assertion sur le fichier passerait au vert sur une
> image qui n'a jamais ete reconstruite.*

**Et le temoin doit savoir echouer** : *sur le conteneur d'aujourd'hui il doit
RENDRE ROUGE.* Un temoin qui passe au vert avant le correctif ne mesure rien.

### 4.3 L'ordre avec `c1`

**`c1` touche `laravel/Dockerfile` pour le vhost TLS ; ce correctif le touche
pour le SAPI.** *La forme (a) deplace le vhost dans un autre conteneur : les
deux travaux ne sont alors plus superposables, ils sont sequentiels.*
**L'ordre se decide avant d'ecrire, et il depend du choix de forme — donc le
choix de forme vient en premier.**

---

## 5. ⚠ CONSTAT HORS DOSSIER — une identification a renouveler

**En mesurant `srv-docker.env`, j'ai affiche en clair le mot de passe SMTP
qu'il contient (`MAIL_SMTP_PASSWORD`, ligne 250).** *C'est ma faute : j'ai
filtre sur `^MAIL` sans masquer, sur un fichier dont je savais qu'il porte des
secrets. Les mesures suivantes sont masquees ; celle-la ne peut pas etre
reprise.*

    le fichier N'EST PAS suivi par git   (`.gitignore:23` = `*.env`)
    aucun secret SMTP dans l'historique  (seul `srv-docker.env.example`, valeur VIDE)

**Le depot est propre. La divulgation est dans la transcription de session, pas
dans le code.** *Elle reste une divulgation :* **cette identification OVH est a
renouveler, et le compte `MAIL_SMTP_USER` a surveiller d'ici la.**

*Rien ne dit qu'elle a ete captee. La regle ne demande pas de preuve d'abus pour
faire tourner un secret expose — c'est precisement l'ordre inverse.*

---

## 6. Ce que je remonte, en clair

    1. l'envoi reel est ARME depuis ce matin 11:05:49, par un arbitrage
       que je n'ai pas vu rendre. Effet SORTANT -> appartient a l'exploitant.
    2. l'etat OPERE est inconnu de moi (pas d'acces docker) : une commande le dit.
    3. l'oracle est structurellement present ; son CADRAGE HTTP n'est pas mesure,
       et le mesurer reviendrait a l'actionner contre une personne reelle.
    4. `php-fpm` est la bonne issue, pour la raison donnee — je ne l'ecris pas.
    5. une identification SMTP est a renouveler, de mon fait.
