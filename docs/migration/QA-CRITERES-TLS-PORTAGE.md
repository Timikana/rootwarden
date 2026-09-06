# Critères d'attestation — TLS sur le portage

> ✅ **ATTESTÉ le 2026-09-06 à 13:11 — T1 à T5 verts, mesurés au réseau après reconstruction.**
> Voir le commit d'attestation pour le détail et pour les quatre points **non** attestés.



**Écrits AVANT toute lecture de la configuration de `gestion-ssh-key-c1`.** État de départ
mesuré à l'instant de la rédaction, indépendamment de son relevé :

    rootwarden_php      8080->80, 8443->443
    rootwarden_laravel  8444->80        SEUL, aucun 443

    https://localhost:8444/connexion   -> 000
    http://localhost:8444/connexion    -> 200
    https://localhost:8443/auth/…      -> 200        TEMOIN, l'instrument voit du TLS

    HSTS envoye par le legacy   max-age=31536000; includeSubDomains; preload
    HSTS envoye par le portage  aucun

---

## T1 — Le TLS RÉPOND, et la session s'établit dessus

`https://…:8444/connexion` doit rendre **200**, pas 000. Et **la page seule ne suffit pas** :
une session doit s'établir et un TOTP passer, sinon on aura certifié qu'un port écoute, pas
qu'un portail fonctionne.

## T2 — ⚠ LA REDIRECTION DOIT ABOUTIR, PAS SEULEMENT PARTIR

**Le critère qui compte, parce que le legacy échoue exactement là.** Mesuré :

    http://localhost:8080/auth/login.php  -> 301  Location: https://localhost:8080/…
    cette cible                            -> 000     rien n'ecoute en TLS sur 8080

`RewriteRule … https://%{HTTP_HOST}/$1` **garde le port de la requête** : le conteneur voit
80/443, l'hôte publie 8080/8443, la redirection renvoie vers un port sans TLS.

> **Un 301 est un succès pour qui lit le premier code, et une panne pour qui suit le lien.**
> J'asserte donc le code FINAL après redirection (`curl -L`), jamais le premier.

Et je vérifie que le port de destination est **dérivé de la configuration**, pas de
`%{HTTP_HOST}` — sans quoi le défaut est recopié plutôt que porté.

## T3 — `SESSION_SECURE_COOKIE` : L'ORDRE EST UN CRITÈRE

Il ne doit **pas** être activé tant que T1 n'est pas vert au réseau. Un cookie `Secure` sans
TLS effectif coupe l'accès à **tout le monde** — *la garde qui mord et refuse tout le monde,
indiscernable d'une garde parfaite si on ne mesure que le refus.*

Une fois T1 acquis : les cookies `rootwarden-session` et `XSRF-TOKEN` portent `Secure`, en
plus de `HttpOnly` et `SameSite`.

## T4 — AUCUN HSTS sur le portage, et c'est une DÉCISION

`c1` ne pose pas de HSTS. **Je gèle cette absence** plutôt que de la constater : un HSTS posé
plus tard doit l'être par arbitrage, pas par recopie du legacy.

⚠ **Motif mesuré, et il déborde déjà** : HSTS est lié à l'**hôte**, pas au port (RFC 6797).
Le legacy envoie `max-age=31536000; includeSubDomains; preload` sur `localhost:8443` — donc
tout navigateur l'ayant visité force `https://` sur `http://localhost:8444`, **qui rend 000**.
*Le portage est déjà inatteignable pour qui a ouvert le legacy dans le même navigateur.*

**Borne, et elle tient** : les navigateurs n'appliquent pas HSTS à une adresse IP littérale.
En production (`192.168.0.245`) l'en-tête est ignoré — **ça mord sur `localhost`, donc sur les
postes de développement, pas sur les utilisateurs.**

**Et aucune suite ne peut le voir** : Puppeteer part d'un contexte neuf, donc sans état HSTS.
*C'est une classe de défaut que le banc ne peut pas atteindre par construction* — à ranger
avec « les deux champs sur une seule ligne, vu à l'image ».

## T5 — Le formulaire pointe en `https`

Mesuré aujourd'hui : `<form method="POST" action="http://localhost:8444/connexion">`. Après
le geste, le schéma doit être `https`. *Un formulaire en clair sur une page servie en TLS
dégrade sans que la barre d'adresse le dise.*

---

## Ce que je n'attesterai PAS — dit maintenant, pas au moment de conclure

- **Les en-têtes de sécurité** (CSP, `X-Frame-Options`, `Referrer-Policy`). Le legacy en porte
  quatre que le portage n'a pas ; `c1` les déclare **hors de ce lot** parce que `/connexion`
  sert du script inline et qu'une CSP mal calibrée casserait la page. **C'est un écart réel,
  déclaré, et son absence dans ce lot ne vaut pas certification.**
- **La validité du certificat.** Auto-signé : je mesure que le TLS répond, pas qu'il est de
  confiance.
- **L'état HSTS des navigateurs déjà empoisonnés.** Il vit dans le poste, pas dans le dépôt.
  Un développeur bloqué devra le purger lui-même ; aucune mesure d'ici ne le dira.
- **Le comportement après l'échange de ports.** Ce sont deux gestes ; les certifier ensemble
  ferait qu'un vert de l'un couvrirait un rouge de l'autre.


---

# ANNEXE HSTS — trois versions en une matinée, et seule la troisième est mesurée

**Chronologie assumée, parce que la forme de l'erreur vaut plus que l'erreur.**

    v1  ALARME       « le portage est deja inatteignable pour qui a ouvert le legacy »
    v2  RETRACTATION « mesure au navigateur : aucun surclassement »
    v3  CE QUI SUIT  la mesure de v2 N'AVAIT AUCUNE VALEUR PROBANTE

## ⛔ v2 était sans valeur : l'instrument est AVEUGLE, témoin positif à l'appui

Le gTLD **`.dev` est préchargé** dans la liste HSTS de Chrome : il doit être surclassé sans
aucun réseau. Mesuré, dans les **deux** modes :

    http://rootwarden.dev:8444   SANS --ignore-certificate-errors  -> code=200, NON surclasse
    http://rootwarden.dev:8444   AVEC le drapeau                    -> code=200, NON surclasse

**Ce navigateur ne surclasse rien, même là où la spécification l'exige.** Donc « aucun
surclassement sur `localhost` » ne disait rien. *« Aucun surclassement » et « mon instrument
ne sait pas voir un surclassement » sont la MÊME sortie* — la règle que je porte depuis des
jours, et que j'ai enfreinte en la connaissant.

⚠ **Et la reproduction n'a rien attrapé** : j'avais refait la mesure de `c1` indépendamment,
et j'ai obtenu le même résultat **avec le même angle mort**. *Reproduire une mesure avec le
même instrument ne la valide pas ; ça la répète.*

## ✅ CE QUI EST ÉTABLI — par le MAGASIN, pas par le comportement

Lecture directe de `<profil>/Default/TransportSecurity`, trois profils :

    A  visite https://localhost:8443/auth/login.php        1 entree
    B  visite https://rootwarden.test:8443/…  (hors localhost)  1 entree
    C  CONTRE-EPREUVE : n'a visite QUE about:blank         1 entree

    la MEME dans les trois :  host = 8/RrMmQlCD2Gsp14wUCE1P8r7B2C5+yE0+g79IPyRsc=
                              expiry - observed = 31536000  (exactement 1 an)

⚠ **Cette entrée ressemblait trait pour trait à celle du legacy** — `force-https`,
`include_subdomains`, et un `max-age` d'un an **identique au sien**. *Tout concordait.*

**Elle est `accounts.google.com`**, semée par Chrome à la création du profil. Empreinte
calculée (SHA-256 du nom en forme DNS, base64) et comparée :

    accounts.google.com   8/RrMmQlCD2Gsp14wUCE1P8r7B2C5+yE0+g79IPyRsc=   <<< CORRESPOND
    localhost             +5SucHeyam84+YKFvzbLSOOu8EIOl0hrqv6OPw5r2/Q=   ABSENT du magasin
    rootwarden.test       2shoigkPzIdaMDJxfT3Fx/R7AqeWzXKMWhtEqWj5WSM=   ABSENT du magasin

**Le magasin est vivant et non vide** — l'entrée semée le prouve — **et `localhost` n'y est
pas.** L'absence constatée n'est donc pas celle d'un instrument muet : c'est une absence
mesurée, avec son témoin positif.

> *La coïncidence du `max-age` à la seconde près est ce qui rend ce faux témoin dangereux :
> 31536000 est une durée d'un an, la valeur la plus banale qui soit. Deux sources sans rapport
> produisaient le même chiffre.*

## ⛔ CE QUI N'EST PAS ÉTABLI : LA CAUSE

**RFC 6797 §8.1** — un agent ne doit pas traiter l'en-tête si la connexion présente des
erreurs de certificat — reste **plausible et non isolée**. Le legacy sert bien un auto-signé
(`subject == issuer`, `CN=localhost`, vérifié). Mais `localhost` est aussi un cas spécial, et
rien dans mes mesures ne départage les deux.

## ⚠ CONSÉQUENCE POUR L'ATTESTATION — une exculpation qui EXPIRE

**Si la cause est le certificat, alors installer un certificat APPROUVÉ fait revenir le
problème en entier** — et c'est la trajectoire prévue de ce portail.

**Donc ceci n'est pas un acquis durable, et la borne doit dire quand elle expire :**

> « Aucun état HSTS n'a été enregistré pour ces hôtes **tant que le certificat n'est pas
> approuvé** — magasin inspecté, empreintes calculées et absentes, **témoin positif sur
> l'inspection du magasin**. Le contrôle **comportemental**, lui, **échoue** : ce navigateur ne
> surclasse rien, même sur un domaine préchargé. Cause non isolée. »

*Une exculpation sans date d'expiration se relit comme une garantie.*

⚠ **Et ma première rédaction disait « témoin positif présent » — vrai d'UN instrument sur
deux.** Deux contrôles, un seul a son témoin :

    lecture du MAGASIN          temoin POSITIF (l'entree `accounts.google.com` est vue)
                                -> « localhost absent » est une vraie mesure
    COMPORTEMENT du navigateur  temoin positif ECHOUE (.dev non surclasse)
                                -> aucune mesure comportementale ne vaut

**Un lecteur de l'attestation n'a aucun moyen de savoir lequel** — il lira la formule courte,
pas les deux heures qui la précèdent. *C'est la forme dont on se fait avoir depuis ce matin :
le fait est juste, l'emballage laisse conclure plus large.* La formule longue est moins
élégante et elle dit **lequel**. *(Précision demandée par `c1` ; elle a raison.)*

## ⚠ T3 GAGNE UNE URGENCE : LE COOKIE DE SESSION TRAVERSE LE PREMIER SAUT

Mesuré aujourd'hui sur le portage servi :

    Set-Cookie: rootwarden-session=…   HttpOnly=OUI   Secure=⛔ NON
    Set-Cookie: XSRF-TOKEN=…           HttpOnly=NON   Secure=⛔ NON

Et `LARAVEL_URL=http://192.168.0.245:8444` — **en HTTP** — est lu par **19 sites du legacy
VIVANT**, surtout le menu latéral (`legacy/menu.php`), avec un repli `http://localhost:8444`.

Après reconstruction, chaque clic du menu legacy vers le portage part donc en **clair**, puis
prend le 301 vers `:8446`. `c1` écrit « aucun identifiant ne circule sur ce premier saut » :
**c'est inexact, et de peu — le cookie de session EST un identifiant, et il est joint à cette
première requête parce qu'il ne porte pas `Secure`.**

> **La fenêtre entre la reconstruction et T3 n'est pas neutre.** Elle n'expose ni mot de passe
> ni TOTP — le formulaire d'authentification, lui, sera servi en TLS — mais elle expose la
> **session déjà ouverte**, à chaque navigation depuis l'ancien portail.

**T3 reste APRÈS T1** — un cookie `Secure` sans TLS effectif coupe l'accès à tout le monde.

### ⛔ ET L'INTERVALLE PEUT ÊTRE NUL — le motif qui le retenait était FAUX

`c1` avait décliné de toucher `LARAVEL_URL` en disant que **« ça casserait les 87 suites en
plein travail »**. Elle a mesuré son propre motif et l'a retiré ; **je l'ai remesuré plutôt
que de ratifier sa correction** :

    LARAVEL_URL dans tests/e2e   1 ligne, et elle est un COMMENTAIRE
                                 -> 0 lecteur en code
    la variable reellement lue   `E2E_BASE`, 94 fichiers
    lecteurs REELS               legacy VIVANT : menu.php (16), head.php (2),
                                 _sortie.php (1)  = 19 lignes

**Aucune suite ne lit `LARAVEL_URL`.** *Une correction de sécurité avait été déclinée pour un
motif jamais mesuré, et le motif était faux.*

⚠ **Et sa remesure porte le bon nombre sur le mauvais nom** : elle cite `E2E_LARAVEL_BASE`
(94), la variable s'appelle **`E2E_BASE`**. *Qui referait la mesure avec le nom cité obtiendrait
ZÉRO et conclurait l'inverse — un chiffre juste rattaché à un identifiant faux se propage
mieux qu'un chiffre faux, parce qu'il résiste au premier contrôle.*

### La séquence, contrainte dans un seul sens

    1. l'exploitant reconstruit            -> 8446 ecoute en TLS
    2. je verifie T1 (200 + session)       -> la cible existe VRAIMENT
    3. LARAVEL_URL -> https://192.168.0.245:8446
       => plus AUCUN saut en clair depuis le menu legacy ; le cookie ne part plus nu
    4. SESSION_SECURE_COOKIE=true          -> T3

**L'étape 3 fait le gros du travail et ne dépend d'aucun drapeau de cookie.** L'inverser a
déjà été fait, et le dépôt en garde la trace :

    tests/e2e/archive.mjs:83
    « `LARAVEL_URL` valait `https://localhost:8444` alors que le portage ecoute en clair »

**Les 16 liens du menu legacy sont morts ce jour-là.** *Et l'incident est consigné dans le
commentaire d'une suite HORS LOT — donc là où aucun rejeu ne peut le rappeler.*

> La contrainte n'est pas « ça casse des suites ». C'est **« la cible doit exister avant qu'on
> y renvoie »** — la même famille que T3, et le même piège que la redirection cassée du legacy
> qui pointe vers un port sans TLS. **Trois fois la même erreur dans le même dossier.**

## CE QUI N'A JAMAIS BOUGÉ

    ✅ la redirection HTTP->HTTPS du LEGACY est cassee   (curl ET navigateur)
    ✅ le vhost du portage ne la reproduit pas — port derive de la configuration
    ✅ T2 tient : le code FINAL, jamais le premier. Fonde sur le defaut du legacy,
       jamais sur le HSTS.

## ⚠ LA LEÇON DE FORME, ET ELLE EST LA PLUS TRANSMISSIBLE

**Trois versions en deux heures : alarme, rétractation, rétractation de la cause.**

- La **v1** a été attrapée parce qu'elle **alarmait** — on relit ce qui accuse.
- La **v2** a été **ratifiée par moi**, parce qu'elle arrivait **en correction**. *Une
  correction se relit moins qu'une accusation* : elle a l'air d'être déjà le produit d'une
  vérification.
- La **v3** est venue d'une seule question : **« qu'est-ce que mon instrument m'a jamais
  montré de POSITIF ? »**

*C'est la seule question qui ait marché, et elle ne demande aucune connaissance du sujet.*

---

# ANNEXE v1/v2 — conservée pour la trace
# ANNEXE — ajoutée le 2026-09-06, puis ⛔ **RÉTRACTÉE le même jour**

## ⛔ CE QUE CETTE ANNEXE AFFIRMAIT, ET QUI EST FAUX

> « Le portage est déjà inatteignable pour qui a ouvert le legacy dans le même navigateur. »
> « Ton 301 ne s'exécutera JAMAIS pour ces navigateurs. »

**Les deux sont faux. Mesuré, profil Chrome PERSISTANT, deux processus distincts :**

    1) legacy en TLS      code=200   en-tete HSTS RECU : max-age=31536000;
                                     includeSubDomains; preload
    2) portage en CLAIR   code=200   url finale = http://localhost:8444/connexion
       SURCLASSEMENT ?    NON
       TEMOIN racine      code=200   (le navigateur navigue bien — l'instrument voit)

**L'en-tête est envoyé et il n'est pas appliqué.** Le portage reste joignable en clair après
une visite du legacy dans le même profil.

### Pourquoi — et je ne prétends pas avoir isolé LA cause

Deux raisons peuvent l'expliquer, et mon épreuve ne les départage pas :

1. **RFC 6797 §8.1** : un agent NE DOIT PAS traiter l'en-tête si la connexion présente des
   erreurs de certificat. Le legacy sert un **auto-signé** — vérifié : `subject == issuer`,
   `CN=localhost`. *La RFC que j'ai citée pour la partie qui servait l'alarme contient aussi
   celle qui la désamorce.*
2. **`localhost` est un cas spécial** dans les navigateurs (origine réputée sûre).

*Je le dis parce que « j'ai vérifié que c'est faux » et « j'ai compris pourquoi » sont deux
choses, et je n'ai que la première.*

## ⚠ POURQUOI CETTE RÉTRACTION COMPTE PLUS QUE L'ERREUR

J'avais écrit que l'annexe était sans danger **parce qu'elle ne faisait que RESTREINDRE**.
Le raisonnement sur le sens de l'ajout était juste, et **il ne protégeait pas de ce cas** :

> **Une restriction fondée sur un fait faux retire de la portée quelque chose qui marche.**
> J'aurais refusé d'attester « le portail est joignable » pour une raison inexistante — et le
> défaut RÉEL, la redirection cassée du legacy, serait resté couvert par le même geste.

**Le sens de l'ajout n'était pas le problème. La prémisse l'était, et ni `c1` ni moi ne
l'avions mesurée.** *Elle l'a introduite, je l'ai amplifiée d'un cran, et elle allait entrer
dans un document scellé sans que personne n'ait ouvert un navigateur.*

⚠ **Et un témoin a failli la confirmer pour la mauvaise raison.**
`http://localhost:8080` rend `net::ERR_SSL_PROTOCOL_ERROR`, ce qui ressemble exactement à un
surclassement HSTS. **C'en est un autre défaut** : le 301 cassé du legacy renvoie vers
`https://localhost:8080`, où un serveur en clair reçoit du TLS. *Deux causes différentes, une
seule trace — et j'aurais lu celle qui allait dans mon sens.*

## CE QUI SURVIT DE TOUT CELA

    ✅ la redirection HTTP->HTTPS du LEGACY est cassee   (curl ET navigateur)
    ✅ le vhost du portage ne la reproduit pas — port derive de la configuration
    ⛔ « le portage est deja inatteignable »              RETIRE
    ⚠ reserve etroite et MESURABLE : la reserve ne vaudrait que pour qui a
       AJOUTE le certificat auto-signe a son magasin de confiance. Ce n'est plus
       « qui a ouvert le legacy » — c'est une population qu'on peut nommer.

## T2 — l'exigence reste, et elle vaut indépendamment

**Le code FINAL après redirection, jamais le premier.** *Un 301 est un succès pour qui lit le
premier code et une panne pour qui suit le lien.* Cette exigence n'a jamais dépendu du HSTS ;
elle est fondée sur le défaut du legacy, mesuré deux fois et par deux instruments.

**Bornage de l'attestation, revu sur ce qui est mesuré :**

> « le serveur redirige HTTP vers HTTPS et la cible répond » — **et** « aucun état HSTS
> n'empêche l'accès depuis un navigateur dont le certificat n'est pas approuvé, mesuré sur
> profil persistant ».

## T2, moitié STATIQUE — mesurée sur `8862849`, et elle tient

    laravel/apache-ssl.conf.tmpl:44   RewriteCond %{HTTP_HOST} ^([^:]+)
    laravel/apache-ssl.conf.tmpl:45   RewriteRule ^/?(.*) https://%1:${LARAVEL_HTTPS_PORT}/$1 [R=301,L]

`%1` est l'hôte **sans son port**, le port vient de la configuration et non de la requête. Le
motif du refus de `%{HTTP_HOST}` est écrit lignes 28-30 : *un lecteur qui trouve la forme
trouve aussi pourquoi l'autre a été écartée.*
