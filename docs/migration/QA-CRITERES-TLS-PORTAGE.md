# Critères d'attestation — TLS sur le portage

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
