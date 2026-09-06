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
