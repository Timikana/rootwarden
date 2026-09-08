# DOSSIER-54 — Le verrou SMTP est armé, et l'en-tête `Host` n'est pas épinglé

**Mesuré le 2026-09-08 entre 11:05 et 11:25 CEST. Aucun courriel n'a été émis :
tout ce qui suit vient de requêtes `GET` et de lectures de configuration.**

> Ce dossier **périme le point ① de `DOSSIER-53`**. Ce point disait « ⛔ ne pas
> armer `MAIL_MAILER=smtp` — le seul verrou de sécurité ». Il est armé. La
> consigne est devenue un constat, et le constat a des conséquences.

---

## 1. La chaîne, maillon par maillon, avec la commande

| # | maillon | mesure |
|---|---|---|
| ① | le lien est bâti **en requête** | `ReinitialisationController.php:156` — `$lien = route('reinit.formulaire', ['uid' => …, 'jeton' => $clair])` |
| ② | `route()` suit l'en-tête `Host` | `GET /connexion` avec `Host: evil.example` → **3** URL absolues en `https://evil.example/…` ; avec le vrai hôte → **0** |
| ③ | rien n'épingle les hôtes | `trustHosts` / `TrustHosts` : **0 fichier** dans `laravel/app`, `laravel/bootstrap`, `laravel/config` |
| ④ | le courriel part **en ligne** | `Mail::raw` à `:219`, et le commentaire `:39` mesure que `QUEUE_CONNECTION=sync` fait que l'envoi s'exécute en ligne |
| ⑤ | le mailer est armé **et fonctionnel** | `mail.default = smtp`, `mail host = ssl0.ovh.net`, port 465, expéditeur réel, identifiants renseignés |

**Enchaînés : un `POST /mot-de-passe-oublie` portant un `Host:` forgé fait partir un
courriel réel dont le lien de réinitialisation pointe chez le demandeur. La
victime clique, le jeton part chez lui.**

### Le témoin, parce qu'un reflet peut venir d'ailleurs

Ma première sonde a mesuré un **301 d'Apache** (`Location: https://evil.example/connexion`)
et j'ai failli l'attribuer à Laravel. Ce n'est pas la même gravité : Apache qui
reflète un `Host` dans une redirection est une redirection ouverte ; Laravel qui
le reflète dans un lien **envoyé par courriel** est une prise de compte.

La sonde refaite attaque Laravel directement (`https://…:8443`, celui qui rend 200 —
`:8446` rend 404, c'est le legacy éteint) et compare deux hôtes. Le témoin est que
la page contient bien **3** `action=`/`href=` absolus générés par le cadriciel : sans
lui, « 0 occurrence » aurait pu vouloir dire « la page ne génère aucune URL ».

---

## 2. ⛔ CE QUE JE N'AI PAS OBSERVÉ

**Je n'ai pas vu un courriel partir.** Le maillon ⑤ est déduit d'une
configuration complète, pas d'un envoi constaté — parce que le constater
exigeait de soumettre le formulaire, ce qui envoie un **vrai** courriel à une
**vraie** personne. Je m'y refuse, et cette limite fait partie du résultat.

**Je n'ai pas mesuré l'exposition hors du LAN.** Le service écoute sur
`192.168.0.245:8443`, une adresse privée. Il faut donc un accès au LAN, ou une
redirection de port / un proxy inverse que je n'ai pas cherchés — **et que je ne
chercherai pas par un balayage.** C'est l'exploitant qui sait si ce port est
publié.

**Atténuations réelles, à mettre dans la balance** : le point d'entrée est limité
par IP (`$this->jetons->autorise($requete->ip())`), il ne révèle pas si un compte
existe, et l'attaquant doit connaître une adresse de courriel valide.

---

## 3. Un second défaut, séparé, trouvé en chemin

`laravel/.env` porte `APP_URL=http://192.168.0.245:8444`.

```
en clair       http://   alors que le service parle https
mauvais port   :8444     Laravel rend 200 sur :8443 ; :8444 est la redirection
la reference   srv-docker.env.example:143  ->  APP_URL=https://${SERVER_NAME}:${LARAVEL_HTTPS_PORT}
```

`APP_URL` ne gouverne pas le lien du courriel (bâti en requête, cf. ①), donc ce
défaut est **distinct** de la chaîne ci-dessus. Il gouverne tout ce qui est
généré **hors requête**. Le point ③ de `DOSSIER-53` demandait de poser `APP_URL`
à la main dans `srv-docker.env` : il n'y est pas, il est dans `laravel/.env`,
avec le mauvais schéma et le mauvais port.

⚠ `laravel/.env` est `-rw-r----- www-data www-data`. Ma première lecture a rendu
« absent » parce que `grep` a échoué en **code 2** (erreur de lecture) et non en
code 1 (aucune correspondance), et mon `2>/dev/null` a effacé la différence.
**Un fichier illisible et un fichier sans la ligne rendent la même sortie.**

---

## 4. Ce qui revient à l'exploitant, et ce que je recommande

Aucun des trois gestes ci-dessous n'est à moi : deux exigent une **recréation**
de conteneur (`env_file` est lu à la création), le troisième est un correctif de
sécurité sur un service vivant.

**① Désarmer le mailer — le moins coûteux, et il coupe le maillon ⑤.**
`MAIL_MAILER=log` dans `srv-docker.env`. Le seul usage du courriel dans le
portage est la réinitialisation ; la désarmer la rend inopérante, ce qui est
l'état que `DOSSIER-53` supposait déjà. **Recommandé si la réinitialisation
n'est pas attendue en service cette semaine.**

**② Épingler les hôtes — le correctif de fond, et il coupe le maillon ③.**
Armer `trustHosts` dans `laravel/bootstrap/app.php` avec la liste des hôtes
légitimes. ⚠ **Un épinglage dont la liste omet l'hôte réel fait répondre 400 à
toute requête** : sur un service vivant et un arbre monté en bind, l'erreur se
voit immédiatement en production interne. À éprouver avant, pas après.

**③ Corriger `APP_URL`** en `https://` et sur le port que Laravel sert
réellement, en suivant la forme de `srv-docker.env.example:143`.

**⛔ Et un geste d'hygiène qui n'attend rien** : le mot de passe de la boîte
`opnsense@…` a été exposé dans un fil de session (par un masquage trop étroit :
la variable s'appelle `MAIL_SMTP_PASSWORD`, le motif visait `MAIL_PASSWORD`).
Il n'est **pas** dans git — `srv-docker.env` n'est pas suivi, `.gitignore:23`
couvre `*.env`, 0 commit dans l'historique. **Le changer reste la bonne réponse.**

---

## 5. Décision consignée

**E-493 — Je ne touche à aucun des trois gestes.** Deux sont des recréations,
explicitement hors de mon périmètre ; le troisième est un correctif de sécurité
qu'une session ne valide pas seule, et qui casse le portail s'il est mal posé.
Je mesure, je consigne, je recommande. *Un correctif de sécurité posé sans
relecture sur un service vivant échange un risque contre un autre, et le second
est immédiat.*
