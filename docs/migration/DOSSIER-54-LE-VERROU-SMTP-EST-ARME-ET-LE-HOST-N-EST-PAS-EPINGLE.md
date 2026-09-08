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

---

# RECTIFICATION du 2026-09-08 11:45 — ce dossier se présentait comme une découverte

**Il n'en est pas une. Le dépôt portait déjà l'analyse complète, et l'ordre à
suivre.** Trouvé par `gestion-ssh-key-0b`, vérifié par moi :
`srv-docker.env.example`, lignes 90 à 143.

```
  ORDRE, ecrit dans le depot :
    1. ecrire A LA MAIN dans srv-docker.env : APP_URL=https://<hote joignable>:8443
    2. des lors env-merge est un NO-OP sur cette cle
    3. recreer le conteneur : l'environnement l'emporte sur laravel/.env
    4. verifier par artisan tinker : port 8443, https, ET un hote joignable
    5. SEULEMENT ENSUITE armer MAIL_MAILER=smtp
```

**`MAIL_MAILER=smtp` est armé et `APP_URL` n'est pas dans l'environnement du
conteneur : l'étape 5 a été faite avant les quatre autres.** Le fichier prévoit
même le piège que ma section 4 croyait signaler pour la première fois — *« dans
un courriel, `localhost` désigne la machine du DESTINATAIRE »* — et il explique
pourquoi `env-merge` est le tuyau qui dénature le remède : il ne complète que
les **absences**, donc si la clé manque au moment de la fusion, c'est la forme
dérivée qui est déposée.

> **Un dossier qui présente en découverte ce que le dépôt documentait déjà fait
> chercher un remède au lieu de faire suivre celui qui existe.**

## Et il datait mieux que moi le « mauvais port »

Ma section 3 dit `:8444` « mauvais port ». Le fichier dit mieux, ligne 104 :

> *« LE SENS DE 8444 S'EST INVERSÉ LE 2026-09-06. Avant cette date, `:8444`
> désignait le PORTAGE ; depuis l'échange de ports, il désigne le LEGACY. »*

**`APP_URL=http://192.168.0.245:8444` était donc JUSTE à l'écriture.** Elle est
devenue fausse le 06/09 sans que rien ne la touche — et elle a survécu aux trois
inversions de port rattrapées dans l'arbre **parce qu'elle vit dans
`laravel/.env`, ignoré par git : aucune garde fondée sur l'arbre ne pouvait la
lire.**

## La mesure que je n'avais pas, et qui précise le remède

Rendue par `gestion-ssh-key-4f` :

```
route() HORS requete (CLI)   ->  http://192.168.0.245:8444/reinitialiser?uid=1&jeton=x
route() EN   requete         ->  suit l'en-tete Host
```

**Donc `APP_URL` ne mord que hors requête**, et le lien du courriel est bâti *en*
requête (`:156`). Poser `APP_URL` selon l'ordre documenté est **nécessaire et non
suffisant pour ce flux-là** : il faudrait en plus `trustHosts` — qui rejette un
hôte inconnu — ou un `URL::forceRootUrl(config('app.url'))` dans un fournisseur.
**Il y a zéro des deux.**

⚠ Et la conséquence opérationnelle que `4f` nomme, qui est le vrai danger :
*si quelqu'un déplaçait l'envoi vers une file ou une tâche planifiée — ce que le
docblock du contrôleur dit avoir envisagé — le lien deviendrait
`http://…:8444`, en clair et vers le legacy, et il partirait pour de vrai.*
**Croire le mailer désarmé est exactement ce qui autoriserait ce déplacement.**

## ⛔ LA LIMITE DE MA PROPRE MESURE, signalée par `0b`

**Ma sonde de l'en-tête `Host` a été jouée avec `APP_URL` ABSENTE de
l'environnement.** Elle ne prouve donc pas que la poser ne suffirait pas. Que
`route()` en requête ignore `app.url` même quand elle est posée est un
**raisonnement** sur le générateur d'URL, pas une mesure — et `4f` l'a mesuré en
CLI, c'est-à-dire hors requête, pas avec les deux conditions réunies.

**Trancher demanderait de forger un en-tête `Host` sur une requête vivante avec
`APP_URL` posée.** C'est un test, pas une lecture, et il exige la recréation qui
n'est pas à moi. *Je marque le régime plutôt que de laisser une inférence porter
l'autorité d'une mesure.*

**L'ordre pratique ne dépend pas de ce verdict** : désarmer `MAIL_MAILER`, ou
appliquer les étapes 1 à 4 puis vérifier avec un `Host` forgé, avant qu'un autre
courriel puisse partir. *Le jeton de réinitialisation est le seul secret que ce
produit envoie hors de la machine.*

