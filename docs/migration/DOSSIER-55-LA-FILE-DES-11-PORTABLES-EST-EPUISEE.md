# DOSSIER-55 — La file des 11 portables est épuisée, et ce n'est pas nous qui l'avons vidée

**Mesuré le 2026-09-08 entre 12:37 et 12:45 CEST.** Aucun geste exercé.

> La mission demande à chaque tour de relancer les sessions sur **une capacité
> précise à porter**, prise dans une file de onze, par risque croissant.
> **Il n'y a plus d'item dont l'implémentation manque.** Ce dossier le montre
> item par item, et dit ce qui reste — qui n'est pas du portage.

---

## 1. Les onze, un par un

| # | item | état | par qui, et la preuve |
|---|---|---|---|
| ① | apparier les 5 catalogues | **fait** | 5 sessions. bashrc 92 clés / 7 gestes · fail2ban 203 / 18 routes · politiques 73 / 4 gestes · serveurs 113 / 112 atteignables · sftp 65 / 4 familles |
| ② | créer un relevé planifié (ssh_audit) | **déjà porté** | `audit-ssh.js:705` `ecris('/ssh-audit/schedules', corps)` → `ssh_audit.py:819` |
| ③ | créer un groupe (groups R2) | **fonctionne, relayé** | `groupes.js:341` → passerelle `web.php:1222` → `groups.py:128`. **Arbitré NE PAS porter** : un écrivain natif sans retrait de `/groups` de `LISTE_BLANCHE` donnerait deux écrivains pour un geste |
| ④ | test de connexion puis import CSV | **CSV déjà porté** | `web.php:876` → `ServeursController::importer:101` → `importeCsv:367` → `importeUneLigne:421` → `ajoute():294` → `DB::table('machines')->insert(` |
| ⑤ | afficher `sshd_config` en LECTURE | **déjà porté** | `audit-ssh.blade.php:61` → `audit-ssh.js:444 litConfig()` → `:457 ecris('/ssh-audit/config')`. Rendu par `textContent`. Le test qui manquait a été écrit à la place (`70aff008`) |
| ⑥ | désactiver une jail · géolocaliser | **sites d'appel présents** | `fail2ban.js:925 litDistant('/fail2ban/jail', …)` · `:1132 litDistant('/fail2ban/geoip', { ip })` |
| ⑦ | relever un serveur (ssh_audit) | **site d'appel présent** | `audit-ssh.js:368 ecris('/ssh-audit/scan', { machine_id })`. L'en-tête du fichier documente : *« trois routes et non une ; `/ssh-audit/scan` OUVRE une session SSH »* |
| ⑧ | scan de dérive de masse (groups) | **implémenté** | `groups.py:38 _BULK_ACTIONS = {'drift_scan','cve_scan'}` · `:257` · `:261 track('drift_scan', …)` · `:293` |
| ⑨ | les 2 capacités PERDUES de superv | **une portée, une bloquée** | rattacher un serveur à un profil : `supervision.js:151` → `supervision.py:2539`, garde complète. Jeton telegraf : **délibérément non portée**, bloquée sur la signature du `patch 03` — la porter ajouterait une entrée pour stocker un secret en clair |

---

## 2. ⛔ CE QUE CE DOSSIER NE DIT PAS

**Un site d'appel plus une route n'est pas « le geste aboutit ».** J'ai mesuré
l'**atteignabilité**, pas la **réussite**. La formule est d'une autre session et
elle vaut ici : *« le JS compose la requête » n'est pas « le geste aboutit ».*

**Aucun des onze n'a été exercé.** Et ça n'est pas un manque de zèle : c'est
gouverné par deux choses qui ne sont pas à nous.

### ⓐ Le service ne charge pas le code de l'arbre

```
hypercorn_config.py:14   workers = 4
hypercorn_config.py:17   use_reloader = False
rootwarden_python        demarre le 2026-09-07 12:53 UTC
commits backend/ depuis  19  ->  ABSENTS du processus qui repond
```

**Donc une épreuve au réseau mesurerait le code d'hier midi, pas le code
d'aujourd'hui.** Toute preuve de bout en bout est vide de sens avant un
redémarrage.

⚠ Et le piège qui rend l'écart invisible : `backend/` est monté en **bind**, donc
un `grep` **dans le conteneur** trouve les correctifs, exactement comme dans
l'arbre. *C'est la vérification qu'on ferait spontanément, et elle rend le
mauvais verdict.* **Un fichier partagé ne fait pas un code partagé : le montage
synchronise l'octet, pas la mémoire du processus qui l'a lu.**

### ⓑ Trois des gestes restants sont sortants, et deux le sont irréductiblement

```
⑦  /ssh-audit/scan   ouvre une session SSH  -> exercable sur la MACHINE 3, autorisee
⑥  /fail2ban/geoip   TRANSFERT sortant vers ip-api.com  -> decision ouverte, DOSSIER-49
⑥  /fail2ban/jail    desactive une jail sur une machine -> mot de l'exploitant
⑧  drift_scan        geste de MASSE sur un groupe       -> a borner a un groupe
                                                            ne contenant que la 3
```

---

## 3. Ce que je tranche

**E-501 — L'étape 2 de la mission n'a plus d'objet, et je cesse d'assigner des
capacités de cette file.** Deux sessions me l'ont dit avant que je le mesure :
*« ne m'assigne rien pour combler le temps »*, *« le dire vaut mieux qu'un
travail inventé »*. Et l'une a chiffré le coût : **cinq assignations en deux
jours portant sur du hors-périmètre ou du déjà-fait**, dont deux sur du travail
déjà livré.

**Le ratio doc/code de 7 pour 1 n'est donc pas de la complaisance : c'est
l'arithmétique d'une file dont les objets ont disparu.** Et six des sept
documents du dernier tour sont des **rétractations de chiffres faux** — un
`StartedAt` périmé de onze jours, deux horodatages sur des horloges
différentes, un `85/18` qui valait `219/19`, une affirmation sans source.

> **Une cascade de rétractations s'auto-entretient : chaque correction est
> elle-même une affirmation qui réclame son régime, sa date et sa source.**
> Six en dix-huit minutes.

**Ce qui la ferme n'est pas d'écrire moins — c'est de mesurer sur le SERVICE au
lieu de l'arbre**, et ça exige le redémarrage.

---

## 4. Ce qui revient à l'exploitant, par ordre de ce que ça débloque

**① `docker compose restart python`.** Met en service **trois** correctifs de
commande root écrits, relus et commités — dont celui qui empêche un rendu de
politique raté d'écrire `NOPASSWD: ALL`. **Et c'est lui qui rend toute épreuve de
bout en bout possible.** Le test de non-régression de ce correctif est absent du
service comme le correctif : *un test vert dans l'arbre sur un défaut ouvert dans
le service est plus trompeur qu'une absence de test — l'absence se remarque, le
vert rassure.*

**② Le mot de passe de la boîte `opnsense@…`**, exposé dans un fil de session par
un masquage trop étroit de ma part. Pas dans git. À changer.

**③ `MAIL_MAILER` / `APP_URL`** — les étapes 1 à 4 de
`srv-docker.env.example:90-143`, ou désarmer le mailer. L'étape 5 a été faite
avant les quatre autres.

**④ La mémoire** — swap à 99,8 %. Bloque toute preuve au navigateur ; trois
sessions refusent d'en lancer un pour cette raison.

**⑤ `ruff`**, absent de l'hôte **et** du conteneur. Le job CI est vert, donc rien
ne le signale en local : un `NameError` sur une branche rare passe l'import et
attend son appelant. C'est arrivé aujourd'hui, et seul un contrôle AST écrit à la
main l'a vu.

**⑥ Les signatures** : `patch 03` (jeton telegraf — débloque ⑨) et `patch 07`
(retrait du service `php` — dernier reste du legacy). Plus les décisions de
`DOSSIER-49` (durées de conservation · sort du transfert `ip-api.com`, qui
gouverne ⑥).


---

## 5. CLÔTURE DU CÔTÉ DES LIENS — mesurée le 2026-09-08 13:05

Il restait une question que ce dossier ne posait pas : **après `patch 07`, le
portage proposerait-il des liens vers un hôte mort ?** `config('app.url_legacy')`
est lu sur **six sites vivants** :

```
PortailController.php:310 · :354
LiensLegacy.php:259 · :280
accueil.blade.php:349
composants/entrees-menu.blade.php:32
```

**La réponse est non, et pour une raison de dessin.** `LiensLegacy::REMPLACEMENTS`
(`:30`) n'est pas une liste de liens **vers** le legacy — c'est une table de
**détournement** :

```
'/commandlog/' => 'journal-commandes'    '/tasks/'    => 'taches'
'/approvals/'  => 'approbations'         '/tickets/'  => 'tickets'
'/drift/'      => 'derive-config'        '/backups/'  => 'sauvegardes'
```

`url_legacy` ne sert que de **repli** pour un chemin sans remplacement. Et sa
table est **dérivée** de l'archive, pas maintenue à la main : le commentaire de
`:36-52` dit que la propriété de la session 7 — *dériver la liste de
`legacy/_deprecated/*` et la comparer à cette table* — a trouvé un `/search/`
manquant **à sa première mesure**, un oubli que personne n'avait vu depuis son
archivage.

**Mesure au réseau, avec son témoin :**

```
GET https://192.168.0.245:8443/connexion   ->  200, 3838 octets
liens vers :8446 (le port du legacy)       ->  0
TEMOIN : liens absolus rendus par la page  ->  3
```

*Sans le témoin, « 0 lien vers `:8446` » aurait pu vouloir dire « la page ne rend
aucun lien absolu ».*

### Ce que les 13 fichiers restants sont

Un `.htaccess` (plus deux dans `logs/` et `vendor/`), un `openapi.yaml`, un
`tailwind.css`, un `composer.json`/`.lock`, quatre images, `htmx.min.js` et
`utils.js`. **C'est la coquille, pas le legacy** : aucun `.php` ne les charge, et
le portage ne les cite pas.

⚠ **Je ne les archive pas, et c'est un choix.** Le geste n'aurait aucun gain
fonctionnel — ils sont déjà inertes — et il ajouterait un `git mv` dans un arbre
que sept sessions partagent. **Leur place est dans `patch 07`, avec le service
qui les servait, pas avant lui.**

⚠ Et une mesure que j'ai ratée en chemin, dite parce qu'elle instruit : mon
premier relevé comptait les citations par **nom de base**. `.htaccess` rendait
10, `composer.json` 7 — c'étaient les mentions de *n'importe quel* `.htaccess` et
du `composer.json` de `laravel/`. **Un compte de grep porte le nom, pas la
chose.** Et ma seconde tentative a rendu des zéros dont le **témoin rendait zéro
aussi** : la mesure n'avait pas eu lieu. Seule la troisième, avec un témoin qui
mord (`url_legacy` 6, `pare-feu` 24, absurdité 0), porte quelque chose.
