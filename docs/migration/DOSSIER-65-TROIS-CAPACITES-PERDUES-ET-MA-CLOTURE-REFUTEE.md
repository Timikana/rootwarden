# DOSSIER-65 — Trois capacités perdues, et ma clôture réfutée

**Mesuré le 2026-09-09 entre 08:00 et 08:40 CEST.** Aucun geste exercé. Trouvé
par `gestion-ssh-key-5f`, vérifié indépendamment ici avant reprise.

> `DOSSIER-64`, écrit une heure plus tôt, déclarait que l'archivage n'avait rien
> coûté : 18 des 20 tables écrites par l'archive ont un écrivain vivant. **Ce
> dossier le réfute sur le fond, et il le réfute par le prédicat que j'avais
> moi-même nommé comme la limite de ma mesure.**

---

## 1. Ce que ma mesure ne pouvait pas voir

`DOSSIER-64` §3 disait :

> *Un écrivain vivant sur la même table peut porter UN geste là où l'archive en
> portait SIX. C'est une question d'ARITÉ, pas de présence — et mon vert est une
> borne inférieure déguisée en verdict.*

**C'était juste, et j'ai quand même écrit « l'archivage n'a rien coûté » dans le
titre.** Le bon grain n'est pas la table : c'est le couple **(verbe, colonnes)**.
Sur `users`, il donne **28 couples archivés contre 16 sites vivants**.

---

## 2. Les trois perdues

### ① `UPDATE users SET sudo` — un drapeau vivant, positionnable une fois

```
ecrit  ComptesController.php:260  'sudo' => 0    <- dans insertGetId
       Comptes.php:866            'sudo' => $sudo <- dans insert
lu     ssh_utils.py:937           u.sudo, dans le SELECT du deploiement
       configure_servers.py       le dict `user` le porte jusqu'au deploiement
AUCUNE `UPDATE` vivante sur cette colonne.
```

**Retirer le sudo global à un compte impose de le supprimer ou de l'anonymiser.**

⚠ Et le redécoupage par machine ne le remplace pas : `Permissions.php:300-330`
documente le passage à `user_machine_access.sudo_preset`, et c'est un choix
assumé — **mais il est ADDITIF.** `users.sudo` continue d'être écrit et lu.
*Le drapeau global n'est pas supprimé : il est échoué.*

**Gravité, mesurée et bornée** : l'**effet** est révocable. `configure_servers.py:873`
gate sur `machine_id in allowed_servers AND user['active']`, et retirer l'accès
machine est porté (`Permissions.php:329`) — l'étape 2 de `:970` retire même les
clés des comptes qui ont perdu l'accès. **Ce n'est donc pas un trou de sécurité :
c'est la piste d'audit qui tombe.** Le drapeau dit `1` pour toujours.

### ② `UPDATE users SET active` — la suspension n'existe plus

```
ecrit  ComptesController.php:259  'active' => 1   <- insert
       Comptes.php:865            'active' => …   <- insert
       Comptes.php:650            'active' => 0   <- UPDATE, mais dans
                                                     l'ANONYMISATION
```

**La seule `UPDATE` qui met `active` à 0 est irréversible.** Suspendre un compte
le temps d'un préavis impose de le détruire ou de l'anonymiser.

Et `active` **décide** : `configure_servers.py:873` ne construit
`allowed_usernames` qu'avec `user['active']`. La capacité était donc utile, et
elle n'a pas de voisin réversible.

### ③ `UPDATE users SET role_id` — promouvoir ou rétrograder

```
ecrit  ComptesController.php:258  'role_id' => $role   <- insert
       Comptes.php:864            'role_id' => $role   <- insert
lu     dans 39 fichiers de laravel/app
AUCUNE `UPDATE`.
```

**Changer le rôle d'un compte impose de le recréer** — et donc de perdre son
historique, ses attributions de machines et ses permissions.

---

## 3. ⚠ L'absence est COHÉRENTE, et c'est ce qui la rend crédible

```
comptes.blade.php   deux <form> seulement : import (:135) et creation (:157)
                    le <select name="role_id"> est a :176, DANS la creation
routes de bascule   AUCUNE (role · actif · sudo)
routes existantes   14, dont anonymiser · cle-ssh · deverrouiller · expiration
                    · mot-de-passe · second-facteur
```

**Aucun contrôle mort, aucune route orpheline.** Les trois gestes n'ont pas été
cassés : ils n'ont jamais été portés. *Et rien ne les documente comme retirés —
c'est ce qui les distingue du retrait assumé de `Permissions.php:305-320`, où la
case `sudo_nopasswd` indépendante du préréglage est nommée comme une capacité
volontairement supprimée.*

> **Retiré et perdu ne se distinguent pas par l'absence : ils se distinguent par
> la présence d'une note.**

---

## 4. Un écart d'anonymisation qui se compose avec ①

Le legacy zérotait **12** colonnes ; le portage en écrit **8** et omet `sudo`,
`force_password_change`, `password_expiry_override`, `locked_until`,
`failed_attempts`.

**Inerte aujourd'hui, et vérifié plutôt que supposé** : les deux purgent les
**six mêmes tables**, dont `user_machine_access`, et le déploiement est
conditionné à l'accès machine. Sans accès, aucun sudoers n'est écrit.

⚠ **Mais avec ①** : un compte anonymisé garde `sudo = 1` **et il n'existe aucun
chemin pour l'effacer**. La sûreté repose entièrement sur la purge.

*Et le portage est plus fort sur un point : `password` reçoit un haché de 64
octets aléatoires là où le legacy mettait `NULL`.*


---

## 7. `gestion-ssh-key-94` — UNE DONNÉE PERSONNELLE QUI SURVIT À L'EFFACEMENT

**32 gestes appariés sur les quatre tables d'authentification, 30 couverts, 2
retirés et MIEUX, et une trouvaille d'un autre ordre.**

### `login_attempts` est la seule des quatre sans clé étrangère

Mesuré sur la base vivante :

```
active_sessions        active_sessions_ibfk_1        CASCADE
password_reset_tokens  password_reset_tokens_ibfk_1  CASCADE
remember_tokens        remember_tokens_ibfk_1        CASCADE
login_attempts         ABSENTE de la liste — AUCUNE contrainte
```

Et elle porte des **données personnelles** :

```
ip_address  varchar(45)
username    varchar(100)     <- migration 035, « detection password spraying »
```

**Trois conséquences, chaînées et toutes mesurées :**

```
① `DELETE FROM users` ne la purge pas       aucune CASCADE
② `Comptes::anonymise` purge SIX tables     login_attempts n'en fait PAS partie
   (Comptes.php:656-658)                    -> le compte devient
                                               `compte-anonymise-<id>` et les
                                               lignes gardent le nom D'ORIGINE
③ la purge de retention ne tourne pas       scheduler.py:447
                                               retention_days = int(os.environ
                                                 .get('LOG_RETENTION_DAYS','0'))
                                               if retention_days <= 0: return
                                             srv-docker.env.example:514 la donne
                                               COMMENTEE
                                             et dans le conteneur EN SERVICE :
                                               LOG_RETENTION_DAYS = NON DEFINI
```

> **Par défaut, le nom de connexion et les adresses IP d'une personne survivent
> à l'anonymisation ET à l'effacement de son compte, sans borne de durée.**

⚠ **Et ce n'est PAS une régression** : le legacy ne purgeait pas non plus à
l'effacement. Il avait une atténuation partielle — `login.php:47` purgeait les
lignes de plus de 24 h à *chaque* tentative, inconditionnellement — que le
portage a rendue **conditionnelle et éteinte par défaut**. *C'est un défaut
hérité que la fin du legacy rend seul.*

**Volume aujourd'hui** : 2 lignes, la plus ancienne d'un jour. *Le mécanisme
d'accumulation est réel ; le stock ne l'est pas encore. C'est le bon moment pour
trancher.*

### ⛔ Et un commentaire qui affirmait qu'un contrôle de sécurité N'EXISTAIT PAS

`MotDePasse.php:522-535` portait, daté du 2026-08-27 :

> *« le PORTAGE ne consulte JAMAIS cette table — zéro occurrence dans ses
> intergiciels […] cette purge ferme les sessions de l'ancien portail, et aucune
> de celui-ci »*, suivi d'un *« le correctif complet est que le portage ÉCRIVE
> cette table […] et la consulte »* présenté comme travail futur.

**Le correctif est livré depuis le 2026-09-02.** Vérifié plutôt que supposé :

```
ECRIRE     SessionsActives::enregistre (updateOrInsert a la connexion)
SUPPRIMER  revoque · ferme · la purge de MotDePasse
LIRE       Http/Middleware/SessionRevoquee.php   <- le volet qui manquait
alias      bootstrap/app.php:77
applique   routes/web.php:140 — et c'est le SEUL `Route::middleware([` du
           fichier, donc le seul groupe authentifie
```

Corrigé dans ce même commit : le constat reste écrit, **daté et au passé**,
parce qu'il explique pourquoi le middleware existe.

> **Laissé tel quel, il faisait pire que se tromper : il disait à son lecteur
> qu'un contrôle de sécurité n'existait pas, et lui donnait donc une raison de
> ne pas mesurer.** *« Si j'avais cru le commentaire, je publiais une fuite de
> session refermée depuis treize jours. »*

### Deux retraits qui sont MEILLEURS que l'archive

Les deux `UPDATE login_attempts SET success = 1` du legacy n'existaient que pour
**corriger après coup** un `success = 0` posé d'office — et les deux portaient
leur commentaire de bug : *« une 2FA RÉUSSIE comptait comme un échec dans le
compteur IP et bloquait des users légitimes derrière un même NAT »*.

Le portage inscrit `success` **déjà juste**. *Le geste n'est pas perdu : il est
devenu **inexprimable**.* **Défaut éliminé par construction, pas rustiné.**

---

## 8. Trois instruments, trois angles morts — et la forme se répète

```
moi (tables)          « la table a un ecrivain »  -> aveugle a l'ARITE
5f (verbe, colonnes)  terminateur au 1er guillemet -> `CONCAT('deleted-', id)`
                      tronquait 12 colonnes a UNE  -> DEDOUANAIT
94 (nom de table)     aveugle a la BOUCLE sur une liste de littéraux
                      (`Comptes.php:657`) et au SCHEMA (`ON DELETE CASCADE`)
c1 (nom de table)     aveugle au HELPER (nom 50 lignes avant le verbe) et au
                      nom dans un TABLEAU
```

**Aucun des quatre ne voyait ce que voyaient les trois autres.** Et trois des
quatre ont produit une fausse alarme qu'ils ont arrêtée eux-mêmes en continuant
de mesurer.

> **Le seul dédouanement du lot — les 12 colonnes tronquées à une — a été trouvé
> par son auteur en corrigeant autre chose.** C'est la troisième source,
> distincte de l'écriture et de la revue.

---

## 5. Ce que je tranche

**E-554 — `DOSSIER-64` est réfuté sur son titre, pas sur sa méthode.** Les 18
tables ont bien un écrivain vivant ; ce fait n'impliquait pas la couverture, je
l'avais écrit, et j'ai quand même titré « n'a rien coûté ». *Une réserve écrite
dans le corps ne rattrape pas un titre qui affirme.*

**E-555 — Les trois sont PERDUES et non retirées, et l'arbitrage revient à
l'exploitant.** Aucune n'est un trou de sécurité : l'effet de ① est révocable en
retirant l'accès machine, ② et ③ n'ouvrent rien. Ce sont des **gestes
d'administration courante** qui manquent.

**Mon ordre, par coût opérationnel décroissant :**

```
② suspendre        le plus courant : un preavis, une absence, un doute.
                   Aujourd'hui il faut DETRUIRE ou ANONYMISER.
③ changer le role  perdre l'historique d'un compte pour le promouvoir est
                   disproportionne.
① retirer le sudo global  l'effet est deja revocable ; ce qui manque est la
                   COHERENCE de la trace.
```

**E-556 — Et je ne referme pas ce dossier moi-même.** Porter ces trois gestes
touche `users`, la table la plus lue du dépôt (39 fichiers lisent `role_id`).
C'est du code neuf sur le contrôle d'accès, et le service ne recharge pas l'arbre
— donc inéprouvable avant un redémarrage. *Écrire trois routes de bascule sans
pouvoir les exercer serait exactement ce que j'ai refusé pour K4.*

---

## 6. Comment ça a été trouvé — et pourquoi je l'avais assigné

**Par le prédicat que j'avais nommé comme la limite de ma propre mesure**, et
donné à trois sessions pour cette raison. Le grain (verbe, colonnes) au lieu de
(table).

**Et `5f` a avoué quatre défauts de son instrument dans le même message** — dont
un qui **dédouanait** : son extracteur tronquait `anonymize_user.php` à UNE
colonne au lieu de douze, parce que son terminateur s'arrêtait au premier
guillemet et que `CONCAT('deleted-', id)` en contient un. *Moins de colonnes,
moins de gestes à porter.* Onze colonnes récupérées après correction.

> **Le seul dédouanement de la nuit trouvé par son auteur l'a été en corrigeant
> autre chose.** C'est la troisième source, distincte de l'écriture et de la
> revue.

---

## 9. Ce qui revient à l'exploitant, en un bloc

```
① porter la SUSPENSION (`users.active`)      le plus courant des trois
② porter le changement de ROLE               perdre un historique pour
                                             promouvoir est disproportionne
③ porter le retrait du SUDO global           l'effet est deja revocable ;
                                             ce qui manque est la trace
④ trancher la retention de `login_attempts`  poser `LOG_RETENTION_DAYS`, et/ou
                                             ajouter la table a la purge
                                             d'anonymisation. Touche les deux
                                             decisions deja en attente sur la
                                             notice de confidentialite.
```

⚠ **Aucun des quatre n'est a moi.** ①②③ sont du code neuf sur le controle
d'acces, ineprouvable avant un redemarrage. ④ est une valeur d'environnement et
une decision de conservation — donc une decision de conformite, pas de code.
