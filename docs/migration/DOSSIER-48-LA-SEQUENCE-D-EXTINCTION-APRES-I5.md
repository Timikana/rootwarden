# DOSSIER-48 — La séquence d'extinction, décidée à l'avance

**Écrit le 2026-09-08 vers 02:15.** *Pour que votre mot sur le port SSH déclenche un
enchaînement DÉJÀ tranché, et non une nouvelle analyse.*

---

## Pourquoi ce dossier existe

**Tout ce qui reste attend un arbitrage, et quand il tombera, personne ne devrait avoir à
re-dériver l'ordre des gestes.** *Cette nuit a montré que la re-dérivation coûte cher : j'ai
publié trois modèles faux du legacy en quatre heures, et chacun a fait écarter du travail
réel.*

⚠ **Ce dossier ne demande aucune décision de plus.** Il fixe l'ordre et les contrôles.

---

## L'état, mesuré et corrigé

```
racines servies : 11        (E-474 — j'avais publie 19, puis 89, puis 0)
  auth/*                7   la chaine d'authentification
  iptables/index.php    1   la derniere PAGE metier
  adm/api/notifications 1   une API
  api_proxy.php         1   la passerelle
  _sortie.php           1   la page 404, cablee par ErrorDocument
```

**Sept des onze racines sont une authentification complète.** *Et elle est PORTEUSE
aujourd'hui, pas résiduelle :*

```
iptables/index.php:37   require_once auth/verify.php
                 :41   session_start()
                 :45   checkAuth([...])
le legacy lit `$_SESSION`   ·   le portage pose une session LARAVEL
=> une session du portage n'ouvre PAS le legacy
```

> **La chaîne d'auth legacy existe pour une seule chose : permettre d'atteindre la page de
> pare-feu.** *Le jour où cette page part, la chaîne n'a plus de consommateur — elle reste
> ATTEIGNABLE, elle cesse d'être NÉCESSAIRE.* **Atteignable et nécessaire sont deux
> questions, et l'archivage répond à la seconde.**

---

## La séquence

### ⓪ Le verrou — **le vôtre**

**Le port SSH**, condition écrite de portage d'I5 (`MODULE-FILTRAGE.md:269`). *Q1 et Q2 sont
écrites, éprouvées et attendent une destination qui n'existe qu'avec I5 (`E-472`).*

### ① Porter I5, avec Q1–Q4

*Cahier des charges dans `E-463`, critères d'écran A1–A5 dans `DOSSIER-47` addendum 3.*

⚠ **Q3 n'est pas une exigence de confort.** *L'écran legacy actuel ne dit NI le succès, NI
l'erreur, NI la trace manquante — 12 appels à `showNotification` visent un `#notifications`
absent des quatre fichiers servis.* **C'est le défaut principal, et je l'avais rangé
troisième.**

### ② Archiver `legacy/iptables/`

```
CONTROLE   les gestes portes rendent > 0 dans laravel/, avec un temoin negatif
PUIS       menu.php:236 et head.php  ->  le dernier lien VIVANT bascule au portage
```

*Après ce geste, `menu.php` n'est plus inclus par personne : `legacy/iptables/index.php:239`
est son **unique** requérant.*

### ③ `adm/api/notifications.php`

**Ses quatre appelants sont dans `menu.php`** (`:191`, `:355`, `:378`, `:392`). *Orphelin dès
que `menu.php` n'est plus rendu.*

⚠ **L'appariement geste par geste est DÉJÀ FAIT** — six gestes, six portés, chacun avec sa
ligne. Il ne reste que le contrôle des appelants, qui devient trivial après ②.

### ④ `api_proxy.php`

*Cité 17 fois, dont `legacy/js/utils.js` et `head.php:57` (`API_URL`).* **Tombe avec le socle
qu'il sert.**

### ⑤ La chaîne d'authentification — sept fichiers

**C'est ici que la séquence cesse d'être mécanique**, et je tranche :

> **Elle s'archive, elle ne se dénie pas.**

*Un `Require all denied` la rendrait inatteignable en la laissant présente — donc exécutable
par tout ce qui l'inclut, et présente au prochain inventaire comme une question ouverte.*
**L'archivage dit ce que le refus tait : cette capacité a été portée, et ceci n'est plus la
porte.**

⚠ **Contrôle propre à cette étape, et il n'est pas dans les autres** : *la réinitialisation
de mot de passe est portée (`E-465` : 4 routes, 9 tests verts) — mais elle envoie un
COURRIEL.* **Vérifier que le portage sait l'envoyer AVANT de retirer la porte legacy**, sinon
on retire le seul chemin de récupération d'un compte.

### ⑥ `_sortie.php` — **en dernier, avec le vhost**

*Elle sert le 404 de tout ce qui précède (`ErrorDocument 404 /_sortie.php`). Elle ne part
qu'avec la configuration qui la nomme.*

---

## Trois contrôles qui valent pour CHAQUE étape

**① Le geste, pas le fichier.** *L'unité d'archivage est le FICHIER, le portage s'est fait
par GESTE. Un verdict « PORTÉ » sur une page ne dit rien de chacun de ses gestes.*

**② Le témoin, toujours.** *Zéro sur la sonde ET zéro sur le témoin veut dire « la mesure n'a
pas eu lieu ». Et un témoin emprunté au parc se périme : `/fail2ban/install` était le témoin
négatif d'une session, il est passé à `APPELÉ` pendant qu'elle mesurait.*

**③ Les cinq espèces de dépendance**, dont un graphe d'`include` ne voit qu'une :

```
require/include  ·  appel HTTP  ·  lien entrant du portage
chemin CONSTRUIT par glob()     ·  configuration du SERVEUR (ErrorDocument)
+ l'URL composee pour un COURRIEL — invisible a toute sonde de code
```

---

## Ce que ce dossier ne couvre pas, et le dit

⛔ **Le redémarrage** (`docker compose restart python`) et **la ligne 15 de
`rw-pre-commit`** sont indépendants de cette séquence et n'attendent qu'un geste.

⛔ **Je n'ai pas mesuré** si un consommateur externe — clé d'API, script, signet — dépend
d'une des onze racines. *La mesure porte sur le dépôt ; elle ne voit pas vos usages.*

⛔ **Et rien ici n'autorise à exercer quoi que ce soit.** *Aucune machine n'a été jointe pour
écrire ce dossier ; tout y est statique.*

---

# ⚠ CONTRE-ÉPREUVE — trois affirmations sur quatre tiennent, la quatrième est mal énoncée

**Mise à l'épreuve indépendante** (`CONTRADICTION-DOSSIER-48.md`, `0cca6d5f`). *Je l'avais
demandée en disant de ne me croire sur aucun chiffre ; c'était justifié.*

## ⛔ L'affirmation ③ est FAUSSE — et la séquence tient quand même

*J'écrivais : « la chaîne d'auth n'a pas d'autre consommateur que la page de pare-feu ».*

```
auth/verify.php a QUATRE requerants :
  iptables/index.php:37          etape ②
  adm/api/notifications.php:13   etape ③   — absent de mon enonce
  api_proxy.php:22               etape ④
  adm/includes/crypto.php:3      — ABSENT DE MA SEQUENCE ENTIERE
```

**Les trois premiers partent avant ⑤ : l'ORDRE est correct. C'est la JUSTIFICATION qui est
fausse.**

> **Et c'est le pire cas pour un dossier de séquence** — *le prochain lecteur vérifiera
> l'énoncé, le trouvera faux, et doutera de tout l'ordre.* **Une conclusion juste tirée d'une
> prémisse fausse ne se distingue pas d'une erreur tant qu'on ne l'a pas rejouée.**

## ⛔ L'étape ⑤ compte 7 fichiers. La fermeture en compte 13.

```
manquaient : crypto.php · audit_log.php · mail_helper.php · totp_crypto.php
             + les deux DEJA denies de auth/ (functions, password_policy)
```

⚠ **Et une contrainte d'ORDRE INTERNE à ⑤ que je n'énonçais pas** : *`login.php` requiert
`crypto.php`, qui requiert `verify.php`.* **Retirer `verify.php` en premier casse les deux
autres. ⑤ n'est pas un bloc indifférencié.**

## ⛔ Trois espèces de dépendance manquent à mon graphe

*Mon graphe n'en employait que DEUX. C'est la faute que je cite aux autres depuis trois
jours, commise dans le dossier qui fixe la séquence.*

```
glob()          lang/fr.php:12 et lang/en.php:12 retiennent 74 catalogues
                -> `lang/` n'apparait a AUCUNE etape de ma sequence
URL par COURRIEL  reset_password.php : 0 requerant, 0 lien
                -> mon graphe le donnerait LIBRE. Il ne l'est pas.
config SERVEUR   je l'emploie pour l'affirmation ④ sans la NOMMER
                -> donc sans la chercher ailleurs
```

## ✅ « Archiver, pas dénier » : le choix tient, l'ARGUMENT change

*Un précédent l'affaiblit, et il est juste :* `auth/.htaccess:5-7` **dénie déjà
`functions.php` et `password_policy.php`** — *exactement l'état que je décrivais comme
dangereux, et le mal annoncé ne s'est pas produit.*

> **C'est un argument de PROPRETÉ, pas de SÛRETÉ.** *Archiver reste plus propre ; ça n'est
> plus urgent.* **Je corrige la qualification plutôt que la décision.**

## ⛔⛔ MAIS L'ALERTE RGPD EST RÉFUTÉE — et nos deux sondes ont échoué DE LA MÊME FAÇON

*La contre-épreuve annonçait : « `login.php` est le SEUL écrivain de `login_history` et
`last_failed_login_at`, tous deux LUS par l'export RGPD — les retirer fige deux sections d'un
livrable légal ».* **Mesuré :**

```
login_history          ConnexionController -> HistoriqueConnexions:79 (injecte :25)  PORTE
last_failed_login_at   ConnexionController:215  $maj = [… 'last_failed_login_at' => now()]  PORTE
                       et son docbloc :205 cite login.php:249 — le portage SAIT
last_failed_login_at   lecteurs qui le NOMMENT : 0
```

**Les deux colonnes ont un écrivain côté portage. Retirer `login.php` ne fige rien.**

⚠ **Et l'instructif est que MA sonde l'avait manqué aussi**, exactement pareil : *je
cherchais `INSERT|UPDATE` sur la MÊME LIGNE que le nom de colonne.* **Le portage écrit par un
tableau (`$maj = [...]`) appliqué par un `->update($maj)` ailleurs — deux lignes, donc
invisible aux deux sondes.**

> **Deux sessions, deux instruments écrits séparément, le même angle mort — parce que les
> deux supposaient que le verbe d'écriture et la colonne tiennent sur une ligne.** *Un angle
> mort partagé ne se corrige pas par une seconde lecture : il se corrige en changeant la
> forme de la question.*

**Une alarme non vérifiée aurait bloqué l'étape ⑤ au nom d'une obligation légale.** *C'est le
côté qui alarme, et il a été relu ; c'est ce qui l'a arrêté.*

## Ce qui reste vrai de la contre-épreuve, et qui entre dans le dossier

**Les capacités de la chaîne d'auth sans équivalent servi**, à vérifier avant ⑤ :

```
l'envoi du COURRIEL de reinitialisation   MAIL_MAILER absente du conteneur (mesure 05/09)
                                          le portage prepare le lien, le legacy ENVOIE
le re-hachage bcrypt au login             0 occurrence au portage
changer sa PROPRE cle SSH                 l'unique ecriture est gardee role:3
changer sa PROPRE adresse                 aucune route, ni pour soi ni pour un admin
```

⚠ **La première est la garde que j'avais posée ; les trois autres sont neuves et je les
reprends.** *Aucune n'est bloquante en soi — toutes doivent être tranchées avant que la porte
ne se ferme.*

