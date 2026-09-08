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

## ⚡ ÉTAT D'ENTRÉE — mesuré le 2026-09-08 à 06:4x, chaque ligne avec sa commande

> ⚠ **Ce bloc est en tête parce que le reste de ce dossier a été écrit entre 02:32 et 03:02,
> AVANT I5 (04:34), I6 (04:49) et le retrait de l'encart (06:08).** *Son étape ① se lit encore
> comme à faire.* **Une séquence qui présente une étape close comme ouverte fait
> recommencer.*

```
⓪  LE VERROU                                          ⛔ L'EXPLOITANT — inchange
①  Porter I5, avec Q1–Q4                              ✅ FAIT
      pare-feu.js code depouille : iptables-validate 1 · apply 1 · rollback 1
                                   pare-feu/version 1  (le chemin de LECTURE)
      Q1 pare-feu-gabarits.js · Q2 pare-feu-ssh-ouvert.js · Q3 pare-feu-retour-visible.js
      + les 4 epreuves dans laravel/tests/Outils/, les 7 du preflight a 0
②  Archiver legacy/iptables/                           ✅ DEBLOQUEE
      2 fichiers suivis · lien entrant du portage : 0 dans le CODE
      (2 occurrences de `/iptables/` dans pare-feu.blade.php, les DEUX en
       commentaire Blade — depouille : 0 · url_legacy : 0 partout)
③  adm/api/notifications.php                           ✅ DEBLOQUEE
      ses gestes cote portage : 7 routes, dont Route::delete(…'supprimer')
      ⚠ le legacy n'y fait que UPDATE (marquer lu) et DELETE — aucun INSERT :
        il n'est l'ecrivain exclusif de rien
④  api_proxy.php                                       ✅ DEBLOQUEE
      le portage a sa passerelle : Route::any('/api/gateway/{chemin?}')
⑤  La chaine d'authentification                        ✅ DEBLOQUEE
      legacy/auth : 10 fichiers suivis
      legacy/lang : 3 a la racine (.htaccess + en.php + fr.php) + 74 CATALOGUES
      les 74 sont atteints par glob(__DIR__ . '/{fr,en}/*.php') — AUCUN fichier
      ne les NOMME : ils meurent avec leurs deux chargeurs
      ⚠ « 74 » est exact — mesure par profondeur de chemin, pas par pathspec :
        `git ls-files 'legacy/lang/*.php'` en rend 76, une pathspec git n'est
        PAS un glob shell et son `*` traverse les `/`
⑥  _sortie.php, avec le vhost                          ⛔ EN DERNIER
      legacy/.htaccess:43   ErrorDocument 404 /_sortie.php
```

### Les SEPT espèces de dépendance, et non cinq

**Ce dossier en listait cinq ; j'en avais mesuré cinq AUTRES et déclaré l'ensemble clos.**
*L'union en fait sept, et deux n'avaient jamais été mesurées avant le 2026-09-08 06:3x.*

```
1  require / include                    les 11 racines           ✅
2  appel HTTP                           backend -> legacy : 0    ✅
3  lien entrant du portage              1, puis 0 (b14767f4)     ✅
4  chemin CONSTRUIT par glob()          2 appels reels           ✅ mesure le 08/09
     TEMOIN+ 183 occurrences du mot « glob » dans legacy/, dont 2 sont des appels
5  configuration du SERVEUR             ErrorDocument, etape ⑥   ✅ mesure le 08/09
6  URL composee pour un COURRIEL        ⛔ DEFAUT REEL, tenu ferme par MAIL_MAILER=log
7  ecrivain exclusif en BASE            le legacy ne l'est de rien ✅
```

> **Seule la sixième porte un défaut vivant** — l'hôte du lien de réinitialisation est fourni
> par le demandeur (`DOSSIER-52`). **Elle n'est pas un obstacle à l'extinction : elle est un
> obstacle à l'ARMEMENT DE SMTP.** *Les deux sont indépendants et ne doivent pas être
> confondus dans la même attente.*

---

## L'état, mesuré et corrigé

```
racines servies : 11        (E-474 — j'avais publie 19, puis 89, puis 0)
  auth/*                7   la chaine d'authentification — mais sa FERMETURE
                            compte 17 fichiers + 74 catalogues (voir ⑤)
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

### ⑤ La chaîne d'authentification — **17 fichiers, plus 74 catalogues**

⚠ **J'avais écrit « sept ». La fermeture, mesurée, en compte DIX-SEPT** — et elle tire
`lang/` que ma séquence ne mentionnait nulle part :

```
auth/    forgot_password · functions · login · logout · password_policy
         reset_password · step_up · verify · verify_2fa              9
tires    adm/includes/{audit_log,crypto}.php                          2
par      includes/{lang,mail_helper,totp_crypto}.php                  3
require  db.php · head.php · lang/fr.php                              3
                                                                     ──
                                                                     17
puis     lang/{fr,en}.php:12  glob('/{fr,en}/*.php')  ->  37 + 37 = 74 catalogues
```

> **⑤ n'est pas une étape : c'est TOUT LE RESTE.** *Une fois ②③④ faits, il ne subsiste que
> cette fermeture et `_sortie.php`.* **La séquence a donc quatre gestes, pas six — et le
> cinquième est le seul qui demande de l'ordre INTERNE.**

**Ordre interne, mesuré :**

```
login.php  ->  crypto.php  ->  verify.php
```

⛔ **Retirer `verify.php` en premier casse les deux autres.** *L'étape n'est pas un bloc
indifférencié, et je l'avais écrite comme si elle l'était.*

### La décision : elle s'archive, elle ne se dénie pas

*Un refus la rendrait inatteignable en la laissant présente — donc exécutable par ce qui
l'inclut, et ouverte au prochain inventaire.* **L'archivage dit ce que le refus tait : cette
capacité a été portée, et ceci n'est plus la porte.**

⚠ **Mais c'est un argument de PROPRETÉ, pas de SÛRETÉ**, et je le corrige après
contre-épreuve : *`auth/.htaccess:5-7` dénie DÉJÀ `functions.php` et `password_policy.php` —
exactement l'état que je décrivais comme dangereux, et le mal annoncé ne s'est pas produit.*

### ⚠ UNE seule capacité sans équivalent servi — j'en avais repris QUATRE

**Trois des quatre sont RÉFUTÉES. Mesuré avant de les inscrire comme verrous :**

```
⛔ « le re-hachage bcrypt : 0 occurrence cote portage »
   MotDePasse.php:236   password_needs_rehash($hache, PASSWORD_BCRYPT, ['cost' => …])
   et son docbloc :211-219 explique pourquoi `Hash::needsRehash()` de Laravel
   n'est PAS l'equivalent -> il a ete porte AVEC SOIN, pas oublie

⛔ « changer sa PROPRE cle SSH : l'unique ecriture est gardee role:3 »
   web.php:225   POST /profil/cle-ssh   -> PortailController::definirCleSsh   POUR SOI
   web.php:803   POST /comptes/{id}/cle-ssh  role:3                           POUR AUTRUI
   DEUX routes, pas une. Et le legacy VIF n'ecrit `ssh_key` NULLE PART.

⛔ « changer sa PROPRE adresse : aucune route »
   web.php:218   POST /profil/courriel  -> PortailController::changerCourriel

✅ l'envoi du COURRIEL de reinitialisation   RESTE la seule, et elle est a l'exploitant
   MAIL_MAILER absente du conteneur (mesure du 05/09) : le portage PREPARE le lien,
   le legacy ENVOIE.
```

> **J'allais inscrire quatre verrous dont trois n'existent pas.** *Un dossier de séquence qui
> porte de faux blocages ne retarde pas l'extinction d'une heure : il la retarde jusqu'à ce
> que quelqu'un reprenne chacun d'eux — et il donne à ce quelqu'un une raison de croire que
> le reste est aussi solide.*

### ⚠ Et le motif est le même que l'alarme RGPD, réfutée une heure plus tôt

*Cette contre-épreuve a été excellente à FALSIFIER mes affirmations — l'ordre interne de ⑤,
les 17 fichiers, `glob()` absent de mon graphe : tout tenait.* **Ses propres affirmations
POSITIVES — « ceci n'existe pas côté portage » — se sont trompées CINQ fois :**

```
login_history · last_failed_login_at · le re-hachage · la route de courriel
· la route de cle SSH
```

> **Falsifier une affirmation qu'on vérifie et ÉNUMÉRER ce qui existe sont deux gestes
> différents.** *Le premier est une mesure ; le second est une ABSENCE, et une absence exige
> un témoin.* **Aucune des cinq n'en portait.**

*Je le note sans reproche : ses contradictions ont corrigé mon dossier sur quatre points
réels, et aucune de mes propres sondes ne les avait vus. **Mais une absence annoncée se
mesure comme une présence, et c'est vrai de nous deux** — ma sonde a manqué les mêmes deux
écrivains, exactement de la même façon.*

⛔ **Et ce qui N'EST PAS un motif de blocage, verifié :** *l'alarme « retirer `login.php` fige
`login_history` et `last_failed_login_at`, lus par l'export RGPD » est REFUTÉE — les deux
colonnes ont un écrivain côté portage (`HistoriqueConnexions:79` injecté dans
`ConnexionController:25`, et `ConnexionController:215`).*

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

