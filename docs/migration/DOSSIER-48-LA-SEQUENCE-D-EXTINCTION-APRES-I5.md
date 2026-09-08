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
