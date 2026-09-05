# DOSSIER 24 — Le portage n'envoie aucun courriel, et les deux jeux de variables ne partagent aucun nom

**Pour signature de l'exploitant.** *Trouvé par la session 3 en refusant de porter la réinitialisation de
mot de passe ; vérifié par moi à 11:30 CEST le 2026-09-04.*

> **Ce dossier bloque une capacité que vous avez demandée** — la réinitialisation de mot de passe en
> libre-service. *La porter aujourd'hui livrerait une capacité INERTE.*

---

## 1. Le portage journalise, il n'envoie pas

    laravel/config/mail.php:17   'default' => env('MAIL_MAILER', 'log')
    laravel/.env.example:63      MAIL_MAILER=log
    l'environnement du conteneur `laravel`   MAIL_MAILER : ABSENT

**Donc le repli s'applique : `log`.** *Tout envoi du portage est écrit dans un journal et ne quitte pas la
machine.*

## 2. ⚠ Et les deux jeux de variables ne partagent AUCUN nom

    ce que Laravel LIT (config/mail.php) :
      MAIL_MAILER · MAIL_HOST · MAIL_PORT · MAIL_USERNAME · MAIL_PASSWORD
      MAIL_SCHEME · MAIL_FROM_ADDRESS · MAIL_FROM_NAME · MAIL_URL
      MAIL_EHLO_DOMAIN · MAIL_LOG_CHANNEL · MAIL_SENDMAIL_PATH

    ce que le projet POSE (srv-docker.env) :
      MAIL_ENABLED · MAIL_DEBUG · MAIL_FROM · MAIL_TO
      MAIL_SMTP_HOST · MAIL_SMTP_PORT · MAIL_SMTP_USER · MAIL_SMTP_PASSWORD · MAIL_SMTP_TLS

    intersection : ZERO

> **Poser `MAIL_MAILER=smtp` en croyant activer l'envoi ferait joindre `127.0.0.1:2525`** — *le défaut de
> Laravel — parce qu'aucun des noms qu'il attend n'est fourni.* **Le geste qui a l'air d'activer l'envoi
> le casserait à la place.**

**Le legacy, lui, envoie** : *`legacy/includes/mail_helper.php` par PHPMailer, en lisant `MAIL_SMTP_*`.*
**Les deux portails ont donc deux mécanismes de courriel qui ne se parlent pas.**

---

## 3. Ce que ça bloque, et pourquoi ce n'est pas rien

**La réinitialisation de mot de passe en libre-service** — *`DOSSIER-18`, le bloquant du « full
Laravel ».* **Son unique canal de délivrance est le courriel.**

    comptes ACTIFS                      12
    `force_password_change = 1`          8
    SANS adresse de courriel             6
    LES DEUX A LA FOIS                   5

> **Cinq comptes actifs doivent déjà changer leur mot de passe et n'ont aucune adresse.** *Le flux
> s'indexe sur l'adresse : il ne les atteint pas, même une fois porté et le SMTP configuré.*

**Donc porter ce flux aujourd'hui livrerait une capacité qui ne délivre rien à personne** — *et la session
3 a refusé de le faire pour cette raison, ce qui est la bonne conduite.*

---

## 4. Le geste exact, et il vous revient entièrement

```
1. DECIDER si le portage doit envoyer des courriels
   -> si NON : la reinitialisation en libre-service ne se porte pas, et il faut
      un autre chemin de recuperation (un geste d'administration nomme)
   -> si OUI : point 2

2. FOURNIR les noms que Laravel attend, dans `srv-docker.env`
      MAIL_MAILER=smtp
      MAIL_HOST=${MAIL_SMTP_HOST}      MAIL_PORT=${MAIL_SMTP_PORT}
      MAIL_USERNAME=${MAIL_SMTP_USER}  MAIL_PASSWORD=${MAIL_SMTP_PASSWORD}
      MAIL_SCHEME=smtps                (le port 465 est un SMTPS implicite)
      MAIL_FROM_ADDRESS=${MAIL_FROM}
   -> et via `srv-docker.env.example`, pour que `env-merge.sh` les propage

3. CONTROLE : un envoi de test, et le journal du conteneur
```

**⛔ Aucune session ne doit poser ce réglage.** *C'est le geste qui fait sortir un courriel du portage vers
un serveur SMTP réel — donc un effet sortant, et la session 3 a refusé de le faire.*

---

## 5. ⚠ ET UN SECRET A ÉTÉ EXPOSÉ EN MESURANT CECI — par moi

**J'ai exécuté `printenv | grep -iE "^MAIL_"` dans le conteneur, sans filtrer la valeur.**
*`MAIL_SMTP_PASSWORD` — le mot de passe du compte `opnsense@timikana-heero.fr` — s'est affiché en clair
dans la conversation.*

> **Ce secret doit être renouvelé.** *La faute est la mienne : j'aurais dû exclure la valeur au lieu de la
> lire, et une mesure qui n'avait besoin que des NOMS n'avait aucune raison de rendre les VALEURS.*

**Règle que j'en tire** : *pour mesurer la présence d'une variable, lire son NOM — jamais son contenu.*
`printenv | cut -d= -f1` suffisait.

---

## Ce qui n'est pas mesuré

- **si le SMTP `ssl0.ovh.net:465` fonctionne** — *je n'ai fait aucun envoi, et je n'en ferai pas : un envoi
  sortant publie quelque chose* ;
- **si le legacy envoie EFFECTIVEMENT aujourd'hui** — *le code est là, `MAIL_ENABLED=true`, mais aucun
  envoi n'a été observé* ;
- **si les cinq comptes sans adresse en ont une ailleurs** *(annuaire, autre système)* — *la question de
  savoir s'il faut leur en poser une est une décision sur des comptes réels, donc la vôtre.*

---

# ⚠⚠ 2026-09-05 — CE QUE POSER LE SMTP RÉOUVRIRA, et personne ne le verra passer

**À lire AVANT de décider le SMTP. C'est une réserve de relecture que je déplace ici, parce qu'elle doit
voyager avec VOTRE décision et non rester dans un échange entre sessions.**

## 1. LE FLUX DE RÉINITIALISATION EST PORTÉ, ET SON ORACLE TEMPOREL EST FERMÉ — **avec `log`**

    le legacy avait egalise le MESSAGE, pas le TEMPS :
      adresse INCONNUE   1 bcrypt
      adresse CONNUE     UPDATE + bcrypt + INSERT + un envoi SMTP SYNCHRONE

**Le portage l'égalise avec `app()->terminating()` — pas une file, car `queue.default = sync` exécute en
ligne.** *Mesure : branche inconnue **185,7 ms**, branche connue **188,1 ms**, écart **2,4 ms (1 %)**.*

## 2. ⛔ MAIS CETTE MESURE A ÉTÉ PRISE LÀ OÙ LE TERME COÛTEUX N'EXISTE PAS

    ce que LARAVEL LUI-MEME rapporte :  config('mail.default') = 'log'
    `MAIL_MAILER` dans le conteneur  :  ABSENTE

> **Avec le pilote `log`, l'« envoi » est une écriture de fichier. La mesure montre que `terminating()` ne
> coûte rien QUAND IL N'A RIEN À DIFFÉRER. Elle ne peut pas montrer qu'il diffère un envoi SMTP — aucun
> envoi SMTP n'a eu lieu.**

## 3. ⛔ ET LE MÉCANISME CHOISI NE PEUT PAS DIFFÉRER SUR CE DÉPLOIEMENT

    apache2ctl -M              php_module (shared)      <- mod_php
                               deflate_module · filter_module   <- ils BUFFERISENT
                               PAS de proxy_fcgi
    command -v php-fpm         NON
    function_exists('fastcgi_finish_request')   NON

> **`terminating()` ne défère que si la réponse peut DÉTACHER la connexion. Le seul mécanisme qui le
> garantit est `fastcgi_finish_request()`, qui n'existe QUE sous FPM. Il est absent ici.**

*Le côté PHP est favorable — `output_buffering=0`, `implicit_flush=1` — mais la chaîne de filtres d'Apache
garde la main, et `mod_deflate` compresse donc bufferise.*

## 4. 🔴 CE QUE ÇA DONNE LE JOUR OÙ VOUS POSEZ LE SMTP

    aujourd'hui   les deux branches ecrivent un fichier -> ecart 2,4 ms, INOFFENSIF
    apres le SMTP le terme couteux revient ENTIER, et `terminating()` ne
                  garantit rien sur ce deploiement
    -> l'ecart de temps entre « cette adresse existe » et « elle n'existe pas »
       peut revenir, sur le chemin de recuperation de compte

> **Et AUCUN COMMIT NE L'EXPLIQUERA.** *C'est l'écart « qui disparaît avec la configuration et revient avec
> elle » — celui qu'on ne sait pas relire six mois plus tard.*

**⚠ Le risque concret n'est pas le défaut : c'est qu'on posera le SMTP en lisant « le temps est
égalisé ».** *Et ce sera vrai de ce qui a été mesuré, faux de ce qui tournera.*

## 5. ✅ CE QUI LE RENDRAIT VRAI PAR CONSTRUCTION — et je ne le prescris pas

    ne pas emettre depuis la requete :
      un magasin durable (table ou fichier) + un PROCESSUS SEPARE qui delivre

**C'est la seule forme qui ne dépende ni du SAPI, ni de `mod_deflate`, ni du tampon d'Apache — et elle ne
demande aucune file Laravel, dont `sync` la rendrait inopérante.**

**⛔ Je ne le prescris pas, et je dis pourquoi** : *c'est un arbitrage de conception, et j'ai déjà prescrit
`Mail::queue` une fois sur ce dépôt sans avoir mesuré le pilote — c'était inopérant pour cette raison
exacte.* **Deux fois la même faute suffirait.**

## 6. VOTRE DÉCISION, ET ELLE A TROIS FORMES

    (a) poser le SMTP et ACCEPTER le residu, en le sachant
        -> le flux delivre, l'oracle temporel revient, borne a un chemin
           qui exige de connaitre une adresse
    (b) poser le SMTP ET faire porter l'emission par un processus separe
        -> la propriete tient par construction, quel que soit le serveur
    (c) ne pas poser le SMTP
        -> le flux reste agnostique, les liens partent au journal, et aucun
           compte NEUF ne peut recevoir son mot de passe

**Ce que je ne veux pas, c'est (a) SANS le savoir.** *C'est pour ça que cette réserve est ici et non dans
une relecture.*

---

# ⛔ CORRECTION DU §3 — un de mes trois maillons ne prouve RIEN

**La conclusion tient. La démonstration que j'en donnais portait un maillon invalide, et c'est le genre de
maillon qui se recopie.**

    ce que j'ai ecrit    function_exists('fastcgi_finish_request')  ->  NON
    ce que j'ai mesure   PHP_SAPI de ma commande  ->  `cli`

> **`fastcgi_finish_request()` appartient au SAPI FPM et n'existe JAMAIS en ligne de commande. Ce test rend
> faux même sur une machine où php-fpm sert parfaitement le web.**

**Mon `docker exec … php -r` est du CLI. Ce maillon ne mesurait pas le serveur, il mesurait mon
interpréteur.**

## ✅ LES DEUX MAILLONS QUI FONDENT LA CONCLUSION, EUX, TIENNENT

    apache2ctl -M    php_module (shared)   <- mod_php charge dans Apache
                     PAS de proxy_fcgi
    binaire php-fpm  ABSENT
    socket php-fpm   0

**Ces deux-là mesurent le SERVEUR, et ils suffisent.** *La conclusion du §3 est inchangée :
`fastcgi_finish_request()` n'est pas disponible au SAPI qui sert les pages, donc `terminating()` ne peut
pas détacher la connexion.*

## ⚠ ET LA PRÉCISION QUI COMPTE POUR QUI LIRA CE DOSSIER

> **`terminating()` déplace le travail après l'ÉCRITURE de la réponse, pas après sa FIN.** *Sous php-fpm ce
> sont la même chose ; sous mod_php, non.*

    un demandeur qui chronometre le DERNIER OCTET du corps  -> ne voit pas l'envoi
    un demandeur qui chronometre la FERMETURE de connexion  -> le voit

**C'est pour ça que la mesure de 2,4 ms ne tranche pas** : *elle chronomètre la mauvaise borne, en plus
d'avoir été prise avec le pilote `log`.* **Deux biais indépendants sur la même mesure.**

## ✅ ET LE PORTAGE A FAIT MIEUX QU'UN COMMENTAIRE — c'est ce qui vous protège

**Un commentaire ne produit aucun ÉVÉNEMENT le jour où sa prémisse cesse d'être vraie.** *C'est la famille
qui a coûté quatre déclarations vraies périmées par un geste sur ce seul chantier, sans qu'aucune ne
signale quoi que ce soit.*

    la premisse est desormais VERIFIEE A L'EXECUTION :
      `TRANSPORTS_LOCAUX` est une liste FERMEE
      un transport INCONNU est traite comme DISTANT
      et tout transport hors liste produit un `Log::warning` qui nomme
      la CONSEQUENCE et le REMEDE

> **Ce n'est pas une garde — elle n'empêche rien. C'est un ÉVÉNEMENT, là où il n'y en avait aucun.**

**Concrètement pour vous : le jour où vous posez le SMTP, le journal vous le dira.** *Vous n'avez pas à
vous souvenir de ce dossier — c'est le produit qui vous rappellera, au moment où ça compte.*

## ⛔ ET LA SEULE MESURE QUI TRANCHERAIT N'A PAS ÉTÉ PRISE

    le temps jusqu'a la FERMETURE DE CONNEXION, sur les deux branches

**Trois raisons de ne pas la lancer, et la troisième suffit** : *elle consomme la limite de débit — qui
compte les demandes REÇUES, et c'est sa qualité ; la branche connue exige un jeton réel sur un compte
réel, ce que j'ai refusé ; et c'est le banc partagé.*

**Inscrite comme non-mesure unique avec ses trois raisons, pas comme deux réserves séparées — une seule
mesure les trancherait toutes les deux.**
