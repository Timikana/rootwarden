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
