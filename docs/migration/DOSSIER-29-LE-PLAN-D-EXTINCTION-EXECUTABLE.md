# DOSSIER 29 — Le plan d'extinction, exécutable

**Établi le 2026-09-05 à 11:19 CEST par la session DSI, sur mesures horodatées.**
*Chaque chiffre porte la commande qui le refait.*

> **⚠ CE DOCUMENT SE PÉRIME.** *La péremption a été mesurée QUATRE fois en deux jours sur
> ce dépôt, dont une en 23 minutes par la même session sur le même objet.* **Un relevé de
> plus d'une heure se présente avec son heure, ou se refait.**

---

## 0. CE QUI EST ÉTABLI, ET CE QUI NE L'EST PAS

    Q1  le geste est-il porte ?          RESOLU — 11 sur 11 (E-411, releve 0b `b15a289`)
    Q2  le fichier est-il REQUIS ?       RESOLU — graphe resolu ci-dessous, 295 liens
    Q3  seul acces a un geste NON porte ?  OUVERT sur 16 fichiers, clos sur les 40 autres

**Le portage des gestes est fini. Ce qui reste est l'ordre, et une Q3 bornée à seize
fichiers.**

---

## 1. L'ÉTAT, remesuré à 11:19

    .php METIER servis     82        (temoin : total brut avec vendor = 944)
    deja archives          19
    liens de dependance    295 resolus · 9 non resolus (hors metier ou chemin variable)

---

## 2. L'ORDRE, donné par le graphe et non par le jugement

    VAGUE 1   59 FEUILLES — aucun fichier metier ne les inclut
              moins 3 INTERDITES par arbitrage
              => 56 archivables, sous reserve de la Q3

    VAGUE 2   23 fichiers INCLUS, par entrants DECROISSANT
              ils ne partent qu'APRES leurs appelants

    les derniers a partir, mesures :
      59 entrants   legacy/db.php              <- LE DERNIER DE TOUS
      56 entrants   legacy/auth/verify.php
      25 entrants   legacy/head.php
      24 entrants   legacy/menu.php
      24 entrants   legacy/auth/functions.php
      19 entrants   legacy/includes/lang.php
      18 entrants   legacy/footer.php
      18 entrants   legacy/adm/includes/audit_log.php

> **Q2 ne se discute plus : elle est calculée.** *`index.php` désigne dix fichiers, et
> c'est pourquoi le graphe est résolu par CHEMIN et non par nom de base.*

---

## 3. ⛔ LES TROIS INTERDITES, et leur condition de levée

    legacy/auth/forgot_password.php   E-408
    legacy/auth/reset_password.php    E-408
      Le legacy ENVOIE (`mail_helper.php:23` : MAIL_ENABLED=true ET MAIL_SMTP_HOST pose,
      PHPMailer present). Le portage N'ENVOIE PAS (`mail.default = log`).
      Les archiver retirerait le SEUL chemin de recuperation de compte qui delivre.
      LEVEE : `MAIL_MAILER=smtp` pose par l'exploitant ET un envoi reel verifie.

    legacy/adm/api/audit_seal.php     E-408 + E-408 rectifie
      1484 lignes hors chaine, 4787 scellees intactes. Les deux sceleurs divergent, et
      le portage ecrirait 1484 `prev_hash` identiques que son propre verificateur
      rejette. LEVEE : arbitrage du DOSSIER-25.

**Les trois sont des FEUILLES** — rien ne dépend d'elles. *Leur interdit ne bloque donc
aucun autre fichier : l'extinction avance sans elles.*

---

## 4. LA Q3 SE POINTE SUR SEIZE FICHIERS, PAS SUR CINQUANTE-SIX

**Un verdict de FICHIER est une MOYENNE, et une moyenne cache la minorité.** *C'est ce qui
a sorti trois pages du bloc archivable — Q1 disait « la page est portée », c'était VRAI, et
le geste de trop n'était pas dans la partie portée.*

**Critère appliqué : plus d'une branche `case` OU plus d'une table écrite, commentaires
DÉPOUILLÉS** (`direct`, `pour`, `si` avaient déjà été pris pour des tables).

    9 branches · 3 tables   legacy/adm/includes/server_actions.php
    6 branches · 1 table    legacy/adm/api/notifications.php
    3 branches · 1 table    legacy/iptables/index.php
    0 branche  · 7 tables   legacy/adm/api/anonymize_user.php
    0 branche  · 6 tables   legacy/privacy.php
    0 branche  · 4 tables   legacy/profile.php
    0 branche  · 3 tables   legacy/adm/api/change_password.php
                            legacy/adm/api/delete_user.php
                            legacy/auth/login.php
    0 branche  · 2 tables   legacy/adm/api/unlock_user.php
                            legacy/adm/api/update_notification_prefs.php
                            legacy/adm/api/update_server_access.php
                            legacy/adm/api/update_user.php
                            legacy/adm/health_check.php

    MONO-GESTE ou LECTURE PURE : 40 fichiers  ->  la Q1 seule suffit

---

## 5. ⚠ UN ARBITRAGE À PART : `legacy/adm/health_check.php`

**Il est FEUILLE, donc archivable dès la vague 1 — et il écrit sur `zabbix`, c'est-à-dire
sur la PRODUCTION, AU CHARGEMENT.**

> **C'est la seule page du parc dont l'archivage est en lui-même une mesure de sûreté :
> tant qu'elle est servie, une simple visite écrit en production.**

**Et elle peut être archivée SANS être ouverte.** *`git mv` déplace un fichier, il ne
l'exécute pas.* **L'interdit permanent « ne jamais ouvrir `health_check.php` » n'interdit
pas de l'archiver — il interdit de le charger.** *Ne pas confondre les deux serait
élargir un interdit, et un interdit élargi coûte autant qu'un interdit manqué.*

**RECOMMANDATION : l'archiver EN PREMIER de la vague 1.**

---

## 6. ⛔ CE QUI BLOQUE, ET CE N'EST PLUS UNE MESURE

**Le `git mv` n'est tenu par AUCUNE session.** *Sept sessions mesurent, arbitrent et
portent ; aucune n'a le geste d'archivage, et trois ont rappelé le même quart d'heure
qu'un périmètre tenu de l'exploitant ne se lève pas sur la parole d'un pair.*

    onze capacites verifiees portees
    trois pages structurelles liberees
    cinquante-six fichiers ordonnes et prets
    -> et personne pour deplacer un fichier

> **Le geste qui manque n'est pas une compétence : c'est une autorisation.**

**Ce que l'exploitant doit dire, et lui seul** : quelle session tient le `git mv`, ou que
la session DSI l'exerce elle-même.

---

# ⚠ CORRECTION DE L'ORDRE (13:35) — deux graphes, et ils vont en SENS INVERSE

**Le plan ci-dessus ordonne par le graphe d'INCLUSION : les feuilles d'abord, `db.php`
dernier. C'est juste, et c'est incomplet.**

> **Il existe un second graphe, invisible au premier : celui des appels HTTP.**

    par `require`   une feuille peut partir     -> LES FEUILLES D'ABORD
    par `fetch`     un fichier APPELE doit rester -> LES APPELANTS D'ABORD

**Les deux ordres sont OPPOSÉS, et un fichier peut être feuille dans l'un et carrefour
dans l'autre.** *`api_proxy.php` en est l'exemple : zéro entrant par `require`, **dix
appelants** par `fetch`.*

## La mesure qui l'établit

**Huit fichiers blanchis geste par geste par la campagne Q3 — donc archivables selon Q1,
Q2 et Q3. Q4 posée sur ce qui VIT ENCORE :**

    libre            adm/api/anonymize_user.php
    libre            adm/api/change_password.php
    ⛔ APPELE (2)    adm/api/delete_user.php        <- manage_users.php, js/admin.js
    ⛔ APPELE (1)    adm/api/notifications.php      <- menu.php
    ⛔ APPELE (1)    adm/api/unlock_user.php        <- manage_users.php
    ⛔ APPELE (4)    auth/enable_2fa.php            <- confirm_2fa.php, login.php
    ⛔ APPELE (2)    auth/logout.php                <- verify.php, menu.php
    ⛔ APPELE (1)    adm/includes/server_actions.php <- manage_servers.php
    ⛔ APPELE (10)   api_proxy.php   TEMOIN, doit ressortir appele -> OK

**Deux sur huit.** *Les six autres sont tenus vivants par des pages qui vivent encore.*

## L'ordre réel de l'extinction, qui n'est pas celui que j'avais écrit

    1. les PAGES d'abord            (`manage_users.php`, `manage_servers.php`, `menu.php`)
    2. puis les POINTS D'ENTREE qu'elles appelaient  (`adm/api/*`)
    3. puis l'INFRASTRUCTURE d'inclusion             (`db.php`, `verify.php`, `head.php`)

> **Tant qu'une page vit, tout ce qu'elle appelle en HTTP vit avec elle.** *C'est pourquoi
> l'extinction ne peut pas commencer par les points d'entrée, même quand ils sont
> parfaitement portés : ils ne sont pas les feuilles de ce graphe-là, ils en sont les
> racines.*

**L'état à 13:35 : 52 fichiers métier servis (82 ce matin) · 49 archivés (19 ce matin).**
