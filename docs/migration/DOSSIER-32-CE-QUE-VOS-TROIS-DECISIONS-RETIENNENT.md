# DOSSIER 32 — Ce que vos trois décisions retiennent : **vingt-six fichiers, pas quatre**

**2026-09-05, 16:45 CEST.** *Mesuré, pas estimé.*

---

## 1. L'état, à cette heure

    .php METIER servis   82 -> 26     en une journee
    archives             19 -> 75

**Et les 26 qui restent sont EXACTEMENT la fermeture transitive des quatre fichiers
bloqués.** *Pas un de plus, pas un de moins.*

---

## 2. La mesure qui change la question

**Sur les 31 fichiers qui restaient il y a une heure, combien étaient appelés depuis
l'EXTÉRIEUR du legacy — par le portage, le backend, un navigateur ?**

    corpus exterieur balaye   295 fichiers
    temoin                    `url_legacy` cite dans 16 fichiers
    -> appeles de l'exterieur : TROIS
    -> et les trois references sont des ROUTES DE REDIRECTION Laravel :

        Route::get('/auth/login.php',     fn () => redirect()->route('connexion'));
        Route::get('/auth/verify_2fa.php', fn () => redirect()->route('second-facteur'));
        Route::get('/profile.php',         fn () => redirect()->route('profil'));

> **Elles ne CALLENT pas le legacy : elles le REMPLACENT.** *Ce ne sont pas des
> dépendances, ce sont ses pierres tombales.*

**Vingt-huit sur trente et un n'étaient tenus QUE par d'autres fichiers legacy.** *La
grappe se tenait elle-même, et personne ne l'appelait.*

---

## 3. ⛔ Ce que chaque décision libère, transitivement

**Les quatre fichiers bloqués exigent 22 autres fichiers pour fonctionner** — `db.php`,
`head.php`, `menu.php`, `footer.php`, `verify.php`, `functions.php`, `lang.php`,
`crypto.php`, `totp_crypto.php`, `mail_helper.php`, `api_proxy.php`, toute la grappe
d'authentification.

    forgot_password.php + reset_password.php   armer le SMTP
      -> ils tirent `mail_helper.php`, `password_policy.php`, et par `verify.php`
         toute la chaine d'authentification

    security/index.php                         le scan sortant
    iptables/index.php                         l'application de regles

> **Votre décision ne porte pas sur quatre fichiers. Elle porte sur les vingt-six qui
> restent servis, et sur le fait que le portail legacy continue de se monter.**

---

## 4. Ce que je vous demande, et ce que je ne demande pas

**Je ne vous demande pas de trancher vite.** *Les trois gestes ont des effets sur des
tiers — un courriel vers une personne réelle, une machine qui peut devenir injoignable —
et c'est précisément pourquoi je ne les ai pas déduits de « aucune limite ».*

**Je vous demande de savoir ce qu'ils coûtent tant qu'ils ne sont pas tranchés :**

    le legacy reste MONTE
    26 fichiers restent SERVIS, dont `db.php` et toute l'authentification
    et l'objectif « on passe en full Laravel » reste a 26 fichiers de son terme

### Le moins cher des trois, et de loin

**Armer le SMTP.** *C'est une variable d'environnement, `MAIL_MAILER=smtp`, et le mappage
est déjà en place et vérifié (`port=465, scheme=smtps`).* **Son seul risque est qu'un
courriel réel parte depuis une page publique — et il partira de toute façon le jour où
quelqu'un utilisera la récupération de compte, puisque le LEGACY, lui, envoie déjà.**

> **Aujourd'hui, la seule chose que « ne pas armer le SMTP » protège, c'est le portage.
> Le legacy envoie, et il est encore servi.** *La prudence protège le portail neuf et
> laisse l'ancien faire ce qu'on ne veut pas qu'il fasse.*

**⚠ Et la contrepartie, mesurée, qui reste vraie** : sous `mod_php` sans `php-fpm`,
l'écart de temps entre « cette adresse existe » et « elle n'existe pas » redevient
mesurable sur la page publique de récupération. *C'est le `DOSSIER-24`, et il n'a pas
bougé.*
