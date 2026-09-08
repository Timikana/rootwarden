# `DOSSIER-48` mis à l'épreuve — **une affirmation fausse, une séquence qui tient**

**Mesuré le 2026-09-08 entre 02:37 et 02:45 CEST**, en lecture seule, sur 24 `.php`
métier vifs (+ `lang/fr.php` et `lang/en.php`, que mon filtre range ailleurs : 26 au
total, comme annoncé).

> **Verdict : trois affirmations sur quatre TIENNENT. La troisième est FAUSSE — et la
> séquence qu'elle justifie survit à sa fausseté.** Ce n'est pas la même chose qu'une
> séquence non contredite, et c'est pour ça qu'il fallait la mesurer.

---

## 1. Les quatre affirmations

| # | affirmation | verdict |
|---|---|---|
| 1 | `iptables/index.php:239` est l'**unique** requérant de `menu.php` | ✅ **EXACTE** — 1 requérant, à cette ligne. *Témoin : `db.php` en a 8* |
| 2 | les 4 appelants de `notifications.php` sont dans `menu.php` | ✅ **EXACTE** — `:191` `:355` `:378` `:392`, tes numéros au caractère près |
| 3 | la chaîne d'auth n'a **pas d'autre consommateur** que la page de pare-feu | ⛔ **FAUSSE** — voir §2 |
| 4 | `_sortie.php` part en dernier, `ErrorDocument` la nomme | ✅ **EXACTE** — `legacy/.htaccess:43` |

---

## 2. ⛔ L'AFFIRMATION 3 EST FAUSSE — `auth/verify.php` a QUATRE requérants

    api_proxy.php:22                 <- etape ④
    iptables/index.php:37            <- etape ②
    adm/api/notifications.php:13     <- etape ③   ⚠ absent de ton enonce
    adm/includes/crypto.php:3        <- ⚠ ABSENT DE TA SEQUENCE ENTIERE

**Mais la séquence tient quand même**, et voici pourquoi : les trois premiers
requérants partent aux étapes ②, ③ et ④ — **toutes avant ⑤**. L'ordre est donc
correct. *L'énoncé est faux, la conclusion est juste.*

> **Une affirmation fausse peut porter une conclusion vraie — et c'est le pire des
> cas pour un dossier de séquence**, parce que le prochain lecteur qui vérifiera
> l'énoncé le trouvera faux et doutera de tout l'ordre.

---

## 3. ⚠ L'ÉTAPE ⑤ COMPTE 7 FICHIERS. LA FERMETURE EN COMPTE **13**.

Six fichiers sont tenus par la chaîne d'auth et **absents de ta liste** :

    adm/includes/crypto.php      <- login.php:18        (et REQUIERT verify.php:3)
    adm/includes/audit_log.php   <- login.php:19
    includes/mail_helper.php     <- forgot_password.php:19
    includes/totp_crypto.php     <- verify_2fa.php:24
    auth/forgot_password.php     <- lien depuis login.php:389
    auth/reset_password.php      <- URL composee pour un COURRIEL (:107)

### 3.1 Et une contrainte d'ordre INTERNE à ⑤, que tu n'énonces pas

    login.php  requiert  crypto.php  (:18)
    crypto.php requiert  verify.php  (:3)
    => dans l'etape ⑤ :  login.php  AVANT  crypto.php  AVANT  verify.php

**Retirer `verify.php` en premier casserait `crypto.php`, qui casserait `login.php`.**
L'étape ⑤ n'est pas un bloc indifférencié.

---

## 4. Les espèces de dépendance que ton graphe n'emploie pas

Tu en emploies **deux** — `require`/`include`, et les chemins cités dans un contexte
d'appel. **Trois autres mordent sur ce dossier :**

| espèce | où elle mord ici | ce qu'elle change |
|---|---|---|
| **chemin construit par `glob()`** | `lang/fr.php:12` et `lang/en.php:12` | **74 catalogues** retenus. *Ta séquence ne mentionne `lang/` à aucune étape* |
| **URL composée pour un COURRIEL** | `forgot_password.php:107` → `reset_password.php` | ce fichier n'a **0 requérant** et **0 lien** : ton graphe le donnerait libre |
| **configuration du SERVEUR** | `.htaccess:43` | tu l'emploies déjà pour l'affirmation 4 — mais **sans la nommer comme espèce**, donc sans la chercher ailleurs |

---

## 5. Sur ton point le plus fragile — ⑤ « archiver, pas dénier »

**Ton raisonnement tient, et il a déjà un précédent qui l'affaiblit :** deux des sept
fichiers de la chaîne sont **DÉJÀ déniés**, et depuis longtemps.

    legacy/auth/.htaccess:5-7
        <FilesMatch "^(functions|password_policy|migrate_crypto|migrate_totp)\.php$">
            Require all denied

`auth/functions.php` et `auth/password_policy.php` sont donc **présents et
inatteignables** — exactement l'état que tu décris comme dangereux. *Le dépôt pratique
déjà ce que tu argumentes contre, sur 2 des 7, sans que le mal annoncé se soit
produit.*

> **Ça ne réfute pas ton choix — archiver reste plus propre que dénier.** Ça retire
> son urgence : le déni n'est pas un état inédit qu'on introduirait, c'est le régime
> courant de ce dossier. **Ton argument est un argument de PROPRETÉ, pas de sûreté.**

### 5.1 Et ta garde sur le courriel est la bonne — je l'élargis

Tu attaches à ⑤ : *vérifier que le portage sait envoyer un courriel avant de retirer
la porte legacy.* **C'est exact, et j'ai mesuré le 2026-09-05 que ce n'était pas le
cas** : `MAIL_MAILER` absente du conteneur → repli sur `log` → le portage prépare le
lien et **n'envoie rien**. *Le legacy, lui, envoie (`MAIL_ENABLED=true`,
`MAIL_SMTP_HOST` posé).*

**Autres capacités de cette chaîne sans équivalent servi**, mesurées le 2026-09-05
(§14 et §15 de `INVENTAIRE-ARCHIVAGE.md`), et qui doivent entrer dans le dossier :

    `INSERT login_history`        aucun ecrivain cote portage — LU par l'export RGPD
    `last_failed_login_at`        aucun ecrivain — LU par l'export RGPD
    le re-hachage bcrypt au login `password_needs_rehash` : 0 occurrence au portage
    changer sa propre cle SSH     l'unique ecriture est gardee `role:3`
    changer sa propre adresse     aucune route, ni pour soi ni pour un administrateur

**Les deux premières sont les plus lourdes** : `login.php` est leur seul écrivain, et
l'export article 20 du portage les lit. *Retirer `login.php` fige deux sections d'un
livrable légal.*

---

## 6. Ce que je n'ai pas fait

- **je n'ai ouvert aucune page** et exercé aucun geste ;
- je n'ai pas vérifié l'étape ① (le portage d'I5) : elle est hors de ma mesure ;
- **les numéros de ligne de ce document sont d'aujourd'hui 02:37-02:45** — sur ce
  dépôt une mesure a une demi-vie de quelques heures, et j'en ai relevé six formes
  de péremption en quatre jours.
