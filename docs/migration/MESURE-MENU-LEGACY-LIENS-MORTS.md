# MESURE — le menu legacy rend 17 liens vers des cibles ARCHIVÉES

    Session   5 — securite, LECTURE SEULE. Aucune ecriture : `legacy/` n'est
              pas mon perimetre.
    Mesure    2026-09-08
    Origine   verification d'une affirmation sur `legacy/adm/includes/`.
              Le point demande est CONFIRME ; celui-ci a ete trouve a cote.

---

## 1. Ce qu'on m'avait demandé de vérifier — CONFIRMÉ

**Affirmation** : *`legacy/adm/includes/` ne contient plus que deux includes,
sans appelant HTTP ; un `Require all denied` y est sans risque.*

**Vérifié sur un AXE DIFFÉRENT du leur** — *ils cherchaient les VERBES
(`fetch|hx-|href|action=|curl|XMLHttpRequest|$.ajax`) ; j'ai cherché les NOMS DE
FICHIER partout, sans supposer la forme de l'appel* :

```
legacy/adm/includes/   audit_log.php  ·  crypto.php     (rien d'autre)
server_actions.php     -> legacy/_deprecated/…          ARCHIVE, confirme

crypto.php     appele par  legacy/auth/login.php:18        require_once
                           test-server/seed_test_machine.php:16   require_once
audit_log.php  appele par  legacy/auth/login.php:19        require_once
appels HTTP vers l'un ou l'autre :   0
TEMOIN+ : la sonde par NOM voit `notifications.php` en hx-post et fetch (menu.php:179,343)
```

**`require_once` lit le système de fichiers, pas HTTP : un `Require all denied`
ne l'affecte pas.** *La page de connexion legacy continuerait de fonctionner.*
**Le remède proposé est sûr — et je ne l'écris pas : `legacy/` n'est pas mon
périmètre.**

---

## 2. ⚠ CE QUE J'AI TROUVÉ À CÔTÉ, ET QUI EST PLUS URGENT

**Un homonyme m'a mis sur la piste** : `/adm/audit_log.php` (la PAGE) et
`adm/includes/audit_log.php` (l'INCLUDE) sont deux fichiers distincts. *La page
est archivée. **Le menu la lie toujours.***

**`legacy/menu.php` — 18 liens `sideLink` vers le legacy, dont 17 pointent vers
une cible ARCHIVÉE :**

```
/adm/admin_page.php          ARCHIVEE      /documentation.php           ARCHIVEE
/adm/audit_log.php           ARCHIVEE      /fail2ban/                   ARCHIVEE
/adm/platform_keys.php       ARCHIVEE      /graylog/                    ARCHIVEE
/adm/server_users.php        ARCHIVEE      /groups/index.php            ARCHIVEE
/adm/server_user_sftp.php    ARCHIVEE      /index.php                   ARCHIVEE
/adm/server_user_sudo.php    ARCHIVEE      /security/                   ARCHIVEE
/api/docs.php                ARCHIVEE      /security/compliance_report.php  ARCHIVEE
/bashrc/                     ARCHIVEE      /ssh-audit/                  ARCHIVEE
                                           /wazuh/                      ARCHIVEE

/iptables/                   VIVANTE       <- le seul
```

**Contre-épreuve individuelle sur trois, plus un témoin forgé :**

```
/index.php          vivant non · archive OUI
/adm/audit_log.php  vivant non · archive OUI
/iptables/          vivant OUI · archive non
/zzz-inexistant.php vivant non · archive non   <- TEMOIN : ni l'un ni l'autre
```

### 2.1 La portée est bornée, et il faut le dire

**`menu.php` n'est plus inclus que par `legacy/iptables/index.php`** — la seule
page legacy servie. *Le rayon d'action est donc « quiconque ouvre cette page ».*
**Ce n'est pas le portail entier ; ce n'est pas rien non plus : c'est la dernière
page legacy, et son menu est mort à 94 %.**

### 2.2 ⚠ Le fichier énonce la règle qu'il enfreint

`legacy/menu.php:135-136`, **cinq lignes au-dessus du premier lien mort** :

> *« … plutôt que de rendre 404 — **un menu qui mène nulle part est le défaut
> qu'on corrige, pas celui qu'on installe.** »*

**Et le remède existe dans le même fichier, sur les lignes adjacentes** : cinq
entrées ont été rebasculées vers le portail (`LARAVEL_URL . '/journal-commandes'`,
`/chatops`, `/tickets`, `/recherche`, `/sauvegardes`). *Le motif est là ; il n'a
pas été appliqué aux dix-sept autres.*

---

## 3. Ce que ça dit de MON propre instrument

**`SONDE-LIENS-VERS-CIBLE-ARCHIVEE.md` rendait `0 lien mort` — et ces dix-sept
existaient déjà.**

> **Ce n'est pas une contradiction : c'est l'angle mort que j'y avais DÉCLARÉ.**
> *La sonde ne voit que `require`/`include`. Elle imprime à chaque exécution
> qu'elle ne voit ni les `href`, ni les routes, ni les chemins composés.*

**La déclaration a fait son travail — mais elle n'a pas empêché le trou d'exister
pendant que j'écrivais le document qui l'annonçait.** *Une espèce déclarée
aveugle reste aveugle : la déclarer évite le FAUX VERDICT, pas le DÉFAUT.*

**La deuxième sonde — celle des `href` — est donc à écrire, et ceci en est le
premier résultat, obtenu à la main.**
