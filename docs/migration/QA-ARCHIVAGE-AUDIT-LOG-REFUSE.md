# QA — `legacy/adm/includes/audit_log.php` : ARCHIVAGE REFUSÉ

**Demandé le 2026-09-07** avec la consigne juste : *« si tu ne peux pas prouver qu'un geste est
porté, n'archive pas et dis-le ».* **Rien n'a été archivé**, et voici pourquoi.

L'inventaire le déclarait « archivable dès le bloc A ». **Il ne l'est pas**, et deux mesures
indépendantes suffisent à le montrer.

---

## ⛔ RAISON N°1 — un fichier VIF en fait un `require_once`

    legacy/auth/login.php:19   require_once __DIR__ . '/../adm/includes/audit_log.php';

    https://localhost:8446/auth/login.php     ->  200   (le legacy sert 8446 depuis l'echange)
    TEMOIN /auth/zzz-inexistant.php           ->  404   (l'instrument discrimine)

**`legacy/auth/login.php` est la page de connexion du legacy, servie à l'instant.** Retirer
le fichier inclus ne « perdrait pas une fonction » : `require_once` sur un fichier absent est
une **erreur fatale**. *La page de connexion du legacy rendrait 500.*

## ⛔ RAISON N°2 — TROIS des quatre écrivains vivent dans le fichier qui RESTE

    TEMOIN  868 fichiers legacy VIFS lus (hors `_deprecated/`)
    appels a audit_log() / audit_log_raw(), hors definitions : 4

    legacy/adm/includes/audit_log.php:54   interne au fichier         -> partirait avec lui
    legacy/auth/login.php:79               echec de connexion (uid 0) -> RESTE
    legacy/auth/login.php:169              « Connexion reussie »      -> RESTE
    legacy/auth/login.php:217              troisieme evenement        -> RESTE

C'est **exactement la condition d'échec nommée dans la consigne** : *« si un écrivain vit dans
un fichier qui RESTE, il perdra sa fonction et ça, ça casse ».* Ici trois y vivent.

Et le compte concorde avec `backend/audit_chain.py` : douze écrivains nus, huit dans
`backend/routes/`, **quatre dans le legacy** — ce sont ces quatre-là.

---

## ⚠ ET UNE TROISIÈME RAISON, QUI DÉPASSE L'ARCHIVAGE

La question posée était : *« `JournalAudit` porte-t-il toujours `verifie()` ET `scelle()` ? »*
Les deux méthodes sont déclarées, hors commentaire. **Mais une méthode présente n'est pas une
capacité portée.** Mesuré sur le code dépouillé :

    verifie()  12 lignes de code · 0 ecriture      -> PORTE (une verification ne doit rien ecrire)

    scelle()   15 lignes de code · 0 ecriture      -> PRESENT, ET IL NE SCELLE RIEN
               'scellees' => 0
               'scellement_possible' => false
               'motif' => 'audit.scellement_impossible'

> **Le legacy porte le seul chemin d'insertion scellée (`audit_log.php:107-116`) ; le portage
> a une méthode du même nom qui rend un refus constant.** *« Le docblock est une prose, pas une
> mesure » — et la signature n'est pas davantage une mesure que le docblock.*

Ce n'est pas un défaut caché : `ScellementDesarmeTest` gèle cet état depuis le 2026-09-06, et
le portage l'assume. Mais **ça change la portée d'un futur archivage** : le jour où
`login.php` sera porté et où ce fichier deviendra retirable, la question « le scellement
est-il porté ? » restera ouverte, et sa réponse est aujourd'hui **non**.

---

## L'INSTRUMENT — et pourquoi celui qui était prescrit ne répond pas à cette question

La consigne demandait `scripts/geste-porte.py` plutôt qu'un motif improvisé. **Il a été lancé,
avec ses témoins :**

    /cve_scan           APPELE    ScanCveController.php:174  url('/api/gateway/cve_scan')
    /tickets            APPELE    tickets.js:188, 208 · ScanCveController.php:222
    /cve_reprioritize   APPELE    ScanCveController.php:160
    /zzz-temoin         ABSENT    (temoin negatif)

**L'outil fonctionne et discrimine.** Mais son domaine est *« ce chemin de passerelle est-il
appelé par le portage »* — or `audit_log.php` n'est pas un chemin de passerelle, c'est un
`require` PHP. **Un instrument juste, appliqué à un objet qu'il ne mesure pas, rend un verdict
sans valeur** : il aurait dit « ABSENT » pour la seule raison qu'il ne cherche pas cela.

*C'est la même famille que les erreurs de désignation de la veille : l'instrument marche, le
résultat est correct, et il ne répond pas à la question posée.* La mesure utilisée ici est
donc un balayage `require`/`include` sur les 868 fichiers vifs, avec son témoin.

---

## CE QUI A ÉTÉ ARCHIVÉ

**Rien.** Aucun fichier retiré, aucune vue Blade touchée, aucun geste exercé sur une machine.

## CE QUI RENDRAIT CE FICHIER ARCHIVABLE

1. Le portage de `legacy/auth/login.php` — c'est lui qui inclut et qui écrit.
2. Et, séparément, une décision sur le **scellement** : le portage ne le porte pas.

*Tant que la connexion du legacy vit, son journal d'audit vit avec elle.*
