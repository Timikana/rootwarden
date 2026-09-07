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

## ⛔ MA TROISIÈME RAISON ÉTAIT FAUSSE — rectifiée le 2026-09-07 au soir

**J'avais écrit** : *« le legacy porte le seul chemin d'insertion scellée
(`audit_log.php:107-116`) ; le portage a une méthode du même nom qui rend un refus
constant. »* **La première moitié est fausse.**

Le portage a son propre chemin d'insertion scellée, et ce n'est pas `scelle()` — c'est
`ajoute()`. Remesuré sur le code dépouillé :

    JournalAudit::ajoute()      DB::transaction  OUI
                                lockForUpdate    OUI
                                whereNotNull     OUI   (la tete saute les lignes nues)
                                prev_hash        OUI   (chaine a la tete)
                                self_hash        OUI   (empreinte du ts qu'on vient de poser)
                                ->insert(        OUI

    appelants en CODE : 9       ComptesController:93 · PermissionsController:70
                                ServeursController:141 · MotDePasse:591
                                ExigePermission:114 · PortailController:64/91/207
                                ExportRgpdController:64

**Ce sont deux opérations différentes, et c'est là que je me suis trompée :**

    ajoute()   sceller A L'INSERTION       PORTE
    scelle()   sceller RETROACTIVEMENT     impossible PAR CONSTRUCTION — et c'est JUSTE

Remettre les lignes nues dans la chaîne exigerait de réécrire le `prev_hash` de toutes les
scellées, c'est-à-dire **de détruire la seule propriété que la chaîne apporte**. Donc
`scellement_possible => false` **déclare une impossibilité vraie, pas une lacune.**

> J'avais écrit : *« la signature n'est pas davantage une mesure que le docblock »*. Le cran
> d'après est celui qui m'a eue : **une VALEUR DE RETOUR n'est pas davantage une mesure qu'une
> signature.** `false` peut vouloir dire « pas porté » **ou** « impossible, et c'est correct » —
> la même ambiguïté qu'une clé i18n absente, au niveau de la méthode.

*Signalé par le DSI, vérifié ici plutôt que ratifié.*

### ⚠ Deux pièges d'instrument rencontrés dans cette rectification

**1. Chercher `self_hash` pour trouver un écrivain trouve le récit de sa disparition.**

    ComptesController · PermissionsController · ServeursController
      `self_hash` brut = 1   ·   en CODE = 0   ·   INSERT `user_logs` = 0

La mention unique est de la **prose de docblock décrivant ce qu'ils faisaient avant**. *Un
faux positif qui ALARME* — il faut compter les `insert`, pas les mentions.

**2. Et « 11 sites » en vaut 9.** Le relevé transmis annonçait onze appels et en listait neuf.
Onze est le compte de `->ajoute(` ; **deux d'entre eux sont un homonyme** —
`ServeursController:77` (`$this->serveurs->ajoute`) et `Serveurs.php:457`, qui ajoutent un
SERVEUR. *Un couple qui ne se referme pas sur lui-même — le nombre et la liste se
contredisaient.*

## ⚠ CE QUI RESTE VRAI DE LA TROISIÈME RAISON

Rien pour l'archivage : elle est retirée des motifs. **Un seul verrou subsiste**, et c'est le
`require_once` de `login.php`.

---

## ~~ET UNE TROISIÈME RAISON~~ — texte d'origine, conservé pour la trace

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
