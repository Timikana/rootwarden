# 🔴 DOSSIER 25 — N'APPUYEZ PAS SUR « SCELLER ». Le bouton casse la chaîne d'audit, définitivement.

**Mesuré le 2026-09-04 entre 15:26 et 16:45 CEST. Trouvé par la session 3, vérifié ligne par ligne et en
base par moi.**

> **Ce n'est pas une exposition théorique. C'est un bouton, dans le portail porté, à un clic, derrière un
> parcours de confirmation qui donne toutes les apparences du geste normal.**

---

## 1. LA RÉGRESSION — les deux implémentations, côte à côte

    legacy/adm/api/audit_seal.php:78-82
        if ($prevSelf === null) {
            $orphanCount++;
            $pending[] = [(int)$r['id'], $lastHash, $computed];
            $lastHash = $computed;          <-- LA TETE AVANCE
        }

    laravel/app/Services/JournalAudit.php (scelle)
        if ($l->self_hash === null) {
            $orphelines++;
            $aSceller[] = [(int) $l->id, $tete,
                $this->empreinte($tete, …)];
            continue;                        <-- $tete N'AVANCE PAS
        }

**Conséquence : toutes les orphelines reçoivent le MÊME `prev_hash` — la tête telle qu'elle était avant la
première.** *Deux orphelines consécutives suffisent : la seconde devrait chaîner sur la première, elle
chaîne sur son prédécesseur.*

## 2. L'AMPLEUR — le défaut mord 462 fois au PREMIER clic

    orphelines                                        1484
    paires d'orphelines CONSECUTIVES (id, id+1)        462
    TEMOIN paires ou les DEUX sont scellees           3733

**Les témoins rendent non-zéro : ce sont des comptes mesurés. Le défaut n'est pas un cas limite — il est
la règle sur ce corpus.**

## 3. C'EST ATTEIGNABLE, ET LE PARCOURS EST CELUI QU'ON ATTEND

    web.php:1031   POST /journal-audit/sceller   role:3 + perm:can_admin_portal
    :247 / :255    le script SIMULE d'abord (`$simulation = true`), affiche
                   « N a sceller », puis la confirmation ECRIT pour de vrai

**Un exploitant qui suit exactement le parcours prévu — simuler, lire le compte, confirmer — déclenche le
défaut.** *La simulation ne le révèle pas : elle annonce le bon NOMBRE de lignes, et c'est leur CONTENU
qui est faux.*

## 4. 🔴 ET C'EST IRRÉVERSIBLE — deux mécanismes s'y ajoutent

    :280   ->where('id', $id)->whereNull('self_hash')
           le garde-fou repris du legacy : une fois ecrites, les lignes ne
           sont plus nulles, donc LE MEME OUTIL NE PEUT PLUS LES CORRIGER

    :264   'arret_sur_incoherence' => $p['erreur'] !== null
    :269   if ($simulation || $p['erreur'] !== null || …) -> n'ecrit pas
           apres le premier passage, `verifie()` rapporte CHAINON_ROMPU,
           donc `scelle()` REFUSE de tourner a nouveau

> **La chaîne serait cassée ET l'outil bloqué.** *Réparer demanderait un geste hors de l'outil, sur une
> table dont l'intérêt entier est de n'être pas modifiable à la main.*

## 5. LA CAUSE, ET ELLE EST INSTRUCTIVE

**Le commentaire de `JournalAudit.php` JUSTIFIE explicitement la tête qui n'avance pas** :

> *« c'est ce que fait `audit_log_raw`, et c'est donc ce que la chaîne inscrite en base signifie »*

**C'est VRAI de `audit_log_raw`, qui insère UNE ligne à la fois. Ce n'est pas vrai d'un SCELLEUR, qui en
traite un LOT.**

> **L'auteur a comparé son code à la bonne fonction pour le mauvais métier : l'homologue de `scelle()`
> n'est pas `audit_log_raw`, c'est `audit_seal.php`.**

*C'est la quatrième fois aujourd'hui qu'un raisonnement juste sur un objet est étendu à son homonyme — et
la première où le résultat est destructeur.*

## 6. ✅ LE CORRECTIF, ET IL TIENT EN UNE LIGNE

**Faire avancer la tête sur chaque orpheline scellée, comme le legacy** : *`$tete` doit recevoir
l'empreinte calculée avant le `continue`.*

**⛔ Je ne le fais pas écrire avant votre lecture de ce dossier, pour une raison qui n'est pas la
prudence** : *le correctif change ce que le bouton ÉCRIT dans la table d'audit. Il doit être relu par un
second regard et éprouvé sur un jeu de lignes, pas posé et cliqué.*

## 7. ⚠ ET LE DÉFAUT DE COUVERTURE DU `DOSSIER-20` EST INSTANCIÉ — pas hypothétique

**J'y écrivais : « la chaîne continuera de répondre *intègre*, parce qu'elle ne mesure que les lignes
qu'elle a scellées ». C'est déjà le cas, et voici le bloc :**

    « Connexion reussie », SCELLEES   4563   du 2026-05-26 au 2026-09-03
    « Connexion reussie », NUES        389   du 2026-08-12 12:38
                                              au 2026-08-15 12:54

    un SEUL ecrivain de cette chaine existe dans les trois couches :
      legacy/auth/login.php:201, et il SCELLE (via audit_log_raw)
    aucun ecrivain de « Connexion reussie » dans laravel/ ni backend/,
      dans les DEUX orthographes

> **Les 389 viennent du même endroit que les 4563. Elles forment un bloc CONTIGU de trois jours en août,
> avec des lignes scellées avant ET après.** *La chaîne a été refermée PAR-DESSUS le trou : `audit_log_raw`
> chaîne depuis « la dernière ligne dont `self_hash` n'est pas NULL », donc il enjambe les orphelines sans
> les voir.*

**Aujourd'hui la chaîne répond « intègre », et trois jours de journal de connexion d'août sont dehors.**

*Ce qui s'est passé du 12 au 15 août n'est pas mesuré, et je ne le suppose pas. Ce que la mesure établit
est que le trou existe, qu'il est contigu, et que la chaîne l'a enjambé.*

## 8. CE QUI VOUS REVIENT, DANS L'ORDRE

    1. ⛔ NE PAS appuyer sur « Sceller » — ni vous, ni personne, jusqu'au correctif
    2. ✅ autoriser le correctif d'une ligne + sa relecture par un second regard
    3. 📌 le trou du 12-15 aout : decider s'il faut chercher ce qui s'est passe.
          Le scellement, une fois CORRIGE, refermera la chaine par-dessus ces
          389 lignes — et ce faisant, il rendra le trou definitivement
          inexplorable par cet outil.

> ⚠ **Le point 3 est le seul qui ait un ordre contraint : si l'on veut savoir quelque chose de ces trois
> jours, il faut le chercher AVANT de sceller, pas après.**

**Et la direction du `DOSSIER-20` — fermer la fenêtre par un scellement périodique — reste juste, mais elle
attend le point 2 :** *automatiser le scellement en l'état ferait tourner ce défaut tout seul, sans
personne pour lire le résultat.*

---

## 9. ⚠ AJOUT — il y a DEUX raisons de chercher avant de sceller, pas une

**La mienne, au point 3** : *après, l'outil ne montrera plus rien.*

**La seconde, que je n'avais pas** : *les 389 lignes portent encore leur `created_at` et leur `action`
intacts. Sceller n'efface pas le CONTENU — il efface le SIGNAL qui dit « ces trois jours sont
différents ».*

> **C'est le MARQUEUR qu'on perd, pas la donnée.** *Une fois scellées, ces 389 lignes seront
> indistinguables des 4563 autres : rien, dans la table, ne dira plus qu'elles ont traversé une fenêtre
> où la chaîne ne les voyait pas.*

**Ça ne change pas la décision, ça change ce qu'elle coûte** : *l'ordre contraint du point 3 ne protège pas
une capacité d'enquête — il protège la seule trace qui indique OÙ enquêter.*

---

# ⛔ CORRECTION D'UNE CITATION DE CE DOSSIER — elle pointait une ligne VIDE

**Mesuré le 2026-09-05. Ce dossier citait `web.php:1031` pour la route de scellement.**

    ligne 1031 aujourd'hui   « »   (VIDE)
    la route reelle          `laravel/routes/web.php:1058`
      Route::post('/journal-audit/sceller', [JournalAuditController::class, 'sceller'])

**27 lignes de glissement. Le pointeur du dossier le plus urgent visait le vide.**

> **Un numéro de ligne dans un document est un fait que TOUTE ÉDITION SITUÉE AU-DESSUS rend faux — et il le
> devient EN SILENCE, puisque ni le document ni le code cité n'ont bougé.**

## ✅ LA FORME QUI NE GLISSE PAS

**Ce dossier repère désormais ses objets par leur NOM, jamais par leur ligne :**

    la route      `POST /journal-audit/sceller`  ->  `JournalAuditController::sceller`
    le scelleur   `JournalAudit::scelle()`, la branche `if ($l->self_hash === null)`
    le legacy     `audit_seal.php`, la branche `if ($prevSelf === null)`
                  et son `$lastHash = $computed;`
    l'ecrivain    `legacy/auth/login.php`, l'appel `audit_log_raw(…, 'Connexion reussie')`

**Un nom se déplace avec ce qu'il désigne ; un numéro reste où on l'a écrit.**

## ⚠ LES DEUX AUTRES CITATIONS DE CE DOSSIER TIENNENT — vérifiées une par une

    `legacy/adm/api/audit_seal.php:78`  ->  `if ($prevSelf === null) {`     ✔
    `legacy/auth/login.php:201`         ->  `audit_log_raw(…)`              ✔

*Elles tiennent parce que personne n'a édité au-dessus d'elles dans le legacy — c'est-à-dire par
l'immobilité d'un composant qu'on éteint, pas par une propriété de la citation.*

## ⚠ ET L'AMPLEUR SUR MES PROPRES ARTEFACTS

    citations `fichier:ligne` dans mes 29 dossiers : 128

**Chacune est un fait qui se périme par le haut. Je ne les réécris pas en masse — mais celle-ci était dans
le dossier que je vous présente comme le plus urgent, et son unique pointeur actionnable visait le vide.**

**Rien d'autre du dossier ne change : le défaut, l'ampleur (462 paires), l'irréversibilité et l'ordre
contraint des 389 lignes du 12-15 août sont inchangés.**
