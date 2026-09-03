# Croisement geste par geste — une capacite declaree absente est-elle deja cablee ?

**Mesure du 2026-09-03, banc occupe (LOT en cours) : ce document ne contient AUCUNE ecriture de
code.** Les deux defauts trouves sont SIGNALES, pas corriges — l'un des deux vit dans des fichiers
PARTAGES.

## Pourquoi ce croisement, et pourquoi il avait echoue

Une capacite peut etre declaree absente alors que le portage l'appelle deja. C'est le defaut qui a
fait declarer `pare-feu` incapable d'une validation qu'il cable, et il s'est reproduit six fois cette
semaine sous des formes differentes.

Les tentatives precedentes se sont trompees pour une raison unique : **elles cherchaient le nom de la
capacite au lieu de partir des ROUTES.** Le legacy dit `uninstall`, le portage dit `desinstallation` —
chercher l'un dans l'autre rend zero, et le zero passe pour un constat.

## L'instrument, et ses SIX pieges

Il part des **203 routes du backend** et demande, pour chacune : le portage l'appelle-t-il ?

    piege                                        ce qu'il faisait rendre
    1  chemin CONCATENE  `'/policy/sudo/' + g`   0 sur un grep du chemin entier
    2  nom francais du portage                   0 en cherchant le nom du legacy
    3  classe de caracteres `[^]]+`, `[a-z_/]`   se referme sur `paire[0]`, exclut `-` `<` `:`
    4  `re.search` au lieu de `re.findall`       un seul bloc lu sur plusieurs
    5  le COMMENTAIRE compte pour un appel       cite != appele
    6  prefixe `/api/gateway` et substituts      `{mid}` cote PHP, `<int:mid>` cote backend

## TROIS ETATS, PAS UN BOOLEEN

    exacte       un litteral concorde sans joker            -> appelee, sur
    indecidable  seule une BASE CONCATENEE concorde          -> A LIRE A LA MAIN
    non          rien ne concorde

Le troisieme etat n'est pas une commodite. Accepter le joker des deux cotes fait concorder
`/policy/sudo/*` avec `/policy/sudo/deploy` — ce qu'il faut — **mais aussi avec n'importe quelle route
soeur que personne n'appelle.** Une base concatenee marquerait toute sa fratrie comme appelee et
**masquerait des absences reelles.** C'est le risque inverse de la sonde qui accuse : celle-la
DEDOUANE.

## LE GARDE DE TEMOINS : l'instrument n'est cru que s'il les passe

    8 temoins POSITIFS   des routes dont je SAIS qu'elles sont appelees
    5 temoins NEGATIFS   des gestes que ce portage n'exerce nulle part

**Cinq versions ont ete refusees par ce garde**, et chaque refus a nomme un defaut de l'instrument,
jamais de la donnee :

    v1  123/203 « appelees »          -> 3 faux negatifs vus AVANT publication
                                         (supervision 1/27, groups 2/4, cve 2/14)
    v2  concordance par segments      -> 4 temoins NEGATIFS tombent : il dedouane
    v3  fichiers declaratifs exclus   -> `RoutesBackend.php` DECLARE des chemins,
                                         il n'en appelle aucun. Un espace de noms
                                         n'est pas un geste.
    v4  liens legacy ecartes          -> `rtrim(url_legacy,'/') . '/wazuh/'` n'est
                                         pas un appel ; le `'/'` du rtrim etait pris
                                         pour un debut de chemin
    v5  regle « base -> enfants » :   -> ce n'etait pas la REGLE qui etait fausse,
        son critere corrige              c'etait son CRITERE. Ce qui distingue un
                                         enfant d'un espace de noms est le `+`.

**Verdict final : les 13 temoins passent.**

    exacte      : 87
    indecidable : 22
    non appelee : 94

*L'ecart avec la v1 est la lecon : elle annoncait 123 appelees, il y en a 87 de sures. Elle
sur-comptait les appels, donc elle **masquait des absences** — dans le sens qui rassure.*

## ⚠ DEFAUT 1 — la legende du menu explique un marqueur qui n'existe plus

    Navigation.php    'route'  => : 32      'legacy' => : 0
    portail.blade.php:26  et  :119         la legende est rendue SANS CONDITION

> « Les entrees marquees d'une fleche ouvrent l'ancien portail dans un nouvel onglet. »

**Aucune entree ne porte la fleche.** La legende est rendue deux fois — barre laterale et tiroir
mobile — et elle explique un marqueur que le menu ne produit plus depuis qu'il est passe a 32/32.

*Elle etait vraie a l'ecriture. Le dernier basculement l'a rendue fausse sans que rien ne la touche.*

**NON CORRIGE** : `layouts/portail.blade.php` et `Navigation.php` sont des fichiers PARTAGES — a
annoncer avant d'ecrire. Et le banc est pris.

## ⚠ DEFAUT 2 — `ssh` declare non portee une lecture qu'il FAIT

    lang/fr/ssh.php   'non_porte' => « Le declenchement du deploiement ET LA LECTURE
                                       DE SON JOURNAL ne sont pas encore portes. »

    matrice           /deploy   non appelee      <- la premiere moitie est VRAIE
                      /logs     EXACTE           <- la seconde est FAUSSE

    ClesSshController.php:93    'url_journal' => url('/api/gateway/logs')
    cles-ssh.js:390             await fetch(L.url_journal, …)

**Le journal est lu.** Une URL fournie n'est pas une URL lue — cette distinction a deja coute une
mesure — donc c'est le `fetch` qui tranche, et il est la.

**Et le commentaire d'en-tete du controleur porte la meme erreur, en plus large** :

> « K1 n'appelle AUCUNE route du backend. Le declenchement du deploiement (K4) et la lecture de son
> flux (K3) restent sur l'ancien portail, et la page le dit. »

`preflight_check` et `logs` sont tous deux appeles. **Une CONJONCTION dont un membre devient faux se
lit comme entierement vraie** — septieme occurrence de cette forme cette semaine.

*`description` porte la meme phrase en plus court (« le deploiement lui-meme reste sur l'ancien
portail ») et elle, elle est JUSTE : elle ne parle que du declenchement.*

## Les 22 indecidables — a lire a la main

Chacune concorde avec une base concatenee. **Il faut enumerer les valeurs que la variable peut
prendre au site d'appel** — c'est ce qui a marche sur `cle-plateforme` : les cles y sont litterales
aux appels, et l'enumeration a rendu 28 cles pour 0 manquante.

    approvals.py
      /approvals/<int:request_id>/approve            POST             approbations.js
      /approvals/<int:request_id>/reject             POST             approbations.js
      /approvals/stats                               GET              approbations.js
    graylog.py
      /graylog/deploy                                POST             graylog.js
      /graylog/templates/<name>                      DELETE,GET       graylog.js
      /graylog/test                                  POST             graylog.js
      /graylog/uninstall                             POST             graylog.js
    groups.py
      /groups/<int:group_id>/members                 GET              groupes.js
      /groups/<int:group_id>/run                     POST             groupes.js
    maintenance.py
      /maintenance/windows/<int:window_id>           DELETE,PUT       maintenance.js
    policies.py
      /policy/sftp/deploy                            POST             acces-sftp.js
      /policy/sftp/remove                            POST             acces-sftp.js
      /policy/sudo/deploy                            POST             politiques.js
      /policy/sudo/remove                            POST             politiques.js
    services.py
      /services/disable                              POST             services.js
      /services/enable                               POST             services.js
      /services/logs                                 POST             services.js
      /services/restart                              POST             services.js
      /services/start                                POST             services.js
      /services/status                               POST             services.js
      /services/stop                                 POST             services.js
    supervision.py
      /supervision/machines/<int:mid>/profile        DELETE,GET,POST  SupervisionController.php

*Ne pas conclure « appelee » ni « non appelee » sur ces 22-la sans avoir ouvert le
fichier.*

## ✅ LES 22 INDECIDABLES SONT RESOLUS — 19 appelees, 3 non appelees

**Methode : enumerer les valeurs que la variable prend AU SITE D'APPEL.** C'est celle qui a marche
sur `cle-plateforme` (28 cles composees, 0 manquante), et elle demande d'ouvrir le fichier — aucune
expression reguliere ne la remplace.

    base                        variable    valeurs LITTERALES trouvees          verdict
    /policy/sudo/               geste       deploy · remove                      2 appelees
    /policy/sftp/               geste       deploy · remove                      2 appelees
    /graylog/                   geste       deploy · test · uninstall            3 appelees
                                            (`graylog.js:318-320`, table fermee)
    /graylog/templates/         nom         suffixe direct (`:376`, `:467`)       1 appelee
    /groups/                    id          + `/members` · + `/run` · nu          2 appelees
                                            (`groupes.js:391,478,521,575,619`)
    /maintenance/windows/       f.id        suffixe direct (`:351`, `:362`)       1 appelee
    /approvals/                 action      approve (`:178`) · reject (`:126`)    2 appelees
    /services/                  geste       stop · restart · start · disable
                                            · enable  (`services.js:216-224`,
                                            table fermee)                        5 appelees
    /supervision/machines/…     mid         `url_profil` (controleur)             1 appelee

### ⚠ Les TROIS que la resolution rend NON APPELEES

    /approvals/stats     seule la base `/approvals/*` la faisait concorder — et cette
                         base ne produit que `approve` et `reject`
    /services/logs       aucune occurrence dans tout le portage
    /services/status     idem — la page lit `/services/list`, un LITTERAL, pour l'etat

*TEMOIN de ce dernier releve : la base `'/services/'` est trouvee une fois dans `services.js`, donc
l'instrument voit bien ce fichier.* **Sans ce temoin, « aucune occurrence » et « je n'ai pas su
chercher » auraient ete la meme sortie.**

**Aucune de ces trois ne contredit une declaration** : `services` et `approbations` ne declarent
aucune absence. Ce sont des capacites du backend que le portage n'emploie pas — et personne n'a
affirme le contraire.

### Le compte final

    exacte, litteral        87
    exacte, apres lecture   19
    non appelee             97
    ---
    total                  203

*Le troisieme etat a donc bien servi : il portait 19 appels que la matrice ne pouvait pas prouver
seule, et 3 absences qu'elle aurait pu dedouaner.*

## Ce que ce croisement ne dit PAS

    une route appelee                 ne dit pas que la page l'OFFRE (elle peut etre
                                      derriere un panneau non branche)
    une route non appelee             ne dit pas que la capacite est absente : elle
                                      peut etre portee SANS backend
                                      (`serveurs.cycle` ecrit en direct)
    une declaration non contredite    ne dit pas qu'elle est vraie : elle dit que
                                      CE croisement ne l'a pas contredite

*La derniere ligne est la plus importante : ce document ecarte une classe de defaut, il n'en atteste
aucune conformite.*
