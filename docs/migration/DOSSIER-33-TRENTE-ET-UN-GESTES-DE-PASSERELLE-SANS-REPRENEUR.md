# DOSSIER 33 — Trente et un gestes de passerelle qu'aucun portail n'appelle plus

**2026-09-05, 18:45 CEST.** *Découvert en corrigeant un défaut que mon propre archivage
avait créé.*

---

## 1. ⛔ CE QUE MA Q3 NE POUVAIT PAS VOIR

**Mon contrôle avant archivage mesurait les ÉCRITURES SQL de la page.** *Une page dont le
geste passe par la PASSERELLE n'écrit rien en SQL : elle appelle le backend.*

    legacy/bashrc/index.php   ecritures SQL : 0   -> classe « LECTURE PURE »
    son JS                    appelle `/bashrc/deploy`
    le portage                appelle `/bashrc/preview`, `/template`, `/users`
                              JAMAIS `/bashrc/deploy`

> **J'ai archivé trois pages qui étaient le seul accès à un geste non porté, en les
> classant « lecture pure ».** *C'est exactement la Q3, ratée par un instrument qui
> mesurait la mauvaise chose.*

**RESTAURÉ dans le même tour** : `bashrc/`, `fail2ban/`, `ssh/` — pages et JS, vérifiés
vivants au réseau (302, JS 200).

---

## 2. LA MESURE QUE PERSONNE N'AVAIT FAITE

**Comparer les chemins de PASSERELLE appelés par le legacy et par le portage**, tous
modules archivés confondus.

    chemins appeles par le PORTAGE : 87   (temoin : `/drift/scan_all` present)

    ⛔ 31 chemins appeles par le legacy archive, et par AUCUN portail :

    wazuh        detect · group · install · install_all · restart · uninstall     6
    ssh-audit    backups · fix · policies · reload · restore · save-config
                 scan-all · toggle                                               8
    services     disable · enable · logs · restart · start · status · stop       7
    supervision  config · config/read · config/save · (fichier de conf)          4
    graylog      deploy · test · uninstall                                       3
    adm          policy/rollback                                                 1
    tasks        tasks/list                                                      1
    api          (motif de documentation, pas un geste)                          1

---

## 3. ⚠ CE QUE CETTE LISTE EST, ET CE QU'ELLE N'EST PAS

**Ce n'est PAS une liste de trente et un défauts.** *Une partie de ces gestes est sur
l'interdit permanent du chantier — les six de `wazuh`, le `scan-all` de `ssh-audit` — et
leur non-portage est une DÉCISION.*

**Mais la liste n'a jamais été établie, donc personne ne peut dire lesquels.** *Et
plusieurs de ces modules ont été archivés bien avant aujourd'hui : `services`, `tasks`,
`supervision`, `graylog` étaient dans les dix-neuf du matin.*

> **La question à trancher n'est pas « faut-il les porter » : c'est « lesquels ont été
> perdus sans que personne ne le décide ».**

---

## 4. Ce que je recommande, et ce que je ne fais pas

**Je ne restaure pas les cinq autres modules.** *Trois l'ont été parce que j'ai la preuve
que leur geste est absent du portage ET que leur page l'offrait encore hier. Pour les
autres, l'archivage est ancien et la perte, si elle existe, ne date pas d'aujourd'hui.*

**Ce qu'il faut, module par module** : *le geste est-il volontairement abandonné, ou
perdu ?* **Trois issues, et la troisième est celle que l'inaction produit :**

    (a) le porter
    (b) l'abandonner EXPLICITEMENT, et le retirer de la documentation
    (c) ne rien dire  <- l'ecran promet, le backend repond, et plus rien n'appelle

**⚠ Et le point qui rend (c) coûteux : le BACKEND répond encore.** *Ces trente et un
points d'entrée existent, sont gardés, et fonctionnent. Ce qui a disparu est l'interface
qui les appelait.* **Une capacité dont le moteur tourne et dont le tableau de bord a été
retiré ne se découvre pas par une panne.**

---

# ⛔ RECTIFICATION (19:40) — le titre de ce dossier est FAUX. Ils sont TROIS, pas trente et un.

**Et sur les trois, un est un exemple de documentation.**

    chemins du portage      226, dont 29 PREFIXES
    temoin  /services/start   couvert ? OUI
    temoin  /zzz/inexistant   couvert ? non

    SANS REPRENEUR :
      api          /a/b/c                      <- un exemple, pas un geste
      supervision  /config/read, /config/save

## Ce que ma sonde faisait de faux, et c'est la troisième fois en deux jours

**Elle cherchait des chemins COMPLETS. Le portage en connaît vingt-neuf sous forme de
PRÉFIXES**, et construit le reste à l'exécution :

    laravel/public/js/services.js     `lit('/services/' + geste, {…})`
    RoutesBackend.php:116             '/services/', '/admin/', '/bashrc/'

**`ServicesSystemd.php` existe, `ServicesController` aussi, et le menu porte une entrée
`services` gardée `can_manage_services`.** *J'ai annoncé sept gestes perdus sur un module
entièrement porté.*

## ⚠ Le motif, et il est le mien

    « 73 orphelins, 651 Kio »   ->  le reseau en a rendu 5
    « 31 gestes sans repreneur » ->  la mesure par prefixe en rend 3
    « 61 suites sans objet »     ->  la session du banc en a compte 33

> **Trois fois en deux jours, j'ai publié un compte que le bon instrument a divisé par dix
> ou plus. Chaque fois, ma sonde cherchait une FORME LITTÉRALE là où le système compose.**

**Et le sens de l'erreur est constant : elle ALARME.** *C'est le côté sûr, et c'est
précisément pourquoi il ne se fait pas contredire — une alarme fait travailler, elle ne
fait pas vérifier.* **Les trois n'ont été corrigées que parce que quelqu'un est allé
mesurer autrement : le réseau, une autre session, et cette fois moi-même en cherchant
pourquoi `services` paraissait perdu alors que son menu existe.**

## Ce qui reste vrai de ce dossier

**Le fait qui l'a ouvert reste entier** : *ma Q3 mesurait les écritures SQL, et trois pages
dont le geste passe par la passerelle ont été archivées à tort.* **Elles sont restaurées.**
*C'est le seul contenu de ce dossier qui tienne, et il vaut la peine qu'il ait été ouvert.*

**Les deux chemins de `supervision` restent à instruire** — `/config/read` et
`/config/save`, sachant que `/supervision/config` EST couvert. *Deux, et je ne les
qualifie pas avant de les avoir mesurés.*

---

# ✅ CLÔTURE (19:55) — **zéro**. Le dossier n'avait pas d'objet, sauf le fait qui l'a ouvert.

    annonce initiale         31 gestes sans repreneur
    apres les PREFIXES        3
    apres verification des
      invocations             0

**Les deux derniers étaient `/config/read` et `/config/save` — des FRAGMENTS.** *Le legacy
comme le portage construisent `'/supervision/' + plateforme + '/config/read'`, et le
portage l'invoque nommément :*

    SupervisionController.php
      'lecture'  => url("/api/gateway/supervision/{$plateforme}/config/read")
      'ecriture' => url("/api/gateway/supervision/{$plateforme}/config/save")

**Le troisième, `/a/b/c`, est un exemple de documentation.**

## ⚠ La distinction que j'ai failli confondre, et dans les deux sens

**« Couvert par un préfixe » veut dire que la passerelle AUTORISE. Cela ne dit pas que le
portage APPELLE.** *J'ai d'abord conclu « couvert » sur la seule liste blanche — c'eût été
la même faute que « présent dans l'arbre donc servi », inversée.*

**Il a fallu chercher l'INVOCATION**, et elle était elle-même construite.

> **Trois fois dans la même enquête, la réponse était « le chemin se construit ».** *Et
> trois fois ma sonde cherchait un littéral.* **Ce n'est plus un piège d'instrument, c'est
> la façon dont ce dépôt est écrit.**

## Ce qui reste de ce dossier, et qui justifie qu'il ait existé

**Ma Q3 mesurait les écritures SQL. Trois pages dont le geste passe par la passerelle ont
été archivées à tort, et sont restaurées.** *C'est un fait, il tient, et il a coûté une
capacité pendant quatre heures.*

**Le reste de ce dossier était un artefact de mes propres sondes.** *Et le sens de l'erreur
a été constant : ALARMER.* **Une alarme fait travailler, elle ne fait pas vérifier — c'est
pourquoi il a fallu trois passes pour la ramener à zéro, alors qu'un dédouanement du même
ordre aurait été cru du premier coup.**
