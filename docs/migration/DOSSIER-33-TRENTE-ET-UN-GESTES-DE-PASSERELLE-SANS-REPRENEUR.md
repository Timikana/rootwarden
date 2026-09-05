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
