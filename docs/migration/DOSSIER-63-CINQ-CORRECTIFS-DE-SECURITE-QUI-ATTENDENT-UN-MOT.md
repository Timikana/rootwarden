# DOSSIER-63 — Cinq correctifs de sécurité qui attendent un mot

**Écrit le 2026-09-09 à 03:20 CEST.** Aucun n'est fusionné. Aucune chaîne n'a été
exercée sur une machine.

> Ce dossier existe pour **remplacer cinq lectures par une**. Chaque PR porte sa
> mesure complète ; ici il n'y a que ce qui décide : la gravité, l'ordre, et ce
> que la fusion coûte.

---

## 1. Les cinq, par gravité décroissante

| # | fichier | ce que l'acteur gagne | forme du défaut |
|---|---|---|---|
| **70** | `routes/graylog.py` | **rôle 2 → exécution root sur toute machine accessible, sans identifiant SSH** | classe trop faible |
| **64** | `sudo_manager.py` | rien de plus qu'il n'a — **la piste d'audit tombe** | validation couplée au formatage |
| **71** | `sftp_manager.py` | rien de plus — **la PERSISTANCE s'ajoute** | appel absent |
| **68** | `ssh_audit.py` | rien : aucune frontière franchie | défense en profondeur |
| **74** | `routes/supervision.py` | rien aujourd'hui : sûr par contingence | durcissement, **rendu prouvé inchangé** |

**Seule la #70 franchit une frontière de confiance.** Les quatre autres corrigent
des défauts réels chez un acteur qui a déjà le privilège — *ce qui les rend moins
urgents, pas moins vrais.*

---

## 2. Ce qu'elles ont en commun, et qui est le résultat de la nuit

**Aucun des trois défauts exploitables n'entre par la valeur interpolée.** Le
cliquet des commandes root indirectes répondait **« sûr »** sur les trois — et il
avait raison, *dans son domaine*.

```
#70  base64 irreprochable         ->  grammaire RSYSLOG, root
#64  shlex.quote irreprochable    ->  grammaire SUDOERS, root
#71  heredoc quote irreprochable  ->  grammaire SSHD_CONFIG, root
```

> **Un gage se juge sur son DOMAINE et sur son PUITS, pas sur sa qualité.** La
> bonne question n'était pas « la garde domine-t-elle ? » — la réponse était
> **oui** les trois fois — mais **« domine-t-elle dans la dimension du puits ? »**

**Et les trois formes sont différentes** : une classe trop faible, une validation
couplée au formatage, un appel absent. *Ce n'est pas une classe de défaut, c'est
une classe de QUESTION.*

---

## 3. Ce que chaque fusion coûte, et ce qu'elle ne coûte pas

**Aucune des cinq n'exige un redémarrage pour être fusionnée.** Mais ⚠ **aucune
n'est en service avant un redémarrage** : `use_reloader = False`, `workers = 4`,
et `rootwarden_python` tourne depuis le 2026-09-07 12:53 UTC avec **37 commits
`backend/` absents du processus**.

```
#74  rendu SEMANTIQUEMENT inchange, mesure sur les 4 appelants  ->  risque nul
#68  une garde AJOUTEE, aucun chemin legitime touche            ->  risque nul
#70  une classe RESSERREE : un chemin de CA hors [A-Za-z0-9._/-]
     serait desormais refuse. 5 chemins reels mesures, tous acceptes
#64  `runas` invalide rend 400 la ou il rendait 200 sur la branche
     `custom` — c'est le correctif, et c'est un changement d'API
#71  ⚠ un CHANGEMENT DE RENDU sur une entree qui passait deja :
     la garde hissee normalise, donc `" /upload "` rend `-d /upload`
     au lieu de `-d  /upload `. Si une empreinte de fichier deploye
     est comparee quelque part, elle bougera. (releve par 0b)
```

---

## 4. ⛔ Ce qui n'a pas été fait, et pourquoi

**Aucune des cinq chaînes n'a été exercée.** Chacune écrirait sur une machine du
parc : une directive rsyslog, une ligne `sudoers`, un `sshd_config`, une
désinstallation d'agent.

> Mieux vaut cinq dossiers qui nomment leur trou que cinq dossiers qui l'ont
> comblé par vraisemblance.

Si une démonstration de bout en bout est voulue, c'est **la machine 3**
(OpenCVE-Test-OnPrem, 192.168.0.2) et **sur ton mot seul** — jamais celui d'une
session.

**Une chose reste non mesurée et nommée dans la #70** : `deploy()` porte
`@threaded_route`, et le traitement d'une exception non rattrapée par ce
décorateur n'a pas été mesuré. *La propriété de sécurité tient quel qu'en soit le
comportement — rien n'est écrit ; c'est le diagnostic qui pourrait souffrir.*

---

## 5. Comment les cinq ont été trouvés

**Aucun par relecture. Aucun par moi seule.**

```
#70  gestion-ssh-key-4f   en qualifiant 3 sites qui se sont tous reveles surs
#64  gestion-ssh-key-94   idem, 4 sites surs, le defaut entre par un ARGUMENT
#71  gestion-ssh-key-0b   idem, 4 sites surs, la garde etait sur l'autre branche
#68  gestion-ssh-key-c1   par une sonde FAUSSE, qu'elle a relue parce qu'elle
                          ALARMAIT
#74  5f puis ec           en corrigeant un COMPTE, pas en cherchant un defaut
```

**Les cinq ont été rejoués avant reprise**, et deux de mes propres relevés ont été
rectifiés par les pairs : un `Store` compté pour une lecture, et un compte
d'appelants **par nom** au lieu de par objet — *celui-là je l'avais relayé sans le
rejouer, parce qu'une correction qui me charge a l'air d'être déjà passée par un
contradicteur.*

---

## 6. Ce que je recommande

**① Fusionner la #70 dès que possible.** C'est la seule qui franchit une
frontière, et son risque de fusion est borné : cinq chemins de CA réels mesurés,
tous acceptés, borne de longueur conservée.

**② Puis #74 et #68**, dont le risque de fusion est nul.

**③ Puis #64 et #71**, qui changent un comportement — la #64 un code de retour,
la #71 un rendu. *Ni l'un ni l'autre n'est un piège, mais ils méritent d'être lus
avant d'être pris.*

**④ Et le redémarrage APRÈS**, pas avant : il met les cinq en service d'un coup,
avec les 37 autres commits. *L'ordre inverse mettrait en service les 37 sans les
cinq.*
