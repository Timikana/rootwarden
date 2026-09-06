# QA — les suites qui existent sans être jouées, et un livrable qui n'a nulle part où atterrir

**Mesure du 2026-09-06 09:3x.** Deux constats distincts, dont le second est bloqué par une
question de droits que ni `c1` ni moi ne pouvons trancher.

---

## 1. L'écart entre ce qui existe et ce qui est joué — mesuré

    TEMOIN   suites `go-*.mjs` sur disque              116  (non nul)
             suites citees dans `scripts/rejouer-lot.sh` 89

    suites ABSENTES des deux listes du runner            26

> **Ce que le runner exerce est la définition de fait de « ce qui est testé ». Ce qui existe
> dans `tests/` est autre chose, et rien ne mesure l'écart.** *(formulation de la session 94,
> reprise telle quelle)*

### Le cas signalé par `c1`, vérifié

    grep -c go-page-profil-rgpd scripts/rejouer-lot.sh   ->  0
    le fichier existe                                    ->  25 007 o, 2026-09-04

Elle est **absente des deux listes, sans commentaire qui l'explique** — là où
`go-adm-import-csv` est exclue *et documentée sur trente lignes* par le runner. **Une absence
sans raison écrite est indiscernable d'un oubli**, et c'est la seule différence qui compte :
`go-adm-import-csv` est une décision, `go-page-profil-rgpd` est un silence.

Elle exerce un export, pas un geste destructeur — donc **moins grave** que
`go-ssh-audit-schedules`, dont la borne d'enrôlement est née.

### ⚠ Et `go-ssh-audit-schedules` est TOUJOURS absente

    grep -c go-ssh-audit-schedules scripts/rejouer-lot.sh   ->  0

Le geste destructeur a été désarmé cette nuit ; **l'invisibilité, elle, demeure**. *Désarmer
une suite et l'enrôler sont deux corrections différentes, et la première laisse la seconde
ouverte.* Ce n'est pas un reproche à qui l'a désarmée — c'est que le défaut de fond n'était
pas le geste, c'était que rien ne pouvait le révéler.

---

## 2. ⛔ Un livrable fini qui n'a nulle part où atterrir — À ARBITRER

`gestion-ssh-key-c1` a produit `go-page-profil-effacement.mjs` : 22 assertions, 0 FAIL,
les deux bornes du DSI tenues. **Le fichier est fini et mesuré. Personne ne peut le poser.**

    `c1`        sa consigne d'exploitation lui interdit d'ecrire dans
                `tests/e2e/`, `laravel/tests/` et `backend/`
    moi (QA)    mon perimetre m'interdit d'ecrire dans `tests/e2e/` — et
                `scripts/rejouer-lot.sh`, ou se fait l'enrolement, n'est pas
                davantage dans mon perimetre d'ecriture

**`c1` a raison de ne pas s'autoriser l'écriture sur la foi d'une décision qui lui arrive par
un pair** : *un pair ne peut pas accorder une permission qu'il n'a pas, même en relayant
fidèlement quelqu'un qui le pourrait.* Si une consigne pouvait être levée par relais, elle ne
vaudrait rien — il suffirait de la faire relayer.

**Et je ne peux pas la poser à sa place.** Deux raisons, chacune suffisante :

1. **`tests/e2e/` est hors de mon périmètre**, indépendamment de sa situation.
2. Même si ce n'était pas le cas, **poser un fichier PARCE QU'UN AUTRE EN EST EMPÊCHÉ est
   précisément le contournement que sa consigne existe pour empêcher.** Le faire au nom de
   l'efficacité viderait la règle de son contenu — et ce serait moi, pas elle, qui l'aurais
   vidée.

### Ce que la QA peut faire, et fait

- **Lire et qualifier** le contenu du fichier contre les deux bornes : c'est le travail
  d'attestation, il ne demande aucun droit d'écriture.
- Consigner l'état bloqué ici, daté, pour qu'il ne se perde pas dans un fil de session.

### Ce qui doit être tranché, et par qui

**L'exploitante.** La décision du DSI (« le harnais entre dans le dépôt ») et la consigne de
`c1` (« pas d'écriture dans `tests/e2e/` ») sont en contradiction, et **la contradiction ne
se résout pas entre pairs** : elle se résout par qui a autorité sur les deux.

*Ni `c1` ni moi ne devons « trouver un arrangement ». C'est exactement le moment où un
arrangement serait le défaut.*


---

## 3. ⛔ `go-policies.mjs` — un POST de DEPLOIEMENT SUDO sur la PRODUCTION, dans aucune liste

**Trouve par `gestion-ssh-key-c1`. Verifie independamment ligne a ligne.**

    tests/e2e/go-policies.mjs:131   xhr.open('POST', '/api_proxy.php/policy/sudo/deploy')
    tests/e2e/go-policies.mjs:138   xhr.send(JSON.stringify({ machine_id: 1, ... }))

    base rootwarden, table `machines` :
      id=1   srv-zabbix            192.168.0.244    ⛔ PRODUCTION
      id=2   Test-Server-Debian    10.10.10.10
      id=3   OpenCVE-Test-OnPrem   192.168.0.2

**`go-policies` n'est dans aucun des deux tableaux du runner.** Elle a donc *les deux*
proprietes de `go-ssh-audit-schedules` : **un geste destructeur sur la production, et
l'invisibilite qui empeche tout lot de le reveler.**

Le test ATTEND un `403` (`:140`) — il ne cherche pas a deployer. **Mais la requete PART.**
Ce qui la rend inoffensive n'est pas son intention, c'est ce qui la refuse a l'autre bout.

### Pourquoi elle est inerte AUJOURD'HUI — et pourquoi ca n'est pas une garde

    definition de `stepUpMark()`   legacy/auth/step_up.php:44        VIVANTE
    APPELS a `stepUpMark()`        1 seul, et il est ARCHIVE :
                                   legacy/_deprecated/auth/step_up_verify.php:68
    CONTRE-EPREUVE                 1 definition trouvee — l'instrument voit bien

**Plus aucun code vivant ne peut poser `_step_up_policy_action`.** `api_proxy.php:63` exige
`stepUpVerify('policy_action')` — action codee **en dur**, donc la garde est correcte a ce
point d'appel — et cette verification echoue desormais toujours. Le deploiement est refuse
**inconditionnellement**.

> **C'est un effet de l'ARCHIVAGE, pas une decision.** Le jour ou le poseur revient porte, le
> POST redevient vivant *et rien ne le dira*. Une suite qui ne fait rien parce qu'une piece
> manque ailleurs n'est pas une suite sure : c'est une suite dont la surete est detenue par
> quelqu'un d'autre, qui l'ignore.

⚠ **Et `c1` a corrige sa propre explication avant qu'elle ne voyage** : elle allait ecrire que
la garde est faible parce que le legacy pose `_step_up_<ce que le client envoie>`. **Faux a ce
point d'appel** — l'action y est en dur. Le defaut de nom libre vit chez qui POSE la marque,
pas chez qui la verifie. *La distinction aurait ete perdue en un relais.*

---

## 4. ⚠ COROLLAIRE EN PRODUCTION — la modale de step-up du legacy est CASSEE

    legacy/js/utils.js:123           POST /auth/step_up_verify.php
    fichier hors de `_deprecated/`   AUCUN  ->  404

**Pour tous les utilisateurs du legacy, pas seulement pour les tests.** Toute action legacy
exigeant un step-up est donc impossible a completer : la modale s'ouvre, poste sur un 404, et
l'action initiale n'est jamais rejouee.

*Le sens de la panne est FERME* — les gestes destructeurs sont refuses, pas ouverts — donc ce
n'est pas un trou de securite. **C'est une capacite perdue que personne n'a declaree**, et
elle est en service. Le portage, lui, a son propre chemin (`POST /profil/step-up`) : le defaut
ne le concerne pas.

**Ni `c1` ni moi ne corrigeons** : `legacy/` est du code applicatif, et la decision de
reparer, d'archiver ou de laisser mourir avec le legacy appartient a l'exploitante.
