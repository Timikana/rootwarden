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
