# `security/backend-cve` — ce que ses six correctifs ferment

Session 4, relecture du **2026-09-02**, en lecture pure. Base de fusion `279f5fa` (2026-08-20),
six commits du **2026-08-21 au matin**, jamais fusionnés. **643 insertions, 6 fichiers**, dont
**321 lignes de tests**.

> **Aucun des six n'a d'équivalent sur le tronc.** Vérifié marqueur par marqueur — ils sont donc
> tous encore nécessaires, et la nuit du 2026-09-02 a montré ce que coûte de l'ignorer : sept
> sessions ont re-trouvé, re-mesuré et re-rédigé `a345e65`, écrit douze jours plus tôt.

---

## Les six, par ce qu'ils ferment

| commit | ce qu'il ferme | famille |
|---|---|---|
| **`3e65ad3`** | le clamp anti-fréquence des scans planifiés était **contournable** — ajoute `_INTERVALLE_MINIMUM = 600` et deux listes fermées (`_SOURCES_SCAN`, `_CIBLES`) | *ne pas offrir d'entrée libre* |
| **`8043303`** | une **panne d'enrichissement effaçait le drapeau KEV** — le « best-effort » écrasait une donnée vraie par une absence. Ajoute `epss_echoue` / `kev_echoue` | *un échec n'est pas une absence de donnée* |
| **`427306c`** | `cve_reprioritize` était **la seule écriture CVE sans aucune garde**, alors que **la page exigeait `can_scan_cve` depuis toujours** | *la garde est sur la page, pas sur la requête* |
| **`399931a`** | le décorateur d'accès machine **ne lisait pas les paramètres de CHEMIN** | latent — voir ci-dessous |
| **`a345e65`** | les scans CVE **joignaient des machines archivées**, et une cible `machines` illisible **retombait sur tout le parc** | *échouer fermé* |
| **`9ac8456`** | une CVE blanchie pouvait être **signée du nom de n'importe qui** — `whitelisted_by` venait du corps de la requête, avec `'admin'` en défaut | *ne jamais dériver une identité du client* |

## Ce que la relecture ajoute, et qui n'était pas demandé

### `399931a` ferme un trou **latent**, pas actif — et c'est mesuré

Le correctif étend `require_machine_access` aux paramètres de chemin. **Mesuré sur l'arbre actuel :
trois routes portent un identifiant de machine dans leur chemin, et aucune des trois ne porte le
décorateur.**

```
/supervision/overrides/<int:machine_id>   ×2   api_key, role, permission — MA absent
/supervision/agents/<int:machine_id>           api_key, role, permission — MA absent
```

**La fusion ne changerait donc l'issue d'aucune requête d'aujourd'hui**, et **mon relevé des gardes
survit intact** — les états `mord` / `redondant` / `sans objet` ne bougent pas. Le correctif protège
la route qui combinerait un jour les deux, et c'est une bonne raison de le prendre : *un garde qui ne
lit pas tous les endroits où l'identifiant peut être ne garde rien le jour où quelqu'un l'y met.*

**Je le dis parce que l'inverse aurait été plus vendeur** : présenter `399931a` comme fermant un trou
ouvert aurait renforcé le dossier de fusion, et c'aurait été faux.

### `8043303` est de la famille que ce chantier compte le plus

*« Un best-effort qui écrase une donnée vraie par une absence »* — c'est `sudoers_orphelin`,
c'est `unknown` sur `wazuh_agents`, c'est le troisième état de `supervision_agents` (migration 064),
et c'est mon prédicat à trois valeurs sur `credential-status`. **Cinq occurrences, et celle-ci est
la plus ancienne écrite.** L'auteur avait la règle avant nous.

### Et `3e65ad3` porte la liste fermée que nous avons re-proposée

`_CIBLES = ('all','tag','machines')` — c'est la liste fermée que E-280 et E-281 ont discutée cette
nuit. **Pour `cve.py`, elle est écrite.** Mon apport E-280 porte sur `ssh_audit.py`, que la branche
ne touche pas (**0 occurrence**, vérifié) : il survit entièrement.

---

## Ce que ça change pour la décision

**La branche n'est pas « six correctifs qui attendent ».** C'est :

- **deux défauts d'autorisation atteignables** (`427306c`, `9ac8456`) — une écriture sans garde, et
  une identité prise dans le corps de la requête ;
- **deux défauts de portée** (`3e65ad3`, `a345e65`) — un garde-fou contournable, et une cible qui
  échoue ouvert sur la tâche dont l'aboutissement **envoie un courriel réel** ;
- **un défaut d'intégrité de donnée** (`8043303`) ;
- **un durcissement latent** (`399931a`), qui ne change rien aujourd'hui.

**Et 321 lignes de tests**, qui ne sont pas sur le tronc non plus.

> Le coût de ne pas fusionner n'est plus théorique : **il a été payé une fois, en une nuit de sept
> sessions.** Les cinq autres correctifs sont exposés au même sort — et chaque jour qui passe rend
> plus probable qu'on en re-trouve un.
