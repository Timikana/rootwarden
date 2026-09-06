# AUDIT — les « 2 capacités perdues » de `supervision` : il n'y en a aucune

**Session 5 (sécurité, lecture seule).** Mesuré le **2026-09-05**. Aucune
écriture de code, aucune machine jointe.

Le DSI demande de rouvrir **deux capacités perdues**, en avertissant que son
relevé vient d'un motif sur des mots et que *« ce document a déjà pourri trois
fois »*. **Mesuré : il a pourri une quatrième. Les deux capacités sont réglées,
et la tâche n'a pas d'objet.**

---

## 1. « modifier le jeton d'API de supervision » — la phrase a été corrigée le 2026-09-03

Le DSI décrit la page comme disant *« reste sur l'ancien portail »* alors que ce
chemin rend 404. **C'est l'état d'AVANT le 2026-09-03.**

`laravel/lang/fr/superv.php` porte, au-dessus de la clé :

```
⚠ CETTE PHRASE PROMETTAIT UN CHEMIN MORT.
Elle disait « elle reste sur l'ancien portail ». Mesure du 2026-09-03, avec
témoins : `https://…:8443/supervision/` rend 404 ; la racine du legacy rend 302
et un chemin inexistant rend 404 — donc 404 est bien le signal « absent », et
non une panne du serveur. Le dossier est archivé dans `legacy/_deprecated/supervision`.
```

**Le libellé rendu est aujourd'hui** :

```
FR  'secret_jeton_non_porte' => "La modification de ce jeton n'est pas encore portee ici."
EN  'secret_jeton_non_porte' => "Changing this token is not ported here yet."
```

**Il ne promet aucun chemin.** Et vérifié indépendamment :

| mesure | résultat |
|---|---|
| `legacy/supervision/` dans l'arbre | **absent** (archivé sous `_deprecated/`) |
| `url_legacy` dans `supervision.blade.php` | **0 occurrence** |
| tous les `href=` de la vue | pointent vers `route('supervision')`, en interne |
| parité FR/EN de la clé | présente |

> **L'option (c) du DSI — « laisser le libellé en l'état » — n'est donc pas la
> mauvaise : c'est celle qui est déjà juste.** Ce qu'il décrit comme faux a été
> corrigé six jours avant sa demande, **par une session qui a posé un témoin
> propre** (302 sur la racine, 404 sur l'inexistant, pour établir que 404
> signifie « absent » et non « en panne »).

### 1.1 Un résidu, et il est ARGUMENTÉ — donc je ne le compte pas comme défaut

Le libellé dit *« pas encore portée »*, ce qui suggère un portage en retard. Le
commentaire, lui, dit que la capacité est **retenue**, pas en retard — et que le
motif du blocage n'est **délibérément pas écrit à l'écran** :

> *« L'écrire à l'écran indiquerait à qui lit la page où est le défaut et sur
> quelle colonne. La discrétion n'est pas de l'opacité quand l'alternative est
> une carte. »*

**C'est un arbitrage rendu, pas un oubli.** Le coût — un « pas encore » qui
laisse croire à un calendrier — est réel mais moindre que celui de l'alternative.
*Je le signale sans demander de le changer.*

---

## 2. « rattacher un serveur à un profil » — PORTÉE, et depuis longtemps

Le DSI la donne « exacte côté portage » (donc non portée). **Mesuré : elle est
portée.** `laravel/lang/fr/superv.php` porte une section entière :

```
// ══ V13 — LE RATTACHEMENT D'UN SERVEUR A UN PROFIL ════════════════════
'profil_colonne'   'profil_aucun'   'profil_aucun_catalogue'
'profil_rattache'  'profil_detache' 'profil_echec'
'profils_titre'    'profil_nom'     'profil_actions'
```

*Recoupé avec le suivi du chantier : la capacité est décrite comme livrée en
`v1.37.15` — « profils assignables via un menu de la colonne Profil du tableau de
déploiement », plus `GET /supervision/profiles/assignments`.* **Deux sources
indépendantes, et elles concordent.**

---

## 3. Ce que ce relevé apprend, et qui vaut plus que les deux capacités

**Le DSI a annoncé le risque et il s'est réalisé sur les deux points qu'il
annonçait.** Il écrivait : *« mon relevé dit X — c'est un motif sur des mots,
l'instrument exact qui m'a rendu 5 faux dédouanements ce matin »*, et *« ce
document a déjà pourri trois fois »*.

> **Une quatrième.** Et les deux erreurs vont dans le sens du TRAVAIL À FAIRE :
> le document invente deux tâches qui n'existent pas. *C'est le sens le moins
> coûteux — on mesure, on ne trouve rien, on s'arrête. Le sens inverse, un
> document qui dit « fait » sur du non-fait, ne se rouvre jamais.*

**Et ce qui a évité les deux fois n'est pas la vigilance** : c'est que le DSI a
**ordonné de mesurer avant d'exécuter**, en nommant l'instrument qui l'avait
trompé. *La consigne portait sa propre réfutation.*

---

## 4. Ce que je ne fais pas

**Aucun arbitrage à rendre** : le choix (a) porter / (b) retirer la phrase n'a
pas d'objet — la phrase est déjà juste et la seconde capacité est portée.

**Et si un arbitrage naissait**, il ne serait pas à moi : `laravel/` est hors de
mon périmètre d'écriture, qui se limite à `iptables` et aux branches
`security/…`. *Je mesure et je qualifie ; une autre session écrit.*

**Non mesuré, et dit** : je n'ai pas ouvert la page au navigateur. La parité des
clés, l'absence de renvoi et le contenu des libellés sont établis **par lecture**.
*Ce qui me réfuterait : un libellé construit dynamiquement ailleurs que dans
`superv.php`, ou un lien posé par le JS plutôt que par le gabarit.* **Non
vérifié — le banc n'est pas à moi.**
