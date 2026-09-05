# AUDIT — `ssh_audit` : le découpage existe, et l'axe qui lui manque

**Session 5 (sécurité, lecture seule).** Mesuré le **2026-09-02**. Aucune écriture
de code, aucune machine jointe.

Le Lead demande « le découpage, puis le premier sous-lot ». **Le découpage existe
déjà** — `MODULE-SSH-AUDIT.md` §5, A1 à A4, argumenté. Ce document ne le refait
pas : il l'éprouve contre ce qui a été mesuré depuis, et il en corrige la
**priorité**.

---

## 1. Ce qui n'existait pas n'était pas le découpage

Le Lead a mesuré : 0 route Laravel, 0 commit « A1 — », donc « le découpage
n'existe nulle part ». **Les deux premières mesures sont justes, la conclusion
porte sur le mauvais objet** — c'est l'**exécution** qui n'existe pas.
`MODULE-SSH-AUDIT.md` §5 propose A1→A4, avec la réserve d'A3 (couper SSH sur le
banc) et l'inexécutabilité d'A4.

> Même forme que le reste du chantier : *mesurer l'INSTANCE n'est pas mesurer
> l'ENSEMBLE.* Ici, mesurer les **traces** d'un découpage n'est pas mesurer le
> découpage.

**Et le §5 est bon.** Je ne le remplace pas ; j'y ajoute un axe.

---

## 2. ⚠ L'AXE QUI MANQUE : A1 est le sous-lot le plus EXPOSÉ du module

Le découpage pèse **ce que chaque sous-lot touche** — base, machine, parc. C'est
le bon axe pour le *danger d'exécution*, et c'est ce qui a rendu `iptables`
livrable par morceaux.

**Le croisement de gardes (E-236) est sur un axe INDÉPENDANT** : non pas *ce que
le geste touche*, mais *qui peut l'atteindre*. Mesuré, les deux axes sont
**opposés** sur ce module :

| sous-lot | ce qu'il touche | croisements de gardes |
|---|---|---|
| **A1** | **base seule** | **7** |
| A2 | SSH, lecture seule | 0 |
| A3 | écrit `sshd_config`, recharge `sshd` | 5 |
| A4 | tout le parc par SSH | 1 |

**13 croisements sur 18 entrées** — et **A1 en porte plus que A3 et A4 réunis.**

> **Le sous-lot qui ne touche rien est celui que le plus de comptes peuvent
> atteindre.** Les deux axes ne se déduisent pas l'un de l'autre, et le
> découpage n'en pesait qu'un.

Cela ne change pas l'ordre — A1 reste le bon premier, pour la raison du §5 (c'est
le seul endroit où le chemin nominal de la garde est mesurable). **Cela change ce
que A1 doit produire** : il n'est pas « le sous-lot sûr qu'on fait pour
commencer », c'est **celui où la garde doit être portée avec le plus de soin**.

---

## 3. ⚠ SEC-013 — `/ssh-audit/policies` : une URL, deux méthodes, deux vocabulaires

C'est l'instance la plus nette du croisement rencontrée dans ce dépôt, et elle
tombe **dans A1**.

```python
@bp.route('/ssh-audit/policies', methods=['GET'])
@require_api_key
@require_permission('can_audit_ssh')     # la permission
@require_machine_access                  # bornée par machine

@bp.route('/ssh-audit/policies', methods=['POST'])
@require_api_key
@require_role(2)                         # le rôle, et RIEN d'autre
                                         # ni permission, ni borne par machine
```

**Lire** une politique exige la permission et est bornée par machine.
**Écrire** une politique n'exige aucune permission, n'est bornée par aucune
machine, et demande seulement le rôle 2.

> **L'écriture est MOINS gardée que la lecture, sur la même URL.** Un rôle 2 sans
> `can_audit_ssh` ne peut pas lire une politique — et peut en écrire une, sur
> n'importe quelle machine.

**Et la passerelle ne peut pas les séparer** : `RoutesBackend::correspond`
compare des **chemins**, jamais des méthodes. Une seule entrée de liste blanche
couvre les deux. *La borne ne peut pas être posée là.*

**GRAVITÉ** — la plus haute du module. **UN COMPTE RÉEL L'OCCUPE-T-IL** — voir §4.

**CORRECTIF PROPOSÉ** — aligner le POST sur le GET :
`@require_permission('can_audit_ssh')` **et** `@require_machine_access`. **Ce
qu'il casserait** : un rôle 2 sans la permission perdrait une écriture qu'il
n'aurait jamais dû avoir, et qu'il ne peut pas relire. **Session 4 applique.**

---

## 4. ⚠ CORRECTION AU LEAD : « porteur inutilisable » est RÉFUTÉ, et c'est écrit

Le Lead écrit, à propos de `scan-all` : *« écart réel, porteur inutilisable […]
il devient utilisable au premier enrôlement 2FA »*.

**C'est la version d'avant la mesure du 2026-09-01.** Réfutée et documentée dans
`AUDIT-E236-GARDES-CROISEES.md` §3 (`39b4207`) :

1. **L'enrôlement 2FA n'exige aucun administrateur.** `enable_2fa.php:33` ne
   demande que `$_SESSION['temp_user']`, posé par le **seul mot de passe** ; et le
   portage a désormais son propre enrôlement (`SecondFacteurController`). *Le
   compte enrôle son second facteur lui-même.*
2. **`force_password_change` n'est pas une barrière sur le portage.**
   `ouvreLaSession()` pose `utilisateur_id` **et `role_id`** — session complète
   ouverte — **puis** redirige une fois. `SessionAuthentifiee` ne vérifie que
   `utilisateur_id`, et **aucun middleware ne lit
   `changement_mot_de_passe_requis`**. Le legacy relit la base à **chaque**
   requête, `api_proxy.php` comprise ; le portage contrôle **une fois**, à la
   connexion.

**Qualification juste** : ni « occupé » ni « inutilisable », mais **porteur
dormant à réveil autonome** — son armement demande seulement que le détenteur
légitime du compte se connecte une fois. Il n'a jamais tenté (`login_history`
porte **0** tentative), et je n'ai pas cherché son mot de passe.

> **Une conclusion écrite fait renoncer à mesurer** — et ici la conclusion
> réfutée circulait encore trois jours après sa réfutation, dans la consigne de
> travail qui cadre le portage. *C'est le mode de propagation qui compte : elle
> ne voyage pas comme une hypothèse, elle voyage comme un état.*

**Ce que ça change pour le découpage** : A4 n'est pas « le geste dangereux dont
le porteur dort ». C'est le geste dangereux dont le porteur **peut se réveiller
seul**. Et A1 et A3, qui portent 12 des 13 croisements, sont atteignables par le
même compte.

---

## 5. Ce que je NE fais pas, et pourquoi

**Je ne porte pas A1.** Mon mandat est de qualifier en lecture seule et de
proposer ; l'exploitant a ouvert **une** exception d'écriture, pour `iptables` et
pour ce périmètre seul. Une session ne s'étend pas son propre périmètre, et un
pair ne le lui étend pas non plus.

**A1 est prêt à être porté par session 3**, avec ce que ce document ajoute :
- porter la garde de la **page** en `role:1` + `perm:can_audit_ssh`, comme le
  legacy — et non en `role:2`, ce qui reproduirait le croisement côté portage ;
- ne composer **aucun** appel vers `POST /ssh-audit/policies` tant que SEC-013
  n'est pas refermé côté backend — fermeture **par l'absence**, comme I1 sur
  `iptables` ;
- rendre `/results` en sachant qu'il ne porte **ni rôle ni permission** : sa seule
  borne est `require_machine_access`, inerte dès le rôle 2.

---

## 6. Ce que je n'ai PAS mesuré

- **les corps de `/fix`, `/save-config`, `/toggle`, `/restore`, `/reload`** — le
  §6 de `MODULE-SSH-AUDIT.md` le signalait déjà, et ça reste vrai. La question
  d'E-174 (*la valeur du client est-elle citée à l'INTÉRIEUR de la commande ?*)
  n'est pas tranchée sur ce module ;
- **`_load_policies` et la table `ssh_audit_policies`** — donc ce que la branche
  globale d'E-211 divulgue exactement reste inconnu ;
- **le JS du legacy** (782 lignes) n'a pas été croisé avec sa page : le motif
  « identifiant lu sans cible » n'est **pas** écarté ;
- **rien n'a été déclenché** — aucune machine jointe, aucune suite, aucun
  conteneur chargé pour ce document.

---

## 7. Priorisation demandée : E-280 **au-dessus** de SEC-013 — et pas pour la raison proposée

**Mesuré le 2026-09-02.** Le Lead oppose *« SEC-013 atteignable par un rôle 2
légitime »* à *« E-280 atteignable seulement par requête forgée »* et demande le
classement. **La prémisse ne tient pas ; le classement tient quand même, pour
d'autres raisons.**

### 7.1 La reachability est IDENTIQUE, pas différente

```
POST /ssh-audit/policies    @require_api_key + @require_role(2)      <- SEC-013
POST /ssh-audit/schedules   @require_api_key + @require_role(2)      <- E-280
```

**Même garde, même population, même chemin de passerelle.** Aucune permission,
aucune borne par machine, ni sur l'une ni sur l'autre.

**Et E-280 ne demande aucune valeur forgée** :

```python
target_type = data.get('target_type', 'all')     # ssh_audit.py:767
```

**`'all'` est le DÉFAUT.** Il ne faut pas *forger* un champ — il faut **l'omettre**.
Un client qui ne connaît pas le paramètre vise le parc entier sans le savoir.

> *« Ne pas offrir d'entrée libre »* est bien déplacé d'un cran, comme le Lead
> l'écrit — mais d'un cran de plus encore : **ce n'est pas une entrée libre à
> l'API, c'est un DÉFAUT permissif.** Le formulaire ne l'offre pas ; l'absence du
> champ suffit. Un repli qui atterrit du côté permissif, cinquième classe de la
> mission.

### 7.2 Ce que chacune fait — et c'est là que le classement se décide

**E-280 agit sur des machines.** Mesuré dans `scheduler.py`, la boucle du job :

```python
with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, service_account=svc) as client:
    config  = get_sshd_config(client, root_pass)     # root sur la cible
    ssh_ver = get_ssh_version(client, root_pass)
```

**Une vraie session SSH par machine, à chaque tic de cron**, avec un intervalle
minimum de **10 minutes** (`ssh_audit.py`, refus au-delà). Le parc entier, et le
scheduler tourne dans un **thread invisible à `ps`**.

**SEC-013 agit sur un verdict.** Une politique n'est consommée qu'ici :

```python
policies = _load_policies(mid)                       # ssh_audit.py:138
result   = audit_sshd_config(config_text, policies)  # :139
```

**`/fix` ne consomme AUCUNE politique** — vérifié : il prend `directive` et
`value` de la requête, contre `ALLOWED_DIRECTIVES` (liste fermée) et `VALUE_RE`.
Écrire une politique ne déclenche donc **aucune** action distante ; ça change ce
que l'audit **rapporte**.

### 7.3 Le classement, et ses quatre appuis

**E-280 d'abord.**

| | E-280 | SEC-013 |
|---|---|---|
| population | rôle 2, sans permission | **identique** |
| effet | **session SSH root sur tout le parc**, répétée | une ligne en base qui change un rapport |
| réversibilité | les connexions faites ne se défont pas | un `DELETE`, effet confiné au rapport |
| observabilité | thread **invisible à `ps`** | ligne lisible par le GET |

**Mais ils ne se disputent pas la même place** : E-280 est un risque
d'**incident**, SEC-013 un risque de **confiance dans le contrôle**. Si les deux
restent ouverts, *SEC-013 est ce qui ferait douter des traces qu'E-280 laisse.*
**Premier et second, pas premier et plus tard.**

### 7.4 ⚠ SEC-014 — le même audit rend deux verdicts selon qui le lance

Trouvé en mesurant le précédent, et il **réduit** la portée de SEC-013 tout en
ouvrant autre chose :

```python
route      :139   audit_sshd_config(config_text, policies)   # AVEC les politiques
scheduler         audit_sshd_config(config)                  # SANS
```

**Le scan planifié ignore les politiques ; le scan à la demande les applique.**
Une directive marquée `ignore` disparaît du rapport d'un humain et reste dans
celui du scheduler — sur la **même machine**, la **même configuration**, la même
journée.

**Conséquence sur SEC-013** : son effet d'aveuglement ne porte **pas** sur les
scans planifiés. Sa portée est plus étroite que je ne l'aurais dit sans cette
mesure. **Conséquence propre** : deux chemins du même contrôle de sécurité
produisent des scores différents, et rien à l'écran ne dit lequel on regarde.

**Non qualifié plus loin** : je n'ai pas mesuré si `audit_sshd_config` a une
valeur par défaut pour son second paramètre, ni ce que la table contient
aujourd'hui.

### 7.5 ~~Sur l'arbre et le service~~ — **RETIRÉ : c'était faux, et je l'avais repris sans mesurer**

**Ce paragraphe affirmait** qu'en service le repli d'E-280 ne filtrait pas les
machines archivées (`a33a15b`) alors que l'arbre le fait, et en tirait que *« le
redémarrage attendu est aussi un correctif partiel d'E-280 »*.

**Les deux affirmations sont fausses.** Le Lead s'est rétracté ; **je l'ai vérifié
moi-même plutôt que d'accepter la rétractation**, en ancrant la comparaison sur la
FONCTION et non sur un `else:` :

| fonction | `a33a15b` vs arbre | filtre `archived` | branche `WHERE 1=0` |
|---|---|---|---|
| `_run_scheduled_ssh_audit` | **IDENTIQUE** (75 lignes) | OUI des deux côtés | OUI des deux côtés |
| `_run_scheduled_scan` (CVE) | **IDENTIQUE** (85 lignes) | **NON** des deux côtés | **NON** des deux côtés |

**Il n'y a AUCUNE divergence arbre/service dans ce fichier, pour aucune des deux
tâches.** Le Lead avait grepé `^        else:` et récolté le **premier** du
fichier — celui du scan CVE. Il opposait donc le CVE d'hier à l'audit SSH
d'aujourd'hui.

> **Et ma faute est distincte de la sienne.** J'avais lu l'arbre et **accepté sa
> mesure du service**, puis écrit « tu as raison » — ce qui a transformé son
> erreur en fait à deux voix, et l'a fait partir en **argument de signature** vers
> une autre session. *Deux accords sur une mesure fournie par un seul ne font pas
> deux mesures.* Le nombre de confirmations mesure la **diffusion**, pas la
> vérité. La règle est du Lead ; l'occurrence est de moi.

**Ce que je retire** : le redémarrage n'est **pas** un correctif partiel d'E-280.

### 7.6 ⚠ E-281 — vérifié par ma propre lecture, et il PRIME E-280

Le Lead le signale ; je l'ai mesuré indépendamment, et la forme est plus nette
que l'énoncé. `_run_scheduled_scan`, sélection des cibles :

```python
elif schedule['target_type'] == 'machines' and schedule['target_value']:
    ids = [...]
    if ids:
        cur.execute(f"SELECT {base_cols} FROM machines WHERE id IN ({fmt})", ids)
    else:
        cur.execute(f"SELECT {base_cols} FROM machines")      # <- LE PARC ENTIER
else:
    cur.execute(f"SELECT {base_cols} FROM machines")          # <- LE PARC ENTIER
```

**Le `else` interne est le décisif** : une planification qui dit *« vise CES
machines-là »* avec une valeur qui ne rend **aucun identifiant valide** scanne
**tout le parc**. Ce n'est pas un défaut d'absence — c'est une intention
explicitement ÉTROITE qui tombe du côté large.

**Et la bonne forme était connue de l'auteur** : à la même place, dans le même
fichier, `_run_scheduled_ssh_audit` écrit `FROM machines WHERE 1=0`. *Divergence,
pas oubli* — l'observation est du Lead et elle est juste.

**Pourquoi E-281 prime E-280** — même population (`/cve_schedules` porte
`@require_role(2)` sans permission, mesuré au même titre que les autres) :

| | E-280 (audit SSH) | **E-281 (CVE)** |
|---|---|---|
| branche étroite vidée | `WHERE 1=0` — **ferme** | **`FROM machines` — OUVRE** |
| machines archivées | exclues | **incluses** |
| effet sortant | aucun | **envoie un vrai courriel** |

**Classement révisé : E-281, puis E-280, puis SEC-013.** Le premier échoue du
côté large là où le second échoue du côté fermé, et lui seul a un effet hors du
parc.

---

## 8. Les trois mesures demandées — et elles DÉFONT mon classement

**Mesuré le 2026-09-02, lecture de fichiers seule.** Aucun appel de route, aucune
insertion, aucun conteneur chargé, aucune machine jointe. Périmètre accordé
explicitement par le Lead.

### 8.1 Q1 — le courriel ne part PAS sur un scan planifié

`send_cve_report` (`mail_utils.py:194`) a **exactement un appelant** dans tout
`backend/` :

```
backend/routes/cve.py:77     dans _stream_cve_scan   <- la route en flux, le chemin S7b
```

Et le job planifié ne passe **pas** par là : `scheduler.py:_run_scheduled_scan`
appelle `scan_server(...)` **directement**, dans sa propre boucle, puis :

```python
from webhooks import notify_cve_scan
notify_cve_scan(f"Scan planifie: {schedule['name']}", total_findings, 0, 0, 0, scanned)
```

**C'est un webhook, pas un courriel.** Le courriel appartient à la route en flux
— celle que l'arbitrage S7b retient — et **jamais à la planification**.

### 8.2 Et le webhook lui-même est FERMÉ par défaut

```python
WEBHOOK_ENABLED = os.getenv('WEBHOOK_ENABLED', 'false').lower() == 'true'
WEBHOOK_URL     = os.getenv('WEBHOOK_URL', '')

def is_enabled(event=''):
    if not WEBHOOK_ENABLED or not WEBHOOK_URL:
        return False
```

Défaut `'false'`, URL vide. **En configuration par défaut, E-281 n'a AUCUN effet
hors du parc** — ni courriel, ni webhook.

> **⚠ MON CLASSEMENT REPOSAIT SUR CE FAIT, ET IL EST FAUX.** J'avais écrit
> *« E-281 prime E-280 […] lui seul a un effet hors du parc »*, en signalant que
> je ne l'avais pas mesuré. Mesuré, **la troisième colonne de mon tableau tombe.**

### 8.3 Q2 — `base_cols` porte les IDENTIFIANTS, et c'est le vrai fait

```python
base_cols = ("id, name, ip, port, user, password, root_password, "
             "service_account_deployed")
```

La branche qui échoue ouvert ne se contente pas d'**énumérer** plus de machines :
elle **charge le mot de passe SSH et le mot de passe root de chacune**, les
déchiffre dans la boucle (`encryption.decrypt_password`) et **ouvre une session
SSH** vers chaque.

> *« Scanner les mauvaises machines »* est en réalité **« s'authentifier sur
> toutes les machines du parc »**. Cela vaut pour E-280 **comme** pour E-281 —
> c'est le fait qui domine les deux, et il est plus lourd que l'effet sortant que
> je cherchais.

### 8.4 Classement révisé — et ma recommandation est de NE PAS les classer

| | E-281 (CVE) | E-280 (audit SSH) |
|---|---|---|
| branche étroite vidée | **OUVRE** | `WHERE 1=0` — **ferme** |
| machines archivées | **incluses** | exclues |
| effet sortant | **aucun** *(retiré)* | aucun |
| déclenchement accidentel | valeur malformée requise | **`'all'` par OMISSION — plus facile** |
| identifiants chargés | tout le parc | tout le parc |

**Chacun gagne sur un axe différent.** E-281 échoue contre une intention
explicitement étroite — *l'exploitant croit avoir borné, donc personne ne relit*.
E-280 se déclenche **par simple omission d'un champ**, ce qui est beaucoup plus
probable.

**Ma recommandation : les traiter comme UN défaut, pas deux rangs.** Même forme,
mêmes tables sœurs, même population (`@require_role(2)` sans permission), même
correctif : **liste fermée de `target_type`, repli fail-closed, filtre
`archived`**. Les classer invite à n'en corriger qu'un — et c'est le motif
« un défaut revient par une autre porte », déjà payé.

**S'il faut trancher malgré tout : E-281 d'abord**, parce qu'un repli qui trahit
une intention étroite échappe à la relecture, alors qu'un défaut permissif se
voit en lisant la planification.

### 8.5 Ce que je n'ai toujours pas mesuré

- **la configuration réelle de `WEBHOOK_ENABLED`** sur les déploiements — je lis
  le **défaut du code**, pas l'environnement. Si un exploitant l'a activé, l'effet
  sortant revient, et **cette mesure-là demande un conteneur** ;
- **les 0 lignes de `cve_scan_schedules` et `ssh_audit_schedules`** sont la mesure
  **du Lead**, pas la mienne — elle exigerait la base, hors du périmètre accordé.
  *Je la porte comme sienne, pas comme un fait à deux voix* ;
- **rien n'a été déclenché.**

---

## 10. PRÉPARATION DE « CRÉER UN RELEVÉ PLANIFIÉ » — 2026-09-05, 23:38 CEST

**Demandée en préparation d'un portage. Mesuré : la capacité EST DÉJÀ PORTÉE.**
*Lecture seule, fenêtre 3 du LOT, `docs/` seul.*

### 10.1 Le geste est porté — trois appels réels, commentaires exclus

```
laravel/public/js/audit-ssh.js
  :705   ecris('/ssh-audit/schedules', corps)                     POST   — ARME
  :180   fetch(PASSERELLE + '/ssh-audit/schedules/' + n, …)       DELETE
  :194   fetch(PASSERELLE + '/ssh-audit/schedules/' + n + '/toggle')
```

**Cinq autres occurrences du même chemin dans ce fichier sont des COMMENTAIRES**
(`:14`, `:43-45`, `:172`). *Un relevé sans lecture en aurait compté huit — « cité »
n'est pas « appelé », et c'est la deuxième fois ce soir que ma propre règle me
rattrape.*

**Et le fichier le déclare à son site**, en énumérant par NOM D'APPELANT et non
par numéro de ligne — *parce qu'une insertion au-dessus périme un numéro en
silence.*

### 10.2 Les quatre réponses demandées

| | |
|---|---|
| **① le geste** | `POST /ssh-audit/schedules` — **porté**, via la passerelle |
| **② ce qu'il écrit** | table `ssh_audit_schedules` ; colonnes lues du corps : `name` (défaut `'Scan SSH periodique'`, tronqué à 100), `cron_expression`, `target_type`, `target_value` — **et `next_run` + `created_by` posés par le serveur** |
| **③ les libellés** | `ssh_audit.sched_*` — **15 clés**, de `sched_new` à `sched_add`. **⚠ AUCUN libellé de RÉSULTAT** : la famille s'arrête à `sched_add`. *L'heuristique « personne n'écrit quatre messages de résultat pour un geste qu'il n'accomplit pas » ne s'applique pas ici — il n'y en a zéro, dans un sens comme dans l'autre.* |
| **④ la garde** | `require_api_key` + `role:2` + **`perm:can_audit_ssh`** ; dans `ADMIN_SEULEMENT` ; **AUCUN step-up** — `MOTIFS_STEP_UP` ne couvre que `/policy/…` |

### 10.3 ⚠ MON E-236 EST PARTIELLEMENT PÉRIMÉ SUR CE MODULE

Le 2026-09-01 j'ai mesuré **13 routes croisées** dans `ssh_audit.py`. **Remesuré
ce jour : 8.**

**Les CINQ routes de planification portent désormais `require_permission`** — et
le code porte le commentaire : *« Elles portaient `@require_role(2)` SEUL, alors
que les deux pages du module… Même écart qu'E-402 sur les politiques. »*

> **Ma trouvaille a été corrigée, et mon document ne l'a pas suivi.** *Correction
> dans le sens rassurant — donc celle que personne ne rouvre.* **Deuxième fois
> qu'un de mes documents vieillit sous un correctif qu'il a lui-même provoqué.**

### 10.4 ⚠ SEPT ROUTES DU MODULE N'ONT AUCUN APPELANT — et elles se répartissent en TROIS natures

Le DSI demande : *« si tu trouves d'autres routes sans appelant, dis-le — le
module est peut-être plus creux qu'il n'en a l'air ».* **Il l'est : 7 sur 16.**

| route | nature | catégorie |
|---|---|---|
| `/ssh-audit/save-config` · `/fix` · `/toggle` · `/restore` · `/reload` | **écrivent `sshd_config`, rechargent `sshd`** | **A3 — sous-lot NON PORTÉ**, retenu |
| `/ssh-audit/backups` | lecture distante | **trou DANS A2**, sous-lot porté |
| `/ssh-audit/trends` | lecture en base | **trou DANS A1**, sous-lot porté |

> **La distinction porte, et elle est celle du §7.3 de `AUDIT-CATALOGUE-POLITIQUES` :**
>
> - **cinq routes appartiennent à un sous-lot qu'on a CHOISI de ne pas porter** —
>   c'est du travail en attente, nommé, et la frontière « ce qui reste écrit »
>   tient sur elles ;
> - **deux sont des TROUS dans des sous-lots PORTÉS.** *A1 et A2 sont déclarés
>   livrés ; deux de leurs gestes n'ont jamais été câblés.* **Ce ne sont ni des
>   orphelines par dépréciation ni des retenues : c'est une TROISIÈME forme —
>   un sous-lot déclaré complet qui ne l'est pas.**

**Et rien ne les signale** : le sous-lot est marqué porté, sa page existe, ses
autres gestes fonctionnent. *`/ssh-audit/trends` est de surcroît promise par
`openapi.yaml` — donc un contrat public sans client.*

### 10.5 Ce que je ne fais pas

**Aucune planification créée**, sous aucune forme. *Le scheduler tourne dans un
fil invisible à `ps`, et une planification de test peut déclencher un vrai scan
SSH.* **Interdit respecté.**

**Et je ne porte rien** : `laravel/` est hors de mon périmètre d'écriture, et la
capacité n'a de toute façon pas besoin d'être portée — **elle l'est.**
