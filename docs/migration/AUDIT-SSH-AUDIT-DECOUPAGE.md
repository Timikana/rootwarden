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

### 7.5 Sur l'arbre et le service — le Lead a raison, et il faut le nommer

Le Lead écrit que « en service c'est pire », le `else` de `a33a15b` étant
`SELECT … FROM machines` **sans filtre**. **Dans l'ARBRE d'aujourd'hui, le filtre
existe** :

```sql
FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'
```

**Ce n'est pas une contradiction, ce sont deux systèmes.** Les `.py` sont lus au
**démarrage** : le processus en service précède la modification de l'arbre. Le
Lead décrit le service, je lis l'arbre, et **les deux affirmations sont vraies en
même temps**. La seule chose qui manquerait serait de ne pas dire lequel on
mesure — *une affirmation sans son régime est invérifiable.*

**Et le régime aggrave bien ici** : jusqu'au prochain redémarrage, la portée du
repli inclut les machines **archivées**. Le redémarrage — déjà en tête des
signatures attendues — est donc aussi un correctif partiel d'E-280.
