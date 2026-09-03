# Relevé des gardes du backend — route par route

Mesuré le **2026-08-27** par la session 4, pour que `api_docs` soit écrite à partir d'un état **juste**
plutôt que recopiée d'un état ancien. **229 routes** dans `backend/routes/*.py`.

---

## 0. ⚠ CE QUE CE RELEVÉ DÉCRIT, ET CE QU'IL NE DÉCRIT PAS

**Il décrit l'ARBRE DE TRAVAIL, pas le service.** Treize correctifs backend sont commités et
**inertes** : `backend/**.py` est lu au démarrage du processus, et il n'y a pas eu de redémarrage
depuis. Tant qu'il n'a pas eu lieu, **aucune ligne de ce tableau ne décrit ce qui tourne**.

Les routes dont l'état a changé aujourd'hui et **n'est pas en vigueur** :

| route | garde dans l'arbre | garde en service |
|---|---|---|
| les 8 de `services/` | `+ can_manage_services` | aucune permission |
| les 18 de `fail2ban/` et `iptables/` | `+ can_manage_fail2ban` / `can_manage_iptables` | aucune permission |
| `POST /deploy` | `+ role(2) + machine_access` | `@require_api_key` **seule** |
| `POST /regenerate_platform_key` | `+ approbation à quatre yeux` | aucune approbation |
| `POST /revoke_service_account` | idem | aucune approbation |

**Vingt-six routes de gardes ont changé aujourd'hui.** Toute documentation d'API écrite avant ce
matin est donc périmée — c'est ce qui a motivé ce relevé.

---

## 1. La méthode, et pourquoi le premier chiffre était faux

**Par arbre syntaxique, jamais par motif textuel.** Quatre sondes de cette session se sont trompées
en comptant un commentaire comme du code ; un relevé de gardes ne pouvait pas se permettre la
cinquième.

Mais l'analyse syntaxique seule n'a pas suffi. Le nombre de gardes classées « sans objet » a bougé
**trois fois** :

| itération | ce que la sonde suivait | « sans objet » |
|---|---|---|
| 1 | le corps de la route seul | **24** |
| 2 | + les helpers du **même fichier** (`_resolve_ssh_creds`) | 17 |
| 3 | + les helpers d'**autres modules** (`validate_machine_id`) | **3** |
| lecture | les trois lus un par un | **1 réelle** |

> **Un balayage ne converge qu'en lisant.** Les vingt-quatre premières auraient été publiées comme
> « vingt-quatre gardes qui ne gardent rien » — faux, et faux **dans le sens qui alarme**.

---

## 2. Les TROIS états de `@require_machine_access`

Deux états ne suffisent pas. Le troisième dépend de la **requête** et non de la route : une même
route est gardée ou nue selon ce que l'appelant envoie.

| état | ce que ça veut dire | routes |
|---|---|---|
| **mord** | atteignable au rôle 1, et un identifiant de machine est exigé | **54** |
| **redondant** | la route porte `@require_role(≥2)` ; `check_machine_access` rend `true` sans condition dès le rôle 2 | **59** |
| **sans objet** | l'identifiant est **optionnel** : le décorateur ne trouve rien à refuser | **3** |
| — | la route ne porte pas le décorateur | 113 |

### Le recoupement avec le chiffre publié, et il tombe juste

`AUDIT-GARDES-BACKEND.md` annonce **114 routes, 57 inertes / 57 qui mordent**. Mesure indépendante :

```
116 routes portent le decorateur   = 114 + les 2 ajoutees aujourd'hui
                                     (/deploy, /server_users_inventory)
 59 redondantes                    = 57 + les 2 (toutes deux role >= 2)
 57 « qui mordent » se scindent en   54 + 3
```

**Le chiffre du chantier est confirmé, et affiné** : les 57 ne mordent pas toutes — **trois** d'entre
elles ne mordent que si l'appelant fournit un identifiant.

---

## 3. Les trois « sans objet », lues une par une

| route | verdict |
|---|---|
| `GET /docker/results` | **DÉDOUANÉE** — `machine_id` est optionnel, mais le corps borne au périmètre du compte (`user_machine_access`, `get_current_user`). L'absence du décorateur ne crée pas de trou |
| `POST /update_zabbix` | **DÉDOUANÉE** — c'est une redirection **307** vers `/supervision/zabbix/deploy`, qui porte `role(2)` + permission + `machine_access`. Le 307 préserve la méthode et le corps : les gardes s'appliquent à l'arrivée |
| `GET /ssh-audit/policies` | ⚠ **LA SEULE RÉELLE**, et **plus étroite que ce que ce document a d'abord écrit** — voir la correction ci-dessous |

### ⚠ CORRECTION — la première rédaction de ce document accusait TROP LARGE

Elle disait : *« un appelant de rôle 1 qui omet le paramètre lit les politiques d'audit SSH au-delà
de son périmètre »*. **C'est FAUX**, et la lecture du corps le montre :

```sql
if machine_id:  … WHERE machine_id = %s OR machine_id IS NULL
else:           … WHERE machine_id IS NULL        -- les politiques GLOBALES seulement
```

Sans `machine_id`, la requête ne rend **que** les politiques globales du portail. **Aucune lecture
transverse du parc.** Un lecteur de la première version aurait cherché une fuite de machines qui
n'existe pas.

**L'écart réel, plus étroit et toujours réel** : les politiques **globales** — `directive`, `policy`,
`reason`, `updated_by` — sont lisibles par **tout porteur de la clé d'API**, quel que soit son rôle,
**sans détenir `can_audit_ssh`**. La page legacy l'exige (`ssh-audit/index.php:13`), et **son seul
appelant passe toujours `machine_id`** (`js/main.js:321`) : le chemin sans paramètre n'est exercé par
**aucune interface**.

**Ce qui en fait un écart — et une SECONDE correction, parce que la première explication se trompait
de mécanisme.** Il était écrit que le décorateur « ne trouve aucun identifiant dans les paramètres
d'URL ». **Faux** : il les lit explicitement.

```python
single = (data.get('machine_id') or request.args.get('machine_id')
          or data.get('server_id') or request.args.get('server_id'))
```

Avec `?machine_id=5`, il trouve l'identifiant et vérifie l'accès. Ce qui le neutralise n'est pas la
**provenance** du paramètre mais son caractère **facultatif** : absent, la liste reste vide, et une
liste vide ne refuse rien. *« Le décorateur ne lit pas la query-string » aurait envoyé corriger le
décorateur — qui n'a rien à corriger — au lieu de la route.*

C'est la quatrième occurrence de « un garde sans objet ne garde rien », et la pire de la famille,
parce que le repli rend un jeu de données **parfaitement cohérent** au lieu d'une erreur. *Un repli permissif ressemble à de la robustesse : le chemin non
gardé est celui qui a l'air de bien se comporter.*

**Et la façon dont cette erreur est arrivée est celle que §1 décrit** : ma sonde était écrite pour
accuser, donc elle s'est trompée **du côté qui alarme** — sur sa trouvaille comme sur son décompte.
Le 24 a été rattrapé parce que son ordre de grandeur était invraisemblable ; celle-ci ne l'était pas,
et rien ne m'a prévenu. *Une intuition sur l'ordre de grandeur est le dernier filet, pas le premier.*

C'est néanmoins la même famille qu'**E-208** : le legacy est incohérent avec lui-même, donc il n'y a
aucune règle du produit à documenter, seulement des décisions dont certaines ont divergé. **Une page
de documentation lisserait cette incohérence sans le vouloir.**

---

## 4. Ce que `api_docs` ne doit pas recopier

**Trois autres routes n'ont même pas `@require_api_key`.** À vérifier avant d'écrire qu'elles sont
protégées.

**Trente-neuf routes n'ont ni rôle ni permission** — c'est le chiffre à énoncer, pas « les routes
sont réservées aux administrateurs ».

**Et une erreur de classement déjà mesurée ailleurs, qui montre le risque de ce document** :
`MODULE-PLATFORM-KEY.md` classe `scan_server_users` en « lecture distante, ne modifie rien ». C'est
**faux** — elle fait `UPDATE` (`ssh.py:1636`, `:1644`), `INSERT` avec **auto-classement**
(`:1650-1675`) dont un statut `pending_review` documenté sans retour, et elle **supprime** les
comptes fantômes. **Une route qui écrit et qui décide, classée comme une lecture dans un document que
tout le monde lit.**

> C'est le motif que ce chantier compte quatre fois : *une documentation qui annonce une garde plus
> stricte — ou un effet plus anodin — que le code*. Il est pire qu'un silence, parce qu'il
> **décourage la question**.

---

## 5. L'effet des routes, mesuré

| | |
|---|---|
| routes qui **écrivent** en base | **69** |
| routes qui **joignent une machine** | **98** |

Ces deux chiffres sont obtenus par recherche de motifs dans le code déparsé (`INSERT`/`UPDATE`/
`DELETE`, `ssh_session`/`execute_as_root`/`subprocess`). **Ils sont indicatifs et non vérifiés une par
une** — contrairement aux états de garde ci-dessus. Ne pas les publier comme des constats.

---

## 6. Remesure

```bash
# le releve complet, en JSON, par arbre syntaxique
python3 <<'EOF'
# voir la sonde : ast.parse par fichier de routes, decorateurs lus sur
# fn.decorator_list, resolveurs d'identifiant suivis sur UN niveau d'appel
# (meme fichier) plus `validate_machine_id`.
EOF

# le recoupement qui valide la mesure
grep -c "114" docs/migration/AUDIT-GARDES-BACKEND.md
```

**Le relevé JSON complet, 229 lignes, est disponible sur demande** — il n'est pas commité ici pour ne
pas figer un état qui change à chaque correctif de garde.
