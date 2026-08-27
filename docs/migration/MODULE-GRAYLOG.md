# Module `graylog/` — inventaire avant portage

Relevé le **2026-08-26**, en **lecture seule**, avant d'écrire le moindre clic. Deux fichiers,
**388 lignes**, **une** entrée de menu. Cinquième dans l'ordre du §4.2 du plan.

Le module configure le transfert des journaux système vers un serveur Graylog : il installe `rsyslog`
sur les machines, y écrit des fichiers de configuration, et pousse des gabarits.

---

## 1. Ce que le module fait vraiment

| fichier | lignes |
|---|---|
| `legacy/graylog/index.php` | 205 |
| `legacy/graylog/js/graylog.js` | 183 |

Dix routes de backend, dans `backend/routes/graylog.py` :

| route | nature |
|---|---|
| `GET /graylog/config` · `POST /graylog/config` | la configuration globale du transfert |
| `GET /graylog/servers` | l'état par machine |
| `POST /graylog/deploy` | **MUTE une machine** — installe `rsyslog`, écrit les confs |
| `POST /graylog/test` | **MUTE une machine** — exécute `logger` à distance |
| `POST /graylog/uninstall` | **MUTE une machine** — retire les confs, redémarre `rsyslog` |
| `GET`/`POST`/`DELETE /graylog/templates…` | les gabarits de configuration |

---

## 2. La garde, et les deux chemins de refus sont MESURABLES

`legacy/graylog/index.php:17-18` : `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` puis
`checkPermission('can_manage_graylog')`. Les routes mutantes portent les quatre décorateurs
(`@require_api_key`, `@require_role(2)`, `@require_permission('can_manage_graylog')`,
`@require_machine_access`).

État des comptes, mesuré en base :

| compte | rôle | `can_manage_graylog` | ce qu'il mesure |
|---|---|---|---|
| `rw-test-super` | 3 | **0** | atteint la page quand même — le rôle 3 **contourne** `checkPermission` |
| `rw-test-admin` | 2 | 0 | le chemin **« permission »**, avec le rôle satisfait |
| `rw-test-user` | 1 | 0 | le chemin **« rôle »** |
| `superadmin` | 3 | 1 | inutilisable (mot de passe hors service) |

**Les deux chemins de la garde sont donc exerçables sans toucher aux droits d'aucun compte** — même
configuration que `chatops/` et `maintenance/`. Rien à modifier, ce qui est la seule bonne façon : un
test qui déplace des droits ne mesure plus l'application réelle.

À noter pour le portage : `@require_machine_access` est ici dans les **57 routes où il est sans effet**
(voir `AUDIT-GARDES-BACKEND.md` §7) — les routes portent déjà `@require_role(2)`, et
`check_machine_access` rend `true` sans condition dès le rôle 2. Ce n'est pas un défaut, mais il ne faut
pas compter sur lui.

---

## 3. ⚠ Ce que les gestes mutants font, et pourquoi ils sont exerçables ici

`POST /graylog/deploy` (`graylog.py:265-345`) ouvre une **session SSH réelle** et exécute **en root** :

```
export DEBIAN_FRONTEND=noninteractive &&
if ! command -v rsyslogd; then apt-get update -qq && apt-get install -y rsyslog; fi
```

puis écrit `/etc/rsyslog.d/` par `printf '%s' '<b64>' | base64 -d` — le motif imposé par le projet, et
il est respecté. Il fait ensuite `rm -f <prefixe>*.conf` avant de pousser les gabarits activés :
**suppression bornée par le préfixe RootWarden**, elle n'emporte pas les confs d'autrui.

> **Cette borne a été REMESURÉE le 2026-08-27, à la suite d'E-174** — parce qu'elle reposait sur une
> conclusion et non sur une mesure, ce qui est exactement ce qui a laissé passer E-174 dans
> `MODULE-FILTRAGE.md`. **Elle tient**, et voici pourquoi elle tient :
>
> le chemin poussé est `f"{_RW_CONF_PREFIX}{tpl['name']}.conf"` (`graylog.py:334`) — une
> **interpolation brute** d'un nom de gabarit venu de la base, donc d'un formulaire. Ce qui la borne
> est `_NAME_RE = ^[a-zA-Z0-9_-]{1,100}$`, testée juste avant (`:332`) **et** à la création (`:499`).
> Mesuré valeur par valeur dans `rootwarden_python` :
>
> | nom de gabarit soumis | verdict |
> |---|---|
> | `syslog` · `a-b_c` | accepte |
> | **`../../etc/cron.d/x`** · `a/b` | **refuse** — aucune évasion de répertoire |
> | `a;id` · `a b` · `a'` · `a.conf` | refuse |
> | `a\n` | **accepte** (voir la réserve ci-dessous) |
>
> Le `/` étant refusé, un gabarit **ne peut pas sortir** de `/etc/rsyslog.d/50-rootwarden-`, donc le
> `rm -f {préfixe}*.conf` couvre bien tout ce que le module a écrit, et rien d'autre.
>
> **La réserve, dite parce qu'elle est réelle** : `_NAME_RE` est employée avec `.match()`, et `$`
> accepte un saut de ligne final. Non exploitable ici — rien ne peut suivre ce saut de ligne — mais
> c'est l'un des **33** validateurs du dépôt dans ce cas, et `.fullmatch()` n'est employé nulle part.
> Relevé complet au **§8 de `MODULE-FILTRAGE.md`**.

`POST /graylog/uninstall` retire ces mêmes fichiers et redémarre `rsyslog`. **Le geste est donc
réversible**, et c'est ce qui rend le sous-lot exerçable.

### Aucune donnée ne sort du réseau, et c'est MESURÉ

| mesure du 2026-08-26 | résultat |
|---|---|
| `graylog_config` | une ligne : `server_host = graylog.test`, port 1514, `tcp` |
| `getent hosts graylog.test` depuis `rootwarden_python` | **ne résout pas** |
| `graylog_rsyslog` (l'état par machine) | **0 ligne** |
| `graylog_templates` | 4 gabarits |

La configuration existe — donc `deploy` **ne** rendra **pas** le `400 « Config Graylog absente »** : il
ira jusqu'à l'installation réelle. Mais l'hôte de destination ne résout pas : `rsyslog` sera configuré
pour transférer vers un néant, et **aucun journal ne quitte le réseau**. C'est ce qui distingue ce
module de `groups/` — pas de courriel, pas de destination vivante.

`POST /graylog/test` exécute `logger -t <tag> <message>` à distance : une entrée de journal **locale**,
qui ne partirait que si le transfert était vivant.

**Sur `shlex.quote`, la ligne précise, remesurée le 2026-08-27** — la version précédente disait
« appliqué au nom de la machine (patch A04-03), ce qui est correct », ce qui décrivait l'intention
plutôt que le code. Le relevé exact (`graylog.py:409-410`) :

```python
msg   = shlex.quote(f"ping depuis RootWarden {row['name']}")
tag_q = shlex.quote(tag)
```

La citation porte sur le **message entier qui contient** `row['name']`, et séparément sur le tag —
donc **les deux** valeurs qui composent la commande. C'est la citation **intérieure**, celle qui sait
que la valeur est une donnée ; c'est précisément celle qui manquait à `ban_ip` avant E-174, où
`execute_as_root` ne protégeait que le shell **extérieur**. **La conclusion est juste, et cette fois
elle porte ce qui l'établit.**

### La cible

**`test-server` (machine 2)** pour tout geste mutant. **`srv-zabbix` (id 1) : jamais jointe** — règle
permanente. Même forme que les sous-lots V de `supervision/`, qui ont déjà installé et désinstallé des
agents sur cette machine.

---

## 4. Ce qui reste à faire, et dans quel ordre

Les neuf temps du §5 du plan. Les deux premiers sont faits par ce document ; le troisième demande le
**banc d'essai**, qui ne peut pas être partagé — le garde anti-rejeu TOTP est par compte et en base.

**G1 est terminé (`v1.37.77`, commit `30a672d`).** Les neuf temps, pour chacun des deux sous-lots :

| temps | G1 — config, gabarits, onglets, gardes | G2 — les trois gestes qui mutent |
|---|---|---|
| 1. inventaire | **fait** | **fait** — §3 et §5 de ce document |
| 2. lire le module d'abord | **fait** | **fait** — le défaut du §5 vient de là |
| 3. caractérisation verte sur le legacy | **fait** — 25/0 | à faire, demande le banc |
| 4. base rouge sur le portage | **fait** — 7/12 | — |
| 5. portage | **fait** | à faire, **avec** son correctif backend |
| 6. même suite verte sur le portage | **fait** — 26/0 | à faire |
| 7. PARITÉ + CHANGELOG | **fait** — E-138, E-139, E-140 | à faire |
| 8. captures 1920/1400/390, regardées et envoyées | **fait** | à faire |
| 9. LOT complet + commit atomique | **fait** — 117 exéc. | à faire |

**Le point tranché au portage de G1** : la configuration globale (`POST /graylog/config`) est un
réglage de flotte. L'écrire depuis une suite change le comportement de tous les déploiements suivants.
La fixture **sauvegarde la ligne existante et la restaure dans un `finally`**, état relu pour être
prouvé — comme `go-captures-enrolement.mjs` le fait pour le secret TOTP. C'est fait, et le gabarit
d'épreuve est borné par son nom pour la même raison.

**Ce que G1 a mesuré et qui vaut d'être rappelé avant G2** : la suite de G1 ouvre l'onglet Machines et
**lit** le tableau, sans cliquer aucun bouton de ligne — `glTest` n'a pas de `confirm()` côté legacy et
ouvrirait une session SSH sur la machine de la ligne, `srv-zabbix` comprise. G2 est précisément le
sous-lot qui lèvera cette réserve, et il ne peut le faire qu'en nommant sa cible.

---

## 5. ⚠ Ce que G2 devra mesurer en premier : un déploiement ÉCHOUÉ se marque « transfert actif »

Relevé le **2026-08-26** en lisant `backend/routes/graylog.py:340-364`, avant d'écrire un seul clic de
G2. C'est la classe *« le marqueur n'est pas le verdict »*, et ici le marqueur est **persisté en base**.

La fin de `deploy()` fait, dans cet ordre :

```python
_, chk_err, chk_code = execute_as_root(client, "rsyslogd -N1 …")   # validation syntaxique
syntax_ok  = (chk_code == 0)
_, rst_err, rst_code = execute_as_root(client, "systemctl restart rsyslog")
restart_ok = (rst_code == 0)

_upsert_state(row['id'], rsyslog_version=version,
              forward_deployed=True,          # ← INCONDITIONNEL
              last_deploy_at=…)
return jsonify({'success': restart_ok and syntax_ok, …})
```

**`forward_deployed=True` est écrit sans regarder `syntax_ok` ni `restart_ok`.** La réponse, elle, rend
`success: false` quand l'un des deux a échoué. Donc :

| ce qui s'est passé sur la machine | ce que la réponse dit | ce que la BASE dit |
|---|---|---|
| rsyslog ne redémarre pas | `success: false` | `forward_deployed = 1` |
| la configuration est syntaxiquement invalide | `success: false` | `forward_deployed = 1` |

Et `_upsert_state` (`:109-123`) écrit bien en base, sans condition ni rollback.

**Conséquence visible** : le tableau affiche la pastille « Transfert actif » pour une machine où
`rsyslog` est arrêté ou refuse sa configuration. L'écran affirme donc l'inverse de la réalité, et il
l'affirme **après** que la page a montré l'échec — le message disparaît au rechargement, la pastille
reste.

C'est la même mécanique que la pastille de `maintenance/` (E-101), avec une différence qui l'aggrave :
là le verdict était recalculé sur une mauvaise horloge, ici il est **écrit en base** et survit à la
session.

### ⚠ ET `uninstall` EST PIRE — mesuré après coup, ce paragraphe ne parlait d'abord que de `deploy`

`uninstall()` (`graylog.py:419-426`) :

```python
with ssh_session(…) as client:
    execute_as_root(client,
        f"rm -f {_RW_FORWARD_CONF} {_RW_CONF_PREFIX}*.conf && systemctl restart rsyslog",
        root_pwd, logger=logger, timeout=30)     # ← resultat ENTIEREMENT jete
_upsert_state(row['id'], forward_deployed=False) # ← inconditionnel
return jsonify({'success': True})                # ← TOUJOURS vrai
```

Le code de retour n'est **pas même capturé** : `deploy` calcule au moins son `success` à partir de deux
vérifications, `uninstall` n'en fait aucune. Un `rm` qui échoue, un `systemctl restart` qui échoue, et
la route répond **`success: true`** en marquant la machine « non déployée ».

**Et ce sens-là est le plus grave des deux, pour un module de transfert de journaux :**

| geste échoué | ce que l'écran affirme | la réalité |
|---|---|---|
| `deploy` | « Transfert actif » | rien ne part — on croit collecter et on ne collecte pas |
| `uninstall` | « Non déployé », et `success: true` | **le transfert continue** — on croit avoir arrêté d'expédier les journaux hors de la machine, et on ne l'a pas arrêté |

Le second est une affirmation de **confidentialité** : quelqu'un qui retire le transfert pour une raison
de conformité obtient une confirmation franche d'un geste qui a pu ne rien faire. Le premier fait perdre
des journaux ; le second fait croire qu'on a cessé d'en envoyer.

G2 mesurera donc **les deux sens**, et le correctif backend porte sur les deux routes : capturer le code
de retour, et n'écrire l'état qu'en accord avec lui.

### Comment G2 mesurera cela sans casser le banc

La branche d'échec n'est pas atteignable par un déploiement normal — il faut la rendre atteignable, ce
qui est l'un des six motifs. Trois options, par ordre de sûreté :

| approche | ce qu'elle exerce | risque |
|---|---|---|
| **lire** l'ordre des instructions et documenter | rien | nul, mais ne prouve rien |
| gabarit **volontairement invalide**, puis `uninstall` | le vrai chemin d'échec | rsyslog reste cassé sur la machine 2 entre les deux gestes |
| **forger** la réponse du backend depuis la page | l'affichage seulement | ne prouve pas l'écriture en base |

**Retenue : la deuxième, sur `test-server` (machine 2) uniquement**, et à condition que la suite
appelle `uninstall` dans un `finally` — ce geste retire les fichiers RootWarden **et** redémarre
`rsyslog`, donc il remet la machine dans son état. La propriété à mesurer est alors précise :

> après un déploiement dont la réponse porte `success: false`, `graylog_rsyslog.forward_deployed`
> **ne doit pas** valoir 1.

**Elle échouera sur le legacy comme sur le portage** : le défaut est dans le backend, pas dans la page.
C'est donc un écart à porter **avec** son correctif backend — la convention 2 l'autorise — et non un
écart de parité entre les deux portails.

**`srv-zabbix` (id 1) : jamais.** Et le gabarit invalide doit porter le nom d'épreuve, pour que le
nettoyage reste borné : un `DELETE FROM graylog_templates` emporterait les quatre gabarits réels.

---

## 6. Le banc mesuré AVANT d'écrire G2 — et il rend le gabarit invalide inutile

Relevé le **2026-08-26**, sur `rootwarden_test_server` (machine 2), avant la première ligne de la suite.
**Le plan du §5 est révisé : aucune fixture destructrice n'est nécessaire.**

| ce que le geste tente | ce que le banc permet |
|---|---|
| `command -v rsyslogd` | **absent** |
| `command -v systemctl` | **ABSENT** — le banc est un conteneur sans systemd |
| `command -v logger` | présent |
| `apt-get install -s -y rsyslog` (simulation) | **`E: Unable to locate package rsyslog`** — pas de DNS vers `deb.debian.org` |
| port 22 depuis `rootwarden_python` | **ouvert** |

### Les deux branches d'échec sont atteignables NATURELLEMENT, et sans rien muter

**`deploy`** échoue à sa **première** commande : `apt-get install -y rsyslog` ne trouve pas le paquet,
donc la route rend `500 « Installation rsyslog echouee »` **avant d'écrire quoi que ce soit** — ni
fichier de configuration sur la machine, ni ligne dans `graylog_rsyslog`. Le paquet n'est pas installé,
le banc n'est pas modifié.

**`uninstall`** exécute `rm -f <confs> && systemctl restart rsyslog`. Le `rm -f` réussit sur des fichiers
absents, puis `systemctl` **n'existe pas** : la chaîne `&&` échoue. Avec le correctif de `v1.37.78` la
route rend **500**, ne touche pas à l'état, et la page affiche l'avertissement localisé. **Rien n'est
supprimé** puisque rien n'était là.

C'est donc l'inverse de ce que le §5 prévoyait : je cherchais comment **rendre** la branche d'échec
atteignable sans dégât, et ce banc ne permet **que** les branches d'échec. Le gabarit volontairement
invalide est abandonné — il n'aurait rien ajouté, la route n'atteignant jamais la validation syntaxique.

### Ce qui devient mesurable, et ce qui ne l'est pas

| propriété | où elle se mesure |
|---|---|
| ouvrir une confirmation n'émet **aucune** requête (3 gestes) | **au navigateur**, G2 |
| `deploy` échoué n'écrit **aucun** état | **au navigateur**, G2 — c'est le cas naturel ici |
| `uninstall` échoué rend 500 et **ne touche pas** l'état | **au navigateur**, G2 — le témoin du correctif |
| `uninstall` échoué **avertit** que le transfert peut continuer | **au navigateur**, G2 |
| `test` ouvre une vraie session SSH et exécute `logger` | **au navigateur**, G2 |
| `deploy` **réussi** marque et date le transfert | **impossible ici** — couvert par le test unitaire |
| `deploy` avec syntaxe invalide, ou redémarrage échoué | **impossible ici** — couverts par les tests unitaires |

**Et c'est pourquoi les sept tests unitaires de `v1.37.78` ne sont pas redondants avec G2** : ils
couvrent exactement les branches que ce banc ne peut pas atteindre. Le dire évite qu'une relecture
future les prenne pour un doublon et les retire.


---

## 7. L'archivage préparé — mesuré le 2026-08-27, à dérouler le jour où G2 tombe

Préparé **en lecture seule**, pendant que G2 attend. Le jour venu, l'archivage doit être une écriture
de dix minutes, pas une demi-journée : tout ce qui suit est mesuré, il ne restera qu'à écrire.

### 7.1 Étape 1 — le sondage AVANT, relevé et daté

Il **doit** précéder le `git mv` : une assertion « rend 404 » sur un chemin qui n'a jamais existé passe
en ne mesurant rien.

| chemin | avant (2026-08-27) | attendu après |
|---|---|---|
| `/graylog/` | **302** | 404 |
| `/graylog/index.php` | **302** | 404 |
| `/graylog/js/graylog.js` | **200** | 404 |
| `/graylog/config` | **404 déjà** | 404 — Apache ne sert **pas** les routes backend |
| `/api_proxy.php/graylog/config` | **302** | **302 — doit rester inchangé** |

Le `200` sur le JS est le comportement normal d'Apache pour un statique. Il est relevé parce qu'il rend
l'assertion **mesurante** : 200 → 404, au lieu de valider du vide.

La dernière ligne est celle qui compte : **les dix routes `/graylog/*` du backend restent vivantes** et
la page portée les appelle. *Tout `/partie/` n'est pas une page.*

### 7.2 ⚠ Étape 3 — les points d'entrée : `graylog/` est le MIROIR de `services/`

| # | point d'entrée | `services/` | **`graylog/`** |
|---|---|---|---|
| 1 | `menu.php` barre latérale | présent | **présent** — `:107` |
| 2 | `menu.php` tiroir mobile | présent | **présent** — `:242` |
| 3 | `head.php` raccourci clavier | présent (`g s`) | **ABSENT** — mesuré, 0 occurrence |
| 4 | `index.php` tuile du tableau de bord | **absent** | **PRÉSENT** — `:378` |

> **Aucun des deux modules n'exerce les quatre emplacements, et ils ne se recouvrent pas.**
> `services/` avait le raccourci clavier et pas la tuile ; `graylog/` a la tuile et pas le raccourci.
>
> C'est exactement pourquoi l'étape 4 a pu être oubliée sur `docker/` : **chaque archivage n'éprouve
> qu'un sous-ensemble différent des quatre emplacements**, et onze archivages ont pu valider le cycle
> sans qu'aucun ne l'exerce en entier. *Une étape de cycle éprouvée seulement sur des cas où elle n'a
> rien à trouver n'est pas éprouvée.*
>
> **Pour `graylog/`, l'étape 4 MORD.** `legacy/index.php:378` pose une tuile
> `['url' => '/graylog/', 'label' => t('dashboard.sc_graylog'), …]` qui deviendrait un 404. C'est le
> point à ne pas manquer, et c'est celui que `services/` ne permettait pas de vérifier.

### 7.3 Étape 4 — `Navigation` : **déjà conforme**

`Navigation.php:92` porte `'route' => 'graylog'`. Aucune écriture.

### 7.4 Étape 5 — `LiensLegacy` : entrée **PRÉVENTIVE**, et elle appartient à la session 3

Ligne à poser : `'/graylog/' => 'graylog'`.

**Mesuré** : le backend n'émet **jamais** `/graylog/` comme lien de page — aucun `link` ne le porte.
Même régime que `/supervision/`, `/docker/`, `/chatops/`, `/maintenance/`, `/services/`. L'entrée ne
répare aucun 404 constaté ; elle évite d'en fabriquer un.

**Le voisinage est sûr** : `normalise('/graylog/config')` rend `/graylog/config/`, et `resoudre()`
compare le chemin normalisé **en entier**. Les dix routes du backend ne peuvent pas être réécrites.

### 7.5 Étape 6 — adresse configurée hors de RootWarden : **il y en a une, et elle est d'une autre nature**

C'est le seul module archivé jusqu'ici où la réponse n'est pas « non ».

`graylog_config` porte `server_host`, un port et un protocole (§3 : `graylog.test`, 1514, `tcp`), et le
déploiement **écrit cette adresse dans `/etc/rsyslog.d/` sur chaque machine**. Mais ce n'est **pas** le
cas de `chatops/` :

| | `chatops/` | `graylog/` |
|---|---|---|
| nature | une adresse **entrante** — le chemin que **Slack appelait** | une adresse **sortante** — celle où les machines **envoient** |
| ce que l'archivage casse | le point d'entrée public disparaît, Slack tombe en silence | **rien** — l'adresse vit en base et dans `rsyslog.d`, pas dans le dossier archivé |

**L'archivage de `graylog/` ne déplace aucune adresse** : il retire une page, pas un point d'entrée.
L'étape 6 est donc **satisfaite**, mais elle méritait d'être posée — et la distinction
entrant/sortant est ce qui la tranche, pas le fait qu'il y ait « une adresse ».

### 7.6 Étape 7 — la référence : `1 + 2 + 2 = 5`

Deux fichiers réels (`index.php`, `js/graylog.js`). Chemins à sonder : `/graylog/`,
`/graylog/index.php`, `/graylog/js/graylog.js`. **À mesurer par la session 7, pas à inscrire** — la
formule est vérifiée dans `archive.mjs` (`:63`, `:67`, `:142`, `:150`), mais une référence se remesure.

### 7.7 ⚠ Étape 8 (neuve) — la passe des liens ENTRANTS

Ajoutée au cycle le 2026-08-27, après le lien de déblocage trouvé sur `remote_users`. Balayée ici sur
**quatre natures** : `href` de gabarit, chaîne injectée en JS, catalogue de traduction, et déclaration
de portée.

| trouvé | nature | effet de l'archivage |
|---|---|---|
| `menu.php:107`, `:242` · `index.php:378` | points d'entrée | **à basculer** — §7.2 |
| `api_proxy.php:135` `'/graylog/'` | liste blanche du **proxy** | devient **surface morte**, comme `/supervision/` et `/services/`. **Laisser** — on ne soigne pas ce qu'on démonte |
| `adm/api_keys.php:372` `'^/graylog/'` | portée de clé d'API | **reste valide** — désigne les routes backend, pas la page |
| `adm/health_check.php:146-148` | trois routes backend | **restent valides**. *(Page par ailleurs interdite : elle écrit sur `srv-zabbix` au chargement.)* |
| `adm/includes/import_csv.php:64` | **commentaire** citant `/graylog/test` | mention périmée — **se relève, ne se corrige pas**, comme le `/docker/` en `<code>` |

**Aucun lien de déblocage, aucun chemin injecté par `innerHTML`.** `graylog/` n'est donc **pas
contraint** dans l'ordre d'archivage, contrairement à `remote_users`.

### 7.8 Ce que la passe a trouvé EN PLUS, et qui n'est pas un lien

**Huit clés de conseil orphelines à l'archivage** : `tip.graylog_title` et `tip.graylog_step1..4`,
en **FR et EN** (`legacy/lang/{fr,en}/tips.php`), consommées par `howto_tip.php` depuis
`legacy/graylog/index.php`. Plus `dashboard.sc_graylog` et `sc_graylog_desc`, qui étiquettent la tuile
du §7.2 et **restent utiles** une fois l'URL basculée.

**Et le portage ne les a pas reprises** : `laravel/lang/fr/graylog.php` existe et ne porte **aucune**
clé de conseil (mesuré). Les quatre étapes du legacy — configurer le serveur et le jeton, éditer les
collecteurs, sélectionner et installer, lire l'onglet Sidecars — **nomment la séquence dans le bon
ordre et sont déjà traduites**.

> C'est la même chose que ce que la passe sur `remote_users` a révélé avec `tip.ssh_step2` : **le
> legacy porte, dans ses catalogues, une réponse contextuelle que le portage n'a pas reprise.** Ce sont
> un **acquis à reprendre**, pas un doublon à écarter. À signaler à la session 3 **avant** l'archivage —
> une fois le dossier déplacé, plus personne n'ira les chercher dans `lang/`.

### 7.9 Ce qui reste bloquant, et ce qui ne l'est pas

**Bloquant** : **G2**. Les trois gestes qui mutent (`deploy`, `test`, `uninstall`) ne sont pas portés,
et le §5 de ce document porte le correctif backend qu'ils exigent — `forward_deployed = True` écrit
sans regarder le verdict, et `uninstall` qui répond `success: true` en jetant le code de retour.

**Non bloquant, et mesuré** : tout le reste. Les huit étapes sont prêtes, `Navigation` est déjà
conforme, le backend n'émet pas le chemin, aucune adresse entrante, aucun lien de déblocage.
