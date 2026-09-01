# Module `wazuh/` — inventaire avant portage

Mesures faites les **2026-08-27 et 2026-08-28**, consolidées ici le **2026-09-01 à 14:34 CEST**.
Lecture seule. **Deux fichiers**, une entrée de menu, **derrière un drapeau de fonctionnalité**.

> **Ce document répare un manquement de ma part.** Les mesures ci-dessous avaient été rendues **par
> messages** et jamais écrites dans le dépôt — et j'ai annoncé au DSI que « les six entrées ont toutes
> leur `MODULE-*.md` » alors que celui-ci n'existait pas. *Une mesure qui ne vit que dans un compte
> rendu ne vit nulle part* : au tour suivant, personne ne la retrouve.

**Volumétrie, les deux chiffres** — `find legacy/wazuh -name '*.php' | xargs wc -l` et
`find legacy/wazuh -type f | xargs wc -l` :

| PHP seul | total (PHP + JS) |
|---|---|
| **291** | **594** |

Le second dimensionne le travail : le portage réécrit son JS et n'en reprend aucune ligne.

---

## 1. ⚠ Le drapeau — lu PARTOUT, et c'est là qu'était le défaut

La question posée était « le drapeau est-il lu partout, ou seulement à l'enregistrement du
blueprint ? ». **Réponse : partout — six lecteurs** — et le défaut n'était pas une absence de lecture.

| couche | lit | si `WAZUH_ENABLED=false` |
|---|---|---|
| backend, enregistrement du blueprint | `Config.WAZUH_ENABLED` (`server.py:129`) | **OFF** — routes 404 nativement |
| backend, exposition en réglage | idem (`settings.py:101`) | OFF |
| legacy, barre latérale et tiroir | `feature_enabled('wazuh')` (`menu.php:110,243`) | OFF |
| **legacy, la PAGE elle-même** | idem (`wazuh/index.php:19`) → **404 explicite** | OFF |
| legacy, tuile du tableau de bord | idem (`index.php:379`) | OFF |
| **portage, `Navigation`** | `config/rootwarden.php` | voir ci-dessous |

**C'est le drapeau le mieux gardé du legacy** — la page elle-même le vérifie, en défense en
profondeur.

### E-223 — le portage lisait une AUTRE variable. **Corrigé, revérifié le 2026-09-01**

Le portage lisait `env('FEATURE_WAZUH', true)` — un **nom différent** — et `FEATURE_WAZUH` n'existait
**nulle part**. Éteindre le module l'aurait donc caché dans le legacy et **laissé visible dans le
portage**, où l'entrée pointe vers une page qui rend 404.

**Corrigé** : `laravel/config/rootwarden.php:122` lit désormais `env('WAZUH_ENABLED', true)`, et les
trois conteneurs voient `true` (mesuré le 2026-09-01). **Les trois couches s'accordent.**

### Ce qui SUBSISTE — le désaccord sur la valeur VIDE

Mesuré interpréteur contre interpréteur :

| valeur | PHP legacy | Python |
|---|---|---|
| `true` · `false` · `TRUE` · `1` · `yes` | identiques | identiques |
| **`''` (présente et vide)** | **ON** (défaut) | **OFF** |

`feature_enabled()` traite `''` comme « absente » et rend **ON** ; Python fait `''.lower() == 'true'`
→ **OFF**. Donc `WAZUH_ENABLED=` — une faute d'exploitation banale — rend **la page servie et toutes
ses routes 404**.

**Ce qui BORNE** : `wazuh` est le **seul** appelant de `feature_enabled()` dans tout le legacy. Le
helper est générique, son rayon est d'un module.

---

## 2. Les gardes — le module le plus uniformément gardé du chantier

**15 routes sur 15** portent `@require_api_key` + `@require_role(2)` +
`@require_permission('can_manage_wazuh')` + `@threaded_route`. Sept ajoutent
`@require_machine_access`, **inerte** (le rôle ≥ 2 court-circuite `check_machine_access`).

À comparer : `services/` avait **0/8** avec rôle ou permission, `iptables`+`fail2ban` **2/23** avec
permission, `groups/` **6/6**.

**Et la page s'accorde avec ses routes** : `wazuh/index.php:25-26` fait
`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` + `checkPermission('can_manage_wazuh')` — **rôle 2 des deux
côtés**. C'est le **premier module du chantier où la page n'est pas plus permissive que ses
requêtes**, alors que `platform_key`, `remote_users`, `iptables` et `fail2ban` admettent tous
`ROLE_USER` pour des routes qui exigent le rôle 2.

**Proxy** : `/wazuh/` est en liste blanche (`api_proxy.php:136`) et **absent** de
`$ADMIN_ONLY_PREFIXES`. Un rôle 1 passe donc le proxy — et le backend le refuse. Défense en profondeur
d'une couche plus courte, **pas un trou**.

---

## 3. Les effets sortants et destructifs

| geste | effet | réversible ? |
|---|---|---|
| `/wazuh/install` | **session SSH** : ajoute `packages.wazuh.com` en dépôt APT/YUM **sur la machine**, importe sa clé GPG dans `/usr/share/keyrings/wazuh.gpg`, `apt-get install` | partiellement — voir E-225 |
| `/wazuh/install_all` | même geste, **sur plusieurs machines** | idem |
| `/wazuh/uninstall` | `apt-get purge -y wazuh-agent \|\| true && rm -rf /var/ossec` | — |
| `/wazuh/detect`, `/restart`, `/group`, `/options`, `/rules*` | **voir le §7** — trois des cinq ne touchent aucune machine | — |

> **`install` fait émettre CHAQUE MACHINE GÉRÉE vers Internet**, et lui fait faire confiance à un
> dépôt tiers de façon permanente. C'est un effet sortant d'une nature que le chantier n'avait pas
> encore rencontrée : ce n'est pas RootWarden qui joint l'extérieur, c'est RootWarden qui **fait
> joindre** l'extérieur par le parc.

### E-224 — `install_all` était CASSÉ, et sa correction a posé la borne qui manquait

La requête faisait `LEFT JOIN wazuh_agents a … WHERE a.id IS NULL`. **`wazuh_agents` n'a pas de colonne
`id`** — sa clé primaire est `machine_id` (`mysql/migrations/034_wazuh.sql:43`). Reproduit à
l'identique : `ERROR 1054 — Unknown column 'a.id' in 'where clause'`. Aucun `try` n'entoure la requête
→ **500**.

**Ce n'était pas une protection, c'était un accident** : la requête corrigée, le geste partait — et il
triait **`CRITIQUE` en premier**, donc commençait par la production.

**Corrigé** : `machine_ids` est désormais **obligatoire**, corps vide → **400**. *« C'est la seule
route de parc du produit qui se borne »*, dit sa docstring. **Vérifié par ma lecture le 2026-08-28.**

### E-225 et E-237 — la désinstallation n'est pas le miroir de l'installation

`uninstall` **ne retire ni le dépôt ni la clé GPG** (mesuré : zéro occurrence de `sources.list` ou
`keyrings` dans la route). **Désinstaller laisse la machine configurée pour faire confiance à un dépôt
tiers.**

Et le code documente depuis un défaut **plus large**, posé par une autre session et que je cite sans le
réclamer : **sur RHEL et SUSE, `apt-get purge` n'existe pas**, le `|| true` avale l'échec, seul
`rm -rf /var/ossec` agit — la désinstallation **retire les données et laisse le paquet**. `success`
vaut désormais `paquet_retire`, mesuré par `dpkg-query`/`rpm`. **E-237** subsiste :
`_upsert_agent(status='never_connected')` est appelé **avant** que ce verdict existe.

---

## 4. Ce qui DÉDOUANE — mesuré, et dit aussi nettement

- **zéro `getElementById` sans cible.** `comm -23` entre les identifiants lus par
  `js/wazuh.js` et les `id=` de `index.php` rend **l'ensemble vide**. (`adm/` en portait douze.) ;
- **`perms.desc_wazuh` décrit le BON produit** — « Déployer l'agent Wazuh et éditer rules/decoders »
  (`admin.php:91` FR, `:249` EN). **Le défaut de `graylog` ne se répète pas** : là, la description de
  la permission décrivait Graylog Sidecar quand le module faisait du `rsyslog`. Cherché ici
  précisément parce que c'était le motif ; il est absent ;
- **six dialogues natifs, LUS commentaires retirés** (`sed -E 's://.*::'`) : `confirm()` sur
  `wzInstall` `:141`, `wzInstallAll` `:148`, `wzUninstall` `:177`, `wzRestart` `:184`,
  `wzDeleteRule` `:289`, et `prompt()` sur `wzSetGroup` `:190`. **Le compte brut donnait la même
  chose** — ce fichier n'a ni commentaire ni chaîne polluante. *Le plancher coïncidait avec le réel ;
  ça ne dispensait pas de le vérifier.*

---

## 5. L'état du banc, et ce qu'il interdit de mesurer

`SELECT COUNT(*) FROM wazuh_agents` → **0** (remesuré le 2026-09-01 à 14:14).

> **Le module n'a jamais servi.** Toute assertion sur l'état d'un agent passerait **faute d'objet** —
> et c'est ce qui a permis à `install_all` d'être cassé sans que personne le voie.

`tip.wazuh_*` : **5 clés FR, 5 EN** (lues **par PHP**, pas au `grep -c`). Le portage n'a **aucun rendu
de panneau pas-à-pas**, comme pour les 26 pages qui en portaient un.

**Points d'entrée, comptés zéro compris** : latérale **1**, tiroir **1**, raccourci clavier **0**,
tuile **1**. Même forme que `graylog/`.

---

## 6. ⚠ Le contexte qui rend toute mesure de comportement suspecte

`docker inspect rootwarden_python --format '{{.State.StartedAt}}'` → **2026-08-27T12:28:43Z**, et
**vingt modules backend hors tests** sont plus récents (vingt-neuf tout compris — *deux chiffres, deux
questions : les tests n'ont aucun effet sur le service*).

> **Le service exécute le code du 27 août.** E-224 et E-237 sont **écrits et INERTES**. Une suite qui
> appellerait `install_all` aujourd'hui obtiendrait le **500** de la requête cassée, ni le **400** du
> code corrigé, ni le geste de parc. **Trois comportements pour une même route selon ce qu'on lit**,
> et un seul est dans l'arbre.

---

## 7. ⚠ Les cinq corps, LUS — et trois des cinq ne touchent AUCUNE machine

Mesuré le **2026-09-01 à 23:32 CEST**, pour les panneaux de décision du portage : *ce qu'un panneau
peut promettre est borné par ce que la route fait réellement.*

| route | effet DISTANT | effet LOCAL | ce que le panneau peut promettre |
|---|---|---|---|
| `POST /detect` | **lecture SSH** — 4 commandes littérales (`test -x`, `wazuh-control info`, `grep` sur `client.keys`, `systemctl is-active`) | écrit `wazuh_agents` | « je relève l'état » — **honnête** |
| `POST /restart` | `systemctl restart wazuh-agent` — **littéral** | audit | « l'agent redémarre » — **succès mesuré au code de retour** |
| `POST /group` | **`systemctl restart` SEULEMENT** | écrit `group_name` en base | ⚠ **ne peut PAS promettre que le groupe est appliqué** |
| `POST /options` | **AUCUN** | `wazuh_machine_options` | ⚠ **ne touche aucune machine** |
| `POST`/`DELETE /rules` | **AUCUN** | `wazuh_rules` | ⚠ **ne touche aucune machine** |

### 7.1 `set_group` — le groupe n'est JAMAIS transmis à la machine

Les commentaires annoncent « Écrit le groupe dans `/var/ossec/etc/ossec.conf` ». **La seule commande
exécutée est `systemctl restart wazuh-agent`**, un littéral. La valeur `group` ne quitte jamais
RootWarden : elle est écrite en base par `_upsert_agent(group_name=group)` et **renvoyée telle quelle**
au client (`{'success': True, 'group': group}`).

**Ce qui a été corrigé, et c'est réel** : le code teste désormais le code de retour du redémarrage, et
sur échec il refuse en disant *« le groupe n'a pas été appliqué, l'agent reste dans son groupe
précédent »*. L'état persisté suit donc un verdict.

> **Mais le verdict porte sur le REDÉMARRAGE, pas sur le groupe.** Un redémarrage réussi ne dit rien
> de la classe où l'agent a atterri : il se ré-inscrit auprès du *manager*, qui lui assigne ce qu'il
> veut. **Rien ne relit le groupe appliqué** — mesuré : aucune commande après le restart.
>
> **Le panneau de décision ne doit donc pas dire « le groupe sera X ».** Il peut dire « l'agent va
> redémarrer et se ré-inscrire », et que RootWarden enregistrera X **comme intention**. Même famille
> que le `forward_deployed = True` de `graylog/` — un état local écrit sur un geste dont l'effet
> distant n'est pas vérifié — mais **d'un cran moins grave** : ici l'échec du redémarrage est
> intercepté, là il ne l'était pas.

### 7.2 `options` et `rules` — écrits par la page, lus par la page, appliqués nulle part

Ni l'un ni l'autre n'ouvre de session SSH. Et **leurs seuls lecteurs sont les `GET` de la même page** :

```
wazuh_machine_options   ->  lu UNIQUEMENT par GET /wazuh/options   (:992)
wazuh_rules             ->  lu UNIQUEMENT par GET /wazuh/rules     (:1080, :1098)
```

**Aucun chemin de déploiement ne les consomme.** Un exploitant règle des chemins FIM, une fréquence
`syscheck`, l'active-response, édite des règles et des décodeurs — **et rien n'atteint jamais une
machine.** C'est le motif « écrit et lu par personne » sous sa forme la plus visible : la page relit
ce qu'elle a écrit, donc **l'écran confirme**, et la boucle se referme sans que rien ne soit appliqué.

> Pour le portage : ces deux écrans sont des **brouillons**, pas des réglages. Le dire est une décision
> de présentation, et elle n'a pas de coût — ce qui n'en a pas, c'est de laisser croire l'inverse.

### 7.3 La question d'E-174 : fermée, et proprement

**Aucune valeur venue du client n'atteint une commande distante dans ces cinq routes.** Relevé
exhaustif des arguments d'`execute_as_root` entre `:690` et `:1180` : **quatre chaînes littérales**, et
le seul `f"…"` est un **message d'audit**, pas une commande.

`_GROUP_RE`, `_NAME_RE` et les validateurs d'options sont donc de la **défense en profondeur pure** —
ils ne gardent aucun chemin d'injection, parce qu'il n'y en a pas. *Le dire évite qu'on les croie
protecteurs*, et évite surtout qu'on les retire en les prenant pour du bruit.

*(`_GROUP_RE` accepte un saut de ligne final, comme les autres validateurs ancrés du dépôt — §8 de
`MODULE-FILTRAGE.md`. Sans objet ici : la valeur n'atteint aucune commande.)*

---

## 8. Ce que je n'ai PAS mesuré

- **`_validate_xml`** (`wazuh.py:164`) : je ne l'ai pas mesuré. **Une autre session l'a fait depuis** —
  `f6c3c84 docs(audit): wazuh — le cas du DSI est un faux positif, et XXE se referme`. Je le cite
  comme sien et ne le reprends pas à mon compte ;
- **la page n'a pas été ouverte**, ni au navigateur ni en HTTP ;
- **aucune machine n'a été jointe**, aucun geste déclenché.
