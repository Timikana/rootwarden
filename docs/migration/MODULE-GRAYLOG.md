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
qui ne partirait que si le transfert était vivant. `shlex.quote` est appliqué au nom de la machine
(patch A04-03), ce qui est correct.

### La cible

**`test-server` (machine 2)** pour tout geste mutant. **`srv-zabbix` (id 1) : jamais jointe** — règle
permanente. Même forme que les sous-lots V de `supervision/`, qui ont déjà installé et désinstallé des
agents sur cette machine.

---

## 4. Ce qui reste à faire, et dans quel ordre

Les neuf temps du §5 du plan. Les deux premiers sont faits par ce document ; le troisième demande le
**banc d'essai**, qui ne peut pas être partagé — le garde anti-rejeu TOTP est par compte et en base.

| temps | état |
|---|---|
| 1. inventaire | **fait** (ce document) |
| 2. lire le module avant de planifier | **fait** — c'est ce document, il n'existait pas de `MODULE-GRAYLOG.md` |
| 3. caractérisation **verte sur le legacy** | à faire — demande le banc |
| 4. base rouge sur le portage | à faire |
| 5. portage | à faire |
| 6. même suite verte sur le portage | à faire |
| 7. PARITÉ + CHANGELOG | à faire |
| 8. captures 1920/1400/390, regardées **et** envoyées | à faire |
| 9. LOT complet + commit atomique | à faire |

**Un point à trancher au moment du portage** : la configuration globale (`POST /graylog/config`) est un
réglage de flotte. L'écrire depuis une suite change le comportement de tous les déploiements suivants.
La fixture devra donc **sauvegarder la ligne existante et la restaurer dans un `finally`**, état relu
pour être prouvé — comme `go-captures-enrolement.mjs` le fait pour le secret TOTP.
