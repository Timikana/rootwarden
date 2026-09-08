# Relevé du traitement de données personnelles

Mesuré le 2026-09-08 sur le **schéma et le code**, jamais sur des lignes. Base
factuelle destinée à la rédaction d'une politique de confidentialité côté
portage — **ce document n'est pas cette politique** et n'en tient pas lieu.

> **Une notice énonce des faits sur un traitement. Ces faits doivent exister
> avant d'être écrits.** *Le lien mort du pied de page a été retiré parce qu'un
> lien légal menant ailleurs atteste une conformité absente ; une notice au
> contenu inventé est le même défaut un cran plus bas — elle n'oriente pas vers
> du faux, elle en énonce.*

⚠ **Chaque manque est écrit « aucune purge », jamais « non déterminé ».** *Une
case vide se lit comme une mesure non faite ; un constat de non-conformité est
utile.*

---

## 1. Table par table

| table | colonnes nominatives | écrivains | purge |
|---|---|---|---|
| `users` | nom, courriel, identifiant | 13 (PHP) | 1 (suppression de compte) |
| `login_history` | `ip_address`, `user_agent`, `user_id` | 2 (PHP) | **aucune purge** |
| `login_attempts` | `ip_address`, `username` | 3 (PHP) | **aucune purge** — voir ⚠ |
| `active_sessions` | `ip_address`, `user_agent`, `user_id` | 3 (PHP) | **7 jours** (`scheduler.py:466`) |
| `command_log` | `user_id` (+ la commande exécutée) | 1 (Python) | **aucune purge** |
| `fail2ban_history` | `ip_address` — **d'un TIERS** | 1 (Python) | **aucune purge** |
| `chatops_users` | `chat_user_id`, `user_id` | 1 (Python) | 1 (désinscription) |
| `api_keys` | `name`, `last_used_ip`, `last_used_at` | 3 (PHP) | **aucune purge** |
| `user_logs` | `user_id` + libellé d'action | 4 | **aucune purge** |
| `password_history` | `user_id` + empreintes | 3 (PHP) | **aucune purge** |

**⚠ `login_attempts` n'a PAS de purge de rétention.** L'unique suppression
(`Comptes.php:397`) efface les échecs **d'un identifiant, à sa connexion
réussie** : c'est une remise à zéro de verrou, un geste FONCTIONNEL. **Les
tentatives réussies ne sont supprimées par rien.** *Compter cette ligne comme
une purge ferait passer une table sans rétention pour une table réglée.*

**Sept tables sur dix n'ont aucune règle de conservation.** Les seuls délais
déclarés du dépôt portent sur des caches (CVE, NVD, KEV, GeoIP), sur les tâches,
les approbations et les notifications — **jamais sur une table nominative**,
`active_sessions` exceptée.

---

## 2. Sorties vers un tiers

**14 destinations externes mesurées dans `backend/`. UNE SEULE transporte une
donnée personnelle.**

| destinataire | schéma | donnée transmise | personne concernée |
|---|---|---|---|
| `ip-api.com` | ⚠ **HTTP en clair** | **une adresse IP** | ⚠ **un TIERS non consentant** |
| `nvd.nist.gov`, `opencve.io`, `api.first.org`, `cisa.gov` | HTTPS | identifiants de CVE, noms de paquets, versions | aucune |
| `packages.wazuh.com`, `packages.centreon.com`, `repos.influxdata.com`, `repo.zabbix.com` | HTTPS | téléchargement de paquets et de clés | aucune |

**Le transfert vers `ip-api.com`** (`fail2ban_manager.py:413`) porte les adresses
de `fail2ban_history` : **des personnes qui ne sont pas utilisatrices du produit
et n'ont consenti à rien.** Il est gouverné depuis E-460 par `GEOIP_ENABLED`
(`config.py:158`), **dont le défaut est `'true'`** — donc actif tant que
l'exploitant ne l'éteint pas.

*Les adresses privées ne partent jamais : le contrôle qui rend `Local`/`LO`
précède l'appel et ne produit aucun trafic.*

⚠ **Un seul interrupteur gouverne les deux portes** — l'appel serveur et le
chemin navigateur (`litDistant('/fail2ban/geoip')`, qui respecte
`reglages.geoip_enabled === false`). *L'occurrence de `http://ip-api.com` dans
`fail2ban.js` est un **commentaire** de docblock, pas un second chemin sortant :
3 occurrences dans le fichier, 0 dans le code dépouillé.*

---

## 3. Cohérence avec `App\Services\ExportRgpd` — écarts NOMMÉS, non résolus

L'export (art. 15 et 20) couvre **neuf** ensembles : `users`, `permissions`,
`user_machine_access`, `user_logs`, `login_history`, `active_sessions`,
`notification_preferences`, `password_history`, `api_keys`.

**Trois tables portent des données de l'utilisateur et n'y figurent pas :**

| table absente de l'export | ce qu'elle porte sur la personne |
|---|---|
| `login_attempts` | son identifiant et l'adresse IP de chaque tentative |
| `command_log` | les commandes exécutées, attribuées à son compte |
| `chatops_users` | le lien entre son compte et une identité de messagerie |

> **Si la notice décrit un traitement que l'export ne restitue pas, les deux se
> contredisent devant la même personne — et c'est la notice qui perd.**

**`fail2ban_history` est un cas distinct** : elle ne peut pas figurer dans un
export destiné à l'utilisateur, puisque la personne concernée **n'est pas lui**.
*Son absence n'est pas un écart de l'export ; c'est le signe qu'un traitement
existe sans destinataire de droits d'accès identifié.*

⚠ **Ces écarts sont relevés, pas tranchés.** Les résoudre demande de décider si
ces tables relèvent de l'art. 15 — ce qui n'est ni une mesure ni un geste de
code.

---

## 4. Ce qui empêche d'écrire une notice VRAIE aujourd'hui

**Deux éléments obligatoires sont indéfinis dans le produit.** Ils ne se règlent
pas en écrivant la page.

**① Les durées de conservation n'existent pas** pour sept tables nominatives sur
dix. Une notice honnête devrait écrire « conservées sans limite déclarée ».

**② Le transfert vers `ip-api.com` n'a ni base légale déclarée ni destinataire
documenté**, et sa personne concernée est un tiers non consentant.

⚠ **Et le passage en HTTPS ne le résout pas** : il réduit l'INTERCEPTION, pas la
COMMUNICATION. *Transmettre l'adresse d'un tiers à un service extérieur est un
traitement ; il lui faut un fondement avant un interrupteur, et un interrupteur
avant un chiffrement.*

---

## Commandes de remesure

    # colonnes nominatives (NOMS seuls, aucune valeur)
    SELECT CONCAT(table_name,".",column_name) FROM information_schema.columns
     WHERE table_schema=DATABASE()
       AND column_name REGEXP "(^|_)(name|email|username|user|ip|ip_address|phone)(_|$)";

    # purges reelles
    grep -rn "DELETE FROM <table>" backend/ --include=*.py | grep -v tests
    grep -rn "table('<table>')->.*delete" laravel/app/

    # surface sortante
    grep -rnoE "https?://[a-z0-9.-]+\.[a-z]{2,}[a-z0-9/{}._-]*" backend/*.py backend/routes/*.py \
      | grep -viE "localhost|127\.0\.0|example\.|schema|w3\.org|python:|rootwarden"

    # portee de l'export
    grep -noE "table\('[a-z_]+'\)" laravel/app/Services/ExportRgpd.php
