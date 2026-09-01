# AUDIT — les compteurs du tableau de bord : `noKey` n'est pas de la classe de `no2fa`

**Session 5 (sécurité, lecture seule).** Mesuré le **2026-09-01**.
Question posée par le DSI : *`noKey` appartient-il à la même classe que `no2fa`,
ou est-ce une donnée d'exploitation légitime à un rôle inférieur ?*

**Réponse : ce ne sont pas les mêmes domaines.** La recommandation du DSI tombe
juste, mais la raison invoquée est fausse — et cette raison-là généraliserait mal.

---

## 1. Le domaine de chacun, lu dans l'usage

### `no2fa` — une faiblesse de l'authentification DU PORTAIL

```sql
SELECT COUNT(*) FROM users WHERE active = 1 AND (totp_secret IS NULL OR totp_secret = '')
```

Ce nombre dit combien de comptes du portail **tombent avec un mot de passe seul**.
C'est une carte de la surface d'attaque de RootWarden lui-même.

### `noKey` — une absence de provisionnement SUR LA FLOTTE

```sql
SELECT COUNT(*) FROM users WHERE active = 1 AND (ssh_key IS NULL OR ssh_key = '')
```

`users.ssh_key` est la **clé publique du compte lui-même**. Mesuré :

- le compte la pose **lui-même** (`profile.php:312`, une zone de saisie) ;
- l'onboarding la lui **demande** (`includes/onboarding.php:61`, étape de
  la liste) ;
- elle est **déployée sur les machines** — `configure_servers.py:543`
  `manage_ssh_keys()` l'écrit dans `/home/<user>/.ssh/authorized_keys`.

Et le point décisif, la branche `else` de ce déploiement :

```python
else:
    execute_command_as_root(channel, f"rm -f {authorized_keys_path}")
```

**« Pas de clé » signifie : ce compte n'a aucun accès par clé à la flotte.** Pas
« il retombe sur un facteur plus faible » — il n'y a pas d'entrée du tout.

---

## 2. Le discriminant n'est pas la sensibilité, c'est la DIRECTION

Les deux nombres *ressemblent* à des compteurs de sécurité. Ce qui les sépare est
ce qu'ils permettent à celui qui les lit :

| | ce que le nombre dit à un attaquant |
|---|---|
| `no2fa` | **combien de cibles tombent avec un mot de passe seul** — une taille de liste de cibles |
| `noKey` | combien de comptes **n'ouvrent rien** sur la flotte — les moins rentables à compromettre |

> `no2fa` compte les comptes **plus faciles à prendre**. `noKey` compte les
> comptes dont la prise **rapporte moins**. Ce sont des vecteurs opposés, pas
> deux intensités du même.

C'est ce qui justifie de les traiter différemment — et pas leur ressemblance de
libellé. **Classer par « ça a l'air d'un compteur de sécurité » mettrait
`noKey` au rôle 3 et laisserait passer le prochain compteur qui n'en a pas
l'air.**

### Conséquence sur la recommandation du DSI

`nbUsers`, `noKey` → **rôle 2**, non parce qu'ils sont sensibles, mais parce que
ce sont des **dénombrements de la population de comptes**, et qu'un rôle 1 n'a pas
à connaître la taille du portail.

`no2fa` → **rôle 3**, parce que c'est une **mesure de surface d'attaque**.

*Le résultat est celui que le DSI proposait. Le chemin n'est pas le même, et c'est
le chemin qui sert la prochaine fois.*

---

## 3. ⚠ Ce que la recommandation ne couvre pas : le bloc entier n'a AUCUNE garde

Le DSI a nommé trois compteurs. Deux seulement sont dans le bloc d'alertes, et ce
bloc en porte **neuf**, rendus sous cette condition et rien d'autre :

```php
<?php if (!empty($alerts)): ?>        // legacy/index.php:192 et :197
```

**Aucune mention de rôle.** Et ce n'est pas un oubli général de la page : la même
page borne quatre autres régions (`:161` à `ROLE_ADMIN`, `:228`, `:288`, `:394`,
`:461` à `role >= 2`). Le bloc d'alertes est simplement hors du dispositif.

Rendus au **rôle 1**, tous :

| alerte | ce qu'elle expose | pire que `no2fa` ? |
|---|---|---|
| `$oldKeys` | **NOMME jusqu'à 5 comptes** et l'âge de leur clé | **oui** |
| `$nbPasswordAuth` | machines encore en authentification par mot de passe, **avec lien** | oui, c'est la flotte |
| `$lowSshScore` | machines au score d'audit SSH < 50, lien `/ssh-audit/` | oui |
| `$critCves` | CVE critiques non résolues, toute la flotte | oui |
| `$no2fa` | comptes sans second facteur | *la question posée* |
| `$noKey` | comptes sans clé | non (cf. §2) |
| `$nbOffline`, `$oldUpdate` | état d'exploitation | non |

Le pire n'est pas un compteur :

```php
$names = implode(', ', array_map(fn($u) => $u['name'] . ' (' . $u['age_days'] . 'j)', $oldKeysData));
$alerts[] = ['type' => 'error', 'msg' => t('dashboard.alert_old_keys', [...]) . " : $names", ...];
```

Une **liste nominative** de comptes dont la clé SSH est périmée, rendue dans le
message **et dans l'attribut `title=`**. Strictement plus identifiant que
n'importe lequel des trois compteurs.

> **Restreindre trois compteurs pendant que cette région reste ouverte serait
> enregistré comme « tableau de bord borné ».** C'est le mode d'échec que nos
> propres notes appellent *une prudence recopiée devient un verdict* : la
> correction partielle ferait renoncer à mesurer le reste.

**Ma recommandation** : le bloc d'alertes se borne **comme région**, pas alerte par
alerte. Trois classes, pas neuf décisions — exploitation (rôle 1), population et
flotte (rôle 2), surface d'attaque (rôle 3) — et `$oldKeys` perd sa liste
nominative quel que soit le rôle retenu, une alerte n'ayant pas besoin de nommer
pour être actionnable.

---

## 4. Un négatif vérifié : `no2fa` mesure bien ce qu'il annonce

J'ai cherché mon propre angle mort — `''` chiffré rend `<> ''` faux, et
`totp_secret` est chiffré. Mesuré sur les trois écrivains :

| écrivain | ce qu'il écrit |
|---|---|
| `auth/reset_totp.php:26` | `NULL` |
| `adm/includes/manage_roles.php:115` | `NULL` |
| `auth/enable_2fa.php:170` | un chiffré `totp:` réel |

Et `auth/migrate_totp.php:44` sélectionne
`WHERE totp_secret IS NOT NULL AND totp_secret != ''` : **elle exclut les vides,
elle ne peut donc pas fabriquer un chiffré de chaîne vide.**

`no2fa` est fiable. *(Le préfixe est `totp:` et non `sodium:` — schéma distinct
d'`encryptPassword`, cohérent avec la note existante.)*

---

## 5. Addendum du 2026-09-01 — j'ai éprouvé mes propres BORNAGES

Ayant écrit que *« une sonde écrite pour BORNER se trompe du côté qui DÉDOUANE, et
personne ne remesure un dédouanement »*, j'ai appliqué la règle à mes propres
chiffres rassurants de ce document. **Trois éprouvés, deux corrigés dans leur
support, aucun dans sa conclusion.**

### 5.1 « `require_role(3)` met deux routes hors de portée » — tenait, mais je ne l'avais pas lu

J'avais écrit ce bornage **sans lire `require_role`**, alors que
`require_machine_access` s'était révélé un non-garde dès le rôle 2 dans ce même
document. Lu : `if role_id < min_role: return 403`, sans contournement. Et
`role_id` est **rechargé en base** par `get_current_user`
(`SELECT id, role_id, active FROM users WHERE id = %s`), donc non forgeable —
seul `X-User-ID` vient d'un en-tête, et sa borne est `@require_api_key`.

**Le bornage tient, et maintenant pour la bonne raison.**

### 5.2 « Aucune permission temporaire non expirée » — le vide n'était pas un négatif

Le résultat était vide. **Un vide rendu par une requête que j'ai écrite est
indiscernable d'une requête cassée**, et je l'avais publié comme un fait.

Témoin : `temporary_permissions` porte **0 ligne au total** — la table n'a jamais
servi. Donc ma requête n'a jamais eu l'occasion de rendre un positif.

Contre-épreuve, sur des lignes synthétiques et **sans rien écrire dans la
table** — le prédicat rend exactement ce qu'il doit :

| ligne synthétique | attendu | rendu |
|---|---|---|
| `can_audit_ssh`, expire dans 1 jour | retenue | **retenue** |
| `can_deploy_keys`, expire dans 1 h | retenue | **retenue** |
| `can_scan_cve`, **expirée** | exclue | **exclue** |
| `can_manage_wazuh`, hors liste | exclue | **exclue** |

**L'instrument peut rendre le positif : le vide réel est donc un négatif.** Et il
porte une nuance que je n'avais pas dite — il vient d'un **mécanisme jamais
exercé**, pas d'un contrôle d'expiration.

### 5.3 « Les TROIS écrivains de `totp_secret` » — il y en a SIX, et le portage manquait

C'est la correction qui vaut. J'avais énuméré trois écrivains et écrit « les
trois », sur la foi d'un **grep filtré** (`update|insert|SET |encryptTotp`). Ce
filtre ne pouvait pas voir la forme Laravel, où la clé et le verbe sont sur des
lignes différentes. Recensement non filtré — **62 occurrences, six écrivains** :

| écrivain | écrit |
|---|---|
| `legacy/auth/enable_2fa.php:170` | chiffré `totp:` réel |
| `legacy/auth/migrate_totp.php:78` | ré-chiffrement (exclut les vides, cf. plus haut) |
| `legacy/auth/reset_totp.php:26` | `NULL` |
| `legacy/adm/includes/manage_roles.php:115` | `NULL` |
| `laravel/app/Services/Comptes.php:299` | `null` |
| `laravel/app/Services/Comptes.php:492` | `null` |
| `…/Auth/SecondFacteurController.php:136` | chiffré réel — **absent de mon relevé** |

**La conclusion ne bouge pas**, et le portage la soutient explicitement :

```php
$secret = (string) $requete->session()->get('enrolement_secret', '');
if ($secret === '' || (int) $requete->session()->get('enrolement_compte') !== $idCompte) {
    return redirect()->route('second-facteur.enrolement');
}
```

Un secret vide **ne peut pas être chiffré ni écrit** — et l'écriture n'arrive
qu'après `$verdict === 'ok'`, donc après un code vérifié contre ce secret.

> **Ce que je corrige n'est pas le verdict, c'est sa portée.** J'avais prouvé
> « fiable » sur le legacy et l'avais annoncé pour le produit. Un bornage publié
> comme EXHAUSTIF et reposant sur un grep filtré est exactement la forme qui
> dédouane : personne ne va rouvrir un « vérifié négatif ».
