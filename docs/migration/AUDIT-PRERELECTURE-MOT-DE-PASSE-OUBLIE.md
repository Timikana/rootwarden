# AUDIT — la réinitialisation en libre-service : spécification de sécurité avant portage

**Session 5 (sécurité, lecture seule).** Mesuré le **2026-09-03**. Aucun geste,
aucun envoi, aucune écriture hors `docs/`.

Le DSI me demande de **porter** cette capacité. **Je ne la porte pas** — §6. Ce
document est ce que je peux livrer : la parité mesurée, les propriétés de sécurité
que le portage doit **préserver**, **deux défauts** que le legacy porte, et le
fait qui **corrige la raison d'urgence invoquée**.

---

## 1. ⚠ LE CHIFFRE QUI BLOQUE LA DÉCISION DE L'EXPLOITANT — REMESURÉ, ET IL EST PIRE

Le DSI porte *« six comptes actifs sur dix portent déjà `force_password_change = 1` »*,
en signalant que le chiffre est **hérité du commentaire d'A2, non remesuré**.
Remesuré ce jour :

```sql
SELECT COUNT(*) AS actifs,
       SUM(force_password_change = 1) AS force_change,
       SUM(email IS NULL OR email = '') AS sans_email,
       SUM(force_password_change = 1 AND (email IS NULL OR email = '')) AS force_ET_sans_email
FROM users WHERE active = 1;
```

| actifs | `force_password_change=1` | sans courriel | **les DEUX** |
|---|---|---|---|
| **12** | **8** | 6 | **5** |

**Le chiffre porté était 6/10. Il est 8/12.** Mais ce n'est pas le résultat.

> **⚠ CINQ comptes actifs portent DÉJÀ l'état que la décision E-131 produirait** :
> ils doivent changer un mot de passe **et n'ont aucune adresse de courriel**.
> **Le portage de cette capacité ne les atteint pas** — le flux s'indexe sur
> `email` (`WHERE email = ? AND active = TRUE`).

**Conséquence sur l'affirmation du DSI** — *« ton portage débloque cette
décision »* : **il la débloque PARTIELLEMENT.** Pour 5 des 8 comptes forcés, la
réinitialisation en libre-service est **inatteignable par construction**. Ces
cinq exigent un geste d'administration — renseigner une adresse, ou poser un mot
de passe côté admin. **Le portage est nécessaire et non suffisant, et la décision
E-131 doit le savoir.**

---

## 2. La parité : ce que les deux pages font

### 2.1 `forgot_password.php` (206 lignes) — la demande

| propriété | mise en œuvre |
|---|---|
| CSRF | jeton en session, `hash_equals`, **régénéré à chaque soumission** |
| limite de débit | **3 demandes par IP et par heure**, comptées sur `password_reset_tokens.ip_address` |
| anti-énumération (message) | **message identique** que l'adresse existe ou non — et le commentaire dit que le défaut était de l'avoir mis DANS le `if ($user)` |
| anti-énumération (temps) | un `password_hash` est brûlé quand l'adresse n'existe pas (Patch A07) — **voir §3.2, il ne suffit pas** |
| jeton | `bin2hex(random_bytes(32))` = 64 hex, stocké en **bcrypt**, jamais en clair |
| usage unique | les jetons précédents non utilisés sont invalidés (`used_at = NOW()`) avant d'en créer un |
| durée de vie | **1 heure** (`expires_at = now + 3600`) |
| URL du lien | `URL_PUBLIC_HTTPS` > `URL_HTTPS` > `https://localhost:8443` — le commentaire documente un incident de reverse-proxy (2026-05-27) |
| en-têtes | `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` |

### 2.2 `reset_password.php` (412 lignes) — la consommation

Reçoit `?uid=<int>&token=<hex>`. `uid` par `FILTER_VALIDATE_INT`.

| propriété | mise en œuvre |
|---|---|
| validation du jeton | les **5** derniers jetons non utilisés et non expirés du compte, `password_verify` sur chacun |
| **double-soumission** | le jeton est **re-validé après** la validation du formulaire, avant d'écrire |
| politique de mot de passe | `passwordPolicyValidateAll` — 15 caractères, 4 classes, historique, HIBP |
| transaction | `beginTransaction` … `commit`, `rollBack` sur `PDOException` |
| historique | l'**ancien** hash est enregistré dans `password_history` avant l'`UPDATE` |
| hachage | `PASSWORD_BCRYPT` avec `BCRYPT_COST` explicite (A02-NEW-01) |
| drapeaux | `force_password_change = FALSE`, `password_updated_at = NOW()`, `password_expires_at` si politique active |
| usage unique | le jeton consommé est marqué `used_at`, **et tous les autres du compte aussi** |
| **révocation des accès** | `DELETE FROM active_sessions` **et** `DELETE FROM remember_tokens` — le commentaire dit le défaut d'origine : *un attaquant ayant volé une session conservait son accès malgré le reset* |
| ordre | la révocation est **après le commit**, en meilleur effort, pour ne pas annuler le reset si une table manque |

### 2.3 La table — elle existe, et elle est dans le SECOND jeu de migrations

```
mysql/init.sql
mysql/migrations/016_password_reset_tokens.sql
```

**⚠ Piège mesuré** : elle n'est **pas** dans `backend/migrations/`. Un premier
balayage de `backend/migrations/*.sql` rend **zéro** et fait croire que la table
n'existe pas. **Le dépôt a deux répertoires de migrations.** La table est bien
présente en base (vérifié par `information_schema`).

### 2.4 Le second facteur n'est PAS touché — et c'est correct

Le DSI demande de surveiller l'anti-rejeu TOTP. **Le flux n'y touche pas** : il
pose un nouveau mot de passe et affiche un message ; **il n'ouvre aucune
session**. Le compte se reconnecte ensuite par `login.php`, qui exige le second
facteur.

**C'est la bonne conception** : réinitialiser le mot de passe ne contourne pas la
2FA. **Corollaire à porter tel quel** — et un corollaire à connaître : un compte
qui a perdu **son mot de passe ET son second facteur** n'a toujours aucun chemin,
et `reset_totp.php` est un geste d'administration.

---

## 3. ⚠ DEUX DÉFAUTS DU LEGACY — à ne PAS porter à l'identique

### 3.1 La limite de débit échoue OUVERTE

```php
} catch (PDOException $e) {
    // Si la table n'existe pas encore (migration pas appliquee), autoriser
    return true;
}
```

**Toute `PDOException` désarme la limite de débit** — pas seulement une table
absente : connexion perdue, verrou expiré, droits insuffisants. La fonction rend
`true` = « autorisé ».

**C'est un repli du côté permissif sur un contrôle de sécurité**, et sa
justification écrite ne couvre qu'un cas sur plusieurs. **Le portage doit échouer
FERMÉ** : si le compteur est illisible, refuser la demande — une demande refusée
se réessaie, une limite désarmée ne se voit pas. *Et la table existe désormais
(§2.3), donc la raison invoquée n'a plus d'objet.*

### 3.2 ⚠ L'oracle de TEMPS n'est PAS refermé — le coût égalisé est le mauvais

Le commentaire annonce : *« on brûle un coût bcrypt équivalent à la génération de
token, sinon la réponse est nettement plus rapide = oracle "l'email existe" »*.

**Mesuré, les deux branches ne sont pas comparables :**

| adresse **inconnue** | adresse **connue** |
|---|---|
| 1 × `password_hash` | 1 × `UPDATE` (invalidation) |
| | 1 × `password_hash` |
| | 1 × `INSERT` |
| | **1 × `sendPasswordResetEmail` — envoi SMTP SYNCHRONE** |

`sendPasswordResetEmail` appelle `createMailer()` puis `addAddress`/`Body` — c'est
**PHPMailer en synchrone**, donc connexion SMTP, poignée de main TLS et
transmission, dans la requête.

> **Un envoi SMTP dure des ordres de grandeur de plus qu'un bcrypt.** Le correctif
> a égalisé le terme le moins coûteux et laissé le plus coûteux d'un seul côté :
> **la branche « l'adresse existe » est nettement PLUS LENTE.** L'oracle
> d'énumération subsiste, simplement inversé par rapport à l'implémentation naïve.
>
> C'est un cas de *« le commentaire affirme plus que le code »* particulièrement
> retors : la mesure qu'il décrit est réelle, elle porte sur le mauvais terme.

**Ce que le portage doit faire** : sortir l'envoi de la requête — file d'attente,
tâche différée, ou `Mail::queue`. **Alors seulement** le message identique du §2.1
referme l'énumération. **Non exercé** : le démontrer demanderait de chronométrer
des requêtes réelles avec un envoi sortant, ce qui est un interdit du chantier.

---

## 4. Ce que le portage doit préserver — liste de contrôle

1. **message identique** dans tous les cas, **hors** de la branche `if (compte)` ;
2. **jeton haché** en base, jamais en clair, 32 octets d'entropie ;
3. **usage unique**, et invalidation des autres jetons du compte ;
4. **durée de vie bornée** (1 h) et **re-validation avant l'écriture** ;
5. **révocation des sessions et des cookies `remember`** après le commit ;
6. **historique du mot de passe** écrit avant l'`UPDATE` ;
7. **aucune ouverture de session** — le compte se reconnecte, 2FA comprise ;
8. **limite de débit qui échoue FERMÉ** (§3.1) ;
9. **envoi hors de la requête** (§3.2) ;
10. `uid` validé en entier ; le lien construit sur `URL_PUBLIC_HTTPS` en priorité.

---

## 5. Ce que je n'ai pas mesuré

- **le corps du courriel** au-delà de son en-tête : je ne l'ai pas relu en entier,
  donc je n'ai pas vérifié que le lien est la **seule** donnée variable qu'il porte ;
- **`passwordPolicyValidateAll`** — l'appel HIBP sort-il vers un service tiers, et
  que se passe-t-il s'il échoue ? *Si c'est un fail-open, la politique de
  complexité tombe pendant une panne réseau* — **question ouverte, non mesurée** ;
- **rien n'a été exercé** : aucune requête, aucun envoi, aucun formulaire soumis.

---

## 6. Pourquoi je ne porte pas cette capacité

Mon mandat est de **qualifier en lecture seule et de proposer** ; l'exploitant a
ouvert **une** exception d'écriture, pour `iptables` et ce périmètre seul.

**Et ici la raison est plus forte qu'un périmètre** : c'est un **flux
d'authentification**. La consigne de l'exploitant dit *« une session ne valide pas
seule une modification de sécurité qu'elle vient d'écrire »*. Si je l'écris,
**personne dans mon rôle ne la relit** — je serais à la fois l'auteur et
l'auditeur du chemin de récupération de compte.

**Un pair ne peut pas étendre ce périmètre**, et je ne me l'étends pas.

**Cette spécification est prête** : session 3 porte, je relis après. Et si
l'exploitant décide que je porte, je le fais — mais alors la relecture doit aller
à quelqu'un d'autre.
