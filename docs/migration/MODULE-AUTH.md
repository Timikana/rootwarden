# Module `auth/` — inventaire, et la CONDITION DE SORTIE de la 2.0

Établi le 2026-08-20, en lecture seule, selon `METHODE-SOUS-LOT.md` §1.

**Ce module n'est pas un module métier : c'est ce qui empêche d'éteindre le legacy.** Le socle
d'authentification est porté (connexion, TOTP obligatoire, anti-rejeu par compte, CGU). Mais quatre
capacités de `legacy/auth/` ne le sont pas, et **aucun chemin d'authentification ne passe sans second
facteur** : tant que l'enrôlement 2FA n'existe que dans le legacy, un compte neuf — ou tout compte
dont un administrateur a remis `totp_secret` à `NULL` — arrive sur une impasse.

---

## 1. Ce qui est atteignable, et ce qui ne l'est pas

`legacy/auth/.htaccess:5-7` refuse en HTTP quatre des quinze fichiers : `functions.php`,
`password_policy.php`, `migrate_crypto.php`, `migrate_totp.php`. `step_up.php` n'y est pas mais ne
contient que des définitions.

**Deux fichiers sont du CODE MORT côté interface**, à archiver plutôt qu'à porter :

- **`confirm_2fa.php`** (128 l.) — aucun formulaire, aucun lien, aucun JS n'y mène.
  `enable_2fa.php:75-117` fait la confirmation lui-même. Atteignable seulement en forgeant un POST.
  Ses clés `confirm_2fa.success_title` / `success_msg` ont zéro appelant, en FR et en EN.
- **`reset_totp.php`** (37 l.) — aucun appelant. Le chemin vivant est
  `legacy/adm/includes/manage_roles.php:101-121`, qui porte **en plus** une garde hiérarchique que
  `reset_totp.php` n'a pas (un rôle 2 ne peut pas réinitialiser un rôle 3). Le fichier mort est donc
  **plus permissif que le chemin vivant**.

Trois fonctions sans appelant dans `functions.php` : `getVerifiedUser()` (`:223`),
`checkPermissionFromDB()` (`:276` — la version *zéro trust* de `checkPermission()`, qui lit la
session), et `recordFailedLoginAttempt()` (`login.php:82`), dont le commentaire affirme « alias
utilisé ailleurs dans le code » — c'est faux.

**Hors périmètre** : `migrate_totp.php` et `migrate_crypto.php` sont des outils d'exploitation en CLI
strict. `migrate_crypto.php` n'est **pas idempotent** et son en-tête dit pourquoi : une seconde
exécution détruirait les données irréversiblement.

---

## 2. La capacité 1 — l'enrôlement, et sa vulnérabilité

`legacy/auth/enable_2fa.php`. **La garde ne vérifie que `isset($_SESSION['temp_user'])`** (`:33`),
c'est-à-dire l'état posé par `login.php:216` **après le mot de passe et avant le second facteur**.
`login.php:223` renvoie certes vers `verify_2fa.php` quand un secret existe — mais c'est une
*redirection*, pas une garde, et `verify.php:118` autorise explicitement `enable_2fa.php` pendant que
la 2FA est en attente.

Conséquence, **vérifiée en conditions réelles le 2026-08-20** : avec le mot de passe seul, sans jamais
fournir de code, un `GET /auth/enable_2fa.php` répond **200** et rend 17 547 octets contenant un QR
code et, `:152`, **le secret TOTP du compte en clair**. Comparaison faite à l'intérieur du conteneur :
c'est bien le secret réel du compte. **Le second facteur est dérivable du premier.**

Le fichier est **identique à l'octet** entre `origin/main` et la branche (empreinte `9f7d1a32`), et
`main` tourne en production.

**RE-VERIFIE INDEPENDAMMENT le 2026-08-23**, sans relire ce document au prealable — et la
seconde mesure est tombee sur les **memes 17 547 octets**. Empreinte comparee autrement :
`sha256(legacy/auth/enable_2fa.php)` et `sha256(origin/main:www/auth/enable_2fa.php)` sont
egales (`be0bfda6…`). La reproduction a demande un detail : l'attribut `value` du jeton CSRF
est sur la **ligne suivante** du HTML, donc un `grep` par ligne ne le trouve pas — il faut
supprimer les retours a la ligne avant de chercher. Un premier essai avait conclu a un 403
et aurait pu passer pour une disculpation.

**Cette entree est restee trois jours sans etre remontee a l'exploitant**, parce que le
document n'a pas ete relu avant de replanifier le module. C'est le cout mesure de la dette
documentaire, inscrit ici pour qu'il serve.

Trois autres défauts du même fichier :

- **aucune limitation de débit** sur la vérification (`:75-117`), là où `verify_2fa.php:60-86` et
  `confirm_2fa.php:60-85` en ont deux (session 5/60 s + IP 10/10 min). Avec la tolérance
  `verify($code, null, 1)` = 3 fenêtres, c'est une force brute non bornée sur 10⁶ combinaisons ;
- **anti-rejeu inerte** — motif E-01 : `:87` pose `last_totp_hash`, `:102` le `unset()` dans la même
  requête ;
- **écriture en base sur un GET, sans jeton CSRF** (`:51-52`).

**Le chemin de ré-enrôlement est cassé, et c'est un trou du legacy, pas du portage.**
`legacy/includes/onboarding.php:68` propose `/auth/enable_2fa.php` comme action de l'étape « 2FA »,
mais un compte connecté n'a plus de `temp_user` → renvoyé vers `login.php`. Et `:64`
`$has2fa = !empty($u['totp_secret'])` est **toujours vrai** pour un compte connecté. Cette étape
d'onboarding est donc simultanément toujours cochée et son lien toujours mort. **Il n'existe aucun
écran de ré-enrôlement pour un compte authentifié.**

Dépendances : `spomky-labs/otphp ^11` (déjà dans `laravel/composer.json`), `bacon/bacon-qr-code ^3.0`,
et **l'extension PHP `imagick`** (`enable_2fa.php:69`, `ImagickImageBackEnd`) que le portage n'a pas.
`legacy/composer.json` déclare aussi `endroid/qr-code ^6` — **zéro utilisation**, dépendance morte.

---

## 3. La capacité 2 — le step-up

> **PORTÉE le 2026-08-24, `v1.37.50`.** `App\Services\StepUp`, `POST /profil/step-up` et
> `POST /profil/step-up/revoquer` ; la passerelle exige une marque fraîche puis transmet. Les quatre
> défauts ci-dessous sont **fermés**, et deux ajouts n'existent pas côté legacy : la **révocation**, et
> la liste d'actions **fermée**. **Non porté, et dit** : le panneau de décision en page, parce
> qu'aucune page du portage n'appelle encore une route gardée — il viendra avec son premier
> consommateur (`ssh/` K4 ou `adm/`). Mesures et détail : `PARITE.md` **E-96**.

`stepUpVerify($action, $maxAge = 900)`, `legacy/auth/step_up.php:34-39`. Clé de session
`_step_up_<action>`, `[^a-z0-9_]` → `_`. Compagnes : `stepUpMark()` (`:44`), `stepUpRequire()`
(`:53`, 403 + `{step_up_required:true}` + `exit`).

**Quatre appelants, aucun autre dans tout `legacy/`**, et l'ordre des gardes est **identique dans les
quatre** — rôle → méthode → CSRF → step-up. C'est le contrat à reproduire :

| Appelant | Action |
|---|---|
| `adm/api/delete_user.php:59` | `delete_user` |
| `adm/api/update_permissions.php:60` | `update_permissions` |
| `adm/api/anonymize_user.php:40` | `anonymize_user` |
| `api_proxy.php:63` | `policy_action` — **une seule action pour TROIS routes** |

L'endpoint `step_up_verify.php` **n'écrit rien en base** — le seul de la famille dans ce cas. Débit
5/60 s en session, anti-rejeu `_step_up_last_totp`, `verify($code, null, 1)`.

Quatre défauts :
1. **anti-rejeu par SESSION, pas par compte** — une session neuve ne voit pas la clé ;
2. **anti-rejeu global, pas par action** — une seule clé pour toutes les actions ;
3. **débit non remis à zéro sur succès** : cinq step-up légitimes en une minute → 429 ;
4. `api_proxy.php:63` fusionne trois routes root sous `policy_action` : un step-up validé pour
   `/policy/rollback` autorise `/policy/sudo/deploy` pendant 15 minutes.

Côté portage, **avant** A5 : `RoutesBackend::MOTIFS_STEP_UP` reprenait les deux motifs et
`PasserelleController:78` **refusait** au lieu de transmettre ; `config/rootwarden.php:46`
`step_up_ttl => 900` existait et **n'était lu par personne**. Les trois points sont levés.

Le modal client (`legacy/js/utils.js:59-146`) est **intégralement en français en dur, et tutoie**.

---

## 4. La capacité 3 — la politique de mot de passe

Un seul endroit : `legacy/auth/password_policy.php`. 15 caractères (`:36`), quatre classes
(`:37-40`), historique de 5 + le hash courant (`:50-78`), HIBP opt-in en k-anonymity avec **fail-open
assumé** (`:112-115`), `BCRYPT_COST` (`:27`). `passwordPolicyValidateAll()` (`:134`) rend une **clé
i18n**, pas un message — et ces clés sont dans `legacy/lang/{fr,en}/profile.php:52-58`.

Trois appelants, tous atteignables : `profile.php:174`, `reset_password.php:98`,
`adm/api/change_password.php:73`.

**Deux défauts sérieux, tous deux dans `manage_roles.php` :**
- `:86` hache le mot de passe généré **sans `BCRYPT_COST`** et surtout **sans appeler
  `passwordPolicyValidateAll` ni `passwordPolicyRecordOld`** — contournement complet de la politique
  par le chemin administrateur ;
- `:93-95` **affiche le mot de passe généré en clair dans le HTML** de la page.

`force_password_change` : posé par `manage_users.php:107` et `manage_roles.php:88`, lu par
`verify.php:134,142` (**prioritaire** sur l'expiration), levé par `profile.php:220`,
`reset_password.php:125`, `change_password.php:85`.

**À MESURER AVANT DE PORTER** : `profile.php:205` n'écrit pas `password_updated_at`, alors que
`verify.php:158` calcule l'expiration dessus. Or `mysql/init.sql:40` déclare la colonne
`ON UPDATE CURRENT_TIMESTAMP`. Si c'est effectif, **toute écriture sur la ligne `users` repousse la
date d'expiration** — `login.php:155` remet `failed_attempts = 0` à chaque connexion réussie. La
politique d'expiration serait alors neutralisée par l'usage normal. **Mesure sur base réelle
requise**, pas une déduction.

---

## 5. La capacité 4 — la réinitialisation

Elle existe et elle est **atteignable** : `login.php:389` porte le lien « mot de passe oublié ».
Chaîne : `forgot_password.php` → courriel → `reset_password.php?uid=&token=` → `login.php`.

Solide sur l'essentiel : débit 3/h par IP, jeton `bin2hex(random_bytes(32))` stocké en
`password_hash`, TTL 3600 s, **re-validation du jeton après la politique** (double soumission),
`used_at`, invalidation des frères, et **purge `active_sessions` + `remember_tokens`** après commit.
Message identique dans tous les cas + égalisation du temps de réponse, avec le correctif
d'énumération explicité `:118-120`.

Réserves : le jeton **circule dans la query string** (historique, `Referer`, journaux Apache) ;
`users.email` est `DEFAULT NULL` et **un compte sans courriel n'a aucun chemin**, ce que le message
anti-énumération lui cache. **Compter les comptes sans courriel avant de dimensionner ce sous-lot.**

**Et c'est le seul des quatre manques qui n'est PAS signalé à l'écran** :
`laravel/resources/views/auth/connexion.blade.php` ne contient **aucun** lien « mot de passe
oublié », là où `login.php:388-393` en a un.

---

## 6. Le chiffrement des secrets TOTP — le point le plus délicat du module

`legacy/includes/totp_crypto.php`. Quatre formats reconnus à la lecture, dans cet ordre :
`totp:sodium:` (HKDF puis clé brute), `totp:gcm:`, `totp:aes:` (**CBC non authentifié, lecture
seule**), et sans préfixe → clair historique. Étiquette HKDF `rootwarden-totp`.
**Fail-closed à l'écriture** (patch A02-04) mais **fail-open silencieux à la lecture** (`:92-95` rend
`''` si `SECRET_KEY` manque — ce que l'appelant lit comme « pas de secret »).

`laravel/app/Support/TotpCrypto.php` porte le **déchiffrement** des quatre formats, fidèlement.
**Il n'expose PAS de méthode de chiffrement** — c'est ce que le sous-lot d'enrôlement devra ajouter,
et c'est là que tout se joue : **un secret chiffré autrement redevient illisible par le legacy**,
donc verrouille le compte sur l'un des deux portails pendant la migration. Le premier test à écrire
est le contrôle croisé dans les deux sens.

---

## 7. Découpage en sous-lots

> **⚠ DEUX NUMÉROTATIONS COEXISTENT, et il faut le savoir avant de lire ce tableau.**
> Ce document appelle **A3** le step-up et **A5** l'enrôlement. Les commits, le `CHANGELOG` et
> `PLAN-DE-MIGRATION.md` appellent **A5** le step-up (`v1.37.50`, `97a1719`). L'ordre d'exécution
> réel, lui, n'a pas changé : politique → changement de mot de passe → step-up → **enrôlement** →
> réinitialisation. C'est le tableau ci-dessous qui fait foi pour le CONTENU et le RISQUE ; les
> étiquettes, elles, ne veulent rien dire hors de leur document.

| Lot | Contenu | Risque |
|---|---|---|
| **A0** | le lien manquant + l'archivage du code mort | nul |
| **A1** | politique de mot de passe, en validation pure — aucun écran, aucune écriture | faible |
| **A2** | changement de mot de passe pour un compte authentifié, et levée de `force_password_change` | moyen |
| **A3** | step-up | moyen-élevé |
| **A4** | réinitialisation par courriel | élevé |
| **A5** | **enrôlement du second facteur** | **le plus risqué — c'est la condition de sortie** |

**A0 d'abord** parce que c'est le seul lot qui **retire** du code, et qu'il corrige un mensonge
d'interface : trois des quatre manques sont signalés à l'écran, la réinitialisation ne l'est pas.
Ajouter l'impasse explicite dans `connexion.blade.php`, archiver `confirm_2fa.php` et
`reset_totp.php`, supprimer les cinq clés mortes et `endroid/qr-code`.

**A1 ensuite** : pas de point d'entrée, pas d'écriture, entièrement testable hors navigateur. C'est
la brique dont A2 et A4 dépendent.

**A2** : première écriture sur `users.password`. Arbitrer explicitement la divergence
`profile.php` / `change_password.php`, et **mesurer le `ON UPDATE CURRENT_TIMESTAMP` avant d'écrire
une ligne**.

**A3** : il **ouvre** trois routes qui donnent root là où la passerelle refuse aujourd'hui. Deux
arbitrages avant de coder — l'action unique `policy_action` est-elle reproduite ou éclatée ? Et
l'anti-rejeu de `Totp` étant partagé, un code consommé au second facteur ne pourra plus valider un
step-up dans la même fenêtre : plus strict que le legacy, probablement souhaitable, mais **à écrire
comme une décision**.

**A4** : le seul sous-lot qui accorde un accès à quelqu'un **qui ne prouve rien** — ni mot de passe,
ni second facteur.

> **PORTÉ le 2026-08-24, `v1.37.52`.** Les trois raisons ci-dessous restaient valables — elles ont
> dicté l'ordre, pas le résultat. L'exécution croisée des secrets a été mesurée EN PREMIER
> (`go-auth-totp-croise.mjs`, 15/0, `v1.37.51`), puis l'écran porté : même suite **18/0 des deux
> côtés**. Le QR est en **SVG** (`bacon/bacon-qr-code`), le conteneur du portage n'ayant ni `gd` ni
> `imagick`. Le **ré-enrôlement** n'est PAS porté et n'a pas d'écran dans le legacy non plus : son
> seul chemin vivant est `adm/includes/manage_roles.php:101-121`, avec sa garde hiérarchique. Détail :
> `PARITE.md` **E-97**.

**A5 en dernier**, pour trois raisons cumulées. C'est le seul qui **écrit** un secret TOTP, et un
format divergent d'un octet rend le compte inaccessible **sans message d'erreur**. Il dépend d'un
moteur de QR que le legacy résout par une extension PHP absente du portage. Et il faut **corriger** le
legacy en le portant : l'écran de référence divulgue le secret d'un compte déjà enrôlé et n'a aucune
limitation de débit. **Porter fidèlement serait porter une vulnérabilité.**

---

## 8. Ce qui reste à mesurer

1. ~~**`ON UPDATE CURRENT_TIMESTAMP` sur `users.password_updated_at`**~~ — **MESURÉ le 2026-08-23,
   sur base réelle. Le défaut est LATENT, pas actif, et l'hypothèse était trop large.**

   | mesure | résultat |
   |---|---|
   | la clause est-elle effective ? | **oui** — un `UPDATE` touchant `failed_attempts` a déplacé `password_updated_at` de `17:00:18` à `17:06:53` |
   | l'expiration se calcule-t-elle dessus ? | **oui** — `verify.php:159` : `(time() - strtotime($pwRow['password_updated_at'])) / 86400` |
   | un `UPDATE` **sans changement réel** la déplace-t-il ? | **NON** — `failed_attempts = 0, locked_until = NULL` sur une ligne déjà dans cet état laisse la date inchangée. MySQL ne déclenche `ON UPDATE` que si la valeur change |
   | un **échec suivi d'un succès** la déplace-t-il ? | **OUI** — `failed_attempts` 0→1 puis 1→0 : la date passe de `17:06:53` à `17:08:06` |
   | la politique est-elle active ? | **NON** — `PASSWORD_EXPIRY_DAYS` est **commentée** dans `srv-docker.env` et `srv-docker.env.example` ; la variable est vide dans le conteneur, donc `$globalExpiryDays = 0`, et **aucun compte n'a d'`override`** |

   **Conséquence.** Rien n'est cassé aujourd'hui : l'expiration est désactivée. Mais le jour où
   quelqu'un pose `PASSWORD_EXPIRY_DAYS=90`, la politique sera **silencieusement vaincue** pour tout
   utilisateur qui se trompe une fois avant de réussir — `login.php:155` remet alors
   `failed_attempts` à 0, la ligne change, et le compteur de jours repart de zéro. Une connexion
   « propre » ne repousse rien, contrairement à ce que l'hypothèse supposait.

   **Ce que le portage doit faire, et qui est la vraie leçon :** **écrire `password_updated_at`
   EXPLICITEMENT** lors d'un changement de mot de passe, et ne jamais s'appuyer sur `ON UPDATE`.
   `profile.php:205` ne l'écrit pas — il compte sur la clause, qui est précisément ce qui rend la
   date non fiable.
2. **Le partage de session entre les deux portails** : les clés `_step_up_<action>` ne sont
   probablement pas communes. À confirmer avant A3.
3. **La proportion de comptes sans `email`** — détermine si A4 est une capacité réelle.
4. **La lisibilité croisée des blobs TOTP** entre les deux implémentations : lecture comparée faite,
   **exécution croisée non faite**. Premier test à écrire avant A5.
