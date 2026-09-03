# AUDIT — E-236 : deux gardes qui ne s'ordonnent pas

**Session 5 (sécurité, lecture seule).** Mesuré le **2026-09-01**. Aucune
écriture de code. Base mesurée : `rootwarden_db` (pile de développement).

Le Lead a relevé la forme sur `ssh-audit`. Le DSI a mesuré le porteur. Ce
document répond à deux questions : **est-ce une classe**, et **le porteur est-il
vraiment inutilisable**.

La réponse à la première est oui, et elle est trois fois plus large. La réponse à
la seconde est **non** — et c'est le résultat principal.

---

## 1. C'est une classe : 39 couples, trois modules

Relevé par AST sur les 230 routes de `backend/routes/` et par lecture des gardes
de page (`checkAuth([...])` + `checkPermission('…')`, commentaires retirés avant
analyse).

| module | page | routes croisées |
|---|---|---|
| `security` | `role >= 1` + `can_scan_cve` | **12** |
| `ssh-audit` | `role >= 1` + `can_audit_ssh` | **13** |
| `ssh` | `role >= 1` + `can_deploy_keys` | **12** |

**39 entrées, 34 chemins distincts.** 37 exigent `role 2`, 2 exigent `role 3`
(`/revoke_service_account`, `/regenerate_platform_key` — hors de portée d'un
rôle 2). Reste **32 chemins atteignables par un rôle 2 sans aucune permission**.

S'y ajoutent **15 routes de ces mêmes modules qui n'ont NI rôle NI permission** —
la permission de la page y est simplement perdue, sans même l'apparence de
sévérité qui donne son nom au croisement.

### Ce que le croisement est vraiment

Ce ne sont pas 39 écarts indépendants. C'est **une seule décision appliquée trois
fois** : les pages bornent par **permission**, les routes bornent par **rôle**, et
les deux vocabulaires n'ont jamais été réconciliés. Le croisement que le Lead a
vu n'est pas un défaut par route — c'en est la **signature**.

> La forme est neuve et le Lead a raison de la nommer : *une garde qui paraît plus
> stricte sur un axe et l'est moins sur l'autre échappe à toute comparaison d'un
> seul côté.* Les six occurrences précédentes comparaient un axe et concluaient ;
> celle-ci exige de comparer **le couple**, et une sonde à un axe l'aurait
> dédouanée — la route a l'air plus stricte.

---

## 2. Le porteur : un seul, et le même pour les 39

Mesure en base, comptes actifs de rôle 2 (il y en a deux) :

| id | `can_audit_ssh` | `can_scan_cve` | `can_deploy_keys` | ligne `permissions` | 2FA | `force_password_change` |
|---|---|---|---|---|---|---|
| 15 | 1 | 1 | 1 | présente | oui | 0 |
| 77 | 0 | 0 | 0 | **AUCUNE** | **non** | **1** |

Aucune permission temporaire non expirée sur ces trois permissions.

`id 15` détient les trois : il ouvre les pages **et** appelle les routes, aucun
croisement occupé. `id 77` n'en détient aucune : il **ne peut ouvrir aucune des
trois pages** et **peut appeler les 32 chemins**.

**Le DSI l'a trouvé sur une route ; c'est le même compte sur les trois modules.**
Ce n'est pas un écart sur `ssh-audit`, c'est un compte porteur de toute la classe.

Dormance confirmée, et plus fortement que « n'a jamais servi » :
`login_history` porte **0 tentative** pour `id 77` — pas zéro succès, zéro
tentative. Personne n'a même essayé son mot de passe.

> ⚠ *`users` ne porte aucune colonne de dernière connexion ; la mesure vient de
> `login_history` et d'`active_sessions`. Et `login_history.status='success'` est
> écrit par `login.php` **avant** l'étape 2FA : les 1688 « succès » d'`id 15` sont
> des mots de passe acceptés, pas des sessions ouvertes. Pour `id 77` c'est 0
> dans les deux lectures.*

---

## 3. ⚠ LE RÉSULTAT PRINCIPAL — « porteur inutilisable » est faux

Le DSI écrit : *« il devient utilisable au premier enrôlement 2FA — le geste que
mon DOSSIER-02 demande par ailleurs »*, et en conclut que deux dossiers se
croisent. **La prémisse ne tient pas, et la conclusion est plus grave que ça :
le réveil ne dépend d'aucun tiers.**

### 3.1 L'enrôlement n'a besoin de personne

`legacy/auth/enable_2fa.php:33` n'exige que `$_SESSION['temp_user']`, posé par
`login.php` **après le seul mot de passe**. Et le portage a désormais son propre
enrôlement (`SecondFacteurController`, trois invariants, écriture après la
preuve).

> **Le compte enrôle son propre second facteur avec son mot de passe seul.**
> Aucun administrateur, aucun DOSSIER-02. *(Correction à ma propre note : « la
> 2FA n'existe QUE dans le legacy » est périmée — un portage l'a livrée depuis.)*

### 3.2 `force_password_change` n'est pas une barrière sur le portage

C'est le point décisif, et c'est la **septième** occurrence de « la garde est sur
la PAGE, pas sur la REQUÊTE » — cette fois sur l'exigence de mot de passe
elle-même.

**Le legacy fait juste.** `auth/verify.php:166-185` relit la base et redirige, et
il est requis par chaque page **et par `api_proxy.php`** (dont le `basename` n'est
pas dans `$expiryExemptPages`). Le contrôle est **par requête**.

**Le portage ne le fait pas.** `SecondFacteurController::ouvreLaSession()` :

```php
$requete->session()->put('utilisateur_id', (int) $compte->id);
$requete->session()->put('role_id', (int) $compte->role_id);   // <- session COMPLETE
if ((int) ($compte->force_password_change ?? 0) === 1) {
    $requete->session()->put('changement_mot_de_passe_requis', true);
    return redirect()->route('profil', ['force_change' => 1]);  // <- une redirection, UNE FOIS
}
```

La session authentifiée est **déjà ouverte** quand la redirection part. Et
`app/Http/Middleware/SessionAuthentifiee.php` ne vérifie que ceci :

```php
if (! $requete->session()->has('utilisateur_id')) { return redirect()->route('connexion'); }
```

**Aucun middleware ne lit `changement_mot_de_passe_requis`** (mesuré : les quatre
middlewares du portage sont `ExigePermission`, `ExigeRole`, `Langue`,
`SessionAuthentifiee`). L'exigence est un **bandeau**, pas un verrou.

### 3.3 La chaîne complète, sans aucun tiers

1. `id 77` se connecte **au portage** avec son mot de passe.
2. Il est envoyé à l'enrôlement, **enrôle lui-même** un second facteur.
3. `ouvreLaSession` pose `utilisateur_id` **et `role_id = 2`**, puis redirige.
4. Requête suivante vers `/api/gateway/…` : `session.authentifiee` passe, rien ne
   lit le drapeau. La route passerelle ne porte **que** ce middleware
   (`web.php:888`, groupe ouvert en `web.php:74` — ni rôle ni permission).
5. La passerelle : `autorisee()` — les 34 chemins sont dans la liste blanche ;
   `reserveeAdmin()` ne bloque que `role < 2`, **il est rôle 2**.
6. Le backend : `require_role(2)` passe, **il n'y a pas de `require_permission`**.
7. `require_machine_access` ne borne rien : `check_machine_access` rend
   `True` inconditionnellement dès `role_id >= 2`. **Toute la flotte.**

**Parmi les 32 chemins ainsi atteints, 17 écrivent ou détruisent**, dont
`/deploy`, `/deploy_service_account`, `/remove_user_keys`,
`/server_user_remove_key`, `/delete_remote_user`, `/sshd_allow_user`,
`/ssh-audit/fix`, `/ssh-audit/restore`, `/ssh-audit/save-config`.

### 3.4 Est-ce occupé aujourd'hui ? Non — et ce n'est pas « inutilisable »

**Personne ne l'exerce** : `id 77` n'a aucun secret TOTP, donc aucune session
n'existe, et il n'a **jamais** tenté de se connecter. Je n'ai pas cherché à
obtenir son mot de passe et ne l'ai pas fait.

Mais la qualification juste n'est ni « occupé » ni « inutilisable » :

> **Porteur dormant à réveil autonome.** Son armement ne demande ni
> administrateur, ni DOSSIER-02, ni changement de mot de passe — seulement que le
> détenteur légitime du compte se connecte une fois.

---

## 4. Ce que je recommande, et dans quel ordre

**La fermeture la moins chère n'est pas les 39 routes.** C'est **le middleware
manquant du portage** : un contrôle par requête sur
`changement_mot_de_passe_requis`, aligné sur ce que `verify.php` fait déjà.

1. il neutralise le porteur **sans toucher aucun des trois modules** ;
2. ce n'est pas une décision de politique, c'est une **divergence d'avec le
   legacy** — le portage a perdu un contrôle que l'original exerce ;
3. il referme du même geste tout autre usage du drapeau, présent et futur.

Une fois le porteur neutralisé, les 39 croisements redeviennent ce qu'ils sont :
**une réconciliation de vocabulaire sans porteur vivant**, qu'on peut séquencer
calmement, module par module, avec l'arbitrage de S7b pour `cve_`.

**Je n'écris pas ce middleware.** Il vit dans `laravel/` : session 3. *Qui écrit
le code ne valide pas seul son correctif.*

---

## 5. Deux résidus relevés en chemin

**`verify.php:210` dit l'inverse de ce qu'il fait.** Le `catch` du contrôle
d'expiration porte le commentaire *« Fail secure : en cas d'erreur DB, ne pas
bloquer mais logger »*. Ne pas bloquer sur erreur est **fail-open**. Une panne de
base pendant ce contrôle laisse passer un compte sous
`force_password_change`. Classe connue : *le commentaire affirme plus que le
code.*

**`no2fa` est fiable — vérifié, pas supposé.** *(⚠ Corrigé le 2026-09-01 : j'écrivais « les trois écrivains » sur la foi d'un grep filtré ; il y en a **six**, et le PORTAGE manquait à mon relevé. Le verdict tient — `SecondFacteurController` refuse un secret vide avant de chiffrer — mais sa portée était surévaluée. Voir `AUDIT-TABLEAU-DE-BORD-COMPTEURS.md` §5.3.)* J'ai cherché mon propre angle mort
(`''` chiffré rendant `<> ''` faux). Les trois écrivains de `totp_secret`
écrivent `NULL` (`reset_totp.php`, `manage_roles.php`) ou un vrai chiffré
`totp:` (`enable_2fa.php`), et `migrate_totp.php:44` sélectionne
`WHERE totp_secret IS NOT NULL AND totp_secret != ''` : **la migration ne peut pas
fabriquer un chiffré de chaîne vide.** Négatif vérifié.
