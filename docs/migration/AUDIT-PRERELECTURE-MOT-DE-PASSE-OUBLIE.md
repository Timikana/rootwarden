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

---

## 7. Mesures du 2026-09-03 (suite) — dont une correction de ma propre question

### 7.1 ⚠ Le troisième défaut : la limite de débit ne borne PAS ce qu'elle existe pour borner

Relevé par le DSI, **vérifié ligne à ligne** — et il est plus grave que mon §3.1.

```php
if ($user) {
    …
    INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_address)  // ligne 92
    …
} else {
    password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT);   // ligne 115 — RIEN n'est insere
}
```

Et le compteur :

```sql
SELECT COUNT(*) FROM password_reset_tokens WHERE ip_address = ? AND created_at >= …
```

> **Sonder une adresse INCONNUE n'insère aucune ligne, donc n'est jamais comptée.**
> La limite de 3/IP/heure ne borne que les demandes portant sur des adresses qui
> **existent** : elle freine l'utilisateur légitime et **laisse l'énumération
> libre**.

**Mon §3.1 disait « elle échoue ouverte sur erreur de base ». C'est vrai et
insuffisant : même avec une base saine, elle ne borne pas l'attaque.** Le
compteur est au mauvais endroit — il compte des **jetons émis**, pas des
**demandes reçues**.

**C'est le seul des trois défauts qui rendrait §3.2 coûteux à exploiter.** Sans
lui, l'oracle de temps est sondable sans limite.

### 7.2 `backend/migrations/` est un répertoire VIDE — formulation corrigée

J'avais écrit *« le dépôt a deux répertoires de migrations »*. **Mesuré : `backend/migrations/`
contient 0 fichier ; `mysql/migrations/` en contient 65.** Ce n'est pas deux jeux
qui divergent — c'est **un répertoire réel et un leurre vide**. La formulation du
DSI est meilleure et je l'adopte : *un balayage du premier rend zéro et ressemble
à une absence.*

### 7.3 La question HIBP — répondue, ET ma question était mal posée

J'avais laissé ouvert : *« l'appel HIBP échoue-t-il OUVERT ? Si oui, la politique
de complexité tombe pendant une panne réseau. »*

**a) Oui, il échoue ouvert — déclaré, journalisé, borné.**

```php
// ligne 82 du docstring : « Si HIBP injoignable (reseau, timeout), on fail-open »
'timeout' => 3,
$body = @file_get_contents($url, false, $ctx);
if ($body === false) {
    error_log('HIBP check: API unreachable, fail-open');
    return null;                       // <- aucune erreur : le mot de passe passe
}
```

**Ce n'est pas la même situation que §3.1** : ici le repli est une **décision
écrite** dans le docstring, journalisée à l'exécution, et bornée à 3 secondes.
En §3.1 le repli est justifié par une raison qui n'a plus d'objet et n'est pas
présentée comme un arbitrage.

**b) ⚠ Mais ma question surestimait la portée, et je la corrige.**

```php
function passwordPolicyValidateAll(PDO $pdo, int $userId, string $newPassword): ?string {
    … passwordPolicyCheckComplexity …     // LOCAL
    … passwordPolicyCheckHistory   …     // LOCAL (base)
    $e = passwordPolicyCheckHIBP($newPassword); if ($e) return $e;   // RESEAU
}
```

**La politique de complexité ne tombe pas.** 15 caractères, 4 classes et
l'historique sont **locaux** et insensibles à une panne réseau. Une coupure fait
tomber **un contrôle sur trois** — celui du corpus de fuites. *Ma formulation
disait « la politique de complexité tombe », ce qui est faux.*

**c) Et le contrôle est ÉTEINT aujourd'hui.**

```
HIBP_ENABLED=[]        HIBP_THRESHOLD=[]        TEMOIN MAIL_ENABLED=[true]
```

Le témoin rend une valeur **par la même commande, dans le même conteneur** : donc
l'instrument a regardé, et le vide des deux premières est un fait, pas un
silence. `password_policy.php:90` sort immédiatement quand `HIBP_ENABLED !== 'true'` :
**le contrôle ne s'exécute jamais.**

**d) Et rien ne l'annonce faussement.** Vérifié : `srv-docker.env.example:529`
pose `HIBP_ENABLED=false` explicitement, `ARCHITECTURE.md:139` dit « opt-in »,
le CHANGELOG dit « off par défaut ». **La plateforme ne revendique pas une
protection qu'elle n'exerce pas.**

> **Conclusion : négatif vérifié, et ma question était trop large.** Le repli est
> réel, déclaré, borné, sans objet aujourd'hui, et honnêtement documenté. **Je le
> signale dans ce sens — celui où personne ne vient corriger une exagération.**

**Reste une question, plus petite** : le portage porte `mdp_erreur_fuite` en FR et
EN (`laravel/lang/*/profil.php`). Une clé pour un contrôle éteint est correcte
**si** le contrôle est porté ; **non vérifié** — c'est à la relecture du portage
de la politique, pas ici.

---

## 8. `login_attempts` — mesuré le 2026-09-05, et la crainte est fondée pour une raison plus forte

Le DSI demande si le flux de réinitialisation alimente `login_attempts`, avec la
conséquence qu'*« une demande de réinitialisation qui échoue pourrait fermer la
CONNEXION de toute une adresse »*.

### 8.1 Le legacy ne l'alimente PAS — zéro occurrence

```
grep 'login_attempts|recordLoginAttempt' forgot_password.php reset_password.php
   -> AUCUNE occurrence dans les deux fichiers
```

Le flux legacy a son **propre** compteur, sur `password_reset_tokens.ip_address`
(3/IP/heure) — celui dont le §7.1 montre qu'il ne borne pas ce qu'il devrait.
**Les deux compteurs sont disjoints, et c'est ce qui protège la connexion
aujourd'hui.**

### 8.2 ⚠ Mais le compteur de connexion N'A AUCUN FILTRE D'ÉTAPE — la colonne existe pourtant

```sql
-- login.php:50, LE GARDE qui bloque réellement :
SELECT COUNT(*) FROM login_attempts
WHERE ip_address = ? AND success = 0 AND attempted_at >= …
--                      ^^^^^^^^^^^  filtre l'echec, PAS l'etape
```

Et le schéma porte bien une colonne `step` :

```
id · ip_address · username · success · step (varchar(16)) · attempted_at
```

**Le portage l'utilise** (`SecondFacteurController`, `step = '2fa'`) ; **le garde
du legacy l'ignore.**

> **Conséquence pour qui portera ce flux :** *toute* écriture dans
> `login_attempts`, depuis *n'importe quel* flux, **avec ou sans `step`**,
> compte dans le verrou de connexion du legacy. La crainte du DSI n'est donc pas
> un « pourrait » conditionnel : **le compteur legacy est structurellement
> incapable de distinguer les étapes.** Écrire les échecs de réinitialisation
> dans cette table fermerait la connexion de l'adresse.
>
> **Contrainte de portage : ne pas écrire les échecs de réinitialisation dans
> `login_attempts`** — ou n'y écrire qu'avec un `step` dédié **et** ajouter le
> filtre correspondant au garde du legacy, ce qui est une modification du
> legacy et sort du portage.

### 8.3 ⚠ ET UN DÉFAUT LIVE, TROUVÉ EN MESURANT : l'écran annonce un verrou qui n'existe pas

```php
// login.php:337 — dans la VUE, pour AFFICHER « adresse bloquée »
SELECT MAX(attempted_at) AS last_attempt, COUNT(*) AS cnt
FROM login_attempts
WHERE ip_address = ? AND attempted_at >= DATE_SUB(NOW(), INTERVAL 600 SECOND)
if (($lockInfo['cnt'] ?? 0) >= 5): … « 🔒 votre adresse est bloquée N minutes »
```

**Cette requête n'a NI `success = 0` NI `step`.** Elle compte **toutes** les
tentatives, **succès compris** — là où le garde de `:50`, lui, filtre les échecs.

> **L'écran et le garde ne comptent pas la même chose.** Cinq connexions
> **réussies** depuis la même adresse en dix minutes affichent
> *« votre adresse est bloquée »* — **alors que rien n'est bloqué** : le
> formulaire fonctionne, `:50` ne compte aucun échec.

**Et l'occupation n'est pas théorique** : c'est un outil interne, derrière une
sortie NAT d'entreprise. **Cinq connexions réussies en dix minutes depuis une
même adresse publique est un mardi matin ordinaire.**

C'est la famille du défaut qu'on démonte, **inversée** : d'habitude l'écran
annonce une protection que le code n'exerce pas ; ici il annonce une
**restriction** que le code n'applique pas. *Le coût est le même — on cesse de
croire l'écran.*

**Non corrigé** : c'est `legacy/auth/login.php`, hors de mon périmètre d'écriture
et hors du portage de ce flux. **Signalé pour arbitrage.**

### 8.4 Mise à jour de ma liste de contrôle (§4) — point 5

Mon point 5 disait *« révocation des sessions et des cookies `remember` **après le
commit** »*, en décrivant le legacy. **E-393 a tranché depuis, et dans l'autre
sens** : `MotDePasse::applique` fait désormais la purge de `remember_tokens`
**DANS** la transaction — *un jeton survivant défait le geste, qui est tout son
objet.*

**Le portage de la réinitialisation doit faire pareil**, sinon le défaut revient
par une autre porte : deux chemins écrivent un mot de passe, et un seul
révoquerait vraiment.

*Et l'asymétrie avec `active_sessions` reste justifiée : le portage ne lit jamais
cette table (ses sessions vivent en fichiers), donc une ligne survivante y est
inerte — mesuré au site de `MotDePasse.php`.*

### 8.5 Le témoin remesuré — et la ventilation par étape aggrave d'un ordre de grandeur

Le DSI mesure *« 23 lignes, 23 succès, zéro échec »*. **Remesuré par moi, confirmé,
et la ventilation dit plus :**

| étape | `success` | lignes |
|---|---|---|
| `2fa` | 1 | **19** |
| `login` | 1 | 4 |
| — | 0 | **0** |

*Fenêtre : 2026-09-03 20:46 → 2026-09-05 06:03, soit ~34 h — donc la purge des
24 h (`login.php:47`) n'a pas tourné sur toute la période, et l'échantillon n'est
pas une fenêtre glissante propre.*

**Trois conséquences, dont deux que la formulation « cinq connexions réussies »
ne portait pas :**

**a) Ce ne sont pas des connexions — ce sont des vérifications de SECOND
FACTEUR.** 19 lignes sur 23. La requête d'affichage ne filtre pas `step`, donc
**cinq passages de 2FA en dix minutes suffisent**, et ils s'accumulent environ
cinq fois plus vite que les lignes de connexion. *Le message faux se déclenche
sur l'événement le plus fréquent de la table.*

**b) Une seule adresse distincte ici** — environnement de développement. **En
production derrière un NAT d'entreprise, toutes les personnes partagent une
adresse** : les lignes `2fa` de tout le monde se cumulent. Sur une équipe d'une
dizaine, cinq vérifications en dix minutes est **une heure de travail normal**,
pas un mardi matin. **Le message serait quasi permanent.**

**c) Et le VRAI garde n'a jamais tiré non plus.** Zéro ligne `success = 0`
signifie que `login.php:50` **n'a jamais eu quoi que ce soit à compter**. La
limite de connexion est donc **entièrement non éprouvée**, et *le seul
« verrouillage » que quiconque ait jamais vu sur cet écran est le faux.*

> **Le correctif arbitré (`AND success = 0` à `:337`) est juste et suffit pour le
> message.** Mais il ne change rien à (c) : après lui, l'écran cessera de mentir
> **et le garde restera sans épreuve**. *Deux propriétés distinctes, et une seule
> est corrigée — c'est à dire, pas à réparer dans le même geste.*

---

## 9. RELECTURE DU PORTAGE `e0c7d27` — 2026-09-05

**Quatre contraintes sur cinq sont tenues. La cinquième — celle que l'auteur
désigne lui-même — n'est PAS tenue par construction, et le déploiement est le cas
DÉFAVORABLE.**

### 9.1 ✅ Contraintes 2 à 5 — vérifiées au code

| # | contrainte | verdict |
|---|---|---|
| 2 | limite de débit fail-closed, sur les **demandes reçues** | **tenue** — compteur en cache incrémenté **avant** de savoir si l'adresse existe ; `catch (\Throwable) → return false`. Et `put` plutôt que `increment`, avec sa raison écrite (le pilote `file` ne garantit pas l'atomicité). *Le défaut du legacy — compter les jetons ÉMIS — est refermé.* |
| 3 | aucune écriture dans `login_attempts` | **tenue** — zéro occurrence ; la seule mention est un **commentaire** qui cite pourquoi. |
| 4 | purge de `remember_tokens` **dans** la transaction | **tenue**, et non réécrite : elle vit dans `MotDePasse::reinitialise`, `DB::transaction(…)`, delete à l'intérieur. |
| 5 | message identique **hors** du `if` | **tenue** — `return back()->with('succes', …)` est la **dernière** instruction de la méthode, hors de toute branche. *Remesuré sur le PORTAGE, pas reconduit du legacy.* |

**Et le lien entrant tient** : `connexion.blade.php:78` porte
`route('reinit.demander')` avec un `data-rw`. *La capacité est atteignable.*

### 9.2 ⛔ Contrainte 1 — LE PARI TOMBE, ET PLUS DUREMENT QUE L'AUTEUR NE LE CRAINT

L'auteur écrit : *« vérifié disponible et vérifié APPELÉ, mais je n'ai PAS mesuré
que la réponse part réellement avant l'envoi **sous php-fpm**. »*

**Mesuré : il n'y a pas de php-fpm.**

```
apache2ctl -M   ->  php_module (shared)        <- mod_php, PAS proxy_fcgi
command -v php-fpm / ls /usr/local/etc/php-fpm*  ->  RIEN
                ->  deflate_module (shared)    <- le filtre BUFFERISE
                    filter_module (shared)
php -r ini_get   ->  output_buffering = '0'   zlib.output_compression = '0'
                     implicit_flush   = '1'    <- cote PHP : favorable
```

**`terminating()` ne défère la réponse que si `Response::send()` peut DÉTACHER la
connexion — et le seul mécanisme qui le garantit est `fastcgi_finish_request()`,
qui n'existe QUE sous FPM/FastCGI. Il est absent ici.**

Sous mod_php, `send()` peut vider les tampons PHP — favorable, ils sont à zéro —
mais **la chaîne de filtres d'Apache garde la main**, et `mod_deflate` compresse,
donc bufferise. *La réponse peut ne pas avoir atteint le client quand
`terminate()` déclenche l'envoi.*

### 9.3 ⚠ ET LA MESURE CITÉE NE PEUT PAS DÉMONTRER LA PROPRIÉTÉ

    branche INCONNUE  185,7 ms
    branche CONNUE    188,1 ms      ecart 2,4 ms (1 %)

**`MAIL_MAILER` est ABSENTE de l'environnement, donc le pilote est `log` : l'« envoi » est une écriture de fichier, en fractions de milliseconde.**

> **La mesure a été prise dans la configuration où le terme coûteux N'EXISTE
> PAS.** Elle montre que `terminating()` ne coûte rien quand il n'a rien à
> différer. **Elle ne peut pas montrer qu'il diffère un envoi SMTP** — aucun
> envoi SMTP n'a eu lieu.

*C'est un témoin sur le mauvais axe : l'instrument rend bien le positif, sur autre
chose que ce qu'on mesure.* **Et l'auteur le dit à moitié** — il annonce que la
mesure est « au service, pas au réseau ». Le second biais, plus décisif, n'est pas
énoncé : elle est **au pilote `log`, pas au SMTP**.

### 9.4 Ce que ça change, et ce que ça ne change pas

**Aujourd'hui : inoffensif.** Avec `log`, les deux branches écrivent un fichier ;
l'écart de 2,4 ms est le résidu `UPDATE`+`INSERT` que l'auteur énonce, et il est
correctement borné.

**⚠ Le jour où le SMTP est posé** : le terme coûteux réapparaît **entier**, et
`terminating()` ne garantit rien sur ce déploiement. **Aucun commit n'expliquera
le changement** — c'est exactement l'écart « qui disparaît avec la configuration
et revient avec elle » du §5, réalisé.

**Ce qui trancherait** : une mesure **au réseau** — temps jusqu'au dernier octet
sur les deux branches, avec un SMTP réel ou un bouchon lent. Non lisible, non
faisable sans poser le transport.

**Ce qui rendrait la propriété vraie PAR CONSTRUCTION, indépendamment du SAPI** :
ne pas émettre depuis la requête du tout. Écrire le message en attente dans un
magasin durable (table ou fichier), et le faire délivrer par un **processus
séparé**. *C'est la seule forme qui ne dépende ni du SAPI, ni de `mod_deflate`,
ni du tampon d'Apache* — et elle ne demande pas de file Laravel, dont le pilote
`sync` la rendrait inopérante.

### 9.5 Verdict

**Le portage est bon et je ne demande pas de le retenir.** Les quatre contraintes
mesurables sont tenues, la limite de débit corrige un défaut du legacy, et le
résidu connu est énoncé au site plutôt que tu.

**Ma seule réserve porte sur la contrainte 1, et elle n'est pas bloquante
aujourd'hui** — elle le devient **le jour de la décision SMTP**. *Elle doit donc
voyager AVEC cette décision, pas rester dans une relecture.* **Le commentaire de
`ReinitialisationController` doit dire que `terminating()` ne défère pas par
construction sur mod_php sans `fastcgi_finish_request`, et que la propriété est à
remesurer au réseau quand le transport change.**
