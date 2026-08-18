# Parite legacy / Laravel — ecarts assumes

Le portage vise la parite de comportement. Quand il s'en ecarte, c'est une decision, elle
est ecrite ici, et le test de caracterisation porte une attente **par cible** : ecart connu
cote legacy, exigence cote Laravel.

Un ecart non ecrit ici est une regression, pas un choix.

---

## E-01 — Le rejeu d'un code TOTP doit etre refuse

**Cible legacy : accepte (defaut). Cible Laravel : REFUSE — corrige le 2026-08-17.**
Releve et mesure le 2026-08-17 · `tests/e2e/go-socle-auth.mjs`, bloc D.

> Etat : le portage refuse desormais le rejeu. Meme test, meme code, meme fenetre de 30 s,
> session neuve : `cible=laravel : 14 PASS / 0 FAIL / 0 ecart`. Le legacy, lui, l'accepte
> toujours — le correctif cote legacy attend une decision de l'exploitant.

### Ce qui a ete mesure

Sur `rw-test-super` (role 3, `can_admin_portal`), le **meme code TOTP** a servi a ouvrir
**deux sessions authentifiees** dans la meme fenetre de 30 secondes, depuis deux contextes
de navigateur distincts. La seconde connexion aboutit sur `/terms.php` exactement comme la
premiere.

Ce n'est pas une deduction de lecture : c'est le resultat du test.

### Pourquoi le garde existant ne protege pas

`legacy/auth/verify_2fa.php` porte bien une garde anti-rejeu :

```php
} elseif (isset($_SESSION['last_totp_hash']) && $_SESSION['last_totp_hash'] === $codeHash) {
    $error = t('2fa.error_reused');          // ligne 92
} elseif ($totp->verify($code, null, 1)) {
    $_SESSION['last_totp_hash'] = $codeHash; // ligne 96
    ...
    unset(..., $_SESSION['last_totp_hash']); // ligne 126
```

Deux defauts se cumulent :

1. **La cle n'est posee que dans la branche de succes (96) et supprimee onze lignes plus
   bas (126), dans la MEME requete.** Elle n'est jamais posee sur un echec. La condition de
   la ligne 92 ne peut donc jamais etre vraie : le garde est **inerte**.
2. **Meme corrige, il resterait sans effet.** Un garde porte par la *session* ne peut rien
   contre un rejeu venu d'une session *neuve* — or c'est exactement le scenario d'attaque :
   un tiers qui detient le mot de passe et a observe un code (hameconnage, epaule, journal
   mal purge) l'utilise depuis son propre navigateur.

C'est le motif « trois pieces justes, resultat inerte » : la comparaison est correcte, le
hachage est correct, le message d'erreur existe et est traduit — et rien ne se declenche.

### Ce qu'a fait le portage

`App\Services\Totp` determine **a quelle fenetre** appartient le code presente — un simple
booleen de validite ne suffisait pas, la garde a besoin du numero de fenetre — puis retient
la derniere fenetre consommee **par compte** et refuse toute fenetre deja consommee ou
anterieure.

Le stockage retenu est le **cache applicatif** (pilote fichier), et non une colonne en base.
Motif : le schema appartient au backend Python, et une migration SQL pour cette seule garde
aurait engage un schema partage. Contrepartie assumee : la garde est propre au frontend
Laravel et ne survit pas a une purge du cache. Elle couvre le scenario reel — un rejeu se
joue en moins de 30 secondes.

Si l'exploitant prefere une garde partagee entre les deux frontends, il faudra une colonne
cote Python, par une migration SQL. Aucune migration Laravel dans les deux cas.

### Portee cote production

Le defaut est present sur `main`, donc en production. Il n'est pas corrige cote legacy a ce
jour : la decision appartient a l'exploitant. Signale le 2026-08-17.

---

## E-02 — Le filtrage des routes backend compare des SEGMENTS, pas des prefixes

**Cible legacy : compare par debut de chaine. Cible Laravel : compare par segment.**
Mesure le 2026-08-18 · `tests/e2e/go-socle-passerelle.mjs`.

### Ce que fait le legacy

`legacy/api_proxy.php` tient une liste blanche de 48 prefixes et une liste de 26 prefixes
reserves a l'administration. Les deux sont comparees ainsi :

```php
if ($path === $prefix || strpos($path, $prefix) === 0) { ... }
```

C'est un filtrage par DEBUT DE CHAINE. Consequence : `/search` etant autorise, `/searchall`
l'est aussi ; `/groups` autorise `/groupsecret` ; `/tickets` autorise `/ticketsdebug`. Et
surtout, **toute route Python future dont le nom commence par un prefixe autorise devient
publique sans que personne ne l'ait decide**.

Mesure : sur le legacy, `POST /api_proxy.php/searchall` rend **405** — c'est-a-dire que la
passerelle l'a TRANSMIS au backend, qui n'a simplement pas de route de ce nom.

### Ce que fait le portage

`App\Support\RoutesBackend` lit chaque entree selon sa FORME :

| Forme | Sens | Exemple |
|---|---|---|
| finit par `/` | espace de noms | `/fail2ban/` couvre tout ce qui commence ainsi |
| finit par `_` ou `-` | racine deliberee | `/cve_` couvre `/cve_scan` |
| sinon | route exacte | `/search` couvre `/search` et `/search/xyz`, **pas** `/searchall` |

Meme requete cote portage : **403**, refusee avant d'atteindre le backend.

### Pourquoi le resserrement ne casse rien

Verifie AVANT de le faire, sur les **201 routes reellement declarees** dans `backend/` :
les deux filtres rendent le **meme verdict**, zero difference — pour la liste blanche comme
pour la liste reservee a l'administration. Le resserrement ne retire donc aucun acces
existant ; il refuse en plus des chemins comme `/searchall`, `/command_logger`, `/updateXYZ`.

Resserrer sans mesurer aurait ete une regression silencieuse : c'est la mesure qui autorise
le changement, pas l'intuition qu'il est plus sur.

### Une difference qui n'en est pas une

La re-authentification ponctuelle (step-up) n'est pas encore portee. La passerelle **refuse**
les routes qui l'exigent (`/policy/(sudo|sftp)/(deploy|remove)`, `/policy/rollback`) au lieu
de les transmettre. Ce n'est pas un ecart de parite mais un manque assume : accorder une
action qui donne root sans le second controle que le legacy exige serait un recul.

---

## E-03 — Les chargements du journal des commandes sont sequences

**Cible legacy : aucun sequencement. Cible Laravel : le dernier chargement gagne.**
2026-08-18 · `tests/e2e/go-page-commandlog.mjs`.

`legacy/commandlog/js/main.js` relance un chargement a chaque changement de filtre, sans
ordonner les reponses. Rien n'empeche donc, en principe, deux requetes rapprochees d'arriver
dans le desordre : l'utilisateur verrait alors le resultat d'un filtre qu'il vient de quitter.

**Ce qui a ete observe, et ce qui ne l'a pas ete.** Un premier passage a bien montre le
tableau conservant deux lignes la ou le filtre demandait zero. Mais le comportement **ne se
reproduit pas de facon fiable** : les executions suivantes, sur le legacy comme sur le portage,
donnent le bon resultat. L'ordre d'arrivee des reponses depend du reseau et de la charge.

Ce qui est donc affirme ici est mesure, et rien de plus :

- l'absence de sequencement dans le legacy est un **fait lisible dans son code** ;
- un resultat perime a ete observe **une fois**, sans reproduction fiable ;
- le portage numerote ses chargements et **seul le dernier ecrit** dans le tableau, ce qui
  retire la possibilite par construction plutot que par chance.

Le test porte l'attente sur les deux cibles ; elle passe des deux cotes aujourd'hui. Elle est
la pour attraper une regression du portage, pas pour accuser le legacy d'un defaut qu'on n'a
pas su reproduire.

---

## Invariants verifies identiques sur les deux cibles

Ceux-ci ne sont pas des ecarts : ils doivent se comporter **de la meme facon** avant et
apres portage. Ils sont mesures par `go-socle-auth.mjs`.

| Reference | Invariant |
|---|---|
| A | Une page protegee sans session renvoie vers la connexion (`/index.php`, `/profile.php`, `/adm/admin_page.php`) |
| B | Un mot de passe correct **seul** n'authentifie pas — il n'existe aucun chemin sans second facteur, pour aucun des trois roles |
| B | Entre le mot de passe et le second facteur, une page protegee reste refusee |
| C | Un mauvais mot de passe n'authentifie pas |
| E | L'identifiant de session **change** apres authentification complete (anti-fixation) |
| F | Apres le second facteur, on passe par les conditions d'utilisation |

Etat au 2026-08-17, cible legacy : **13 PASS / 0 FAIL / 1 ecart connu**.
