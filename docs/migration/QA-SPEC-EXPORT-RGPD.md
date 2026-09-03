# QA — l'export RGPD : la PARITÉ à porter, et les trois divergences à arbitrer

> **Ce document ne porte pas la capacité.** Le portage — route, contrôleur, vue, i18n —
> est du code applicatif dans `laravel/`, hors de mon mandat : je qualifie et je transmets.
> Ce qui est ici est ce que je peux produire et qui manque à celui qui portera : **le relevé
> exact de ce que le legacy exporte**, les protections délibérées à ne pas perdre, les
> divergences à trancher, et **la spécification de la suite** qui l'exercera.

---

## 1. L'absence, vérifiée indépendamment

Mesure refaite **sans `grep`** — il est une fonction ripgrep sur ce poste et il est aveugle
sur `storage/`, `vendor/`, `node_modules/`. `pathlib.rglob` + `io.open`, **10 627 fichiers
lus** sous `laravel/`, le 2026-09-03 :

| motif cherché | trouvé |
|---|---|
| `RGPD`, `portabilite`, `art_20`, `donnees-personnelles` | **0** |
| `rgpd` | **1** — `ComptesController.php`, et c'est **l'article 17** (anonymisation), pas le 20 |

**La portabilité n'est pas portée.** Ne pas la confondre avec l'anonymisation, qui l'est.

**Et ce qui EST déjà là** compte pour celui qui portera : les trois tables les moins
évidentes ont déjà leurs lecteurs dans le portage —

    password_history           app/Services/MotDePasse.php, Comptes.php
    active_sessions            app/Services/SessionsActives.php, MotDePasse.php, Comptes.php
    notification_preferences   app/Services/Notifications.php, Comptes.php

Le portage n'a donc **aucune requête à inventer** : il a des services qui connaissent déjà
ces tables. C'est le genre de fait qu'un relevé d'absence ne dit pas et qui change le coût.

---

## 2. Ce que le legacy exporte, section par section

`legacy/profile/export.php`, 121 lignes, lues en entier. Neuf sections, toutes filtrées
par `user_id` = l'utilisateur **connecté** — jamais un identifiant reçu en paramètre.

| section | contenu | à noter |
|---|---|---|
| `_metadata` | `generated_at`, `rootwarden_version`, `user_id`, `format_version: '1.0'`, `rgpd_articles` | la version vient de `version.txt` |
| `user` | 16 colonnes nommées **explicitement** | voir §3.3 |
| `permissions` | **`SELECT *`** | voir §3.3 |
| `user_machine_access` | `machine_id` + `machine_name` + `ip`, par `LEFT JOIN` | le `LEFT JOIN` conserve la ligne quand la machine a disparu |
| `user_logs` | `id`, `action`, `created_at`, **`LEFT(self_hash,16)`** — `LIMIT 10000` | voir §3.1 |
| `login_history` | `ip_address`, `user_agent`, `status`, `created_at` — `LIMIT 1000` | succès **et** échecs |
| `active_sessions` | `session_id` **tronqué à 8 caractères + `...`** | voir §4.1 |
| `notification_preferences` | `event_type`, `email`, `in_app` | |
| `password_history` | **`changed_at` seulement** | voir §4.2 |
| `api_keys_created` | `name`, `key_prefix`, `scope_json`, dates — **seulement si `role_id === 3`** | clés créées **par** l'utilisateur |

**L'appel d'audit précède la lecture** : `audit_log_raw(… '[rgpd] Export … demandé')` est
posé **avant** toute requête. C'est juste au regard de l'article 30 — l'événement
enregistrable est la **demande**, pas sa réussite — et il faut le porter dans cet ordre.

---

## 3. Les trois divergences à arbitrer — je les signale, je ne les tranche pas

### 3.1 ⚠ Deux coupes SILENCIEUSES, et l'une porte l'obligation

    user_logs      ORDER BY created_at DESC LIMIT 10000
    login_history  ORDER BY created_at DESC LIMIT 1000

**Rien dans le fichier produit ne dit qu'il a été coupé.** L'utilisateur reçoit un JSON qui
se présente comme complet.

C'est la classe de défaut la plus répétée du chantier — *une coupe silencieuse se lit comme
une réussite* — et ici elle a une conséquence qui dépasse la qualité : **une réponse de
portabilité tronquée sans le dire est une réponse incomplète**, et le demandeur n'a aucun
moyen de le savoir.

Le remède ne coûte rien et ne change aucune donnée : **un compte total à côté du compte
exporté**, ou un `tronque: true` dans `_metadata` — la forme retenue pour l'import CSV de
`/serveurs`, qui annonce sa troncature.

**Ce que je ne tranche pas** : faut-il supprimer la borne, ou l'annoncer ? Une borne
protège la mémoire du serveur sur un compte à 200 000 lignes de journal. **L'annoncer est
sans risque ; la retirer n'en est pas.**

### 3.2 ⚠ Une lecture en échec produit un fichier qui a l'air complet

```php
} catch (\Exception $e) {
    error_log(...);
    return ['_error' => 'fetch failed'];
}
```

Une section en échec devient `{"_error": "fetch failed"}` — **et le téléchargement part
quand même, en `200`, avec son en-tête `attachment`**. L'utilisateur obtient un fichier
nommé `rootwarden-export-…json`, qu'il archivera comme sa copie de données.

Même famille qu'E-90 et qu'`install_all` : *un geste qui échoue en partie et s'annonce
comme réussi.* La différence est qu'ici l'échec **est** dans le fichier, en clair — donc
lisible par qui l'ouvre, et invisible pour qui l'archive.

**Ce que je ne tranche pas** : refuser l'export entier sur une section en échec, ou le
livrer en le **disant en tête** (`_metadata.sections_en_echec`). La seconde forme préserve
la portabilité partielle, qui vaut mieux que rien.

### 3.3 `SELECT *` sur `permissions` — une divergence qui n'existe pas encore

`permissions` est exporté par `SELECT *` : le contenu **suit la table**. Une colonne ajoutée
demain y entre toute seule.

Un portage qui nomme ses colonnes — la bonne pratique partout ailleurs — **cesserait de
suivre**, et la divergence apparaîtrait le jour d'une migration, **sans que rien ne rougisse**.

**Ce que je ne tranche pas** : reproduire le `SELECT *`, ou nommer les colonnes **et**
poser un relevé gelé du schéma qui rougit quand la table gagne une colonne. La seconde est
plus sûre et coûte un test ; la première est la parité stricte.

---

## 4. Les deux protections délibérées — à ne PAS perdre au portage

### 4.1 `session_id` est tronqué à 8 caractères

```php
$s['session_id'] = substr($s['session_id'] ?? '', 0, 8) . '...';
```

**Un jeton de session en clair dans un fichier que l'utilisateur télécharge, archive et
transfère par courriel est une fuite d'identifiant.** La troncature n'est pas cosmétique :
elle est ce qui rend cette section exportable. La perdre au portage transformerait une
mesure de conformité en incident.

### 4.2 `password_history` n'exporte que les DATES

Le commentaire du legacy le dit : *« pas les hashes »*. Les empreintes ne sont pas
réversibles, mais elles n'ont **rien à faire** dans une copie de données personnelles, et
elles offriraient une cible hors ligne.

> **Ces deux-là se lisent comme des détails d'implémentation et sont des décisions de
> sécurité.** Un portage qui recopie les requêtes sans les commentaires les perd toutes
> les deux en silence — et aucune suite ne le verrait, parce que le fichier resterait
> parfaitement valide.

---

## 5. La suite qui l'exercera — ce qu'elle doit asséser

Écrite **après** le portage, dans `laravel/tests/`. Ordre délibéré : le chemin heureux
vient en dernier.

**Les gardes, mesurés au réseau**
1. un visiteur non authentifié n'obtient **rien** ;
2. un **rôle 1** obtient son export — c'est le point : la capacité est ouverte à *tout
   compte connecté* dès le rôle 1, et une suite qui n'exercerait que l'administrateur
   laisserait le seul chemin qui compte non emprunté ;
3. l'export d'un utilisateur ne contient **aucune ligne d'un autre** — la seule assertion
   qui protège contre un filtre oublié, et elle exige **deux comptes peuplés** ;
4. aucun paramètre reçu ne peut désigner un autre utilisateur : la source est **la
   session**, jamais la requête. À vérifier même si aucun paramètre n'est offert — *ne pas
   offrir d'entrée libre est plus sûr que la valider, mais se mesure quand même*.

**Les deux protections du §4 — et ce sont les assertions qui manqueront si on les oublie**
5. `session_id` exporté est **plus court** que le vrai et se termine par `...` ;
6. `password_history` ne porte **que** `changed_at` : assérer l'**ensemble des clés**, pas
   l'absence de `hash` — *une assertion d'absence nommée ne voit pas la colonne qu'on n'a
   pas nommée*.

**Les sections**
7. les neuf sections sont présentes, et **la liste est gelée** : une section qui disparaît
   doit rougir. Un export amputé reste un JSON valide ;
8. `api_keys_created` n'apparaît **que** pour le rôle 3 — les deux sens mesurés ;
9. `_metadata.user_id` est celui du demandeur.

**La forme du téléchargement**
10. `Content-Disposition: attachment`, nom de fichier portant l'identifiant et l'horodatage ;
11. `Content-Type: application/json; charset=utf-8` ;
12. `Cache-Control: no-store` — **un export de données personnelles ne doit pas se retrouver
    dans un cache partagé**.

**La trace**
13. la demande est journalisée **avant** la lecture, et elle l'est **même si une section
    échoue**.

⚠ **Ce qu'aucune de ces assertions ne dira** : si l'export **satisfait l'article 20**. La
parité avec le legacy est mesurable ; la conformité est un jugement juridique, et il
n'appartient ni à une suite ni à moi.

---

## 6. Le chemin détourné, et pourquoi il ne rougira pas tout seul

`LiensLegacy::REMPLACEMENTS` traduit `/profile.php` → `profil`. Un utilisateur qui suit le
portage arrive donc sur une page **où la capacité n'est pas**, et rien ne le lui dit.

**Perdre un bouton se voit ; le remplacer par une page qui n'en parle pas ne se voit pas.**

Et aucune suite existante ne rougira le jour où `legacy/profile/` sera archivé : le dossier
tombera avec son bloc. **La seule chose qui puisse le prévenir est un relevé qui gèle les
capacités du legacy encore non portées** — le même mécanisme que mes deux relevés de routes
et d'appelants, appliqué à l'archivage. Signalé ici parce que ce document est le seul
endroit où l'observation existe pour l'instant.
