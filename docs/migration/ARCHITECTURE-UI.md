# Architecture de l'interface — decision

Phase 0bis de la migration Laravel. Decision prise le 2026-08-17 sur la branche
`Migration-Laravel`, a partir des grandeurs mesurees dans `INVENTAIRE.md` et de quatre
mesures complementaires prises pour cette decision.

**Decision : Blade nu, avec un noyau de composants et une feuille de style ecrite a la main.
Filament est ecarte.** L'exploitant avait explicitement autorise Tailwind et une etape de
construction ; ce n'est donc pas cette contrainte qui tranche. Ce sont les chiffres ci-dessous.

---

## 1. Ce qui a ete mesure pour decider

| Grandeur | Valeur | Source |
|---|---:|---|
| Part CRUD du code a porter | 35,8 % | `INVENTAIRE.md` §4 |
| Part operationnelle | 36,4 % | `INVENTAIRE.md` §4 |
| Part socle (auth, gabarit, passerelle, i18n) | 27,8 % | `INVENTAIRE.md` §4 |
| Lignes de JS dans la part operationnelle | 6 492 pour 4 624 de PHP | `INVENTAIRE.md` §4 |
| Tables du schema partage | 63 | `information_schema` |
| Tables portant `created_at` **et** `updated_at` | **5** | `information_schema` |
| Tables portant un seul des deux | 35 | `information_schema` |
| Tables sans horodatage | 23 | `information_schema` |
| Tables sans cle primaire | 0 | `information_schema` |
| Tables distinctes manipulees par la part CRUD | 21 | extraction sur `www/adm/` + modules CRUD |
| Version PHP du conteneur | 8.4.20 | `php -v` |
| Version Laravel de la tentative precedente | 13.17 | `composer.json` de la branche `laravel` |

---

## 2. Pourquoi Filament est ecarte

### 2.1 Aucune famille ne domine — il n'y a rien a amortir

Filament rend son investissement sur du CRUD declaratif. Ici le CRUD pese **35,8 %**.
L'operationnel pese 36,4 %, le socle 27,8 %. Trois tiers, a moins d'un point d'ecart entre
les deux premiers.

Un outil qui couvre bien un tiers d'une application laisse les deux autres tiers a ecrire
autrement. Le calcul ne bascule que si le CRUD est massivement majoritaire — disons 70 % et
plus. Il ne l'est pas.

### 2.2 Le tiers operationnel n'est pas un probleme de formulaires

Dans cette famille, le JavaScript depasse le PHP : **6 492 lignes de JS pour 4 624 de PHP**.
Ce ne sont pas des ecrans de saisie, ce sont des pilotes : sondage du centre de taches, flux
de journaux, tableaux rafraichis sans rechargement, editeur de regles de pare-feu, scans qui
repondent immediatement puis se terminent en arriere-plan.

Filament sait accueillir ce genre de page — sous forme de `Page` personnalisee, c'est-a-dire
une vue Blade. On paierait donc l'ensemble du cadre pour ecrire, dans ce tiers, exactement le
Blade qu'on aurait ecrit sans lui.

### 2.3 Le schema partage ne suit pas les conventions d'Eloquent

Filament est bati sur Eloquent. Or, sur les 63 tables du schema :

- **5 seulement** portent `created_at` et `updated_at`, le couple qu'Eloquent suppose par
  defaut ;
- 35 n'en portent qu'un ;
- 23 n'en portent aucun.

Autrement dit **58 tables sur 63 (92 %)** demandent une configuration explicite du modele
(`$timestamps = false` ou colonnes nommees a la main). Le point favorable : les 63 tables ont
une cle primaire, et 48 ont un `id` auto-incremente.

Contre-verification honnete : la part CRUD ne touche pas les 63 tables, elle en manipule
**21**. Ecrire 21 modeles configures a la main n'est pas demesure — c'est meme la voie
normale d'un `laravel/legacy-schema`. Mais ces 21 modeles sont un prealable **avant le premier
ecran rendu**, et ils achetent la couverture d'un tiers du code. C'est le rapport qui est
mauvais, pas la quantite de travail prise isolement.

### 2.4 L'authentification n'est pas raccordable a bas cout

Le legacy impose un second facteur : `login.php` renvoie vers `enable_2fa.php` si le compte
n'a pas de secret TOTP, vers `verify_2fa.php` sinon. Il n'y a pas de chemin sans TOTP.
S'y ajoutent `step_up.php` / `step_up_verify.php` (re-authentification ponctuelle pour les
actions sensibles), une politique de mot de passe (`password_policy.php`), une garde anti-
rejeu et un historique des mots de passe.

Un panneau Filament apporte sa propre pile d'authentification, avec ses pages de connexion et
son middleware. La raccorder a cette chaine est un chantier a part entiere — et ce chantier
appartient au socle, c'est-a-dire au tiers que Filament ne couvre pas.

### 2.5 Deux systemes de design coutent plus que le gain de l'un des deux

C'est la consequence directe du §2.1 : avec 36 / 36 / 28, un panneau Filament pour le CRUD
laisse forcement les deux autres tiers hors du panneau. On obtiendrait deux vocabulaires
visuels, deux facons de rendre un tableau, deux endroits ou corriger une couleur — pour un
gain sur un tiers.

### 2.6 Une etape de construction reintroduit un piege deja paye

Le catalogue `rw-pieges` porte deja l'entree : *« Tailwind compile localement avec purge : une
classe jamais utilisee est absente du CSS de production. »* Ce piege a produit une regression
reelle. Le legacy n'a aucune etape de construction ; en reintroduire une remet ce mode de
panne dans le circuit, et ajoute un job a la CI.

L'exploitant a accepte ce cout. Il ne fait donc pas partie des raisons du refus — mais
puisque les raisons 2.1 a 2.5 suffisent, il n'y a pas lieu de le payer.

---

## 3. Ce que Filament aurait apporte

A dire, pour que la decision reste revisable sur des faits et non sur une humeur :

- des tableaux tries, filtres, pagines, exportables, sans code de rendu ;
- des formulaires valides et des relations gerees de maniere declarative ;
- une politique d'acces par ressource, homogene ;
- un gain reel et substantiel sur `adm/` — 7 608 lignes de PHP, le plus gros dossier de
  l'application.

**Condition de reouverture** : si le perimetre evolue au point que le CRUD depasse 70 % du
code a porter, ou si le schema est normalise sur les conventions Eloquent, cette decision doit
etre reprise. Elle est datee et chiffree pour cela.

---

## 4. Ce qui est retenu a la place

### 4.1 Blade, avec un noyau de composants

Un jeu restreint de composants `x-rw.*` couvrant ce qui se repete : encart, badge, carte,
alerte, etat vide, icone, fenetre modale, en-tete de page, tableau. La tentative precedente
en avait sept, eprouves par 67 fichiers de test E2E ; ils sont consultables par
`git show laravel:laravel/resources/views/components/rw/<nom>.blade.php`.

### 4.2 Feuille de style ecrite a la main, sans etape de construction

Jetons de couleur et d'espacement dans un fichier, classes `.rw-*` dans deux autres, theme
sombre par une classe sur la racine du document. Aucun outil entre l'edition et le rendu :
ce qui est ecrit est ce qui est servi. C'est ce qui permet au critere « je clique et je
verifie » d'etre immediat.

L'exploitant a acte que la perte de Tailwind est sans importance.

### 4.3 Le socle avant les pages

Dans l'ordre : authentification (TOTP, step-up, politique de mot de passe), gabarit et
navigation, passerelle vers le backend Python, i18n. C'est le tiers qui conditionne les deux
autres — 27,8 % du code, et 100 % des pages en dependent.

### 4.4 Modeles Eloquent : au fil de l'eau, jamais en prealable

Pas de campagne de generation des 63 modeles. Un modele est ecrit quand une page portee en a
besoin, avec sa configuration explicite d'horodatage. **Rappel imperatif : aucune migration
Laravel.** Le schema appartient au backend Python et a son propre executeur de migrations.

---

## 5. Ce qui est repris de la tentative precedente, et comment

La branche `laravel` n'est pas un echec a effacer : elle a atteint 2 825 assertions vertes.
Elle est une source de reference, a consulter, jamais a recopier telle quelle — le present
depart de zero est volontaire.

Recuperables par `git show laravel:<chemin>` :

| Chemin | Contenu |
|---|---|
| `docs/migration/DESIGN-SYSTEM.md` | jetons, classes, theme sombre |
| `docs/migration/LAYOUT.md` | gabarit, barre laterale, tiroir |
| `docs/migration/AUTH.md` | chaine TOTP + step-up portee |
| `docs/migration/GATEWAY.md` | passerelle `/api/gateway`, listes blanches |
| `docs/migration/PORTAGE.md` | ~1 300 lignes de motifs accumules |
| `docs/migration/PARITE.md` | ecarts assumes entre les deux cibles |
| `laravel/resources/views/components/rw/*.blade.php` | 7 composants |
| `tests/e2e/*` | 67 fichiers de test |

Ces motifs doivent finir dans la skill `rw-laravel`, pas dans un document que la prochaine
remise a zero emporterait. C'est la lecon du 2026-08-17 : la branche a ete abandonnee, et
1 300 lignes de motifs avec elle.

---

## 6. Ce que cette decision n'a pas tranche

- **Livewire.** Non evalue ici. La question se posera pour les ecrans operationnels a
  rafraichissement partiel, ou 6 492 lignes de JS attendent un successeur. A traiter comme une
  decision distincte, mesuree, quand le premier ecran de ce type sera porte — pas maintenant.
- **La strategie de test.** `rw-e2e` fixe les conventions Puppeteer existantes ; leur
  articulation avec le critere « verification en direct, en cliquant » reste a ecrire.
- **Le sort du conteneur `rootwarden_laravel`**, actuellement « unhealthy » parce que ses
  fichiers ont ete supprimes. A reconstruire ou a arreter en vague 0.
