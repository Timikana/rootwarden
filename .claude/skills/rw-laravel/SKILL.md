---
name: rw-laravel
description: Conventions du portage RootWarden vers Laravel - schema partage sans migrations, pilotes fichier obligatoires, passerelle vers le backend Python, i18n FR/EN, composants Blade, contrats DOM des tests. A charger AVANT de toucher a laravel/.
---

# Portage RootWarden vers Laravel

Le frontend Laravel (`laravel/`, port 8444) tourne **en parallele** du legacy
(`legacy/`, port 8443) pendant toute la migration. Le legacy reste la reference
tant que la parite d'un module n'est pas prouvee.

Decisions et mesures : `docs/migration/{INVENTAIRE,ARCHITECTURE-UI,DEPRECIATION}.md`.

## Interdits absolus

- **Aucune migration Laravel.** Le schema (63 tables) appartient au backend
  Python et evolue par `mysql/migrations/*.sql`. Ni `migrate`, ni
  `migrate:fresh`, ni `db:seed`, ni `schema:dump`. Voir
  `laravel/database/migrations/README.md`.
- **Le backend Python ne se touche pas.** Laravel le joint par une passerelle,
  il ne le remplace pas.
- **Pas d'etape de construction.** CSS ecrit a la main, jetons + classes
  `.rw-*`. Filament et Tailwind ont ete evalues et ecartes sur mesure
  (`ARCHITECTURE-UI.md`).

## Pieges specifiques a ce portage

- **Les pilotes `database` sont des mines.** Laravel 13 propose par defaut
  `SESSION_DRIVER=database`, `QUEUE_CONNECTION=database`, `CACHE_STORE=database`.
  Ils exigent les tables `sessions`, `jobs`, `cache` — que ce projet ne cree
  pas. Laisses tels quels, ils cassent l'application a la PREMIERE requete,
  avec une erreur SQL et non un message clair. Rester sur `file` / `sync` /
  `file`.
- **`env()` hors de `config/` rend `null`** des le premier `config:cache`. Tout
  reglage se lit dans un fichier de `config/`, jamais ailleurs. Les
  identifiants de base sont lus en repli sur `MYSQL_*` dans
  `config/database.php` : ne pas les recopier sous `DB_*`, un mot de passe
  present a deux endroits finit par diverger.
- **Modeles Eloquent au fil de l'eau**, jamais en prealable. Sur 63 tables, **5
  seulement** portent `created_at` ET `updated_at` : la quasi-totalite des
  modeles demande un `public $timestamps = false;` explicite ou des colonnes
  nommees a la main. 23 tables n'ont aucun horodatage.
- **Sans `view:cache`, Blade recompile chaque gabarit a CHAQUE requete** : 2 a
  4,6 s par requete contre 0,21 s une fois compile. L'entrypoint le fait au
  demarrage. Ne PAS ajouter `config:cache` ni `route:cache` pendant la
  migration : ils figeraient des valeurs encore en mouvement.
- **Apres modification** : `config:clear` apres un changement de config,
  `view:clear` + `view:cache` apres un changement de vue.
- **Sur un hote Windows, le bind mount est ~258x plus lent que le systeme de
  fichiers du conteneur** : 9 300 ms contre 36 ms pour lire 1 500 fichiers PHP
  (mesure du 2026-08-17). Le legacy charge ~5 fichiers par page, Laravel
  plusieurs centaines : une premiere requete a froid depasse 6 s, puis retombe
  a 0,17 s une fois le cache du systeme chaud. Consequences :
  - la sonde du conteneur a un delai de 20 s, pas 5 s — avec 5 s elle echouait
    toujours et le conteneur restait « unhealthy » en permanence sans qu'aucun
    defaut applicatif n'existe ;
  - **toute mesure de latence faite sur cet hote est suspecte.** Comparer
    Laravel au legacy sur ce poste compare surtout leur nombre de fichiers
    charges. L'ecart releve precedemment sur la recherche (2,2 s contre 24 ms)
    doit etre re-mesure ailleurs avant d'etre traite comme un defaut.
- **`@json` multiligne casse le PHP compile.** Le garder sur une ligne.
- **Une cle de traduction absente rend son IDENTIFIANT a l'ecran**, sans
  erreur. Mesurer les cles MORTES : trois pieces justes peuvent donner un
  ecran inerte.

## i18n

Parite FR/EN **stricte**, dans le meme commit. Point de depart mesure au
2026-08-17 : 2 545 cles FR = 2 545 cles EN cote legacy.

Cote legacy le PHP appelle `t('module.cle')` et le JS `__('cle')` (injecte par
`head.php`) — ne pas confondre : une recherche de `__(` dans le PHP ne trouve
rien et le silence passe pour un zero.

## Tests

- Test de caracterisation **vert sur le legacy d'abord**, puis le MEME test
  vert sur Laravel. Divergence voulue -> CHANGELOG + attendu PAR CIBLE.
- **Suivre les liens DU MENU**, jamais une liste d'URL ecrite a la main : sept
  404 ont vecu dans le menu sans qu'aucune suite ne les voie.
- **Mesurer un booleen, pas une longueur.** La longueur du texte d'une page
  bouge seule d'une execution a l'autre (journal d'audit alimente par la
  connexion du test, tableaux asynchrones inacheves) : 2693 / 2690 / 2688
  releves sur la meme page sans aucun changement de code.
- **Verifier les droits avec les comptes dedies** `rw-test-user` (role 1, zero
  permission), `rw-test-admin` (role 2), `rw-test-super` (role 3). Une suite
  qui s'authentifie en superadmin ne mesure aucun cloisonnement — 21 vagues
  ont ete perdues a ecrire « non mesurable ».
- Conventions Puppeteer : voir la skill `rw-e2e`. Un contexte de navigateur
  NEUF par compte (`newPage()` partage les cookies), 30 s entre deux connexions
  du meme compte (fenetre TOTP).

## Environnement

- `laravel/.env` (ignore par git) part de `laravel/.env.example`. L'entrypoint
  genere `APP_KEY` au premier demarrage.
- Toute nouvelle variable va dans `srv-docker.env.example` : les exploitants la
  recuperent automatiquement via `./maj.sh`.
- `MSYS_NO_PATHCONV=1` devant tout `docker exec` portant un chemin absolu :
  Git Bash traduit `/var/www/html` en `C:/Program Files/Git/var/www/html`.

## Authentification — ce que le legacy fait vraiment

Mesure par `tests/e2e/go-socle-auth.mjs` (13 PASS / 1 ecart connu cote legacy) :

- **Aucun chemin sans second facteur.** `login.php` renvoie vers `enable_2fa.php`
  si le compte n'a pas de secret, vers `verify_2fa.php` sinon. Entre le mot de
  passe et le code, la session n'est PAS authentifiee : une page protegee reste
  refusee. Verifie sur les trois roles.
- **L'identifiant de session change** apres authentification complete.
- **Apres le second facteur**, passage par `/terms.php` — sauf
  `force_password_change`, qui renvoie vers `profile.php?force_change=1`.
- Limitation de debit du second facteur : 5 tentatives par session sur 60 s,
  ET un compteur par IP en base (`login_attempts`, `step='2fa'`, seuil 10 sur
  10 min). Une 2FA reussie repasse sa ligne a `success=1` — sans quoi une
  reussite comptait comme un echec.
- **Le garde anti-rejeu TOTP est INERTE** — voir `docs/migration/PARITE.md`
  E-01. `$_SESSION['last_totp_hash']` n'est pose que dans la branche de succes
  puis supprime dans la meme requete. Le portage doit porter ce garde par
  COMPTE, en base, jamais par session : un garde de session ne peut rien contre
  un rejeu venu d'une session neuve.
- Step-up : `stepUpVerify($action, 900)`, cle `_step_up_<action>` par ACTION,
  limitation a 5 tentatives, anti-rejeu `_step_up_last_totp`.

## Navigation

- **`App\Support\Navigation` est la SOURCE UNIQUE du menu.** Le legacy decrit
  le sien DEUX FOIS (barre laterale + tiroir mobile) avec la logique de droits
  recopiee. Ici, les deux rendus incluent le meme partiel
  `composants/entrees-menu.blade.php`, et un test verifie qu'ils rendent les
  memes entrees.
- Chaque entree porte `route` (page PORTEE, lien interne) **ou** `legacy`
  (non portee, lien externe), jamais les deux : l'etat du portage se lit d'un
  coup d'oeil et se verifie par un test.
- Une entree non portee s'affiche avec un marqueur visible et
  `target="_blank"`. Un lien qui change de portail sans le dire trahit
  l'utilisateur. Le test mesure la LARGEUR RENDUE du marqueur : un marqueur
  present dans le HTML mais large de zero ne previent personne.
- Gardes reprises telles quelles du legacy : une permission vaut
  « cette permission OU superadmin (role 3) ». `docker` est garde par le ROLE
  et non par une permission — releve tel quel, signale dans INVENTAIRE.md, pas
  corrige en silence pendant un portage de navigation.
- Les droits sont lus **en base** par `App\Services\Droits` (memorise pour la
  duree de la requete), jamais depuis la session. Le legacy porte lui-meme
  l'avertissement « ne jamais utiliser $_SESSION['permissions'] pour une
  decision de securite ».
- Une section vide n'est pas rendue : un intitule sans rien dessous laisse
  croire qu'un contenu a disparu.
- Menu attendu au 2026-08-18 : **33 entrees** au total ; role 1 → 3, role 2
  (8 permissions, sans can_admin_portal) → 13, role 3 → 33.

## Interface — exigences de l'exploitant

- **REGARDER le rendu, pas seulement l'asserter.** `tests/e2e/go-captures-socle.mjs`
  produit des captures a 1920, 1400 et 390 px ; les OUVRIR. Une assertion DOM
  ne voit ni un bouton mal place, ni une largeur gaspillee, ni un pave de texte
  illisible. Trois defauts n'ont ete vus qu'a l'image : ~1000 px vides de
  chaque cote sur grand ecran, « Connecte en tant que » affiche deux fois, et
  « ancien portail » repete 31 fois dans le menu.
- **Utiliser la largeur.** Pas de `max-width` sur la page : `.rw-contenu` prend
  toute la place et `.rw-grille` (`auto-fit`, minimum 280 px) la remplit. Seule
  la PROSE se borne, par `.rw-prose` (68ch) — un paragraphe centre sur 1900 px
  se relit ligne par ligne.
- **Boutons.** Action principale a DROITE en pied de formulaire (`.rw-actions`),
  action secondaire a gauche (`.rw-actions__gauche`). Pas de bouton pleine
  largeur sauf action unique dans une carte etroite. Compte et deconnexion dans
  l'EN-TETE, pas en pied de barre laterale — la ils bornaient la liste du menu,
  qui se coupait en plein libelle.
- **Guidage.** Fil d'etapes sur les ecrans d'authentification (`.rw-etapes`),
  aide sous les champs (`.rw-aide`), etats vides qui disent ce qui manque ET
  pourquoi (`.rw-vide`), tuiles d'orientation sur l'accueil (`.rw-tuile`).
- **Marqueur des pages non portees** : une fleche discrete, expliquee UNE FOIS
  par la legende en tete de menu, avec le detail dans le `title`.

## Passerelle vers le backend

- `App\Support\RoutesBackend` est la SOURCE UNIQUE des listes (blanche, admin,
  step-up). `App\Http\Controllers\PasserelleController` applique les controles
  DANS L'ORDRE, fail-closed a chaque etape : session authentifiee (middleware),
  falsification de requete (middleware `web`), traversee de chemin, liste
  blanche, reserve a l'administration, re-authentification exigee, transmission.
- **Comparaison par SEGMENT, jamais par prefixe.** Voir `PARITE.md` E-02. Une
  entree finissant par `/` est un espace de noms, par `_` ou `-` une racine
  deliberee, sinon une route exacte. Verifie sur les 201 routes reelles du
  backend avant de resserrer : zero difference de verdict.
- Les permissions transmises au backend (`X-User-Permissions`) sont relues EN
  BASE, pas prises dans la session.
- Le statut du backend est PROPAGE tel quel : un 404 devenu 200 ferait croire
  au frontend que l'appel a reussi.
- **La falsification de requete est deja geree par le cadre.** Laravel 13 place
  `PreventRequestForgery` dans le groupe `web` : il accepte si la methode est en
  lecture, si le chemin est exclu, si l'ORIGINE est valide
  (`Sec-Fetch-Site: same-origin`) ou si le jeton correspond. Ne PAS ajouter
  `ValidateCsrfToken` par-dessus.
  Piege de mesure paye le 2026-08-18 : un `fetch` same-origin sans jeton passe,
  ce qui a fait croire a une absence de controle. C'est le comportement
  ATTENDU. La propriete a mesurer est qu'une requete **cross-site** soit
  refusee — et le navigateur interdisant de forger `Sec-Fetch-Site`, il faut
  rejouer la requete depuis Node avec les cookies de session.
- **Ne pas sonder le legacy avec des requetes mutantes.** Un POST refuse par son
  controle CSRF invalide la session ; son JS de sondage part alors vers la page
  de connexion, et cette navigation DETRUIT le contexte d'execution : le
  `page.evaluate` en cours ne rend jamais et tout le lot expire sans rien
  mesurer.

## i18n

- `App\Http\Middleware\Langue` : priorite `?lang=` > session > cookie > `fr`.
  La liste blanche `['fr','en']` est un CONTROLE DE SECURITE, pas une
  commodite : cote legacy, un pentest a montre qu'un cookie forge permettait
  d'inclure un fichier arbitraire. Toute valeur hors liste retombe sur le
  defaut, sans exception et sans message.
- Le selecteur vit dans `composants/langue.blade.php`, inclus par les DEUX
  gabarits. Il doit rester atteignable AVANT toute connexion : une personne qui
  ne lit pas le francais doit pouvoir basculer pour comprendre l'ecran de
  connexion lui-meme.
- **Le repli de langue MASQUE la moitie des defauts.** Avec
  `APP_FALLBACK_LOCALE=en`, une cle absente des DEUX langues affiche son
  identifiant (`auth.xxx`, visible), mais une cle presente en anglais et
  absente en francais affiche LE TEXTE ANGLAIS — invisible a l'oeil comme a un
  test qui cherche des identifiants. Il faut donc DEUX controles :
  1. aucun identifiant a l'ecran, dans les deux langues ;
  2. **parite des jeux de cles** fr / en, module par module.
  `tests/e2e/go-socle-i18n.mjs` fait les deux ; le second passe par PHP dans le
  conteneur, parce qu'analyser des fichiers PHP a l'expression reguliere
  reviendrait a reecrire un interpreteur — et une cle mal lue serait declaree
  absente a tort.
- Le cookie de preference part CHIFFRE (middleware `EncryptCookies`). Le
  dernier argument booleen de `cookie()` est `raw`, PAS le chiffrement : les
  confondre conduit a ecrire un commentaire qui dit l'inverse du code.

## Contrat DOM des tests

**Ne jamais ancrer un test sur « le premier bouton submit ».** Deplacer un
bouton a suffi a faire cliquer « Refuser et se deconnecter » au lieu
d'« Accepter » : les scripts se deconnectaient en croyant entrer, et l'erreur
ne se voyait qu'a une exception trois etapes plus loin.

Les elements que les tests pilotent portent un attribut `data-rw="<nom>"`
stable. Attributs poses a ce jour : `cgu-accepter`, `cgu-refuser`.
Les champs de formulaire gardent le nom du legacy (`username`, `password`,
`2fa_code`) : le MEME test vise les deux cibles, il ne peut pas connaitre deux
noms de champ.

## Etat du portage — le SOCLE est complet

| Piece | Etat | Lot |
|---|---|---|
| Squelette et conteneur | fait | — |
| Authentification (TOTP obligatoire, anti-rejeu par compte) | fait | auth 14 / 13+1 |
| Gabarit et navigation (33 entrees, source unique) | fait | navigation 35 |
| Interface (largeur, boutons, guidage) | fait | captures regardees |
| Passerelle vers le backend (filtrage par segment) | fait | passerelle 10 / 5+1 |
| i18n (bascule FR/EN, parite verifiee) | fait | i18n 23 |

NON PORTE, et signale a l'ecran plutot que silencieusement absent : enrolement
d'un second facteur, re-authentification ponctuelle (step-up), politique de mot
de passe, reinitialisation. Un compte sans secret TOTP arrive sur une impasse
explicite renvoyant vers l'ancien portail.

### Pages metier

| Page | Route | Garde | Archivee |
|---|---|---|---|
| Journal des commandes | `journal-commandes` | `role:2` + `perm:can_admin_portal` | oui, 2026-08-18 |
| Approbations a quatre yeux | `approbations` | `role:2` + `perm:can_admin_portal` | oui, 2026-08-18 |
| Derive de configuration | `derive-config` | `role:2` + `perm:can_view_compliance` | oui, 2026-08-18 |
| Sauvegardes de la base | `sauvegardes` | `role:2` + `perm:can_admin_portal` | oui, 2026-08-18 |
| Centre de taches | `taches` | `role:2` SEUL (comme le legacy) | oui, 2026-08-18 |
| Ticketing ITSM | `tickets` | `role:2` + `perm:can_admin_portal` | oui, 2026-08-18 |

Le cycle d'archivage est eprouve : `git mv legacy/<partie> legacy/_deprecated/`,
puis l'URL du legacy doit rendre **404** — c'est la preuve que plus rien ne la
sert. Penser aussi a rediriger l'entree du menu DU LEGACY vers le nouveau
portail (`LARAVEL_URL`), sans quoi on installe soi-meme un 404 dans un menu.

### Gardes de page

`role:2` (role au moins administrateur) et `perm:can_admin_portal` (cette
permission OU superadmin). La garde vit DANS LA ROUTE et nulle part ailleurs.
Les deux refus rendent 403 avec des messages distincts, sans detailler ce qui
manque.

### Tableaux et chargements

- Rendu par `textContent`, jamais par interpolation : les donnees journalisees
  contiennent par nature des caracteres de shell.
- Les libelles affiches par un script sont poses EN DONNEES dans la page
  (`@json` sur UNE ligne) : une chaine ecrite en dur dans du JS echappe a la
  parite FR/EN.
- **Sequencer les chargements** : numeroter chaque appel et n'ecrire que si le
  numero est encore le dernier. Sans cela, deux changements de filtre
  rapproches peuvent laisser la reponse la plus ancienne gagner.
- Le defilement horizontal appartient au CADRE du tableau, jamais au corps de
  la page.

### Aucune boite native — la decision se prend DANS la page

`confirm()` et `prompt()` sont proscrits dans le portage. Une confirmation
s'ouvre EN LIGNE, sous la ligne concernee, avec ses champs et ses deux boutons
(`rw-panneau-decision`). Trois raisons :

1. la boite native recouvre precisement la ligne sur laquelle on decide ;
2. elle ne se style pas — action destructrice et annulation au meme poids ;
3. elle **bloque Puppeteer**, donc le test ne peut pas mener l'action au bout.

Le bouton de confirmation porte `rw-bouton--danger`, l'annulation reste
`rw-bouton--discret`, et les deux portent un `data-rw`.

### Une regle appliquee par le backend se REND VISIBLE

Quand le backend refusera de toute facon (regle des quatre yeux : on n'approuve
pas sa propre demande), le bouton est **desactive** avec l'explication en
infobulle, plutot que cliquable pour rien. La regle n'est jamais deplacee cote
navigateur — elle est seulement annoncee plus tot.

Si aucun compte de test ne permet d'exercer la branche, **le dire** dans
`PARITE.md` plutot que de modifier des droits pour se satisfaire : un test qui
deplace les droits ne mesure plus l'application reelle.

### Le tableau doit DIRE qu'il defile

`.rw-tableau-cadre` porte des ombres de bord en CSS pur : deux voiles
`background-attachment: local` qui glissent avec le contenu, deux ombres
`scroll` collees au cadre. L'indice apparait seulement s'il reste des colonnes
a atteindre. Le jeton `--rw-bord-defilement` est defini PAR THEME — une ombre
noire est strictement invisible sur un fond sombre, ce qui etait le cas de la
premiere version, la ou elle servait.

Cause : une capture a 390 px montrait des lignes dont la colonne d'actions —
la raison d'etre de la page — etait hors ecran, sans le moindre indice.

### Constat d'archivage : `tests/e2e/archive.mjs`

Une partie archivee ne doit pas laisser une suite ROUGE derriere elle. Deux
parties archivees, deux suites rouges en permanence, et plus personne ne lit
les rouges.

Sur la cible legacy, le test commence par sonder l'URL. 404 = archivee, et il
bascule sur trois verifications qui ont un sens apres le deplacement :

| Verification | Ce qu'elle empeche |
|---|---|
| la partie rend 404 | un dossier vide mais toujours servi |
| ses fichiers reels rendent 404 | un script encore joignable |
| le menu du legacy mene au portage | installer soi-meme un 404 dans un menu |

Deux details qui ont ete payes :

- la sonde passe par `node:https` (certificat auto-signe), **pas** par
  `fetch`, et surtout pas en posant `NODE_TLS_REJECT_UNAUTHORIZED` sur tout le
  processus pour lire un code de statut ;
- sonder un chemin qui **n'a jamais existe** rend 404 et fait passer
  l'assertion pour rien. Verifier le nom reel dans `legacy/_deprecated/<partie>/`.
  Une assertion creuse est pire qu'une assertion absente : elle occupe la place.

### Jamais d'attente FIXE apres un geste qui declenche un appel

Attendre `1500` ms apres un changement de filtre tient tant que la table est
courte, puis produit de FAUX ECHECS des qu'elle grossit : la sonde lit encore
le resultat precedent et le test accuse le filtre.

Le motif correct, deux temps :

1. attendre que l'empreinte du corps **change** (et ne soit plus « Chargement ») ;
2. puis attendre qu'elle **cesse de bouger** — une reponse en retard peut encore
   ecraser ce qu'on vient de lire.

Vaut aussi pour le script de captures, qui photographiait « Chargement… ».

### Ce que le backend cache dans une infobulle, l'afficher

Un attribut `title` ne s'ouvre ni au doigt, ni au clavier, ni pour un lecteur
d'ecran. Quand ce qu'il contient est la seule information ACTIONNABLE de la
page — le detail d'un ecart, la raison d'un refus —, l'afficher
(`rw-detail-ecart`). Le montrer seulement sur les lignes qui demandent une
action : repete sur les lignes saines, il noie ce qu'on cherchait.

Meme regle pour les libelles muets : `?` et `—` dans un tableau de conformite
se lisent aussi bien « inconnu » que « erreur ». Ecrire « Jamais evalue ».

### Annoncer durablement, pas dans une bulle fugace

`toast` est proscrit. Une action qui change ce qui est affiche s'annonce dans
une region persistante (`rw-annonce`, `role="status"`, `aria-live="polite"`),
vide au chargement (`:empty { display: none }`). Une bulle disparue ne dit plus
si les valeurs qu'on relit sont celles d'avant ou celles d'apres.

Cote test, RELEVER l'annonce plutot que l'exiger : le legacy n'a rien de
durable a annoncer, et une attente identique sur les deux cibles ferait echouer
le test sur celle qu'il caracterise.

### Lire ce qu'un bouton fait AVANT de cliquer sur un parc de production

`scan_all` de la derive couvre la machine 1. Le code a ete lu avant d'ecrire le
test : aucun appel SSH, un recalcul depuis la base. La page le DIT desormais a
l'ecran, description et infobulle du bouton comprises.

### La garde par permission ne se prouve qu'avec un compte qui la porte

`can_admin_portal` n'est portee que par le superadministrateur parmi les
comptes de test : sur les pages qui l'exigent, rien ne distingue une garde par
PERMISSION d'une garde par ROLE. `can_view_compliance` est portee par
`rw-test-admin` (role 2) : le meme compte est autorise sur `derive-config` et
refuse sur `journal-commandes`. C'est cette paire qui prouve la lecture de la
permission. Choisir l'ordre de portage en tenant compte de cela.

### Attendre la CONDITION, pas le calme

Le motif « changement puis stabilite » a une faille : pendant une action, le
bouton affiche « Scan en cours » et le tableau ne bouge PLUS DU TOUT. La sonde
trouve le calme immediatement, lit l'etat d'avant, et rapporte que l'action n'a
rien fait — alors que la requete a abouti et la base ete ecrite.

Quand on sait ce qu'on va asserter, ATTENDRE CELA, avec une limite :

    const apres = await attendJusqua(page, e => e.horodatage !== avant);

### Une assertion trop stricte mesure autre chose

« Chaque horodatage a change » echoue quand deux ecritures tombent dans la meme
seconde : le test mesure alors la resolution de l'affichage, pas l'action. La
propriete juste etait « le plus ancien d'apres n'est pas anterieur au plus
recent d'avant ». Comparer des dates AFFICHEES demande de les convertir : a
l'ordre alphabetique, le 18 janvier passe apres le 17 decembre.

### Un test ne doit pas consommer ce dont il depend

Le test des approbations rejetait une demande a chaque execution et travaillait
sur des demandes creees a la main : au bout de quelques passages, la file etait
vide et il echouait sans qu'aucune page ne soit cassee. Il PRODUIT desormais
ses demandes, avec le compte qui en produit legitimement, sur des cibles
inexistantes et horodatees (le backend refuse une demande identique deja en
attente). Il y gagne une assertion : l'action destructrice repond bien 202.

Ne le faire que sur la cible Laravel : sonder le legacy avec une requete
mutante invalide sa session et detruit le contexte d'execution.

### Grille de tuiles : 160 px, pas 190

Quatre tuiles de resume a `minmax(190px, 1fr)` tiennent sur UNE colonne a
390 px et repoussent le tableau sous quatre ecrans de contexte. A 160 px elles
tiennent deux par deux, et sur grand ecran rien ne change : `auto-fit`
effondre les pistes vides. Classe : `rw-grille--compacte`.

### Une confirmation doit EMPECHER, pas reprocher

Pour une action irreversible, la confirmation en ligne ne suffit pas : le bouton
de confirmation naît DESACTIVE et ne s'active que lorsque la saisie egale
exactement ce qui est demande (nom du fichier, nom de la machine). Le legacy
laissait confirmer puis annoncait « le nom ne correspond pas » — le geste avait
deja ete fait, et rien n'empechait de recommencer.

Effet de bord utile : le chemin d'erreur devient TESTABLE. Avec `prompt()`, il
ne l'etait pas — le gestionnaire de dialogue annule avant toute saisie.

### Un libelle qui promet plus que le code ne tient est un defaut

`verify_backup()` compare l'empreinte, decompresse et compte les `CREATE TABLE`.
Il n'execute AUCUNE instruction. Le legacy l'annonce pourtant, en trois
endroits, comme un « test de restauration qui recharge la sauvegarde dans une
base temporaire ». Un dump lisible mais inapplicable passe sans reserve.

Le portage appelle la meme route et ne change que les mots. TOUJOURS LIRE LA
FONCTION avant de recopier le libelle qui la decrit : une promesse de controle
conduit a ne pas faire le controle qu'on croit deja fait.

### Ne jamais mener une action destructive sur la base PARTAGEE

`/admin/backups/restore` fait un `DROP TABLE` sur la base que se partagent le
legacy, Laravel et le backend Python. Un test qui la restaure detruit les
sessions et les donnees des autres suites — les siennes comprises.

Verifier que l'action EXISTE, qu'elle est gardee, et que le chemin d'erreur ne
la declenche pas. Puis ECRIRE que la voie nominale n'est pas couverte, plutot
que de laisser croire qu'elle l'est.

### La garde de la PAGE n'est pas la garde de la CAPACITE

La page des sauvegardes exige `can_admin_portal` ; le backend ne demande que le
role 2 sur `/admin/backups`, et la passerelle double le backend sans inventer.
Depuis une session role 2 refusee sur la page avec un 403,
`GET /api/gateway/admin/backups` repond 200 avec la liste.

MESURER cette paire pour toute page dont la permission differe de celle du
backend. Ne pas resserrer : retirer une possibilite a un role est un changement
de droits, pas une decision de portage. Le releve va dans DEPRECIATION.md.

### Attendre le BOUTON, pas la premiere annonce

Une region d'annonce affiche d'abord « en cours ». Une sonde qui lit des qu'elle
est non vide recolte le message de travail, jamais le verdict. Le signal juste
est le bouton : desactive pendant l'appel, reactive dans le MEME bloc synchrone
que l'ecriture du verdict. Il ne depend ni de la cible ni de la langue.

### Ne pas asserter sur un mot qu'on vient soi-meme de changer

Une attente cherchait « valide » dans le verdict d'un controle — alors que le
portage avait justement renonce a ce mot, le controle ne prouvant pas la
validite. Asserter sur ce que l'action RAPPORTE (deux nombres : des tables, des
instructions) tient dans les deux langues et survit a une reformulation.

### Un nom de fichier n'est pas une commande

`.rw-code` coupe a n'importe quel caractere : il est fait pour des commandes de
plusieurs centaines de caracteres. Applique a un nom de fichier dans une colonne
etroite, il rend « rootwa / rden_b / ackup_ » sur six lignes. Utiliser
`.rw-code--fichier` : le nom reste d'une piece, le debordement appartient au
cadre du tableau.

### L'archivage peut faire tomber une exception de `.gitignore`

`.gitignore` exclut `backups/` (le stockage) avec une exception explicite pour
`legacy/backups/**`, qui est du CODE. `git mv legacy/backups
legacy/_deprecated/backups` fait tomber l'exception : le dossier archive
retombe sous la regle generale.

Les fichiers DEJA SUIVIS survivent au deplacement, ce qui masque entierement le
probleme — jusqu'au jour ou l'on ajoute un fichier dans l'archive et qu'il
devient invisible. Apres chaque archivage, verifier :

    git check-ignore -v legacy/_deprecated/<partie>/

et etendre l'exception si besoin.

### Une erreur ne s'avale pas : montrer moins plutot que montrer faux

Le legacy n'ecrit son tableau que si l'appel a REUSSI, et ne fait RIEN sur
echec : les lignes precedentes restent affichees. Sur le centre de taches, ou le
filtre par statut repond 500, cela laisse cent taches « Reussie » a l'ecran
quand on a demande « Echec ». Des donnees exactes presentees comme la reponse a
une question qu'on n'a pas posee.

Dans le portage, tout `if (reussi)` a un `else` : vider, et DIRE. Un
`if` sans `else` fabrique un ecran rassurant et faux, comme un `catch` vide
fabrique un rapport rassurant et faux.

### Ce qui est CACHE n'est pas GARDE

Deux ecarts symetriques, mesures :

| Page | Ecart |
|---|---|
| sauvegardes | la PAGE exige `can_admin_portal`, la CAPACITE se contente du role 2 |
| taches | le MENU exige `can_admin_portal`, la PAGE se contente du role |

Sur `tasks`, un role 2 sans la permission ne voit pas l'entree et atteint
pourtant la page en tapant son adresse.

Pour chaque page portee, MESURER la paire (entree de menu, acces direct) quand la
garde du menu differe de celle de la page. Reproduire l'ecart tel quel et le
consigner : corriger d'un cote ou de l'autre change des droits.

### Mesurer une fonction, pas ses effets visibles

L'auto-rafraichissement ne se verifie PAS en regardant si le tableau change : sur
un historique stable, un rafraichissement parfaitement fonctionnel ne change rien
a l'ecran. Compter les requetes :

    let n = 0;
    const ecoute = (r) => { if (/\/tasks\/list/.test(r.url())) n++; };
    page.on('request', ecoute); await dors(7000); page.off('request', ecoute);

Verifier AUSSI que le couper l'arrete vraiment — zero requete.

### Un libelle de periode vaut mieux qu'un libelle d'intention

« Rafraichir auto » ne dit pas si ce qu'on lit date de 5 s ou de 5 min.
« Actualiser toutes les 5 s » le dit.

### `flex-shrink: 0` fait DEBORDER au lieu de replier

Un bloc d'actions en `flex-shrink: 0` garde sa largeur naturelle : a 390 px il
sort du champ et son texte est coupe net, meme avec `flex-wrap` sur le parent.
Retirer `flex-shrink`, poser `min-width: 0` et `flex-wrap: wrap`, et ne pas
mettre `white-space: nowrap` sur un libelle long.

### Ne JAMAIS definir deux fois la meme classe CSS

`.rw-etiquette` a designe le LIBELLE d'un champ, puis la PASTILLE d'une
categorie. La seconde regle l'emportant, tous les libelles de formulaire du
portail — « Identifiant » et « Mot de passe » compris — etaient rendus en
pastille bleue pendant plusieurs vagues.

Aucune assertion ne pouvait le voir : les libelles etaient presents, corrects,
traduits, associes a leur champ. SEULE LA CAPTURE le montrait. C'est le defaut
`escHtml()` defini deux fois du legacy, reproduit dans notre propre feuille.

Avant d'ajouter une regle : `grep -n "^\.rw-<nom> {" rw.css`. Un nom deja pris
se renomme (`.rw-badge`), il ne se surcharge pas.

### Un test ne doit pas SATURER un espace de cles borne

« Produire ce qu'il consomme » ne suffit pas. Le dedoublonnage des tickets
porte sur `(source, ref, machine)` : le formulaire manuel ne peut creer qu'UN
ticket par machine, pour toujours. Un test qui vise toujours la machine 2
reussit une fois, puis echoue a chaque execution suivante.

Chercher un creneau LIBRE, exclure la machine de production, et si aucun n'est
disponible, le DIRE et jouer l'autre branche. Les deux branches doivent mesurer
quelque chose.

### Attendre la RELECTURE, pas un changement d'etat

Apres un envoi, attendre « le nombre de lignes a change » ne finit jamais quand
l'action a ete DEDOUBLONNEE — rien ne change, et c'est le comportement correct.
Le signal juste est la requete de relecture que la page declenche apres l'envoi,
identique dans les deux cas :

    let statut = 0, relectures = 0;
    page.on('response', r => {
        if (!/\/tickets(\?|$)/.test(r.url())) return;
        if (r.request().method() === 'POST') statut = r.status();
        else if (statut !== 0) relectures++;
    });

### Extraire AVANT de recopier

Le controleur des tickets allait recopier la liste des machines du controleur du
journal. `App\Services\Machines` la porte desormais pour les deux. Le service
documente pourquoi il ne filtre pas par acces (pages d'administration) ET
avertit de ne pas le reprendre ailleurs — c'est precisement le defaut du tableau
de bord du legacy.

### `.rw-carte` est plafonnee a 420 px

Elle est faite pour l'ecran de connexion. Un formulaire POSE DANS UNE PAGE prend
`.rw-carte--pleine`, sans quoi ses colonnes sont a l'etroit avec 1 200 px de
vide a cote.

### Cacher un formulaire par `hidden`, pas par une classe

L'attribut `hidden` rend l'etat lisible sur la GEOMETRIE
(`getClientRects().length`), qu'un test mesure sans connaitre nos conventions de
nommage — et qui vaut pour le legacy comme pour le portage.

### Une URL EXTERNE se pose par `setAttribute`, jamais par interpolation

`external_url` vient de l'ITSM. Filtrer sur `^https?://` puis
`a.setAttribute('href', url)` : il n'y a alors aucun guillemet a echapper a la
main, contrairement au `escAttr` que le legacy a du s'inventer.

## Detail

Socle complet. Six pages metier portees et archivees ; le cycle est rode et se
deroule d'une traite : caracterisation verte sur le legacy, portage, meme test
vert sur Laravel, verification en cliquant, captures REGARDEES, archivage,
rejeu du LOT, commit.

Reference consultable sur la branche abandonnee `laravel` (22 vagues, 2 825
assertions vertes) : `git show laravel:docs/migration/{AUTH,GATEWAY,LAYOUT,DESIGN-SYSTEM,PORTAGE}.md`
et `git show laravel:laravel/resources/views/components/rw/<nom>.blade.php`
(7 composants). A consulter, jamais a recopier telle quelle.
