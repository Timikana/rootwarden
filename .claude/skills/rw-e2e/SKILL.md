---
name: rw-e2e
description: Conventions des tests E2E Puppeteer RootWarden - harnais login+TOTP, scripts auto-validants, nettoyage d'etat, machines autorisees. A charger avant d'ecrire ou modifier un script tests/e2e/go-*.mjs.
---

# Tests E2E Puppeteer RootWarden

Les scripts vivent dans `tests/e2e/go-<sujet>.mjs`. Un script de regression est
**auto-validant** : headless, assertions PASS/FAIL, `process.exit(0|1)`, et il
**restaure l'etat initial** (supprime ce qu'il cree, re-toggle ce qu'il toggle).

## Modeles a copier
- `go-access-toggle-refresh.mjs` — toggle + verification DOM sans reload (marqueur JS anti-reload).
- `go-update-filter.mjs` — lecture seule, verification tableau + absence d'erreur dans les logs.
- `go-ssh-audit-scanall.mjs` — operation asynchrone : reponse immediate puis polling jusqu'au terminal.
- `go-supervision-profile-assign.mjs` — CRUD + assignation + persistance apres reload + cleanup.

## Harnais (identique partout)
- Base `https://localhost:8443`, viewport **1400x900**, `headless: 'new'`,
  args `--ignore-certificate-errors --allow-insecure-localhost`.
- Login : `superadmin` + mot de passe (defaut du script, surchargable `E2E_USER`/`E2E_PASS`),
  TOTP calcule a la volee depuis **`E2E_TOTP_SECRET` (variable d'env, JAMAIS en dur
  dans le script — gitleaks est bloquant en CI)**. Gerer les redirections
  `verify_2fa` et `terms` (voir boilerplate des modeles).
- Si le secret 2FA a change (apres `docker compose down -v`), le regenerer via
  l'enrollment puis mettre a jour l'env.
- `check(label, ok)` : log `PASS/FAIL`, compteur d'echecs, verdict final `=== TOUT OK ===`.
- Capturer `page.on('pageerror')` et asserter zero erreur JS.
- Screenshots dans `./screenshots/<sujet>/NN_etape.png` (dossier gitignore).
- **LES CAPTURES SE DEPOSENT ET S'ENVOIENT.** Un script ad hoc lance depuis le
  scratchpad y laisse ses images : personne ne les voit. Ecrire dans
  `tests/e2e/screenshots/<module>/` **et** les envoyer (SendUserFile) a chaque
  sous-lot — grand ecran, pied de la page concernee, mobile 390. « Capture
  regardee » dans un CHANGELOG ne remplace pas l'image.

## Regles d'or
- **Attendre le TOTP** : si `30 - (epoch % 30) < 6`, dormir jusqu'a la fenetre suivante.
- **CLIQUER LE BOUTON, PAS APPELER LA FONCTION. C'est une CONVENTION du projet**, rappelee
  par l'exploitant le 2026-08-23. Une suite se pilote par des **clics simules** sur les
  elements reels (`page.click`, `page.type`), pas par `page.evaluate(() => fonctionDeLaPage())`
  ni par des requetes HTTP brutes.

  Cette ligne disait l'inverse jusqu'au 2026-08-23 (« preferer `page.evaluate` aux clics
  fragiles quand on teste la LOGIQUE »), et c'est ce qui a laisse deriver une suite entiere
  vers `node:https` sans navigateur. **Appeler la fonction ne mesure pas que le bouton
  l'appelle** : un `onclick` absent, un bouton `disabled`, un ecouteur jamais attache, un
  formulaire dont l'action a change — rien de tout cela ne se voit.

  Les deux seules exceptions, et elles ont chacune leur raison ecrite :
  - la **requete FORGEE**, pour exercer ce qu'aucun clic ne peut atteindre (revalidation
    cote serveur qu'un `<input>` ne peut pas violer, ou geste isole de l'enchainement qui le
    corrige) — elle s'emet alors **depuis la page**, par `fetch` dans un `page.evaluate`,
    donc avec la session et les en-tetes reels ;
  - la **sonde `node:https`** de `archive.mjs`, qui lit un code de statut sur un certificat
    auto-signe la ou aucune page n'existe plus.
  Dans les deux cas, le commentaire dit pourquoi le clic ne convenait pas.
- Pour verifier "sans reload" : poser `window.__marker = 42` avant l'action et
  verifier qu'il survit apres.
- Operations asynchrones (centre de taches) : poll toutes les 5 s avec garde-fou
  de duree max, jamais d'attente infinie.
- Mutations : UNIQUEMENT sur la stack locale (localhost:8443) ou test-server
  (machine id=2). JAMAIS de mutation sur srv-zabbix (id=1, PROD).
- Le backend Python est monte en bind : apres modification backend,
  `docker restart rootwarden_python` avant de lancer l'E2E. Le PHP/JS est servi
  direct (pas de restart necessaire).

## Une fixture doit porter sur une donnee REELLEMENT AFFICHEE

Paye en S5, et le prix etait eleve : la remediation de fixture etait posee sur un
identifiant de CVE **invente**. Il n'apparaissait donc dans aucune ligne du
tableau, et l'assertion « le suivi affiche l'etat stocke » lisait le selecteur
d'une AUTRE ligne — pour laquelle « vide » est la bonne reponse. **Le test
echouait sur le portage alors que le portage avait raison.**

Deux regles qui en sortent :

1. la fixture se choisit DANS les donnees rendues — ici la premiere CVE dans
   l'ordre d'affichage, ce qui garantit en plus qu'elle est sur la premiere page ;
2. le reperage se fait par le CONTENU de la ligne (`tr.textContent.includes(...)`),
   pas par « le premier element de ce type » : c'est le seul reperage qui vise la
   meme chose sur les deux portails.

Et quand une assertion echoue sur la cible corrigee, se demander d'abord si c'est
LA MESURE qui vise a cote.

## Trois pieges de mesure payes en S3

**UN BLOC REPLIE NE RECOIT PAS LES FRAPPES.** Le champ de recherche existait dans
le DOM, `page.$()` le trouvait, `type()` ne levait pas — et rien ne se passait,
parce que le bloc etait masque. Les gestes ne mesuraient rien, et la suite mourait
vingt lignes plus loin sur « Node is either not clickable ». **Deplier d'abord, et
l'asserter** : `getBoundingClientRect().height > 0` et `display !== 'none'`.

**UN COMPTEUR SE LIT AVANT LE GESTE QUI LE CHANGE.** Lu apres un filtre, il
annonce le sous-total du filtre — ce qui est correct. L'asserter la comparait deux
grandeurs differentes. Mon erreur, pas celle du legacy.

**UN TEST QUI NE PEUT PAS ECHOUER.** `go-cve-schedules.mjs:98-113` : le seul test
d'interface de la suite est une branche `if (beforeHtml)` dont le resultat du clic
est simplement `console.log`e. Si le bouton manque, ou si le clic ne change rien,
la suite passe quand meme — alors que son en-tete annonce verifier exactement ce
bug. Se defier de toute branche conditionnelle et de tout resultat seulement
journalise.

## Apres avoir edite une suite : `node --check`

Une seconde, et cela attrape ce qu'aucune relecture ne voit. En S2b, une
fonction ajoutee a declare un `const COMPTES` alors que le fichier portait deja
une carte des comptes de test du meme nom : `SyntaxError: Identifier 'COMPTES'
has already been declared`. Sans le controle, la suite mourait au chargement et
le rejeu du LOT l'aurait rapportee « 0 PASS » — le symptome qui a deja fait
diagnostiquer trois fois de la flakiness a tort.

Verifier aussi les **imports devenus morts** apres une extraction : ils ne
cassent rien, mais ils mentent sur ce dont le fichier depend.
`grep -c "execFileSync(" <suite>` a 0 alors que l'import est la = import mort.

## Lire la base depuis une suite : `lib-base.mjs`, jamais a la main

    import { litEnBase, compteEnBase } from './lib-base.mjs';

Il lit le mot de passe dans `srv-docker.env` (jamais en dur : gitleaks est
bloquant en CI) et **expurge l'erreur** en cas d'echec — `mysql` prend son mot de
passe en argument, et Node recopie l'argv complet dans le message. Voir
`rw-pieges`.

## Une action a effet SORTANT ne se teste pas en la declenchant

Avant de faire cliquer un test sur une action, chercher ce qu'elle ENVOIE :
`send_*`, `notify_*`, un webhook, un appel a un service externe — et verifier si
l'environnement est reellement configure pour l'envoyer (`MAIL_ENABLED`,
`MAIL_TO`, un SMTP joignable). Le scan CVE envoie un rapport par courriel des que
son evenement `done` porte des findings ; ici vers une adresse reelle.

Consequences pour la conception d'une suite :

- **le geste dangereux ne vise jamais une cible qui peut repondre** — viser un
  identifiant valide mais inexistant, qui traverse les gardes et ne produit
  qu'une erreur ;
- **ne jamais s'appuyer sur un garde-fou serveur qu'on a « arme »** : voir
  `rw-pieges`, une limite en memoire de processus est multipliee par les workers
  et N refus observes ne predisent pas le N+1 ;
- **la propriete « rien n'est parti » se mesure au RESEAU** (`page.on('request')`)
  et **« rien n'a ete ecrit » se mesure EN BASE**, avant et apres ;
- si un declenchement accidentel a lieu : `sudo -n docker restart
  rootwarden_python` coupe le flux avant son evenement final, donc avant l'envoi
  — puis PROUVER l'absence d'effet (aucune ligne creee, aucune trace SMTP) et le
  dire.

## Exercer les DEUX chemins d'une garde « permission OU role »

Une suite qui se connecte toujours avec le compte qui PORTE la permission ne
mesure qu'un des deux chemins. `rw-test-super` (role 3) n'a PAS
`can_manage_supervision` : c'est le seul compte qui distingue « la garde laisse
passer parce que la permission est la » de « parce que le role l'emporte ».
Verifier en base quels droits portent vraiment les trois comptes avant de
supposer.

## Deux connexions dans la meme suite : attendre la fenetre TOTP

Le garde anti-rejeu est par COMPTE et EN BASE : un contexte de navigateur neuf
n'y echappe pas. Une suite qui se connecte deux fois (passe FR puis passe EN)
doit **attendre le basculement de la fenetre** entre les deux, **asserter que la
seconde session a tenu** (URL != page de connexion), et reproposer une fois un
code neuf si le second facteur est refuse.

Sans la deuxieme piece, les controles d'i18n passent sur l'ecran de connexion —
qui ne porte evidemment aucun identifiant de traduction. Un PASS dont on ne sait
pas pourquoi il passe ne vaut rien.

## Cliquer un bouton dont l'action joindrait la production

Motif eprouve sur V8 (`go-page-supervision-releve`) : activer
`page.setRequestInterception(true)`, **avorter la seule requete dangereuse** et
laisser passer le reste. On clique alors le vrai bouton, on mesure la requete
emise (methode, chemin, corps) — et rien n'atteint la machine.

Le contrat du backend se mesure a part, sur une **portee explicite** qui ne peut
pas atteindre la production (`machine_ids: [2]`). Et le chemin « tout le parc »,
qu'aucun navigateur ne peut declencher sans danger, s'exerce cote **pytest** en
patchant le helper de creation de thread.

## Lancement

**Passer par le lanceur, jamais par `node go-*.mjs` a la main** :

```bash
./scripts/rejouer-lot.sh --laravel go-<sujet>
./scripts/rejouer-lot.sh                     # tout le LOT, les deux versants
```

Il porte les six prealables sans lesquels rien ne marche et compare a la
reference. **Voir le skill `rw-lot`** : les prealables, les chiffres de reference
et les trois signatures d'echec qui ont deja trompe y vivent, et nulle part
ailleurs.

Pour se connecter A LA MAIN a un portail : `node tests/e2e/code-totp.mjs <compte>`
imprime le code a six chiffres.

### L'ancienne invocation, pour memoire

```bash
cd tests/e2e
E2E_TOTP_SECRET='<secret>' node go-<sujet>.mjs
```

## Pieges d'attente et de mesure (sous-lot V12, 2026-08-23)

### NE JAMAIS combiner la verification d'un rejeu et son lancement

Troisieme fois que ce piege coute quelque chose (2026-08-23). `pgrep -cf "[r]ejouer-lot"`
place dans la MEME commande qu'un `setsid ./scripts/rejouer-lot.sh` rend **1** sur une machine
au repos : la ligne de commande du shell contient le chemin en clair, et la classe de
caracteres n'y change rien. On croit alors avoir lance un second rejeu concurrent — ou, pire,
on croit qu'aucun ne tourne alors qu'un tourne.

**Deux appels distincts, toujours.** Et pour compter ce qui vit vraiment :
`ps -eo pid,etime,cmd | grep "rejouer-lot.sh" | grep -v grep` — un rejeu = **deux** lignes
(le `timeout` et le `bash`), pas une.

### `pgrep -f` s'attrape lui-meme

`until ! pgrep -f "rejouer-lot.sh --legacy"; do sleep 5; done` ne finit **jamais** :
le motif apparait dans la ligne de commande du shell qui execute la boucle. Deux
attentes de plus de 400 s ont ete perdues ainsi, alors que le rejeu etait fini
depuis dix minutes. Ecrire `pgrep -f "[r]ejouer-lot.sh --legacy"` — la classe de
caracteres ne se reconnait pas elle-meme.

### Un `&` detache le travail du conteneur de tache

`nohup ... &` lance en arriere-plan **dans** un outil deja en arriere-plan fait
sortir le wrapper immediatement : la tache se declare « terminee, code 0 » alors
que le rejeu commence a peine. Utiliser `setsid ... < /dev/null &` puis attendre
explicitement la disparition du processus, et **ne jamais conclure d'un code de
sortie** qu'un rejeu est fini — lire le journal.

### Le legacy n'ecrit pas ou l'on croit

`appendDeployLog` cree une fenetre par serveur dans **`#deploy-logs-container`** ;
`#deploy-logs` reste vide. Une suite qui lit le mauvais conteneur mesure une
chaine vide et **accuse le legacy de ne rien conclure** alors qu'il conclut
ailleurs. Lire la fonction d'affichage avant de choisir le selecteur.

### Tester la visibilite du CONTENEUR, pas du descendant

Un `<ul>` sans attribut `hidden` place dans un panneau `hidden` est « non
cache »... et invisible. Filtrer sur `! u.hidden` faisait passer une assertion
alors que le bouton etait desactive et que le panneau n'avait jamais paru.
Mesurer `offsetParent !== null` sur le PANNEAU, et faire de son ouverture une
assertion a part entiere.

### Une forme de retour CONSTANTE

`page.evaluate` qui rend `{porte: false}` dans un cas et
`{porte, ouvert, items}` dans l'autre fait lever `items.length` **deux
assertions plus loin**, la ou l'erreur est illisible. Rendre toujours les memes
cles, avec des valeurs neutres.

### Compter les requetes plutot que regarder le DOM

« Ouvrir ce panneau n'envoie rien » se mesure au RESEAU :
`page.on('request', r => { if (/\/deploy(\?|$)/.test(r.url())) n += 1; })`. C'est
ce qui permet d'ouvrir le panneau sur la ligne d'une machine de PRODUCTION pour
lire son avertissement **sans jamais la joindre**.

## Le constat d'archivage (2026-08-23, archivage de `supervision/`)

### Une assertion « X mene a Y » par INCLUSION DE CHAINE accepte le chemin qu'on vient de supprimer

`archive.mjs` filtrait les liens du menu par `href.includes(routeportee)`. La route portee est
`/supervision`, l'ancien chemin legacy `/supervision/` : **le second contient le premier**. L'assertion
annoncait « l'entree de menu mene au portage » en affichant `/supervision/` — le 404 qu'on venait
d'installer.

Comparer des **CHEMINS** (`new URL(h).pathname === route`), jamais des sous-chaines, et **exiger un lien
ABSOLU** : un lien relatif est servi par le legacy, donc par construction il ne mene pas au portage. Meme
discipline que la comparaison par SEGMENT de la passerelle.

**Et surtout** : huit archivages avaient valide ce filtre. Aucun ne pouvait echouer — `/update/` contre
`/mises-a-jour`, `/tasks/` contre `/taches` : zero recouvrement. **N validations precedentes ne prouvent
rien si aucune ne pouvait echouer.**

### Une aide qui LEVE au lieu de rendre un verdict masque le probleme

Ce qui a revele le defaut n'est pas l'assertion mais un `TypeError: Invalid URL` leve deux lignes plus bas
par `new URL('/supervision/')`. Si l'ancien lien avait ete absolu, le PASS serait passe inapercu. `repond()`
rend desormais `0` sur un href non absolu : un verdict, pas une exception au milieu d'une suite.

### Greffer le constat EN TETE du `try`

Avant toute fixture. Le bloc archive appelle `process.exit()`, qui **ne joue pas le `finally`** : place
plus bas, il laisserait derriere lui la fixture posee (fichier distant, ligne en base, paquet installe).
Place en tete, il n'y a rien a defaire.

### La reference legacy CHANGE, et se mesure

Une suite archivee ne rend plus ses assertions de caracterisation mais celles du constat :
`1 (404 du repertoire) + N (fichiers sondes) + 2 (le lien du menu, et le fait qu'il aboutisse)`. Mesurer,
puis inscrire. Sonder les fichiers **REELS** du module : un chemin qui n'a jamais existe rend 404 et fait
passer l'assertion pour rien.

### Aucune session pendant un rejeu — captures comprises

Le garde anti-rejeu TOTP est **par compte et EN BASE** : il traverse les contextes de navigateur ET les
executions. Prendre des captures pendant un LOT rend une suite instable. Attendre la fin.

## Lire le bon element, cliquer le bon bouton (sous-lot A2, 2026-08-23)

Trois defauts dans une seule suite, et **les trois etaient des PASS pour une mauvaise
raison** — la forme la plus couteuse, parce qu'un vert ne se relit pas.

### Ne JAMAIS ancrer la soumission sur « le premier bouton submit »

`legacy/profile.php` porte **CINQ** formulaires, et le premier bouton `submit` de la page
appartient a celui du **COURRIEL**. Six assertions de refus soumettaient donc le mauvais
formulaire : elles passaient parce que le message lu (« 0 ») ne ressemblait pas a un succes,
sans jamais rien mesurer. La regle etait deja ecrite dans `rw-laravel` — la voici ici aussi,
avec son cout.

**Remonter du CHAMP a son formulaire** :

```js
const bouton = await page.evaluateHandle(() => {
    const champ = document.querySelector('input[name="new_password"]');
    const form = champ ? champ.closest('form') : null;
    return form ? form.querySelector('button[type="submit"]') : null;
});
```

### Un message se lit dans SON porte-messages

`[class*="text-red"]` attrapait un compteur valant « 0 » cote legacy. Puis, cote portage, le
**bandeau d'exigence** — qui porte la meme classe `.rw-erreur` et vient AVANT dans le DOM. Un
selecteur par classe attrape le premier venu, pas le bon.

Donner au porte-messages du formulaire son `data-rw`, et le viser en priorite :
`[data-rw="profil-mdp-message"]`, avec le bloc du legacy en repli.

### Une garde du NAVIGATEUR deplace le refus, elle ne le supprime pas

Le portage pose `minlength` : le navigateur refuse d'emettre la requete, donc **aucun message
serveur n'apparait**. Une assertion qui exigeait un message faisait echouer une garde agissant
plus tot. **Mesurer la PROPRIETE** — « pas accepte, etat inchange » — et prouver la
revalidation SERVEUR par une **requete forgee** depuis la page : `minlength` est une commodite
qu'un attaquant ne respecte pas. C'est un cas ou les deux cibles refusent **differemment** et
ou les deux ont raison : ca se declare dans PARITE, ca ne se force pas.

### `DELETE ... JOIN` n'accepte ni `ORDER BY` ni `LIMIT`

MySQL refuse. Et l'exception partait **dans le `finally`** : la suite rendait « 0 PASS /
0 FAIL » sans dire si la restauration du compte avait abouti — treize suites en dependaient.

Deux regles : **borner un nettoyage par un DELTA** (`id > borneRelevee_a_l_entree`), et
**isoler chaque etape** du `finally` dans son propre `try`, en transformant l'echec en FAIL
lisible plutot qu'en exception qui emporte tout.
