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

## Regles d'or
- **Attendre le TOTP** : si `30 - (epoch % 30) < 6`, dormir jusqu'a la fenetre suivante.
- Preferer `page.evaluate(() => fonctionDeLaPage())` a la simulation de clics fragiles
  quand on teste la LOGIQUE (les clics restent utiles pour tester le cablage DOM).
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
