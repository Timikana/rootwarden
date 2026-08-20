---
name: rw-lot
description: Rejouer le LOT de tests E2E de la migration RootWarden - les six prealables sans lesquels rien ne marche, le lanceur scripts/rejouer-lot.sh, les chiffres de reference, et comment lire un echec. A charger AVANT de lancer une suite E2E ou d'interpreter un resultat.
---

# Rejouer le LOT

Le LOT est l'ensemble des suites de caractérisation qui doivent rester vertes à
chaque sous-lot porté. **Toucher au gabarit casse une suite antérieure** : on le
rejoue en entier, pas seulement la suite du jour.

```bash
./scripts/rejouer-lot.sh                    # tout, les deux versants
./scripts/rejouer-lot.sh --laravel          # le portage seul
./scripts/rejouer-lot.sh --legacy go-page-conformite
```

Le script porte les six préalables, compare à la référence, et dit `conforme`,
`ECART attendu=N` ou `ECHEC`. **Ne pas relancer `node go-*.mjs` à la main** :
c'est ainsi qu'on repaie les préalables un par un.

## Les six préalables, et ce que chacun a coûté

Chacun a coûté au moins une séance de diagnostic. Ils sont dans le script, mais
il faut savoir qu'ils existent pour comprendre un échec.

1. **Le compte de développement n'est pas forcément dans le groupe `docker`.**
   Le script passe par `sudo -n docker`. **Ne pas ajouter le compte au groupe**
   pour contourner : l'appartenance vaut un accès root permanent.
2. **Le banc d'essai vit derrière le profil compose `preprod`.** `test-server`
   (machine 2) et `mock-opencve` ne démarrent qu'avec `--profile preprod`. Un
   `docker compose up -d` nu les laisse à terre, et les sous-lots qui les
   utilisent rendent « Erreur interne » ou meurent **dans leur propre nettoyage**,
   avant la première assertion.
3. **`E2E_BASE` doit être posée DANS LES DEUX SENS.** Les suites n'ont pas le même
   défaut : `go-socle-auth` vise le **legacy**, les pages visent **Laravel**.
   Effacer la variable ne désigne aucune cible — et donne 13 PASS au lieu de 14
   sans un seul FAIL.
4. **`login_attempts` doit être vide AVANT CHAQUE SUITE.** Le second facteur a un
   compteur **par IP** en base (seuil 10 sur 10 min). Enchaîner les suites le fait
   déborder tout seul.
5. **Il faut attendre le basculement de la fenêtre TOTP entre deux suites.** Le
   garde anti-rejeu est **par compte et en base** : il traverse les suites.
6. **`go-vague0-legacy` vise `superadmin`**, dont le mot de passe en base n'est pas
   celui qu'attend la suite et dont `force_password_change` vaut 1. Le script le
   joue avec `rw-test-super`.

## L'exécution parallèle est impossible, et ce n'est pas une question de mémoire

C'est le préalable 5. Deux suites concurrentes utilisant le même compte se
sabotent **en silence**. Augmenter la RAM ne change rien à cela — il faudrait des
comptes dédiés par suite, qui n'existent pas.

## Comment lire un échec — trois signatures qui ont déjà trompé

### « refusée » qui échoue sur un **200**, sans aucun compte verrouillé

C'est le préalable 4 ou 5. La connexion de la suite a échoué, donc chaque appel
atterrit sur `/connexion`, qui rend **200 en HTML**. Chercher un compte bloqué ne
mène nulle part : **regarder le CORPS de la réponse.** Une page HTML là où on
attend du JSON dit que la session n'a pas tenu.

`go-socle-passerelle` et `go-page-update-u3` ont été déclarées « flaky » pour
cette seule raison. Elles ne l'étaient pas.

### « 0 PASS » avec un code de sortie non nul

La suite est **morte avant d'imprimer son tampon** — typiquement une `TypeError`
sur un élément absent, vingt lignes après l'assertion qui l'avait détecté. Le
« 0 PASS » ne veut pas dire qu'elle n'a rien mesuré : il veut dire qu'elle n'a
rien **dit**. Lire le journal, chercher la trace de pile.

Quand on écrit une suite : **sortir par le chemin normal** en imprimant le
tampon, plutôt que de laisser mourir.

### Un écart de +1 ou −1 PASS sans aucun FAIL

Souvent une **assertion conditionnelle** : `go-page-backups` rend 17 sur une base
sans sauvegarde et 16 ensuite, parce qu'une assertion ne vaut que pour l'état
vide — et parce que la suite **ne nettoie pas ce qu'elle pose**. Un écart n'est
pas forcément une régression, mais il doit toujours être **expliqué**.

## Mettre la référence à jour

Les chiffres vivent dans `scripts/rejouer-lot.sh`, tableaux `REF_LARAVEL` et
`REF_LEGACY`. **Un sous-lot qui ajoute une assertion met la référence à jour dans
le même commit**, et le CHANGELOG dit laquelle et pourquoi. Une référence périmée
transforme chaque rejeu en enquête.

## Ce qu'il ne faut pas faire

- **Ne pas écrire en dur une adresse de déploiement dans une suite.** Payé deux
  fois : `go-socle-navigation` et `go-page-search` comparaient à
  `https://localhost:8443`, et trois assertions sont tombées dès que `LEGACY_URL`
  a pointé ailleurs. Lire `app.url_legacy` à la même source que la page.
- **Ne pas prendre une partie ARCHIVÉE comme page témoin d'un refus.** Elle rend
  404, et une assertion « pas 200 » passe alors sans rien mesurer. Exiger le code
  **exact**, et vérifier que le témoin est encore servi.
- **Ne pas se reconnecter avec le même compte** dans la même fenêtre TOTP :
  conserver la session ouverte.
