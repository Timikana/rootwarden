# DOSSIER-39 — le durcissement prod ne fait pas ce qu'il annonce, et `maj.sh` ne l'applique pas

**Session DSI. Mesuré le 2026-09-06 à 20:40 CEST.** Banc libre, arbre propre.
*Écrit en réponse à trois questions de l'exploitant : les scripts sont-ils sains,
`git pull && ./maj.sh` fonctionne-t-il, le durcissement est-il appliqué.*

---

## ① CE QUI EST SAIN, et je commence par là

```
113 fichiers .sh          0 erreur de syntaxe (bash -n)
  TEMOIN : un fichier volontairement casse ECHOUE bien
maj.sh · start.sh · stop.sh    executables
les deux passent --env-file    donc `srv-docker.env` gagne sur les defauts du compose
les quatre ports ecoutent      8080 · 8443 · 8444 · 8446
```

**Rien à corriger de ce côté.**

---

## ② 🔴 `git pull && ./maj.sh` NE MARCHE PAS AUJOURD'HUI

**`maj.sh` tire `main` (canal release). `origin/main` a 53 commits de retard.**

```
main      ${HTTP_PORT:-8080}  ${HTTPS_PORT:-8443}  ${LARAVEL_PORT:-8444}
          -> TROIS lignes de ports. `LARAVEL_HTTPS_PORT` n'y EXISTE PAS.

branche   ${HTTP_PORT:-8444} ${HTTPS_PORT:-8446} ${LARAVEL_PORT:-8080}
          ${LARAVEL_HTTPS_PORT:-8443}            -> QUATRE lignes
```

> **Tirer `main` et lancer `maj.sh` supprimerait la publication HTTPS du
> portail.** *Le TLS posé aujourd'hui disparaîtrait — sans panne bruyante : le
> port cesse simplement d'être publié.*

**Remède : fusionner `Migration-Laravel` dans `main` AVANT.** *C'est le geste qui
rend la phrase vraie, et il appartient à l'exploitant.*

---

## ③ 🔴 LE DURCISSEMENT PROD N'EST APPLIQUÉ PAR AUCUN SCRIPT

**`CONTRIBUTING-SECURITY.md:45` déclare la surcharge OBLIGATOIRE en prod :**

```
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

**`maj.sh` et `start.sh` ne la nomment nulle part.** *Zéro occurrence.* **Donc
« on lance `maj.sh` » et « on est en prod durcie » sont deux choses
différentes.**

### DÉCISION — oui, `maj.sh` doit l'appliquer, et voici ce qu'elle donne VRAIMENT

**La surcharge est VALIDE et APPLICABLE aujourd'hui** — vérifié sans rien
démarrer :

```
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --env-file srv-docker.env config      -> code 0, 564 lignes resolues

read_only: true                          actif
tmpfs uid=33,gid=33 sur les QUATRE chemins que l'entrypoint ecrit
storage/logs reste un MONTAGE (persiste), pas un tmpfs
chemins declares a la fois en volume ET en tmpfs :  AUCUN
```

**Ce qu'elle apporte réellement** : `read_only`, `cap_drop ALL`,
`no-new-privileges`, tmpfs bornés. *C'est du durcissement mesurable, et il n'a
aucune raison de rester inappliqué.*

---

## ④ ⚠ MAIS ELLE NE FAIT PAS CE QUE SON COMMENTAIRE ANNONCE

**`docker-compose.prod.yml` écrit, deux fois :**

> *« Retire `./laravel:/var/www/html` (utilise l'image baked), comme `php`. »*
> *« Retire `./legacy:/var/www/html` (utilise l'image baked). »*

**Aucun des deux retraits n'a lieu.** *Config RÉSOLUE, qui est ce que compose
emploierait :*

```
php       legacy  -> /var/www/html      <- l'ARBRE DE TRAVAIL, toujours monte
laravel   laravel -> /var/www/html      <- idem
```

**Pourquoi** : *Compose fusionne les listes `volumes` en les APPENDANT. Une
surcharge ne peut pas RETIRER une entrée déclarée dans la base* — il y faudrait
`!reset` (Compose Spec ≥ 2.24), non employé ici.

### Et la prémisse est fausse à la racine : il n'existe PAS d'image *baked*

```
laravel/Dockerfile   COPY composer · COPY apache-ssl.conf.tmpl · COPY entrypoint
                     AUCUN `COPY laravel/ /var/www/html`
```

**Contre-épreuve au réseau, sans rien modifier :**

```
md5 de laravel/public/css/rw.css dans l'arbre   fa4eaa64ac0895f26e6d57d0713738b3
md5 de ce que https://<hote>:8443/css/rw.css rend   fa4eaa64ac0895f26e6d57d0713738b3
-> IDENTIQUES : le portail sert l'arbre de travail
```

> **« La prod utilise l'image bakée » est faux deux fois : la surcharge ne
> retire pas le montage, et il n'y a rien de baké derrière.**

*C'est le défaut habituel de ce dépôt — un commentaire qui promet plus que le
code — trouvé cette fois DANS le fichier de durcissement.*

### Ce que ça change, concrètement

| | |
|---|---|
| un `git pull` change ce qui est SERVI | **instantanément**, sans reconstruction |
| l'immuabilité de l'image | **n'existe pas**, ni avec ni sans la surcharge |
| `read_only: true` | protège quand même : le conteneur ne peut pas écrire dans l'arbre |

---

## ⑤ CE QUI VOUS REVIENT

1. **Fusionner `Migration-Laravel` dans `main`** — sans quoi `maj.sh` retire le
   TLS du portail. *Un mot suffit, je le fais.*
2. **Faire appliquer la surcharge prod par `maj.sh` et `start.sh`** — décidé
   ici, hors de mon périmètre d'écriture. *Gain réel, sans régression mesurée.*
3. **Si l'immuabilité est voulue** — c'est un `COPY` dans les deux `Dockerfile`,
   pas un changement de compose. **C'est un chantier, pas un correctif**, et je
   ne le recommande pas avant l'extinction du legacy.

⚠ **Non mesuré** : le comportement d'un `docker compose up` réel sous la
surcharge — je n'ai validé que la configuration résolue, sans rien démarrer.
