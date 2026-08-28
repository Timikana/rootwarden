# DOSSIER 07 — Recréer le conteneur `rootwarden_laravel`

**Pour signature de l'exploitant.** Préparé par la session 8 le **2026-08-28**.
C'est le plus petit dossier de la série, et il est **indépendant du `DOSSIER-01`** : deux conteneurs,
deux gestes, aucune dépendance entre eux.

---

## 1. Recommandation

**Recréer.** Le geste est `docker compose up -d laravel`, il ne touche ni la base, ni le backend, ni le
legacy, et il ne met en service **aucun code non observé** — le portage est relu à **chaque requête**,
donc tout ce qu'il contient est déjà en service.

**Ce que la recréation change, et c'est tout** : un montage en lecture seule apparaît.

---

## 2. Conséquence, mesurée

### L'état, mesuré

    docker inspect rootwarden_laravel
      montages   ./laravel -> /var/www/html (rw)        <- UN SEUL
      StartedAt  2026-08-20T10:09:31Z

    docker-compose.yml:76
      - ./legacy/version.txt:/var/www/html/version.txt:ro   <- ajoute le 2026-08-27 (0b5ccc7)

    depuis le conteneur : test -f /var/www/html/version.txt  ->  ABSENT

**Le conteneur a démarré le 2026-08-20 ; la ligne a été écrite le 2026-08-27.** Le montage est donc
**inerte**, et cela se mesure par trois voies concordantes : la liste des montages, l'absence du fichier
vue **depuis le conteneur**, et l'antériorité du `StartedAt` sur le commit.

> **Une ligne de `volumes` n'est pas prise par un `docker restart` — il faut RECRÉER.** C'est le
> cinquième régime de lecture du chantier, et il ne se déduit d'aucun des quatre autres.

### Ce que la recréation apporte

**Le portage n'affiche aucun numéro de version** — zéro lecteur de `version.txt` dans `laravel/`. **Le
jour où le legacy s'éteint, c'est-à-dire l'objectif 2.0 que l'exploitant vient de réaffirmer, la version
disparaît de l'interface.** Le montage est la pièce qui l'empêche.

**Et la forme retenue est la seule sans dérive** : le fichier est monté **en lecture seule**, source
unique. Les deux autres issues — une variable d'environnement, une copie au démarrage — feraient exister
le numéro **à deux endroits**. *Ajouter une seconde copie d'un chiffre qui vient de diverger deux fois
dans la même journée, c'est traiter le symptôme en aggravant la cause.*

### Ce que la recréation ne risque pas, dit aussi nettement

| | |
|---|---|
| du code non observé mis en service ? | **non.** `laravel/**` est relu à **chaque requête** — ce qui est dans l'arbre est déjà servi |
| une perte d'état ? | **non.** Le seul montage est le code lui-même ; les sessions du portage vivent dans `laravel/storage/`, à l'intérieur de ce montage |
| un effet sur la base, le backend, le legacy ? | **aucun** — un seul service est recréé |
| une mesure en cours cassée ? | **oui, si un rejeu tourne.** Le portage est une cible du LOT |

**Le repli est correct par construction** : avant la recréation, l'écran affiche « version inconnue » —
*c'est le comportement juste du repli, pas un repli en échec.*

---

## 3. Le geste exact

```bash
cd /home/utilisateur/Documents/Gestion_SSH_KEY

# 1. le banc doit etre libre — le portage est une cible du LOT.
#    Cela se DEMANDE a la session 7, jamais ne se deduit d un `ps`.

# 2. le geste — `up -d`, PAS `restart` : un restart ne relit pas les `volumes`
sudo -n docker compose up -d laravel

# 3. controle, DEPUIS LE CONTENEUR — une verification lancee du mauvais cote
#    d un montage rend « tout va bien »
sudo -n docker exec rootwarden_laravel sh -c 'cat /var/www/html/version.txt'
sudo -n docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' rootwarden_laravel
```

**Le point 3 n'est pas une formalité.** Le contrôle de couverture de `LiensLegacy` a rendu *« aucune
partie manquante »* en énumérant depuis le conteneur Laravel, **qui ne monte pas `legacy/`** : la boucle
n'a jamais tourné, et la propriété universelle était vraie sur l'ensemble vide. **Ici on LIT une valeur,
donc l'échec serait bruyant** — mais le contrôle doit quand même se faire du côté qui voit le chemin.

---

## 4. Ce qui se passe si on ne fait rien

**Aujourd'hui : le portage n'affiche pas de version.** Gênant, pas grave — le legacy l'affiche encore, et
c'est lui qui sert la majorité des pages.

**Le jour où le legacy s'éteint — l'objectif que l'exploitant vient de réaffirmer** :

> **Le numéro de version disparaît de l'interface, et rien ne le signale.** Ce n'est pas un écran cassé :
> c'est un écran qui cesse de dire quelque chose qu'il disait, et l'extinction du legacy est précisément
> le moment où l'on aura le plus besoin de savoir quelle version tourne.

**Et une conséquence de calendrier** : l'archivage des huit dernières entrées de menu se fait module par
module. **Il n'y aura pas de jour où « le legacy s'éteint » — il y aura un dernier `git mv`**, et si la
recréation n'a pas eu lieu avant, la version disparaîtra ce jour-là sans que personne n'ait fait le lien.
*Une dépendance qui se rompt à une date qu'on ne fixe pas se diagnostique mal.*

**Il n'y a aucun autre effet de l'inaction** : le montage ne protège rien, ne garde rien, n'écrit rien.
C'est le dossier le moins urgent des huit, et le moins cher — **c'est pour cela qu'il vaut d'être signé
avec le `DOSSIER-01`, quand une fenêtre est déjà ouverte.**

---

## Ce qui n'est pas mesuré

- **le comportement de la page une fois le fichier monté.** Aucun lecteur de `version.txt` n'existe
  aujourd'hui dans `laravel/` : le montage rend la **donnée** disponible, il ne pose pas l'**affichage**.
  Celui-ci reste à écrire (session 3) ;
- **si d'autres lignes de `docker-compose.yml` sont inertes** pour la même raison. Un seul montage a été
  comparé ; les `ports` et `env_file` du service n'ont pas été confrontés au conteneur en cours.
