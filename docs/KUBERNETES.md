# RootWarden sur Kubernetes

RootWarden s'installe de deux façons, qui coexistent :

| | Docker Compose | Kubernetes |
|---|---|---|
| Fichiers | `docker-compose.yml`, `maj.sh` | `deploy/kubernetes/` |
| Code | monté depuis le disque | dans les images |
| Configuration | `srv-docker.env` | le même fichier, converti en Secret |
| Mise à jour | `./maj.sh --release` | nouvelles images, `helm upgrade` |

Rien de ce qui suit ne change le fonctionnement sous Docker Compose.

## Ce qui est déployé

- `db` : MySQL 9.7 (StatefulSet, un volume de 10 Gi par défaut). `mysql/init.sql` est joué au
  premier démarrage, volume vide.
- `python` : le backend (Hypercorn, 4 workers). Racine en lecture seule, comme
  `docker-compose.prod.yml`. Deux volumes conservés même après `helm uninstall` :
  `rootwarden-platform-ssh` (la paire de clés de la plateforme) et `rootwarden-backups`.
- `laravel` : le portail (Apache). HTTPS sur le port 443, avec un certificat auto-signé, un
  certificat fourni, ou derrière un Ingress qui termine le TLS.

Les Services s'appellent `db`, `python` et `laravel`, comme les services Compose :
`DB_HOST=db` et `BACKEND_INTERNAL_URL=https://python:5000` restent valables.

## Installer

Outils : `docker`, `kubectl`, `helm` (v3 ou v4), et un registre d'images joignable par le cluster.

```sh
# 1. Images (étiquette par défaut : le commit court)
REGISTRE=registry.example.com/rootwarden/ POUSSER=1 deploy/kubernetes/construire-images.sh v1.0.0

# 2. Secret et ConfigMap, depuis le fichier d'environnement de Docker Compose
deploy/kubernetes/preparer.sh /chemin/vers/srv-docker.env rootwarden

# 3. Chart
helm upgrade --install rw deploy/kubernetes/helm/rootwarden -n rootwarden \
  --set imageTag=v1.0.0 \
  --set images.laravel.repository=registry.example.com/rootwarden/rootwarden-laravel \
  --set images.python.repository=registry.example.com/rootwarden/rootwarden-python

# 4. Premier compte (installation neuve) : le mot de passe s'affiche une seule fois
kubectl -n rootwarden exec deploy/laravel -- runuser -u www-data -- php artisan rootwarden:premier-compte
```

`preparer.sh` résout les renvois du fichier (`MYSQL_DATABASE=${DB_NAME}`) comme Docker Compose,
car `kubectl` ne le fait pas. Il ajoute une `APP_KEY` : celle du fichier si elle y est, sinon celle
du Secret existant, sinon une nouvelle. Relancer le script ne change donc jamais la clé : en changer
déconnecterait tout le monde et rendrait illisible ce que Laravel a chiffré.

Adapter `APP_URL` et `LARAVEL_HTTPS_PORT` à l'adresse publique du portail (port 443 derrière un
Ingress).

## Exposer le portail

Sans Ingress : `kubectl -n rootwarden port-forward svc/laravel 8443:443`.

Avec ingress-nginx, le portail servant HTTPS :

```yaml
ingress:
  enabled: true
  className: nginx
  host: rootwarden.example.com
  tlsSecret: rootwarden-tls
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"      # flux en direct (SSE)
    nginx.ingress.kubernetes.io/proxy-read-timeout: "900"   # BACKEND_TIMEOUT_FLUX
```

`laravel.sslMode=disabled` sert le portail en HTTP. À réserver au cas où l'Ingress termine le TLS
et où le trafic interne au cluster est considéré comme sûr.

## Réseau

- Le backend ouvre des sessions SSH vers les machines du parc : ses pods doivent les joindre
  (port 22, ou le port de chaque machine). Ne pas lui imposer de règle de sortie qui le bloque.
- `networkPolicy.enabled=true` limite la base au portail et au backend, et le backend au portail,
  comme le réseau `internal` de Docker Compose.

## Plusieurs replicas

- **Backend** : le planificateur prend un verrou MySQL (`GET_LOCK`). Un seul processus exécute les
  tâches planifiées, quel que soit le nombre de workers ou de pods. Mais la paire de clés et les
  sauvegardes sont sur des volumes ReadWriteOnce : au-delà d'un replica, il faut un stockage
  ReadWriteMany.
- **Portail** : les sessions sont des fichiers dans le pod (`SESSION_DRIVER=file`). Plusieurs
  replicas demandent un pilote de session partagé (`database`, `redis`) ou l'affinité de session
  sur l'Ingress.

## Sauvegarder

- La base : le volume `donnees-db-0`, ou les dumps du backend dans `rootwarden-backups`.
- **La paire de clés de la plateforme** : le volume `rootwarden-platform-ssh`. La perdre coupe
  l'accès aux machines dont les mots de passe ont été effacés.

## Essai local (kind)

```sh
deploy/kubernetes/kind/essai-local.sh /chemin/vers/srv-docker.env
```

Crée le cluster `rootwarden` s'il n'existe pas, construit et charge les images (sans registre),
prépare l'espace de noms et installe le chart. Le fichier doit porter de vrais secrets : le script
refuse les `CHANGEZ_MOI` de l'exemple.

## Ce que la CI vérifie

Le job « Chart Helm » lance `helm lint`. Il valide aussi le rendu de trois variantes contre le
schéma Kubernetes (`kubeconform`) : défaut ; Ingress et règles réseau ; certificat fourni et deux
replicas. Il vérifie enfin la résolution du fichier d'environnement. Ce job bloque l'étiquetage
automatique.
