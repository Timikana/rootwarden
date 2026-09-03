#!/usr/bin/env bash
#
# installer-sur-vm.sh — la moitie DISTANTE de la migration.
#
# S'execute SUR la VM Debian, alimente par `migrer-vers-vm.sh` :
#
#     ssh ... bash -s < scripts/installer-sur-vm.sh
#
# POURQUOI UN FICHIER A PART. La premiere version embarquait ce bloc dans un
# heredoc, lui-meme dans une chaine passee a `eval`. Trois couches de citation
# superposees : les `$` du bloc distant sont arrives litteralement, et
# `apt-get` a recu la chaine « $besoin » comme nom de paquet. Un fichier
# separe n'a AUCUNE couche d'echappement — c'est du bash ordinaire.
#
set -euo pipefail

CIBLE="${CIBLE:-/root/Gestion_SSH_KEY}"
ATELIER="${ATELIER:-/tmp/rw-migration}"

titre() { printf '\n-- %s\n' "$*"; }

# ── Ce qui manque, s'il manque quelque chose ────────────────────────────────
titre "paquets"
manquants=""
for p in git curl ca-certificates rsync; do
    dpkg -s "$p" >/dev/null 2>&1 || manquants="$manquants $p"
done
if [ -n "$manquants" ]; then
    echo "   installation de :$manquants"
    apt-get update -qq
    # shellcheck disable=SC2086
    apt-get install -y -qq $manquants
else
    echo "   rien a installer"
fi

titre "docker"
docker --version
docker compose version

# ── Le depot, depuis le bundle ──────────────────────────────────────────────
#
# Le bundle porte TOUTES les branches et etiquettes. Il est utilise plutot
# qu'un `git clone` depuis GitHub parce que les commits de `Migration-Laravel`
# ne sont PAS pousses : le depot distant ne les connait pas.
titre "depot"
if [ -d "$CIBLE/.git" ]; then
    echo "   $CIBLE existe deja — recuperation sans ecraser"
    git -C "$CIBLE" fetch "$ATELIER/rootwarden.bundle" '*:refs/remotes/bundle/*'
else
    git clone "$ATELIER/rootwarden.bundle" "$CIBLE"
    git -C "$CIBLE" remote remove origin 2>/dev/null || true
    git -C "$CIBLE" remote add origin https://github.com/Timikana/rootwarden.git
    git -C "$CIBLE" checkout Migration-Laravel
fi
git -C "$CIBLE" log --oneline -3
git -C "$CIBLE" status --short | head -5

# ── Les secrets ─────────────────────────────────────────────────────────────
titre "secrets"
cp "$ATELIER/srv-docker.env" "$CIBLE/srv-docker.env"
chmod 600 "$CIBLE/srv-docker.env"
echo "   srv-docker.env pose en 600"

MDP_ROOT=$(grep -m1 '^MYSQL_ROOT_PASSWORD=' "$CIBLE/srv-docker.env" | cut -d= -f2-)

# ── La memoire du projet ────────────────────────────────────────────────────
#
# Le dossier de projet de Claude Code est derive du CHEMIN du depot. Il est
# calcule ici plutot que code en dur : si `CIBLE` change, le nom suit.
titre "memoire du projet"
if [ -d "$ATELIER/memory" ]; then
    encode=$(echo "$CIBLE" | sed 's|[/_.]|-|g')
    dest="$HOME/.claude/projects/$encode/memory"
    mkdir -p "$dest"
    cp -r "$ATELIER/memory/." "$dest/"
    echo "   $(ls "$dest" | wc -l) fichiers dans $dest"
else
    echo "   aucune memoire a poser"
fi

# ── La pile ─────────────────────────────────────────────────────────────────
#
# Quatre services se CONSTRUISENT (php, laravel, python, mock, test-server) :
# la premiere montee est longue. `db` demarre seul d'abord, pour restaurer la
# base avant que le backend ne s'y connecte.
titre "base de donnees"
cd "$CIBLE"
docker compose --env-file srv-docker.env up -d db

# ATTENDRE UNE REQUETE AUTHENTIFIEE, PAS UN PING.
#
# Mesure payee ici meme : `mysqladmin ping` reussit des que le serveur repond,
# y compris pendant la phase d'initialisation ou l'entrypoint fait tourner un
# serveur temporaire — le mot de passe root n'est applique qu'apres. L'attente
# rendait donc « base prete » et la restauration suivante echouait sur
# « Access denied ». Une requete qui S'AUTHENTIFIE mesure ce qu'on attend.
echo "   attente de la base (requete authentifiee)..."
pret=0
for _ in $(seq 1 90); do
    if docker exec rootwarden_db mysql -uroot -p"$MDP_ROOT" -N -e 'SELECT 1' >/dev/null 2>&1; then
        pret=1
        break
    fi
    sleep 2
done
[ "$pret" = "1" ] || { echo "   la base n'a pas accepte le mot de passe en 180 s"; exit 1; }
echo "   base prete, identifiants acceptes"

titre "restauration"
docker exec -i rootwarden_db mysql -uroot -p"$MDP_ROOT" < "$ATELIER/rootwarden.sql"
lignes=$(docker exec rootwarden_db mysql -uroot -p"$MDP_ROOT" -N -e \
    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='rootwarden';" 2>/dev/null)
echo "   $lignes tables restaurees"

titre "construction et demarrage du reste (long a la premiere montee)"
docker compose --env-file srv-docker.env up -d --build

echo "   attente des conteneurs..."
sleep 15
docker ps --format '{{.Names}}\t{{.Status}}' | sort

titre "les deux portails repondent-ils ?"
curl -s  -o /dev/null -w "   laravel http=%{http_code}\n" http://localhost:8444/connexion || true
curl -sk -o /dev/null -w "   legacy  http=%{http_code}\n" https://localhost:8443/auth/login.php || true

titre "termine"
