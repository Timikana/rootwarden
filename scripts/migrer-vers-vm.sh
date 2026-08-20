#!/usr/bin/env bash
#
# migrer-vers-vm.sh — bascule l'environnement de developpement RootWarden
#                     depuis le poste Windows vers une VM Debian.
#
# A LANCER DEPUIS GIT BASH, sur le poste Windows, a la racine du depot.
#
#   ./scripts/migrer-vers-vm.sh --dry-run    # montre tout, n'execute rien
#   ./scripts/migrer-vers-vm.sh              # execute
#
# CE QUI EST MIGRE
#   1. le depot, par `git bundle` — les 32 commits de `Migration-Laravel` ne
#      sont PAS pousses sur origin, un `git clone` depuis GitHub les perdrait ;
#   2. `srv-docker.env` — jamais commite, il porte TOUS les secrets ;
#   3. la base, par `mysqldump` ;
#   4. la memoire du projet (`~/.claude/.../memory/`) — des fichiers Markdown,
#      sans secret.
#
# CE QUI N'EST PAS MIGRE, DELIBEREMENT
#   - les transcriptions de conversation (~140 Mo) : elles contiennent en clair
#     les mots de passe des comptes de test, leurs secrets TOTP, et ceux du
#     compte superadmin. Les copier les diffuse. Si tu y tiens, fais-le a la
#     main et chiffre le transfert ;
#   - `tests/e2e/screenshots/` et `node_modules/` : regenerables.
#
# APRES LA BASCULE
#   - renouvelle les secrets des comptes de test si les transcriptions ont
#     circule ;
#   - la VM a ete mesuree a 3,8 Gio de RAM : c'est SOUS le plancher. Les
#     conteneurs declarent 2,9 Gio de plafonds et une suite E2E coute 525 Mio.
#     Passe la VM a 8 Gio avant de lancer le lot, sinon tu partiras en swap.
#
set -euo pipefail

# ── Reglages ────────────────────────────────────────────────────────────────
VM_HOTE="${VM_HOTE:-192.168.0.245}"
VM_USER="${VM_USER:-root}"
VM_CLE="${VM_CLE:-$HOME/.ssh/claude-agent-debian}"
VM_CIBLE="${VM_CIBLE:-/root/Gestion_SSH_KEY}"

DEPOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATELIER="${TMPDIR:-/tmp}/rw-migration"
MEMOIRE_LOCALE="$HOME/.claude/projects/c--Users-timik-OneDrive-Documents-0-VisualStudioCode-Gestion-SSH-KEY/memory"


SEC=0
[ "${1:-}" = "--dry-run" ] && SEC=1

dit()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fais() {
    printf '   %s\n' "$*"
    [ "$SEC" = "1" ] && return 0
    eval "$@"
}

# ── 0. Controles prealables ─────────────────────────────────────────────────
dit "Controles prealables"

[ -f "$DEPOT/srv-docker.env" ] || { echo "srv-docker.env introuvable — lance depuis le depot"; exit 1; }
[ -f "$VM_CLE" ] || { echo "cle SSH introuvable : $VM_CLE"; exit 1; }

ssh -i "$VM_CLE" -o BatchMode=yes -o ConnectTimeout=8 "$VM_USER@$VM_HOTE" true \
    || { echo "la VM ne repond pas en SSH"; exit 1; }
echo "   VM joignable, cle acceptee"

RAM=$(ssh -i "$VM_CLE" -o BatchMode=yes "$VM_USER@$VM_HOTE" \
      "awk '/MemTotal/ {printf \"%.1f\", \$2/1048576}' /proc/meminfo")
echo "   RAM de la VM : ${RAM} Gio"
awk -v r="$RAM" 'BEGIN { if (r < 6) print "   ATTENTION : sous 6 Gio, le lot E2E partira en swap." }'

# ── 1. Empaqueter ───────────────────────────────────────────────────────────
dit "Empaquetage dans $ATELIER"

fais "mkdir -p '$ATELIER'"

# Le bundle porte TOUTES les branches et TOUTES les etiquettes : c'est le depot
# entier, historique compris, dans un seul fichier.
fais "cd '$DEPOT' && git bundle create '$ATELIER/rootwarden.bundle' --all"
fais "cd '$DEPOT' && git bundle verify '$ATELIER/rootwarden.bundle'"

fais "cp '$DEPOT/srv-docker.env' '$ATELIER/srv-docker.env'"

# La base : dump coherent, routines et evenements compris.
MDP_ROOT=$(grep -m1 '^MYSQL_ROOT_PASSWORD=' "$DEPOT/srv-docker.env" | cut -d= -f2-)
fais "docker exec rootwarden_db mysqldump -uroot -p'$MDP_ROOT' \
        --single-transaction --routines --events --databases rootwarden \
        > '$ATELIER/rootwarden.sql'"

if [ -d "$MEMOIRE_LOCALE" ]; then
    fais "cp -r '$MEMOIRE_LOCALE' '$ATELIER/memory'"
else
    echo "   memoire du projet introuvable — passe"
fi

[ "$SEC" = "1" ] || { echo; du -sh "$ATELIER"/* 2>/dev/null; }

# ── 2. Transferer ───────────────────────────────────────────────────────────
dit "Transfert vers $VM_USER@$VM_HOTE"

fais "ssh -i '$VM_CLE' '$VM_USER@$VM_HOTE' 'mkdir -p /tmp/rw-migration'"
fais "scp -i '$VM_CLE' -r '$ATELIER'/* '$VM_USER@$VM_HOTE:/tmp/rw-migration/'"

# ── 3. Installer sur la VM ──────────────────────────────────────────────────
#
# La moitie distante vit dans SON PROPRE FICHIER, alimente par l'entree
# standard de ssh. La premiere version l'embarquait dans un heredoc lui-meme
# dans une chaine passee a `eval` : trois couches de citation, et les `$` du
# bloc distant sont arrives litteralement — `apt-get` a recu « $besoin » comme
# nom de paquet. Un fichier separe n'a aucune couche d'echappement.
dit "Installation sur la VM"

fais "ssh -i '$VM_CLE' '$VM_USER@$VM_HOTE'         CIBLE='$VM_CIBLE' ATELIER=/tmp/rw-migration bash -s         < '$DEPOT/scripts/installer-sur-vm.sh'"

# ── 4. Verifier ─────────────────────────────────────────────────────────────
dit "Verification"

fais "ssh -i '$VM_CLE' '$VM_USER@$VM_HOTE' \
      'curl -s -o /dev/null -w \"laravel http=%{http_code}\\n\" http://localhost:8444/connexion; \
       curl -sk -o /dev/null -w \"legacy  http=%{http_code}\\n\" https://localhost:8443/auth/login.php'"

dit "Termine"
cat <<'FIN'
   Il reste a faire, a la main :

   1. LARAVEL_URL dans srv-docker.env pointe sur localhost — a passer sur
      l'adresse de la VM si tu ouvres les portails depuis ton poste.
   2. Les dependances des tests :  cd tests/e2e && npm ci
   3. Le lot, pour verifier la bascule :
        cd tests/e2e && node go-socle-navigation.mjs
   4. Le dossier de projet de Claude Code est derive du CHEMIN : verifie le
      nom reel apres le premier lancement, et deplace `memory/` s'il differe.
   5. Si les transcriptions ont circule : renouvelle les secrets des comptes
      de test et du compte superadmin.
FIN
