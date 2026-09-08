#!/usr/bin/env bash
#
# ÉTEINDRE LE LEGACY — la séquence du DOSSIER-48, armée de ses propres refus.
#
# ══ CE SCRIPT NE FAIT RIEN PAR DÉFAUT ════════════════════════════════════════
#
# À sec sans argument. Il faut `--executer` pour qu'un seul `git mv` ait lieu, et
# un drapeau inconnu est une ERREUR — pas un silence.
#
#   *Un `--dry-run` inconnu est ignoré en silence : c'est ainsi qu'on écrit dans
#   un socle pendant son propre gel. Ici le défaut est à sec et l'inconnu refuse.*
#
# ══ POURQUOI UN SCRIPT ET PAS UNE LISTE DE COMMANDES ════════════════════════
#
# `./legacy` est monté en direct — `docker-compose.yml:25 ./legacy:/var/www/html`.
# **Un `git mv` prend effet sur le portail SERVI, sans redémarrage.** Vérifié : le
# conteneur voit le fichier de l'hôte, même taille, même mtime.
#
# Donc chaque étape est un geste d'exploitation, et les contrôles doivent tenir
# AVANT, pas après. Une liste de commandes dans un document ne porte pas ses
# refus ; celui-ci les porte.
#
# ⛔ L'ÉTAPE ⓪ DU DOSSIER-48 — le verrou — N'EST PAS ICI. Elle appartient à
#    l'exploitant, et ce script ne la simule pas.
#
# Usage :
#   ./scripts/eteindre-le-legacy.sh              # a sec, tout, avec les controles
#   ./scripts/eteindre-le-legacy.sh --etape 2    # a sec, une seule etape
#   ./scripts/eteindre-le-legacy.sh --etape 2 --executer
#
# Sortie : 0 tout va bien · 1 un controle refuse · 2 l'instrument n'a pas mesure
set -u -o pipefail
cd "$(dirname "$0")/.." || exit 2

EXECUTER=0
ETAPE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --executer) EXECUTER=1 ;;
        --etape)    shift; ETAPE="${1:-}" ;;
        *) printf '⛔ drapeau inconnu : %s\n   Un drapeau inconnu est une ERREUR, pas un silence.\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

# ── LES ÉTAPES, DÉCLARÉES ────────────────────────────────────────────────────
# Chaque entrée : numéro | chemin(s) | ce que la mesure a établi
etapes() {
    cat <<'ETAPES'
2|legacy/iptables|les cinq gestes sont portes (validate/apply/rollback + lecture)
3|legacy/adm/api/notifications.php|7 routes cote portage, dont Route::delete('supprimer')
4|legacy/api_proxy.php|le portage a sa passerelle : /api/gateway/{chemin?}
5|legacy/auth legacy/lang|la chaine d'auth est portee ; les 74 catalogues meurent avec leurs 2 chargeurs
6|legacy/_sortie.php|l'ErrorDocument du vhost — EN DERNIER, avec le vhost
ETAPES
}

ko=0
dire() { printf '%s\n' "$*"; }

# ══ CONTRÔLE 1 — LE FICHIER QUE LE PORTAGE MONTE DEPUIS LE LEGACY ═══════════
#
# `docker-compose.yml:123` monte `./legacy/version.txt` en lecture seule DANS le
# portage. Son docblock (`laravel/app/Support/Version.php`) dit que la source
# unique est deliberee — le numero avait derive deux fois en une journee.
#
# `Version::numero()` rend `null` si le fichier manque : la page affiche
# « version inconnue ». **Ce n'est pas une panne, c'est une perte SILENCIEUSE** —
# donc exactement le genre de defaut qu'un script d'extinction doit refuser.
dire "══ contrôle 1 — le fichier monté dans le portage ══"
if grep -qE '^\s+- \./legacy/version\.txt:' docker-compose.yml; then
    dire "  ./legacy/version.txt est monté dans le portage (compose)"
    for p in $(etapes | cut -d'|' -f2); do
        if git ls-files "$p" | grep -qx 'legacy/version.txt'; then
            dire "  ⛔ version.txt tombe dans la portée de « $p » — REFUS"
            dire "     le déplacer HORS de legacy/ et corriger le montage d'abord"
            ko=$((ko+1))
        fi
    done
    dire "  ✅ aucune étape ne l'emporte"
else
    dire "  ⚠ le montage n'est plus déclaré — vérifier ce qui a changé avant de continuer"
    ko=$((ko+1))
fi

# ══ CONTRÔLE 2 — LES SEPT ÉPREUVES SANS NAVIGATEUR ══════════════════════════
dire ""
dire "══ contrôle 2 — les sept épreuves sans navigateur ══"
for s in tests/e2e/jetons-interdits.mjs tests/e2e/liens-morts-legacy.mjs tests/e2e/archive.mjs \
         laravel/tests/Outils/q1-gabarits.mjs laravel/tests/Outils/q2-ssh-ouvert.mjs \
         laravel/tests/Outils/q3-retour-visible.mjs laravel/tests/Outils/ports-des-deux-portails.mjs; do
    if [ ! -f "$s" ]; then dire "  ⛔ ABSENTE : $s — ne rien conclure"; ko=$((ko+1)); continue; fi
    if node "$s" >/dev/null 2>&1; then dire "  ✅ $(basename "$s")"
    else dire "  ⛔ $(basename "$s") ÉCHOUE"; ko=$((ko+1)); fi
done

# ══ CONTRÔLE 3 — L'ARBRE EST-IL À QUELQU'UN D'AUTRE ? ═══════════════════════
#
# Sept sessions commitent sur cette branche. Un `git mv` par-dessus le travail en
# cours d'une autre session le rendrait indissociable du mien.
dire ""
dire "══ contrôle 3 — l'arbre ══"
sales=$(git status --porcelain | wc -l)
if [ "$sales" -eq 0 ]; then dire "  ✅ arbre propre"
else dire "  ⛔ $sales fichier(s) en cours — une autre session écrit. REFUS"; git status --porcelain | sed 's/^/     /'; ko=$((ko+1)); fi

# ══ CONTRÔLE 4 — LE BANC ════════════════════════════════════════════════════
#
# `ps` a rendu 3 puis 0 en quelques secondes, trois fois : à ce grain c'est un
# signal de bruit. Le signal qui tient est l'ÉCRITURE de captures, avec son
# témoin — « 0 sans témoin » ne distingue pas « rien ne tourne » de « je ne
# mesure rien ».
dire ""
dire "══ contrôle 4 — le banc ══"
if [ -d tests/e2e/screenshots ]; then
    recent=$(find tests/e2e/screenshots -newermt "$(date -d '-3 minutes' '+%Y-%m-%d %H:%M:%S')" -type f 2>/dev/null | wc -l)
    temoin=$(find tests/e2e/screenshots -newermt "$(date -d '-30 days' '+%Y-%m-%d %H:%M:%S')" -type f 2>/dev/null | wc -l)
    if [ "$temoin" -eq 0 ]; then dire "  ⛔ TÉMOIN MUET — 0 capture sur 30 jours : la sonde ne mesure rien"; ko=$((ko+1))
    elif [ "$recent" -gt 0 ]; then dire "  ⛔ $recent capture(s) écrite(s) en 3 min — une suite tourne. REFUS"; ko=$((ko+1))
    else dire "  ✅ aucune capture en 3 min (témoin : $temoin sur 30 jours)"; fi
else
    dire "  ⚠ tests/e2e/screenshots absent — le signal de banc n'existe pas ici"; ko=$((ko+1))
fi

# ══ VERDICT DES CONTRÔLES ═══════════════════════════════════════════════════
dire ""
if [ "$ko" -gt 0 ]; then
    dire "⛔ $ko contrôle(s) refusent. AUCUN geste, même avec --executer."
    exit 1
fi
dire "✅ les quatre contrôles passent."

# ══ LA SÉQUENCE ═════════════════════════════════════════════════════════════
#
# ⚠ L'ORDRE N'EST PAS INDIFFÉRENT. `_sortie.php` est l'ErrorDocument du vhost :
# le retirer avant les autres ferait rendre l'erreur d'Apache par défaut à la
# place d'une page qui explique. Il part EN DERNIER, avec le vhost.
dire ""
dire "══ la séquence ══"
[ "$EXECUTER" -eq 1 ] && dire "  ⚠ MODE EXÉCUTION" || dire "  À SEC — rien ne sera déplacé"
dire ""

mkdir -p legacy/_deprecated 2>/dev/null

while IFS='|' read -r num chemins raison; do
    [ -n "${ETAPE:-}" ] && [ "$ETAPE" != "$num" ] && continue
    n=0
    for p in $chemins; do n=$((n + $(git ls-files "$p" | wc -l))); done
    dire "  étape $num — $n fichier(s) suivis"
    dire "     $raison"
    if [ "$n" -eq 0 ]; then dire "     ✅ déjà archivée"; continue; fi
    for f in $(for p in $chemins; do git ls-files "$p"; done); do
        # ══ L'UNITÉ EST LE FICHIER, PAS LE RÉPERTOIRE ═══════════════════════
        #
        # Deux jets faux avant celui-ci, et le second se croyait « par
        # construction » :
        #
        #   1  `_deprecated/$(basename "$p")`  ->  DEUX destinations sur six deja
        #      occupees, et l'a-sec restait VERT : il annoncait sans verifier.
        #   2  `_deprecated/${p#legacy/}` sur le REPERTOIRE  ->  `legacy/auth`
        #      donne `_deprecated/auth`, qui existe DEJA avec 5 fichiers. J'avais
        #      ecrit « la collision devient inexprimable » : faux — la derivation
        #      n'evite que les collisions entre sources DIFFERENTES, pas celle
        #      d'une source avec l'archive PARTIELLE du meme chemin.
        #
        # Mesure : `_deprecated/auth` porte 5 fichiers (2FA, step-up), `legacy/auth`
        # en porte 10 AUTRES. **Aucune collision par fichier** — donc la fusion est
        # propre du moment que l'unite deplacee est le FICHIER.
        #
        # > Un archivage par REPERTOIRE echoue des qu'une partie du repertoire est
        # > deja archivee ; par FICHIER, il fusionne.
        dest="legacy/_deprecated/${f#legacy/}"
        if [ -e "$dest" ]; then
            dire "     ⛔ DESTINATION OCCUPÉE : $dest — REFUS"
            dire "        deux versions du même fichier : c'est une décision, pas un déplacement"
            exit 1
        fi
        if [ "$EXECUTER" -eq 1 ]; then
            mkdir -p "$(dirname "$dest")"
            if git mv "$f" "$dest" 2>/dev/null; then dire "     ✅ $f -> $dest"
            else dire "     ⛔ git mv $f a ÉCHOUÉ"; exit 1; fi
        else
            dire "     [à sec] $f -> $dest"
        fi
    done
done < <(etapes)

dire ""
if [ "$EXECUTER" -eq 1 ]; then
    dire "⚠ DÉPLACÉ, PAS COMMITÉ. Relire, puis committer PAR CHEMINS — jamais par l'index,"
    dire "  qui est partagé entre sept sessions."
    dire "  Réversible : legacy/_deprecated/ est déjà refusé par RedirectMatch 404."
else
    dire "Rien n'a été déplacé. Ajouter --executer, une fois le verrou de l'exploitant donné."
fi
