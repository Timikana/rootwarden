#!/usr/bin/env bash
# ecrire-version.sh - Pose `laravel/version.txt` avant que les conteneurs montent.
#                     (l'en-tete disait `legacy/` — corrige le 2026-09-10 ;
#                      la CIBLE reelle est `laravel/version.txt`, cf. plus bas)
#
# ⚠ CE FICHIER EXISTE PARCE QUE LA DECISION N'ETAIT CABLEE A RIEN.
#
# `DECISIONS-DSI.md:12718` decidait que les entrees futures portent le numero que
# `scripts/version.sh --ecrire` produit. Mesure du 2026-09-07 : **`--ecrire`
# n'avait AUCUN appelant** — ni `start.sh`, ni `maj.sh`, ni l'entrypoint, ni la
# CI. Les deux portails affichaient donc `2.0.11` quand la regle rendait
# `2.0.180` : **169 commits de retard**. *Une decision qui n'est cablee a rien
# est une intention, et c'est ainsi qu'un numero DERIVE redevient un numero
# ASSIGNE.*
#
# ── DEUX GARDE-FOUS, CHACUN MESURE ──────────────────────────────────────────
#
# 1. `version.sh` SORT EN 2 hors d'un depot git (« pas un depot git »). Cable
#    nu dans un script en `set -e`, il casserait le demarrage d'une
#    installation qui n'est pas un clone. **On tolere son echec.**
#
# 2. SANS FICHIER, DOCKER CREE UN REPERTOIRE au point de montage
#    (`./legacy/version.txt:/var/www/html/version.txt:ro`) et le montage de
#    fichier ne s'accroche plus jamais. C'est le piege deja documente pour son
#    jumeau `laravel/version.txt` dans `.gitignore`. Le fichier n'etant plus
#    suivi par git, **c'est desormais a ce script de garantir qu'il EXISTE.**
#
# Le lecteur, lui, degrade proprement : `Version.php` rend `null` si le fichier
# manque, est illisible, est un repertoire, ou ne correspond pas a
# `^\d+\.\d+\.\d+$` ; `legacy/menu.php` affiche une chaine vide. Un numero
# absent est donc un pied de page muet, jamais une page cassee.
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIBLE="$RACINE/laravel/version.txt"

if "$RACINE/scripts/version.sh" --ecrire >/dev/null 2>&1; then
    printf '  version derivee du depot : %s\n' "$(cat "$CIBLE")"
    exit 0
fi

# Echec de la derivation : on ne casse rien, mais le point de montage DOIT
# exister. On ne fabrique pas un faux numero — le jalon suivi de `.0` est une
# valeur de forme VALIDE et visiblement provisoire.
if [ ! -s "$CIBLE" ]; then
    jalon="$(tr -d ' \t\n\r' < "$RACINE/VERSION-JALON" 2>/dev/null || echo '0.0')"
    printf '%s.0\n' "$jalon" > "$CIBLE"
    printf '  version NON derivee (hors depot git) : %s posee comme point de montage\n' "$(cat "$CIBLE")"
else
    printf '  version NON derivee (hors depot git) : %s conservee\n' "$(cat "$CIBLE")"
fi
