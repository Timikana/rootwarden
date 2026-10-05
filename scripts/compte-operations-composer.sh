#!/usr/bin/env bash
# compte-operations-composer.sh - Combien d'operations `composer install` FERAIT-il ?
#
# Fichier a SOURCER (`maj.sh` le fait) : il ne definit qu'une fonction.
#
# ── POURQUOI CE N'EST PAS LE CODE RETOUR ─────────────────────────────────────
#
# Mesure du 2026-10-05 sur `composer install --dry-run` :
#
#     vendor en retard   « Package operations: 0 installs, 4 updates, 0 removals »   rc=0
#     vendor a jour      « Nothing to install, update or remove »                    rc=0
#
# Les deux rendent 0 : le code retour ne discrimine RIEN. C'est le NOMBRE qui
# decide, et la phrase « Nothing to install » n'est lue que pour rendre 0.
#
# ── LE DOUTE VA DU COTE DE L'INSTALLATION ────────────────────────────────────
#
# Sortie non reconnue -> la fonction rend une chaine VIDE, et l'appelant
# installe. `composer install` est idempotent : installer pour rien coute
# quelques secondes, ne pas installer laisse en service des paquets que l'audit
# declare vulnerables, avec une CI verte qui dit le contraire.

compte_operations_composer() {
    local sortie="$1" ligne

    ligne=$(printf '%s\n' "$sortie" \
        | grep -oE 'Package operations: [0-9]+ installs?, [0-9]+ updates?, [0-9]+ removals?' \
        | head -1)
    if [ -n "$ligne" ]; then
        printf '%s\n' "$ligne" | grep -oE '[0-9]+' | awk '{ s += $1 } END { print s }'
        return 0
    fi
    if printf '%s\n' "$sortie" | grep -q 'Nothing to install, update or remove'; then
        echo 0
        return 0
    fi
    echo ""
}
