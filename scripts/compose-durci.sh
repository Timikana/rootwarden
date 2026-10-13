#!/usr/bin/env bash
# compose-durci.sh - Les fichiers compose a passer quand le durcissement est actif.
#
# Fichier a SOURCER (`maj.sh`, `start.sh`) : il ne definit qu'une fonction.
#
# Audit 2026-10-13, H-4. `docker-compose.prod.yml` (cap_drop ALL, read_only du
# backend) n'etait appele par AUCUN script — et il ne demarrait pas : verifie,
# puis corrige, sur une stack complete isolee. Il s'active par
# `COMPOSE_DURCI=true` dans srv-docker.env.
#
# ⚠ OPTION ABSENTE OU FAUSSE -> CHAINE VIDE : les commandes restent STRICTEMENT
# celles d'avant (aucun `-f`), donc aucune regression possible tant qu'on ne
# l'active pas.
#
# ⚠ PASSER `-f` DESACTIVE LE CHARGEMENT AUTOMATIQUE de docker-compose.override.yml.
# S'il existe, on l'inclut a la main, a sa place (apres la base, avant le durci).

drapeaux_compose_durci() {
    local env_file="$1" dir="${2:-.}" valeur
    valeur=$(grep -E '^COMPOSE_DURCI=' "$env_file" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"' ' | tr '[:upper:]' '[:lower:]')
    [ "$valeur" = "true" ] || return 0
    local f="-f ${dir}/docker-compose.yml"
    [ -f "${dir}/docker-compose.override.yml" ] && f="$f -f ${dir}/docker-compose.override.yml"
    echo "$f -f ${dir}/docker-compose.prod.yml"
}
