#!/usr/bin/env bash
# ==============================================================================
# version.sh - LA VERSION SE DERIVE, ELLE NE S'ASSIGNE PLUS.  (INF-004)
#
#   MAJEUR.MINEUR   VERSION-JALON, seul fichier ecrit a la main, change aux jalons
#   CORRECTIF       DERIVE du depot : nombre de commits de PREMIER PARENT depuis
#                   la derniere modification de VERSION-JALON
#
# ── POURQUOI ON NE REPARE PAS `bump-version.sh` ───────────────────────────────
#
# Il porte `VERSION_FILE="www/version.txt"`, chemin disparu depuis le renommage
# `www/` -> `legacy/`. Il est mort depuis, et personne ne l'avait vu.
#
# Mais le reparer laisserait la CLASSE ouverte : un numero ASSIGNE — par un
# humain, par un message — est valide au moment ou on l'ecrit, pas au moment ou
# un autre l'emploie. Le 2026-08-27, TROIS commits de TROIS sessions ont
# revendique le meme numero en 2 min 06 s. C'est le defaut d'index : un controle
# juste, separe de son usage par un delai.
#
# Un numero derive n'a pas de delai : il est calcule a l'instant ou il sert.
#
# ── POURQUOI `--first-parent`, ET C'EST UNE MESURE ────────────────────────────
#
# Trois candidats ont ete mesures sur l'historique reel (583 commits, 28 fusions) :
#
#   ancre = dernier TAG ancestral      1 RECUL franc, 2 doublons sur 300 commits.
#                                      Le recul tombe exactement sur un tag neuf :
#                                      le compte repart a zero et DEUX commits
#                                      differents portent le meme numero. Un
#                                      numero qui se repete est pire qu'un numero
#                                      qui saute. Et c'est un CYCLE : le job
#                                      auto-tag CREE le tag depuis la version.
#
#   ancre fixe, tous parents           0 doublon sur 300 commits… et 7 sur 583.
#                                      Les fusions font porter le meme compte a
#                                      deux commits de branches paralleles. La
#                                      premiere fenetre etait MERGE-FREE : elle
#                                      mesurait le domaine de validite de la
#                                      formule, pas la formule.
#
#   ancre fixe, --first-parent         473 numeros pour 473 commits, strictement
#                                      croissant, ZERO doublon sur tout
#                                      l'historique. RETENU.
#
# Usage :
#   scripts/version.sh              affiche la version derivee
#   scripts/version.sh --ecrire     l'ecrit aussi dans legacy/version.txt
#   scripts/version.sh --epreuve    joue les proprietes sur un depot jetable
# ==============================================================================

set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FICHIER_JALON="VERSION-JALON"
FICHIER_PRODUIT="legacy/version.txt"

derive() {
    local depot="${1:-$RACINE}"

    git -C "$depot" rev-parse --git-dir >/dev/null 2>&1 || {
        echo "version.sh : pas un depot git ($depot)" >&2
        return 2
    }

    [[ -f "$depot/$FICHIER_JALON" ]] || {
        echo "version.sh : $FICHIER_JALON introuvable" >&2
        return 2
    }

    local jalon
    jalon="$(tr -d ' \t\n\r' < "$depot/$FICHIER_JALON")"

    # FAIL-CLOSED SUR LA FORME. Un jalon illisible ne doit pas produire une
    # version plausible : `1.38` et `1.38.x` ne se distinguent pas a l'oeil dans
    # un journal, et une version fausse voyage plus loin qu'une erreur.
    [[ "$jalon" =~ ^[0-9]+\.[0-9]+$ ]] || {
        echo "version.sh : jalon invalide '$jalon' (attendu MAJEUR.MINEUR)" >&2
        return 2
    }

    # L'ancre est le dernier commit qui a TOUCHE le fichier de jalon.
    local ancre
    ancre="$(git -C "$depot" log -1 --format=%H -- "$FICHIER_JALON" 2>/dev/null || true)"

    local correctif
    if [[ -z "$ancre" ]]; then
        # Le fichier existe mais n'a jamais ete commite : on est avant le premier
        # jalon. Le dire par un correctif 0 plutot que par une erreur — le cas
        # arrive une fois, a la creation.
        correctif=0
    else
        correctif="$(git -C "$depot" rev-list --count --first-parent "$ancre..HEAD")"
    fi

    echo "${jalon}.${correctif}"
}

# ── Epreuve : les proprietes, sur un depot JETABLE ───────────────────────────
#
# Elle ne mesure PAS l'historique reel : celui-ci changerait a chaque commit et
# l'epreuve deviendrait irreproductible. Elle fabrique un depot qui porte ce
# qu'il faut mesurer — dont une FUSION, sans laquelle la propriete d'unicite ne
# serait pas eprouvee (elle a deja ete crue vraie sur une fenetre merge-free).
epreuve() {
    local tmp echecs=0
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    verifie() {
        if [[ "$2" == "$3" ]]; then
            echo "  ok   $1 : $2"
        else
            echo "  FAIL $1 : attendu '$3', obtenu '$2'"
            echecs=$((echecs + 1))
        fi
    }

    git -C "$tmp" init -q -b principale
    git -C "$tmp" config user.email epreuve@local
    git -C "$tmp" config user.name epreuve
    mkdir -p "$tmp/legacy" "$tmp/scripts"
    cp "$RACINE/scripts/version.sh" "$tmp/scripts/version.sh"

    echo "1.38" > "$tmp/$FICHIER_JALON"
    git -C "$tmp" add -A && git -C "$tmp" commit -qm "jalon 1.38"
    verifie "le commit du jalon vaut .0" "$(derive "$tmp")" "1.38.0"

    for i in 1 2 3; do
        echo "$i" > "$tmp/fichier"
        git -C "$tmp" add -A && git -C "$tmp" commit -qm "travail $i"
    done
    verifie "trois commits plus tard" "$(derive "$tmp")" "1.38.3"

    # UNE FUSION. C'est le cas qui a fait tomber le candidat « tous parents ».
    git -C "$tmp" checkout -q -b cote
    echo cote > "$tmp/cote"; git -C "$tmp" add -A; git -C "$tmp" commit -qm "sur le cote 1"
    echo cote2 > "$tmp/cote"; git -C "$tmp" add -A; git -C "$tmp" commit -qm "sur le cote 2"
    git -C "$tmp" checkout -q principale
    git -C "$tmp" merge -q --no-ff cote -m "fusion"
    verifie "une fusion ne compte que pour UN" "$(derive "$tmp")" "1.38.4"

    # Le jalon change : le correctif REPART.
    echo "2.0" > "$tmp/$FICHIER_JALON"
    git -C "$tmp" add -A && git -C "$tmp" commit -qm "jalon 2.0"
    verifie "un jalon neuf remet le correctif a zero" "$(derive "$tmp")" "2.0.0"
    echo suite > "$tmp/fichier"; git -C "$tmp" add -A; git -C "$tmp" commit -qm "apres le jalon"
    verifie "et il repart de la" "$(derive "$tmp")" "2.0.1"

    # STRICTEMENT CROISSANT ET SANS DOUBLON sur toute la chaine.
    local serie precedent=-1 doublons=0 reculs=0
    serie="$(git -C "$tmp" rev-list --reverse --first-parent HEAD)"
    local vus=""
    for c in $serie; do
        local n
        n="$(git -C "$tmp" rev-list --count --first-parent "$c")"
        [[ "$n" -le "$precedent" ]] && reculs=$((reculs + 1))
        [[ " $vus " == *" $n "* ]] && doublons=$((doublons + 1))
        vus="$vus $n"; precedent="$n"
    done
    verifie "aucun recul le long du premier parent" "$reculs" "0"
    verifie "aucun doublon le long du premier parent" "$doublons" "0"

    # FAIL-CLOSED : ce qui doit ECHOUER, et bruyamment.
    rm "$tmp/$FICHIER_JALON"
    if derive "$tmp" >/dev/null 2>&1; then
        echo "  FAIL un jalon absent doit faire ECHOUER, pas produire un numero"
        echecs=$((echecs + 1))
    else
        echo "  ok   un jalon absent fait echouer"
    fi

    echo "malforme" > "$tmp/$FICHIER_JALON"
    if derive "$tmp" >/dev/null 2>&1; then
        echo "  FAIL un jalon malforme doit faire ECHOUER"
        echecs=$((echecs + 1))
    else
        echo "  ok   un jalon malforme fait echouer"
    fi

    echo
    if [[ "$echecs" -eq 0 ]]; then
        echo "epreuve : toutes les proprietes tiennent"
        return 0
    fi
    echo "epreuve : $echecs propriete(s) en echec"
    return 1
}

case "${1:-}" in
    --epreuve) epreuve ;;
    --ecrire)
        v="$(derive)"
        printf '%s\n' "$v" > "$RACINE/$FICHIER_PRODUIT"
        echo "$v -> $FICHIER_PRODUIT"
        ;;
    "") derive ;;
    *) echo "Usage: $0 [--ecrire|--epreuve]" >&2; exit 1 ;;
esac
