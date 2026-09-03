#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  banc-libre.sh — dit si une suite E2E tourne A CET INSTANT.
#
#  ⚠ CE SCRIPT NE REPOND PAS « LIBRE », ET C'EST VOULU.
#
#  Il rend deux etats seulement :
#      OCCUPE            une suite tourne, avec son PID et son nom
#      RIEN VU           aucun processus VU A CET INSTANT -> DEMANDE LA FENETRE
#
#  Pourquoi il refuse de dire « libre » : un garde instantane sur un banc qui se
#  relance en boucle mesure UN INSTANT, PAS UN ETAT. Mesure du 2026-09-02 : le
#  garde d'une session est tombe dans le trou entre deux rejeux et lui a rendu
#  « libre » a tort ; et le Lead a mesure « arbre calme, aucun LOT » a 04:22 puis
#  ecrit a 04:49 sur la foi de ce releve. *Un preflight ne certifie qu'un
#  instant.*
#
#  Le remede n'est donc PAS un meilleur `ps` : c'est la FENETRE NOMMEE. Une
#  fenetre est accordee par quelqu'un qui sait s'il va relancer, et AUCUNE SONDE
#  NE LIT CETTE INTENTION. Ce script sert a attraper le cas ou l'on oublie de
#  demander — jamais a dispenser de demander.
#
#  Filtrage : sur `go-*.mjs` dans la ligne de commande, JAMAIS sur `comm` seul —
#  huit processus `node` permanents vivent ici (VS Code, serveurs MCP), et un
#  garde qui les compte rend OCCUPE en permanence, donc se contourne, donc ne
#  garde rien.
#
#  Codes de sortie :  0 = rien vu     1 = occupe     2 = l'instrument a echoue
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

# `ps` plutot que `pgrep` : le motif `go-…\.mjs` n'apparait pas contigu dans
# CETTE ligne, donc pas d'auto-capture. Le piege a mordu QUATRE fois le 02/09,
# sur quatre motifs differents, dont deux fois chez le Lead.
sortie=$(ps -eo comm=,pid=,args= 2>/dev/null) || {
  echo "banc-libre: ps a echoue — instrument indisponible, NE RIEN CONCLURE" >&2
  exit 2
}

trouves=$(printf '%s\n' "$sortie" | awk '$1=="node" && $0 ~ /go-[a-z0-9-]+\.mjs/ {print}')

if [ -n "$trouves" ]; then
  echo "OCCUPE — une suite tourne a cet instant :"
  printf '%s\n' "$trouves" | awk '{printf "  pid %-8s %s\n", $2, $0}' | sed 's/node *[0-9]* *//'
  echo
  echo "N'ECRIS PAS dans laravel/ legacy/ backend/ ni tests/e2e/."
  exit 1
fi

echo "RIEN VU — aucune suite E2E visible a cet instant."
echo
echo "⚠ CE N'EST PAS « LE BANC EST LIBRE »."
echo "  Un rejeu peut demarrer dans la seconde qui suit ce releve, et ce script"
echo "  ne lit l'intention de personne. DEMANDE LA FENETRE a qui tient le banc."
exit 0
