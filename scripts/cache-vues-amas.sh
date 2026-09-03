#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  cache-vues-amas.sh — QUALIFICATEUR, pas garde. Dit si le cache de vues Blade a
#  ete RECONSTRUIT dans une fenetre, pour rendre un FAIL de DELAI interpretable.
#
#  ⚠ IL NE BLOQUE RIEN, ET C'EST VOULU. Une reconstruction NE PEUT PAS changer ce
#  que la page rend — elle change son DELAI : une premiere compilation coute 2 a
#  4,6 s contre 0,21 en cache. Donc un FAIL de DELAI peut en venir, JAMAIS un FAIL
#  de CONTENU. Bloquer la-dessus arreterait des mesures pour une cause qui
#  n'affecte pas le contenu — et un garde qu'on contourne ne garde rien.
#
#  LA SIGNATURE MESUREE : `artisan view:clear` + `view:cache` recompile TOUT en un
#  bloc. Releve du 2026-09-03 : 111 gabarits sur 112 partagent la MEME seconde,
#  etendue totale 1 s. Une compilation PARESSEUSE ne peut pas fabriquer ca — elle
#  produit un fichier a la fois, etale sur des heures. C'est donc une grandeur que
#  le fonctionnement nominal NE PEUT PAS PRODUIRE, et c'est ce qui rend la sonde
#  fidele : elle ne mesure pas l'ABSENCE d'une action, elle mesure une empreinte
#  positive.
#
#  ⚠⚠ CE QU'IL NE PEUT PAS DISTINGUER — a lire avant de croire son silence :
#    · deux reconstructions qui se suivent, d'une seule lente : meme amas ;
#    · une reconstruction d'un `touch` de masse : meme empreinte ;
#    · un conteneur lent peut ETALER l'amas au-dela du seuil -> LA SONDE RATE la
#      reconstruction. **Son silence n'est donc PAS la preuve qu'il n'y en a pas
#      eu.** *Une propriete non atteinte n'est un defaut que si elle POUVAIT
#      l'etre* — et ici, non atteinte ne veut pas dire absente.
#
#  Usage :  cache-vues-amas.sh [depart_epoch] [fin_epoch]
#           sans argument : releve l'etat, sans fenetre
#  Sortie :  AMAS: n gabarits en Ds a <date>   |   (rien d'imprime si aucun amas)
#  Codes  :  0 = aucun amas       1 = amas detecte       2 = instrument indisponible
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SEUIL_N=${CACHE_AMAS_N:-20}      # au moins N gabarits
SEUIL_S=${CACHE_AMAS_S:-3}       # dans une fenetre de S secondes
CONTENEUR=${CACHE_CONTENEUR:-rootwarden_laravel}
CHEMIN=${CACHE_CHEMIN:-/var/www/html/storage/framework/views}

if [ -n "${CACHE_AMAS_FICHIER:-}" ]; then
  # mode EPROUVE : lit les mtime depuis un fichier, un par ligne. Sert aux temoins.
  mt=$(cat "$CACHE_AMAS_FICHIER") || { echo "cache-vues-amas: fichier illisible" >&2; exit 2; }
else
  mt=$(sudo -n docker exec "$CONTENEUR" sh -c "cd $CHEMIN && stat -c %Y *.php" 2>/dev/null) || {
    echo "cache-vues-amas: conteneur ou chemin injoignable — NE RIEN CONCLURE" >&2; exit 2; }
fi
[ -n "$mt" ] || { echo "cache-vues-amas: aucun gabarit lu — NE RIEN CONCLURE" >&2; exit 2; }

printf '%s\n' "$mt" | sort -n | awk -v n="$SEUIL_N" -v s="$SEUIL_S" \
  -v d="${1:-0}" -v f="${2:-9999999999}" '
  { t[NR]=$1 }
  END {
    meilleur=0; base=0; etendue=0
    for (i=1; i<=NR; i++) {
      c=0; dernier=t[i]
      for (j=i; j<=NR && t[j]-t[i]<=s; j++) { c++; dernier=t[j] }
      if (c>meilleur) { meilleur=c; base=t[i]; etendue=dernier-t[i] }
    }
    if (meilleur>=n && base>=d && base<=f) {
      # ETENDUE MESUREE, pas le seuil : *un detail se CALCULE a partir de l etat
      # mesure, il ne se REDIGE jamais a partir du parametre.* La premiere version
      # imprimait le seuil (3s) quand l etendue reelle etait 1s -- huitieme
      # occurrence du motif « un detail qui affirme ce qu il n a pas mesure ».
      printf "AMAS: %d gabarits en %ds (seuil %d en %ds) a %s\n", \
             meilleur, etendue, n, s, strftime("%Y-%m-%d %H:%M:%S", base)
      exit 1
    }
    exit 0
  }'
