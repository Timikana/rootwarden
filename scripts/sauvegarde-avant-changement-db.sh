#!/usr/bin/env bash
# sauvegarde-avant-changement-db.sh - Dump COMPLET de la base avant qu'elle change d'image.
#
# Fichier a SOURCER (`maj.sh`) : il ne definit qu'une fonction.
#
# Audit 2026-10-21. Passer d'une image MySQL a une autre (9.2.0 -> 9.7 LTS) convertit le
# dossier de donnees au premier demarrage : c'est IRREVERSIBLE, on ne revient pas en
# arriere. `docker compose up -d` le ferait en silence des que l'image change. Cette
# fonction compare l'image EN SERVICE a l'image VISEE et, si elles different (nom ou
# digest), produit et VERIFIE un dump avant de laisser faire.
#
# Le mot de passe root n'apparait JAMAIS sur la ligne de commande de l'hote : il est lu
# dans l'environnement DU CONTENEUR (`$MYSQL_ROOT_PASSWORD`), entre apostrophes.
#
# Retour : 0 = rien a faire, ou dump verifie ; 1 = dump impossible -> NE PAS continuer.

sauvegarde_si_image_db_change() {
    local conteneur="$1" image_cible="$2" dossier="$3" simulation="${4:-0}"

    if ! docker inspect "$conteneur" >/dev/null 2>&1; then
        echo "  base : conteneur ${conteneur} absent - rien a sauvegarder (installation neuve)"
        return 0
    fi
    local id_actuel id_cible nom_actuel
    id_actuel=$(docker inspect -f '{{.Image}}' "$conteneur")
    nom_actuel=$(docker inspect -f '{{.Config.Image}}' "$conteneur")
    id_cible=$(docker image inspect -f '{{.Id}}' "$image_cible" 2>/dev/null || true)
    if [ -z "$id_cible" ]; then
        if [ "$simulation" = "1" ]; then
            echo "  [dry-run] ${image_cible} sera telechargee puis comparee a ${nom_actuel}"
            return 0
        fi
        echo "  base : image ${image_cible} introuvable localement - impossible de comparer" >&2
        return 1
    fi
    if [ "$id_actuel" = "$id_cible" ]; then
        echo "  base : image inchangee (${nom_actuel}) - pas de sauvegarde necessaire"
        return 0
    fi

    local horodatage fichier
    horodatage=$(date +%Y%m%d_%H%M%S)
    fichier="${dossier}/avant-changement-image-db_${horodatage}.sql.gz"
    echo "  base : l'image CHANGE (${nom_actuel} -> ${image_cible}) - la conversion des donnees sera IRREVERSIBLE"
    if [ "$simulation" = "1" ]; then
        echo "  [dry-run] dump complet vers ${fichier}"
        return 0
    fi
    if ! docker inspect -f '{{.State.Running}}' "$conteneur" | grep -q true; then
        echo "  base : ${conteneur} est ARRETE - impossible de faire le dump. Le demarrer d'abord." >&2
        return 1
    fi
    mkdir -p "$dossier"
    # Le code de retour de mysqldump est lu DANS la sous-coquille : apres elle,
    # PIPESTATUS ne decrit plus le tube.
    ( umask 077
      docker exec "$conteneur" sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump -uroot \
          --single-transaction --routines --triggers --events --all-databases' | gzip > "${fichier}.partiel"
      exit "${PIPESTATUS[0]}" )
    local rc_dump=$?
    # VERIFIER le dump, pas croire la commande : archive lisible ET contenu reel.
    # Ecrit dans `.partiel`, renomme SEULEMENT apres verification : un echec ne peut
    # ni laisser un dump tronque sous le nom final, ni ecraser un dump valide portant
    # le meme horodatage (mesure du 2026-10-21 : deux lancements dans la meme seconde).
    if [ "$rc_dump" != "0" ] || ! gzip -t "${fichier}.partiel" 2>/dev/null \
       || ! zcat "${fichier}.partiel" | grep -q 'CREATE TABLE'; then
        echo "  base : ⛔ dump INVALIDE (${fichier}) - mise a jour INTERROMPUE, rien n'a change" >&2
        rm -f -- "${fichier}.partiel"
        return 1
    fi
    chmod 600 "${fichier}.partiel"
    mv -f -- "${fichier}.partiel" "$fichier"
    echo "  base : dump verifie -> ${fichier} ($(du -h "$fichier" | cut -f1), $(zcat "$fichier" | grep -c 'CREATE TABLE') tables)"
    return 0
}
