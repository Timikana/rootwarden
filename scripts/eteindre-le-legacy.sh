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
# ══ ÉTAPE ⑦ — MESURÉE LE 2026-09-08 08:4x, ET ELLE N'EXISTAIT PAS AVANT ═══════
#
# Après l'étape ⑤, il ne reste que DOUZE `.php` servis, et DIX sont orphelins —
# aucun fichier ne les inclut. Les deux exceptions ne le sont que par des
# orphelins :
#
#     includes/feature_flags.php   inclus par menu.php        (orphelin)
#     includes/lang.php            inclus par footer/head/menu (les trois orphelins)
#
# > **Le reste du legacy après ⑤ n'est pas un ensemble de fichiers isolés : c'est
# > un GRAPHE FERMÉ d'orphelins.** *Rien hors de lui n'y entre, et il ne sort
# > nulle part.*
#
# ⚠ Cette étape ne se mesure qu'APRÈS ⑤ — avant, `auth/verify.php` inclut
# `head.php`, et `head.php` inclut `lang.php`. **L'ordre n'est pas un confort :
# l'orphelinage est une CONSÉQUENCE de ⑤, pas un état préexistant.**
#
# ══ ET L'ErrorDocument DE L'ÉTAPE ⑥ ═══════════════════════════════════════════
#
#     legacy/.htaccess:43   ErrorDocument 404 /_sortie.php
#     vhost du conteneur    aucun ErrorDocument actif (exemples commentes seulement)
#
# Archiver `_sortie.php` laisse donc une directive qui pointe vers rien : Apache
# retombe sur sa page 404 par défaut. **Pas de panne, mais une directive morte.**
# *La ligne 43 doit partir avec `_sortie.php`, et le `.htaccess` entier avec le
# vhost — après ⑦ il ne garde plus rien.*
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
EPREUVE=0
ETAPE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --executer) EXECUTER=1 ;;
        --epreuve-des-gardes) EPREUVE=1 ;;
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
7|legacy/db.php legacy/head.php legacy/footer.php legacy/menu.php legacy/includes legacy/adm/includes|les 12 .php restants sont un GRAPHE D'ORPHELINS — mesure apres ⑤
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
# ⛔ CETTE GARDE ÉTAIT MORTE, ET ELLE NE POUVAIT PAS SE SIGNALER.
#
#    Sa forme précédente demandait `git ls-files "$p" | grep -qx
#    'legacy/version.txt'`. Or `.gitignore:162` liste `legacy/version.txt` :
#    `git ls-files` ne le rend JAMAIS, donc le `grep` échouait toujours, donc
#    la garde ne pouvait JAMAIS refuser. Mesuré le 2026-09-09 :
#
#      grep -n version.txt .gitignore      -> :162 legacy/version.txt
#      git ls-files legacy/version.txt     -> (vide)
#      git check-ignore -v <fichier>       -> .gitignore:162
#      le fichier sur le disque            -> PRÉSENT, 7 octets
#      montages dans docker-compose.yml    -> 2
#
#    Elle passait donc pour la mauvaise raison — et elle aurait laissé passer
#    une étape future portant sur `legacy` tout entier.
#
#    LA BONNE QUESTION N'EST PAS « git le suit-il » MAIS « ce préfixe le
#    contient-il ». `capture_le_fichier` répond à celle-là, ne dépend d'aucun
#    index, et surtout : elle est ÉPROUVABLE. `--epreuve-des-gardes` lui donne
#    des entrées forgées et exige qu'elle refuse ET qu'elle accepte.
#
#    Une garde qui n'a jamais refusé n'est pas une garde prouvée.

# Le préfixe « $1 » capture-t-il le fichier « $2 » ? Fonction PURE, sans effet.
capture_le_fichier() {
    prefixe="${1%/}"
    cible="$2"
    [ "$prefixe" = "$cible" ] && return 0
    case "$cible" in
        "$prefixe"/*) return 0 ;;
    esac
    return 1
}

# ══ ÉPREUVE DES GARDES ══════════════════════════════════════════════════════
#
# Une garde qui n'a jamais refusé n'est pas une garde prouvée — et celle du
# contrôle 1 a passé pendant des jours SANS POUVOIR refuser. Ce mode lui donne
# des entrées forgées et exige qu'elle discrimine dans les DEUX sens.
#
#   ./scripts/eteindre-le-legacy.sh --epreuve-des-gardes
#
# Il n'exécute aucun geste et ne lit ni git ni Docker : il éprouve le prédicat.
if [ "$EPREUVE" -eq 1 ]; then
    # ── GARDE SUR LE SCRIPT LUI-MEME ────────────────────────────────────────
    #
    # QUATRE FOIS cette nuit, des backticks dans une chaine a guillemets DOUBLES
    # ont EXECUTE ce qu'ils citaient : un `dire` citant un nom de fichier entre
    # backticks l'a lance comme une commande, et rendu un message ampute.
    # J'avais ecrit un controle pour ca — et je ne l'ai pas rejoue apres le
    # patch suivant.
    #
    #   > Un controle qu'on doit penser a relancer n'est pas une garde. Celui-ci
    #   > vit DANS le script, donc il tourne chaque fois qu'on l'eprouve.
    dire '══ garde : aucun backtick executable dans un dire a guillemets doubles ══'
    coupables=$(grep -nE 'dire[[:space:]]+"[^"]*`' "$0" || true)
    if [ -n "$coupables" ]; then
        n=$(printf '%s\n' "$coupables" | wc -l)
        dire "  ⛔ $n ligne(s) portent un backtick executable :"
        printf '%s\n' "$coupables" | sed 's/^/     /'
        exit 1
    fi
    dire '  ✅ aucune'
    dire ''
    dire '══ épreuve du prédicat capture_le_fichier ══'
    CIBLE='legacy/version.txt'
    rate=0
    # DOIT capturer — sinon la garde est morte, comme sa version précédente
    for cas in 'legacy' 'legacy/' 'legacy/version.txt'; do
        if capture_le_fichier "$cas" "$CIBLE"; then
            dire "  ✅ « $cas » capture — la garde refuserait"
        else
            dire "  ⛔ « $cas » NE capture PAS — la garde est MORTE"
            rate=$((rate+1))
        fi
    done
    # NE DOIT PAS capturer — sinon la garde refuse tout et on cesse de la lire
    for cas in 'legacy/auth' 'legacy/lang' 'legacy/iptables' 'legacy/_sortie.php' \
               'legacy/version.txt.bak' 'legacy/versionXtxt' 'laravel/version.txt' ''; do
        if capture_le_fichier "$cas" "$CIBLE"; then
            dire "  ⛔ « $cas » capture À TORT — la garde est trop large"
            rate=$((rate+1))
        else
            dire "  ✅ « $cas » ne capture pas"
        fi
    done
    # ⚠ `legacy/version.txt.bak` et `legacy/versionXtxt` sont là exprès : une
    #    garde écrite avec `grep` ou `case "$cible" in "$prefixe"*)` — sans la
    #    barre — les capturerait, et refuserait des étapes légitimes.
    dire ""
    dire "── et la liste RÉELLE des étapes, aujourd'hui ──"
    capture_reelle=0
    for p in $(etapes | cut -d'|' -f2); do
        capture_le_fichier "$p" "$CIBLE" && capture_reelle=$((capture_reelle+1))
    done
    dire "  $capture_reelle étape(s) sur $(etapes | wc -l) capturent version.txt"
    dire "  (0 attendu aujourd'hui — et c'est un CONSTAT, pas la preuve que la garde marche :"
    dire "   la preuve est au-dessus, sur des entrées forgées.)"
    dire ""
    if [ "$rate" -gt 0 ]; then
        dire "⛔ $rate cas discriminent mal. La garde du contrôle 1 n'est pas fiable."
        exit 1
    fi
    dire "✅ les 11 cas forgés discriminent. La garde peut refuser ET accepter."
    exit 0
fi

dire "══ contrôle 1 — le fichier monté dans le portage ══"
if grep -qE '^\s+- \./legacy/version\.txt:' docker-compose.yml; then
    dire "  ./legacy/version.txt est monté dans le portage (compose)"
    capture=0
    for p in $(etapes | cut -d'|' -f2); do
        if capture_le_fichier "$p" 'legacy/version.txt'; then
            dire "  ⛔ version.txt tombe dans la portée de « $p » — REFUS"
            dire "     le déplacer HORS de legacy/ et corriger le montage d'abord"
            capture=$((capture+1))
            ko=$((ko+1))
        fi
    done
    # ⚠ CE DÉTAIL EST CONDITIONNÉ À SON VERDICT, et il ne l'était pas.
    #    L'ancien `✅ aucune étape ne l'emporte` vivait APRÈS le `done` et
    #    s'imprimait même quand la boucle venait d'incrémenter `ko` : un détail
    #    qui AFFIRME la propriété qu'il vient de réfuter fait chercher au
    #    mauvais endroit. Le verdict agrégé restait juste ; la ligne, non.
    if [ "$capture" -eq 0 ]; then
        dire "  ✅ aucune étape ne l'emporte ($(etapes | wc -l) étapes examinées)"
    else
        dire "  ⛔ $capture étape(s) l'emportent"
    fi
elif [ -s laravel/version.txt ] && ! grep -qE '^\s+- \./legacy/' docker-compose.yml; then
    # ── TROISIEME ETAT : `patch 08` est applique ──────────────────────────────
    #
    # Ce controle exigeait que le montage soit DECLARE, et refusait sinon. C'etait
    # juste tant que le montage existait — mais `patch 08` l'a RETIRE, et le
    # refus est devenu la reponse a un succes. Troisieme fois cette nuit qu'une
    # garde de ce chantier refuse pour toujours parce que sa premisse a expire,
    # et la premiere sur une garde que j'ai ecrite moi-meme.
    #
    #   > Une porte qui ne peut plus s'ouvrir cesse d'etre une garde et devient
    #   > un mur — et son rouge ressemble a un defaut.
    #
    # Le TEMOIN separe l'etat terminal de l'anomalie : `laravel/version.txt`
    # existe et n'est pas vide, ET aucune ligne de montage `./legacy/` ne
    # subsiste. Sans lui, « le montage a disparu » et « quelqu'un a casse le
    # compose » rendent la meme sortie.
    dire "  ✅ ETAT TERMINAL — patch 08 applique, plus aucun montage ./legacy/"
    dire "     laravel/version.txt : $(wc -c < laravel/version.txt) octets, [$(cat laravel/version.txt)]"
    dire "     TEMOIN : ce vert n'est pas « rien lu » — une valeur a ete extraite."
    dire '     Version.php lit base_path(version.txt), et laravel/ est monte sur'
    dire '     /var/www/html : le fichier y apparait de lui-meme.'
else
    dire "  ⚠ le montage n'est plus déclaré ET laravel/version.txt manque ou est vide"
    dire "     — ce n'est pas l'etat terminal, c'est un compose casse. REFUS."
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
else
    # ⚠ « une AUTRE session écrit » était une attribution que ce contrôle ne peut
    # pas mesurer : il voit des modifications, pas leur auteur — et trois fois sur
    # trois c'était MA propre édition non commitée.
    #
    # > Un contrôle qui nomme une cause qu'il ne mesure pas fait chercher au mauvais
    # > endroit. Il dit ce qu'il VOIT, et laisse conclure.
    dire "  ⛔ $sales modification(s) non commitée(s). REFUS — un git mv par-dessus"
    dire "     rendrait le déplacement indissociable de ce travail, quel qu'en soit l'auteur."
    git status --porcelain | sed 's/^/     /'
    ko=$((ko+1))
fi

# ══ CONTRÔLE 5 — LA SONDE DE VIE DU LEGACY VISE CE QU'ON ARCHIVE ════════════
#
# `docker-compose.yml:48` :
#     test: ["CMD","curl","-fsk","https://localhost:443/auth/login.php","-o","/dev/null"]
#
# **L'étape ⑤ archive `legacy/auth/login.php`.** Après elle, `curl -f` reçoit 404,
# cinq échecs consécutifs, et le conteneur passe UNHEALTHY.
#
# ⚠ CE DÉFAUT A DÉJÀ ÉTÉ PAYÉ, ET LE COMPOSE LE RACONTE. La sonde visait la
# RACINE ; l'archivage de `legacy/index.php` l'a cassée — **conteneur UNHEALTHY
# pendant VINGT-ET-UNE HEURES alors qu'il servait parfaitement.** Le remède fut de
# la lier à l'écran de connexion, « qui vit exactement aussi longtemps que ce
# conteneur a une raison d'exister ».
#
# > **La sonde a été déplacée d'une page archivée vers une page dont l'archivage
# > était décidé. Le même défaut, un pas plus loin.**
#
# ✅ MAIS LA CONSÉQUENCE EST BORNÉE, ET MESURÉE : rien ne dépend de `php` en
# `service_healthy` — le graphe est `php -> db`, `php -> python`, `laravel -> db`,
# `python -> db`. Et `restart: unless-stopped` ne relance pas sur UNHEALTHY, seulement
# sur sortie. Le conteneur resterait donc unhealthy SANS boucler.
#
# ⛔ DONC CE N'EST PAS UN REFUS : C'EST UN AVERTISSEMENT. Un UNHEALTHY inexpliqué
# est exactement ce qui ferait annuler une extinction correcte.
dire ""
dire "══ contrôle 5 — la sonde de vie ══"
if grep -qE 'test:.*auth/login\.php' docker-compose.yml; then
    dire "  ⚠ le healthcheck de « php » vise /auth/login.php, que l'étape ⑤ archive"
    dire "     APRÈS l'étape ⑤ : le conteneur passera UNHEALTHY — c'est ATTENDU, pas un symptôme"
    dire "     rien ne dépend de php en service_healthy (vérifié), et unless-stopped"
    dire "     ne relance pas sur unhealthy : il restera unhealthy sans boucler"
    dire "     ⛔ ce déjà-vu a coûté 21 h d'UNHEALTHY faux, en 2026-09-05, pour la même raison"
else
    dire "  ✅ le healthcheck ne vise plus une cible de la séquence"
fi

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
