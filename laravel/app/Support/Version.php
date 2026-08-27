<?php

namespace App\Support;

/**
 * Le numero de version du produit, LU et jamais calcule.
 *
 * ══ POURQUOI UNE LECTURE DE FICHIER, ET PAS UN CALCUL ════════════════════
 *
 * La regle qui produit ce numero a besoin de l'HISTORIQUE git. Le conteneur du
 * portage n'a pas de depot : un `git describe` y rendrait une erreur, ou pire,
 * un vide qui passerait pour une version. La source unique est donc
 * `legacy/version.txt`, une ligne, `MAJEUR.MINEUR.CORRECTIF`.
 *
 * ══ POURQUOI CE CHEMIN, ET CE QU'IL A COUTE DE LE MESURER ════════════════
 *
 * Le fichier vit dans `legacy/`, et le conteneur du portage ne monte QUE
 * `laravel/`. Mesure du 2026-08-27 : `docker inspect` ne rend qu'un montage, et
 * quatre chemins plausibles ont ete sondes, aucun ne trouvait le fichier. La
 * donnee n'etait pas la — ce n'etait pas un defaut de code.
 *
 * Il est desormais monte en LECTURE SEULE a la racine servie
 * (`./legacy/version.txt:/var/www/html/version.txt:ro`). Le numero reste donc a
 * UN seul endroit : `version.txt` a derive deux fois dans la seule journee du
 * 2026-08-27 — reste a 1.38.17 pendant deux increments, puis trois commits sur
 * le meme numero. Une variable d'environnement ou une copie a l'entrypoint
 * auraient ajoute une SECONDE source a un chiffre qui venait de diverger.
 *
 * ══ UNE VERSION INCONNUE SE DIT ══════════════════════════════════════════
 *
 * Fichier absent, illisible ou vide : on rend `null`, et l'ecran ECRIT
 * « version inconnue ». Jamais un vide — un pied de page muet se lit comme une
 * page sans version, pas comme une lecture qui a echoue.
 *
 * **Un montage de `volumes` ne prend pas effet a un `docker restart` : il faut
 * RECREER le conteneur.** Tant que ce n'est pas fait, `null` est donc le
 * comportement CORRECT et non un defaut — ne pas conclure d'une mesure prise
 * avant la recreation.
 */
final class Version
{
    /** Le chemin du montage en lecture seule, a la racine servie. */
    private const CHEMIN = '/version.txt';

    /** Memorise pour la requete : le fichier ne change pas en cours de route. */
    private static ?string $lue = null;
    private static bool $deja = false;

    /** Le numero, ou `null` si on ne le connait pas. */
    public static function numero(): ?string
    {
        if (self::$deja) {
            return self::$lue;
        }
        self::$deja = true;

        $chemin = public_path(self::CHEMIN);
        if (! is_file($chemin) || ! is_readable($chemin)) {
            return self::$lue = null;
        }

        $brut = @file_get_contents($chemin);
        if ($brut === false) {
            return self::$lue = null;
        }

        // UNE SEULE LIGNE, ET ON NE FAIT PAS CONFIANCE A SA FORME. Un fichier
        // qui porterait autre chose qu'un numero ne doit pas s'afficher tel
        // quel dans un pied de page : ce serait publier le contenu d'un fichier.
        $ligne = trim((string) strtok($brut, "\r\n"));

        return self::$lue = preg_match('/^\d+\.\d+\.\d+$/', $ligne) === 1 ? $ligne : null;
    }
}
