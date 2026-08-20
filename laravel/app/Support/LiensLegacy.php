<?php

namespace App\Support;

/**
 * Traduit un chemin de l'ANCIEN portail vers sa destination actuelle.
 *
 * POURQUOI CETTE CLASSE EXISTE. Le backend Python ne connait qu'un frontend :
 * l'ancien. `/search` rend, pour chaque resultat, un lien de navigation ecrit
 * en dur — `/tickets/index.php`, `/adm/audit_log.php`, `/update/index.php`.
 * Chaque page archivee transforme donc un de ces liens en **404**, et la
 * recherche devient un menu qui mene a des pages disparues. C'est exactement le
 * defaut releve dans le legacy — sept 404 ont vecu dans un menu que personne ne
 * suivait — sauf qu'ici c'est la migration elle-meme qui le fabrique.
 *
 * Le backend n'est pas touche : il continue d'emettre ses chemins. C'est le
 * frontend qui decide ou envoyer la personne, ce qui est son role.
 *
 * TENIR CETTE TABLE A JOUR EST UNE ETAPE DU CYCLE D'ARCHIVAGE. Un test le
 * verifie : aucun lien rendu par la recherche ne doit pointer vers une partie
 * archivee.
 */
class LiensLegacy
{
    /**
     * Parties archivees -> route Laravel qui les remplace.
     *
     * La cle est le chemin NORMALISE (sans `index.php`, avec un `/` final).
     */
    public const REMPLACEMENTS = [
        '/commandlog/' => 'journal-commandes',
        '/approvals/'  => 'approbations',
        '/drift/'      => 'derive-config',
        '/backups/'    => 'sauvegardes',
        '/tasks/'      => 'taches',
        '/tickets/'    => 'tickets',
        // Le backend ecrit `/update/index.php` en dur pour CHAQUE machine trouvee
        // (`backend/routes/search.py`) : pour ce module, la table cesse d'etre
        // preventive. Sans cette ligne, la recherche mene a un 404 mesurable.
        '/update/'     => 'mises-a-jour',
    ];

    /**
     * Normalise un chemin de l'ancien portail : `/tickets/index.php` et
     * `/tickets/` designent la meme partie.
     */
    public static function normalise(string $chemin): string
    {
        $chemin = '/' . ltrim(parse_url($chemin, PHP_URL_PATH) ?: '', '/');
        $chemin = preg_replace('#/index\.php$#', '/', $chemin);

        return str_ends_with($chemin, '/') ? $chemin : $chemin . '/';
    }

    /**
     * Ou envoyer quelqu'un qui suit ce chemin ?
     *
     * @return array{url: string, externe: bool}
     *   `externe` vaut true quand la destination reste l'ancien portail : le
     *   lien doit alors porter le meme marqueur que le menu, sans quoi on
     *   change de portail sans le dire.
     */
    public static function resoudre(string $chemin): array
    {
        $normalise = self::normalise($chemin);

        if (isset(self::REMPLACEMENTS[$normalise])) {
            return ['url' => route(self::REMPLACEMENTS[$normalise]), 'externe' => false];
        }

        // Chemin inchange : la page vit encore sur l'ancien portail. On garde
        // le chemin D'ORIGINE, pas sa forme normalisee — `/adm/audit_log.php`
        // n'est pas `/adm/audit_log/`.
        $origine = '/' . ltrim(parse_url($chemin, PHP_URL_PATH) ?: '', '/');

        return ['url' => rtrim(config('app.url_legacy'), '/') . $origine, 'externe' => true];
    }

    /**
     * La table de resolution, prete pour le navigateur.
     *
     * Le rendu des resultats se fait cote client : la table doit donc y
     * parvenir. Elle est construite ICI, a partir de la meme constante, pour
     * qu'il n'existe jamais deux versions de cette correspondance.
     *
     * @return array{remplacements: array<string,string>, base_legacy: string}
     */
    public static function pourLeNavigateur(): array
    {
        $remplacements = [];
        foreach (self::REMPLACEMENTS as $ancien => $route) {
            $remplacements[$ancien] = route($route);
        }

        return [
            'remplacements' => $remplacements,
            'base_legacy'   => rtrim(config('app.url_legacy'), '/'),
        ];
    }
}
