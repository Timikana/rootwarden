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
        /*
         * `supervision/` archive le 2026-08-23. Ici la table redevient
         * PREVENTIVE : mesure faite, `backend/routes/search.py` n'emet que
         * `/security/`, `/tickets/index.php` et `/update/index.php` — jamais
         * `/supervision/`. L'entree ne repare donc aucun 404 constate ; elle
         * evite d'en fabriquer un le jour ou un resultat de recherche, une
         * notification ou un rapport citera ce chemin. Tenir cette table a jour
         * est une etape du cycle d'archivage, pas une reaction a un defaut.
         */
        '/supervision/' => 'supervision',
        /*
         * `docker/` et `chatops/` archives les 2026-08-25. Preventives elles
         * aussi : mesure refaite ce jour-la, `backend/routes/search.py:50,82`
         * n'emet que `/update/index.php` et `/tickets/index.php`. Aucun autre
         * fichier du backend n'ecrit de chemin de page.
         *
         * `/docker/` MANQUAIT : l'archivage de la v1.37.54 avait saute cette
         * etape du cycle. Elle ne reparait aucun 404 constate — c'est justement
         * ce qui la rend facile a oublier, et ce qui fait qu'on ne s'en apercoit
         * que le jour ou un resultat de recherche cite le chemin.
         */
        '/docker/'      => 'docker',
        '/chatops/'     => 'chatops',
        /*
         * `maintenance/` archive le 2026-08-25, preventive elle aussi.
         *
         * ATTENTION AU VOISINAGE : `/maintenance/check` et `/maintenance/windows`
         * sont des routes du BACKEND, toujours appelees par le portage. Elles ne
         * sont pas touchees ici parce que la table compare le chemin NORMALISE en
         * entier — `/maintenance/check` ne vaut pas `/maintenance/`. Une table qui
         * comparerait par prefixe les reecrirait, et la page de maintenance
         * cesserait de fonctionner sans que personne ne fasse le lien.
         */
        '/maintenance/' => 'maintenance',
        /*
         * `adm/audit_log.php` porte le 2026-08-25 (`v1.37.59`). Cette entree
         * n'est PAS preventive : `backend/routes/search.py:95` ecrit
         * `'link': '/adm/audit_log.php'` pour CHAQUE resultat d'audit trouve.
         * Sans elle, une recherche qui remonte une entree du journal renvoie a
         * l'ancien portail alors que la page est portee — et le lien porte alors
         * le marqueur « ancien portail », ce qui serait faux.
         *
         * La cle est la forme NORMALISEE : `normalise()` n'enleve `/index.php`
         * que s'il termine le chemin, puis ajoute une barre finale. Un fichier
         * `.php` nomme autrement devient donc `/adm/audit_log.php/`.
         *
         * `adm/` n'est PAS archive : ses cinq autres pages vivent toujours. La
         * table ne reecrit que ce chemin-la, parce qu'elle compare le chemin
         * normalise EN ENTIER.
         */
        '/adm/audit_log.php/' => 'journal-audit',

        /*
         * ══ LES LIENS DES NOTIFICATIONS DU BACKEND, ajoutes le 2026-08-26 ═══
         *
         * Le docblock de cette classe annonce depuis le debut qu'elle sert aussi
         * aux notifications — « evite d'en fabriquer un le jour ou un resultat
         * de recherche, une NOTIFICATION ou un rapport citera ce chemin ».
         * L'intention etait ecrite, le cablage manquait : la vue des
         * notifications rendait le chemin TEL QUEL.
         *
         * Releve des liens que le backend pose reellement (`link='…'`) :
         *
         *   /adm/admin_page.php#permissions   x3   -> ici
         *   /security/                        x3   -> ici
         *   /ssh-audit/                       x2   -> non porte, reste externe
         *   /profile.php                      x1   -> ici
         *   /approvals/                       x1   -> deja present
         *   /                                 x1   -> ici, et c'est le plus net
         *
         * `/` MERITE UN MOT : sans cette ligne, la notification au lien le plus
         * generique qui soit envoie hors du portail. C'est une correspondance
         * EXACTE sur le chemin normalise, pas un prefixe — elle ne capture rien
         * d'autre.
         *
         * `/adm/admin_page.php` mene aux COMPTES : c'est la page qui porte les
         * trois onglets de l'administration, et les trois sont portes.
         */
        '/adm/admin_page.php/' => 'comptes',
        '/security/'           => 'scan-cve',
        '/profile.php/'        => 'profil',
        '/'                    => 'accueil',
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
        // le chemin D'ORIGINE, pas sa forme normalisee — `/adm/server_users.php`
        // n'est pas `/adm/server_users/`.
        // (L'exemple etait `/adm/audit_log.php` jusqu'au 2026-08-25 ; cette
        // page est portee depuis, et figure donc dans la table ci-dessus. Un
        // commentaire qui ment est pire que pas de commentaire.)
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
