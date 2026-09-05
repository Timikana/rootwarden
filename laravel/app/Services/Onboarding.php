<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * L'assistant de premiere configuration — portage de
 * `legacy/includes/onboarding.php`.
 *
 * ══ POURQUOI IL SE PORTE, ET POURQUOI CA GOUVERNE SA FORME ════════════════
 *
 * **Son absence est INDETECTABLE par quiconque travaille sur une installation
 * deja configuree — c'est-a-dire par toute l'equipe.** Le produit est
 * auto-heberge : cette capacite vaut pour des deploiements que personne ici ne
 * verra jamais.
 *
 * On ne peut donc PAS la valider par ce qu'on voit a l'ecran. Sur ce depot, six
 * des huit etapes sont deja franchies : l'assistant y est presque vide, et un
 * test qui se contenterait de constater « il s'affiche » ne mesurerait rien.
 *
 * **D'ou la separation qui structure ce fichier :**
 *
 *     mesures()   touche la base, et ne DECIDE rien
 *     etapes()    decide, et ne touche RIEN — elle est pure et statique
 *
 * *Chaque detection devient verifiable separement, en forcant son etat, sans
 * ecrire une ligne en base.* C'est la seule facon de couvrir des etats que ce
 * depot ne produira jamais.
 *
 * ══ HUIT ETAPES, ET LE BRIEF EN ANNONCAIT CINQ ════════════════════════════
 *
 * Releve du 2026-09-05 sur `onboarding.php` : `servers`, `users`, `2fa`,
 * `ssh_key`, `keypair`, `remove_passwords`, `api_key`, `first_scan`. Les trois
 * premieres et `api_key` manquaient a l'enumeration recue. *Porter cinq sur
 * huit aurait retire trois detections en silence — et personne ici ne s'en
 * serait apercu, par la raison meme qui fait porter cette page.*
 */
final class Onboarding
{
    /** Le legacy l'inclut si `role_id >= ROLE_ADMIN` (`index.php:162`). */
    public const ROLE_MINIMAL = 2;

    /**
     * Les huit etapes, DANS L'ORDRE, et la cle de navigation qui les mene.
     *
     * ⚠ LA DESTINATION EST UNE CLE DE MENU, PAS UNE URL. Le legacy ecrit des
     * chemins en dur (`/adm/admin_page.php#servers`, `/profile.php`) ; ici la
     * cle se resout par `Navigation`, exactement comme les tuiles et les
     * alertes de l'accueil. **Consequence voulue : une etape dont la page est
     * fermee au compte n'affiche AUCUN lien**, au lieu d'en proposer un qui
     * menerait a un 403.
     *
     * `null` = aucune page ne correspond ; l'etape se lit sans lien.
     */
    public const ETAPES = [
        'serveurs'         => 'admin',
        'comptes'          => 'admin',
        'second_facteur'   => 'profil',
        'cle_ssh'          => 'profil',
        'cle_plateforme'   => 'platform_key',
        'sans_mot_de_passe' => 'platform_key',
        'cle_api'          => 'admin',
        'premier_releve'   => 'ssh_audit',
    ];

    /**
     * LES MESURES. Le seul point de ce service qui touche la base.
     *
     * Chaque valeur est un NOMBRE, jamais un verdict : c'est `etapes()` qui
     * decide, et c'est ce partage qui rend chaque detection eprouvable.
     *
     * @return array<string, int>
     */
    public function mesures(int $idCompte): array
    {
        $compte = DB::table('users')
            ->where('id', $idCompte)
            ->first(['totp_secret', 'ssh_key']);

        return [
            'machines' => (int) DB::table('machines')->count(),

            // « Au moins un administrateur EN PLUS du superadmin initial » :
            // le legacy teste `> 1`, et ce seuil vit dans `etapes()`.
            'administrateurs' => (int) DB::table('users')
                ->whereIn('role_id', [2, 3])->where('active', 1)->count(),

            'second_facteur' => ($compte !== null && ! empty($compte->totp_secret)) ? 1 : 0,
            'cle_ssh' => ($compte !== null && ! empty($compte->ssh_key)) ? 1 : 0,

            /*
             * ⚠ LE LEGACY COMPTE `platform_keypair`, UNE TABLE QUI N'EXISTE PAS.
             *
             * Mesure du 2026-09-05 : `SELECT COUNT(*) FROM platform_keypair`
             * rend `ERROR 1146`, **aucun fichier de `mysql/` ne cree cette
             * table**, et `012_platform_keypair.sql` n'ajoute que des colonnes a
             * `machines`. Le seul lecteur de ce nom dans tout le depot est
             * `onboarding.php` lui-meme.
             *
             * Son `try/catch` avale l'erreur et pose zero. **L'etape ne pouvait
             * donc JAMAIS etre franchie** — l'assistant n'atteignait jamais 8/8
             * et n'affichait jamais son panneau final — **et l'avertissement de
             * l'etape suivante, conditionne a ce zero, etait affiche en
             * permanence.**
             *
             * *Ce n'est pas une capacite a reproduire, c'est une detection morte.*
             * On lit donc la source qui EXISTE et que la page `cle-plateforme`
             * gere deja : le nombre de machines portant la cle de plateforme.
             */
            'machines_avec_cle' => (int) DB::table('machines')
                ->where('platform_key_deployed', 1)->count(),

            /*
             * ⚠ ET « PLUS DE MOT DE PASSE » NE SE LIT PAS SUR UNE SEULE COLONNE.
             *
             * Le legacy teste `password IS NOT NULL AND password != ''`. Deux
             * defauts, tous deux mesures sur ce depot :
             *
             *   - il ignore `root_password`, la seconde colonne de secret ;
             *   - `!= ''` compare des OCTETS. PHP chiffre la chaine vide en
             *     `sodium:…` — non vide — tandis que Python rend `''`. Une
             *     machine saisie sans mot de passe par le formulaire du legacy
             *     compte donc comme « en portant un ».
             *
             * On reprend le predicat que `ClePlateforme::machines()` emploie
             * deja : les DEUX colonnes, `IS NOT NULL AND <> ''`. Il garde
             * l'angle mort du chiffrement de la chaine vide — **il vit du cote
             * qui detient la cle, donc dans le backend** — mais il cesse
             * d'ignorer la moitie du sujet.
             */
            'machines_avec_mot_de_passe' => (int) DB::table('machines')
                ->where(function ($q) {
                    $q->where(function ($w) {
                        $w->whereNotNull('password')->where('password', '<>', '');
                    })->orWhere(function ($w) {
                        $w->whereNotNull('root_password')->where('root_password', '<>', '');
                    });
                })->count(),

            'cles_api_scopees' => (int) DB::table('api_keys')
                ->whereRaw('COALESCE(auto_generated, 0) = 0')
                ->whereNull('revoked_at')->count(),

            'releves' => (int) DB::table('ssh_audit_results')->count()
                + (int) DB::table('cve_scans')->count(),
        ];
    }

    /**
     * LA DERIVATION. Pure, statique, sans base : chaque detection est
     * eprouvable en forcant `$m`.
     *
     * @param  array<string, int>  $mesures
     * @return list<array{cle: string, faite: bool, nav: string|null, avertit: bool}>
     */
    public static function etapes(array $mesures): array
    {
        $n = static fn (string $c): int => (int) ($mesures[$c] ?? 0);

        $cleEnPlace = $n('machines_avec_cle') > 0;

        $faites = [
            'serveurs'         => $n('machines') > 0,
            // `> 1` et non `>= 1` : le legacy compte le superadmin initial dans
            // le total, donc « un second administrateur » se lit « plus d'un ».
            'comptes'          => $n('administrateurs') > 1,
            'second_facteur'   => $n('second_facteur') > 0,
            'cle_ssh'          => $n('cle_ssh') > 0,
            'cle_plateforme'   => $cleEnPlace,
            // Un parc VIDE ne peut pas avoir « retire ses mots de passe » : il
            // n'en avait aucun. Le legacy porte deja cette condition, et elle
            // evite d'annoncer une etape franchie a une installation neuve.
            'sans_mot_de_passe' => $n('machines') > 0 && $n('machines_avec_mot_de_passe') === 0,
            'cle_api'          => $n('cles_api_scopees') > 0,
            'premier_releve'   => $n('releves') > 0,
        ];

        $etapes = [];
        foreach (self::ETAPES as $cle => $nav) {
            $etapes[] = [
                'cle'   => $cle,
                'faite' => $faites[$cle],
                'nav'   => $nav,
                /*
                 * L'AVERTISSEMENT NE PORTE QUE SUR UNE ETAPE, ET SEULEMENT SI
                 * ELLE RESTE A FAIRE. Retirer les mots de passe sans cle de
                 * plateforme deployee laisse le parc sans aucun acces — c'est le
                 * `sans_retour` que `ClePlateforme` compte deja.
                 */
                'avertit' => $cle === 'sans_mot_de_passe' && ! $cleEnPlace && ! $faites[$cle],
            ];
        }

        return $etapes;
    }

    /** @param  list<array{faite: bool}>  $etapes */
    public static function progression(array $etapes): array
    {
        $total = count($etapes);
        $faites = count(array_filter($etapes, static fn (array $e) => $e['faite']));

        return [
            'faites' => $faites,
            'total'  => $total,
            // Un total nul ne divise pas — la liste est constante, mais la garde
            // coute une comparaison et evite une division par zero de principe.
            'pourcent' => $total > 0 ? (int) round($faites / $total * 100) : 0,
            'terminee' => $total > 0 && $faites === $total,
        ];
    }

    /**
     * L'assistant a-t-il ete masque par ce compte ?
     *
     * ⚠ LE LEGACY RETOURNE EN SILENCE SI LA COLONNE MANQUE (`try/catch`, migration
     * 042 non appliquee). Ici la colonne EXISTE — mesure du 2026-09-05 sur
     * `information_schema` — et le portage ne pose pas de filet contre une
     * absence qu'il a verifiee. *Un `try/catch` qui cache un etat qu'on n'a pas
     * mesure transforme une panne en page muette.*
     */
    public function masque(int $idCompte): bool
    {
        return DB::table('users')->where('id', $idCompte)
            ->whereNotNull('onboarding_dismissed_at')->exists();
    }

    public function masquer(int $idCompte): void
    {
        DB::table('users')->where('id', $idCompte)
            ->update(['onboarding_dismissed_at' => now()]);
    }
}
