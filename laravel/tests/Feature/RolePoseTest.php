<?php

namespace Tests\Feature;

use App\Services\Comptes;
use App\Support\RolePose;
use Tests\TestCase;

/**
 * E-385 puis E-399 — le role qu'un auteur est REELLEMENT autorise a poser, et
 * LAQUELLE des deux coercitions a joue.
 *
 * ══ CE FICHIER REMPLACE `RoleAutoriseTest`, ET LE ROUGE ETAIT JUSTE ═══════
 *
 * `roleAutorise(int, int): array{int, bool}` n'existe plus. Le booleen unique
 * ne rapportait que la coercition d'AUTORISATION — ma mesure du 2026-09-04 :
 *
 *     auteur 3 ou 2, valeur hors liste  ->  role 1, EN SILENCE
 *     auteur 1, n'importe quelle valeur ->  role 1, ANNONCE
 *
 * `rolePose(?int, int): RolePose` rend trois proprietes NOMMEES, et les deux
 * drapeaux sont INDEPENDANTS : une valeur invalide devient le plancher, que
 * l'autorisation peut a son tour refuser. **Quatre combinaisons, pas deux** —
 * rendre « laquelle des deux » au singulier aurait force a en taire une.
 *
 *     ->role            le role ecrit, toujours dans `ROLES`
 *     ->valeurInvalide  phrase de VALIDITE  : « ce n'est pas une valeur de role »
 *     ->rangRamene      phrase de SECURITE  : « votre autorisation a ete reduite »
 *
 * ── DEUX FONCTIONS, ET LA DISTINCTION VIT DANS LEUR COMPOSITION ────────────
 *
 * `rolePose(null, …)` rend `valeurInvalide = true`. Ce n'est donc PAS elle qui
 * distingue l'absence : c'est `roleDuLibelle('')`, qui rend le role par defaut
 * plutot que `null`. **L'ancienne expression ecrasait les deux** — elle
 * fabriquait `1` pour la cellule vide ET pour `'admni'`.
 *
 * *Verifie ici plutot que repris de la description qu'on m'en a faite : on m'a
 * annonce « cellule vide -> valeurInvalide = false », ce qui est vrai de la
 * COMPOSITION et faux de `rolePose` seule.*
 *
 * ── POURQUOI ICI ET PAS AU BANC ────────────────────────────────────────────
 *
 * Les deux fonctions sont PURES — aucun `DB::` dans leur corps, temoin : 28
 * occurrences ailleurs dans le meme fichier. Ni compte jetable, ni base, ni
 * fenetre de banc. Et la table s'EPUISE, la ou un parcours de navigateur n'en
 * mesure qu'un chemin.
 */
class RolePoseTest extends TestCase
{
    private Comptes $comptes;

    protected function setUp(): void
    {
        parent::setUp();
        $this->comptes = app(Comptes::class);
    }

    /**
     * LA TABLE DE VERITE, EPUISEE — les TROIS membres a chaque ligne.
     *
     * Ecrite a la main plutot que derivee de `ROLES` : *un releve qui se derive
     * de son objet ne mesure que lui-meme.*
     *
     * @return array<string, array{0: ?int, 1: int, 2: int, 3: bool, 4: bool}>
     */
    public static function table(): array
    {
        return [
            //                                   demande, auteur, role, invalide, ramene
            'un superadmin pose un superadmin'      => [3, 3, 3, false, false],
            'un superadmin pose un admin'           => [2, 3, 2, false, false],
            'un superadmin pose un utilisateur'     => [1, 3, 1, false, false],

            // ⚠ LE CAS QUI A FAIT ECRIRE LA REGLE : un admin ne fabrique pas un
            // superadmin, sinon il prend le controle par le magic-link.
            'un admin tente un superadmin'          => [3, 2, 1, false, true],
            // Egal n'est pas inferieur.
            'un admin tente un admin'               => [2, 2, 1, false, true],
            'un admin pose un utilisateur'          => [1, 2, 1, false, false],

            'un utilisateur tente un superadmin'    => [3, 1, 1, false, true],
            'un utilisateur tente un admin'         => [2, 1, 1, false, true],
            'un utilisateur tente un utilisateur'   => [1, 1, 1, false, true],

            // ── LES QUATRE COMBINAISONS DE DRAPEAUX ────────────────────────
            // La valeur invalide devient le plancher, ET l'autorisation peut
            // ensuite refuser CE plancher. Les deux vraies a la fois.
            'valeur invalide, par un superadmin'    => [99, 3, 1, true, false],
            'valeur invalide, par un admin'         => [99, 2, 1, true, false],
            'valeur invalide, par un utilisateur'   => [99, 1, 1, true, true],
            'null, par un superadmin'               => [null, 3, 1, true, false],
            'null, par un utilisateur'              => [null, 1, 1, true, true],
            'un role negatif, par un superadmin'    => [-1, 3, 1, true, false],
            'le role zero, par un admin'            => [0, 2, 1, true, false],
        ];
    }

    public function test_la_table_de_verite(): void
    {
        // Une BOUCLE et non un `@dataProvider` : PHPUnit ne le reconnait pas
        // dans ce projet et appelle la methode SANS argument. Rencontre deux
        // fois, refait une fois.
        foreach (self::table() as $nom => [$demande, $auteur, $role, $invalide, $ramene]) {
            $pose = $this->comptes->rolePose($demande, $auteur);

            $this->assertSame(
                [$role, $invalide, $ramene],
                [$pose->role, $pose->valeurInvalide, $pose->rangRamene],
                "« $nom » : rolePose(" . var_export($demande, true) . ", $auteur)");
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // LES QUATRE COMBINAISONS SONT TOUTES ATTEIGNABLES
    // ══════════════════════════════════════════════════════════════════════

    public function test_les_deux_drapeaux_sont_INDEPENDANTS(): void
    {
        /*
         * Deux booleens ne valent mieux qu'un que si les QUATRE etats existent.
         * Si l'un impliquait l'autre, le second serait redondant — et un lecteur
         * finirait par n'en lire qu'un.
         */
        $vus = [];
        foreach ([null, -1, 0, 1, 2, 3, 99] as $demande) {
            foreach (Comptes::ROLES as $auteur) {
                $p = $this->comptes->rolePose($demande, $auteur);
                $vus[($p->valeurInvalide ? 'V' : 'v') . ($p->rangRamene ? 'R' : 'r')] = true;
            }
        }

        // (Un « garde-fou de forme » figurait ici : une assertion tautologique
        // que j'avais ecrite sans la relire. Elle passait toujours et ne
        // mesurait rien — retiree plutot que gardee pour le compte.)
        foreach (['VR', 'Vr', 'vR', 'vr'] as $combinaison) {
            $this->assertArrayHasKey($combinaison, $vus,
                "la combinaison « $combinaison » (valeurInvalide/rangRamene) n'est "
                . "atteinte par AUCUN couple : si un drapeau en implique un autre, "
                . 'le second est redondant et cessera d\'etre lu');
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // LA DISTINCTION QUE L'ANCIENNE EXPRESSION ECRASAIT
    // ══════════════════════════════════════════════════════════════════════

    public function test_une_cellule_VIDE_n_est_pas_une_valeur_invalide(): void
    {
        /*
         * ⚠ LA PROPRIETE VIT DANS LA COMPOSITION, pas dans `rolePose`.
         *
         * `rolePose(null, 3)` rend `valeurInvalide = true` — mesure, pas
         * lecture. Ce qui distingue l'absence est `roleDuLibelle('')`, qui rend
         * le role par DEFAUT au lieu de `null`. Personne n'a rien demande : ce
         * n'est pas une coercition, et l'annoncer comme telle ferait crier au
         * loup sur chaque ligne d'un CSV sans colonne `role`.
         */
        $pose = $this->comptes->rolePose(Comptes::roleDuLibelle(''), 3);

        $this->assertFalse($pose->valeurInvalide,
            "une cellule VIDE est signalee comme une valeur invalide : la "
            . "distinction que E-399 introduit est perdue");
        $this->assertSame(Comptes::IMPORT_ROLES[Comptes::IMPORT_ROLE_DEFAUT],
            $pose->role);
    }

    public function test_un_libelle_INCONNU_est_bien_une_valeur_invalide(): void
    {
        // Le contre-cas de la precedente : sans lui, un `roleDuLibelle` qui
        // rendrait TOUJOURS le defaut passerait le test d'au-dessus.
        $pose = $this->comptes->rolePose(Comptes::roleDuLibelle('admni'), 3);

        $this->assertTrue($pose->valeurInvalide, "« admni » passe pour un role");
        $this->assertSame(Comptes::ROLE_PLANCHER, $pose->role);
    }

    public function test_les_libelles_connus_se_traduisent(): void
    {
        foreach (Comptes::IMPORT_ROLES as $libelle => $attendu) {
            $this->assertSame($attendu, Comptes::roleDuLibelle($libelle), $libelle);
            $this->assertSame($attendu, Comptes::roleDuLibelle(strtoupper($libelle)),
                "la casse fait echouer « $libelle »");
            $this->assertSame($attendu, Comptes::roleDuLibelle("  $libelle  "),
                "les espaces font echouer « $libelle »");
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // LES PROPRIETES QUI SURVIVENT A L'AJOUT D'UN ROLE
    // ══════════════════════════════════════════════════════════════════════

    public function test_aucun_auteur_ne_pose_un_role_SUPERIEUR_au_sien(): void
    {
        foreach (Comptes::ROLES as $auteur) {
            foreach ([null, -1, 0, 1, 2, 3, 4, 99] as $demande) {
                $this->assertLessThanOrEqual($auteur,
                    $this->comptes->rolePose($demande, $auteur)->role,
                    'un auteur de role ' . $auteur . ' a obtenu davantage');
            }
        }
    }

    public function test_seul_un_superadmin_pose_son_PROPRE_role(): void
    {
        // « Strictement inferieur » pour les autres : c'est ce que casse la
        // mutation `<` -> `<=` ou `>=` -> `>`.
        foreach ([1, 2] as $auteur) {
            $p = $this->comptes->rolePose($auteur, $auteur);
            $this->assertSame(Comptes::ROLE_PLANCHER, $p->role,
                "un auteur de role $auteur a pu poser son propre role");
            $this->assertTrue($p->rangRamene,
                "la reduction n'est pas annoncee pour un auteur de role $auteur");
        }

        $p = $this->comptes->rolePose(3, 3);
        $this->assertSame(3, $p->role);
        $this->assertFalse($p->rangRamene);
    }

    public function test_le_role_pose_est_TOUJOURS_une_valeur_de_la_liste(): void
    {
        foreach ([null, -99, -1, 0, 4, 99, PHP_INT_MAX] as $demande) {
            foreach (Comptes::ROLES as $auteur) {
                $this->assertContains(
                    $this->comptes->rolePose($demande, $auteur)->role,
                    Comptes::ROLES,
                    'rolePose(' . var_export($demande, true) . ", $auteur) sort de ROLES");
            }
        }
    }

    public function test_le_plancher_est_le_MOINS_privilegie(): void
    {
        // Ce que la coercition vaut depend entierement de cette valeur : un
        // plancher a 2 rendrait chaque refus PROMOTEUR.
        $this->assertSame(min(Comptes::ROLES), Comptes::ROLE_PLANCHER,
            'le plancher de coercition n\'est plus le role le moins privilegie');
    }
}
