<?php

namespace Tests\Feature;

use App\Services\Comptes;
use Tests\TestCase;

/**
 * E-385 — le role qu'un auteur est REELLEMENT autorise a poser.
 *
 * LA REGLE, reprise de `manage_users.php:92` : un non-superadministrateur ne
 * pose qu'un role STRICTEMENT INFERIEUR au sien. Le commentaire du legacy dit
 * l'incident qui l'a fait ecrire — quelqu'un « creait un superadmin, recevait le
 * magic-link sur son email et prenait le controle ».
 *
 * ⚠ DEUX PROPRIETES QU'IL NE FAUT PAS CONFONDRE, et E-385 vient de ce que seule
 * la premiere etait verifiee :
 *
 *     `ROLES`          borne a des valeurs VALIDES
 *     `roleAutorise`   borne a des valeurs PERMISES
 *
 * ── POURQUOI ICI PLUTOT QU'AU BANC ─────────────────────────────────────────
 *
 * `roleAutorise` est PURE : aucun `DB::` dans son corps — temoin, 28 occurrences
 * ailleurs dans le meme fichier, donc une sonde qui n'en voit aucune ICI voit
 * bien. Elle ne demande donc ni compte jetable, ni base, ni fenetre de banc.
 *
 * **Et la table s'EPUISE**, la ou un parcours de navigateur n'en mesure qu'un
 * chemin. Le jour ou quelqu'un ajoute un role 4, c'est ce fichier qui rougit.
 *
 * ── CE QUE CHAQUE CAS ASSERTE, ET C'EST LE TUPLE ENTIER ────────────────────
 *
 * Le second membre — « le role a ete ABAISSE » — est ce que l'ecran doit
 * annoncer. Le legacy en porte TROIS implementations dont **deux annoncent la
 * coercition et la troisieme est muette** : asserter le seul role effectif
 * laisserait revenir la version muette sans qu'aucun test ne bouge.
 */
class RoleAutoriseTest extends TestCase
{
    private Comptes $comptes;

    protected function setUp(): void
    {
        parent::setUp();
        $this->comptes = app(Comptes::class);
    }

    /**
     * LA TABLE DE VERITE, EPUISEE — et le tuple ENTIER a chaque ligne.
     *
     * Elle est ecrite a la main plutot que derivee d'une boucle sur `ROLES` :
     * une table derivee de la meme constante que le code ne peut pas contredire
     * le code. *Un releve qui se derive de son objet ne mesure que lui-meme.*
     *
     * @return array<string, array{0: int, 1: int, 2: int, 3: bool}>
     */
    public static function table(): array
    {
        return [
            // demande, auteur, role effectif attendu, abaisse ?
            'un superadmin pose un superadmin'      => [3, 3, 3, false],
            'un superadmin pose un admin'           => [2, 3, 2, false],
            'un superadmin pose un utilisateur'     => [1, 3, 1, false],

            // ⚠ LE CAS QUI A FAIT ECRIRE LA REGLE : un admin ne fabrique pas
            // un superadmin, sinon il prend le controle par le magic-link.
            'un admin tente un superadmin'          => [3, 2, 1, true],
            // Egal n'est pas inferieur : un admin ne pose pas un admin.
            'un admin tente un admin'               => [2, 2, 1, true],
            'un admin pose un utilisateur'          => [1, 2, 1, false],

            // Un utilisateur ne pose rien au-dessus de rien : tout est >= 1.
            'un utilisateur tente un superadmin'    => [3, 1, 1, true],
            'un utilisateur tente un admin'         => [2, 1, 1, true],
            'un utilisateur tente un utilisateur'   => [1, 1, 1, true],

            // ⚠ VALEUR HORS LISTE : ramenee a 1 par `ROLES`, et le drapeau
            // reste FAUX pour TOUT auteur — j'avais ecrit `true` pour l'admin,
            // par raisonnement et non par mesure. La coercition de VALIDITE est
            // silencieuse ; seule celle d'AUTORISATION s'annonce.
            'un admin tente un role inexistant'     => [99, 2, 1, false],
            'un superadmin tente un role inexistant' => [99, 3, 1, false],
            'un role negatif, par un superadmin'    => [-1, 3, 1, false],
            'le role zero, par un admin'            => [0, 2, 1, false],
        ];
    }

    public function test_la_table_de_verite(): void
    {
        // Une BOUCLE et non un `@dataProvider` : PHPUnit ne reconnait pas
        // l'annotation dans ce projet et appelle la methode SANS argument —
        // `ArgumentCountError`, un rouge qui ne parle pas de la propriete
        // testee. Deja rencontre sur `PorteeAllRetireeTest`, et je l'ai refait.
        // *Un test qui echoue pour une raison etrangere a sa propriete ne
        // mesure pas sa propriete.*
        foreach (self::table() as $nom => [$demande, $auteur, $attendu, $abaisse]) {
            $obtenu = $this->comptes->roleAutorise($demande, $auteur);

            $this->assertSame([$attendu, $abaisse], $obtenu,
                "« $nom » : roleAutorise($demande, $auteur) rend "
                . json_encode($obtenu) . ' au lieu de '
                . json_encode([$attendu, $abaisse]));
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // LES PROPRIETES QUI TIENNENT MEME SI LA TABLE CHANGE
    // ══════════════════════════════════════════════════════════════════════

    public function test_aucun_auteur_ne_pose_un_role_SUPERIEUR_au_sien(): void
    {
        // La propriete generale, balayee sur tout ce qu'un appelant peut
        // envoyer — y compris hors liste. Elle survit a l'ajout d'un role.
        foreach (Comptes::ROLES as $auteur) {
            foreach ([-1, 0, 1, 2, 3, 4, 99] as $demande) {
                [$effectif, ] = $this->comptes->roleAutorise($demande, $auteur);

                $this->assertLessThanOrEqual($auteur, $effectif,
                    "un auteur de role $auteur a obtenu le role $effectif");
            }
        }
    }

    public function test_seul_un_superadmin_pose_son_PROPRE_role(): void
    {
        // « Strictement inferieur » pour les autres : c'est ce que la mutation
        // `<` -> `<=` ou `>=` -> `>` casse, et c'est le coeur de la regle.
        foreach ([1, 2] as $auteur) {
            [$effectif, $abaisse] = $this->comptes->roleAutorise($auteur, $auteur);

            $this->assertSame(1, $effectif,
                "un auteur de role $auteur a pu poser son propre role");
            $this->assertTrue($abaisse,
                "l'abaissement n'est pas annonce pour un auteur de role $auteur");
        }

        [$effectif, $abaisse] = $this->comptes->roleAutorise(3, 3);
        $this->assertSame(3, $effectif, 'un superadmin ne peut plus poser un superadmin');
        $this->assertFalse($abaisse, 'un superadmin verrait un abaissement qui n\'a pas eu lieu');
    }

    public function test_le_role_effectif_est_TOUJOURS_une_valeur_de_la_liste(): void
    {
        foreach ([-99, -1, 0, 4, 99, PHP_INT_MAX] as $demande) {
            foreach (Comptes::ROLES as $auteur) {
                [$effectif, ] = $this->comptes->roleAutorise($demande, $auteur);

                $this->assertContains($effectif, Comptes::ROLES,
                    "roleAutorise($demande, $auteur) rend $effectif, hors de ROLES");
            }
        }
    }

    public function test_le_drapeau_suit_la_COERCITION_DE_ROLE_et_non_la_validite(): void
    {
        /*
         * ⚠ CE TEST MESURE, IL NE BENIT PAS — et il a corrige mon attendu.
         *
         * J'avais ecrit la propriete comme une EQUIVALENCE : le drapeau vrai
         * exactement quand le role rendu differe du role VALIDE demande. Le code
         * ne la satisfait pas, et la mesure le dit :
         *
         *     roleAutorise(99, 3)  ->  [1, false]
         *     roleAutorise(99, 2)  ->  [1, false]
         *     roleAutorise(0,  2)  ->  [1, false]
         *
         * LE DRAPEAU NE RAPPORTE QUE LA SECONDE COERCITION — celle de
         * l'AUTORISATION — jamais la premiere, celle de la VALIDITE (`ROLES`).
         * Une valeur hors liste devient donc le role 1 EN SILENCE, POUR TOUT
         * AUTEUR, superadministrateur compris.
         *
         * ⚠ ET J'AI ECRIT DEUX LIGNES DE LA TABLE PAR RAISONNEMENT ET NON PAR
         * MESURE : j'attendais `[1, true]` pour `(99, 2)` et `(0, 2)`, en
         * supposant que « les deux bornes se composent ». Elles ne se composent
         * pas — la seconde compare le role DEJA ramene a 1, donc `1 >= 2` est
         * faux et le drapeau reste bas. Troisieme fois aujourd'hui qu'un
         * attendu ecrit de tete est corrige par la sortie.
         *
         * Est-ce un defaut ? Ce n'est pas a moi de le dire : les deux
         * coercitions n'ont pas le meme sens, et n'annoncer que celle qui
         * REFUSE se defend. **Transmis, non tranche.** Ce test verrouille le
         * comportement OBSERVE avec sa question ecrite : s'il rougit, la
         * question a ete repondue — remplacer alors le test par la regle
         * retenue, ne pas le contourner.
         */
        foreach (Comptes::ROLES as $auteur) {
            foreach ([-99, -1, 0, 4, 99] as $demande) {
                [$effectif, $abaisse] = $this->comptes->roleAutorise($demande, $auteur);

                $this->assertSame(1, $effectif,
                    "une valeur hors liste doit etre ramenee a 1 "
                    . "(demande $demande, auteur $auteur)");

                // ⚠ ET LE DRAPEAU DEPEND DE L'AUTEUR, PAS DE LA DEMANDE.
                // Auteur 1 : le role ramene (1) est `>= 1`, donc la regle
                // d'AUTORISATION mord et annonce — un auteur de role 1 voit
                // donc TOUJOURS un abaissement, meme quand il demande 1.
                // Auteurs 2 et 3 : `1 >= 2` et la seconde borne ne s'applique
                // pas au superadmin, donc SILENCE.
                $this->assertSame($auteur === 1, $abaisse,
                    "roleAutorise($demande, $auteur) : le drapeau vaut "
                    . var_export($abaisse, true) . ' — la coercition de VALIDITE '
                    . "n'est annoncee que lorsque la regle d'AUTORISATION mord "
                    . 'par ailleurs. Si ce rouge apparait, la politique a change : '
                    . 'remplacer ce test par la regle retenue, il verrouillait une '
                    . 'OBSERVATION et non une intention.');
            }
        }
    }

    public function test_le_drapeau_est_VRAI_chaque_fois_qu_un_role_est_REFUSE(): void
    {
        /*
         * La moitie de la propriete qui, elle, EST arbitree : quand la regle
         * d'autorisation mord, l'ecran doit l'annoncer. Le legacy en porte une
         * version MUETTE (`import_csv:156`) — asserter le seul role effectif
         * laisserait cette version revenir sans qu'aucun test ne bouge.
         */
        foreach ([1, 2] as $auteur) {
            foreach (Comptes::ROLES as $demande) {
                [$effectif, $abaisse] = $this->comptes->roleAutorise($demande, $auteur);

                if ($demande >= $auteur) {
                    $this->assertSame(1, $effectif,
                        "un auteur de role $auteur a obtenu le role $demande");
                    $this->assertTrue($abaisse,
                        "le refus du role $demande a un auteur de role $auteur "
                        . "n'est PAS annonce : l'ecran serait muet sur une "
                        . 'coercition, comme `import_csv:156` du legacy');
                } else {
                    $this->assertSame($demande, $effectif);
                    $this->assertFalse($abaisse,
                        "un abaissement est annonce alors que le role $demande "
                        . "a bien ete accorde a un auteur de role $auteur");
                }
            }
        }
    }
}
