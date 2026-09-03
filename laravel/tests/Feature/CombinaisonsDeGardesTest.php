<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Route as Routeur;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

/**
 * LES DEUX CHEMINS D'UNE GARDE « PERMISSION OU ROLE », ET LE CHEMIN QUI PASSE.
 *
 * `GardesDeRoutesTest` mesure les REFUS sur les vraies routes — c'est ce qu'on
 * peut mesurer sans base ni backend, parce qu'un refus s'arrete avant le
 * controleur. Le chemin AUTORISE, lui, entrerait dans le controleur : il
 * demanderait la base du banc et le backend Python.
 *
 * Il est donc mesure ici, sur des routes TEMPORAIRES portant exactement les
 * memes combinaisons de gardes, et dont le terminus est une fermeture qui rend
 * « ok ». Ce qui est mesure est la CHAINE DE GARDES, telle que le cadre la
 * compose — pas une reimplementation.
 *
 * Le partage des roles entre les deux fichiers n'est pas un pis-aller, et il
 * faut le dire clairement :
 *
 *   InventaireDesGardesTest    quelles gardes chaque route DECLARE
 *   CombinaisonsDeGardesTest   ce que chaque combinaison de gardes FAIT
 *   GardesDeRoutesTest         que les vraies routes refusent vraiment
 *
 * Les trois ensemble disent « telle route refuse tel compte ». Aucun des trois
 * seul ne le dit : le premier declarerait juste sur un middleware casse, le
 * deuxieme mesurerait une route qui n'existe pas dans le portail, le troisieme
 * ne peut pas atteindre le cas autorise.
 */
class CombinaisonsDeGardesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Un terminus qui rend une chaine reconnaissable. S'il repond, c'est que
        // TOUTES les gardes de la route ont laisse passer — et rien d'autre ne
        // peut produire ce corps.
        $terminus = fn () => 'GARDES-FRANCHIES';

        Routeur::middleware(['web', 'session.authentifiee'])
            ->get('/_epreuve/authentifiee', $terminus);

        foreach ([1, 2, 3] as $niveau) {
            Routeur::middleware(['web', 'session.authentifiee', "role:$niveau"])
                ->get("/_epreuve/role-$niveau", $terminus);

            Routeur::middleware(['web', 'session.authentifiee', "role:$niveau", 'perm:can_epreuve'])
                ->get("/_epreuve/role-$niveau-perm", $terminus);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Le chemin qui passe
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function un_role_suffisant_franchit_la_garde_de_role(): void
    {
        foreach ([[1, 1], [2, 1], [2, 2], [3, 1], [3, 2], [3, 3]] as [$role, $exige]) {
            $reponse = $this->connecte($role)->get("/_epreuve/role-$exige");

            $reponse->assertOk();
            $this->assertSame('GARDES-FRANCHIES', $reponse->getContent(),
                "un role $role doit franchir role:$exige");
        }
    }

    #[Test]
    public function le_role_1_porteur_de_la_permission_passe(): void
    {
        // PREMIER chemin de « permission OU role » : le compte n'a pas le role
        // eleve, il a la permission. C'est le cas de `/fail2ban`, `/services`,
        // `/scan-cve` et `/cles-ssh` — quatre pages ouvertes au role 1.
        $reponse = $this->connecte(1, ['can_epreuve'])->get('/_epreuve/role-1-perm');

        $reponse->assertOk();
        $this->assertSame([self::COMPTE], $this->droits->consultations,
            'la permission doit avoir ete VERIFIEE, pas supposee');
    }

    #[Test]
    public function le_role_3_court_circuite_la_permission(): void
    {
        /*
         * SECOND chemin : le compte n'a AUCUNE permission et passe quand meme,
         * parce que « perm:x » se lit « cette permission OU superadmin ».
         *
         * Ce test ne celebre pas ce comportement, il le DOCUMENTE — c'est la
         * regle du legacy, et la porter etait la decision. Sa consequence est
         * mesuree ici plutot que supposee : sur une route deja reservee au
         * role 3, la permission declaree ne peut JAMAIS decider de rien. Elle
         * n'est pas un danger ; elle est une garde qui se lit comme une
         * protection sans en etre une, et c'est pour cela qu'il faut l'ecrire.
         *
         * Les routes concernees dans le portail : les DIX-SEPT de `role:3` +
         * `perm:can_admin_portal` ou `perm:can_manage_api_keys`.
         */
        $reponse = $this->connecte(3, [])->get('/_epreuve/role-3-perm');

        $reponse->assertOk();
        $this->assertSame([], $this->droits->consultations,
            'un role 3 ne doit meme pas faire lire les permissions — le garde rend la main avant');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Les refus
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function un_role_insuffisant_est_refuse_a_chaque_niveau(): void
    {
        foreach ([[1, 2], [1, 3], [2, 3]] as [$role, $exige]) {
            $reponse = $this->connecte($role, ['can_epreuve'])->get("/_epreuve/role-$exige");

            $reponse->assertStatus(403);
            $this->assertSame(__('acces.role_insuffisant'), $reponse->exception->getMessage(),
                "role $role sur role:$exige");
        }
    }

    #[Test]
    public function un_role_suffisant_sans_la_permission_est_refuse(): void
    {
        $reponse = $this->connecte(2, [])->get('/_epreuve/role-2-perm');

        $reponse->assertStatus(403);
        $this->assertInstanceOf(HttpException::class, $reponse->exception);
        $this->assertSame(__('acces.permission_manquante'), $reponse->exception->getMessage());
        $this->assertSame([self::COMPTE], $this->droits->consultations);
    }

    #[Test]
    public function une_permission_VOISINE_n_ouvre_pas(): void
    {
        // « Un garde sans objet ne garde rien » : un jeu de permissions non vide
        // mais qui ne porte pas CELLE qu'on exige doit refuser. Un garde qui se
        // contenterait de « ce compte a des permissions » passerait ici.
        $reponse = $this->connecte(2, ['can_autre_chose', 'can_admin_portal'])
            ->get('/_epreuve/role-2-perm');

        $reponse->assertStatus(403);
    }

    #[Test]
    public function une_session_a_moitie_authentifiee_ne_franchit_rien(): void
    {
        /*
         * Entre le mot de passe et le second facteur, la session ne porte qu'un
         * `compte_temporaire`. C'est l'invariant du socle : il n'existe aucun
         * chemin sans second facteur.
         *
         * On pose ici EXACTEMENT ce que le premier facteur laisse en session, et
         * on verifie que le garde ne s'en contente pas. Un garde qui lirait
         * « une session existe » plutot que « utilisateur_id est pose »
         * laisserait passer.
         */
        $reponse = $this->visiteur()
            ->withSession(['compte_temporaire' => self::COMPTE, 'role_id' => 3])
            ->get('/_epreuve/role-1');

        $reponse->assertRedirect(route('connexion', absolute: false));
    }

    #[Test]
    public function un_role_absent_de_la_session_vaut_zero(): void
    {
        // Fail-closed sur l'absence : une session qui porte un identifiant mais
        // pas de role ne doit franchir aucun `role:`. La valeur par defaut du
        // garde est 0, et 0 est inferieur a 1.
        $reponse = $this->visiteur()
            ->withSession(['utilisateur_id' => self::COMPTE])
            ->get('/_epreuve/role-1');

        $reponse->assertStatus(403);
    }

    #[Test]
    public function un_role_ecrit_en_texte_est_compare_comme_un_nombre(): void
    {
        /*
         * Le pilote de base peut rendre `'3'` plutot que `3` selon
         * `ATTR_EMULATE_PREPARES`, et le chantier porte deja une garde du legacy
         * qui compare avec `===` sans transtyper — le motif exact d'une garde
         * morte. Ici le transtypage est explicite ; cette assertion tient ce
         * choix.
         */
        $reponse = $this->visiteur()
            ->withSession(['utilisateur_id' => self::COMPTE, 'role_id' => '3'])
            ->get('/_epreuve/role-3');

        $reponse->assertOk();
    }
}
