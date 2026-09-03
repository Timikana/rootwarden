<?php

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\Support\TableDesGardes;
use Tests\TestCase;

/**
 * LES REFUS, MESURES SUR LES VRAIES ROUTES.
 *
 * `InventaireDesGardesTest` mesure ce que les routes DECLARENT. Celui-ci mesure
 * ce qu'elles FONT — les deux ne se remplacent pas : un middleware declare mais
 * casse declarerait juste et laisserait passer.
 *
 * Trois proprietes, et chacune s'arrete AVANT le controleur. C'est la condition
 * pour que ces tests soient hermetiques : aucune base MySQL, aucun backend.
 *
 *   1. sans session          → redirection vers la connexion, sur les 84 routes
 *   2. role insuffisant      → 403, et c'est le garde de ROLE qui l'a dit
 *   3. permission absente    → 403, c'est le garde de PERMISSION qui l'a dit,
 *                              et il a REELLEMENT interroge les droits
 *
 * ── POURQUOI ON N'ASSERTE PAS LE STATUT SEUL ─────────────────────────────────
 *
 * Un 403 ne dit pas QUI a refuse. Une route dont le garde `perm:` disparaitrait
 * pourrait rendre 403 pour une autre raison, et l'assertion resterait verte —
 * la forme d'echec la plus couteuse, un vert qui ne mesure plus rien. On lit
 * donc l'exception portee par la reponse : son message nomme le garde. Et pour
 * la permission, on verifie en plus que le double des droits a ete CONSULTE.
 *
 * ── CE QUI N'EST PAS ICI ─────────────────────────────────────────────────────
 *
 * Le chemin AUTORISE — « ce compte passe » — ne peut pas etre mesure sur une
 * vraie route sans la base et le backend : le controleur s'executerait. Il est
 * mesure sur des routes temporaires portant les memes combinaisons de gardes,
 * dans `CombinaisonsDeGardesTest`.
 */
class GardesDeRoutesTest extends TestCase
{
    // ─────────────────────────────────────────────────────────────────────────
    // 1. Sans session
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    #[DataProvider('routesAuthentifiees')]
    public function un_visiteur_est_renvoye_a_la_connexion(string $methode, string $uri): void
    {
        $reponse = $this->visiteur()->call($methode, '/' . TableDesGardes::chemin($uri));

        $reponse->assertRedirect(route('connexion', absolute: false));

        // Une redirection n'est une garde que si RIEN n'a ete lu au passage.
        // Un garde qui interrogerait les droits d'un visiteur travaillerait sur
        // un identifiant de compte nul — la valeur qui a deja ouvert les lignes
        // de diffusion a un role 1 sur un autre module.
        $this->assertFalse($this->droits->aEteConsulte(),
            "$methode /$uri : les droits ont ete interroges pour un visiteur sans session");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Role insuffisant
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    #[DataProvider('rolesInsuffisants')]
    public function un_role_insuffisant_est_refuse(string $methode, string $uri, int $role, string $exige): void
    {
        // Toutes les permissions du portail sont accordees a ce compte : si le
        // refus tient quand meme, c'est bien le ROLE qui l'a produit, et non une
        // permission absente. Sans cette precaution le test passerait pour la
        // mauvaise raison.
        $reponse = $this->connecte($role, self::TOUTES_LES_PERMISSIONS)
            ->call($methode, '/' . TableDesGardes::chemin($uri));

        $reponse->assertStatus(403);

        $this->assertInstanceOf(HttpException::class, $reponse->exception,
            "$methode /$uri : le 403 n'est pas un refus d'acces");

        $this->assertSame(__('acces.role_insuffisant'), $reponse->exception->getMessage(),
            "$methode /$uri exige $exige : le refus oppose a un role $role doit venir du garde de ROLE");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Permission absente
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    #[DataProvider('permissionsRefusables')]
    public function une_permission_absente_est_refusee(string $methode, string $uri, int $role, string $permission): void
    {
        // Le compte a le ROLE exige et AUCUNE permission : seul le garde de
        // permission peut refuser.
        $reponse = $this->connecte($role, [])->call($methode, '/' . TableDesGardes::chemin($uri));

        $reponse->assertStatus(403);

        $this->assertInstanceOf(HttpException::class, $reponse->exception,
            "$methode /$uri : le 403 n'est pas un refus d'acces");

        $this->assertSame(__('acces.permission_manquante'), $reponse->exception->getMessage(),
            "$methode /$uri : le refus doit venir du garde de PERMISSION ($permission), pas d'ailleurs");

        // La preuve que le garde a fait son travail plutot que d'etre court-circuite.
        $this->assertSame([self::COMPTE], $this->droits->consultations,
            "$methode /$uri : les droits du compte n'ont pas ete interroges — "
            . 'le 403 vient donc d\'autre chose que du garde de permission');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fournisseurs
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Les neuf permissions que porte le compte de role 2 du banc, plus celles
     * que le portage exige ailleurs. Employees pour NEUTRALISER le garde de
     * permission quand on veut mesurer celui du role.
     */
    private const TOUTES_LES_PERMISSIONS = [
        'can_admin_portal', 'can_deploy_keys', 'can_update_linux', 'can_scan_cve',
        'can_view_compliance', 'can_manage_backups', 'can_manage_fail2ban',
        'can_manage_services', 'can_audit_ssh', 'can_manage_supervision',
        'can_manage_bashrc', 'can_manage_graylog', 'can_manage_api_keys',
        'can_manage_remote_users',
    ];

    /** @return iterable<string,array{0:string,1:string}> */
    public static function routesAuthentifiees(): iterable
    {
        foreach (TableDesGardes::authentifiees() as [$methode, $uri, $gardes]) {
            yield "$methode /$uri" => [$methode, $uri];
        }
    }

    /**
     * Un cas par (route, role trop bas). Une route `role:3` en produit DEUX —
     * le role 1 et le role 2 — parce que deux comptes distincts doivent etre
     * refuses et qu'un seul mesure ne repond que pour lui.
     *
     * @return iterable<string,array{0:string,1:string,2:int,3:string}>
     */
    public static function rolesInsuffisants(): iterable
    {
        foreach (TableDesGardes::authentifiees() as [$methode, $uri, $gardes]) {
            $exige = self::roleExige($gardes);

            for ($role = 1; $role < $exige; $role++) {
                yield "$methode /$uri (role $role < $exige)" => [$methode, $uri, $role, "role:$exige"];
            }
        }
    }

    /**
     * Un cas par route dont la permission peut REELLEMENT refuser.
     *
     * Les routes `role:3` en sont exclues, et ce n'est pas un oubli : le garde
     * `perm:` rend la main des que le role vaut 3 (« cette permission OU
     * superadmin »). Sur une route deja reservee au role 3, la permission
     * declaree ne peut donc jamais decider de rien. Le fait est mesure a part —
     * voir `ExigePermissionTest::le_role_3_court_circuite_la_permission` et la
     * liste dressee dans `InventaireDesGardesTest`.
     *
     * @return iterable<string,array{0:string,1:string,2:int,3:string}>
     */
    public static function permissionsRefusables(): iterable
    {
        foreach (TableDesGardes::authentifiees() as [$methode, $uri, $gardes]) {
            $permission = self::permissionExigee($gardes);
            $roleExige  = self::roleExige($gardes);

            if ($permission === null || $roleExige >= 3) {
                continue;
            }

            yield "$methode /$uri ($permission absente, role $roleExige)"
                => [$methode, $uri, max(1, $roleExige), $permission];
        }
    }

    /** @param  list<string>  $gardes */
    private static function roleExige(array $gardes): int
    {
        foreach ($gardes as $garde) {
            if (str_starts_with($garde, 'role:')) {
                return (int) substr($garde, 5);
            }
        }

        return 0;
    }

    /** @param  list<string>  $gardes */
    private static function permissionExigee(array $gardes): ?string
    {
        foreach ($gardes as $garde) {
            if (str_starts_with($garde, 'perm:')) {
                return substr($garde, 5);
            }
        }

        return null;
    }
}
