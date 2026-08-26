<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Les permissions fonctionnelles — module `adm/`, sous-lot D5.
 *
 * ══ UNE SEULE LISTE, ET ELLE VIENT DES COLONNES ELLES-MEMES ════════════════
 *
 * Le legacy en porte TROIS, mesurees le 2026-08-26 :
 *
 *   colonnes `can_*` de `permissions`                18
 *   posables A LA CREATION (`manage_users.php:116`)  14
 *   basculables ENSUITE (`update_permissions.php`)   16
 *
 * Et les ecarts se CROISENT — ils ne se compensent pas :
 *
 *   `can_manage_fail2ban`  creable, jamais basculable : on l'accorde et on ne
 *                          peut plus la retirer par l'interface. Elle garde
 *                          `fail2ban/` et son entree de menu SUR LES DEUX
 *                          portails.
 *   `can_manage_api_keys`  ni creable ni basculable : inatteignable dans les
 *                          deux sens, alors qu'elle garde `adm/api_keys.php`.
 *
 * Mesure en base : deux comptes portent la premiere, un porte la seconde. Ils
 * les ont recues a la creation ou par import CSV — il y a donc bien des droits
 * accordes que l'interface ne sait pas reprendre. Voir PARITE E-118.
 *
 * ICI LA LISTE EST LUE DANS LE SCHEMA. Elle ne peut pas diverger d'une table
 * ecrite a la main, parce qu'il n'y a pas de table ecrite a la main : ajouter
 * une colonne `can_*` suffit a la rendre reglable, et en retirer une la fait
 * disparaitre partout a la fois.
 *
 * L'interpolation du nom de colonne reste inevitable — PDO ne lie pas un nom de
 * colonne — mais elle est desormais bornee par le SCHEMA lui-meme, ce qui est
 * plus sur qu'une liste blanche recopiee : une liste peut vieillir, le schema
 * est la verite.
 */
class Permissions
{
    /** @var array<int, string>|null memorise pour la duree de la requete */
    private ?array $colonnes = null;

    /**
     * Les noms de colonnes `can_*` de `permissions`, lus dans le schema.
     *
     * @return array<int, string>
     */
    public function toutes(): array
    {
        if ($this->colonnes === null) {
            $this->colonnes = DB::table('information_schema.COLUMNS')
                ->where('TABLE_SCHEMA', DB::getDatabaseName())
                ->where('TABLE_NAME', 'permissions')
                ->where('COLUMN_NAME', 'like', 'can\\_%')
                ->orderBy('ORDINAL_POSITION')
                ->pluck('COLUMN_NAME')->all();
        }

        return $this->colonnes;
    }

    /** Le nom est-il une colonne REELLE ? La seule garde contre l'injection. */
    public function connue(string $nom): bool
    {
        return in_array($nom, $this->toutes(), true);
    }

    /**
     * Les permissions d'un compte, toutes les colonnes presentes, meme celles
     * qu'aucune ligne ne porte encore.
     *
     * @return array<string, bool>
     */
    public function pour(int $id): array
    {
        $ligne = DB::table('permissions')->where('user_id', $id)->first();
        $sortie = [];
        foreach ($this->toutes() as $nom) {
            $sortie[$nom] = $ligne !== null && (int) ($ligne->{$nom} ?? 0) === 1;
        }

        return $sortie;
    }

    /**
     * Bascule une permission.
     *
     * `INSERT … ON DUPLICATE KEY UPDATE`, comme le legacy : un compte sans ligne
     * dans `permissions` en obtient une au premier reglage.
     *
     * @return bool false si le nom n'est pas une colonne reelle
     */
    public function definit(int $id, string $nom, bool $actif): bool
    {
        if (! $this->connue($nom)) {
            return false;
        }
        $valeur = $actif ? 1 : 0;
        // Le nom vient de `toutes()`, donc du schema : il ne peut pas porter
        // autre chose qu'un nom de colonne existant.
        DB::statement(
            "INSERT INTO permissions (user_id, `{$nom}`) VALUES (?, ?) "
            . "ON DUPLICATE KEY UPDATE `{$nom}` = ?",
            [$id, $valeur, $valeur]
        );

        return true;
    }

    /* ═══ Acces machines ═══════════════════════════════════════════════════ */

    /**
     * Les machines auxquelles un compte a acces.
     *
     * @return array<int, int> identifiants de machines
     */
    public function machinesDe(int $id): array
    {
        return DB::table('user_machine_access')->where('user_id', $id)
            ->pluck('machine_id')->map(static fn ($m) => (int) $m)->all();
    }

    /**
     * Accorde ou retire l'acces d'un compte a une machine.
     *
     * ANTI-ESCALADE, relevee du legacy (`update_server_access.php:66`) : un role
     * inferieur a 3 ne s'accorde pas un acces a lui-meme. Le legacy ne pose
     * cette garde que sur `add` — la retirer a soi-meme ne donne rien de plus,
     * et on reprend ce choix tel quel.
     *
     * @return string|null la cle du message de refus, ou null si le geste a eu lieu
     */
    public function definitAcces(int $id, int $machine, bool $accorde, int $auteur, int $roleAuteur): ?string
    {
        if ($accorde && $id === $auteur && $roleAuteur < 3) {
            return 'perms.err_auto_acces';
        }
        if (DB::table('machines')->where('id', $machine)->doesntExist()) {
            return 'perms.err_machine';
        }
        if ($accorde) {
            DB::table('user_machine_access')->insertOrIgnore([
                'user_id' => $id, 'machine_id' => $machine,
            ]);
        } else {
            DB::table('user_machine_access')
                ->where('user_id', $id)->where('machine_id', $machine)->delete();
        }

        return null;
    }
}
