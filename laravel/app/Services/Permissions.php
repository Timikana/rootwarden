<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Les permissions fonctionnelles — module `adm/`, sous-lot D5.
 *
 * ══ UNE SEULE LISTE, ET ELLE VIENT DES COLONNES ELLES-MEMES ════════════════
 *
 * Le legacy en porte TROIS, mesurees le 2026-08-26 — et une QUATRIEME source
 * decide de l'acces sans figurer dans aucune : `temporary_permissions`, que
 * `checkPermissionFromDB` consulte et que cette page ne montre pas. Voir E-134
 * et le sous-lot D5b.
 *
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
 *                          deux sens — et elle ne garde RIEN. Sa seule
 *                          consultation du depot est `api_keys.php:20`, sur une
 *                          page dont la ligne precedente est
 *                          `checkAuth([ROLE_SUPERADMIN])` ; or
 *                          `checkPermissionFromDB` rend `true` sans condition
 *                          pour le role 3. Elle ne peut jamais decider de rien.
 *                          (Ce commentaire disait « alors qu'elle garde
 *                          `adm/api_keys.php` » : c'etait faux, corrige le
 *                          2026-08-26 apres mesure. E-118 le disait
 *                          correctement ; c'est ce resume-ci qui derivait.)
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
    /**
     * Les prereglages sudo PROPOSABLES — liste FERMEE, cote serveur.
     *
     * ⚠ CE N'EST PAS L'ENUM DE LA BASE, ET C'EST DELIBERE. `mysql/migrations/051`
     * declare SEPT valeurs ; deux d'entre elles ne peuvent pas fonctionner :
     *
     *   `systemctl_specific`  exige une liste de SERVICES. Aucune colonne de
     *                         `user_machine_access` ne la porte, et
     *                         `ssh_utils.py:958-963` ne met aucune cle `services`
     *                         dans la politique transmise.
     *   `custom`              exige `sudo_custom_rules`. Cette colonne existe
     *                         (051) et n'a AUCUN ecrivain dans tout le depot :
     *                         cinq fichiers la citent, dont deux documents, le
     *                         SELECT du collecteur et le ADD COLUMN.
     *
     * Or `sudo_manager.render_policy` leve `ValueError` dans les deux cas
     * (`:124` liste vide, `:144` regles vides), et `add_to_sudoers` rattrape
     * cette exception en repliant sur `NOPASSWD: ALL` — un repli FAIL-OPEN
     * (`configure_servers.py:369-377`).
     *
     * **Proposer ces deux valeurs serait donc offrir un bouton « donner le root
     * complet » etiquete « restreint ».** La liste sure est celle de ce que
     * `render_policy` REND, pas celle de ce que la base accepte.
     *
     * Les deux absentes se DECLARENT a l'ecran, avec leur raison — une capacite
     * retiree qui ne se declare pas est une capacite perdue en silence.
     */
    public const PRESETS = [
        'none',
        'all_nopasswd',
        'restart_services',
        'apt_only',
        'read_logs',
    ];

    /** Les deux valeurs de l'ENUM qu'on ne propose PAS, et pourquoi. */
    public const PRESETS_ABSENTS = ['systemctl_specific', 'custom'];

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

    /* ═══ Permissions TEMPORAIRES — sous-lot D5b ═══════════════════════════ */

    /**
     * Les octrois temporaires encore valides.
     *
     * ══ LU EN BASE, ACCORDE PAR LA PASSERELLE ═════════════════════════════
     *
     * `GET /admin/temp_permissions` ne fait qu'un `SELECT` avec trois jointures :
     * il n'y a rien a heriter d'un aller-retour, et la meme lecture se fait ici.
     *
     * L'OCTROI, LUI, PASSE PAR LA PASSERELLE — et c'est la seule raison qui
     * vaille : `POST /admin/temp_permissions` NOTIFIE le compte concerne
     * (`notify(type='perm_granted')`, `admin.py:196`). Reecrire l'insertion ici
     * priverait la personne de son avertissement, sans que rien ne le signale.
     * Un effet de bord qu'on ne sait pas reproduire est une raison de ne PAS
     * court-circuiter.
     *
     * LA REVOCATION, elle, n'a aucun effet de bord : `DELETE` seul. Elle s'ecrit
     * donc ici, par un formulaire — les quatre gestes de D6b ont montre ce que
     * coute un `fetch` dont le jeton n'arrive pas.
     *
     * `expires_at > NOW()` : la table garde les expires jusqu'a ce que le
     * planificateur les purge (deux fois, `scheduler.py:400` et `:782`). Les
     * montrer laisserait croire a des droits qui n'agissent plus.
     *
     * @return list<array<string, mixed>>
     */
    public function temporaires(): array
    {
        return DB::table('temporary_permissions as tp')
            ->join('users as u', 'u.id', '=', 'tp.user_id')
            ->leftJoin('users as g', 'g.id', '=', 'tp.granted_by')
            ->leftJoin('machines as m', 'm.id', '=', 'tp.machine_id')
            ->where('tp.expires_at', '>', now())
            ->select('tp.id', 'tp.permission', 'tp.reason', 'tp.expires_at', 'tp.created_at',
                'tp.machine_id', 'u.name as compte', 'u.role_id', 'g.name as accorde_par',
                'm.name as machine')
            ->orderBy('tp.expires_at')
            ->get()->map(static fn ($p) => (array) $p)->all();
    }

    /**
     * Revoque un octroi temporaire.
     *
     * @return bool false s'il n'existe pas, ou s'il avait deja expire
     */
    public function revoqueTemporaire(int $id): bool
    {
        return DB::table('temporary_permissions')
            ->where('id', $id)->where('expires_at', '>', now())
            ->delete() > 0;
    }

    /** Le libelle d'un octroi, pour l'annoncer avant de le revoquer. */
    public function libelleTemporaire(int $id): ?string
    {
        $l = DB::table('temporary_permissions as tp')
            ->join('users as u', 'u.id', '=', 'tp.user_id')
            ->where('tp.id', $id)
            ->select('tp.permission', 'u.name')->first();

        return $l === null ? null : $l->permission . ' — ' . $l->name;
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
     * Le prereglage sudo par machine, pour un compte.
     *
     * `sudo_preset` est `NOT NULL DEFAULT 'none'` (051) : une ligne d'acces
     * creee sans preglage vaut donc « aucun sudo », et le deploiement RETIRE le
     * sudo de ce compte sur cette machine. Ce n'est pas une absence de decision,
     * c'est la decision « pas de sudo » — et l'ecran doit le dire.
     *
     * @return array<int, string> machine_id => prereglage
     */
    public function presetsDe(int $id): array
    {
        /*
         * Les cles sont CASTEES en entier explicitement. `pluck()` conserve le
         * type que rend le pilote, et une cle chaine ferait tomber le
         * `?? 'none'` de la vue sur une machine qui porte pourtant un
         * privilege : l'ecran afficherait « sans sudo » sur un compte qui a le
         * sudo complet. Sur un ecran de privilege, un repli silencieux est un
         * mensonge.
         */
        $sortie = [];
        foreach (
            DB::table('user_machine_access')->where('user_id', $id)
                ->select('machine_id', 'sudo_preset')->get() as $ligne
        ) {
            $sortie[(int) $ligne->machine_id] = (string) ($ligne->sudo_preset ?: 'none');
        }

        return $sortie;
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
    public function definitAcces(
        int $id,
        int $machine,
        bool $accorde,
        int $auteur,
        int $roleAuteur,
        ?string $preset = null,
    ): ?string {
        if ($accorde && $id === $auteur && $roleAuteur < 3) {
            return 'perms.err_auto_acces';
        }
        if (DB::table('machines')->where('id', $machine)->doesntExist()) {
            return 'perms.err_machine';
        }
        if ($preset !== null && ! in_array($preset, self::PRESETS, true)) {
            return 'perms.err_preset';
        }
        if ($accorde) {
            DB::table('user_machine_access')->insertOrIgnore([
                'user_id' => $id, 'machine_id' => $machine,
            ]);
            if ($preset !== null) {
                /*
                 * `sudo_nopasswd` est DERIVE du prereglage, il ne s'offre pas.
                 *
                 * Le legacy en fait une case a cocher INDEPENDANTE
                 * (`manage_access.php:230`), ce qui autorise la paire
                 * incoherente `all_nopasswd` + `nopasswd = 0`. On ne porte pas
                 * ce choix libre, et c'est une capacite RETIREE, pas oubliee :
                 * `restart_services` sans mot de passe etait exprimable et ne
                 * l'est plus ici. Elle se declare a l'ecran.
                 *
                 * `sudo_runas` vaut 'root' cote serveur et n'est pas un champ :
                 * le legacy le valide par une expression reguliere
                 * (`update_server_access.php:117`) alors que son interface envoie
                 * TOUJOURS 'root'. Une entree libre absente ne se contourne pas.
                 */
                DB::table('user_machine_access')
                    ->where('user_id', $id)->where('machine_id', $machine)
                    ->update([
                        'sudo_preset' => $preset,
                        'sudo_nopasswd' => $preset === 'all_nopasswd' ? 1 : 0,
                        'sudo_runas' => 'root',
                    ]);
            }
        } else {
            DB::table('user_machine_access')
                ->where('user_id', $id)->where('machine_id', $machine)->delete();
        }

        return null;
    }
}
