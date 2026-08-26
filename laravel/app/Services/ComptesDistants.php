<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Les comptes distants d'une machine — module `adm/`, sous-lot D8.
 *
 * Porte `legacy/adm/server_users.php`. **PREMIERE ECRITURE DISTANTE d'`adm/`.**
 *
 * ══ CE QUI SE LIT EN BASE, ET CE QUI DOIT JOINDRE LA MACHINE ══════════════
 *
 * Le scan (`POST /scan_server_users`) ouvre une session SSH, enumere les comptes
 * de la machine et remplit `server_user_inventory` et `server_user_ssh_keys`.
 * **Tout l'affichage se lit ensuite en base** : la page n'a aucune raison de
 * joindre la machine pour montrer ce qu'un scan anterieur a deja releve.
 *
 * Seuls QUATRE gestes joignent la machine, et ils passent par la passerelle :
 *
 *   `/scan_server_users`   enumere              — LIT
 *   `/server_user_keys`    detaille les cles    — LIT
 *   `/remove_user_keys`    efface les cles      — **MODIFIE**
 *   `/sshd_allow_user`     modifie sshd_config  — **MODIFIE**
 *   `/delete_remote_user`  `userdel`            — **DETRUIT, irreversible**
 *
 * ══ LE CLASSEMENT S'ECRIT EN BASE, COMME LE CYCLE DE VIE ══════════════════
 *
 * `POST /admin/user_inventory/classify` ne fait qu'un `UPDATE` sur
 * `server_user_inventory` — aucun effet distant. Meme decision que D6d pour
 * `/server_lifecycle` et que V4 pour `supervision_config` : il n'y a rien a
 * heriter d'un aller-retour.
 *
 * UNE DIFFERENCE MERITE D'ETRE NOTEE, parce qu'elle explique pourquoi ce
 * geste-la n'a PAS le defaut E-133. La route de classement ecrit
 * `reviewed_at = NOW()` en plus du statut : une ligne existante compte donc
 * TOUJOURS comme modifiee, et son `rowcount == 0` ne peut signifier que
 * « ligne absente ». `/server_lifecycle`, qui n'ecrit que la valeur changee,
 * confond « rien a changer » et « machine absente ». La justesse vient ici d'un
 * effet de bord, pas d'une intention — on la garde, en la nommant.
 *
 * ══ TROIS STATUTS SE POSENT, QUATRE EXISTENT ══════════════════════════════
 *
 * `server_user_inventory.status` est un `enum` de QUATRE valeurs, et la liste
 * fermee du backend (`VALID_INVENTORY_STATUS`) n'en accepte que TROIS :
 * `pending_review` se pose au scan et **ne se repose jamais**. C'est coherent —
 * « pas encore examine » n'est pas une decision qu'on prend — mais cela veut
 * dire qu'un classement est SANS RETOUR : on ne remet pas un compte en attente
 * d'examen. La page doit le dire.
 */
class ComptesDistants
{
    /** Reprise de `VALID_INVENTORY_STATUS` (`backend/routes/admin.py:311`). */
    public const STATUTS = ['managed', 'excluded', 'unmanaged'];

    /**
     * Le statut que le scan pose et qu'aucun classement ne restaure.
     *
     * Il n'est pas dans `STATUTS` : le proposer serait offrir un geste que le
     * backend refuse, et que la base accepterait pourtant.
     */
    public const STATUT_INITIAL = 'pending_review';

    /** `managed_by` derive du statut, exactement comme le backend le derive. */
    private const GESTIONNAIRE = [
        'managed' => 'rootwarden',
        'excluded' => 'manual',
        'unmanaged' => 'external',
    ];

    /**
     * L'inventaire d'une machine, tel que le dernier scan l'a laisse.
     *
     * @return list<array<string, mixed>>
     */
    public function inventaire(int $machine): array
    {
        return DB::table('server_user_inventory')
            ->where('machine_id', $machine)
            ->select('id', 'username', 'uid', 'home_dir', 'shell', 'status', 'managed_by',
                'keys_count', 'has_platform_key', 'first_seen_at', 'last_seen_at',
                'reviewed_by', 'reviewed_at', 'notes')
            ->orderBy('username')
            ->get()->map(static fn ($u) => (array) $u)->all();
    }

    /**
     * Le compte des comptes en attente d'examen — ce qui justifie un geste.
     *
     * Un « 0 » s'enonce plutot que de s'afficher : « aucun compte n'attend
     * d'examen » dit quelque chose, un zero ne dit rien.
     */
    public function enAttente(int $machine): int
    {
        return (int) DB::table('server_user_inventory')
            ->where('machine_id', $machine)
            ->where('status', self::STATUT_INITIAL)
            ->count();
    }

    /**
     * Les cles d'un compte distant, telles que le dernier scan les a relevees.
     *
     * ON NE REND QUE L'EMPREINTE, JAMAIS LA CLE. La table ne stocke d'ailleurs
     * que `fingerprint_sha256` — il n'y a rien d'autre a rendre, et c'est le
     * bon choix : une cle publique n'est pas un secret, mais la lister en clair
     * dans une page d'administration n'apporte rien qu'une empreinte n'apporte.
     *
     * @return list<array<string, mixed>>
     */
    public function cles(int $machine, string $username): array
    {
        return DB::table('server_user_ssh_keys')
            ->where('machine_id', $machine)->where('username', $username)
            ->select('id', 'key_type', 'fingerprint_sha256', 'comment', 'is_platform_key', 'last_seen_at')
            ->orderBy('id')
            ->get()->map(static fn ($k) => (array) $k)->all();
    }

    /**
     * Classe un compte, EN BASE.
     *
     * @return string 'introuvable' | 'statut_refuse' | 'fait'
     */
    public function classe(int $machine, string $username, string $statut, int $auteur, string $notes = ''): string
    {
        if (! in_array($statut, self::STATUTS, true)) {
            return 'statut_refuse';
        }

        // LA LIGNE EST RESOLUE AVANT D'ETRE MUTEE. Le backend s'en remet a son
        // `rowcount`, ce qui marche ici par un effet de bord (`reviewed_at =
        // NOW()`) mais ne marche pas ailleurs (E-133). On ne s'appuie pas sur
        // un accident.
        $existe = DB::table('server_user_inventory')
            ->where('machine_id', $machine)->where('username', $username)->exists();
        if (! $existe) {
            return 'introuvable';
        }

        DB::table('server_user_inventory')
            ->where('machine_id', $machine)->where('username', $username)
            ->update([
                'status' => $statut,
                'managed_by' => self::GESTIONNAIRE[$statut],
                'notes' => $notes === '' ? null : mb_substr($notes, 0, 500),
                'reviewed_by' => $auteur,
                'reviewed_at' => now(),
            ]);

        return 'fait';
    }

    /**
     * Classe d'un coup tous les comptes EN ATTENTE d'une machine.
     *
     * @return int le nombre de comptes reellement classes
     */
    public function classeLesEnAttente(int $machine, string $statut, int $auteur): int
    {
        if (! in_array($statut, self::STATUTS, true)) {
            return 0;
        }

        return DB::table('server_user_inventory')
            ->where('machine_id', $machine)->where('status', self::STATUT_INITIAL)
            ->update([
                'status' => $statut,
                'managed_by' => self::GESTIONNAIRE[$statut],
                'reviewed_by' => $auteur,
                'reviewed_at' => now(),
            ]);
    }
}
