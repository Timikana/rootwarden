<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Les notifications in-app — module `adm/`, sous-lot D2.
 *
 * LECTURE ET ECRITURE EN BASE. `notifications` et `notification_preferences`
 * n'ont aucun effet de bord externe, et aucune route du backend Python ne les
 * expose en lecture : le portage les lit directement.
 *
 * ══ UNE SEULE REGLE DE PORTEE, POUR LA LECTURE **ET** POUR L'ECRITURE ═══════
 *
 * Le legacy en a deux, et c'est le defaut E-110. Sa lecture filtre bien — un
 * role 1 ne voit pas les lignes de diffusion (`user_id = 0`) — mais deux de ses
 * trois ecritures ne filtrent pas :
 *
 *   `delete`   (`notifications.php:125-130`)  scinde sur le role   -> correct
 *   `read`     (`:93`)   `id = ? AND (user_id = ? OR user_id = 0)` -> non
 *   `read_all` (`:108`)  `(user_id = ? OR user_id = 0)`            -> non
 *
 * Le commentaire du `case 'delete'` NOMME pourtant le probleme, et le corrige —
 * pour cette branche seulement. Mesure du 2026-08-26 : un role 1 ne voit pas la
 * ligne de diffusion et la marque pourtant lue.
 *
 * Ici la portee est calculee UNE fois, par `portee()`, et les quatre gestes s'y
 * adossent. Il ne peut plus y avoir de branche oubliee, parce qu'il n'y a plus
 * de branche.
 *
 * ══ LES DOUZE TYPES, ET LES DEUX CHEMINS QUI LES PRODUISENT ════════════════
 *
 * `notifications.type` est un `varchar(50)` sans contrainte, et QUATRE endroits
 * du legacy en enumeraient les valeurs sans s'accorder. Le partage n'est pas
 * arbitraire : il suit le chemin d'emission du backend.
 *
 *   `notify()` / `notify_admins()`  -> INSERT direct, IGNORE les preferences
 *       cve_critical · server_offline · perm_granted · perm_expired · password_expiry
 *   `notify_subscribed()`           -> filtre sur `notification_preferences`
 *       cve_scan · security_alert · ssh_audit
 *
 * La page du legacy nomme exactement les cinq premiers et affiche « Autre » pour
 * les autres — donc precisement pour ceux dont on a regle la preference. Ici,
 * `TYPES` porte les DOUZE, et un type inconnu s'affiche sous son nom brut : un
 * libelle qu'on peut diagnostiquer vaut mieux qu'un « Autre » qui ne dit rien.
 *
 * `TYPES_REGLABLES` est la sous-liste que la page de reglages propose — c'est
 * `$allowedTypes` du legacy, inchangee. Les cinq du chemin direct restent
 * inconfigurables tant que `notify()` ne consulte pas les preferences : c'est
 * une decision de comportement du backend, pas un detour de portage.
 */
class Notifications
{
    /** Les douze types que le backend peut emettre. Mesure, pas devinee. */
    public const TYPES = [
        // Chemin `notify_subscribed()` — gouverne par les preferences.
        'cve_scan', 'security_alert', 'ssh_audit',
        // Declares reglables mais jamais emis par ce chemin a ce jour.
        'compliance_report', 'backup_status', 'update_status',
        // Chemin direct `notify()` / `notify_admins()` — ignore les preferences.
        'cve_critical', 'server_offline', 'perm_granted', 'perm_expired',
        'password_expiry', 'info',
    ];

    /** Ce que la page de reglages propose — `$allowedTypes` du legacy, tel quel. */
    public const TYPES_REGLABLES = [
        'cve_scan', 'ssh_audit', 'compliance_report',
        'security_alert', 'backup_status', 'update_status',
    ];

    /** Les types que le backend emet SANS consulter les preferences. */
    public const TYPES_INCONDITIONNELS = [
        'cve_critical', 'server_offline', 'perm_granted', 'perm_expired', 'password_expiry',
    ];

    public const PAR_PAGE = 20;

    /**
     * La portee d'un compte, appliquee IDENTIQUEMENT en lecture et en ecriture.
     *
     * Role >= 2 : ses lignes et les diffusions. Role 1 : ses lignes seules — il
     * ne les voit pas, il ne doit donc pas les toucher.
     */
    private function portee(\Illuminate\Database\Query\Builder $q, int $userId, int $roleId): \Illuminate\Database\Query\Builder
    {
        // FAIL-CLOSED SUR L'ABSENCE D'IDENTIFIANT, et ce n'est pas une precaution
        // theorique : `user_id = 0` est la valeur des lignes de DIFFUSION. Sans
        // ce garde, une session dont l'identifiant ne se lit pas ne se voit pas
        // refuser l'acces — elle recoit EXACTEMENT les diffusions. Un garde sans
        // objet ne garde rien ; ici il accorderait. Mesure du 2026-08-26 : c'est
        // arrive, en lisant `user_id` la ou la session ecrit `utilisateur_id`.
        if ($userId <= 0) {
            return $q->whereRaw('1 = 0');
        }
        if ($roleId >= 2) {
            return $q->where(static fn ($w) => $w->where('user_id', $userId)->orWhere('user_id', 0));
        }

        return $q->where('user_id', $userId);
    }

    private function base(int $userId, int $roleId): \Illuminate\Database\Query\Builder
    {
        return $this->portee(DB::table('notifications'), $userId, $roleId);
    }

    /* ═══ Lecture ═══════════════════════════════════════════════════════════ */

    public function nonLues(int $userId, int $roleId): int
    {
        return (int) $this->base($userId, $roleId)->whereNull('read_at')->count();
    }

    public function compte(int $userId, int $roleId, array $filtres): int
    {
        return (int) $this->filtre($this->base($userId, $roleId), $filtres)->count();
    }

    public function liste(int $userId, int $roleId, array $filtres, int $page): array
    {
        return $this->filtre($this->base($userId, $roleId), $filtres)
            ->select('id', 'type', 'title', 'message', 'link', 'read_at', 'created_at')
            ->orderByDesc('created_at')
            ->offset(max(0, ($page - 1) * self::PAR_PAGE))->limit(self::PAR_PAGE)
            ->get()->map(static fn ($n) => (array) $n)->all();
    }

    /** `type` est compare a la liste FERMEE : pas d'entree libre sur un `varchar`. */
    public function filtres(array $brut): array
    {
        $type = is_string($brut['type'] ?? null) ? $brut['type'] : '';
        $etat = is_string($brut['status'] ?? null) ? $brut['status'] : '';

        return [
            'type' => in_array($type, self::TYPES, true) ? $type : '',
            'etat' => in_array($etat, ['unread', 'read'], true) ? $etat : '',
        ];
    }

    private function filtre(\Illuminate\Database\Query\Builder $q, array $filtres): \Illuminate\Database\Query\Builder
    {
        if ($filtres['type'] !== '') {
            $q->where('type', $filtres['type']);
        }
        if ($filtres['etat'] === 'unread') {
            $q->whereNull('read_at');
        }
        if ($filtres['etat'] === 'read') {
            $q->whereNotNull('read_at');
        }

        return $q;
    }

    /* ═══ Ecriture — MEME portee ════════════════════════════════════════════ */

    /** Rend le nombre de lignes reellement touchees : 0 dit « hors de ta portee ». */
    public function marqueLue(int $id, int $userId, int $roleId): int
    {
        return $this->base($userId, $roleId)
            ->where('id', $id)->whereNull('read_at')
            ->update(['read_at' => now()]);
    }

    public function marqueToutLu(int $userId, int $roleId): int
    {
        return $this->base($userId, $roleId)->whereNull('read_at')->update(['read_at' => now()]);
    }

    public function supprime(int $id, int $userId, int $roleId): int
    {
        return $this->base($userId, $roleId)->where('id', $id)->delete();
    }

    /* ═══ Preferences ═══════════════════════════════════════════════════════ */

    /** @return array<string, bool> les types reglables, avec leur etat. */
    public function preferences(int $userId): array
    {
        $lues = DB::table('notification_preferences')
            ->where('user_id', $userId)->pluck('enabled', 'event_type');

        $sortie = [];
        foreach (self::TYPES_REGLABLES as $type) {
            $sortie[$type] = (bool) ($lues[$type] ?? false);
        }

        return $sortie;
    }

    /** Les comptes actifs, pour la page de reglages. */
    public function comptes(): array
    {
        return DB::table('users')->where('active', 1)
            ->select('id', 'name', 'role_id')->orderBy('name')
            ->get()->map(static fn ($u) => (array) $u)->all();
    }

    /**
     * Bascule une preference. Le type est verifie contre la liste FERMEE, comme
     * dans le legacy (`update_notification_prefs.php:46`) : une valeur hors
     * liste est refusee, jamais inseree.
     */
    public function definitPreference(int $userId, string $type, bool $actif): bool
    {
        if (! in_array($type, self::TYPES_REGLABLES, true)) {
            return false;
        }
        DB::table('notification_preferences')->updateOrInsert(
            ['user_id' => $userId, 'event_type' => $type],
            ['enabled' => $actif ? 1 : 0, 'updated_at' => now()],
        );

        return true;
    }
}
