<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Les sept collectes du rapport de conformite, et la notation de posture.
 *
 * Portage de `legacy/security/compliance_report.php`. Aucune route backend,
 * aucun SSH : tout est du SQL local, comme dans le legacy.
 *
 * CHAQUE COLLECTE FACULTATIVE EST GARDEE, ET SON ECHEC EST JOURNALISE. Le legacy
 * entoure cinq de ses requetes d'un `try { } catch (\Exception $e) {}` VIDE : une
 * table absente rend une section vide, et rien n'en garde trace. Les tables en
 * cause (`cve_remediation`, `iptables_history`, `ssh_audit_results`,
 * `supervision_agents`, `fail2ban_status`, `config_drift`) appartiennent a des
 * modules qui peuvent n'avoir jamais tourne — un vide est donc un etat NORMAL,
 * mais un vide et une erreur ne doivent pas se ressembler.
 */
class Conformite
{
    /**
     * Le parc, avec les compteurs du dernier scan CVE termine de chaque machine.
     *
     * PAS DE FILTRE SUR `lifecycle_status` : le legacy n'en a pas, et une machine
     * archivee figure donc au rapport. Repris tel quel — l'exclure retirerait des
     * lignes d'un rapport de conformite, ce qui est une decision et non un effet
     * de bord de portage. (Contrairement a la page des mises a jour, il n'y a ici
     * qu'UNE source : rien ne peut divergerau rafraichissement.)
     *
     * @return list<object>
     */
    public function serveurs(): array
    {
        $dernier = static fn (string $colonne): string =>
            "(SELECT $colonne FROM cve_scans WHERE machine_id = m.id AND status='completed'"
            . " ORDER BY scan_date DESC LIMIT 1)";

        return DB::table('machines as m')
            ->selectRaw(
                'm.id, m.name, m.ip, m.port, m.user, m.linux_version, m.status,'
                . ' m.lifecycle_status, m.online_status, m.environment, m.criticality,'
                . ' m.network_type, m.last_checked, m.last_reboot, m.maj_secu_date,'
                . ' m.maj_secu_last_exec_date, m.created_at,'
                . $dernier('scan_date') . ' as last_scan,'
                . $dernier('cve_count') . ' as cve_count,'
                . $dernier('critical_count') . ' as critical_count,'
                . $dernier('high_count') . ' as high_count'
            )
            ->orderBy('m.name')
            ->get()->all();
    }

    /**
     * Les comptes, joints a leur role.
     *
     * `totp_secret` et `ssh_key` sont selectionnes parce que le legacy les
     * selectionne, et parce qu'ils entrent dans l'antecedent de son empreinte
     * d'integrite. AUCUN DES DEUX NE SORT JAMAIS AUTREMENT QU'EN BOOLEEN —
     * verifie aux trois rendus du legacy. Voir `empreinte()` pour ce que cela
     * coute, et `PARITE.md` D-2 pour la decision en attente.
     *
     * @return list<object>
     */
    public function comptes(): array
    {
        return DB::table('users as u')
            ->join('roles as r', 'u.role_id', '=', 'r.id')
            ->select('u.name', 'u.email', 'u.active', 'u.sudo', 'u.ssh_key',
                     'u.ssh_key_updated_at', 'u.totp_secret', 'u.password_updated_at',
                     'u.created_at', 'r.name as role_name')
            ->orderBy('u.name')
            ->get()->all();
    }

    /** @return array<string,int> */
    public function remediation(): array
    {
        $stats = ['open' => 0, 'in_progress' => 0, 'resolved' => 0,
                  'accepted' => 0, 'wont_fix' => 0, 'overdue' => 0];
        try {
            foreach (DB::table('cve_remediation')
                        ->selectRaw('status, COUNT(*) as cnt')
                        ->groupBy('status')->get() as $r) {
                $stats[$r->status] = (int) $r->cnt;
            }
            $stats['overdue'] = DB::table('cve_remediation')
                ->whereRaw('deadline < CURDATE()')
                ->whereIn('status', ['open', 'in_progress'])
                ->count();
        } catch (\Throwable $e) {
            $this->manque('cve_remediation', $e);
        }
        return $stats;
    }

    /** Les dix dernieres modifications de pare-feu, avec leur AUTEUR.
     *  @return list<object> */
    public function historiqueParefeu(): array
    {
        try {
            return DB::table('iptables_history as h')
                ->join('machines as m', 'h.server_id', '=', 'm.id')
                ->select('h.server_id', 'm.name', 'h.changed_by', 'h.created_at')
                ->orderByDesc('h.created_at')->limit(10)
                ->get()->all();
        } catch (\Throwable $e) {
            $this->manque('iptables_history', $e);
            return [];
        }
    }

    /**
     * Le dernier audit sshd de chaque machine, avec ses ecarts comptes.
     *
     * `findings_json` est LU pour compter, puis JETE : il porte le detail de la
     * configuration sshd d'une machine, qui n'a rien a faire dans un rapport
     * exporte. Le legacy fait de meme (`unset`).
     *
     * @return list<object>
     */
    public function auditSsh(): array
    {
        try {
            $lignes = DB::table('ssh_audit_results as r')
                ->join('machines as m', 'r.machine_id', '=', 'm.id')
                ->select('r.machine_id', 'm.name', 'm.ip', 'r.score', 'r.grade',
                         'r.findings_json', 'r.created_at as audited_at')
                ->whereRaw('r.id = (SELECT MAX(r2.id) FROM ssh_audit_results r2'
                           . ' WHERE r2.machine_id = r.machine_id)')
                ->orderBy('r.score')
                ->get()->all();

            foreach ($lignes as $l) {
                $ecarts = json_decode($l->findings_json ?? '[]', true) ?: [];
                $l->critical_count = count(array_filter($ecarts, static fn ($f) =>
                    ($f['severity'] ?? '') === 'critical' || ($f['level'] ?? '') === 'FAIL'));
                $l->high_count = count(array_filter($ecarts, static fn ($f) =>
                    ($f['severity'] ?? '') === 'high' || ($f['level'] ?? '') === 'WARN'));
                unset($l->findings_json);
            }
            return $lignes;
        } catch (\Throwable $e) {
            $this->manque('ssh_audit_results', $e);
            return [];
        }
    }

    /** @return list<object> */
    public function agentsSupervision(): array
    {
        try {
            return DB::table('supervision_agents as sa')
                ->join('machines as m', 'sa.machine_id', '=', 'm.id')
                ->select('sa.machine_id', 'm.name', 'm.ip', 'sa.platform',
                         'sa.agent_version', 'sa.config_deployed')
                ->orderBy('m.name')->orderBy('sa.platform')
                ->get()->all();
        } catch (\Throwable $e) {
            $this->manque('supervision_agents', $e);
            return [];
        }
    }

    /**
     * La posture consolidee, serveur par serveur.
     *
     * Le bareme est celui du legacy, a l'unite pres : le score d'audit sshd s'il
     * existe, 50 sinon ; -30 pour au moins une CVE critique, sinon -15 pour au
     * moins une CVE haute ; -15 sans fail2ban installe ; -10 par derive de
     * configuration, plafonne a -30. Borne a [0,100], puis une lettre A-F.
     *
     * Le tri est CROISSANT : ce qui va le plus mal se lit en premier.
     *
     * @param  list<object>  $serveurs
     * @param  list<object>  $auditSsh
     * @return list<array{name:string,ip:string,score:int,grade:string,reasons:string}>
     */
    public function posture(array $serveurs, array $auditSsh): array
    {
        $sshParMachine = [];
        foreach ($auditSsh as $a) { $sshParMachine[$a->machine_id] = $a; }

        $f2bParMachine = [];
        try {
            foreach (DB::table('fail2ban_status')->select('server_id', 'installed', 'running')->get() as $f) {
                $f2bParMachine[$f->server_id] = $f;
            }
        } catch (\Throwable $e) {
            $this->manque('fail2ban_status', $e);
        }

        $deriveParMachine = [];
        try {
            foreach (DB::table('config_drift')
                        ->selectRaw("machine_id, SUM(status = 'drift') AS dc")
                        ->groupBy('machine_id')->get() as $d) {
                $deriveParMachine[$d->machine_id] = (int) $d->dc;
            }
        } catch (\Throwable $e) {
            $this->manque('config_drift', $e);
        }

        $posture = [];
        foreach ($serveurs as $s) {
            $score = isset($sshParMachine[$s->id]) ? (int) $sshParMachine[$s->id]->score : 50;
            $ecarts = [];
            if (! isset($sshParMachine[$s->id])) {
                $ecarts[] = __('conformite.ecart_sshd_non_audite');
            }
            $crit = (int) ($s->critical_count ?? 0);
            $haut = (int) ($s->high_count ?? 0);
            if ($crit > 0) {
                $score -= 30;
                $ecarts[] = __('conformite.ecart_cve_critiques', ['nombre' => $crit]);
            } elseif ($haut > 0) {
                $score -= 15;
                $ecarts[] = __('conformite.ecart_cve_hautes', ['nombre' => $haut]);
            }
            $f2b = $f2bParMachine[$s->id] ?? null;
            if (! $f2b || empty($f2b->installed)) {
                $score -= 15;
                $ecarts[] = __('conformite.ecart_fail2ban');
            }
            $derives = $deriveParMachine[$s->id] ?? 0;
            if ($derives > 0) {
                $score -= min(30, 10 * $derives);
                $ecarts[] = __('conformite.ecart_derives', ['nombre' => $derives]);
            }
            $score = max(0, min(100, $score));
            $posture[] = [
                'name'    => (string) $s->name,
                'ip'      => (string) $s->ip,
                'score'   => $score,
                'grade'   => $this->note($score),
                'reasons' => $ecarts ? implode(', ', $ecarts) : __('conformite.ecart_aucun'),
            ];
        }
        usort($posture, static fn ($a, $b) => $a['score'] <=> $b['score']);
        return $posture;
    }

    public function note(int $score): string
    {
        return match (true) {
            $score >= 90 => 'A',
            $score >= 75 => 'B',
            $score >= 60 => 'C',
            $score >= 40 => 'D',
            default      => 'F',
        };
    }

    /**
     * L'empreinte d'integrite du rapport.
     *
     * REPRISE TELLE QUELLE DU LEGACY, et ce n'est pas satisfaisant : l'antecedent
     * porte les colonnes `totp_secret` et `ssh_key`, qui ne figurent NULLE PART
     * dans le rapport — elles n'en sortent qu'en booleen. Le lecteur du rapport ne
     * peut donc pas recalculer l'empreinte a partir de ce qu'il tient, et une
     * preuve d'integrite invraisemblable vaut exactement autant que pas de
     * preuve. Le legacy enonce d'ailleurs la regle a l'endroit ou il la viole :
     * son commentaire dit que les mots de passe chiffres n'ont rien a faire « ni
     * dans le hash SHA-256 d'integrite ».
     *
     * LA CORRIGER CHANGE LA VALEUR DE L'EMPREINTE : les rapports deja emis ne se
     * verifieraient plus contre la nouvelle formule. C'est donc une decision
     * d'exploitant, pas un effet de bord de portage — `PARITE.md` D-2, en attente.
     * D'ici la, le portage reproduit le calcul du legacy a l'octet pres.
     *
     * @param  list<object>  $serveurs
     * @param  list<object>  $comptes
     * @param  array<string,int>  $remediation
     */
    public function empreinte(array $serveurs, array $comptes, array $remediation, string $date): string
    {
        return hash('sha256', json_encode([
            'servers'  => $serveurs,
            'users'    => $comptes,
            'remStats' => $remediation,
            'date'     => $date,
        ]));
    }

    /**
     * Une collecte facultative a echoue.
     *
     * Elle rend un vide, comme dans le legacy — mais elle le DIT. Un vide et une
     * erreur produisent le meme ecran ; sans trace, personne ne peut les
     * distinguer apres coup.
     */
    private function manque(string $table, \Throwable $e): void
    {
        Log::warning("[Conformite] collecte « {$table} » indisponible : " . $e->getMessage());
    }
}
