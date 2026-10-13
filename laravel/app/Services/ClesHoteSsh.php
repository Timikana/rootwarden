<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Clés d'hôte SSH mémorisées par le backend — audit du 2026-10-13, H-3.
 *
 * Le backend refuse désormais toute connexion dont la clé d'hôte diffère de
 * celle vue au premier usage (`backend/ssh_utils.py`, `PolitiqueTofu`). Une
 * machine RÉINSTALLÉE présente une clé neuve et serait refusée pour toujours :
 * ce service permet de l'« oublier », pour qu'elle soit réenregistrée à la
 * prochaine connexion.
 *
 * L'identifiant est celui que paramiko présente à la politique : l'adresse pour
 * le port 22, `[adresse]:port` sinon. On efface les DEUX formes : une machine
 * dont on a changé le port en garderait une orpheline.
 */
class ClesHoteSsh
{
    /** @return list<string> */
    public function identifiants(string $ip, int $port): array
    {
        return array_values(array_unique([$ip, "[{$ip}]:{$port}"]));
    }

    private function identifiantCourant(string $ip, int $port): string
    {
        return $port === 22 ? $ip : "[{$ip}]:{$port}";
    }

    /**
     * La clé mémorisée de chaque machine, ou null.
     *
     * Tolère l'ABSENCE de la table (migration 066 pas encore appliquée) : la
     * page des serveurs ne doit pas tomber pour un renseignement d'appoint.
     *
     * @param  list<array{id:int|string, ip:string, port:int|string}>  $machines
     * @return array<int, array{type:string, empreinte:string, depuis:string}|null>
     */
    public function parMachine(array $machines): array
    {
        try {
            $lignes = DB::table('ssh_host_keys')->get()->keyBy('hote');
        } catch (\Throwable $e) {
            Log::warning('cles d\'hote : table illisible (migration 066 ?)', ['erreur' => $e->getMessage()]);
            $lignes = collect();
        }

        $res = [];
        foreach ($machines as $m) {
            $l = $lignes->get($this->identifiantCourant((string) $m['ip'], (int) $m['port']));
            $res[(int) $m['id']] = $l === null ? null : [
                'type' => (string) $l->key_type,
                'empreinte' => (string) $l->fingerprint_sha256,
                'depuis' => (string) $l->first_seen,
            ];
        }

        return $res;
    }

    /** Oublie la clé d'une machine. Rend le nombre de lignes effacées. */
    public function oublie(string $ip, int $port): int
    {
        return DB::table('ssh_host_keys')->whereIn('hote', $this->identifiants($ip, $port))->delete();
    }
}
