<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Lectures des scans CVE et de leurs resultats.
 *
 * Le module `security/` du legacy lit ces tables directement en PDO, sans passer
 * par le backend Python : `cve_export.php` et `compliance_report.php` sont du
 * SQL local de bout en bout. Le portage fait de meme, et centralise ici pour que
 * les sous-lots suivants (S3 consultation, S6 re-priorisation) s'y adossent
 * plutot que de recopier les memes requetes — c'est la lecon du service
 * `Machines`, ne au moment ou un deuxieme controleur allait recopier le premier.
 *
 * AUCUNE ECRITURE ici. Les tables `cve_scans` et `cve_findings` appartiennent au
 * backend Python, qui les alimente ; ce service ne fait que les relire.
 */
class ScansCve
{
    /**
     * Le dernier scan TERMINE d'une machine, ou null.
     *
     * Le filtre `status = 'completed'` est celui du legacy : un scan en cours ou
     * en echec porte des compteurs partiels, et l'exporter donnerait un rapport
     * qui a l'air complet.
     */
    public function dernierScanComplet(int $machineId): ?object
    {
        return $this->requeteScan()
            ->where('s.machine_id', $machineId)
            ->where('s.status', 'completed')
            ->orderByDesc('s.scan_date')
            ->first();
    }

    /**
     * Un scan par son identifiant, quel que soit son statut.
     *
     * Le legacy ne filtre PAS sur le statut dans cette branche — un scan en
     * cours demande par son id est donc exportable. Repris tel quel : resserrer
     * retirerait une possibilite, ce qui n'est pas une decision de portage.
     */
    public function parId(int $scanId): ?object
    {
        return $this->requeteScan()->where('s.id', $scanId)->first();
    }

    /**
     * Les vulnerabilites d'un scan, dans l'ordre d'affichage du legacy :
     * severite decroissante, puis score CVSS decroissant.
     *
     * @return list<object>
     */
    public function resultats(int $scanId): array
    {
        return DB::table('cve_findings')
            ->select('cve_id', 'package_name', 'package_version', 'cvss_score', 'severity', 'summary')
            ->where('scan_id', $scanId)
            ->orderByRaw("FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW','NONE')")
            ->orderByDesc('cvss_score')
            ->get()
            ->all();
    }

    /**
     * Le compte a-t-il acces a cette machine ?
     *
     * A n'appeler que pour un role < 2 : au-dela, le legacy ne cloisonne pas.
     * L'appelant passe le `machine_id` DU SCAN RESOLU, jamais celui recu dans
     * l'URL — un garde qui controle le parametre recu ne garde rien des que le
     * chemin d'acces change.
     */
    public function accesMachine(int $idCompte, int $machineId): bool
    {
        return DB::table('user_machine_access')
            ->where('user_id', $idCompte)
            ->where('machine_id', $machineId)
            ->exists();
    }

    private function requeteScan(): \Illuminate\Database\Query\Builder
    {
        return DB::table('cve_scans as s')
            ->join('machines as m', 's.machine_id', '=', 'm.id')
            ->select('s.*', 'm.name as machine_name');
    }
}
