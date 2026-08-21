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
            ->select(
                'cve_id', 'package_name', 'package_version', 'cvss_score', 'severity', 'summary',
                // Enrichissement EPSS / KEV — colonnes de la migration 054.
                'epss_score', 'kev', 'kev_date_added', 'priority_score', 'priority_label',
            )
            ->where('scan_id', $scanId)
            // CE QUI EST REELLEMENT EXPLOITE PASSE DEVANT CE QUI EST GRAVE EN THEORIE.
            // Les cinq findings KEV du parc sont HIGH (7,1 a 7,8) : un tri par
            // severite les enterrait derriere 103 CRITICAL a 9,8. Le legacy trie
            // deja ainsi (`backend/cve_scanner.py:1230-1241`), et son script
            // retriait par-dessus ; ici l'ordre est etabli UNE FOIS, en SQL, et le
            // script ne fait plus que filtrer — donc aucun geste ne peut le defaire.
            //
            // MySQL classe NULL comme la plus petite valeur : en DESC, un finding
            // non enrichi arrive donc APRES tous les autres, exactement ce que le
            // legacy obtenait par `priority_score ?? -1`. Le comportement est
            // identique ; ce qui change, c'est que la page l'EXPLIQUE desormais.
            ->orderByDesc('kev')
            ->orderByDesc('priority_score')
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

    /**
     * Les machines visibles par ce compte, dans l'ordre d'affichage.
     *
     * ECART VOULU AVEC LE LEGACY (E-46). `legacy/security/index.php` filtre les
     * machines archivees dans sa branche `role >= 2` (l.42-45) et **ne les filtre
     * pas** dans sa branche role 1 (l.47-54) : un lecteur voit donc, et peut
     * faire scanner, une machine qu'un administrateur ne voit plus. L'oubli tombe
     * sur l'utilisateur le moins privilegie. Ici le filtre est pose UNE FOIS,
     * avant le branchement — il ne peut plus manquer dans une moitie.
     *
     * @return list<object>
     */
    public function machinesVisibles(int $idCompte, int $role): array
    {
        $requete = DB::table('machines')
            ->select('id', 'name', 'ip', 'environment', 'criticality')
            ->where(function ($q) {
                $q->whereNull('lifecycle_status')
                  ->orWhere('lifecycle_status', '!=', 'archived');
            });

        if ($role < 2) {
            $requete->join('user_machine_access as uma', 'uma.machine_id', '=', 'machines.id')
                    ->where('uma.user_id', $idCompte);
        }

        return $requete->orderBy('name')->get()->all();
    }

    /**
     * Le dernier scan termine de CHACUNE des machines donnees, indexe par machine.
     *
     * Une seule requete pour tout le parc : le legacy en fait une par carte, par
     * un appel reseau, et la page se peint donc en autant d'allers-retours.
     *
     * @param  list<int>  $machineIds
     * @return array<int,object>
     */
    public function derniersScansParMachine(array $machineIds): array
    {
        if ($machineIds === []) {
            return [];
        }

        $derniers = DB::table('cve_scans')
            ->selectRaw('machine_id, MAX(id) as dernier')
            ->whereIn('machine_id', $machineIds)
            ->where('status', 'completed')
            ->groupBy('machine_id');

        $lignes = DB::table('cve_scans as s')
            ->joinSub($derniers, 'd', fn ($j) => $j->on('s.id', '=', 'd.dernier'))
            ->select('s.id', 's.machine_id', 's.scan_date', 's.cve_count',
                     's.critical_count', 's.high_count', 's.medium_count', 's.low_count',
                     's.packages_scanned', 's.min_cvss')
            ->get();

        $parMachine = [];
        foreach ($lignes as $l) {
            $parMachine[(int) $l->machine_id] = $l;
        }

        return $parMachine;
    }

    /**
     * Le resume de parc, BORNE aux machines donnees.
     *
     * ECART VOULU AVEC LE LEGACY (E-47). `index.php:196-207` n'est joint NI a
     * `machines` NI a `user_machine_access` : il agrege le dernier scan de TOUTES
     * les machines de la base, archivees comprises, et s'affiche des que le compte
     * en voit deux. Un role 1 y lit donc les compteurs de la flotte entiere, et un
     * administrateur y voit des machines absentes du tableau juste en dessous.
     * **Un agregat doit porter le meme perimetre que la liste qu'il resume.**
     *
     * @param  list<int>  $machineIds
     * @return array{serveurs_scannes:int,total:int,critiques:int,hautes:int,moyennes:int}
     */
    public function resumeParc(array $machineIds): array
    {
        $vide = ['serveurs_scannes' => 0, 'total' => 0, 'critiques' => 0, 'hautes' => 0, 'moyennes' => 0];
        if ($machineIds === []) {
            return $vide;
        }

        $scans = $this->derniersScansParMachine($machineIds);
        foreach ($scans as $s) {
            $vide['serveurs_scannes']++;
            $vide['total']     += (int) $s->cve_count;
            $vide['critiques'] += (int) $s->critical_count;
            $vide['hautes']    += (int) $s->high_count;
            $vide['moyennes']  += (int) $s->medium_count;
        }

        return $vide;
    }

    /**
     * Les vulnerabilites d'un scan, preparees pour le rendu de la page.
     *
     * Cles COURTES et resume TRONQUE : la charge part en donnees dans la page, et
     * 1458 findings a cles longues pesent inutilement. La troncature a 200
     * caracteres laisse de la marge sur les 150 reellement affiches.
     *
     * @return list<array<string,mixed>>
     */
    public function findingsPourAffichage(int $scanId): array
    {
        return array_map(static fn ($f) => [
            'c' => (string) $f->cve_id,
            'p' => (string) ($f->package_name ?? ''),
            'v' => (string) ($f->package_version ?? ''),
            's' => (string) ($f->severity ?? 'NONE'),
            'n' => (float) ($f->cvss_score ?? 0),
            'r' => mb_substr((string) ($f->summary ?? ''), 0, 200),
            // L'ENRICHISSEMENT EST TRANSMIS, PARCE QU'IL EST AFFICHE. Le
            // `priority_label` en particulier etait calcule, stocke, et jamais
            // montre par le legacy : c'est le meme defaut que l'etat de suivi de
            // S5 (E-57). Ici il explique en infobulle pourquoi une ligne est la ou
            // elle est — sans ajouter de colonne, donc sans elargir le tableau.
            'k' => (int) ($f->kev ?? 0) === 1,
            'kd' => (string) ($f->kev_date_added ?? ''),
            'e' => $f->epss_score === null ? null : (float) $f->epss_score,
            'pl' => (string) ($f->priority_label ?? ''),
        ], $this->resultats($scanId));
    }

    /**
     * Comparaison des deux derniers scans termines d'une machine.
     *
     * REIMPLEMENTE, et non appele : le legacy fait ce diff EN PYTHON
     * (`backend/routes/cve.py:368-370`) derriere `GET /cve_compare`, une route
     * qui n'a ni role ni permission et dont le garde d'acces ne lit pas le meme
     * parametre que la route elle-meme. Le portage lit la base directement, comme
     * S1 : le diff revient donc ici.
     *
     * Rend TOUJOURS un etat lisible — `assez` dit s'il y avait de quoi comparer.
     * Le legacy, lui, repond « moins de 2 scans » avec un code HTTP 200 ; une
     * absence de donnee n'est pas une erreur, mais elle doit se DIRE.
     *
     * @return array{assez:bool,nb_scans:int,scan1:?object,scan2:?object,
     *               ajoutees:list<array<string,mixed>>,corrigees:list<array<string,mixed>>,
     *               inchangees:int}
     */
    public function comparaison(int $machineId): array
    {
        $deux = $this->requeteScan()
            ->where('s.machine_id', $machineId)
            ->where('s.status', 'completed')
            ->orderByDesc('s.scan_date')
            ->limit(2)
            ->get()
            ->all();

        $etat = [
            'assez' => count($deux) >= 2,
            'nb_scans' => count($deux),
            'scan1' => $deux[1] ?? null,   // le plus ANCIEN des deux
            'scan2' => $deux[0] ?? null,   // le plus RECENT
            'ajoutees' => [],
            'corrigees' => [],
            'inchangees' => 0,
        ];

        if (! $etat['assez']) {
            return $etat;
        }

        $indexe = function (int $scanId): array {
            $par = [];
            foreach ($this->resultats($scanId) as $f) {
                $par[(string) $f->cve_id] = $f;
            }
            return $par;
        };

        $avant = $indexe((int) $etat['scan1']->id);
        $apres = $indexe((int) $etat['scan2']->id);

        foreach ($apres as $cve => $f) {
            if (! isset($avant[$cve])) {
                $etat['ajoutees'][] = $f;
            } else {
                $etat['inchangees']++;
            }
        }
        foreach ($avant as $cve => $f) {
            if (! isset($apres[$cve])) {
                $etat['corrigees'][] = $f;
            }
        }

        return $etat;
    }

    private function requeteScan(): \Illuminate\Database\Query\Builder
    {
        return DB::table('cve_scans as s')
            ->join('machines as m', 's.machine_id', '=', 'm.id')
            ->select('s.*', 'm.name as machine_name');
    }
}
