<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Le suivi de remediation des vulnerabilites — module `security/`, sous-lot S5.
 *
 * TROIS DEFAUTS MESURES SE REFERMENT ICI.
 *
 * 1. L'ETAT STOCKE N'ETAIT JAMAIS AFFICHE. Le generateur du legacy ne pose aucune
 *    option `selected`, et son JS ne fait AUCUN `GET /cve_remediation` — sa seule
 *    occurrence est le POST. La cellule montrait donc un tiret meme quand une
 *    remediation existait, et apres un rechargement le choix qu'on venait de
 *    faire disparaissait de l'ecran alors qu'il etait bien enregistre.
 *    `parMachine()` existe pour cela.
 *
 * 2. UN CHANGEMENT DE STATUT ECRASAIT TROIS CHAMPS. Le client n'envoie que
 *    `{cve_id, machine_id, status}` ; cote backend `assigned_to`, `deadline` et
 *    `resolution_note` retombaient a leur defaut, et l'`ON DUPLICATE KEY UPDATE`
 *    reaffectait les CINQ colonnes. Mesure sur la pile reelle :
 *      `open | 16 | 2026-12-31 | note`  ->  `in_progress | VIDE | VIDE | VIDE`
 *    Deplacer une CVE de `open` a `in_progress` effacait donc l'assignataire,
 *    l'echeance et la note — et defaisait en silence l'auto-resolution du
 *    scanner. `definirStatut()` n'ecrit QUE la colonne demandee.
 *
 * 3. LE STATUT N'ETAIT CONTROLE PAR RIEN. La colonne est un `ENUM` ; une valeur
 *    inventee remontait l'erreur MySQL 1265 nue, donc un 500 avec une page HTML
 *    au lieu d'un 400.
 *
 * CE QUI RESTE IMPOSSIBLE, ET QU'IL FAUT DIRE : `cve_remediation` n'a **aucune
 * colonne d'auteur** (`id, cve_id, machine_id, status, assigned_to, deadline,
 * resolution_note, opened_at, resolved_at`). `assigned_to` est un ASSIGNATAIRE,
 * pas un auteur. Le schema appartient au backend Python et la migration est
 * interdite au portage : l'attribution d'un changement de statut reste donc
 * impossible, quel que soit le soin qu'on y mette. Voir PARITE.
 */
class SuiviCve
{
    /**
     * Les statuts acceptes — c'est l'ENUM de la colonne.
     *
     * `resolved` en fait partie mais l'interface ne le PROPOSE pas : il est pose
     * par le scanner seul, quand une CVE disparait d'un scan suivant
     * (`backend/cve_scanner.py:1092`). Il est donc accepte en LECTURE et affiche,
     * mais absent du selecteur — proposer a un humain de « resoudre » ce que le
     * scanner constate brouillerait les deux gestes.
     */
    public const STATUTS = ['open', 'in_progress', 'resolved', 'accepted', 'wont_fix'];

    /** Ceux qu'un humain peut choisir. */
    public const STATUTS_CHOISISSABLES = ['open', 'in_progress', 'accepted', 'wont_fix'];

    /**
     * Les remediations d'une machine, indexees par identifiant de CVE.
     *
     * @return array<string,string>  cve_id => statut
     */
    public function parMachine(int $machineId): array
    {
        return DB::table('cve_remediation')
            ->where('machine_id', $machineId)
            ->pluck('status', 'cve_id')
            ->all();
    }

    public function statut(string $cveId, int $machineId): ?string
    {
        $v = DB::table('cve_remediation')
            ->where('cve_id', $cveId)->where('machine_id', $machineId)
            ->value('status');

        return $v === null ? null : (string) $v;
    }

    /**
     * Pose un statut SANS toucher a quoi que ce soit d'autre.
     *
     * A la creation, les colonnes non renseignees prennent leur defaut — c'est
     * normal, il n'y avait rien a preserver. A la mise a jour, SEULE la colonne
     * `status` est ecrite : c'est la difference exacte avec le legacy.
     *
     * `resolved_at` suit le statut, et lui seul : il est pose quand on passe a
     * `resolved`, efface quand on en sort. Le laisser en place sur une CVE
     * reouverte en ferait une date de resolution mensongere.
     */
    public function definirStatut(string $cveId, int $machineId, string $statut): void
    {
        $existe = DB::table('cve_remediation')
            ->where('cve_id', $cveId)->where('machine_id', $machineId)
            ->exists();

        $resolu = $statut === 'resolved';

        if ($existe) {
            DB::table('cve_remediation')
                ->where('cve_id', $cveId)->where('machine_id', $machineId)
                ->update([
                    'status' => $statut,
                    'resolved_at' => $resolu ? now() : null,
                ]);

            return;
        }

        DB::table('cve_remediation')->insert([
            'cve_id' => $cveId,
            'machine_id' => $machineId,
            'status' => $statut,
            'resolved_at' => $resolu ? now() : null,
        ]);
    }

    /** Le statut est-il dans l'ENUM ? */
    public function statutAccepte(string $statut): bool
    {
        return in_array($statut, self::STATUTS, true);
    }

    /** Un humain peut-il le choisir ? */
    public function statutChoisissable(string $statut): bool
    {
        return in_array($statut, self::STATUTS_CHOISISSABLES, true);
    }
}
