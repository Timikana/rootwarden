<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Le parc, tel que la page « Cles SSH » a le droit de le montrer (sous-lot K1).
 *
 * K1 N'APPELLE AUCUNE ROUTE DU BACKEND. C'est tout l'interet de commencer par
 * lui : le module `ssh/` est le plus dangereux du depot — un seul bouton y
 * declenche `configure_servers.py` en root sur chaque machine cochee — et sa page
 * nue, elle, ne fait que lire la base.
 *
 * LE CLOISONNEMENT EST LA MEME REGLE PARTOUT, Y COMPRIS POUR LE VOCABULAIRE.
 *
 * Le legacy cloisonne la liste des machines (`INNER JOIN user_machine_access`
 * pour un role 1) mais PAS la liste des tags : `index.php:61` fait un
 * `SELECT DISTINCT tag FROM machine_tags` sans le moindre filtre, deux lignes
 * au-dessus d'un `$allEnvs` qui, lui, derive de la liste deja filtree. Une ligne
 * cloisonnee, sa voisine non. Un role 1 lit donc le vocabulaire de tags de tout
 * le parc — y compris celui de machines qu'il ne peut pas voir.
 *
 * Ici les deux listes viennent du MEME ensemble de machines. Ce n'est pas
 * mesurable avec les comptes existants (aucun compte de role 1 ne porte
 * `can_deploy_keys`, donc aucun ne peut ouvrir la page), et c'est dit tel quel
 * dans `PARITE.md` : corriger un defaut non exercable reste correct, pretendre
 * l'avoir mesure ne l'est pas.
 */
class ParcSsh
{
    /**
     * Les machines que ce compte a le droit de voir, jamais les archivees.
     *
     * @return list<object>
     */
    public function machinesVisibles(int $idCompte, int $role): array
    {
        $requete = DB::table('machines')
            ->select('machines.id', 'machines.name', 'machines.ip', 'machines.port',
                     'machines.environment')
            // Le filtre de cycle de vie est pose UNE FOIS, avant la branche de
            // role : le mettre dans chaque branche, c'est l'oublier dans l'une
            // des deux le jour ou une troisieme apparait (lecon E-46).
            ->where(function ($q) {
                $q->whereNull('machines.lifecycle_status')
                  ->orWhere('machines.lifecycle_status', '!=', 'archived');
            });

        if ($role < 2) {
            $requete->join('user_machine_access as uma', 'uma.machine_id', '=', 'machines.id')
                    ->where('uma.user_id', $idCompte);
        }

        return $requete->orderBy('machines.name')->get()->all();
    }

    /**
     * Les tags de CES machines, indexes par machine.
     *
     * @param  list<int>  $machineIds
     * @return array<int,list<string>>
     */
    public function tagsParMachine(array $machineIds): array
    {
        if ($machineIds === []) {
            return [];
        }

        $parMachine = [];
        foreach (DB::table('machine_tags')->select('machine_id', 'tag')
                    ->whereIn('machine_id', $machineIds)->orderBy('tag')->get() as $ligne) {
            $parMachine[(int) $ligne->machine_id][] = (string) $ligne->tag;
        }

        return $parMachine;
    }

    /**
     * Le vocabulaire de filtrage, DERIVE des machines visibles et d'elles seules.
     *
     * @param  list<object>  $machines
     * @param  array<int,list<string>>  $tagsParMachine
     * @return array{tags:list<string>,environnements:list<string>}
     */
    public function vocabulaire(array $machines, array $tagsParMachine): array
    {
        $tags = [];
        $envs = [];
        foreach ($machines as $m) {
            foreach ($tagsParMachine[(int) $m->id] ?? [] as $tag) {
                $tags[$tag] = true;
            }
            $env = trim((string) ($m->environment ?? ''));
            if ($env !== '') {
                $envs[$env] = true;
            }
        }
        $tags = array_keys($tags);
        $envs = array_keys($envs);
        sort($tags);
        sort($envs);

        return ['tags' => $tags, 'environnements' => $envs];
    }
}
