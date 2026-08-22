<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Le module `supervision/`, sous-lot V1 : la page et ses quatre onglets.
 *
 * V1 NE JOINT AUCUNE MACHINE ET N'APPELLE AUCUNE ROUTE DU BACKEND. C'est ce qui
 * en fait le bon point d'entree d'un module dont les quatre derniers sous-lots
 * ecrivent sur des serveurs distants, en desinstallent l'agent ou en redemarrent
 * le service.
 *
 * DIFFERENCE MESUREE AVEC LE LEGACY, ET ELLE EST LE POINT DE V1. La page legacy
 * emet DEUX requetes backend des son chargement — `GET /supervision/profiles` et
 * `GET /supervision/profiles/assignments` — puis les rejoue a CHAQUE bascule
 * d'onglet. Le catalogue de profils est donc charge d'emblee, pas a l'ouverture
 * de son onglet : la frontiere V1/V2 n'existe pas cote legacy. Ici, la page se
 * peint entierement cote serveur (decision S3/S4) et son script ne parle a
 * personne.
 *
 * La garde de la page etant `role:2`, il n'y a PAS de cloisonnement par
 * `user_machine_access` a porter : le legacy n'en fait aucun non plus, et aucun
 * role 1 ne peut ouvrir cette page. Le filtre de cycle de vie, lui, est repris
 * tel quel — les machines archivees n'apparaissent pas.
 */
class Supervision
{
    /**
     * Les plateformes d'agent que le module connait, dans l'ordre du legacy.
     *
     * Liste FERMEE et posee en dur : elle sert de liste blanche au bloc de
     * configuration visible. Une plateforme lue d'une requete serait un
     * identifiant venu de la base injecte dans un `id=` de la page.
     *
     * @return list<string>
     */
    public function plateformes(): array
    {
        return ['zabbix', 'centreon', 'prometheus', 'telegraf'];
    }

    /**
     * Les quatre onglets, dans l'ordre du legacy.
     *
     * @return list<string>
     */
    public function onglets(): array
    {
        return ['config', 'profiles', 'deploy', 'editor'];
    }

    /**
     * Le parc que la page a le droit de montrer : tout, sauf les archivees.
     *
     * Le filtre de cycle de vie est pose UNE FOIS et non dans une branche : le
     * mettre par branche, c'est l'oublier dans l'une d'elles le jour ou une
     * troisieme apparait (lecon E-46).
     *
     * @return list<object>
     */
    public function machines(): array
    {
        return DB::table('machines')
            ->select('machines.id', 'machines.name', 'machines.ip', 'machines.port',
                     'machines.environment')
            ->where(function ($q) {
                $q->whereNull('machines.lifecycle_status')
                  ->orWhere('machines.lifecycle_status', '!=', 'archived');
            })
            ->orderBy('machines.name')
            ->get()
            ->all();
    }
}
