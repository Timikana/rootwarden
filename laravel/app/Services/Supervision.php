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
     * Le catalogue de profils, par plateforme — sous-lot V2, LECTURE SEULE.
     *
     * LE SCHEMA A ETE MESURE AVANT D'ECRIRE CETTE REQUETE, et il a corrige deux
     * suppositions : la table s'appelle `supervision_metadata_profiles` (pas
     * `supervision_profiles`), et le nombre de machines assignees ne vit pas dans
     * une colonne de `machines` mais dans `machine_supervision_profile`, dont la
     * cle primaire est `(machine_id, platform)` — une machine porte donc UN profil
     * PAR PLATEFORME, et le compte se filtre par plateforme.
     *
     * LES COLONNES SONT NOMMEES, jamais `SELECT *`. La route backend, elle, fait
     * `SELECT *` et envoie au navigateur `notes`, `tls_connect`, `tls_accept`,
     * `created_at` et `updated_at` alors que son tableau n'affiche que cinq
     * colonnes. Ici la page ne recoit que ce qu'elle montre.
     *
     * @return array<string,list<object>> indexe par plateforme
     */
    public function profilsParPlateforme(): array
    {
        $comptes = DB::table('machine_supervision_profile')
            ->select('profile_id', 'platform')
            ->selectRaw('COUNT(*) as machines')
            ->groupBy('profile_id', 'platform')
            ->get();

        $parProfil = [];
        foreach ($comptes as $ligne) {
            $parProfil[(int) $ligne->profile_id][(string) $ligne->platform] = (int) $ligne->machines;
        }

        $catalogue = array_fill_keys($this->plateformes(), []);

        $profils = DB::table('supervision_metadata_profiles')
            ->select('id', 'platform', 'name', 'description', 'host_metadata',
                     'zabbix_server', 'zabbix_server_active', 'zabbix_proxy', 'listen_port')
            ->whereIn('platform', $this->plateformes())
            ->orderBy('name')
            ->get();

        foreach ($profils as $p) {
            $plateforme = (string) $p->platform;
            // La plateforme vient d'une colonne de la base : on ne cree JAMAIS
            // une entree pour une valeur inattendue, sinon un enregistrement
            // decide de la structure de la page.
            if (! array_key_exists($plateforme, $catalogue)) {
                continue;
            }
            $p->machines = $parProfil[(int) $p->id][$plateforme] ?? 0;
            $catalogue[$plateforme][] = $p;
        }

        return $catalogue;
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
