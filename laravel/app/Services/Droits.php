<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Role et permissions du compte connecte, lus EN BASE.
 *
 * Le legacy porte cet avertissement dans son propre code : « ne jamais utiliser
 * $_SESSION['permissions'] pour une decision de securite » — et son menu s'en
 * sert quand meme, pour l'affichage. On garde la meme distinction, mais on la
 * rend explicite : ici la base est la seule source, et le resultat est memorise
 * POUR LA DUREE DE LA REQUETE seulement. Une permission revoquee prend effet a
 * la requete suivante, pas au prochain redemarrage.
 */
class Droits
{
    /** @var array<int, array<string,bool>> */
    private array $memoire = [];

    /**
     * Permissions du compte, sous forme de tableau nom => booleen.
     * Un compte sans ligne dans `permissions` obtient un tableau vide, ce qui
     * refuse tout : fail-closed.
     *
     * @return array<string,bool>
     */
    public function permissions(int $idCompte): array
    {
        if (isset($this->memoire[$idCompte])) {
            return $this->memoire[$idCompte];
        }

        $ligne = DB::table('permissions')->where('user_id', $idCompte)->first();

        $permissions = [];
        if ($ligne) {
            foreach ((array) $ligne as $colonne => $valeur) {
                if ($colonne !== 'user_id') {
                    $permissions[$colonne] = (bool) $valeur;
                }
            }
        }

        // ══ LES PERMISSIONS TEMPORAIRES COMPTENT AUSSI ═════════════════════
        //
        // `checkPermissionFromDB()` du legacy (`auth/functions.php:294`)
        // consulte TROIS sources : le repli superadministrateur, la table
        // `permissions`, et `temporary_permissions` non expirees. Ce portage
        // n'en lisait que la deuxieme — un octroi temporaire ouvrait la page sur
        // l'ancien portail et rendait 403 ici. Releve le 2026-08-26 en
        // inventoriant D7 ; voir PARITE E-134.
        //
        // La divergence allait dans le sens RESTRICTIF, donc elle n'ouvrait
        // rien — mais elle cassait la parite, et elle rendait inoperante une
        // capacite que le backend expose par trois routes et que le
        // planificateur purge deux fois.
        //
        // `machine_id` N'EST PAS FILTRE, et c'est fidele : le legacy ne le
        // filtre pas davantage. La colonne existe, aucune interface ne la
        // renseigne, et la verification l'ignore — voir E-134.
        foreach (
            DB::table('temporary_permissions')
                ->where('user_id', $idCompte)
                ->where('expires_at', '>', now())
                ->pluck('permission') as $accordee
        ) {
            $permissions[(string) $accordee] = true;
        }

        return $this->memoire[$idCompte] = $permissions;
    }

    /**
     * Drapeaux de fonctionnalite. Le legacy les lit par `feature_enabled()`,
     * alimente par des variables d'environnement. Absent = actif, comme lui.
     *
     * @return array<string,bool>
     */
    public function fonctionnalites(): array
    {
        return [
            'wazuh' => (bool) config('rootwarden.fonctionnalites.wazuh', true),
        ];
    }
}
