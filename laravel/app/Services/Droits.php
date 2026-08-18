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
