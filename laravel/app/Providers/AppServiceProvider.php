<?php

namespace App\Providers;

use App\Services\Droits;
use App\Support\Navigation;
use Illuminate\Support\Facades\View;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {
        /*
         * Le menu est calcule UNE FOIS par requete et injecte dans toutes les
         * vues qui en ont besoin. Le calculer dans chaque controleur reviendrait
         * a recopier une decision d'acces — exactement ce que le legacy fait, et
         * exactement ce qui finit par diverger.
         *
         * Les droits sont lus EN BASE, pas dans la session : une permission
         * revoquee cesse d'ouvrir une entree de menu a la requete suivante.
         */
        View::composer(['layouts.portail', 'composants.entrees-menu'], function ($vue) {
            $idCompte = session('utilisateur_id');
            if (! $idCompte) {
                $vue->with('menu', []);

                return;
            }

            $droits = app(Droits::class);

            $vue->with('menu', Navigation::pour(
                (int) session('role_id', 0),
                $droits->permissions((int) $idCompte),
                $droits->fonctionnalites(),
            ));
        });
    }
}
