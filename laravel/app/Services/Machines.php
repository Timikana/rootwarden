<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Liste de reference des machines du parc, pour les selecteurs et les filtres.
 *
 * Deux pages en avaient besoin — le journal des commandes et les tickets — et
 * la seconde allait recopier la premiere. Une decision recopiee finit par
 * diverger : elle vit donc a un seul endroit.
 *
 * AUCUN FILTRE D'ACCES ICI. Les pages qui s'en servent sont reservees a
 * l'administration, qui a vocation a voir le parc entier ; c'est le meme choix
 * que le legacy, et il est delibere. Il ne doit PAS etre repris pour une page
 * ouverte a des comptes sans permission — c'est precisement le defaut du
 * tableau de bord du legacy, qui sert ces memes donnees a tout le monde.
 */
class Machines
{
    /** @return list<object> */
    public function liste(): array
    {
        try {
            return DB::table('machines')->select('id', 'name')->orderBy('name')->get()->all();
        } catch (\Throwable) {
            // Une liste de reference est un confort : son indisponibilite ne
            // doit pas empecher la consultation de la page.
            return [];
        }
    }
}
