<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

/**
 * Transfert des journaux vers Graylog : configuration, deploiement de `rsyslog`
 * sur les machines, et gabarits de configuration.
 *
 * ══ CE QUE CE CONTROLEUR LIT, ET CE QU'IL LAISSE A LA PASSERELLE ════════════
 *
 * Il lit UNE chose : l'historique, depuis `user_logs`. Tout le reste —
 * configuration, machines, gabarits — passe par la passerelle, comme dans le
 * legacy dont le JavaScript appelle `/graylog/config` au chargement
 * (`glLoadConfig`, js:25).
 *
 * Ce partage n'est pas un choix d'elegance, c'est celui du legacy : trois de ses
 * quatre onglets viennent du backend, et le quatrieme est rendu en PHP parce
 * qu'IL N'EXISTE AUCUNE ROUTE `/graylog/history`. Le premier jet de ce portage
 * l'appelait quand meme ; verifie avant d'executer, et corrige.
 *
 * Pour la configuration, la tentation etait de la rendre cote serveur pour
 * eviter un aller-retour. Ecartee : l'ECRITURE passe forcement par la passerelle
 * (c'est une route du backend), et lire d'un cote pour ecrire de l'autre
 * installe deux chemins qui peuvent diverger. Une seule source par donnee.
 *
 * ══ CE QUE LA PAGE DOIT DIRE ET QUE LE LEGACY NE DIT PAS ════════════════════
 *
 * Trois des gestes de cette page ouvrent une session SSH REELLE et executent en
 * root sur la machine choisie : `deploy` installe `rsyslog` par `apt-get`,
 * `uninstall` retire les fichiers et redemarre le service, `test` execute
 * `logger`. Le legacy demande confirmation pour les deux premiers et **pas pour
 * le troisieme** (`glTest`, js:100) : un seul clic, une session SSH.
 *
 * Le portage confirme les TROIS, en page, et nomme la machine dans la
 * confirmation — le tableau liste toutes les machines non archivees, machine de
 * production comprise, et rien dans le legacy ne distingue sa ligne.
 */
class GraylogController extends Controller
{
    public function __invoke(): View
    {
        /*
         * L'HISTORIQUE EST LU ICI, ET C'EST LA SEULE LECTURE DIRECTE.
         *
         * Le premier jet de ce portage appelait `/graylog/history` par la
         * passerelle. Cette route N'EXISTE PAS : verifie avant d'executer quoi
         * que ce soit. Le legacy rend cet onglet cote serveur, depuis
         * `user_logs` (`index.php:20-27`), et c'est le seul de ses quatre
         * onglets qui ne passe pas par le backend.
         *
         * Le portage fait donc pareil. La requete est la meme, au filtre pres :
         * les actions du module sont prefixees `[graylog]`, ce qui est un
         * marqueur de CHAINE et non une colonne — c'est ainsi que le legacy les
         * range, et changer ce rangement en portant une page reviendrait a
         * perdre l'historique deja ecrit.
         */
        $historique = DB::table('user_logs as ul')
            ->leftJoin('users as u', 'u.id', '=', 'ul.user_id')
            ->where('ul.action', 'like', '[graylog]%')
            ->orderByDesc('ul.created_at')
            ->limit(100)
            ->get(['ul.id', 'ul.action', 'ul.created_at', 'u.name as user_name']);

        /*
         * Les quatre onglets sont posees ici, en donnees, plutot qu'ecrites
         * quatre fois dans le gabarit : leur ordre et leur nombre se lisent d'un
         * coup, et le test peut les parcourir sans connaitre la page.
         */
        return view('graylog', [
            'onglets'    => ['config', 'deploy', 'templates', 'history'],
            'historique' => $historique,
        ]);
    }
}
