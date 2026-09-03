<?php

namespace App\Http\Controllers;

use App\Services\Machines;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Wazuh — sous-lot R1 : LECTURE SEULE.
 *
 * ══ CE QUE R1 PORTE ═══════════════════════════════════════════════════════
 *
 * Les CINQ routes de lecture, et elles seules :
 *
 *     GET /wazuh/config          la configuration du manager
 *     GET /wazuh/servers         l'inventaire des agents
 *     GET /wazuh/options         les options d'un serveur
 *     GET /wazuh/rules           les regles, decodeurs et listes CDB
 *     GET /wazuh/rules/<name>    le contenu d'une regle
 *
 * ══ POURQUOI CE SOUS-LOT N'EST PAS BLOQUE PAR LE REDEMARRAGE ══════════════
 *
 * Le backend en service tient `6663e83` (2026-08-27), qui contient DEJA
 * `routes/wazuh.py`. Les cinq routes GET y sont IDENTIQUES a celles de
 * l'arbre : les trois seules differences vivent dans `_upsert_agent`,
 * `install_all` et `uninstall` — trois routes d'ECRITURE que R1 n'appelle
 * pas. **Le redemarrage ne change rien a ce que cette page lit.**
 *
 * ══ ⚠ TROIS CHEMINS PORTENT DEUX METHODES ═════════════════════════════════
 *
 *     /wazuh/config        GET lit   ·  POST ecrit
 *     /wazuh/options       GET lit   ·  POST ecrit
 *     /wazuh/rules/<name>  GET lit   ·  DELETE supprime
 *
 * Un classement par CHEMIN ne peut donc pas separer ce que cette page porte
 * de ce qu'elle declare absent. **Le discriminant est la METHODE**, et la
 * discipline du module la rend fiable : 5 GET qui lisent, 10 non-GET qui
 * agissent — `detect` compris, qui est un POST et ouvre une session SSH.
 *
 * ══ LA GARDE EST CELLE DU LEGACY ══════════════════════════════════════════
 *
 * `legacy/wazuh/index.php:25-26` pose `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`
 * + `checkPermission('can_manage_wazuh')`. Les cinq routes backend exigent la
 * meme paire. Le portage porte `role:2` + `perm:can_manage_wazuh`, et l'entree
 * de menu garde son drapeau de fonctionnalite `wazuh`.
 */
class WazuhController extends Controller
{
    public function __construct(private readonly Machines $machines)
    {
    }

    public function __invoke(Request $requete): View
    {
        $role = (int) $requete->session()->get('role_id', 0);
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        /*
         * Le selecteur de serveur des options. On NE recopie AUCUN predicat de
         * bornage : `Machines::perimetre()` porte la regle pour tout le
         * service. Trois implementations de la meme borne finiraient par
         * diverger — c'est le motif que ce portage refuse partout.
         *
         * La page etant gardee `role:2`, la borne ne mord pas ici. On l'emploie
         * quand meme : le jour ou la garde changerait, le selecteur suivrait
         * sans qu'on ait a y penser.
         */
        $perimetre = $this->machines->perimetre($role, $idCompte);

        return view('wazuh', [
            'serveurs' => $perimetre['serveurs'],
            'lisible'  => $perimetre['lisible'],
            'libelles' => __('wazuh'),
            'lienLegacy' => rtrim((string) config('app.url_legacy'), '/') . '/wazuh/',
        ]);
    }
}
