<?php

namespace App\Http\Controllers;

use App\Services\Machines;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Wazuh — sous-lot R2 : LES TROIS GESTES QUI N'OUVRENT PAS DE SESSION SSH.
 *
 * ══ CE QUE R2 AJOUTE A R1, ET LA LIGNE QUI SEPARE ═════════════════════════
 *
 *     POST   /wazuh/config          enregistre la configuration du manager
 *     POST   /wazuh/options         enregistre les options d'un serveur
 *     POST   /wazuh/rules           cree ou modifie une regle
 *     DELETE /wazuh/rules/<name>    supprime une regle
 *
 * **La ligne n'est pas « ecrire ou lire », c'est « ouvrir une session SSH ou
 * non ».** Les six gestes restants du module (`install`, `install_all`,
 * `detect`, `uninstall`, `restart`, `group`) ouvrent une session SSH sur la
 * machine ; les quatre ci-dessus n'ecrivent qu'en base. *Un classement par
 * ECRITURE aurait mis les dix du meme cote et n'aurait rien porte.*
 *
 * ══ ⚠ ET ENREGISTRER NE VEUT PAS DIRE LA MEME CHOSE SUR LES TROIS ═════════
 *
 * Mesure du 2026-09-05 — « qui LIT ce que ce geste ECRIT », sur tout le depot :
 *
 *     wazuh_config           lu par `install()` (:339) et `install_all()` (:531)
 *                            -> effet DIFFERE, reel : decide de la PROCHAINE
 *                               installation
 *     wazuh_machine_options  DEUX occurrences dans tout le depot : son propre
 *                            SELECT (:992) et son propre INSERT (:1048)
 *                            -> AUCUN effet aujourd'hui
 *     wazuh_rules            lu par `list_rules` (:1080) et `get_rule` (:1098)
 *                            -> AUCUN effet aujourd'hui
 *
 * L'ecran porte donc TROIS phrases d'effet distinctes, attachees chacune a son
 * geste. *Un « Enregistre. » identique sur les trois ferait croire trois fois
 * la meme chose, et deux fois ce serait faux — c'est la difference entre regler
 * une surveillance et croire l'avoir reglee.*
 *
 * ══ CE QUE R1 PORTAIT DEJA — LECTURE SEULE ════════════════════════════════
 *
 *
 * Les CINQ routes de lecture :
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
    /**
     * Les formats de log admis, releves de `_LOG_FORMATS` (`wazuh.py:60`).
     *
     * ⚠ RECOPIER UNE LISTE FERMEE EST UN RISQUE ASSUME, ET IL EST BORNE.
     * Le portage ne peut pas interroger le backend pour construire un
     * `<select>` : il n'existe aucune route qui rende cette liste. Deux
     * copies peuvent donc diverger — mais la divergence est INOFFENSIVE dans
     * un sens et VISIBLE dans l'autre : une valeur retiree cote backend fait
     * refuser l'enregistrement avec son message, une valeur ajoutee la rend
     * simplement inatteignable depuis cet ecran. **Aucune des deux ne fabrique
     * une valeur que le serveur accepterait a tort** — c'est la propriete qui
     * compte, et c'est elle qui rend la copie acceptable ici.
     *
     * Le gabarit ne recopie PAS cette liste : il la rend depuis cette source.
     */
    public const FORMATS_LOG = [
        'syslog', 'snort-full', 'squid', 'json', 'multi-line', 'eventlog', 'nmapg',
    ];

    /** Les trois types de regle, releves de `_VALID_RULE_TYPES` (`wazuh.py:61`). */
    public const TYPES_REGLE = ['rules', 'decoders', 'cdb'];

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

        /*
         * Les libelles des types sont resolus ICI et non dans le gabarit : une
         * boucle qui ferait `__('wazuh.type_' . $cle)` construirait sa cle par
         * concatenation, et une cle construite est invisible a tout controle
         * qui cherche des cles litterales. *Le releve des cles mortes du projet
         * lit des litteraux ; une cle assemblee lui echappe.*
         */
        $typesRegle = [];
        foreach (self::TYPES_REGLE as $type) {
            $typesRegle[$type] = match ($type) {
                'rules' => __('wazuh.type_rules'),
                'decoders' => __('wazuh.type_decoders'),
                'cdb' => __('wazuh.type_cdb'),
            };
        }

        return view('wazuh', [
            'serveurs' => $perimetre['serveurs'],
            'lisible'  => $perimetre['lisible'],
            'libelles' => __('wazuh'),
            'formatsLog' => self::FORMATS_LOG,
            'typesRegle' => $typesRegle,
            /*
             * ⛔ NUL DEPUIS LE 2026-09-05 : la cible est ARCHIVEE et rend 404.
             * Offrir un lien vers une page retiree est le defaut que ce chantier
             * a corrige deux fois ailleurs (supervision le 03/09, /profil le 05/09).
             * La vue garde le nul et n'affiche plus le renvoi.
             */
            'lienLegacy' => null,
        ]);
    }
}
