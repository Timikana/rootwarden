<?php

namespace App\Http\Controllers;

use App\Services\Iptables;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Pare-feu iptables — sous-lot I1.
 *
 * **Ce controleur n'ouvre aucune session SSH.** Ouvrir la page ne joint aucune
 * machine : elle rend la liste des cibles et attend un geste explicite. Le
 * releve des regles actives part du navigateur, par la passerelle, machine par
 * machine.
 *
 * Garde : `role:1` + `perm:can_manage_iptables`, reprise telle quelle du legacy
 * — dont l'en-tete annonce pourtant « superadmin uniquement ». Voir
 * `App\Services\Iptables`.
 *
 * ══ CE QUE I1 NE FAIT PAS, ET POURQUOI C'EST ECRIT ═══════════════════════
 *
 * `POST /iptables` porte DEUX gestes sous une seule route : `action: "get"` lit
 * les regles, `action: "apply"` **les applique**. La passerelle ne peut donc
 * pas les distinguer — elle filtre sur le CHEMIN, jamais sur le corps.
 *
 * I1 n'emet que `action: "get"`, et l'ecran n'offre aucun moyen d'emettre
 * autre chose : il n'y a ni champ d'edition, ni bouton d'application. C'est une
 * fermeture **par l'absence**, la seule qu'une requete forgee ne contourne pas
 * — « ne pas offrir d'entree libre plutot que la valider ».
 */
class PareFeuController extends Controller
{
    public function __construct(private Iptables $iptables)
    {
    }

    public function __invoke(Request $requete): View
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        $roleId = (int) $requete->session()->get('role_id', 0);

        $machines = $this->iptables->machines($idCompte, $roleId);

        $lignes = [];
        foreach ($machines as $m) {
            $lignes[] = [
                'machine'  => $m,
                'sensible' => $this->iptables->estSensible($m),
            ];
        }

        /*
         * `@json` avec un litteral inline casse le PHP compile par Blade : les
         * libelles se calculent ici (defaut paye en `bashrc/` B1 — page en 500).
         *
         * Et une chaine ecrite en dur dans le JS echapperait a la parite FR/EN :
         * tout ce que le script affiche passe par cette table.
         */
        $textes = [];
        foreach ([
            'choisir', 'chargement', 'echec', 'echec_reseau',
            'releve_le', 'sensible_avert',
            'bloc_actives_v4', 'bloc_actives_v6', 'bloc_fichier_v4', 'bloc_fichier_v6',
            'bloc_vide_titre', 'bloc_vide', 'fichier_absent_titre', 'fichier_absent',
            'releve_ok', 'aucune_machine_choisie',
            'port_ssh_annonce',
            // I2
            'copie_absente', 'copie_le', 'copie_rien_a_enregistrer',
            'copie_lignes_multiples', 'copie_bloc_v4', 'copie_bloc_v6',
        ] as $cle) {
            $textes[$cle] = __('pare-feu.' . $cle);
        }

        return view('pare-feu', [
            'lignes'    => $lignes,
            'sensibles' => $this->iptables->compteSensibles($machines),
            'total'     => count($machines),
            /*
             * Le port SSH par machine voyage avec la page. I1 s'en sert pour
             * l'annoncer au moment du choix ; I4 et I5 s'en serviront pour
             * composer un gabarit qui ne suppose pas 22. Voir le service.
             */
            'portsSsh'  => $this->iptables->portsSsh($machines),
            'textes'    => $textes,
        ]);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  SOUS-LOT I2 — LA COPIE EN BASE
    // ══════════════════════════════════════════════════════════════════════
    //
    // Ces deux gestes ne passent PAS par la passerelle : ce sont des lectures
    // et des ecritures de la base du portail, exactement comme les handlers PDO
    // locaux du legacy (`index.php:86-118`). Rien ne joint de machine.
    //
    // La falsification de requete est deja geree par le cadre : `PreventRequestForgery`
    // est dans le groupe `web`. On n'ajoute rien par-dessus.

    /** Lit la copie en base pour une machine. */
    public function charger(Request $requete): JsonResponse
    {
        $machine = $this->machineDeLaRequete($requete);
        if ($machine === null) {
            return response()->json([
                'success' => false,
                'message' => __('pare-feu.machine_refusee'),
            ], 403);
        }

        $regles = $this->iptables->reglesEnBase((int) $machine->id);
        if ($regles === null) {
            return response()->json([
                'success' => false,
                'aucune_copie' => true,
                'message' => __('pare-feu.copie_absente'),
            ]);
        }

        /*
         * COMBIEN DE LIGNES, ET NON « IL Y EN A UNE ».
         *
         * `iptables_rules` n'a aucune contrainte d'unicite sur `server_id`
         * (mesure du schema). On lit deterministiquement la plus recente, ET on
         * DIT s'il y en a plusieurs : un ecran qui affiche une copie sans dire
         * qu'il en existe d'autres laisse croire qu'il n'y en a qu'une.
         */
        $lignes = $this->iptables->compteLignesEnBase((int) $machine->id);

        return response()->json([
            'success'   => true,
            'rules_v4'  => (string) ($regles->rules_v4 ?? ''),
            'rules_v6'  => (string) ($regles->rules_v6 ?? ''),
            'enregistre_le' => (string) ($regles->updated_at ?? ''),
            'lignes'    => $lignes,
        ]);
    }

    /** Remplace la copie en base pour une machine. */
    public function enregistrer(Request $requete): JsonResponse
    {
        $machine = $this->machineDeLaRequete($requete);
        if ($machine === null) {
            return response()->json([
                'success' => false,
                'message' => __('pare-feu.machine_refusee'),
            ], 403);
        }

        /*
         * ══ `has()` POUR L'EXISTENCE, `input()` POUR LA VALEUR ═══════════
         *
         * `ConvertEmptyStringsToNull` est dans le groupe `web` : `input('rules_v6')`
         * rend `null` pour une chaine vide, **indiscernable d'un champ non
         * soumis**. Or ici « vide » a un SENS — une machine sans regle IPv6 est
         * un cas normal, et l'enregistrer vide est une decision, pas un oubli.
         *
         * Defaut deja paye sur `supervision/` V10a : le code testait `=== null`
         * et ne supprimait jamais rien.
         */
        if (! $requete->has('rules_v4') || ! $requete->has('rules_v6')) {
            return response()->json([
                'success' => false,
                'message' => __('pare-feu.champs_manquants'),
            ], 400);
        }

        $v4 = (string) ($requete->input('rules_v4') ?? '');
        $v6 = (string) ($requete->input('rules_v6') ?? '');

        /*
         * UNE COPIE VIDE N'EST PAS UNE COPIE — et la regle vient d'ailleurs.
         *
         * `iptables-rollback` refuse deja d'appliquer une version dont `rules_v4`
         * est vide : « Version vide, restauration refusee » (`iptables.py`). On
         * REMONTE cette regle au lieu d'en inventer une : enregistrer ce que la
         * restauration refusera de toute facon fabriquerait une copie inutile,
         * et l'ecran annoncerait un enregistrement reussi.
         *
         * `rules_v6` peut etre vide : toutes les machines n'ont pas d'IPv6.
         */
        if (trim($v4) === '') {
            return response()->json([
                'success' => false,
                'message' => __('pare-feu.copie_v4_vide'),
            ], 400);
        }

        /*
         * LA BORNE EST CONTROLEE AVANT L'ECRITURE, PAS DECOUVERTE APRES.
         *
         * Les deux colonnes sont des `TEXT` — 65 535 octets. En mode permissif
         * MySQL TRONQUE en silence : l'ecran annoncerait « enregistre » sur une
         * copie amputee, et la troncature ne se verrait qu'au moment d'appliquer.
         * On mesure en OCTETS (`strlen`), pas en caracteres : c'est la borne de
         * la colonne.
         */
        $max = \App\Services\Iptables::OCTETS_MAX;
        if (strlen($v4) > $max || strlen($v6) > $max) {
            return response()->json([
                'success' => false,
                'message' => __('pare-feu.copie_trop_grande', ['max' => $max]),
            ], 400);
        }

        $this->iptables->enregistreRegles((int) $machine->id, $v4, $v6);

        return response()->json([
            'success' => true,
            'message' => __('pare-feu.copie_enregistree', ['machine' => $machine->name]),
        ]);
    }

    /**
     * La machine visee, RESOLUE et controlee — ou `null`.
     *
     * Un seul point de resolution pour les deux gestes : deux copies de ce
     * controle finiraient par diverger, et c'est un controle d'acces.
     */
    private function machineDeLaRequete(Request $requete): ?object
    {
        $id = (int) $requete->input('machine_id', 0);
        if ($id <= 0) {
            return null;
        }

        return $this->iptables->machineAccessible(
            (int) $requete->session()->get('utilisateur_id', 0),
            (int) $requete->session()->get('role_id', 0),
            $id
        );
    }
}
