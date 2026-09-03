<?php

namespace App\Http\Controllers;

use App\Services\Politiques;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Les droits sudo d'un compte distant — sous-lot D9a.
 *
 * **Ce controleur ne fait AUCUNE ecriture.** Les trois gestes qui touchent la
 * machine — deployer, auditer, retirer — partent par la passerelle vers
 * `backend/routes/policies.py`, qui seul sait ouvrir une session SSH, valider
 * par `visudo -cf` et deplacer le fichier. Il n'y a rien a heriter d'un
 * aller-retour PHP au milieu.
 *
 * La passerelle les inscrit deja en re-authentification ponctuelle
 * (`RoutesBackend::MOTIFS_STEP_UP`), avec un nom d'action PAR ROUTE. Le legacy
 * fusionne les trois sous `policy_action` : un step-up consenti pour ANNULER y
 * autorise un DEPLOIEMENT pendant quinze minutes. Ici, non.
 */
class PolitiquesController extends Controller
{
    public function __construct(private Politiques $politiques)
    {
    }

    public function __invoke(Request $requete): View
    {
        $machines = $this->politiques->machines();

        // `has()` et non `input() !== null` : `ConvertEmptyStringsToNull` rend
        // `?machine=` indiscernable d'un parametre absent. Defaut paye en V10a.
        $machine = $requete->has('machine')
            ? (int) $requete->input('machine')
            : (int) ($machines[0]->id ?? 0);

        // Le parametre est un CHOIX, pas une autorisation : une machine qui
        // n'est pas dans la liste proposee retombe sur la premiere, elle
        // n'ouvre pas un acces. La garde d'acces est le middleware.
        $connues = array_map(static fn ($m) => (int) $m->id, $machines);
        if (! in_array($machine, $connues, true)) {
            $machine = (int) ($machines[0]->id ?? 0);
        }

        $comptes = $machine ? $this->politiques->comptes($machine) : [];
        $compte = $requete->has('compte')
            ? (int) $requete->input('compte')
            : (int) ($comptes[0]->id ?? 0);
        $proposables = array_map(static fn ($c) => (int) $c->id, $comptes);
        if (! in_array($compte, $proposables, true)) {
            $compte = (int) ($comptes[0]->id ?? 0);
        }

        $politique = ($machine && $compte) ? $this->politiques->politique($machine, $compte) : null;

        // Les libelles partent en UN bloc JSON, calcules ici : `@json` multiligne
        // casse le PHP compile par Blade, et une aide de prereglage ne se
        // recopie pas dans le JS — elle vient du catalogue, comme le reste.
        $libelles = ['portee' => Politiques::PORTEE, 'aide' => []];
        foreach (Politiques::PREREGLAGES as $p) {
            $libelles['aide'][$p] = __('politiques.aide_' . $p);
        }
        foreach ([
            'portee_root', 'portee_root_detail', 'portee_borne', 'portee_borne_detail',
            'portee_inconnu', 'portee_inconnu_detail', 'confirmer_titre', 'confirmer_intro',
            'confirmer_valider', 'confirmer_root', 'retirer_titre', 'retirer_intro',
            'retirer_valider', 'reauth', 'confirmer_machine', 'confirmer_compte', 'confirmer_portee',
        ] as $cle) {
            $libelles[$cle] = __('politiques.' . $cle);
        }

        return view('politiques', [
            'libelles'   => $libelles,
            'machines'   => $machines,
            'machine'    => $machine,
            'comptes'    => $comptes,
            'compte'     => $compte,
            'politique'  => $politique,
            'prereglage' => $politique->preset ?? Politiques::PREREGLAGE_INITIAL,
            'historique' => ($machine && $compte)
                ? $this->politiques->historique($machine, $compte)
                : [],
        ]);
    }
}
