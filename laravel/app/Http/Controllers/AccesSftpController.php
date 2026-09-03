<?php

namespace App\Http\Controllers;

use App\Services\AccesSftp;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * L'acces SFTP/SSH d'un compte distant — sous-lot D9b.
 *
 * **Ce controleur ne fait AUCUNE ecriture.** Comme en D9a, les trois gestes qui
 * touchent la machine partent par la passerelle vers `routes/policies.py`, seul
 * a savoir ouvrir une session SSH, valider par `sshd -t` et deplacer le fichier.
 *
 * `RoutesBackend::MOTIFS_STEP_UP` couvre deja `/policy/sftp/(deploy|remove)`,
 * avec un nom d'action PAR ROUTE.
 */
class AccesSftpController extends Controller
{
    public function __construct(private AccesSftp $acces)
    {
    }

    public function __invoke(Request $requete): View
    {
        $machines = $this->acces->machines();

        // `has()` et non `input() !== null` : `ConvertEmptyStringsToNull` rend
        // `?machine=` indiscernable d'un parametre absent (defaut paye en V10a).
        $machine = $requete->has('machine')
            ? (int) $requete->input('machine')
            : (int) ($machines[0]->id ?? 0);

        // Le parametre est un CHOIX, pas une autorisation : une machine hors de
        // la liste proposee retombe sur la premiere. La garde d'acces est le
        // middleware, pas ce filtre.
        $connues = array_map(static fn ($m) => (int) $m->id, $machines);
        if (! in_array($machine, $connues, true)) {
            $machine = (int) ($machines[0]->id ?? 0);
        }

        $comptes = $machine ? $this->acces->comptes($machine) : [];
        $compte = $requete->has('compte')
            ? (int) $requete->input('compte')
            : (int) ($comptes[0]->id ?? 0);
        $proposables = array_map(static fn ($c) => (int) $c->id, $comptes);
        if (! in_array($compte, $proposables, true)) {
            $compte = (int) ($comptes[0]->id ?? 0);
        }

        $politique = ($machine && $compte) ? $this->acces->politique($machine, $compte) : null;

        // Les libelles partent en UN bloc JSON calcule ici : `@json` multiligne
        // casse le PHP compile par Blade.
        $libelles = ['effets' => AccesSftp::REGLAGES];
        foreach ([
            'confirmer_titre', 'confirmer_intro', 'confirmer_valider', 'confirmer_ouvre',
            'retirer_titre', 'retirer_intro', 'retirer_valider', 'reauth',
            'confirmer_machine', 'confirmer_compte', 'confirmer_effet', 'aucun_reglage_ouvert',
        ] as $cle) {
            $libelles[$cle] = __('sftp.' . $cle);
        }

        return view('acces-sftp', [
            'machines'   => $machines,
            'machine'    => $machine,
            'comptes'    => $comptes,
            'compte'     => $compte,
            'politique'  => $politique,
            'etat'       => $this->acces->etat($politique),
            'neuve'      => $politique === null,
            'libelles'   => $libelles,
            'historique' => ($machine && $compte)
                ? $this->acces->historique($machine, $compte)
                : [],
        ]);
    }
}
