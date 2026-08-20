<?php

namespace App\Http\Controllers;

use App\Services\ScansCve;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Module `security/`, sous-lot S3 : la consultation des resultats CVE.
 *
 * Portage de la partie LECTURE SEULE de `legacy/security/index.php` (549 lignes)
 * et de son JS (1026 lignes). Hors perimetre : la planification (S4), le suivi et
 * le ticketing (S5), EPSS/KEV (S6), et le DECLENCHEMENT du scan (S7 — flux SSH,
 * destructif, en dernier).
 *
 * PAS DE PASSERELLE. Le legacy peint cette page par des appels
 * `GET /cve_results`, un par machine, a travers `api_proxy.php`. Trois mesures
 * ont impose un autre chemin :
 *   - sur les 19 routes CVE du backend, `require_permission` apparait **zero**
 *     fois, et `can_scan_cve` n'existe dans tout le backend que dans une fixture
 *     de test : la permission ne garde AUCUNE requete, seulement des pages ;
 *   - `require_machine_access` resout l'identifiant de machine par le CORPS JSON
 *     d'abord (`backend/routes/helpers.py:331-332`) alors que les routes GET
 *     lisent EXCLUSIVEMENT `request.args` — le garde autoriserait une machine et
 *     la route en servirait une autre. Ferme aujourd'hui par les passerelles, qui
 *     ne relaient pas le corps d'un GET, mais ferme par accident ;
 *   - le decorateur ne refuse pas non plus quand aucun identifiant n'est trouve.
 * Ce controleur lit donc la base directement, comme S1 (`ExportCveController`).
 * Le backend Python n'est pas touche, et la garde de la route redevient la seule
 * chose a lire pour savoir qui entre.
 *
 * LE CLOISONNEMENT EST FAIT PAR LA REQUETE, pas apres. `machinesVisibles()`
 * joint `user_machine_access` pour un role 1 : une machine non attribuee n'entre
 * jamais dans la page, donc aucun rendu ne peut la laisser fuir. Et le resume de
 * parc est calcule SUR CETTE MEME LISTE — le legacy, lui, agrege toute la base
 * (E-47).
 *
 * LA COMPARAISON EST PARESSEUSE, et c'est deliberé. La calculer pour chaque
 * machine au chargement relirait DEUX jeux de findings entiers par machine pour
 * un panneau que personne n'a encore ouvert. Elle vit donc dans
 * `ComparaisonCveController`, appele au clic, sous la MEME garde.
 *
 * TOUT LE RESTE EST RENDU EN UNE REQUETE. Les findings de chaque machine scannee partent
 * en donnees dans la page ; la pagination, la recherche et le filtre travaillent
 * dessus sans rien redemander. Cela ferme le defaut d'affichage mesure sur le
 * legacy — quatre generateurs de lignes dont trois oublient une colonne — parce
 * qu'il n'y a plus qu'UN generateur, cote navigateur, et qu'il est partage par
 * tous les gestes. S7 s'y branchera au lieu de le dupliquer.
 */
class ScanCveController extends Controller
{
    public function __construct(private readonly ScansCve $scans)
    {
    }

    public function __invoke(Request $requete): View
    {
        $role     = (int) $requete->session()->get('role_id', 0);
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        $machines = $this->scans->machinesVisibles($idCompte, $role);
        $ids      = array_map(static fn ($m) => (int) $m->id, $machines);

        $derniers = $this->scans->derniersScansParMachine($ids);

        // Les findings, machine par machine, et SEULEMENT pour celles qui ont un
        // scan : une machine jamais scannee doit rendre un etat vide explicite,
        // pas un tableau de zero ligne qui ressemble a un chargement inacheve.
        $findings = [];
        foreach ($derniers as $machineId => $scan) {
            $findings[$machineId] = $this->scans->findingsPourAffichage((int) $scan->id);
        }

        return view('scan-cve', [
            'machines'   => $machines,
            'derniers'   => $derniers,
            'findings'   => $findings,
            'facettes'   => array_map([$this, 'facettes'], $findings),
            'resume'      => $this->scans->resumeParc($ids),
            'seuilDefaut' => (int) (getenv('CVE_MIN_CVSS') ?: 0),
            'libelles'    => $this->libelles(),
        ]);
    }

    /**
     * Les libelles consommes par le script, POSES EN DONNEES.
     *
     * Une chaine ecrite en dur dans du JS echappe a la parite FR/EN — le script
     * du legacy en porte plus de trente. Ils sont assembles ICI et non dans le
     * gabarit parce qu'un `@json` multiligne casse le PHP compile.
     *
     * @return array<string,string>
     */
    private function libelles(): array
    {
        return [
            'affiche_sur' => __('cve.affiche_sur', ['montre' => '{montre}', 'total' => '{total}']),
            'aucun_resultat' => __('cve.aucun_resultat'),
            'erreur_chargement' => __('cve.erreur_chargement'),
            'erreur_comparaison' => __('cve.erreur_comparaison'),
            'comparaison_titre' => __('cve.comparaison_titre'),
            'comparaison_insuffisante' => __('cve.comparaison_insuffisante'),
            'comparaison_ajoutees' => __('cve.comparaison_ajoutees'),
            'comparaison_corrigees' => __('cve.comparaison_corrigees'),
            'comparaison_inchangees' => __('cve.comparaison_inchangees'),
            'comparaison_identique' => __('cve.comparaison_identique'),
            'fermer' => __('cve.fermer'),
            'suivi_a_venir' => __('cve.suivi_a_venir'),
            'voir_details' => __('cve.voir_details'),
            'replier' => __('cve.replier'),
            'url_comparaison' => route('scan-cve.comparaison'),
            // La langue de la SESSION, jamais 'fr-FR' en dur : le legacy fige la
            // locale de ses dates a trois endroits, donc un utilisateur anglais y
            // lit des dates francaises.
            'langue' => app()->getLocale(),
        ];
    }

    /**
     * Les severites et les annees REELLEMENT presentes dans un jeu de findings,
     * avec leur compte.
     *
     * Calcule ici et rendu par le gabarit : les boutons de filtre sont alors du
     * HTML traduit, et non des chaines fabriquees par du JS — cote legacy, le
     * libelle « Tout (n) » et les noms de severite sont ecrits en dur dans le
     * script, donc hors de toute parite FR/EN.
     *
     * @param  list<array<string,mixed>>  $findings
     * @return array{severites:array<string,int>,annees:array<string,int>,total:int}
     */
    private function facettes(array $findings): array
    {
        $ordre = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3, 'NONE' => 4];
        $severites = [];
        $annees = [];

        foreach ($findings as $f) {
            $sev = (string) ($f['s'] ?: 'NONE');
            $severites[$sev] = ($severites[$sev] ?? 0) + 1;
            // L'annee vient de l'identifiant CVE, jamais d'une date de scan :
            // « CVE-2019-... » reste de 2019 quel que soit le jour du scan.
            $an = preg_match('/^CVE-(\d{4})-/', (string) $f['c'], $m) ? $m[1] : '?';
            $annees[$an] = ($annees[$an] ?? 0) + 1;
        }

        uksort($severites, fn ($a, $b) => ($ordre[$a] ?? 9) <=> ($ordre[$b] ?? 9));
        krsort($annees);

        return ['severites' => $severites, 'annees' => $annees, 'total' => count($findings)];
    }
}
