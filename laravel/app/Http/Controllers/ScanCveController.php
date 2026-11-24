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
 * LE DETAIL N'EST PLUS DANS LA PAGE. Elle y mettait les findings du dernier
 * scan de CHAQUE machine visible : 85 133 lignes pour 32 machines en production,
 * et le `json_encode` du gabarit epuisait les 128 Mo de PHP — un 500 sur toute la
 * page. Elle ne rend plus que le resume de parc, les compteurs de chaque scan et
 * les facettes (calculees en SQL, `facettesParScan`) ; les lignes d'une machine
 * arrivent a l'ouverture de sa carte, page par page, par
 * `FindingsCveController`. Il n'y a toujours qu'UN generateur de lignes, cote
 * navigateur — le defaut du legacy, quatre generateurs dont trois oublient une
 * colonne, reste ferme.
 */
class ScanCveController extends Controller
{
    public function __construct(
        private readonly ScansCve $scans,
        private readonly \App\Services\PlanificationsCve $planifs,
        private readonly \App\Services\Droits $droits,
    ) {
    }

    public function __invoke(Request $requete): View
    {
        $role     = (int) $requete->session()->get('role_id', 0);
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        $machines = $this->scans->machinesVisibles($idCompte, $role);
        $ids      = array_map(static fn ($m) => (int) $m->id, $machines);

        $derniers = $this->scans->derniersScansParMachine($ids);

        // Indexees par MACHINE, comme les cartes qui les affichent.
        $parScan  = $this->scans->facettesParScan(array_map(static fn ($s) => (int) $s->id, array_values($derniers)));
        $facettes = [];
        foreach ($derniers as $machineId => $scan) {
            $facettes[$machineId] = $parScan[(int) $scan->id];
        }

        return view('scan-cve', [
            // LE BLOC DE PLANIFICATION N'EST PAS RENDU EN DESSOUS DU ROLE 2, et le
            // script ne s'initialise donc pas : le legacy, lui, branche
            // `loadSchedules` pour TOUS les roles (`js/main.js:991`) alors que son
            // bloc est sous `$role >= 2`. Un role 1 y emet un `GET /cve_schedules`
            // a chaque chargement de page, refuse en 403 et avale en silence.
            'peutPlanifier' => $role >= 2,
            /*
             * LISTE BLANCHE — meme seuil que la planification, et pour la meme
             * raison : le bloc n'est pas rendu en dessous du role 2, donc le
             * script ne s'initialise pas et aucun appel refuse n'est emis a
             * l'affichage. Le backend garde ses trois routes en `role:2`
             * (`cve.py:641`) ; l'ecran ne peut pas etre plus ouvert que ce
             * qu'il commande.
             */
            'peutBlanchir' => $role >= 2,
            'libellesListeBlanche' => $role >= 2 ? $this->libellesListeBlanche() : [],
            'tags'          => $role >= 2 ? $this->planifs->tagsDisponibles() : [],
            'machines'   => $machines,
            'derniers'   => $derniers,
            'facettes'   => $facettes,
            // UNE REGLE APPLIQUEE PAR LE BACKEND SE REND VISIBLE. `POST /tickets`
            // exige `can_admin_portal` ; sans elle, le bouton est DESACTIVE avec
            // son explication plutot que cliquable pour rien. La regle n'est pas
            // deplacee cote navigateur : c'est toujours le backend qui refuse.
            'peutTicket'  => $role >= 3
                || ($this->droits->permissions($idCompte)['can_admin_portal'] ?? false),
            'resume'      => $this->scans->resumeParc($ids),
            'seuilDefaut' => (int) (getenv('CVE_MIN_CVSS') ?: 0),
            'libelles'    => $this->libelles(),
            'libellesPlanif' => $role >= 2 ? $this->libellesPlanif() : [],
            'libellesSuivi'  => $this->libellesSuivi(),
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
            'chargement' => __('cve.chargement'),
            'erreur_comparaison' => __('cve.erreur_comparaison'),
            'comparaison_titre' => __('cve.comparaison_titre'),
            'comparaison_insuffisante' => __('cve.comparaison_insuffisante'),
            'comparaison_ajoutees' => __('cve.comparaison_ajoutees'),
            'comparaison_corrigees' => __('cve.comparaison_corrigees'),
            'comparaison_inchangees' => __('cve.comparaison_inchangees'),
            // ── Enrichissement EPSS / KEV (sous-lot S6) ──────────────────────
            'kev_aide' => __('cve.kev_aide'),
            'kev_depuis' => __('cve.kev_depuis', ['date' => '{date}']),
            'blanchie' => __('cve.blanchie'), 'blanchie_aide' => __('cve.blanchie_aide'),
            'epss_aide' => __('cve.epss_aide'),
            'priorite_aide' => __('cve.priorite_aide', ['libelle' => '{libelle}']),
            'non_enrichi' => __('cve.non_enrichi'),
            'reprio_encours' => __('cve.reprio_encours'),
            'reprio_ok' => __('cve.reprio_ok', ['kev' => '{kev}', 'epss' => '{epss}']),
            'reprio_echec' => __('cve.reprio_echec'),
            // LA RE-PRIORISATION PASSE PAR LA PASSERELLE, et pour la meme raison
            // que le ticket de S5 : elle interroge deux services EXTERNES
            // (FIRST.org pour l'EPSS, le catalogue CISA pour le KEV). La
            // reimplementer ici dupliquerait cette integration, et le portage n'a
            // aucune raison de porter un client HTTP vers l'exterieur.
            'url_reprio' => url('/api/gateway/cve_reprioritize'),
            // ── Le scan (sous-lot S7a) ───────────────────────────────────────
            'scan_en_cours' => __('cve.scan_en_cours'),
            'scan_demarre' => __('cve.scan_demarre'),
            'scan_paquet' => __('cve.scan_paquet', [
                'paquet' => '{paquet}', 'courant' => '{courant}', 'total' => '{total}',
            ]),
            'scan_termine' => __('cve.scan_termine', ['paquets' => '{paquets}', 'cve' => '{cve}']),
            'scan_erreur' => __('cve.scan_erreur', ['message' => '{message}']),
            'scan_refuse' => __('cve.scan_refuse', ['statut' => '{statut}']),
            'scan_interrompu' => __('cve.scan_interrompu'),
            // LE SCAN EST UN FLUX SERVI PAR LE BACKEND : il passe par la
            // passerelle, comme le ticket de S5 et la re-priorisation de S6. Il ne
            // se reimplemente pas — c'est lui qui ouvre les sessions SSH.
            'url_scan' => url('/api/gateway/cve_scan'),
            'comparaison_identique' => __('cve.comparaison_identique'),
            'fermer' => __('cve.fermer'),
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
     * Les libelles du suivi, POSES EN DONNEES.
     *
     * Le legacy en portait DEUX JEUX pour les memes statuts — `Open`/`Accepte`
     * dans son selecteur, `Ouverte`/`Acceptee` dans son message de confirmation,
     * dont un en anglais. Ici il n'y en a qu'un.
     *
     * @return array<string,mixed>
     */
    private function libellesSuivi(): array
    {
        $statuts = [];
        foreach (\App\Services\SuiviCve::STATUTS as $st) {
            $statuts[$st] = __('suivi.' . $st);
        }

        return [
            'statuts' => $statuts,
            'choisissables' => \App\Services\SuiviCve::STATUTS_CHOISISSABLES,
            'aucun' => __('suivi.aucun'),
            'resolved_aide' => __('suivi.resolved_aide'),
            'ticket' => __('suivi.ticket'),
            'ticket_court' => __('suivi.ticket_court'),
            'ticket_aide' => __('suivi.ticket_aide'),
            'ticket_refuse' => __('suivi.ticket_refuse'),
            'ticket_cree' => __('suivi.ticket_cree'),
            'ticket_existant' => __('suivi.ticket_existant'),
            'ticket_echec' => __('suivi.ticket_echec'),
            'enregistre' => __('suivi.enregistre'),
            'err_reseau' => __('suivi.err_reseau'),
            'url_suivi' => route('scan-cve.suivi'),
            // LE TICKET PASSE PAR LA PASSERELLE, contrairement au reste du module :
            // `POST /tickets` appelle un fournisseur ITSM externe quand il est
            // configure, et le reimplementer dupliquerait une integration.
            'url_ticket' => url('/api/gateway/tickets'),
        ];
    }

    /**
     * Les libelles du bloc de planification, POSES EN DONNEES.
     *
     * Le script du legacy en porte VINGT-SIX en dur, donc hors de toute parite
     * FR/EN — dont ses deux pluriels fabriques par concatenation.
     *
     * @return array<string,string>
     */
    private function libellesPlanif(): array
    {
        $cles = ['aucune', 'actives', 'selection', 'apercu_titre', 'apercu_invalide',
                 'apercu_trop_frequent', 'col_nom', 'col_recurrence', 'col_cible',
                 'col_prochaine', 'col_derniere', 'col_auteur', 'col_etat', 'etat_active',
                 'etat_suspendue', 'activer', 'suspendre', 'supprimer', 'confirmer_suppression',
                 'confirmer_oui', 'confirmer_non', 'jamais', 'auteur_inconnu', 'creee',
                 'supprimee', 'modifiee', 'err_reseau', 'cible_all', 'cible_tag',
                 'cible_machines'];
        $libelles = [];
        foreach ($cles as $c) {
            // Les compteurs gardent leur marqueur : le script le remplace, il ne
            // fabrique pas de pluriel par concatenation.
            $libelles[$c] = __('planif.' . $c, ['nombre' => '{nombre}']);
        }
        $libelles['url_planifs'] = route('scan-cve.planifs');
        $libelles['url_apercu'] = route('scan-cve.apercu-cron');
        $libelles['langue'] = app()->getLocale();

        return $libelles;
    }

    /**
     * Les libelles de la liste blanche, plus l'adresse de ses routes.
     *
     * UNE SEULE adresse est transmise : le script derive la suppression en y
     * ajoutant l'identifiant. Deux adresses transmises separement finissent par
     * diverger — c'est ce que ce module a deja paye sur `url_planifs`.
     *
     * @return array<string,string>
     */
    private function libellesListeBlanche(): array
    {
        $cles = ['titre', 'description', 'poser', 'retirer', 'confirmer_retrait',
                 'portee_globale', 'sans_echeance', 'echue', 'vide', 'posee',
                 'retiree', 'err_reseau'];

        $libelles = [];
        foreach ($cles as $c) {
            $libelles[$c] = __('liste_blanche.' . $c);
        }
        $libelles['url_liste'] = route('scan-cve.liste-blanche');
        $libelles['langue'] = app()->getLocale();

        return $libelles;
    }
}
