<?php

namespace App\Http\Controllers;

use App\Services\JournalAudit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Le journal d'audit — module `adm/`, sous-lot D1.
 *
 * La garde vit dans les middlewares de la route (`role:2` + `perm:can_admin_portal`),
 * jamais ici : le legacy pose la sienne sur la PAGE et sur AUCUN de ses seize
 * points d'API, et c'est le defaut le plus repandu du depot.
 *
 * Les deux gestes d'integrite sont reserves au ROLE 3, comme dans le legacy
 * (`adm/audit_log.php:147` cote page, `checkAuth([ROLE_SUPERADMIN])` cote point
 * d'API). Ici la reserve est portee par la ROUTE, donc elle vaut pour la requete
 * et pas seulement pour l'affichage du bouton.
 */
class JournalAuditController extends Controller
{
    public function __construct(private readonly JournalAudit $journal)
    {
    }

    public function __invoke(Request $requete): View
    {
        $filtres = $this->journal->filtres($requete->query());
        $total = $this->journal->compte($filtres);
        $pages = max(1, (int) ceil($total / JournalAudit::PAR_PAGE));
        // `?page[]=1` arriverait en tableau : on ne convertit que ce qui est
        // scalaire, le reste retombe sur la premiere page.
        $demandee = $requete->query('page', 1);
        $page = min($pages, max(1, is_scalar($demandee) ? (int) $demandee : 1));

        return view('journal-audit', [
            'filtres' => $filtres,
            'total' => $total,
            // Formate ICI et non dans la vue : le separateur de milliers depend
            // de la langue, et une vue n'a pas a porter cette regle.
            'nombreFormate' => app()->getLocale() === 'en'
                ? number_format($total)
                : number_format($total, 0, ',', ' '),
            'page' => $page,
            'pages' => $pages,
            'filtre' => array_filter($filtres, static fn (string $v): bool => $v !== '') !== [],
            'lignes' => $this->journal->lignes($filtres, $page),
            'peutSceller' => (int) session('role_id', 0) === 3,
        ]);
    }

    /**
     * Export CSV de TOUS les resultats filtres.
     *
     * ASSEMBLE EN MEMOIRE PUIS RENDU D'UN BLOC — jamais ecrit au fil de l'eau
     * dans la sortie. C'est la parade posee apres l'incident de `cve_export.php`
     * (E-24) : un avertissement PHP emis en cours d'ecriture s'inserait DANS le
     * fichier telecharge, et 1 458 vulnerabilites y sont devenues 4 374
     * enregistrements. Rien ne part avant que tout soit ecrit.
     */
    public function csv(Request $requete): StreamedResponse
    {
        $filtres = $this->journal->filtres($requete->query());
        $nom = 'journal_audit_' . date('Y-m-d') . '.csv';

        $tampon = fopen('php://temp', 'r+');
        // BOM UTF-8 : sans lui, Excel lit les accents en Latin-1.
        fwrite($tampon, "\xEF\xBB\xBF");
        fputcsv($tampon, [
            __('audit.col_id'), __('audit.col_date'),
            __('audit.col_utilisateur'), __('audit.col_action'),
        ], ',', '"', '\\');

        foreach ($this->journal->toutesPourExport($filtres) as $ligne) {
            fputcsv($tampon, [
                $ligne['id'], $ligne['created_at'], $ligne['utilisateur'], $ligne['action'],
            ], ',', '"', '\\');
        }

        rewind($tampon);
        $contenu = (string) stream_get_contents($tampon);
        fclose($tampon);

        return response()->streamDownload(
            static function () use ($contenu): void { echo $contenu; },
            $nom,
            ['Content-Type' => 'text/csv; charset=utf-8']
        );
    }

    /** Verdict d'integrite. LECTURE SEULE — aucune ecriture sur ce chemin. */
    public function verifier(): JsonResponse
    {
        return response()->json(['success' => true] + $this->journal->verifie());
    }

    /**
     * Scellement des lignes orphelines.
     *
     * DEUX GESTES, PAS UN. `?simulation=1` rend ce que l'ecriture produirait
     * sans rien ecrire ; sans lui, l'ecriture a lieu. Le legacy offre bien la
     * meme distinction (methode non-POST = simulation) mais aucun element de son
     * interface ne l'emet : le seul bouton POSTe, donc la simulation n'est
     * atteignable par aucun clic.
     *
     * L'ecriture est IRREVERSIBLE — remettre des NULL fabriquerait un autre etat,
     * pas celui d'avant. La page fait donc saisir le nombre de lignes concernees
     * avant d'activer la confirmation, et ce controle est REPETE ici : une garde
     * du navigateur deplace le refus, elle ne le supprime pas.
     */
    public function sceller(Request $requete): JsonResponse
    {
        $simulation = $requete->boolean('simulation');

        if (! $simulation) {
            $attendu = $this->journal->verifie()['orphelines'];
            $brut = $requete->input('confirmation', -1);
            $saisi = is_scalar($brut) ? (int) $brut : -1;
            if ($saisi !== $attendu) {
                return response()->json([
                    'success' => false,
                    'message' => __('audit.err_confirmation', ['attendu' => $attendu]),
                ], 422);
            }
        }

        return response()->json(['success' => true] + $this->journal->scelle($simulation));
    }
}
