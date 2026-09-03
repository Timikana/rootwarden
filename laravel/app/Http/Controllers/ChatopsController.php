<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\View\View;

/**
 * ChatOps : correspondances « identifiant chat -> compte RootWarden ».
 *
 * Deux pieces de nature TRES differente vivent ici, et il faut les distinguer :
 *
 *   1. la PAGE de configuration, gardee par `role:2` + `perm:can_admin_portal`,
 *      qui lit et ecrit par la passerelle authentifiee ;
 *   2. le WEBHOOK, point d'entree **public et sans session**, que Slack appelle.
 *
 * ══ ETAT MESURE DE LA FONCTIONNALITE ════════════════════════════════════════
 *
 * Aucune variable `CHATOPS_*` dans `srv-docker.env` (seul l'exemple en porte, a
 * `false`), et zero correspondance en base. Le backend rend **403 « ChatOps
 * desactive »** avant tout examen de signature
 * (`backend/routes/chatops.py:34`). Le webhook est donc, en l'etat, une porte
 * qui ne mene nulle part — mais il faut la porter pour que la fonctionnalite
 * reste activable apres la bascule.
 */
class ChatopsController extends Controller
{
    /** Les en-tetes d'authentification chat, et EUX SEULS, sont relayes. */
    private const ENTETES_CHAT = [
        'X-Slack-Signature',
        'X-Slack-Request-Timestamp',
        'X-ChatOps-Token',
        'X-ChatOps-Platform',
    ];

    public function page(Request $requete): View
    {
        /*
         * Les comptes actifs peuplent le choix de correspondance. C'est la seule
         * requete SQL de la page — le reste passe par la passerelle.
         */
        $comptes = DB::table('users')
            ->select('id', 'name')
            ->where('active', 1)
            ->orderBy('name')
            ->get();

        return view('chatops', [
            'comptes' => $comptes,
            /*
             * L'URL A CONFIGURER COTE SLACK. Construite depuis la requete
             * courante, comme le legacy le fait avec `HTTP_HOST` : c'est
             * l'adresse par laquelle on vient d'arriver, donc celle qui marche.
             *
             * ATTENTION EXPLOITATION : cette adresse DIFFERE de celle du legacy
             * (`/chatops/webhook.php`). Activer ChatOps apres la bascule demande
             * de la reconfigurer dans Slack. Sans mapping ni secret aujourd'hui,
             * l'impact est nul — mais il doit etre dit.
             */
            'urlWebhook' => $requete->getSchemeAndHttpHost() . '/chatops/webhook',
        ]);
    }

    /**
     * Le passthrough PUBLIC. Aucune session, aucun jeton CSRF, aucun privilege.
     *
     * POURQUOI SANS AUTHENTIFICATION DE SESSION : Slack ne peut pas en presenter
     * une. L'authentification reelle est faite par le backend, sur la SIGNATURE
     * Slack ou un jeton partage — et il refuse d'emblee si la fonctionnalite est
     * desactivee. Cette route ne lit RIEN de la session et n'accorde RIEN : elle
     * recopie un corps brut et quatre en-tetes vers un service interne.
     *
     * Ce qu'elle ne fait surtout pas : relayer les en-tetes de la requete en
     * bloc. Un `Cookie` ou un `Authorization` recopie vers le backend
     * transformerait ce relais en confusion d'identite. La liste est FERMEE.
     */
    public function webhook(Request $requete): JsonResponse
    {
        $entetes = ['X-API-KEY' => (string) config('rootwarden.backend.cle_api', '')];
        foreach (self::ENTETES_CHAT as $nom) {
            $valeur = $requete->header($nom);
            if ($valeur !== null && $valeur !== '') {
                $entetes[$nom] = $valeur;
            }
        }
        $entetes['Content-Type'] = (string) ($requete->header('Content-Type')
            ?: 'application/x-www-form-urlencoded');

        try {
            $reponse = Http::withHeaders($entetes)
                ->withoutVerifying()
                ->timeout((int) config('rootwarden.backend.delai', 120))
                ->withBody($requete->getContent(), $entetes['Content-Type'])
                ->post(rtrim((string) config('rootwarden.backend.url'), '/') . '/chatops/command');
        } catch (\Throwable $e) {
            /* Le detail part au JOURNAL, jamais au client : celui-ci est public. */
            Log::warning('chatops: backend injoignable', ['erreur' => $e->getMessage()]);

            return response()->json(['text' => __('chatops.backend_injoignable')], 502);
        }

        /*
         * LE STATUT DU BACKEND EST PROPAGE TEL QUEL. Un 401 devenu 200 ferait
         * croire a Slack que la commande a ete acceptee.
         */
        $corps = $reponse->json();

        return response()->json(
            is_array($corps) ? $corps : ['text' => (string) $reponse->body()],
            $reponse->status(),
        );
    }
}
