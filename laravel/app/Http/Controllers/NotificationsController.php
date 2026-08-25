<?php

namespace App\Http\Controllers;

use App\Services\Notifications;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Les notifications in-app — module `adm/`, sous-lot D2.
 *
 * ══ TOUT GESTE QUI ECRIT EST UN POST, ET UNE ROUTE A LUI ═══════════════════
 *
 * Le legacy porte un point d'API unique dont l'action est lue dans `$_GET`
 * d'abord (`adm/api/notifications.php:23`), et ne verifie le jeton que si la
 * methode est `POST` (`:26-27`). `GET ?action=read_all` ecrit donc sans aucun
 * jeton — mesure du 2026-08-26 : `200 {"updated":2}`, deux non lues avant, zero
 * apres. C'est E-109, et c'est la regle « un GET ne doit rien ecrire » prise en
 * defaut.
 *
 * Ici chaque geste a sa route et sa methode. Les `POST` traversent
 * `PreventRequestForgery` du groupe `web` ; le `GET` du compteur ne fait que
 * lire.
 *
 * ══ LA PORTEE VIT DANS LE SERVICE, PAS ICI ═════════════════════════════════
 *
 * `Notifications::portee()` s'applique a la lecture comme a l'ecriture. Le
 * controleur ne compose aucune clause : il ne peut donc pas en oublier une, ce
 * qui est exactement ce qui est arrive au legacy sur deux de ses trois
 * ecritures (E-110).
 */
class NotificationsController extends Controller
{
    public function __construct(private readonly Notifications $notifications)
    {
    }

    private function qui(Request $requete): array
    {
        return [
            (int) $requete->session()->get('utilisateur_id', 0),
            (int) $requete->session()->get('role_id', 0),
        ];
    }

    public function __invoke(Request $requete): View
    {
        [$userId, $roleId] = $this->qui($requete);
        $filtres = $this->notifications->filtres($requete->query());
        $total = $this->notifications->compte($userId, $roleId, $filtres);
        $pages = max(1, (int) ceil($total / Notifications::PAR_PAGE));
        $demandee = $requete->query('page', 1);
        $page = min($pages, max(1, is_scalar($demandee) ? (int) $demandee : 1));

        return view('notifications', [
            'lignes' => $this->notifications->liste($userId, $roleId, $filtres, $page),
            'total' => $total,
            'nonLues' => $this->notifications->nonLues($userId, $roleId),
            'filtres' => $filtres,
            'page' => $page,
            'pages' => $pages,
            'types' => Notifications::TYPES,
        ]);
    }

    /** Le compteur de la pastille. LECTURE SEULE. */
    public function compte(Request $requete): JsonResponse
    {
        [$userId, $roleId] = $this->qui($requete);

        return response()->json([
            'success' => true,
            'nombre' => $this->notifications->nonLues($userId, $roleId),
        ]);
    }

    /**
     * Marquer UNE notification lue.
     *
     * Rend le compteur a jour dans la MEME reponse : la page n'a alors rien a
     * recalculer, et surtout rien a supposer. Le legacy, lui, retire le bouton
     * dans un `onclick` qui s'execute AVANT que la requete parte — si bien
     * qu'aucune requete ne part et que l'ecran annonce une lecture qui n'a pas
     * eu lieu (E-108).
     */
    public function lire(Request $requete, int $id): JsonResponse
    {
        [$userId, $roleId] = $this->qui($requete);
        $touchees = $this->notifications->marqueLue($id, $userId, $roleId);

        return response()->json([
            'success' => $touchees > 0,
            'touchees' => $touchees,
            'nonLues' => $this->notifications->nonLues($userId, $roleId),
            'message' => $touchees > 0 ? __('notif.marquee_lue') : __('notif.err_hors_portee'),
        ], $touchees > 0 ? 200 : 404);
    }

    public function toutLire(Request $requete): JsonResponse
    {
        [$userId, $roleId] = $this->qui($requete);
        $touchees = $this->notifications->marqueToutLu($userId, $roleId);

        return response()->json([
            'success' => true,
            'touchees' => $touchees,
            'nonLues' => $this->notifications->nonLues($userId, $roleId),
        ]);
    }

    public function supprimer(Request $requete, int $id): JsonResponse
    {
        [$userId, $roleId] = $this->qui($requete);
        $touchees = $this->notifications->supprime($id, $userId, $roleId);

        return response()->json([
            'success' => $touchees > 0,
            'nonLues' => $this->notifications->nonLues($userId, $roleId),
            'message' => $touchees > 0 ? __('notif.supprimee') : __('notif.err_hors_portee'),
        ], $touchees > 0 ? 200 : 404);
    }

    /* ═══ Reglages — role 3, garde portee par la ROUTE ══════════════════════ */

    public function reglages(): View
    {
        $comptes = $this->notifications->comptes();
        $prefs = [];
        foreach ($comptes as $compte) {
            $prefs[$compte['id']] = $this->notifications->preferences($compte['id']);
        }

        return view('notifications-reglages', [
            'comptes' => $comptes,
            'prefs' => $prefs,
            'reglables' => Notifications::TYPES_REGLABLES,
            'inconditionnels' => Notifications::TYPES_INCONDITIONNELS,
        ]);
    }

    public function definirPreference(Request $requete): JsonResponse
    {
        $cible = $requete->input('user_id');
        $type = $requete->input('event_type');
        // `ConvertEmptyStringsToNull` rend « vide » indiscernable d'« absent » :
        // on teste la PRESENCE avant de lire la valeur.
        if (! is_scalar($cible) || ! is_string($type) || ! $requete->has('value')) {
            return response()->json([
                'success' => false, 'message' => __('notif.err_donnees'),
            ], 422);
        }

        $actif = $requete->boolean('value');
        if (! $this->notifications->definitPreference((int) $cible, $type, $actif)) {
            return response()->json([
                'success' => false, 'message' => __('notif.err_type'),
            ], 422);
        }

        return response()->json([
            'success' => true,
            'actif' => $actif,
            'message' => $actif ? __('notif.pref_activee') : __('notif.pref_desactivee'),
        ]);
    }
}
