<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\Onboarding;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/**
 * Le seul geste d'ecriture de l'assistant : le masquer.
 *
 * ══ UN FORMULAIRE, PAS DU JAVASCRIPT ══════════════════════════════════════
 *
 * Le legacy pose un `fetch` vers `/adm/api/dismiss_onboarding.php` et retire le
 * bloc du DOM a la main. Ici c'est un `<form method="POST">` : le geste est
 * idempotent, sans consequence, et il n'a besoin ni d'un compte rendu ni d'une
 * mise a jour partielle de la page. *Un script qui n'apporte rien qu'un
 * formulaire ne fasse est une piece de plus a maintenir et un chemin de plus a
 * eprouver.*
 *
 * La falsification de requete est deja traitee par le groupe `web`
 * (`PreventRequestForgery`) : on n'ajoute pas un second controle par-dessus.
 *
 * ══ LE GESTE NE VISE QUE SON PROPRE COMPTE ════════════════════════════════
 *
 * L'identifiant vient de la SESSION, jamais d'un parametre. Il n'existe donc
 * aucune facon de masquer l'assistant de quelqu'un d'autre — la garde est dans
 * l'absence de parametre, pas dans un controle qu'on pourrait oublier.
 */
class OnboardingController extends Controller
{
    public function __construct(private readonly Onboarding $onboarding)
    {
    }

    public function masquer(Request $requete): RedirectResponse
    {
        $id = (int) $requete->session()->get('utilisateur_id', 0);
        if ($id > 0) {
            $this->onboarding->masquer($id);
        }

        return redirect()->route('accueil');
    }
}
