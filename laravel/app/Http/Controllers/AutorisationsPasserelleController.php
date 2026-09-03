<?php

namespace App\Http\Controllers;

use App\Services\AutorisationsPasserelle;
use Illuminate\View\View;

/**
 * Ce que la passerelle autorise — remplace `legacy/api/docs.php`.
 *
 * ══ LA GARDE EST CELLE DU CODE, PAS CELLE DE SON COMMENTAIRE ═════════════
 *
 * `legacy/api/docs.php:4` annonce « Accessible uniquement aux admins et
 * superadmins ». Sa ligne 9 fait `checkAuth([ROLE_SUPERADMIN])` : **superadmin
 * seul**. Le commentaire promet un acces PLUS LARGE que le code — E-231, et
 * consigne de ne pas le transporter.
 *
 * La garde portee est donc `role:3`, celle que le code applique. Et le motif est
 * le bon : `openapi.php` avait recu le meme resserrement (« la spec brute revele
 * toutes les routes/parametres -> meme niveau d'acces que l'UI Swagger »).
 *
 * ══ CE QUE CETTE PAGE N'EST PAS ══════════════════════════════════════════
 *
 * **Ce n'est pas une reference d'API.** Elle ne decrit ni les parametres, ni les
 * corps de requete, ni les reponses — elle derive des AUTORISATIONS. Un titre
 * qui promettrait une reference serait la meme faute un etage plus haut que
 * celle qu'on vient de retirer.
 */
final class AutorisationsPasserelleController extends Controller
{
    public function __construct(private readonly AutorisationsPasserelle $autorisations)
    {
    }

    public function __invoke(): View
    {
        return view('autorisations-passerelle', [
            'compteurs'     => $this->autorisations->compteurs(),
            'listeBlanche'  => $this->autorisations->listeBlanche(),
            'reserveAdmin'  => $this->autorisations->reserveAdmin(),
            'flux'          => $this->autorisations->flux(),
            'motifsReauth'  => $this->autorisations->motifsReauthentification(),
        ]);
    }
}
