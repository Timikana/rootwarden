<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\ExportRgpd;
use App\Services\JournalAudit;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Le telechargement des donnees personnelles — RGPD article 15 et 20.
 *
 * Porte de `legacy/profile/export.php`. Specification de reference :
 * `docs/migration/QA-SPEC-EXPORT-RGPD.md`.
 *
 * ⚠ CETTE CAPACITE EST OUVERTE A TOUT COMPTE CONNECTE, DES LE ROLE 1, et c'est
 * volontaire : la portabilite est un droit de la personne, pas un privilege
 * d'administration. Le legacy fait de meme
 * (`checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])`). Une suite qui
 * n'exercerait que l'administrateur laisserait le seul chemin qui compte non
 * emprunte.
 *
 * ⚠ LA SOURCE EST LA SESSION, JAMAIS LA REQUETE. Aucun parametre ne peut
 * designer un autre compte, et il n'en est offert aucun — ne pas offrir
 * d'entree libre est plus sur que la valider, parce qu'une entree absente ne se
 * forge pas.
 */
class ExportRgpdController extends Controller
{
    public function __construct(
        private readonly ExportRgpd $export,
        private readonly JournalAudit $journal,
    ) {
    }

    public function __invoke(Request $requete): Response
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        $roleCompte = (int) $requete->session()->get('role_id', 0);

        /*
         * FAIL-CLOSED. L'intergiciel `role:1` garde deja cette route, mais une
         * session sans identifiant ne doit pas produire un export « du compte 0 »
         * — ce serait un filtre `WHERE user_id = 0`, donc un fichier vide
         * presente comme la copie des donnees de quelqu'un.
         */
        if ($idCompte <= 0) {
            abort(403);
        }

        /*
         * LA DEMANDE SE JOURNALISE AVANT LA LECTURE, et cet ordre est le fond
         * de l'affaire : au regard de l'article 30, l'evenement enregistrable
         * est la DEMANDE, pas sa reussite. Journaliser apres perdrait la trace
         * de toute demande qui echoue — c'est-a-dire precisement celles qu'un
         * registre doit montrer.
         *
         * Le legacy appelle `audit_log_raw` (`profile/export.php:37`), qui
         * chaine dans une transaction verrouillee. On passe par l'ecrivain
         * canonique, qui reprend ce verrou.
         */
        $this->journal->ajoute($idCompte, '[rgpd] Export des donnees personnelles demande');

        $contenu = json_encode(
            $this->export->pour($idCompte, $roleCompte),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
        );

        /*
         * `json_encode` rend `false` sur une donnee non encodable — par exemple
         * un octet invalide en UTF-8 venu d'un `user_agent`. Un `false` renvoye
         * tel quel produirait un fichier VIDE nomme comme un export : la
         * personne archiverait un fichier de zero octet en croyant detenir sa
         * copie. On refuse plutot que de livrer ca.
         */
        if ($contenu === false) {
            abort(500);
        }

        return response($contenu, 200, [
            'Content-Type' => 'application/json; charset=utf-8',
            'Content-Disposition' => 'attachment; filename="'
                . $this->export->nomFichier($idCompte) . '"',
            // Un export de donnees personnelles ne doit pas se retrouver dans un
            // cache partage, ni dans celui du navigateur.
            'Cache-Control' => 'no-store, no-cache, must-revalidate',
            'Pragma' => 'no-cache',
        ]);
    }
}
