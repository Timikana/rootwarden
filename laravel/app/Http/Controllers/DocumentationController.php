<?php

namespace App\Http\Controllers;

use App\Services\Droits;
use App\Support\Navigation;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Documentation du portail.
 *
 * ══ LA GARDE EST UN SEUIL DE ROLE, PAS UNE PERMISSION ═════════════════════
 *
 * `legacy/documentation.php:11` pose `checkAuth([ROLE_USER, ROLE_ADMIN,
 * ROLE_SUPERADMIN])` et **aucun** `checkPermission` — la seule occurrence du
 * fichier (`:295`) est dans un EXEMPLE DE CODE. Le seul cloisonnement est
 * `$isAdmin = $role >= 2` (`:16`), qui enclot six blocs et cinq sections :
 * `api`, `proxy`, `healthcheck`, `preprod` et la console.
 *
 * Un role 1 voit donc 43 des 48 sections, et se trouve borne a la
 * documentation FONCTIONNELLE. C'est coherent, et c'est la seule chose de
 * cette page gardee par une decision plutot que par l'oubli.
 *
 * La route ne porte donc NI `role:` NI `perm:` — comme `accueil` et `profil`,
 * dont l'entree de menu porte aussi `'garde' => 'tous'`. Le seuil vit DANS la
 * page, exactement ou le legacy le place.
 *
 * ⚠ Et il est DECLARE a l'ecran : `'garde' => 'tous'` est vrai de la PAGE et
 * faux de son CONTENU. Un lecteur qui cherche une permission n'en trouvera
 * pas et conclura que tout est ouvert.
 *
 * ══ CE QUE CETTE PAGE NE RECOPIE PAS ══════════════════════════════════════
 *
 * `grep -c '$pdo' legacy/documentation.php` -> **0**. La page du legacy ne
 * fait aucune requete : tout ce qu'elle affirme sur les routes, les roles et
 * les permissions est du HTML ecrit a la main, qu'aucun mecanisme ne
 * regenere. L'inventaire y a mesure douze chemins de page perimes, deux
 * routes citees qui n'existent pas, et onze sections decrivant des parties
 * retirees du produit.
 *
 * **Reproduire un artefact que rien ne regenere n'est pas de la fidelite :
 * c'est recopier un cache.** Ce qui peut etre derive l'est ailleurs —
 * `autorisations-passerelle`, construite a partir de la liste blanche reelle.
 *
 * Sont donc portes : les 22 cles `guide.*`, seule partie TRADUITE du fichier,
 * et la structure. Pas la prose, pas la console d'API.
 */
class DocumentationController extends Controller
{
    public function __construct(private readonly Droits $droits)
    {
    }

    public function __invoke(Request $requete): View
    {
        $role = (int) $requete->session()->get('role_id', 0);
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        /*
         * ══ UN LIEN QU'ON N'OFFRE QUE S'IL MENE QUELQUE PART ══════════════
         *
         * `autorisations-passerelle` est gardee `role:3`. Conditionner son
         * lien au SEUIL DE CETTE PAGE (role >= 2) offrirait a un role 2 une
         * porte qui refuse — et poser `role >= 3` en dur ici recopierait la
         * garde de cette route, donc en creerait une seconde copie a faire
         * diverger.
         *
         * On lit donc l'entree dans le MENU du compte, comme les tuiles de
         * l'accueil et les alertes de `groups`. Une seule source.
         *
         * ⚠ Ce defaut, je l'avais evite par construction sur `groups` et
         * REINTRODUIT ici : appliquer une regle dans un module ne la porte
         * pas au suivant.
         */
        $entrees = collect(Navigation::pour($role, $this->droits->permissions($idCompte)))->flatten(1);
        $derive = $entrees->firstWhere('cle', 'api_docs')
            ?? $entrees->firstWhere('route', 'autorisations-passerelle');

        return view('documentation', [
            // Le MEME seuil que `$isAdmin` du legacy, au meme endroit : dans
            // la page. Le porter en middleware fermerait la page entiere, la
            // ou le legacy n'en ferme que cinq sections.
            'administration' => $role >= 2,
            // Non pas « ce compte est administrateur », mais « cette page-la
            // lui est ouverte ». Les deux ne coincident pas.
            'lienDerive' => $derive !== null && isset($derive['route']) ? route($derive['route']) : null,
            'lienLegacy' => rtrim((string) config('app.url_legacy'), '/') . '/documentation.php',
        ]);
    }
}
