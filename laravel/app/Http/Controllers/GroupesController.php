<?php

namespace App\Http\Controllers;

use Illuminate\View\View;

/**
 * Groupes de machines et actions de masse — sous-lot R1.
 *
 * ══ CE CONTROLEUR NE FAIT AUCUNE LECTURE NI AUCUNE ECRITURE ══════════════
 *
 * Tout passe par la passerelle : `GET /groups` et `GET /groups/<id>/members`
 * sont appeles depuis le navigateur, comme dans le legacy. `RoutesBackend`
 * porte deja `/groups` dans la liste blanche ET dans la reserve
 * d'administration — il n'y avait rien a y ajouter.
 *
 * ══ CE QUE R1 PORTE, ET CE QU'IL NE PORTE PAS ════════════════════════════
 *
 * Porte : la page, ses gardes, la liste, le depliage des membres, l'etat vide.
 * NON porte : creation (`POST /groups`), suppression (`DELETE /groups/<id>`)
 * et les deux actions de masse (`POST /groups/<id>/run`).
 *
 * Les quatre gestes absents n'ont PAS de bouton inerte : chacun ouvre un
 * panneau qui dit ce qu'il engage, puis renvoie vers l'ancien portail. Le
 * formulaire de creation, lui, n'est pas rendu du tout — un formulaire dont
 * « Enregistrer » ne ferait rien serait exactement le bouton inerte que cette
 * convention interdit. Il viendra AVEC sa route.
 *
 * ══ ET CE QUE LA PAGE DIT QUE LE LEGACY TAIT ═════════════════════════════
 *
 * `_resolve_dynamic` (`backend/routes/groups.py:77`) termine par
 * `where = (' AND '.join(clauses)) if clauses else '1=1'` : un groupe
 * dynamique SANS aucun critere contient le parc entier, `srv-zabbix`
 * comprise. Le legacy affiche ce cas comme une ligne de resume VIDE
 * (`main.js:21-28`, `filtersSummary({})` rend `''`). Ici il est nomme.
 */
class GroupesController extends Controller
{
    public function __invoke(): View
    {
        return view('groupes', [
            // Le catalogue part d'un bloc, en une ligne : `@json` multiligne
            // casse le PHP compile.
            'libelles' => __('groups'),
            // L'adresse de l'ancien portail est resolue ICI et non dans le
            // script : une URL construite en JavaScript ne se relit pas, et
            // c'est la meme forme que partout ailleurs dans le portage.
            'lienLegacy' => rtrim((string) config('app.url_legacy'), '/') . '/groups/index.php',
        ]);
    }
}
