<?php

namespace App\Http\Controllers;

use App\Services\ComptesDistants;
use App\Services\Machines;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Les comptes distants d'une machine — module `adm/`, sous-lot D8.
 *
 * ══ LA GARDE EST ALIGNEE SUR LES ACTIONS, ET C'EST UNE DIVERGENCE ═════════
 *
 * `server_users.php:11` admet le ROLE 1 (`checkAuth([ROLE_USER, ROLE_ADMIN,
 * ROLE_SUPERADMIN])`). Or SIX de ses SEPT routes exigent `@require_role(2)`, et
 * la page ne distingue aucun role dans son rendu — un role 1 porteur de
 * `can_manage_remote_users` verrait tous les boutons et recevrait 401 sur six
 * d'entre eux, sans avertissement.
 *
 * Le portage exige donc `role:2`. Ce n'est pas un durcissement gratuit : c'est
 * l'alignement de la page sur ce qu'elle peut reellement faire. Proposer un
 * geste qu'on sait impossible est pire que le refuser.
 *
 * CE QUE CELA RETIRE, et il faut le dire : un role 1 porteur de la permission
 * perdrait l'acces a `/server_user_keys` — la seule des sept routes qui l'admet,
 * bornee par `@require_machine_access` a ses propres machines. Mesure du
 * 2026-08-26 : **aucun compte de role 1 ne porte cette permission**, un seul
 * compte du parc l'a et c'est `superadmin`. Rien n'est donc retire a personne
 * aujourd'hui. Voir PARITE, sous-lot D8.
 *
 * ══ AUCUN SCAN AU CHARGEMENT ══════════════════════════════════════════════
 *
 * `/scan_server_users` ouvre une session SSH. La page ne le declenche JAMAIS
 * d'elle-meme : elle affiche ce que le dernier scan a laisse en base, et le
 * scan est un geste. `health_check.php` a montre ce que coute une page qui
 * joint le parc en s'ouvrant.
 */
class ComptesDistantsController extends Controller
{
    public function __construct(
        private readonly ComptesDistants $comptes,
        private readonly Machines $machines,
    ) {}

    public function __invoke(Request $requete): View
    {
        $machine = (int) $requete->query('machine', 0);
        $parc = $this->machines->liste();
        if ($machine === 0 && $parc !== []) {
            $machine = (int) $parc[0]->id;
        }

        return view('comptes-distants', [
            'parc' => $parc,
            'machine' => $machine,
            'nomMachine' => $this->nomDe($parc, $machine),
            'comptes' => $machine > 0 ? $this->comptes->inventaire($machine) : [],
            'enAttente' => $machine > 0 ? $this->comptes->enAttente($machine) : 0,
            'statuts' => ComptesDistants::STATUTS,
            'statutInitial' => ComptesDistants::STATUT_INITIAL,
            // Les libelles que le JS compose. Ils partent en JSON, jamais en
            // interpolation : un nom de compte distant vient de la machine, pas
            // de nous, et E-114 a coute une page entiere pour une apostrophe.
            'libelles' => [
                'scan_en_cours' => __('distants.scan_en_cours'),
                'scan_fait' => __('distants.scan_fait'),
                'illisible_ligne' => __('distants.illisible_ligne', ['motif' => '{motif}']),
                'illisible_classable' => __('distants.illisible_classable'),
                'illisible_hors_gestes' => __('distants.illisible_hors_gestes'),
                'illisible_divergence' => __('distants.illisible_divergence', ['nombre' => '{nombre}']),
                'url_inventaire' => '/api/gateway/server_users_inventory',
                'illisibles_titre' => __('distants.illisibles_titre'),
                'illisibles_texte' => __('distants.illisibles_texte', ['nombre' => '{nombre}', 'liste' => '{liste}']),
                'illisibles_bloquant' => __('distants.illisibles_bloquant'),
                'motif_vide' => __('distants.motif_vide'),
                'motif_trop_long' => __('distants.motif_trop_long'),
                'motif_composant_de_chemin' => __('distants.motif_composant_de_chemin'),
                'motif_caracteres_interdits' => __('distants.motif_caracteres_interdits'),
                'motif_inconnu' => __('distants.motif_inconnu'),
                'scan_non_concluant' => __('distants.scan_non_concluant', ['sources' => '{sources}']),
                'scan_comptes_lus' => __('distants.scan_comptes_lus'),
                'scan_source_comptes' => __('distants.scan_source_comptes'),
                'scan_source_cles_root' => __('distants.scan_source_cles_root'),
                'scan_source_cles_utilisateur' => __('distants.scan_source_cles_utilisateur'),
                'scan_echec' => __('distants.scan_echec'),
                'geste_sans_compte' => __('distants.geste_sans_compte'),
                'geste_en_cours' => __('distants.geste_en_cours'),
                'geste_fait' => __('distants.geste_fait'),
                'geste_echec' => __('distants.geste_echec'),
                'panneau_cles_titre' => __('distants.panneau_cles_titre', ['nom' => '__NOM__']),
                'panneau_cles_texte' => __('distants.panneau_cles_texte', ['nom' => '__NOM__', 'machine' => '__MACHINE__']),
                'panneau_sshd_titre' => __('distants.panneau_sshd_titre', ['nom' => '__NOM__']),
                'panneau_sshd_texte' => __('distants.panneau_sshd_texte', ['nom' => '__NOM__', 'machine' => '__MACHINE__']),
                'panneau_suppr_titre' => __('distants.panneau_suppr_titre', ['nom' => '__NOM__']),
                'panneau_suppr_texte' => __('distants.panneau_suppr_texte', ['nom' => '__NOM__', 'machine' => '__MACHINE__']),
            ],
        ]);
    }

    /** Classe un compte. Ecrit EN BASE — la route du backend ne fait rien d'autre. */
    public function classer(Request $requete, int $machine): RedirectResponse
    {
        $username = (string) $requete->input('username', '');
        $statut = (string) $requete->input('statut', '');

        $issue = $this->comptes->classe(
            $machine, $username, $statut,
            (int) $requete->session()->get('utilisateur_id', 0),
            (string) $requete->input('notes', ''),
        );

        return match ($issue) {
            'introuvable' => $this->retour($machine, erreur: __('distants.err_introuvable', ['nom' => $username])),
            'statut_refuse' => $this->retour($machine, erreur: __('distants.err_statut')),
            default => $this->retour($machine, succes: __('distants.classe', [
                'nom' => $username, 'statut' => __('distants.statut_' . $statut),
            ])),
        };
    }

    /**
     * Classe d'un coup tous les comptes en attente d'examen.
     *
     * LE NOMBRE EST ANNONCE. « 7 comptes classes » se verifie, « classement
     * effectue » ne dit pas sur combien d'objets le geste a porte — et decider
     * d'un geste de masse sans savoir sur combien il porte n'a pas de sens.
     */
    public function classerLesEnAttente(Request $requete, int $machine): RedirectResponse
    {
        $statut = (string) $requete->input('statut', '');
        $n = $this->comptes->classeLesEnAttente(
            $machine, $statut, (int) $requete->session()->get('utilisateur_id', 0),
        );

        return $n === 0
            ? $this->retour($machine, erreur: __('distants.err_aucun_en_attente'))
            : $this->retour($machine, succes: __('distants.classes_en_masse', [
                'n' => $n, 'statut' => __('distants.statut_' . $statut),
            ]));
    }

    /** Les cles d'un compte, telles que le dernier scan les a relevees. */
    public function cles(int $machine, string $username): View
    {
        return view('composants.distants-cles', [
            'username' => $username,
            'cles' => $this->comptes->cles($machine, $username),
        ]);
    }

    /** @param  list<object>  $parc */
    private function nomDe(array $parc, int $machine): string
    {
        foreach ($parc as $m) {
            if ((int) $m->id === $machine) {
                return (string) $m->name;
            }
        }

        return '';
    }

    private function retour(int $machine, ?string $succes = null, ?string $erreur = null): RedirectResponse
    {
        $r = redirect()->route('comptes-distants', ['machine' => $machine]);

        return $succes !== null ? $r->with('succes', $succes) : $r->with('erreur', $erreur);
    }
}
