<?php

namespace App\Http\Controllers;

use App\Services\Fail2ban;
use Illuminate\Http\JsonResponse;
use Illuminate\View\View;

/**
 * Fail2ban — sous-lot F1.
 *
 * **Ce controleur n'ouvre aucune session SSH.** Le statut affiche vient du CACHE
 * (`fail2ban_status`), et le rafraichir demande un geste explicite : ouvrir la
 * page ne doit pas joindre toutes les machines du parc.
 *
 * ══ F6 : LES DEUX GESTES DE PARC ET LEUR PORTEE ══════════════════════════
 *
 * `portee()` rend en JSON ce que les deux routes de parc du backend
 * toucheraient. Elle existe pour une raison precise : un releve ECRIT le cache
 * (`_update_status_cache`), donc la portee CHANGE apres un releve. Sans
 * relecture, l'ecran porterait deux verites sur le meme objet — le defaut que
 * F1 a corrige sur la ligne du tableau de cache, ici a l'echelle du parc.
 *
 * Elle porte les MEMES gardes que la page. Une capacite ne se garde pas moins
 * parce qu'elle sert une zone d'information : ce qu'elle rend est la liste des
 * machines du parc avec leur environnement.
 *
 * Garde : `role:1` + `perm:can_manage_fail2ban`, reprise telle quelle du legacy
 * — dont l'en-tete annonce pourtant « admin (2), superadmin (3) ». Voir
 * `App\Services\Fail2ban` : le role 1 est un choix assume du projet, l'en-tete
 * est une erreur.
 */
class Fail2banController extends Controller
{
    public function __construct(private Fail2ban $fail2ban)
    {
    }

    public function __invoke(): View
    {
        /*
         * E-205 : LE PARC EST BORNE PAR LE ROLE, comme dans le legacy. Les deux
         * valeurs viennent de la SESSION, ou elles ont ete posees apres
         * verification en base au second facteur.
         */
        $machines = $this->fail2ban->machines(
            (int) request()->session()->get('utilisateur_id', 0),
            (int) request()->session()->get('role_id', 0)
        );
        $statuts = $this->fail2ban->dernierStatut();

        // ── F2 : ce qu'il faut pour que l'ecran ne mente pas ────────────
        //
        // `GET /fail2ban/history` rend 50 lignes au plus SANS annoncer de total,
        // et `performed_by` est un identifiant NUMERIQUE. Les deux valeurs qui
        // manquent au navigateur pour dire vrai — le total par machine et les
        // noms de comptes — se lisent ici, en deux requetes, et voyagent avec
        // la page.
        $totaux = $this->fail2ban->totauxHistorique();
        $noms = $this->fail2ban->nomsUtilisateurs();

        $lignes = [];
        foreach ($machines as $m) {
            $lignes[] = [
                'machine'  => $m,
                'sensible' => $this->fail2ban->estSensible($m),
                'cache'    => $statuts[(int) $m->id] ?? null,
                'histo'    => $totaux[(int) $m->id] ?? 0,
            ];
        }

        // `@json` avec un litteral inline casse le PHP compile par Blade : les
        // libelles se calculent ici (defaut paye en `bashrc/` B1 — page en 500).
        $textes = [];
        foreach ([
            'choisir', 'chargement', 'echec', 'etat_absent', 'etat_absent_aide',
            'etat_arrete', 'etat_arrete_aide', 'etat_actif', 'jails_aucune',
            'jails_une', 'jails_plusieurs', 'adresses_une', 'adresses_plusieurs',
            'compte_bannies_une', 'compte_bannies_plusieurs',
            'cache_maintenant', 'sensible_avert',
            // F2
            'histo_vide_titre', 'histo_vide', 'histo_echec_titre',
            'histo_echec', 'histo_tout', 'histo_tronque',
            'action_ban', 'action_unban', 'par_inconnu', 'par_repli', 'par_repli_aide',
            'frise_vide_titre', 'frise_vide', 'frise_jour',
            // F3
            'lu_a_l_instant', 'fichier_absent_titre', 'fichier_absent',
            'journal_absent_titre', 'journal_absent',
            'lecture_echec_titre', 'lecture_echec',
            'services_installe', 'services_absent',
            'services_jail_active', 'services_vide_titre', 'services_vide',
            // F4
            'jail_detail_titre', 'jail_maxretry', 'jail_bantime', 'jail_findtime',
            'jail_secondes', 'jail_inconnu', 'bannies_vide_titre', 'bannies_vide',
            'debannir', 'conf_titre_ban', 'conf_texte_ban',
            'conf_titre_debannir', 'conf_texte_debannir',
            'conf_titre_tout', 'conf_texte_tout',
            'geste_reussi', 'geste_echoue', 'ban_invalide',
            // F5
            'blanche_lue', 'blanche_supposee_titre', 'blanche_supposee',
            'blanche_vide_titre', 'blanche_vide', 'blanche_retirer',
            'blanche_non_retirable', 'blanche_non_retirable_aide',
            'conf_titre_blanche_ajout', 'conf_texte_blanche_ajout',
            'conf_titre_blanche_retrait', 'conf_texte_blanche_retrait',
            'jail_reglages_titre', 'conf_titre_jail', 'conf_texte_jail',
            // F6
            'portee_titre', 'portee_cache', 'portee_installer',
            'portee_installer_aucune', 'portee_bannir', 'portee_bannir_aucune',
            'portee_jamais', 'portee_jamais_aide', 'portee_archivee',
            'portee_archivee_aide', 'portee_releve_le', 'portee_relue',
            'portee_echec', 'sensible',
            'portee_inconnue_titre', 'portee_inconnue', 'parc_ban_inconnue',
            'conf_titre_parc_inconnue', 'conf_texte_parc_inconnue',
            'parc_ban_aide', 'parc_ban_aide_aucune',
            'conf_titre_parc_ban', 'conf_texte_parc_ban',
            'conf_titre_parc_ban_vide', 'conf_texte_parc_ban_vide',
            'conf_titre_parc_install', 'conf_texte_parc_install',
            'conf_titre_parc_install_vide', 'conf_texte_parc_install_vide',
            'parc_envoi', 'parc_resultat_machine',
            'parc_ok', 'parc_echec', 'parc_echec_muet', 'parc_rien',
            'parc_apres_install',
            /*
             * ══ F7 — ET POURQUOI CES DEUX LIGNES MANQUAIENT ══════════════
             *
             * `conf_titre_desact` et `conf_texte_desact` existaient dans LES
             * DEUX catalogues et n'etaient pas dans CETTE liste. Le panneau de
             * confirmation s'ouvrait donc avec un titre VIDE et un texte VIDE :
             * on demandait de confirmer un geste qui arrete la protection
             * contre le force brute et ouvre une session SSH, sans qu'un mot
             * dise lequel ni sur quelle machine.
             *
             * ⚠ AUCUN DE NOS CONTROLES NE VOIT CE DEFAUT :
             *   la parite i18n passe      — les cles existent, FR et EN
             *   les ancres DOM existent   — `f2b-confirmation-titre`, `-texte`
             *   le panneau s'ouvre        — il est visible
             *   une cle ABSENTE rendrait son IDENTIFIANT, donc se verrait
             *   une cle NON TRANSMISE rend du VIDE, et le vide ne se signale pas
             *
             * Et aucune sonde statique ne peut le trouver ici, parce que la cle
             * est COMPOSEE A L'EXECUTION (`fail2ban.js:376  textes[cleTitre]`) :
             * `conf_titre_desact` n'apparait litteralement dans aucun `.js`.
             *
             * QUI AJOUTE UN PANNEAU AJOUTE SES DEUX CLES ICI, dans le meme
             * commit que le geste.
             */
            'conf_titre_desact', 'conf_texte_desact',
        ] as $cle) {
            $textes[$cle] = __('fail2ban.' . $cle);
        }

        return view('fail2ban', [
            'lignes'    => $lignes,
            'noms'      => $noms,
            'sensibles' => $this->fail2ban->compteSensibles($machines),
            'total'     => count($machines),
            'textes'    => $textes,
            // ── F6 ──────────────────────────────────────────────────────
            'portee'    => $this->fail2ban->portee(),
            /*
             * LES DEUX GESTES DE PARC EXIGENT LE ROLE 2, ET EUX SEULS.
             *
             * `ban_all_servers` et `install_all` sont les deux seules routes du
             * module a porter `@require_role(2)` (`fail2ban.py:508` et `:675`).
             * Les quatorze autres portent `@require_machine_access`, dont
             * `check_machine_access` rend `True` des le role 2 — c'est au role 1
             * qu'il mord, en le bornant a `user_machine_access`. Les gestes de
             * parc, eux, n'ont AUCUNE notion de machine a borner : le backend
             * les ferme donc au role.
             *
             * Un role 1 lit cette page (la garde de la page l'admet) et ces deux
             * gestes ne peuvent que lui rendre 403. Il recoit donc la RAISON, pas
             * un bouton — la meme regle qu'E-169 pour une entree de liste blanche
             * qu'aucun retrait ne peut aboutir.
             *
             * **Branche non exercee sur le banc, et c'est dit** : aucun compte de
             * role 1 ne porte `can_manage_fail2ban`, donc aucun n'atteint la page.
             */
            'peutParc'  => ((int) request()->session()->get('role_id', 0)) >= 2,
        ]);
    }

    /**
     * La portee des deux gestes de parc, relue en base.
     *
     * Appelee au chargement par la page elle-meme et apres chaque releve : le
     * releve ecrit le cache, donc la portee bouge. C'est une LECTURE — trois
     * `SELECT`, aucune machine jointe.
     */
    public function portee(): JsonResponse
    {
        return response()->json([
            'success' => true,
            'portee'  => $this->fail2ban->portee(),
        ]);
    }
}
