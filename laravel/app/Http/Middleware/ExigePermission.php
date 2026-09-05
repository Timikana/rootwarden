<?php

namespace App\Http\Middleware;

use App\Services\Droits;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Exige une permission, ou le role superadministrateur.
 *
 * `perm:can_admin_portal` se lit « cette permission OU superadmin », comme
 * partout ailleurs dans le projet — c'est la regle du legacy et celle de
 * App\Support\Navigation. Une regle d'acces qui differe selon l'endroit ou on
 * la lit finit par diverger.
 *
 * Les permissions sont relues EN BASE a chaque requete (memorisees pour sa
 * duree) : une permission revoquee cesse d'ouvrir la page a la requete
 * suivante, sans attendre une reconnexion.
 */
class ExigePermission
{
    public function __construct(private readonly Droits $droits)
    {
    }

    public function handle(Request $requete, Closure $suite, string $permission): Response
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        $roleId   = (int) $requete->session()->get('role_id', 0);

        if ($roleId >= 3) {
            return $suite($requete);
        }

        if (! ($this->droits->permissions($idCompte)[$permission] ?? false)) {
            $this->journaliseLeRefus($idCompte, $permission);
            // 403 et non une redirection : la page existe, l'acces est refuse.
            // Rediriger ferait croire a une page disparue.
            abort(403, __('acces.permission_manquante'));
        }

        return $suite($requete);
    }

    /**
     * Enregistre le refus dans `user_logs`, comme le legacy.
     *
     * **Regression rattrapee** : le portage refusait correctement — 403, mesure
     * par `go-services-s1` — mais **sans laisser de trace**. Le legacy ecrit
     * « Permission refusee : <permission> » (`auth/verify.php:307-312`). Un 403
     * dit que la page a refuse ; le journal dit que le refus a ete ENREGISTRE.
     * Ce ne sont pas les memes proprietes, et seule la seconde survit a la
     * session.
     *
     * La ligne part SANS empreinte de chaine, exactement comme celle du legacy :
     * `user_logs` porte une chaine `prev_hash`/`self_hash` que seul le scellage
     * alimente, et 998 lignes y sont deja non scellees. La cohesion mesuree par
     * `go-adm-audit` porte sur la SOUS-CHAINE SCELLEE — une ligne non scellee ne
     * la rompt pas.
     *
     * **L'echec d'ecriture ne bloque JAMAIS le refus.** Le refus est la
     * propriete de securite ; sa trace est une propriete d'audit. Faire
     * dependre la premiere de la seconde transformerait une base indisponible en
     * porte ouverte. Le legacy fait le meme choix.
     */
    private function journaliseLeRefus(int $idCompte, string $permission): void
    {
        /*
         * ⚠ CETTE ECRITURE ETAIT NUE, ET C'ETAIT UN CHOIX — REVERSE SUR
         * ARBITRAGE DE L'EXPLOITANT LE 2026-09-05.
         *
         * Elle inserait en SQL brut, sans `prev_hash` : chaque refus de
         * permission posait une ligne HORS chaine. Mesure du 05/09 : c'etait la
         * source la plus FREQUENTE — 17 lignes/heure sous la charge du banc, et
         * une ligne non chainee ne se rattrape jamais.
         *
         * ══ L'ARGUMENT DU DOCBLOC RESTE VRAI, ET LE `catch` LE PORTE ═════════
         *
         * « Le refus est une propriete de securite ; sa trace est une propriete
         * d'audit. Faire dependre la premiere de la seconde transformerait une
         * base indisponible en porte ouverte. »
         *
         * Ce raisonnement n'est pas annule : il est SATISFAIT PAR LE `catch`.
         * Le refus a deja eu lieu quand on arrive ici — cette methode ne decide
         * rien, elle trace. Si la chaine est indisponible, on journalise
         * l'echec et le refus TIENT.
         */
        /*
         * ⚠ ET UNE GARDE QUI MANQUAIT AUX DEUX VERSIONS. `user_logs.user_id` est
         * `NOT NULL` **et** porte une cle etrangere vers `users`
         * (`user_logs_ibfk_1`). L'ancien code passait `$idCompte ?: null` : sur
         * un refus ANONYME il tentait un `null` sur une colonne non nulle,
         * l'insertion levait, et le `catch` l'avalait. La ligne etait perdue et
         * personne ne le voyait.
         *
         * On ne tente plus une ecriture dont on SAIT qu'elle echouera : sans
         * compte identifie, il n'y a pas d'auteur a inscrire, et le dire au
         * journal applicatif vaut mieux qu'une exception silencieuse.
         */
        if (! $idCompte) {
            Log::warning('refus de permission SANS compte identifie — non journalise en base', [
                'permission' => $permission,
            ]);

            return;
        }

        try {
            app(\App\Services\JournalAudit::class)
                ->ajoute((int) $idCompte, 'Permission refusee : ' . $permission);
        } catch (\Throwable $e) {
            Log::warning('refus de permission non journalise', [
                'permission' => $permission,
                'erreur'     => $e->getMessage(),
            ]);
        }
    }
}
