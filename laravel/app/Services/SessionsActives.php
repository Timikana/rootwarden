<?php

namespace App\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * La liste de revocation des sessions — E-203.
 *
 * ══ CE QUE CETTE TABLE DECIDE, ET NON COMMENT LE LEGACY L'ECRIT ═══════════
 *
 * `legacy/auth/verify.php:58-115` a ete lu pour sa DECISION, pas pour sa
 * forme. Elle tient en quatre points :
 *
 *   1. une session pleinement authentifiee est vivante SI la paire
 *      (`session_id`, `user_id`) est presente dans `active_sessions` ;
 *   2. absente => la session est detruite et l'on repart a la connexion.
 *      **Revoquer, c'est SUPPRIMER la ligne** — la table ne porte aucune
 *      colonne `revoked` (verifie au schema) ;
 *   3. presente => `last_activity` est touchee, mais **au plus une fois par
 *      minute** : sans ce frein, chaque requete ecrirait en base ;
 *   4. base injoignable => **on laisse passer**, et on journalise.
 *
 * ══ LE POINT 4 EST UN ARBITRAGE, PAS UN OUBLI ═════════════════════════════
 *
 * Fail-OPEN. Un incident de base deconnecterait sinon tout le monde, et la
 * revocation est une commodite de securite, pas une garde d'acces : les
 * gardes de role et de permission, elles, restent en place. Le legacy prend
 * le meme parti et l'ecrit ; on le reprend en le disant plutot qu'en le
 * laissant deviner.
 *
 * ══ POURQUOI LE PORTAGE EN AVAIT BESOIN ═══════════════════════════════════
 *
 * Ses sessions vivent en FICHIERS (`SESSION_DRIVER=file`). Supprimer une ligne
 * de cette table n'en fermait donc AUCUNE : l'ecran offrait une revocation qui
 * ne revoquait rien. **Tant que les deux portails coexistent, le legacy fait
 * le travail et le manque ne se voit pas** — le jour ou il s'eteint, la
 * capacite disparait en silence.
 */
class SessionsActives
{
    /** Une seule ecriture de `last_activity` par minute et par session. */
    private const FREIN_SECONDES = 60;

    /*
     * ══ LA LISTE EST BORNEE, ET LA BORNE EST DITE ════════════════════════
     *
     * ⚠ E-315 — LES HORODATAGES DE CETTE TABLE SONT EN UTC.
     *
     * Le conteneur et MySQL tournent en UTC, l'hote en CEST : **deux heures
     * d'ecart**. Une session comparant l'heure d'une suite (hote) au
     * `created_at` d'une ligne a conclu que la table n'etait plus alimentee
     * depuis deux heures. Elle l'etait. Le silence etait PLAUSIBLE, et c'est
     * ce qui le rend dangereux : une valeur hors de toute plage physique est
     * un defaut d'instrument, une valeur plausible et fausse ne se signale
     * pas d'elle-meme.
     *
     * Mesure du 2026-09-02 : `active_sessions` porte **4 477 lignes**, dont
     * **3 373 de plus de sept jours** — `rw-test-super` en compte 2 583, la
     * plus vieille du 15 aout. Le legacy pose une ligne par connexion et
     * **n'en retire jamais** : ni a la deconnexion, ni a l'expiration.
     *
     * Deux consequences, et la seconde est la plus importante :
     *
     *   - un ecran qui les rendrait toutes serait inutilisable (mesure : le
     *     profil rendait 2 584 lignes) ;
     *   - **une ligne de trois semaines n'est PAS une session ouverte.** Le
     *     fichier de session a expire depuis longtemps. Les presenter comme
     *     des « sessions ouvertes » serait FAUX, pas seulement illisible.
     *
     * On borne donc, on annonce le total, et l'ecran dit que la table n'est
     * pas purgee. Montrer vingt lignes sur 2 584 sans le dire serait le
     * compteur qui ment qu'on corrige partout ailleurs.
     */
    private const LIMITE_AFFICHEE = 20;

    /**
     * Pose ou remet a jour la ligne de la session COURANTE.
     *
     * A appeler apres `regenerate()`, jamais avant : l'identifiant change, et
     * c'est le nouveau qui doit etre enregistre.
     */
    public function enregistre(Request $requete, int $idCompte): void
    {
        try {
            DB::table('active_sessions')->updateOrInsert(
                ['session_id' => $requete->session()->getId()],
                [
                    'user_id'       => $idCompte,
                    'ip_address'    => (string) ($requete->ip() ?? ''),
                    // La colonne accepte 500 caracteres ; un en-tete plus long
                    // ferait echouer l'insertion et, avec elle, la connexion.
                    'user_agent'    => mb_substr((string) $requete->userAgent(), 0, 500),
                    'last_activity' => now(),
                ],
            );
        } catch (\Throwable $e) {
            // Une connexion ne doit pas echouer parce que la liste de
            // revocation n'a pas pu s'ecrire. Mais le dire : sans ligne, la
            // session sera vue comme revoquee au prochain passage du garde.
            Log::error('[SessionsActives::enregistre] ' . $e->getMessage());
        }
    }

    /**
     * Suit une REGENERATION d'identifiant : retire l'ancienne ligne et pose la
     * nouvelle.
     *
     * ⚠ Sans cela, `PortailController` regenere la session apres un changement
     * de mot de passe, la ligne devient perimee, et le garde ci-dessous
     * deconnecte la personne **juste apres** son changement. Un dispositif de
     * securite qui met dehors celui qui vient de se securiser.
     */
    public function suitLaRegeneration(Request $requete, string $ancienIdentifiant, int $idCompte): void
    {
        try {
            if ($ancienIdentifiant !== '' && $ancienIdentifiant !== $requete->session()->getId()) {
                DB::table('active_sessions')->where('session_id', $ancienIdentifiant)->delete();
            }
        } catch (\Throwable $e) {
            Log::error('[SessionsActives::suitLaRegeneration] ' . $e->getMessage());
        }

        $this->enregistre($requete, $idCompte);
    }

    /**
     * La session est-elle toujours dans la liste ?
     *
     * Rend `null` quand la table n'a pas pu etre lue — et l'appelant DOIT
     * distinguer ce cas de `false`. Rendre `true` par defaut cacherait
     * l'incident ; rendre `false` deconnecterait tout le monde.
     */
    public function estVivante(string $identifiant, int $idCompte): ?bool
    {
        try {
            return DB::table('active_sessions')
                ->where('session_id', $identifiant)
                ->where('user_id', $idCompte)
                ->exists();
        } catch (\Throwable $e) {
            Log::error('[SessionsActives::estVivante] ' . $e->getMessage());

            return null;
        }
    }

    /** Touche `last_activity`, au plus une fois par minute. */
    public function touche(string $identifiant, int $idCompte): void
    {
        try {
            DB::table('active_sessions')
                ->where('session_id', $identifiant)
                ->where('user_id', $idCompte)
                ->where('last_activity', '<', now()->subSeconds(self::FREIN_SECONDES))
                ->update(['last_activity' => now()]);
        } catch (\Throwable $e) {
            Log::error('[SessionsActives::touche] ' . $e->getMessage());
        }
    }

    /**
     * Les sessions d'un compte, la plus recente d'abord.
     *
     * `lisible` a faux distingue « la table n'a pas repondu » de « aucune
     * session » — un ecran de securite qui rend une liste vide sur une erreur
     * affirme un fait qu'il n'a pas mesure.
     */
    public function pour(int $idCompte): array
    {
        try {
            $total = DB::table('active_sessions')->where('user_id', $idCompte)->count();

            $lignes = DB::table('active_sessions')
                ->where('user_id', $idCompte)
                ->orderByDesc('last_activity')
                ->limit(self::LIMITE_AFFICHEE)
                ->get(['session_id', 'ip_address', 'user_agent', 'last_activity', 'created_at'])
                ->all();

            return ['lisible' => true, 'sessions' => $lignes, 'total' => $total];
        } catch (\Throwable $e) {
            Log::error('[SessionsActives::pour] ' . $e->getMessage());

            return ['lisible' => false, 'sessions' => [], 'total' => 0];
        }
    }

    /**
     * Revoque UNE session du compte.
     *
     * Le `user_id` est dans la clause : sans lui, un identifiant de session
     * devine ou vole permettrait de fermer la session d'un autre compte.
     * Rend le nombre de lignes reellement supprimees — `0` veut dire que la
     * session n'existait pas OU n'appartenait pas a ce compte, et l'ecran ne
     * doit pas annoncer une fermeture qui n'a pas eu lieu.
     */
    public function revoque(string $identifiant, int $idCompte): int
    {
        try {
            return DB::table('active_sessions')
                ->where('session_id', $identifiant)
                ->where('user_id', $idCompte)
                ->delete();
        } catch (\Throwable $e) {
            Log::error('[SessionsActives::revoque] ' . $e->getMessage());

            return 0;
        }
    }

    /*
     * ══ L'IDENTIFIANT DE SESSION NE SORT PAS DU SERVEUR ══════════════════
     *
     * La page de profil du LEGACY publie l'identifiant COMPLET de chaque
     * session ouverte. Un identifiant de session EST un identifiant d'acces :
     * l'afficher, c'est le mettre dans une capture d'ecran, un ticket, un
     * copier-coller.
     *
     * L'ecran ne montre donc qu'une EMPREINTE, et la revocation vise cette
     * empreinte. Le mettre dans un champ cache pour pouvoir revoquer aurait
     * annule la precaution : le HTML l'aurait publie tout autant.
     *
     * Douze caracteres hexadecimaux : assez pour distinguer les sessions d'un
     * compte a l'oeil, trop peu pour reconstituer quoi que ce soit.
     */
    public function empreinte(string $identifiant): string
    {
        return substr(hash('sha256', $identifiant), 0, 12);
    }

    /**
     * Revoque par EMPREINTE, en bornant au compte.
     *
     * On resout parmi les sessions DE CE COMPTE, jamais sur toute la table :
     * une empreinte est courte, et une collision entre deux comptes ne doit
     * pas pouvoir fermer la session d'un tiers. Rend le nombre de lignes
     * reellement supprimees.
     */
    public function revoqueParEmpreinte(string $empreinte, int $idCompte): int
    {
        /*
         * ⚠ On resout sur TOUTES les sessions du compte, pas sur la liste
         * AFFICHEE : `pour()` est bornee a vingt lignes, et s'en servir ici
         * rendrait les autres impossibles a fermer — un bouton qui marche
         * pour les vingt premieres et echoue en silence pour les suivantes.
         */
        try {
            $toutes = DB::table('active_sessions')
                ->where('user_id', $idCompte)
                ->get(['session_id'])
                ->all();
        } catch (\Throwable $e) {
            Log::error('[SessionsActives::revoqueParEmpreinte] ' . $e->getMessage());

            return 0;
        }

        foreach ($toutes as $ligne) {
            if (hash_equals($this->empreinte((string) $ligne->session_id), $empreinte)) {
                return $this->revoque((string) $ligne->session_id, $idCompte);
            }
        }

        return 0;
    }

    /** Retire la ligne a la deconnexion. */
    public function ferme(string $identifiant): void
    {
        try {
            DB::table('active_sessions')->where('session_id', $identifiant)->delete();
        } catch (\Throwable $e) {
            Log::error('[SessionsActives::ferme] ' . $e->getMessage());
        }
    }
}
