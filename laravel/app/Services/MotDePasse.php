<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * La politique de mot de passe, et le changement — sous-lot A2.
 *
 * POURQUOI CE SERVICE EXISTE. Le changement de mot de passe est l'un des DEUX
 * blocages de la v2.0. Mesure du 2026-08-23 : **six comptes actifs sur dix**
 * portent `force_password_change = 1`, dont **`superadmin`**. Le portage
 * DETECTAIT le drapeau et l'annoncait par un bandeau, mais n'offrait aucun
 * formulaire : apres une bascule directe, ces comptes n'auraient jamais pu
 * satisfaire l'exigence.
 *
 * LA POLITIQUE EST CELLE DU LEGACY, A L'IDENTIQUE. Les deux portails partagent
 * la base : une regle plus laxiste d'un cote serait un contournement de l'autre.
 * Quinze caracteres, quatre classes, les cinq derniers haches refuses, HIBP en
 * option. Voir `legacy/auth/password_policy.php`.
 *
 * DEUX ECARTS ASSUMES, tous deux mesures (voir `docs/migration/PARITE.md`) :
 *
 *  1. **`password_updated_at` est ecrit EXPLICITEMENT.** Le legacy ne l'ecrit pas
 *     (`profile.php:205`) et compte sur `ON UPDATE CURRENT_TIMESTAMP`. Or cette
 *     clause se declenche a **toute** modification reelle de la ligne `users` :
 *     un echec de connexion suivi d'un succes remet `failed_attempts` a 0, la
 *     ligne change, et le compteur de jours d'expiration repart de zero. La
 *     politique d'expiration serait donc vaincue par une simple faute de frappe.
 *     Elle est desactivee aujourd'hui (`PASSWORD_EXPIRY_DAYS` non definie), donc
 *     le defaut est LATENT — mais on ne s'appuie pas sur un effet de bord.
 *
 *  2. **`password_expires_at` n'est PAS ecrite.** Le legacy la calcule et
 *     l'enregistre, mais **personne ne la lit** : `verify.php:159` calcule
 *     l'expiration depuis `password_updated_at`. Mesure : **0 ligne** renseignee
 *     dans toute la table. Porter cette ecriture reviendrait a porter une colonne
 *     morte.
 */
class MotDePasse
{
    /** Une CLE i18n, jamais un message : la vue traduit, le service decide. */
    public const OK = 'profil.mdp_ok';

    private function cout(): int
    {
        return (int) config('rootwarden.mot_de_passe.cout', 12);
    }

    /**
     * La complexite locale. Rend `null` si le mot de passe passe, sinon la cle du
     * message. Le legacy rend UNE seule cle pour les cinq regles : on garde ce
     * choix, parce que detailler quelle regle a echoue renseigne autant l'attaquant
     * que la personne.
     */
    public function verifieComplexite(string $clair): ?string
    {
        $minimum = (int) config('rootwarden.mot_de_passe.longueur_minimale', 15);

        if (mb_strlen($clair) < $minimum) { return 'profil.mdp_erreur_politique'; }
        if (! preg_match('/[a-z]/', $clair)) { return 'profil.mdp_erreur_politique'; }
        if (! preg_match('/[A-Z]/', $clair)) { return 'profil.mdp_erreur_politique'; }
        if (! preg_match('/[0-9]/', $clair)) { return 'profil.mdp_erreur_politique'; }
        if (! preg_match('/[^a-zA-Z0-9]/', $clair)) { return 'profil.mdp_erreur_politique'; }

        return null;
    }

    /**
     * Le mot de passe fait-il partie des derniers utilises ?
     *
     * La comparaison passe par `password_verify` sur chaque hache — donc en temps
     * constant — et non par une egalite de chaines : les haches bcrypt portent
     * chacun leur sel, ils ne se comparent pas entre eux.
     */
    public function dejaUtilise(int $idCompte, string $clair): bool
    {
        $taille = (int) config('rootwarden.mot_de_passe.taille_historique', 5);
        $anciens = DB::table('password_history')
            ->where('user_id', $idCompte)
            ->orderByDesc('changed_at')
            ->limit($taille)
            ->pluck('password_hash');

        foreach ($anciens as $hache) {
            if ($hache !== null && $hache !== '' && password_verify($clair, $hache)) {
                return true;
            }
        }

        // Le hache COURANT compte aussi : reprendre son propre mot de passe n'est
        // pas un changement.
        $courant = DB::table('users')->where('id', $idCompte)->value('password');

        return $courant !== null && password_verify($clair, $courant);
    }

    /**
     * Le mot de passe apparait-il dans une fuite publique ?
     *
     * K-ANONYMITY : seuls les CINQ PREMIERS caracteres de l'empreinte SHA-1
     * quittent le serveur ; le service distant renvoie tous les suffixes de ce
     * prefixe, et la comparaison se fait ici. Le mot de passe ne sort jamais.
     *
     * OPT-IN ET FAIL-OPEN, comme le legacy : desactive par defaut, et une panne du
     * service distant ne doit pas empecher quelqu'un de changer son mot de passe.
     * Mesure du 2026-08-23 : `HIBP_ENABLED` n'est definie dans aucun conteneur, ce
     * chemin est donc INERTE et aucune requete ne sort.
     */
    public function compromis(string $clair): bool
    {
        if (! config('rootwarden.mot_de_passe.hibp', false)) {
            return false;
        }

        try {
            $empreinte = strtoupper(sha1($clair));
            $prefixe = substr($empreinte, 0, 5);
            $suffixe = substr($empreinte, 5);
            $reponse = Http::timeout(5)->get("https://api.pwnedpasswords.com/range/{$prefixe}");
            if (! $reponse->successful()) { return false; }

            foreach (explode("\n", $reponse->body()) as $ligne) {
                if (str_starts_with(strtoupper(trim($ligne)), $suffixe . ':')) {
                    return true;
                }
            }
        } catch (\Throwable $e) {
            // FAIL-OPEN ASSUME : on journalise et on laisse passer. Bloquer un
            // changement de mot de passe parce qu'un service tiers est en panne
            // serait pire que le risque qu'on cherche a couvrir.
            Log::warning('verification HIBP indisponible', ['erreur' => $e->getMessage()]);
        }

        return false;
    }

    /**
     * Change le mot de passe. Rend une CLE i18n : `self::OK` ou la cle du refus.
     *
     * L'ORDRE DES CONTROLES EST CELUI DU LEGACY : l'ancien mot de passe d'abord
     * (sans quoi on renseignerait un attaquant sur la politique), puis la
     * correspondance, puis la politique.
     */
    public function change(
        int $idCompte,
        string $actuel,
        string $nouveau,
        string $confirmation,
        ?string $sessionCourante = null,
    ): string {
        $compte = DB::table('users')->where('id', $idCompte)
            ->select('id', 'password')->first();
        if ($compte === null) { return 'profil.mdp_erreur_compte'; }

        if (! password_verify($actuel, (string) $compte->password)) {
            return 'profil.mdp_erreur_actuel';
        }
        if ($nouveau !== $confirmation) {
            return 'profil.mdp_erreur_correspondance';
        }
        if (($cle = $this->verifieComplexite($nouveau)) !== null) {
            return $cle;
        }
        if ($this->dejaUtilise($idCompte, $nouveau)) {
            return 'profil.mdp_erreur_historique';
        }
        if ($this->compromis($nouveau)) {
            return 'profil.mdp_erreur_fuite';
        }

        $ancien = (string) $compte->password;

        DB::transaction(function () use ($idCompte, $ancien, $nouveau) {
            // L'ANCIEN HACHE D'ABORD : c'est lui qui rend le refus de reutilisation
            // possible au prochain changement.
            DB::table('password_history')->insert([
                'user_id' => $idCompte,
                'password_hash' => $ancien,
                'changed_at' => now(),
            ]);

            /*
             * `password_updated_at` EXPLICITEMENT, et `force_password_change` dans
             * la MEME ecriture — le legacy fait deux `UPDATE` successifs.
             * `password_expires_at` n'est pas touchee : personne ne la lit.
             */
            DB::table('users')->where('id', $idCompte)->update([
                'password' => password_hash($nouveau, PASSWORD_BCRYPT, ['cost' => $this->cout()]),
                'password_updated_at' => now(),
                'force_password_change' => 0,
            ]);
        });

        /*
         * ══ CE QUE CETTE PURGE FERME VRAIMENT — E-203 ════════════════════
         *
         * Le commentaire disait « LES AUTRES SESSIONS TOMBENT ». Il affirmait
         * plus que le code, et sur un ecran de securite.
         *
         * Mesure du 2026-08-27 :
         *   — le LEGACY verifie `active_sessions` a CHAQUE requete
         *     (`auth/verify.php:58-66`) et force un re-login si la ligne a
         *     disparu. Supprimer la ligne ferme donc reellement ses sessions ;
         *   — le PORTAGE ne consulte JAMAIS cette table — zero occurrence dans
         *     ses intergiciels et ses controleurs d'authentification. Ses
         *     sessions vivent en FICHIERS (`SESSION_DRIVER=file`), et supprimer
         *     une ligne de base n'en ferme aucune.
         *
         * Donc : cette purge ferme les sessions de l'ancien portail, et **aucune
         * de celui-ci**. L'aide de l'ecran le dit desormais dans ces termes,
         * plutot que de promettre une fermeture qu'elle n'obtient pas.
         *
         * Le correctif complet est que le portage ECRIVE cette table a la
         * connexion, comme le legacy le fait (`login.php:212`), et la consulte.
         * Aucune migration n'est necessaire : la table existe et porte deja les
         * colonnes voulues.
         *
         * Best-effort, comme le legacy : un echec de purge ne doit pas annuler un
         * changement de mot de passe deja ecrit.
         */
        try {
            $requete = DB::table('active_sessions')->where('user_id', $idCompte);
            if ($sessionCourante !== null && $sessionCourante !== '') {
                $requete->where('session_id', '!=', $sessionCourante);
            }
            $requete->delete();
        } catch (\Throwable $e) {
            Log::warning('purge active_sessions', ['erreur' => $e->getMessage()]);
        }
        try {
            DB::table('remember_tokens')->where('user_id', $idCompte)->delete();
        } catch (\Throwable $e) {
            Log::warning('purge remember_tokens', ['erreur' => $e->getMessage()]);
        }

        /*
         * LE JOURNAL S'ECRIT NU, comme partout ailleurs. `user_logs` porte
         * `prev_hash` et `self_hash`, mais la chaine n'est PAS calculee a
         * l'insertion : elle l'est par un scellement separe
         * (`legacy/adm/api/audit_seal.php`). Mesure du 2026-08-23 : 3368 lignes,
         * dont 757 sans empreinte. Calculer la chaine ici, seul, la casserait.
         */
        try {
            DB::table('user_logs')->insert([
                'user_id' => $idCompte,
                'action' => 'Mise a jour du mot de passe',
                'created_at' => now(),
            ]);
        } catch (\Throwable $e) {
            Log::warning('journalisation du changement de mot de passe', ['erreur' => $e->getMessage()]);
        }

        return self::OK;
    }
}
