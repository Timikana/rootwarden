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
 *  2. **`password_expires_at` EST ecrite — et ce point corrige une affirmation
 *     qui vivait ici, de moi.**
 *
 *     Elle disait : *« Le legacy la calcule et l'enregistre, mais **personne ne
 *     la lit** : `verify.php` calcule l'expiration depuis `password_updated_at`.
 *     Porter cette ecriture reviendrait a porter une colonne morte. »*
 *
 *     **La moitie citee etait vraie** — `verify.php:196-197` calcule bien depuis
 *     `password_updated_at`, sans toucher la colonne. **La conclusion ne l'etait
 *     pas** : `backend/scheduler.py` la LIT deux fois (`:623` et `:820`), et la
 *     premiere **envoie un courriel** — « Votre mot de passe RootWarden expire
 *     le … ».
 *
 *     > **J'ai infere « personne » de « pas le portail que je comparais ».**
 *     > *Mesurer l'appelant qu'on a sous les yeux n'est pas mesurer la chaine, et
 *     > un consommateur qui vit dans un autre depot ne se signale pas.*
 *
 *     Consequence de l'affirmation tant qu'elle a tenu : **tout mot de passe
 *     change par le portage restait sans date d'expiration**, donc le rappel ne
 *     partait jamais pour cette personne — et rien ne le signalait, la tache
 *     trouvant simplement zero ligne a traiter.
 *
 *     La regle de calcul, a trois branches, est dans `expirationApres()`.
 */
class MotDePasse
{
    /** Une CLE i18n, jamais un message : la vue traduit, le service decide. */
    public const OK = 'profil.mdp_ok';

    /**
     * La date d'expiration a poser, ou `null` si le compte est exempte.
     *
     * ══ LA REGLE EST CELLE DU LEGACY, ET ELLE A TROIS BRANCHES ════════════
     *
     * `profile.php:190-197` et `adm/api/update_user.php:53-65` :
     *
     *     override === 0        ->  EXEMPTE, aucune expiration
     *     override > 0          ->  cette duree-la, propre au compte
     *     override absent       ->  la duree globale, ou aucune si elle vaut 0
     *
     * ⚠ ZERO ET ABSENT NE SONT PAS LA MEME CHOSE, et c'est tout le sens de la
     * colonne : `0` est une exemption DEMANDEE, `NULL` est « rien de demande,
     * suis la regle globale ». *Les confondre exempterait tout le monde le jour
     * ou la duree globale serait posee.*
     *
     * **Le calcul part de MAINTENANT** — comme `profile.php:197`
     * (`strtotime("+N days")`), et non de `password_updated_at` comme
     * `update_user.php`. Les deux coincident ici, puisque cette ecriture pose
     * `password_updated_at = now()` dans la meme requete.
     *
     * ⚠ AUJOURD'HUI LE RESULTAT EST `null` POUR TOUS : `PASSWORD_EXPIRY_DAYS`
     * n'est pas posee et aucun compte ne porte d'override (mesure : 12 comptes,
     * 0 override, 0 expiration). **Le geste est donc dormant — et c'est la
     * raison de l'ecrire**, comme le re-hachage bcrypt : le jour ou la duree
     * sera posee, les mots de passe changes par le portage en tiendront compte
     * au lieu de rester eternellement sans echeance.
     */
    /**
     * Pose — ou retire — l'exemption d'expiration d'un compte, ET recalcule sa
     * date d'echeance dans la meme transaction.
     *
     * ══ LE QUATRIEME ECRIVAIN QUE LE LEGACY DETENAIT SEUL ═════════════════
     *
     * `password_expiry_override` n'avait AUCUN ecrivain porte, et son unique
     * ecrivain vivant est `legacy/adm/api/update_user.php:49`. **Or ce fichier-ci
     * la LIT, deux lignes plus bas** (`expirationApres()`), et `ExportRgpd` la
     * publie dans l'export RGPD.
     *
     * *Je viens de corriger « personne ne la lit » sur `password_expires_at` en
     * decouvrant un lecteur dans un autre depot. Ici le lecteur etait dans mon
     * propre fichier.*
     *
     * ══ ⚠ TROIS VALEURS, ET « VIDE » N'EST PAS « ZERO » ═══════════════════
     *
     *     null  ->  aucune exemption demandee : la duree GLOBALE s'applique
     *     0     ->  EXEMPTE, aucune expiration
     *     N > 0 ->  cette duree-la, propre au compte
     *
     * Le legacy traite `'null'` et `''` comme `null` (`:47`). Ici l'entree est
     * une LISTE FERMEE cote formulaire, et le service reçoit un `?int` : le cas
     * « chaine vide » n'existe pas, il est inexprimable dans le type.
     *
     * ⚠ ET UNE VALEUR NEGATIVE EST REFUSEE. Le legacy fait `(int)$val` sans
     * borne : `-1` s'ecrirait, et `DATE_ADD(..., INTERVAL -1 DAY)` poserait une
     * echeance DANS LE PASSE — donc un compte expire a l'instant meme, par une
     * valeur qui ressemble a un reglage.
     *
     * @return bool l'ecriture a-t-elle eu lieu
     */
    public function poseOverride(int $idCompte, ?int $override): bool
    {
        if ($override !== null && $override < 0) {
            return false;
        }

        /*
         * ⚠⚠ LA LECTURE VIENT AVANT, ET `password_updated_at` EST REECRITE A SA
         * PROPRE VALEUR. Ce n'est pas du zele : la colonne porte
         * `ON UPDATE CURRENT_TIMESTAMP` (mesure sur `information_schema`), donc
         * **toute modification de la ligne la deplace a maintenant**.
         *
         * Consequence si on ne le fait pas — et mon premier jet l'a eue, le test
         * l'a mordue : *poser un override RAJEUNIT le mot de passe*, et
         * l'echeance recalculee repart de zero. **Une expiration se repousserait
         * indefiniment en basculant un reglage qui n'a rien a voir.**
         *
         * *Le legacy a le meme defaut, en pire : il fait DEUX `UPDATE` a la
         * suite (`update_user.php:49` puis `:57`), donc il deplace la date au
         * premier et recalcule depuis la date deplacee au second.*
         *
         * Poser explicitement la valeur ancienne empeche `ON UPDATE` de tirer —
         * une valeur fournie l'emporte toujours sur la clause.
         */
        $ligne = DB::table('users')->where('id', $idCompte)
            ->first(['password_updated_at']);
        if ($ligne === null) {
            return false;
        }
        $base = $ligne->password_updated_at;

        $jours = ($override !== null && $override === 0)
            ? 0
            : (($override !== null && $override > 0)
                ? $override
                : (int) config('rootwarden.mot_de_passe.expiration_jours', 0));

        $echeance = ($jours > 0 && $base !== null)
            ? \Illuminate\Support\Carbon::parse((string) $base)->addDays($jours)->format('Y-m-d')
            : null;

        /*
         * UNE SEULE ECRITURE. Le legacy en fait deux : entre les deux, la ligne
         * porte un override neuf et une echeance ancienne — *un etat que
         * personne n'a voulu, et qu'une lecture concurrente verrait.*
         */
        DB::table('users')->where('id', $idCompte)->update([
            'password_expiry_override' => $override,
            'password_expires_at' => $echeance,
            'password_updated_at' => $base,
        ]);

        return true;
    }

    private function expirationApres(int $idCompte): ?string
    {
        $override = DB::table('users')->where('id', $idCompte)->value('password_expiry_override');

        if ($override !== null && (int) $override === 0) {
            return null;
        }

        $jours = ($override !== null && (int) $override > 0)
            ? (int) $override
            : (int) config('rootwarden.mot_de_passe.expiration_jours', 0);

        return $jours > 0 ? now()->addDays($jours)->format('Y-m-d') : null;
    }

    private function cout(): int
    {
        return (int) config('rootwarden.mot_de_passe.cout', 12);
    }

    /**
     * Met le hache d'un compte au cout courant, a la connexion.
     *
     * ══ POURQUOI ICI, ET NULLE PART AILLEURS ══════════════════════════════
     *
     * Re-hacher demande le mot de passe EN CLAIR, et il n'existe qu'a un seul
     * instant du produit : celui ou quelqu'un vient de le saisir et ou il vient
     * d'etre verifie. *Aucune tache de fond ne peut faire ce geste, parce
     * qu'aucune tache de fond ne detient le clair.*
     *
     * ⚠ ET LE COUT SE LIT A LA MEME SOURCE QUE CELUI DES ECRIVAINS.
     *
     * `Hash::needsRehash()` de Laravel serait l'equivalent APPARENT. Il ne l'est
     * pas : il compare a `hashing.bcrypt.rounds`, qui lit `BCRYPT_ROUNDS`, tandis
     * que **tous** les ecrivains de mot de passe du portage lisent `BCRYPT_COST`.
     * Mesure du 2026-09-05, en forcant `BCRYPT_COST` a 13 en memoire :
     *
     *     motif du projet                       -> $2y$13$
     *     Hash::make                            -> $2y$12$
     *     Hash::needsRehash sur un cout 12      -> NON
     *     password_needs_rehash, cout projet    -> OUI
     *
     * *Ecrire ce geste avec `Hash::` aurait produit une remise a niveau qui ne se
     * declenche jamais, dans le seul cas de figure ou elle existe.* Et le `.env`
     * pose `BCRYPT_ROUNDS=12` sans poser `BCRYPT_COST` : la divergence n'est pas
     * une hypothese, c'est le chemin par defaut.
     *
     * ⚠ UN ECHEC NE CASSE PAS LA CONNEXION — MAIS IL SE JOURNALISE.
     * Le legacy avale l'exception sans rien dire (`login.php:166`,
     * `catch (\Exception $e) {}`). *Une mise a niveau qui echoue en silence ne se
     * distingue pas d'une mise a niveau qui n'a jamais ete ecrite* — et c'est
     * exactement le defaut que le commentaire du legacy raconte avoir corrige.
     *
     * @return bool le hache a-t-il ete remplace
     */
    public function rehacheSiNecessaire(int $idCompte, string $hacheActuel, string $clair): bool
    {
        if (! password_needs_rehash($hacheActuel, PASSWORD_BCRYPT, ['cost' => $this->cout()])) {
            return false;
        }

        try {
            DB::table('users')->where('id', $idCompte)->update([
                'password' => password_hash($clair, PASSWORD_BCRYPT, ['cost' => $this->cout()]),
            ]);
        } catch (\Throwable $e) {
            Log::warning('[mot de passe] remise a niveau du cout impossible pour le compte '
                . $idCompte . ' : ' . $e->getMessage());

            return false;
        }

        /*
         * `password_updated_at` N'EST PAS TOUCHEE, ET C'EST VOULU. Le mot de
         * passe n'a pas change : seule sa representation a ete renforcee.
         * Deplacer la date ferait croire a un changement qui n'a pas eu lieu, et
         * repousserait une expiration que personne n'a demande a repousser.
         *
         * `password_history` non plus : elle sert a refuser la REUTILISATION, et
         * le mot de passe reste le meme. Y ecrire le ferait refuser a son
         * proprietaire au prochain changement.
         */
        return true;
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

        return $this->applique(
            $idCompte,
            (string) $compte->password,
            $nouveau,
            $confirmation,
            $sessionCourante,
            'Mise a jour du mot de passe',
        );
    }

    /**
     * Reinitialise le mot de passe SANS l'ancien — apres validation d'un jeton
     * de courriel. Rend une CLE i18n : `self::OK` ou la cle du refus.
     *
     * POURQUOI CETTE METHODE EXISTE, ET POURQUOI ELLE NE COPIE RIEN. Le flux de
     * reinitialisation ne connait pas le mot de passe actuel — c'est sa raison
     * d'etre. Recopier ici la chaine de controles de `change()` donnerait DEUX
     * implementations d'une meme regle de securite, qui divergeraient : c'est le
     * defaut que ce depot a paye trois fois (trois copies du garde SSRF, trois
     * compteurs 2FA, deux fichiers `sudoers.d` en conflit). Les deux entrees
     * partagent donc `applique()`, et ne different QUE par la verification de
     * l'ancien mot de passe.
     *
     * ⚠ AUCUNE session n'est preservee : la personne n'est pas connectee, il n'y
     * a pas de session courante a epargner. C'est aussi le choix du legacy
     * (`reset_password.php:153` : `DELETE FROM active_sessions WHERE user_id = ?`
     * sans exception) — et il est le bon : une reinitialisation par courriel doit
     * chasser un intrus qui detiendrait une session.
     */
    public function reinitialise(
        int $idCompte,
        string $nouveau,
        string $confirmation,
    ): string {
        $compte = DB::table('users')->where('id', $idCompte)
            ->select('id', 'password')->first();
        if ($compte === null) { return 'profil.mdp_erreur_compte'; }

        return $this->applique(
            $idCompte,
            (string) $compte->password,
            $nouveau,
            $confirmation,
            null,
            'Reinitialisation du mot de passe par jeton',
        );
    }

    /**
     * La chaine de controles et l'ecriture, communes aux deux entrees.
     *
     * L'ORDRE EST CELUI DU LEGACY : correspondance, complexite, historique,
     * fuite. La verification de l'ancien mot de passe reste chez l'appelant,
     * parce qu'elle est justement ce qui les distingue.
     */
    private function applique(
        int $idCompte,
        string $ancien,
        string $nouveau,
        string $confirmation,
        ?string $sessionCourante,
        string $actionJournal,
    ): string {
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
             *
             * ⚠⚠ ~~`password_expires_at` n'est pas touchee : personne ne la lit.~~
             * **CETTE PHRASE ETAIT DE MOI, ET ELLE ETAIT FAUSSE.** Mesure du
             * 2026-09-05 : `backend/scheduler.py` la lit DEUX fois — `:623` et
             * `:820` — et la premiere **ENVOIE un courriel** (« Votre mot de
             * passe RootWarden expire le … »).
             *
             * *Consequence de mon affirmation : tout mot de passe change par le
             * portage n'avait AUCUNE date d'expiration, donc le rappel ne
             * partait jamais pour cette personne — et rien ne le signalait,
             * puisque la tache trouve simplement zero ligne.*
             *
             * **La colonne est donc ecrite, dans la meme ecriture que les deux
             * autres.** Voir `expirationApres()` pour la regle.
             */
            DB::table('users')->where('id', $idCompte)->update([
                'password' => password_hash($nouveau, PASSWORD_BCRYPT, ['cost' => $this->cout()]),
                'password_updated_at' => now(),
                'force_password_change' => 0,
                'password_expires_at' => $this->expirationApres($idCompte),
            ]);

            /*
             * ══ LES JETONS « SE SOUVENIR DE MOI » MEURENT DANS LA MEME
             *    TRANSACTION, ET C'EST DELIBERE ═════════════════════════════
             *
             * Cette purge etait en MEILLEUR EFFORT, hors transaction et sous
             * `try/catch` — j'ai deplace le bloc ce matin en extrayant
             * `applique()` sans reviser sa forme. La session 6 l'a releve avant
             * que je remplisse la table.
             *
             * **Un jeton qui survit a un changement de mot de passe DEFAIT ce
             * changement** : il restitue l'identite sous l'ANCIEN secret. Le
             * changement n'a donc pas atteint son objet, et reussir en le disant
             * serait mentir. **Echouer visiblement vaut mieux que reussir
             * faussement** : la transaction annule tout, la personne voit une
             * erreur, et son ancien mot de passe reste le bon — un etat
             * coherent, meme s'il est desagreable.
             *
             * ⚠ AUJOURD'HUI C'EST INOFFENSIF, parce que le portage ne remplit
             * JAMAIS `remember_tokens` : il vide une table qu'il n'ecrit pas.
             * **Le trou nait au moment ou je porte « Se souvenir de moi ».**
             * C'est la forme « un defaut qui protege par accident cesse de
             * proteger quand on corrige l'accident », et le corriger AVANT est
             * la seule fenetre ou il ne coute rien.
             *
             * *La forme stricte existait deja dans ce depot : `Comptes::anonymise`
             * purge les six tables DANS sa transaction, sans `try/catch`. Ce
             * n'etait donc pas un arbitrage a rendre, mais une incoherence a
             * resoudre du bon cote.*
             */
            DB::table('remember_tokens')->where('user_id', $idCompte)->delete();
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
            /*
             * CELLE-CI reste en meilleur effort, et les deux politiques
             * divergent DELIBEREMENT : son echec ne defait pas le changement de
             * mot de passe. E-203 mesure qu'elle ne ferme que les sessions de
             * l'ANCIEN portail — celles du portage vivent en FICHIERS et ne sont
             * pas dans cette table. Faire echouer un changement de mot de passe
             * parce qu'on n'a pas pu fermer des sessions d'un portail qu'on
             * demonte serait un mauvais echange.
             */
            Log::warning('purge active_sessions', ['erreur' => $e->getMessage()]);
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
                'action' => $actionJournal,
                'created_at' => now(),
            ]);
        } catch (\Throwable $e) {
            Log::warning('journalisation du changement de mot de passe', ['erreur' => $e->getMessage()]);
        }

        return self::OK;
    }
}
