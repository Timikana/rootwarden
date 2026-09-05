<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Le cycle de vie du jeton de reinitialisation.
 *
 * Le CHANGEMENT du mot de passe n'est pas ici : il vit dans `MotDePasse`, et
 * c'est deliberé. *Deux chemins ecrivent un mot de passe — le profil et cette
 * reinitialisation — et si un seul revoquait les acces, le defaut reviendrait
 * par l'autre porte.* `MotDePasse::reinitialise()` porte deja l'historique, la
 * politique, la purge des jetons « se souvenir de moi » DANS la transaction
 * (E-393) et celle des sessions actives.
 *
 * ══ CE SERVICE NE POSE AUCUNE SESSION ═════════════════════════════════════
 *
 * Reinitialiser un mot de passe ne contourne pas le second facteur : le compte
 * se reconnecte ensuite par l'ecran de connexion, qui l'exige. *Un compte qui a
 * perdu son mot de passe ET son second facteur n'a toujours aucun chemin — c'est
 * un geste d'administration, et c'est correct.*
 */
final class ReinitialisationMotDePasse
{
    /** Une heure, comme le legacy (`forgot_password.php`, `expires_at = now + 3600`). */
    public const DUREE_SECONDES = 3600;

    /** Trois demandes par adresse IP et par heure. */
    public const DEMANDES_MAX = 3;
    public const FENETRE_SECONDES = 3600;

    /**
     * Les cinq derniers jetons vivants du compte sont eprouves. Le legacy en
     * prend cinq aussi : au-dela, le cout de `password_verify` par tentative
     * deviendrait lui-meme un levier.
     */
    public const JETONS_EPROUVES = 5;

    /**
     * ══ LA LIMITE DE DEBIT COMPTE LES DEMANDES RECUES, PAS LES JETONS EMIS ══
     *
     * ⚠ C'EST LE DEFAUT LE PLUS COUTEUX DU LEGACY, ET IL EST SILENCIEUX.
     *
     * `forgot_password.php` compte les lignes de `password_reset_tokens` pour
     * une adresse IP. **Or une demande portant une adresse INCONNUE n'insere
     * aucune ligne** : elle n'est donc jamais comptee.
     *
     * > *Un compteur qui ne compte que les demandes reussies ne limite pas
     * > l'enumeration — il la finance.* Sonder dix mille adresses ne consomme
     * > aucun credit tant qu'aucune n'existe, et la premiere qui existe est
     * > justement celle qu'on cherchait.
     *
     * Le compteur vit donc dans le CACHE, hors de toute table liee au compte,
     * et il est incremente **avant** de savoir si l'adresse existe.
     *
     * ⛔ ET PAS DANS `login_attempts` : le garde de `login.php:50` IGNORE la
     * colonne `step`. Toute ecriture, quelle que soit son etape, compte dans le
     * verrou de CONNEXION par adresse IP — une reinitialisation demandee
     * fermerait la connexion de tout un NAT.
     */
    public function autorise(string $ip): bool
    {
        $cle = 'reinit:demandes:' . sha1($ip);

        try {
            $n = (int) Cache::get($cle, 0);
            if ($n >= self::DEMANDES_MAX) {
                return false;
            }
            // `put` et non `increment` : le pilote `file` ne garantit pas
            // l'atomicite de l'increment, et un compteur qui perd des unites
            // sous-compte — donc autorise plus que la limite.
            Cache::put($cle, $n + 1, self::FENETRE_SECONDES);

            return true;
        } catch (\Throwable $e) {
            /*
             * ⚠ ECHEC FERME, ET C'EST UNE CORRECTION DU LEGACY.
             *
             * Il rend `true` — « autorise » — sur toute `PDOException`, avec pour
             * justification « si la table n'existe pas encore ». *Le repli couvre
             * un cas et s'applique a tous : connexion perdue, verrou expire,
             * droits insuffisants.* Un repli du cote permissif sur un controle de
             * securite ne se voit pas : rien ne signale une limite desarmee.
             *
             * Ici c'est l'inverse. Une demande refusee se reessaie ; une limite
             * qui n'existe plus ne se remarque qu'apres.
             */
            Log::error('[reinitialisation] compteur illisible, demande refusee : ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Emet un jeton pour ce compte et rend sa valeur EN CLAIR — la seule fois
     * ou elle existe. La base n'en garde que le hache.
     *
     * @return string 64 caracteres hexadecimaux
     */
    public function emet(int $idCompte, string $ip): string
    {
        $clair = bin2hex(random_bytes(32));

        DB::transaction(function () use ($idCompte, $ip, $clair): void {
            /*
             * LES JETONS PRECEDENTS MEURENT D'ABORD. Sans cela, une personne
             * demandant trois liens en aurait trois valides — et le plus ancien,
             * peut-etre lu par quelqu'un d'autre, resterait utilisable une heure.
             */
            DB::table('password_reset_tokens')
                ->where('user_id', $idCompte)
                ->whereNull('used_at')
                ->update(['used_at' => now()]);

            DB::table('password_reset_tokens')->insert([
                'user_id' => $idCompte,
                // BCRYPT, jamais le clair : la table est lisible par qui lit la
                // base, et un jeton en clair y serait un mot de passe a usage
                // unique en libre-service.
                'token_hash' => password_hash($clair, PASSWORD_BCRYPT, ['cost' => $this->cout()]),
                'expires_at' => now()->addSeconds(self::DUREE_SECONDES),
                'ip_address' => mb_substr($ip, 0, 45),
                'created_at' => now(),
            ]);
        });

        return $clair;
    }

    /**
     * Brule un cout de hachage EQUIVALENT, sans rien ecrire.
     *
     * ⚠ CE N'EST PAS LA FERMETURE DE L'ORACLE DE TEMPS, C'EST UN DE SES TERMES.
     * Voir `ReinitialisationController` : le terme dominant — l'envoi — est
     * sorti de la requete, et c'est LUI qui refermait l'ecart. Celui-ci egalise
     * le bcrypt, qui reste le cout le plus lourd de ce qui subsiste en ligne.
     */
    public function brule(): void
    {
        password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT, ['cost' => $this->cout()]);
    }

    /**
     * Le jeton correspond-il a un jeton VIVANT de ce compte ?
     *
     * Rend l'identifiant de la ligne, ou `null`. L'appelant s'en sert pour la
     * marquer consommee — et il la REVALIDE juste avant d'ecrire, parce que
     * entre l'affichage du formulaire et sa soumission, le jeton a pu expirer ou
     * etre consomme ailleurs.
     */
    public function valide(int $idCompte, string $clair): ?int
    {
        // La forme AVANT le contenu : 64 hexadecimaux, rien d'autre. Un jeton
        // malforme ne merite pas cinq `password_verify`.
        if (preg_match('/^[a-f0-9]{64}$/', $clair) !== 1) {
            return null;
        }

        $lignes = DB::table('password_reset_tokens')
            ->where('user_id', $idCompte)
            ->whereNull('used_at')
            ->where('expires_at', '>', now())
            ->orderByDesc('id')
            ->limit(self::JETONS_EPROUVES)
            ->get(['id', 'token_hash']);

        foreach ($lignes as $l) {
            if (password_verify($clair, (string) $l->token_hash)) {
                return (int) $l->id;
            }
        }

        return null;
    }

    /**
     * Consomme le jeton — ET TOUS LES AUTRES DU COMPTE.
     *
     * *Un lien utilise doit fermer les liens que la meme demande a pu semer :
     * un courriel transfere, une copie dans une corbeille.*
     */
    public function consomme(int $idCompte): void
    {
        DB::table('password_reset_tokens')
            ->where('user_id', $idCompte)
            ->whereNull('used_at')
            ->update(['used_at' => now()]);
    }

    /** Le compte porteur de cette adresse, ou `null`. Actifs seulement. */
    public function compteParCourriel(string $courriel): ?object
    {
        return DB::table('users')
            ->where('email', $courriel)
            ->where('active', 1)
            ->first(['id', 'name', 'email']);
    }

    private function cout(): int
    {
        return (int) config('rootwarden.bcrypt_cost', 12);
    }
}
