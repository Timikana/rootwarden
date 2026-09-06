<?php

declare(strict_types=1);

namespace App\Support;

use Illuminate\Support\Facades\DB;

/**
 * L'implantation en base de `DepotJetonsMemorisation`.
 *
 * ⚠ SUR LA PROVENANCE DE LA TABLE, ET C'EST UNE RESERVE. `remember_tokens` est
 * definie dans `mysql/init.sql:49-55` — **pas dans `mysql/migrations/`**.
 * `001_initial_schema.sql` ne la cite qu'en COMMENTAIRE d'en-tete et ne porte
 * AUCUN `CREATE TABLE` (mesure : zero sur tout le fichier).
 *
 * *`init.sql` n'est joue qu'a la PREMIERE initialisation du conteneur MySQL. La
 * table est donc presente sur une base initialisee ainsi — ce qui est mesure —
 * mais cette garantie est CONTINGENTE la ou une migration serait DURABLE.*
 *
 * **Ce depot echoue donc franchement si la table manque, plutot que de rendre
 * `null` :** un `null` se lirait « ce compte n'a pas de jeton », c'est-a-dire un
 * REFUS — et un refus silencieux pour cause de schema absent serait indiscernable
 * d'un refus pour cause de jeton faux. *Le depot ne rattrape rien ; l'appelant
 * verra l'exception.*
 */
class DepotJetonsMemorisationBase implements DepotJetonsMemorisation
{
    public function pour(int $idCompte): ?object
    {
        return DB::table('remember_tokens')->where('user_id', $idCompte)
            ->select('token_hash', 'expires_at')->first();
    }

    public function remplace(int $idCompte, string $hache, string $expireLe): void
    {
        // `upsert` sur la cle primaire `user_id` : c'est le `REPLACE INTO` du
        // legacy, et c'est ce qui evince le jeton d'un autre appareil.
        DB::table('remember_tokens')->upsert(
            [['user_id' => $idCompte, 'token_hash' => $hache, 'expires_at' => $expireLe]],
            ['user_id'],
            ['token_hash', 'expires_at'],
        );
    }

    public function retire(int $idCompte): void
    {
        DB::table('remember_tokens')->where('user_id', $idCompte)->delete();
    }

    public function compte(int $idCompte): ?object
    {
        return DB::table('users')->where('id', $idCompte)
            ->select('active', 'totp_secret', 'name', 'role_id')->first();
    }
}
