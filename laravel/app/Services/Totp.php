<?php

namespace App\Services;

use App\Support\TotpCrypto;
use Illuminate\Support\Facades\Cache;
use OTPHP\TOTP as OtpHp;

/**
 * Verification des codes TOTP, avec garde anti-rejeu PAR COMPTE.
 *
 * Pourquoi par compte, et non par session : le legacy portait sa garde dans
 * $_SESSION. Une garde de session ne peut rien contre un rejeu venu d'une
 * session NEUVE — or c'est exactement le scenario d'attaque, et il a ete
 * REPRODUIT le 2026-08-17 sur un compte administrateur (le meme code a ouvert
 * deux sessions dans la meme fenetre de 30 s). Voir docs/migration/PARITE.md
 * E-01.
 *
 * La derniere fenetre consommee est retenue dans le cache applicatif (pilote
 * fichier). Ce choix evite une migration du schema, qui appartient au backend
 * Python. Contrepartie assumee : la garde est propre au frontend Laravel et ne
 * survit pas a une purge du cache. Elle couvre le scenario reel — un rejeu se
 * joue en moins de 30 secondes.
 */
class Totp
{
    /**
     * Verifie un code pour un compte donne.
     *
     * @param  int     $idCompte      identifiant du compte, pour la garde anti-rejeu
     * @param  ?string $secretStocke  valeur brute de users.totp_secret (chiffree)
     * @param  string  $code          code a 6 chiffres saisi
     * @return string  'ok' | 'invalide' | 'rejeu' | 'sans_secret'
     */
    public function verifie(int $idCompte, ?string $secretStocke, string $code): string
    {
        $secret = TotpCrypto::dechiffre($secretStocke);
        if ($secret === '') {
            return 'sans_secret';
        }

        $code = trim($code);
        if (! preg_match('/^\d{6}$/', $code)) {
            return 'invalide';
        }

        $otp        = OtpHp::createFromSecret($secret);
        $tolerance  = (int) config('rootwarden.totp.tolerance', 1);
        $maintenant = time();

        // Determiner A QUELLE fenetre appartient le code presente. On ne peut
        // pas se contenter d'un verify() global : la garde anti-rejeu a besoin
        // du numero de fenetre, pas d'un simple booleen.
        $fenetre = null;
        for ($decalage = -$tolerance; $decalage <= $tolerance; $decalage++) {
            $instant = $maintenant + ($decalage * 30);
            if (hash_equals($otp->at($instant), $code)) {
                $fenetre = intdiv($instant, 30);
                break;
            }
        }

        if ($fenetre === null) {
            return 'invalide';
        }

        // Garde anti-rejeu : toute fenetre deja consommee, ou anterieure a la
        // derniere consommee, est refusee.
        $cle       = 'totp:derniere_fenetre:' . $idCompte;
        $derniere  = Cache::get($cle);
        if ($derniere !== null && $fenetre <= (int) $derniere) {
            return 'rejeu';
        }

        Cache::put($cle, $fenetre, (int) config('rootwarden.totp.retention_rejeu', 120));

        return 'ok';
    }
}
