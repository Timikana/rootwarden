<?php

namespace App\Support;

use Psr\Http\Message\StreamInterface;

/**
 * Relaie un flux du backend au navigateur, AU FIL DE L'EAU.
 *
 * ══ POURQUOI PAS `$corps->read(8192)` (2026-10-27) ══════════════════════════
 *
 * Le backend parle HTTPS. Sur une socket TLS ouverte par l'enveloppe `http` de
 * PHP (ce qu'utilise Guzzle avec `stream => true`), `fread($r, 8192)` BLOQUE
 * jusqu'a avoir 8 192 octets ou la fin du flux. Mesure sur la pile isolee :
 *
 *     « Debut de l'execution... » disponible a       292 ms
 *     rendu par read(8192) a                       7 465 ms, avec TOUT le reste
 *
 * Un journal de moins de 8 Ko n'arrivait donc JAMAIS en direct, et un plus long
 * arrivait par paquets de 8 Ko : c'est le « les logs ne remontent pas en live »
 * de l'exploitation, sur tous les ecrans en flux. Ni HTTP en clair ni le codage
 * `chunked` seuls ne le reproduisent : c'est TLS (voir `RelaisFluxTest`).
 *
 * La ressource est donc lue en NON BLOQUANT : `fread` rend ce qui est arrive,
 * et une courte pause separe deux lectures vides. `stream_select` n'est pas une
 * option : il refuse les flux de l'enveloppe `http`.
 *
 * Le delai de Guzzle ne s'applique plus a une lecture non bloquante : le delai
 * d'INACTIVITE est donc tenu ici, avec la meme valeur (`delai_flux`).
 */
final class RelaisFlux
{
    /**
     * @param  callable(string): void  $ecrit       recoit chaque morceau des son arrivee
     * @param  int  $inactiviteMaxS                  silence au-dela duquel on abandonne
     * @param  (callable(): bool)|null  $abandonne   vrai si le navigateur est parti
     */
    public static function relaie(StreamInterface $corps, callable $ecrit, int $inactiviteMaxS,
                                  ?callable $abandonne = null, int $pauseUs = 20000): void
    {
        $meta = $corps->getMetadata();
        $ressource = is_array($meta) && isset($meta['stream_type']) ? $corps->detach() : null;

        if (! is_resource($ressource)) {
            // Pas de ressource sous-jacente (flux en memoire, doublure de test) :
            // la lecture ordinaire convient, elle ne passe pas par TLS.
            while (! $corps->eof()) {
                $morceau = $corps->read(8192);
                if ($morceau !== '') {
                    $ecrit($morceau);
                }
            }

            return;
        }

        stream_set_blocking($ressource, false);
        $dernierMorceau = microtime(true);
        try {
            while (! feof($ressource)) {
                if ($abandonne !== null && $abandonne()) {
                    return;
                }
                $morceau = fread($ressource, 65536);
                if ($morceau === false) {
                    return;
                }
                if ($morceau === '') {
                    if (microtime(true) - $dernierMorceau > $inactiviteMaxS) {
                        return;
                    }
                    usleep($pauseUs);
                    continue;
                }
                $dernierMorceau = microtime(true);
                $ecrit($morceau);
            }
        } finally {
            fclose($ressource);
        }
    }
}
