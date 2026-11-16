<?php

declare(strict_types=1);

namespace App\Support;

/**
 * UNE machine sensible, UNE regle, pour toutes les pages qui l'avertissent.
 *
 * `PROD` OU `CRITIQUE`, et un environnement INCONNU (`OTHER` ou vide) compte
 * comme sensible : il ne veut pas dire « pas de production », il veut dire
 * « on ne sait pas », et un avertissement se range du cote sur.
 *
 * ══ POURQUOI UNE SEULE FONCTION ══════════════════════════════════════════
 *
 * La regle etait recopiee dans cinq services (bashrc, services systemd,
 * fail2ban, iptables, cle de plateforme). Mesure du 2026-11-16 : la copie de
 * `ClePlateforme` avait PERDU la criticite — son commentaire disait « `PROD` ou
 * `CRITIQUE` », son code ne lisait que l'environnement, et sa requete ne
 * selectionnait meme pas la colonne. Une machine DEV marquee CRITIQUE n'etait
 * donc pas signalee sur la page qui peut couper l'acces a tout le parc.
 * **Cinq copies d'une regle finissent par en faire deux.**
 *
 * Les deux colonnes sont des `enum` (`PROD|DEV|TEST|OTHER`,
 * `CRITIQUE|NON CRITIQUE`) ; la normalisation en majuscules est une precaution.
 */
final class MachineSensible
{
    public static function est(object $machine): bool
    {
        $env = strtoupper(trim((string) ($machine->environment ?? '')));
        $crit = strtoupper(trim((string) ($machine->criticality ?? '')));

        return $env === 'PROD' || $env === 'OTHER' || $env === ''
            || $crit === 'CRITIQUE';
    }
}
