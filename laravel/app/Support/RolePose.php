<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Le role effectivement pose, et LAQUELLE des deux coercitions a joue.
 *
 * ══ POURQUOI UN OBJET ET PAS UN SECOND BOOLEEN DANS LE TUPLE ═════════════
 *
 * `roleAutorise()` rendait `array{int, bool}`, et ce booleen ne rapportait que
 * la coercition d'AUTORISATION. La QA l'a mesure :
 *
 *     auteur 3 ou 2, valeur hors liste  ->  role 1, EN SILENCE
 *     auteur 1, n'importe quelle valeur ->  role 1, ANNONCE
 *
 * Les deux coercitions ne disent pas la meme chose. *« Votre autorisation a ete
 * reduite »* est une phrase de securite ; *« la valeur soumise n'est pas une
 * valeur de role »* est une phrase de validite. **Un drapeau qui signifie deux
 * choses n'est fiable pour aucune** — et le lecteur d'un tuple ne peut pas se
 * tromper sur un nom de propriete comme il se trompe sur une position.
 *
 * ⚠ LES DEUX PEUVENT JOUER ENSEMBLE, et alors les deux sont vraies : une valeur
 * invalide devient le role plancher, que l'autorisation peut a son tour refuser.
 * *Rendre « laquelle des deux » au SINGULIER aurait forcé à en taire une.*
 */
final readonly class RolePose
{
    public function __construct(
        /** Le role effectivement ecrit en base. Toujours dans `Comptes::ROLES`. */
        public int $role,
        /** La valeur soumise n'etait pas une valeur de role — phrase de VALIDITE. */
        public bool $valeurInvalide,
        /** L'autorisation de l'auteur a borne le rang — phrase de SECURITE. */
        public bool $rangRamene,
    ) {}
}
