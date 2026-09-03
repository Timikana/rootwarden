<?php

namespace Tests\Doubles;

use App\Services\Droits;

/**
 * Double de `App\Services\Droits` qui rend un jeu de permissions fixe et
 * ENREGISTRE qui l'a interroge.
 *
 * La trace n'est pas un confort : elle permet d'affirmer qu'un 403 vient bien
 * du garde de permission. Un test qui n'assertait que le statut passerait a
 * l'identique si le garde `perm:` disparaissait et qu'un autre refus prenait sa
 * place — c'est la forme d'echec la plus couteuse, un vert qui ne mesure rien.
 *
 * Il ETEND la vraie classe plutot que d'implementer une interface : le
 * middleware la recoit par injection de type, donc un double qui ne serait pas
 * un `Droits` ne serait meme pas accepte. Le contrat est ainsi verifie par le
 * langage.
 */
class DroitsFictifs extends Droits
{
    /** Identifiants de compte pour lesquels `permissions()` a ete appelee. */
    public array $consultations = [];

    /** @param  array<string,bool>  $accordees */
    public function __construct(private array $accordees = [])
    {
    }

    public function permissions(int $idCompte): array
    {
        $this->consultations[] = $idCompte;

        return $this->accordees;
    }

    public function aEteConsulte(): bool
    {
        return $this->consultations !== [];
    }
}
