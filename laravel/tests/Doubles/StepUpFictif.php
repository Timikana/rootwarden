<?php

namespace Tests\Doubles;

use App\Services\StepUp;

/**
 * Double de `App\Services\StepUp` pour les tests de la PASSERELLE.
 *
 * Il ne remplace pas un test de `StepUp` lui-même — celui-là devra mesurer
 * l'anti-rejeu par compte, le quota remis à zéro sur succès et la liste fermée
 * d'actions. Ici on mesure ce que la passerelle FAIT du verdict : à quelle
 * action elle le demande, et si elle transmet quand la réponse est non.
 *
 * Poser une vraie marque demanderait un code TOTP valide, donc un secret — et
 * **on n'invente jamais un secret TOTP** : il ne fait pas échouer la mesure là
 * où elle porte, il la fait échouer à la connexion, ce qui se diagnostique de
 * travers.
 *
 * `actionPour()` n'est PAS remplacée : c'est elle qui dérive le nom de l'action
 * depuis le chemin, et c'est une propriété qu'on veut mesurer pour de vrai.
 */
class StepUpFictif extends StepUp
{
    /** @var list<string> les actions pour lesquelles la passerelle a interrogé */
    public array $demandes = [];

    /** @param list<string> $accordees */
    public function __construct(private array $accordees = [])
    {
    }

    public function valide(int $idCompte, string $action): bool
    {
        $this->demandes[] = $action;

        return in_array($action, $this->accordees, true);
    }
}
