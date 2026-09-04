<?php

declare(strict_types=1);

namespace App\Support;

/**
 * L'acces aux jetons « se souvenir de moi ».
 *
 * ══ POURQUOI UNE INTERFACE ══════════════════════════════════════════════
 *
 * `JetonMemorisation::decide()` porte une propriete d'AUTHENTIFICATION. La
 * session 6 doit pouvoir la verrouiller **sans base et sans navigateur** : le
 * banc n'est pas libre, et un verrou qui depend d'un banc arrive apres le code
 * qu'il devait garder.
 *
 * *Avec ce depot doublable, « un cookie forge ne restaure rien » se mesure en
 * memoire, et `Refus` se distingue de tout le reste sans qu'aucune URL soit
 * observee — donc sans le piege que la session 5 a nomme : si tous les refus
 * redirigent vers la meme page, une assertion sur l'URL ne distingue pas
 * « refuse » de « la route n'existe pas ».*
 */
interface DepotJetonsMemorisation
{
    /**
     * Le jeton d'un compte, ou `null`.
     *
     * @return object{token_hash: string, expires_at: string}|null
     */
    public function pour(int $idCompte): ?object;

    /**
     * Pose le jeton d'un compte, en REMPLACANT le precedent.
     *
     * ⚠ `remember_tokens` porte `PRIMARY KEY (user_id)` (`mysql/init.sql:49-55`) :
     * **un seul jeton par compte**. Se souvenir sur un second appareil evince
     * donc le premier — c'est une limite du schema, pas un choix du portage, et
     * elle se DECLARE a l'ecran plutot que de se decouvrir.
     */
    public function remplace(int $idCompte, string $hache, string $expireLe): void;

    public function retire(int $idCompte): void;

    /**
     * L'etat du compte, ou `null` s'il n'existe pas.
     *
     * ⚠ POURQUOI L'ETAT DU COMPTE VIT DERRIERE LA MEME COUTURE. La decision a
     * besoin d'exactement DEUX faits : le jeton, et si le compte est actif et
     * porte un second facteur. Les mettre derriere DEUX dependances doublerait
     * le doublage — et un verrou dont le montage est penible finit par ne pas
     * etre ecrit. **Une seule couture, donc, et elle porte ce dont la decision a
     * besoin : pas les jetons, la DECISION.**
     *
     * ⚠ ELLE REND AUSSI `name` ET `role_id`, dont la DECISION n'a pas besoin.
     * `SecondFacteurController` consomme `compte_temporaire` sous la forme
     * `['id', 'nom', 'role']` (`ConnexionController:74`, lue a `:120` et `:162`),
     * et l'aiguillage doit poser la MEME forme. *Un second aller-retour en base
     * pour deux colonnes deja lues serait du zele ; une seconde dependance a
     * doubler serait un verrou plus penible a monter, donc moins probable.*
     *
     * @return object{active: int, totp_secret: string|null, name: string, role_id: int}|null
     */
    public function compte(int $idCompte): ?object;
}
