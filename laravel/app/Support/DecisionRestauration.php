<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Ce qu'un cookie « se souvenir de moi » peut obtenir — et RIEN D'AUTRE.
 *
 * ══ POURQUOI IL N'Y A PAS DE CAS `Portail` ═══════════════════════════════
 *
 * La session 6 proposait quatre valeurs : `PORTAIL | DEFI | ENROLEMENT | REFUS`,
 * pour pouvoir asserter que `PORTAIL` n'est jamais rendu.
 *
 * **Il n'y en a que trois, et c'est plus fort** : l'acces direct au portail
 * n'est pas « jamais rendu », il est **INEXPRIMABLE**. Aucun test n'a a le
 * verifier, parce qu'aucun code ne peut le produire — le type l'interdit.
 *
 * *C'est la difference entre une propriete verifiee et une propriete garantie.
 * Une assertion se supprime ; un type ne se contourne pas sans qu'on le voie.*
 *
 * ⚠ LE DEFAUT QUE CELA FERME. Le legacy conditionne sa re-authentification a
 * `if ($totpSecret)` sans `else` (`auth/verify.php:139`) : pour un compte SANS
 * secret TOTP, aucun drapeau n'est pose, le garde suivant ne tire pas, et le
 * cookie authentifie SEUL — sans second facteur et sans la redirection vers
 * l'enrolement que `login.php` impose partout ailleurs.
 *
 * **La restauration ne rend donc jamais une authentification : elle rend un
 * CHEMIN VERS une authentification, ou un refus.**
 */
enum DecisionRestauration
{
    /** Le compte porte un second facteur : il doit le presenter. */
    case Defi;

    /** Le compte n'en porte pas : il doit l'enroler. JAMAIS le portail. */
    case Enrolement;

    /** Rien de valide : cookie absent, malforme, jeton faux, expire, compte inactif. */
    case Refus;
}
