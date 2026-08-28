<?php

/**
 * Ce que la passerelle autorise — francais.
 *
 * Parite stricte avec lang/en/autorisations.php : meme jeu de cles, meme commit.
 */
return [

    'title' => 'Ce que la passerelle autorise',
    'desc'  => "Cette page est DÉRIVÉE du code de la passerelle, à chaque affichage. Elle ne recopie aucun fichier de description : elle lit les listes qui décident, ici et maintenant.",

    // ── CE QUE LA PAGE N'EST PAS ─────────────────────────────────────────
    'pas_reference_titre' => "Ce n'est pas une référence d'API",
    'pas_reference_texte' => "Cette page ne décrit ni les paramètres, ni les corps de requête, ni les réponses. Elle décrit des AUTORISATIONS : ce que la passerelle laisse passer, ce qu'elle réserve à l'administration, ce qu'elle relaie morceau par morceau. Pour les contrats d'appel, il n'existe pas de source à jour dans ce portail — et l'annoncer vaut mieux que de renvoyer vers une qui mentirait.",

    // ── LES TROIS COUCHES ────────────────────────────────────────────────
    'couches_titre' => "Une autorisation traverse trois couches, et cette page n'en décrit qu'une",
    'couche_1' => "La garde de la PAGE : le rôle et la permission exigés par la route du portail. Visible dans les routes du portail.",
    'couche_2' => "La PASSERELLE : liste blanche, réserve à l'administration, re-authentification, relais en flux. C'est cette couche, et elle est dérivée ci-dessous.",
    'couche_3' => "Les DÉCORATEURS du backend : clé d'API, rôle, permission, accès à la machine. Cette page ne les voit pas — le portail ne monte pas le code du backend — et elle ne les affirme donc pas.",
    'couches_aide' => "Ces trois couches ont déjà divergé, et un écran qui les mélangerait refabriquerait le défaut qu'il documente. Chaque énoncé de cette page nomme donc la sienne.",

    // ── POURQUOI CETTE PAGE REMPLACE UN FICHIER ──────────────────────────
    'remplace_titre' => "Ce que cette page remplace, et pourquoi elle ne le porte pas",
    'remplace_texte' => "L'ancien portail servait une description OpenAPI statique de 91 Ko, datée du 20 août 2026, que rien ne régénérait. Mesuré le 28 août : 146 chemins déclarés contre 203 routes réelles — 139 justes, 7 inexistants, 64 routes passées sous silence.",
    'remplace_detail' => "Les 7 inexistants ont une seule cause : le module d'audit SSH y est déclaré sous DEUX séparateurs. Dix routes avec le tiret, servies ; sept avec le souligné, en 404. La même route y figure deux fois sous deux orthographes, dont une fausse — et rien dans le document ne dit laquelle.",
    'remplace_raison' => "Porter ce fichier n'aurait pas été de la fidélité mais la recopie d'un cache : un portage fidèle reproduit un comportement contradictoire et le nomme, alors qu'un artefact figé n'est pas un comportement. Vingt-six routes ont changé de garde le 27 août seul — aucun document figé ne peut suivre ce rythme.",
    'remplace_silence' => "Les 64 routes que l'ancienne description passait sous silence ne sont pas documentées ici non plus : cette page décrit la passerelle, pas le catalogue des routes. La différence est qu'elle le DIT. Un document qui omet ce qu'il ne sait pas est plus trompeur qu'un document daté, parce qu'un lecteur ne peut pas savoir qu'il manque quelque chose.",

    // ── LA LISTE BLANCHE ─────────────────────────────────────────────────
    'blanche_titre' => 'Liste blanche : ce que la passerelle transmet',
    'blanche_aide' => "Un chemin absent de cette liste est refusé avant d'atteindre le backend. La comparaison se fait par SEGMENT : la forme du dernier caractère décide de la portée.",
    'th_motif' => 'Entrée',
    'th_portee' => 'Portée',
    'portee_espace' => 'espace de noms',
    'portee_route' => 'route',
    'portee_espace_aide' => "Finit par « / », « _ » ou « - » : tout chemin qui commence par cette chaîne est transmis.",
    'portee_route_aide' => "Le chemin exact, ou un sous-chemin séparé par « / ».",

    // ── LA RESERVE A L'ADMINISTRATION ────────────────────────────────────
    'admin_titre' => "Réservé à l'administration",
    'admin_aide' => "Ces chemins exigent un rôle 2 au minimum, à la passerelle. C'est une défense en profondeur : le backend applique ses propres gardes, et cette page ne les décrit pas.",
    'admin_couverte' => 'resserre une entrée de la liste blanche',
    'admin_orpheline' => "⚠ ne correspond à aucune entrée de la liste blanche : ne resserre rien",
    'admin_aucune_orpheline' => "Aucune de ces entrées n'est sans objet : chacune resserre bien un chemin que la liste blanche laisse passer. Ce nombre est calculé, pas supposé.",

    // ── LE RELAIS EN FLUX ────────────────────────────────────────────────
    'flux_titre' => 'Relayé morceau par morceau',
    'flux_aide' => "Ces chemins tiennent leur réponse ouverte pendant que la commande tourne. Le statut HTTP part AVANT que le travail ne commence : il ne dit donc rien du résultat, et un écran qui le prendrait pour un verdict annoncerait une réussite qui n'a pas eu lieu.",
    'flux_hors_liste' => "⚠ ce chemin n'est autorisé par aucune entrée de la liste blanche",
    'flux_par_espace' => "Quatre de ces chemins ne sont pas eux-mêmes des entrées de la liste blanche : ils passent par un espace de noms. C'est pourquoi cette liste est énumérée depuis sa propre source et non déduite de la liste blanche.",

    // ── LA RE-AUTHENTIFICATION ───────────────────────────────────────────
    'reauth_titre' => 'Exige une re-authentification ponctuelle',
    'reauth_aide' => "Ce sont des EXPRESSIONS, pas des chemins : chacune s'applique à un ensemble fini de chemins concrets et à aucun autre. Les rendre comme une liste de chemins inventerait une précision que la source n'a pas.",
    'reauth_aucune' => "Aucun motif de re-authentification n'est configuré.",

    // ── LES COMPTEURS ────────────────────────────────────────────────────
    'compte_blanche' => 'entrées en liste blanche',
    'compte_espaces' => "dont espaces de noms",
    'compte_admin' => "réservées à l'administration",
    'compte_flux' => 'relayées en flux',
    'compte_reauth' => 'motifs de re-authentification',
];
