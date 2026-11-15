<?php

/**
 * Ce que la passerelle autorise — francais.
 *
 * Parite stricte avec lang/en/autorisations.php : meme jeu de cles, meme commit.
 * Regles de redaction : docs/REDACTION-INTERFACE.md.
 */
return [

    'title' => 'Ce que la passerelle autorise',
    'desc'  => "Les règles que la passerelle du portail applique aux appels vers le backend, lues dans son code à chaque affichage.",

    // ── CE QUE LA PAGE COUVRE (replie) ───────────────────────────────────
    'couches_titre' => "Ce que cette page couvre",
    'couche_1' => "La garde de chaque page du portail (rôle et permission) : non décrite ici.",
    'couche_2' => "La passerelle : liste blanche, réserve à l'administration, relais en flux, re-authentification. C'est ce que décrit cette page.",
    'couche_3' => "Les contrôles propres au backend : non visibles depuis le portail, donc non décrits.",
    'pas_reference_texte' => "Ce n'est pas une référence d'API : ni paramètres, ni réponses, ni liste complète des routes.",

    // ── LA LISTE BLANCHE ─────────────────────────────────────────────────
    'blanche_titre' => 'Liste blanche : ce que la passerelle transmet',
    'blanche_aide' => "Tout chemin absent de cette liste est refusé.",
    'th_motif' => 'Entrée',
    'th_portee' => 'Portée',
    'portee_espace' => 'espace de noms',
    'portee_route' => 'route',
    'portee_espace_aide' => "Finit par « / », « _ » ou « - » : tout chemin qui commence par cette chaîne est transmis.",
    'portee_route_aide' => "Le chemin exact, ou un sous-chemin séparé par « / ».",

    // ── LA RESERVE A L'ADMINISTRATION ────────────────────────────────────
    'admin_titre' => "Réservé à l'administration",
    'admin_aide' => "Ces chemins exigent au moins le rôle Administrateur.",
    'admin_couverte' => 'restreint une entrée de la liste blanche',
    'admin_orpheline' => "⚠ ne correspond à aucune entrée de la liste blanche : sans effet",
    'admin_aucune_orpheline' => "Chaque entrée restreint bien un chemin de la liste blanche.",

    // ── LE RELAIS EN FLUX ────────────────────────────────────────────────
    'flux_titre' => 'Relayé morceau par morceau',
    'flux_aide' => "La réponse arrive au fil de l'exécution : son statut HTTP ne dit rien du résultat.",
    'flux_hors_liste' => "⚠ ce chemin n'est autorisé par aucune entrée de la liste blanche",

    // ── LA RE-AUTHENTIFICATION ───────────────────────────────────────────
    'reauth_titre' => 'Exige une re-authentification ponctuelle',
    'reauth_aide' => "Les chemins qui correspondent à ces expressions demandent un nouveau code TOTP juste avant l'action.",
    'reauth_aucune' => "Aucun motif de re-authentification n'est configuré.",

    // ── LES COMPTEURS ────────────────────────────────────────────────────
    'compte_blanche' => 'entrées en liste blanche',
    'compte_espaces' => "dont espaces de noms",
    'compte_admin' => "réservées à l'administration",
    'compte_flux' => 'relayées en flux',
    'compte_reauth' => 'motifs de re-authentification',
];
