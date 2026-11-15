<?php

// lang/fr/search.php - Recherche globale.

return [
    'title' => 'Recherche globale',
    'desc'  => "Serveurs, utilisateurs, CVE, tickets et journal d'audit, en un seul champ.",

    'placeholder' => "Serveur, utilisateur, CVE, ticket…",
    'tip_input'   => "Deux caractères au minimum.",
    'label'       => "Terme recherché",
    /* Le panneau de recherche de l'en-tete. Le reste de ses libelles est REPRIS
     * de cette meme liste (`placeholder`, `label`, `hint_min`, `searching`,
     * `no_results`, `err`, `cat_*`) : deux formulations pour un meme etat
     * finiraient par se contredire. */
    'menu_ouvrir' => 'Rechercher',
    'menu_voir_tout' => 'Ouvrir la recherche complète',

    'guide_titre'  => 'Ce que la recherche couvre',
    'guide_portee' => "Dix résultats au plus par catégorie : la recherche oriente vers la page qui gère l'objet.",
    'guide_droits' => "Réservée à l'administration du portail, car elle traverse les comptes et le journal d'audit.",
    'guide_liens'  => "Chaque résultat mène à la page qui le gère.",

    'cat_machines' => 'Serveurs',
    'cat_users'    => 'Utilisateurs',
    'cat_cves'     => 'CVE',
    'cat_tickets'  => 'Tickets',
    'cat_audit'    => 'Journal d\'audit',

    'hint_min'     => "Tapez au moins deux caractères.",
    'searching'    => "Recherche…",
    'results_for'  => "résultat(s) pour",
    'no_results'   => "Aucun résultat",
    'no_results_aide' => "Essayez un nom de serveur, une adresse IP, un identifiant de CVE ou un mot d'un ticket.",
    'err'          => "La recherche a échoué.",
    'ancien_portail' => "ancien portail, dans un nouvel onglet",
];
