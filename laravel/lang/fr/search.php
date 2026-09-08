<?php

// lang/fr/search.php - Recherche globale.

return [
    'title' => 'Recherche globale',
    'desc'  => 'Cherchez en un seul endroit parmi les serveurs, les utilisateurs, les CVE, les '
             . 'tickets et le journal d\'audit.',

    'placeholder' => 'Un serveur, un utilisateur, une CVE, un ticket...',
    'tip_input'   => 'Recherche transverse, deux caracteres au minimum.',
    'label'       => 'Terme recherche',
    /* Le panneau de recherche de l'en-tete. Le reste de ses libelles est REPRIS
     * de cette meme liste (`placeholder`, `label`, `hint_min`, `searching`,
     * `no_results`, `err`, `cat_*`) : deux formulations pour un meme etat
     * finiraient par se contredire. */
    'menu_ouvrir' => 'Rechercher',
    'menu_voir_tout' => 'Ouvrir la recherche complète',

    'guide_titre'  => 'Ce que la recherche couvre',
    'guide_portee' => 'Cinq sources : serveurs, utilisateurs, CVE, tickets et journal d\'audit. '
                    . 'Chaque categorie rend au plus dix resultats — la recherche oriente, elle ne remplace '
                    . 'pas les pages dediees.',
    'guide_droits' => 'Elle traverse les comptes et le journal d\'audit : c\'est pourquoi elle est reservee '
                    . 'a l\'administration du portail.',
    'guide_liens'  => 'Un resultat mene a la page qui le gere. Les pages encore servies par l\'ancien portail '
                    . 'sont signalees par une fleche et s\'ouvrent dans un nouvel onglet.',

    'cat_machines' => 'Serveurs',
    'cat_users'    => 'Utilisateurs',
    'cat_cves'     => 'CVE',
    'cat_tickets'  => 'Tickets',
    'cat_audit'    => 'Journal d\'audit',

    'hint_min'     => 'Tapez au moins deux caracteres.',
    'searching'    => 'Recherche...',
    'results_for'  => 'resultat(s) pour',
    'no_results'   => 'Aucun resultat',
    'no_results_aide' => 'Aucune des cinq sources ne contient ce terme. Un nom de serveur, une adresse IP, '
                       . 'un identifiant de CVE ou un resume de ticket donnent les meilleurs resultats.',
    'err'          => 'La recherche a echoue.',
    'ancien_portail' => 'ouvre l\'ancien portail dans un nouvel onglet',
];
