<?php

/**
 * Sous-navigation des pages d'administration — module `adm/`.
 *
 * `admin_page.php` porte TROIS onglets en JavaScript sous une seule URL. Le
 * portage en fait trois PAGES, et ces trois libelles sont les seuls elements
 * qu'elles partagent : ils vivent donc a un seul endroit.
 */
return [
    'nav_titre' => 'Administration',
    'nav_comptes' => 'Comptes',
    'nav_serveurs' => 'Serveurs',
    'nav_permissions' => 'Accès & permissions',
];
