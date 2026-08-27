<?php

/**
 * Fail2ban — sous-lot F1.
 *
 * L'en-tete du legacy annonce « admin (2), superadmin (3) » alors que sa garde
 * admet le role 1 (motif E-36). Aucun texte de cette page ne doit annoncer un
 * acces plus strict que celui qui est applique.
 *
 * Et aucun ne doit laisser croire que la permission `can_manage_fail2ban`
 * protege les GESTES : sur 23 routes des deux modules de filtrage, deux
 * seulement la verifient (E-152). Elle protege l'ecran.
 */

return [
    'titre' => 'Fail2ban',
    'intro' => 'Fail2ban bannit les adresses qui échouent trop souvent à s\'authentifier. Cette page montre son état sur vos machines, et les jails qu\'il surveille.',
    'serveur' => 'Machine',
    'choisir' => 'Choisissez une machine, puis relevez son état.',
    'relever' => 'Relever l\'état',
    'sensible' => 'Production',
    'sensible_avert' => 'Fail2ban PROTÈGE cette machine de production. Le désactiver ou vider ses jails la laisserait exposée.',
    'avert_titre' => 'Une machine de production figure dans cette liste',
    'avert_un' => 'Une des :total machines proposées est en production ou marquée critique.',
    'avert_plusieurs' => ':nb des :total machines proposées sont en production ou marquées critiques.',
    'chargement' => 'Lecture de l\'état sur la machine…',
    'echec' => 'L\'état n\'a pas pu être lu. La machine est-elle joignable ?',
    'etat' => 'État',
    'etat_absent' => 'Fail2ban n\'est pas installé',
    'etat_absent_aide' => 'Rien ne bannit les tentatives d\'authentification sur cette machine. L\'installation se fait depuis l\'ancien portail.',
    'etat_arrete' => 'Installé, mais arrêté',
    'etat_arrete_aide' => 'Fail2ban est présent et ne tourne pas : aucune adresse n\'est bannie tant qu\'il reste arrêté.',
    'etat_actif' => 'Actif',
    'jails' => 'Jails surveillées',
    'jails_aucune' => 'Aucune jail active. Fail2ban tourne, mais ne surveille rien.',
    // LE PLURIEL SE COMPOSE, IL NE SE PARENTHESE PAS. « 1 bannies » etait
    // rendu a l'ecran : vu a l'image, invisible a toute assertion. Et en
    // francais zero prend le SINGULIER — « 0 bannie ».
    'jails_une' => '1 jail',
    'jails_plusieurs' => ':nb jails',
    'adresses_une' => '1 adresse bannie',
    'adresses_plusieurs' => ':nb adresses bannies',
    'bannies' => 'bannies',
    'compte_bannies_une' => ':nb bannie',
    'compte_bannies_plusieurs' => ':nb bannies',
    'cache_maintenant' => 'relevé à l\'instant',
    'cache_titre' => 'Dernier relevé connu',
    'cache_jamais' => 'jamais relevé',
    'cache_le' => 'relevé le :date',
    'cache_aide' => 'Cet état vient du dernier relevé enregistré, pas de la machine à l\'instant. Relevez-le pour le rafraîchir.',
    'vide_titre' => 'Aucune machine au parc',
    'vide_texte' => 'Aucune machine active n\'est enregistrée. Ajoutez-en depuis l\'administration des serveurs.',
    'vide_action' => 'Ouvrir les serveurs',
    'non_porte_titre' => 'Les gestes sur Fail2ban ne sont pas encore portés',
    'non_porte_texte' => 'Bannir, débannir, modifier une jail ou la liste blanche se font pour l\'instant depuis l\'ancien portail. Cette page porte l\'état et les accès ; les gestes suivent.',
    'non_porte_lien' => 'Ouvrir Fail2ban dans l\'ancien portail',

    // ── Sous-lot F2 : historique et frise ────────────────────────────────
    'histo_titre' => 'Historique des bans',
    'histo_aide' => 'Les bans et débans enregistrés pour cette machine. Cette liste est lue en base : elle reste consultable même si la machine est injoignable.',
    'histo_choisir' => 'Choisissez une machine pour voir son historique.',
    'histo_vide_titre' => 'Aucun ban enregistré',
    'histo_vide' => 'Aucun ban ni déban n\'a jamais été enregistré pour cette machine. Ce n\'est pas une erreur de lecture : la liste est vide.',
    'histo_echec_titre' => 'L\'historique n\'a pas pu être lu',
    'histo_echec' => 'La lecture en base a échoué. Ce n\'est pas la même chose qu\'un historique vide — réessayez, puis regardez le journal du portail.',
    'histo_tout' => ':nb ligne(s), tout l\'historique de cette machine',
    'histo_tronque' => 'Les :montre plus récentes sur :total. Les plus anciennes ne sont pas affichées.',
    'histo_th_date' => 'Date',
    'histo_th_jail' => 'Jail',
    'histo_th_ip' => 'Adresse',
    'histo_th_action' => 'Action',
    'histo_th_par' => 'Par',
    'action_ban' => 'banni',
    'action_unban' => 'débanni',
    'par_inconnu' => 'compte n° :id (supprimé ?)',
    'par_repli' => 'non attribué',
    'par_repli_aide' => 'Le backend inscrit « admin » quand il ne reçoit pas d\'identifiant : ce n\'est pas forcément le compte nommé « admin ».',
    'frise_titre' => 'Activité des 30 derniers jours',
    'frise_aide' => 'Un rectangle par jour. Sa hauteur compte TOUS les événements du jour — bans et débans — et sa couleur dit lesquels dominent.',
    'frise_vide_titre' => 'Aucune activité sur 30 jours',
    'frise_vide' => 'Aucun ban ni déban n\'a été enregistré pour cette machine au cours des 30 derniers jours.',
    'frise_jour' => ':date — :bans banni(s), :unbans débanni(s)',
    'frise_legende_ban' => 'bans',
    'frise_legende_unban' => 'débans',
];
