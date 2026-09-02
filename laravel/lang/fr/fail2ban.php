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
    // LE NOMBRE EST TOUJOURS SUBSTITUE, MEME AU SINGULIER : cette forme sert
    // aussi pour ZERO (en francais, zero prend le singulier), et un « 1 »
    // ecrit en dur y affichait « 1 adresse bannie » pour zero adresse.
    'jails_une' => ':nb jail',
    'jails_plusieurs' => ':nb jails',
    'adresses_une' => ':nb adresse bannie',
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
    /*
     * ⚠ LE COMPTE EST RETIRE, PAS REDUIT. F7 porte la desactivation d'une
     * jail : « Quatre » devient faux. Le passer a « Trois » le laisserait
     * pourrir au prochain portage — l'enumeration est la seule source.
     *
     * Et les TROIS restants sont apparies un par un contre les 19 routes du
     * backend, pas deduits : `install`, `restart` et `geoip` ne sont appeles
     * par aucun script du portage.
     */
    'non_porte_titre' => "Ce que cet onglet ne fait pas encore",
    'non_porte_texte' => "Installer Fail2ban sur UNE machine, redémarrer le service et interroger la géolocalisation d'une adresse se font encore depuis l'ancien portail. Tout le reste est ici : l'état, les jails et leur désactivation, l'historique, la configuration, les journaux, les bans, la liste blanche et les deux gestes de parc.",
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

    // ── Sous-lot F3 : configuration, journaux, services ──────────────────
    'voir_config' => 'Voir jail.local',
    'voir_logs' => 'Voir les journaux',
    'config_titre' => 'Configuration — /etc/fail2ban/jail.local',
    'logs_titre' => 'Journal — /var/log/fail2ban.log',
    'lu_a_l_instant' => 'Lu à l\'instant sur :machine.',
    'fichier_absent_titre' => 'Ce fichier n\'existe pas sur la machine',
    'fichier_absent' => 'La machine a répondu qu\'aucun fichier de configuration n\'est présent. Ce n\'est pas une configuration vide : il n\'y en a aucune.',
    'journal_absent_titre' => 'Ce journal n\'existe pas sur la machine',
    'journal_absent' => 'La machine a répondu qu\'aucun fichier de journal n\'est présent. Fail2ban n\'y a donc encore rien écrit — ou n\'y tourne pas.',
    'lecture_echec_titre' => 'La lecture a échoué',
    'lecture_echec' => 'La machine n\'a pas répondu, ou a refusé la lecture. Ce n\'est pas la même chose qu\'un fichier absent.',
    'services_titre' => 'Services détectés et jails disponibles',
    'services_aide' => 'Ce que la machine a répondu à la détection. Un service absent ne peut pas être surveillé : sa jail n\'aurait rien à lire.',
    'services_installe' => 'Installé',
    'services_absent' => 'Non installé',
    'services_jails' => 'Jails :',
    'services_jail_active' => 'active',
    'services_vide_titre' => 'Aucun service détecté',
    'services_vide' => 'La détection n\'a rapporté aucun service. Fail2ban n\'a donc rien à surveiller sur cette machine.',

    // ── Sous-lot F4 : bannir et débannir ─────────────────────────────────
    'jail_detail_titre' => 'Jail :jail',
    'jail_fermer' => 'Fermer',
    'jail_maxretry' => 'Tentatives avant ban',
    'jail_bantime' => 'Durée du ban',
    'jail_findtime' => 'Fenêtre d\'observation',
    'jail_secondes' => ':nb s',
    'jail_inconnu' => 'non lu',
    'bannies_titre' => 'Adresses actuellement bannies',
    'bannies_vide_titre' => 'Aucune adresse bannie',
    'bannies_vide' => 'Cette jail ne bannit personne en ce moment. Ce n\'est pas une erreur de lecture : la liste est vide.',
    'bannies_th_ip' => 'Adresse',
    'bannies_th_action' => 'Action',
    'ban_etiquette' => 'Adresse à bannir',
    'ban_placeholder' => '198.51.100.42',
    'ban_aide' => 'Une adresse IPv4 ou IPv6. Le ban ne vaut que pour la machine affichée ci-dessus.',
    'bannir' => 'Bannir',
    'debannir' => 'Débannir',
    'tout_debannir' => 'Tout débannir',
    'conf_titre_ban' => 'Bannir :ip sur :machine ?',
    'conf_texte_ban' => 'L\'adresse :ip sera bannie dans la jail :jail, sur :machine et sur elle seule. Toute connexion venant de cette adresse sera refusée jusqu\'à expiration du ban.',
    'conf_titre_debannir' => 'Débannir :ip sur :machine ?',
    'conf_texte_debannir' => 'L\'adresse :ip pourra de nouveau se connecter à :machine. Si elle est bannie sur d\'autres machines, elles ne sont pas touchées.',
    'conf_titre_tout' => 'Débannir TOUTES les adresses de :jail sur :machine ?',
    'conf_texte_tout' => 'Les :nb adresse(s) actuellement bannies dans cette jail pourront de nouveau se connecter à :machine. Ce geste ne se défait pas : la liste des adresses bannies sera perdue.',
    'conf_confirmer' => 'Confirmer',
    'conf_annuler' => 'Annuler',
    'geste_journal' => 'Journal des gestes',
    'geste_vide' => 'Aucun geste n\'a encore été effectué sur cette page.',
    'geste_reussi' => ':message',
    'geste_echoue' => 'Échec — :message',
    'ban_invalide' => 'Ce n\'est pas une adresse IP valide. Rien n\'a été envoyé.',

    // ── Sous-lot F5 : jails et liste blanche ─────────────────────────────
    'blanche_titre' => 'Adresses jamais bannies (liste blanche)',
    'blanche_aide' => 'Ces adresses sont exemptées : fail2ban ne les bannira jamais, quelle que soit la jail.',
    'blanche_lue' => 'Lue dans /etc/fail2ban/jail.local sur :machine.',
    'blanche_supposee_titre' => 'Cette liste est SUPPOSÉE, pas lue',
    'blanche_supposee' => 'Le fichier /etc/fail2ban/jail.local de :machine ne contient aucune ligne ignoreip. Les entrées ci-dessous sont celles que fail2ban applique par défaut — elles ne figurent nulle part dans la configuration de cette machine, et il n\'y a donc rien à en retirer.',
    'blanche_vide_titre' => 'Aucune adresse exemptée',
    'blanche_vide' => 'Aucune adresse n\'est exemptée sur cette machine.',
    'blanche_etiquette' => 'Adresse à exempter',
    'blanche_ajouter' => 'Exempter cette adresse',
    'blanche_retirer' => 'Retirer',
    'blanche_non_retirable' => 'Ne peut pas être retirée',
    'blanche_non_retirable_aide' => ':ip n\'est pas une adresse mais un réseau, et le backend n\'accepte que des adresses. Un retrait échouerait toujours.',
    'conf_titre_blanche_ajout' => 'Exempter :ip sur :machine ?',
    'conf_texte_blanche_ajout' => ':ip ne sera plus jamais bannie sur :machine, dans aucune jail. ⚠ Ce geste REDÉMARRE fail2ban : tous les bans en cours sur cette machine seront perdus.',
    'conf_titre_blanche_retrait' => 'Retirer l\'exemption de :ip sur :machine ?',
    'conf_texte_blanche_retrait' => ':ip pourra de nouveau être bannie sur :machine. ⚠ Ce geste REDÉMARRE fail2ban : tous les bans en cours sur cette machine seront perdus.',
    'jail_reglages_titre' => 'Activer la jail :jail sur :machine',
    'jail_reglages_avert' => '⚠ Activer une jail RÉÉCRIT /etc/fail2ban/jail.local et REDÉMARRE le service : tous les bans en cours sur cette machine seront perdus.',
    'jail_activer' => 'Activer la jail',
    'jail_desactiver' => 'Désactiver',
    'jail_maxretry_aide' => 'Nombre d\'échecs avant bannissement.',
    'jail_bantime_aide' => 'Durée du bannissement, en secondes. Minimum 60.',
    'jail_findtime_aide' => 'Fenêtre pendant laquelle les échecs sont comptés, en secondes. Minimum 60.',
    'conf_titre_jail' => 'Activer :jail sur :machine ?',
    'conf_texte_jail' => 'La jail :jail sera écrite dans /etc/fail2ban/jail.local sur :machine, avec :maxretry tentative(s), un ban de :bantime s et une fenêtre de :findtime s. ⚠ Le service REDÉMARRE : tous les bans en cours sur cette machine seront perdus.',

    // ── Sous-lot F6 : les deux gestes sur TOUT LE PARC ───────────────────
    //
    // Ces deux gestes ne prennent AUCUNE machine en parametre : le backend
    // choisit ses cibles en base. Aucun texte de cette section ne doit donc
    // laisser croire que l'operateur choisit la portee — il ne peut que la
    // LIRE. Et aucun ne dit « tous les serveurs » sans donner le nombre : le
    // legacy le faisait, et c'est E-173.
    'parc_titre' => "Gestes sur tout le parc",
    'parc_aide' => "Ces deux gestes ne visent pas la machine choisie ci-dessus : ils n'en prennent aucune. Le backend choisit ses cibles lui-même, en base, d'après le dernier relevé enregistré. Ce que cette section annonce est le résultat de SES requêtes, lues sur la même base.",
    'parc_installer' => "Installer Fail2ban sur tout le parc",
    'parc_bannir' => "Bannir sur tout le parc",
    'parc_ban_titre' => "Bannir sur tout le parc",
    'parc_ban_aide' => "L'adresse saisie ci-dessus serait bannie sur les machines que le dernier relevé dit actives, et sur elles seules — :nb au total : :machines.",
    'parc_ban_aide_aucune' => "Le dernier relevé ne dit AUCUNE machine active : ce geste ne toucherait rien. Relevez l'état des machines pour que la portée soit connue.",
    'parc_role_titre' => "Ces deux gestes demandent le rôle administrateur",
    'parc_role' => "Les deux routes de parc du backend exigent le rôle 2 — ce sont les seules du module. Avec votre rôle, elles refuseraient. Les gestes machine par machine, eux, restent disponibles.",
    'portee_titre' => "Ce que ces gestes toucheraient aujourd'hui",
    'portee_cache' => "Cette portée est décidée par le dernier relevé enregistré, machine par machine — pas par l'état des machines à l'instant. Une machine dont Fail2ban est tombé depuis son relevé ne figure pas dans les installations, bien qu'elle ne protège plus rien ; une machine installée depuis y figure encore.",
    'portee_installer' => "Installer Fail2ban sur tout le parc toucherait :nb machine(s), sur un parc de :parc :",
    'portee_installer_aucune' => "Installer Fail2ban sur tout le parc ne toucherait aucune machine : le relevé enregistré dit que tout le parc (:parc) l'a déjà.",
    'portee_bannir' => "Bannir une adresse sur tout le parc toucherait :nb machine(s), sur un parc de :parc :",
    'portee_bannir_aucune' => "Bannir une adresse sur tout le parc ne toucherait AUCUNE machine : le relevé enregistré ne dit active aucune des machines du parc (:parc).",
    'portee_jamais' => "jamais relevée",
    'portee_jamais_aide' => "Une machine marquée « jamais relevée » n'a aucune ligne de relevé. La requête d'installation retient les machines dont le relevé ne dit pas « installé » — et une machine sans relevé en fait partie : ne l'avoir jamais regardée suffit à la faire installer.",
    'portee_archivee' => "retirée du parc",
    'portee_archivee_aide' => "Cette machine est archivée : elle ne figure pas dans le sélecteur ci-dessus. Les deux requêtes de parc, elles, ne filtrent pas le cycle de vie — elle reste donc une cible.",
    'portee_releve_le' => "relevée le :date",
    'portee_inconnue_titre' => "La portée n'a pas pu être lue",
    'portee_inconnue' => "Ni le chargement de la page ni la relecture n'ont rendu la portée de ces deux gestes. Ce n'est PAS « aucune machine » : on ne sait pas lesquelles seraient touchées, et les deux gestes sont donc refusés ici. Rechargez la page.",
    'parc_ban_inconnue' => "La portée n'a pas pu être lue : ce geste est refusé tant qu'on ne sait pas quelles machines il toucherait.",
    'conf_titre_parc_inconnue' => "Portée inconnue — rien ne sera envoyé",
    'conf_texte_parc_inconnue' => "La portée de ce geste n'a pas pu être lue. Un geste de parc ne s'envoie pas sans savoir sur combien de machines il porte : rien ne sera envoyé.",
    'portee_relire' => "Relire la portée",
    'portee_relue' => "Portée relue à l'instant.",
    'portee_echec' => "La portée n'a pas pu être relue. Les listes affichées sont celles du chargement de la page.",
    'conf_titre_parc_ban' => "Bannir :ip sur :nb machine(s) du parc ?",
    'conf_texte_parc_ban' => ":ip sera bannie dans la jail :jail sur les machines que le dernier relevé dit actives — :nb au total : :machines. Les machines dont Fail2ban est absent ou arrêté ne sont pas touchées, même exposées. Ce geste part vers plusieurs machines à la fois.",
    'conf_titre_parc_ban_vide' => "Aucune machine ne serait bannie",
    'conf_texte_parc_ban_vide' => "Le dernier relevé ne dit aucune machine active : la portée de ce geste est de 0 machine, et :ip ne serait bannie nulle part. Rien ne sera envoyé.",
    'conf_titre_parc_install' => "Installer Fail2ban sur :nb machine(s) du parc ?",
    'conf_texte_parc_install' => "Fail2ban sera installé par apt-get sur les machines dont le relevé ne dit pas qu'elles l'ont — :nb au total : :machines. Machines de production ou marquées critiques dans cette portée : :prod. Machines jamais relevées : :jamais — ne l'avoir jamais regardée suffit à la faire installer. Ce geste installe un paquet sur plusieurs machines à la fois, et il ne se défait pas depuis cette page.",
    'conf_titre_parc_install_vide' => "Aucune machine à installer",
    'conf_texte_parc_install_vide' => "Le relevé enregistré dit que tout le parc (:parc) a déjà Fail2ban : la portée de ce geste est de 0 machine. Rien ne sera envoyé.",
    'recopie_etiquette' => "Pour confirmer, recopiez le nombre de machines touchées",
    'recopie_aide' => "Ce geste porte sur plusieurs machines à la fois. Le confirmer demande de recopier leur nombre : deux « oui » d'affilée sont un réflexe, pas deux décisions.",
    'recopie_faux' => "Le nombre recopié ne correspond pas.",
    'parc_envoi' => "Geste de parc envoyé vers :nb machine(s)…",
    'parc_resultat_machine' => ":machine : :etat",
    'parc_ok' => "abouti",
    'parc_echec' => "échoué — :message",
    'parc_echec_muet' => "échoué — le backend ne dit pas pourquoi",
    'parc_apres_install' => "Le relevé n'est pas mis à jour par ce geste : la portée ci-dessus restera la même jusqu'à ce que chaque machine soit relevée.",
    'parc_rien' => "Le backend n'a rapporté aucune machine.",

    // UNE CLE SANS LECTEUR AUJOURD'HUI, ET C'EST DIT PLUTOT QUE CORRIGE.
    // `histo_choisir` n'est lue ni par la vue ni par le script.
    //
    // ✅ `jail_desactiver` EN A UN DEPUIS F7 : la note precedente annoncait
    // « le sera par F7 » et c'est fait — le bouton du detail de jail la rend.
    // L'arbitrage du 2026-08-27 (garder plutot que retirer-remettre) a donc
    // tenu, et cette ligne est mise a jour avec le code qu'elle decrit.

    // ══ F7 — DESACTIVER UNE JAIL ═════════════════════════════════════════
    //
    // ⚠ CE GESTE BAISSE UNE GARDE. Il n'est pas destructeur — rien n'est
    // efface, et « Activer la jail » le retablit — mais il ARRETE une
    // protection contre le force brute sur une machine reelle, et il ouvre une
    // session SSH pour le faire (`backend/routes/fail2ban.py:418`).
    //
    // Le panneau nomme donc la CONSEQUENCE et non le mecanisme : ce qui compte
    // pour qui decide n'est pas qu'un fichier change, c'est que la machine
    // cesse d'etre protegee.
    'conf_titre_desact' => "Désactiver :jail sur :machine ?",
    'conf_texte_desact' => "La jail :jail cessera de surveiller :machine : les tentatives d'authentification en échec ne seront plus bannies. Le geste ouvre une session SSH sur la machine. Il se rétablit par « Activer », et aucune adresse déjà bannie n'est libérée.",
    // Mesure du 2026-09-02 : 0 occurrence dans `command_log`, `tasks` et
    // `user_logs` (temoin : 5 920 lignes au total). Le dire plutot que de
    // laisser croire que le chemin est eprouve.
    'desact_jamais_exercee' => "Ce geste n'a encore jamais été exercé depuis cette interface.",
];
