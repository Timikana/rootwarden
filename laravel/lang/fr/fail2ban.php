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
    'intro' => 'Fail2ban bannit les adresses qui échouent trop souvent à s\'authentifier.',
    'serveur' => 'Machine',
    'choisir' => 'Choisissez une machine, puis relevez son état.',
    'relever' => 'Relever l\'état',
    'sensible' => 'Production',
    'sensible_avert' => 'Machine de production : désactiver Fail2ban ou vider ses jails la laisserait exposée.',
    'avert_titre' => 'Une machine de production figure dans cette liste',
    'avert_un' => 'Une des :total machines proposées est en production ou marquée critique.',
    'avert_plusieurs' => ':nb des :total machines proposées sont en production ou marquées critiques.',
    'chargement' => 'Lecture de l\'état sur la machine…',
    'echec' => 'L\'état n\'a pas pu être lu. La machine est-elle joignable ?',
    'etat' => 'État',
    'etat_absent' => 'Fail2ban n\'est pas installé',
    'etat_absent_aide' => 'Rien ne bannit les tentatives d\'authentification sur cette machine.',
    'etat_arrete' => 'Installé, mais arrêté',
    'etat_arrete_aide' => 'Aucune adresse n\'est bannie tant qu\'il reste arrêté.',
    'etat_actif' => 'Actif',
    'jails' => 'Jails surveillées',
    'jails_aucune' => 'Aucune jail active : Fail2ban ne surveille rien.',
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
    'cache_aide' => 'État du dernier relevé enregistré. Relevez-le pour le rafraîchir.',
    'vide_titre' => 'Aucune machine au parc',
    'vide_texte' => 'Ajoutez une machine depuis la page Serveurs.',
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
    /*
     * ⚠ L'ENUMERATION PERD UN ELEMENT, ET C'EST TOUT CE QU'ELLE PERD.
     *
     * Elle citait trois gestes : installer sur UNE machine, redemarrer le
     * service, interroger la geolocalisation. Le troisieme est porte par F8 ;
     * les deux autres restent. Le compte avait deja ete RETIRE en F7 — « quatre
     * gestes » ne se corrige pas en « trois », il se remplace par
     * l'enumeration, qui est la seule source.
     */

    // ══ F8 — LA GEOLOCALISATION D'UNE ADRESSE BANNIE ══════════════════════
    //
    // ⚠ CE GESTE EST UN APPEL SORTANT VERS UN TIERS, EN CLAIR.
    //
    // Le panneau NOMME le tiers et l'absence de chiffrement. « Un service
    // tiers » laisse croire a une relation contractuelle ; « ip-api.com, en
    // clair » dit ce qui se passe. Un panneau de decision qui reste vague ne
    // decide rien.
    //
    // Il porte AUSSI le fait rassurant, mesure : les adresses privees, de
    // bouclage et reservees ne partent pas — `fail2ban_manager.py` les rend
    // « Local » sans aucun appel. Une personne qui decide doit savoir ce qui
    // part ET ce qui ne part pas.
    //
    // ⛔ ET LA RESERVE DU BACKEND N'EST PAS RECOPIEE. Elle dit « l'IP est deja
    // publique, donc fuite negligeable ». C'est faux : ce qui n'est pas
    // public, c'est LE FAIT QUE NOTRE INFRASTRUCTURE L'A BANNIE. Un
    // observateur du trafic sortant ne lit pas une adresse, il lit la carte de
    // ce que nous bloquons. Une reserve fausse recopiee devient une
    // justification.
    'geo_bouton'     => 'Géolocaliser',
    'geo_conf_titre' => 'Interroger un service tiers sur :ip ?',
    'geo_conf_texte' => "L'adresse :ip sera envoyée en clair (HTTP) à ip-api.com, un service tiers. Les adresses privées et réservées ne sont jamais envoyées.",
    'geo_en_cours'   => 'Interrogation en cours…',
    /*
     * ⚠ LE RESULTAT RENDU DANS LA LIGNE NE REPETE PAS L'ADRESSE.
     *
     * `go-fail2ban-f4.mjs:566` mesure qu'une adresse bannie APPARAIT dans la
     * liste, par `includes()` sur son `innerText`. Ma premiere redaction
     * rendait « :ip — France (FR) » DANS la ligne : l'assertion serait devenue
     * satisfiable par mon rendu et non par le ban.
     *
     * Elle n'aurait pas rougi — elle serait devenue vraie pour une autre
     * raison. **Un faux vert sur une assertion de surete ne se signale
     * jamais**, la ou un faux rouge se voit tout de suite.
     *
     * La cellule d'adresse porte deja l'IP ; la repeter n'ajoutait rien qu'un
     * couplage. Le JOURNAL, lui, la porte — c'est un autre element, et une
     * trace qui ne nomme pas son objet ne sert a rien.
     */
    'geo_resultat'   => ':pays (:code)',
    'geo_locale'     => 'adresse locale, aucune requête n\'est partie.',
    'geo_inconnu'    => 'le service n\'a pas su répondre.',
    /*
     * ⚠ « DESACTIVEE » N'EST PAS « EN PANNE », ET C'EST TOUT L'OBJET DE CETTE CLE.
     * Le backend rend le code `OFF` (`fail2ban_manager.py:399`) et JAMAIS `??`,
     * qui signifie deja « le service n'a pas su repondre ». Reutiliser `??`
     * ferait passer un reglage delibere pour une panne du tiers : on
     * chercherait une panne inexistante, ou on rallumerait l'interrupteur
     * en croyant reparer.
     *
     * Le libelle NOMME la variable : sur un portail d'administration, savoir
     * QUOI changer fait la difference entre un etat subi et un etat choisi.
     */
    'geo_desactivee' => "géolocalisation désactivée (GEOIP_ENABLED) : aucune requête envoyée.",
    /*
     * ⚠ ETEINT, IL N'Y A PAS DE CONSENTEMENT A DEMANDER — IL Y A UN ETAT A DIRE.
     * `geo_conf_texte` annonce que l'adresse « sera transmise a ip-api.com EN
     * CLAIR ». Interrupteur eteint, cette phrase est FAUSSE : rien ne part.
     *
     * Et elle se trompe du cote PRUDENT, ce qui est precisement ce qui la rend
     * nuisible : l'exploitant consent, rien ne part, et il apprend que
     * l'avertissement est du theatre. Ce qui s'use alors n'est pas cette
     * phrase-la, c'est la credibilite de toutes les autres.
     */
    'geo_off_titre' => 'Géolocalisation désactivée',
    'geo_off_texte' => "Aucune adresse ne sera envoyée à ip-api.com. Pour l'activer, réglez GEOIP_ENABLED=true sur le serveur.",
    'geo_journal'    => ':ip — :detail',
    'geo_echec'      => "La géolocalisation a échoué. :message",

    // ── Sous-lot F2 : historique et frise ────────────────────────────────
    'histo_titre' => 'Historique des bans',
    'histo_aide' => 'Bans et débans enregistrés pour cette machine, consultables même si elle est injoignable.',
    'histo_choisir' => 'Choisissez une machine pour voir son historique.',
    'histo_vide_titre' => 'Aucun ban enregistré',
    'histo_vide' => 'Aucun ban ni déban enregistré pour cette machine.',
    'histo_echec_titre' => 'L\'historique n\'a pas pu être lu',
    'histo_echec' => 'Réessayez ; si l\'erreur persiste, consultez le journal du portail.',
    'histo_tout' => ':nb ligne(s), tout l\'historique de cette machine',
    'histo_tronque' => 'Les :montre plus récentes sur :total.',
    'histo_th_date' => 'Date',
    'histo_th_jail' => 'Jail',
    'histo_th_ip' => 'Adresse',
    'histo_th_action' => 'Action',
    'histo_th_par' => 'Par',
    'action_ban' => 'banni',
    'action_unban' => 'débanni',
    'par_inconnu' => 'compte n° :id (supprimé ?)',
    'par_repli' => 'non attribué',
    'par_repli_aide' => 'Action enregistrée sans identifiant de compte : « admin » ne désigne pas forcément le compte de ce nom.',
    'frise_titre' => 'Activité des 30 derniers jours',
    'frise_aide' => 'Un rectangle par jour : sa hauteur compte bans et débans, sa couleur dit lesquels dominent.',
    'frise_vide_titre' => 'Aucune activité sur 30 jours',
    'frise_vide' => 'Aucun ban ni déban sur les 30 derniers jours.',
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
    'fichier_absent' => 'Aucun fichier de configuration sur la machine.',
    'journal_absent_titre' => 'Ce journal n\'existe pas sur la machine',
    'journal_absent' => 'Fail2ban n\'y a encore rien écrit, ou n\'y tourne pas.',
    'lecture_echec_titre' => 'La lecture a échoué',
    'lecture_echec' => 'La machine n\'a pas répondu ou a refusé la lecture.',
    'services_titre' => 'Services détectés et jails disponibles',
    'services_aide' => 'Un service non installé ne peut pas être surveillé.',
    'services_installe' => 'Installé',
    'services_absent' => 'Non installé',
    'services_jails' => 'Jails :',
    'services_jail_active' => 'active',
    'services_vide_titre' => 'Aucun service détecté',
    'services_vide' => 'Fail2ban n\'a rien à surveiller sur cette machine.',

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
    'bannies_vide' => 'Cette jail ne bannit personne en ce moment.',
    'bannies_th_ip' => 'Adresse',
    'bannies_th_action' => 'Action',
    'ban_etiquette' => 'Adresse à bannir',
    'ban_placeholder' => '198.51.100.42',
    'ban_aide' => 'IPv4 ou IPv6. Le ban ne vaut que pour cette machine.',
    'bannir' => 'Bannir',
    'debannir' => 'Débannir',
    'tout_debannir' => 'Tout débannir',
    'conf_titre_ban' => 'Bannir :ip sur :machine ?',
    'conf_texte_ban' => 'L\'adresse :ip sera bannie dans la jail :jail, sur :machine seulement, jusqu\'à expiration du ban.',
    'conf_titre_debannir' => 'Débannir :ip sur :machine ?',
    'conf_texte_debannir' => 'L\'adresse :ip pourra de nouveau se connecter à :machine. Les autres machines ne sont pas touchées.',
    'conf_titre_tout' => 'Débannir TOUTES les adresses de :jail sur :machine ?',
    'conf_texte_tout' => 'Les :nb adresse(s) bannies dans cette jail pourront de nouveau se connecter à :machine. Irréversible : la liste des bans sera perdue.',
    'conf_confirmer' => 'Confirmer',
    'conf_annuler' => 'Annuler',
    'geste_journal' => 'Journal des gestes',
    'geste_vide' => 'Aucune action effectuée.',
    'geste_reussi' => ':message',
    'geste_echoue' => 'Échec — :message',
    'ban_invalide' => 'Adresse IP invalide : rien n\'a été envoyé.',

    // ── Sous-lot F5 : jails et liste blanche ─────────────────────────────
    'blanche_titre' => 'Adresses jamais bannies (liste blanche)',
    'blanche_aide' => 'Fail2ban ne bannira jamais ces adresses, quelle que soit la jail.',
    'blanche_lue' => 'Lue dans /etc/fail2ban/jail.local sur :machine.',
    'blanche_supposee_titre' => 'Valeurs par défaut, absentes de la configuration',
    'blanche_supposee' => 'jail.local ne contient pas de ligne ignoreip sur :machine : ces entrées sont les valeurs par défaut de Fail2ban, rien à retirer.',
    'blanche_vide_titre' => 'Aucune adresse exemptée',
    'blanche_vide' => 'Aucune adresse n\'est exemptée sur cette machine.',
    'blanche_etiquette' => 'Adresse à exempter',
    'blanche_ajouter' => 'Exempter cette adresse',
    'blanche_retirer' => 'Retirer',
    'blanche_non_retirable' => 'Ne peut pas être retirée',
    'blanche_non_retirable_aide' => ':ip est un réseau : seules des adresses peuvent être retirées.',
    'conf_titre_blanche_ajout' => 'Exempter :ip sur :machine ?',
    'conf_texte_blanche_ajout' => ':ip ne sera plus jamais bannie sur :machine. ⚠ Fail2ban redémarre : les bans en cours sur cette machine seront perdus.',
    'conf_titre_blanche_retrait' => 'Retirer l\'exemption de :ip sur :machine ?',
    'conf_texte_blanche_retrait' => ':ip pourra de nouveau être bannie sur :machine. ⚠ Fail2ban redémarre : les bans en cours sur cette machine seront perdus.',
    'jail_reglages_titre' => 'Activer la jail :jail sur :machine',
    'jail_reglages_avert' => '⚠ Activer une jail réécrit /etc/fail2ban/jail.local et redémarre le service : les bans en cours sur cette machine seront perdus.',
    'jail_activer' => 'Activer la jail',
    'jail_desactiver' => 'Désactiver',
    'jail_maxretry_aide' => 'Nombre d\'échecs avant bannissement.',
    'jail_bantime_aide' => 'En secondes, 60 au minimum.',
    'jail_findtime_aide' => 'Période de comptage des échecs, en secondes, 60 au minimum.',
    'conf_titre_jail' => 'Activer :jail sur :machine ?',
    'conf_texte_jail' => 'La jail :jail sera écrite dans /etc/fail2ban/jail.local sur :machine : :maxretry tentative(s), ban de :bantime s, fenêtre de :findtime s. ⚠ Le service redémarre : les bans en cours sur cette machine seront perdus.',

    // ── Sous-lot F6 : les deux gestes sur TOUT LE PARC ───────────────────
    //
    // Ces deux gestes ne prennent AUCUNE machine en parametre : le backend
    // choisit ses cibles en base. Aucun texte de cette section ne doit donc
    // laisser croire que l'operateur choisit la portee — il ne peut que la
    // LIRE. Et aucun ne dit « tous les serveurs » sans donner le nombre : le
    // legacy le faisait, et c'est E-173.
    'parc_titre' => "Actions sur tout le parc",
    'parc_aide' => "Elles ne visent pas la machine choisie : leurs cibles sont déduites du dernier relevé enregistré.",
    'parc_installer' => "Installer Fail2ban sur tout le parc",
    'parc_bannir' => "Bannir sur tout le parc",
    'parc_ban_titre' => "Bannir sur tout le parc",
    'parc_ban_aide' => "L'adresse saisie ci-dessus serait bannie sur les :nb machine(s) que le dernier relevé dit actives : :machines.",
    'parc_ban_aide_aucune' => "Le dernier relevé ne dit aucune machine active : ce ban ne toucherait rien. Relevez l'état des machines.",
    'parc_role_titre' => "Ces deux actions demandent le rôle Administrateur",
    'parc_role' => "Avec votre rôle, elles seraient refusées. Les actions machine par machine restent disponibles.",
    'portee_titre' => "Ce que ces gestes toucheraient aujourd'hui",
    'portee_cache' => "Portée déduite du dernier relevé de chaque machine, pas de son état actuel.",
    'portee_installer' => "Installer Fail2ban sur tout le parc toucherait :nb machine(s), sur un parc de :parc :",
    'portee_installer_aucune' => "Installer Fail2ban sur tout le parc ne toucherait aucune machine : le relevé enregistré dit que tout le parc (:parc) l'a déjà.",
    'portee_bannir' => "Bannir une adresse sur tout le parc toucherait :nb machine(s), sur un parc de :parc :",
    'portee_bannir_aucune' => "Bannir une adresse sur tout le parc ne toucherait AUCUNE machine : le relevé enregistré ne dit active aucune des machines du parc (:parc).",
    'portee_jamais' => "jamais relevée",
    'portee_jamais_aide' => "Une machine jamais relevée fait partie des installations.",
    'portee_archivee' => "retirée du parc",
    'portee_archivee_aide' => "Machine archivée : absente du sélecteur, mais toujours ciblée par les actions de parc.",
    'portee_releve_le' => "relevée le :date",
    'portee_inconnue_titre' => "La portée n'a pas pu être lue",
    'portee_inconnue' => "On ne sait pas quelles machines seraient touchées : les deux actions sont refusées. Rechargez la page.",
    'parc_ban_inconnue' => "Portée illisible : ce ban est refusé.",
    'conf_titre_parc_inconnue' => "Portée inconnue — rien ne sera envoyé",
    'conf_texte_parc_inconnue' => "La portée n'a pas pu être lue : rien ne sera envoyé.",
    'portee_relire' => "Relire la portée",
    'portee_relue' => "Portée relue à l'instant.",
    'portee_echec' => "Relecture impossible : les listes affichées datent du chargement de la page.",
    'conf_titre_parc_ban' => "Bannir :ip sur :nb machine(s) du parc ?",
    'conf_texte_parc_ban' => ":ip sera bannie dans la jail :jail sur les :nb machine(s) que le dernier relevé dit actives : :machines. Les machines où Fail2ban est absent ou arrêté ne sont pas touchées.",
    'conf_titre_parc_ban_vide' => "Aucune machine ne serait bannie",
    'conf_texte_parc_ban_vide' => "Le dernier relevé ne dit aucune machine active : :ip ne serait bannie nulle part. Rien ne sera envoyé.",
    'conf_titre_parc_install' => "Installer Fail2ban sur :nb machine(s) du parc ?",
    'conf_texte_parc_install' => "Fail2ban sera installé par apt-get sur :nb machine(s) : :machines. Production ou critiques : :prod. Jamais relevées : :jamais. Irréversible depuis cette page.",
    'conf_titre_parc_install_vide' => "Aucune machine à installer",
    'conf_texte_parc_install_vide' => "Le relevé dit que tout le parc (:parc) a déjà Fail2ban. Rien ne sera envoyé.",
    'recopie_etiquette' => "Pour confirmer, recopiez le nombre de machines touchées",
    'recopie_aide' => "Cette action touche plusieurs machines à la fois.",
    'recopie_faux' => "Le nombre recopié ne correspond pas.",
    'parc_envoi' => "Geste de parc envoyé vers :nb machine(s)…",
    'parc_resultat_machine' => ":machine : :etat",
    'parc_ok' => "abouti",
    'parc_echec' => "échoué — :message",
    'parc_echec_muet' => "échoué, sans motif rapporté",
    'parc_apres_install' => "Cette action ne met pas le relevé à jour : relevez chaque machine pour actualiser la portée.",
    'parc_rien' => "Aucune machine dans la réponse.",

    // UNE CLE SANS LECTEUR AUJOURD'HUI, ET C'EST DIT PLUTOT QUE CORRIGE.
    // `histo_choisir` n'est lue ni par la vue ni par le script.
    //
    // ✅ `jail_desactiver` EN A UN DEPUIS F7 : la note precedente annoncait
    // « le sera par F7 » et c'est fait — le bouton du detail de jail la rend.
    // L'arbitrage du 2026-08-27 (garder plutot que retirer-remettre) a donc
    // tenu, et cette ligne est mise a jour avec le code qu'elle decrit.

    // ══ F7 — DESACTIVER UNE JAIL ═════════════════════════════════════════
    //
    // CE GESTE BAISSE UNE GARDE, et il redemarre le service comme l'activation
    // (`disable_jail` appelle `restart_fail2ban`) : les bans en cours sont perdus.
    // Le panneau nomme la CONSEQUENCE, pas le mecanisme.
    'conf_titre_desact' => "Désactiver :jail sur :machine ?",
    'conf_texte_desact' => "La jail :jail cessera de surveiller :machine. ⚠ Le service redémarre : les bans en cours sur cette machine seront perdus. « Activer » rétablit la jail.",

    /*
     * ══ LES DEUX GESTES PAR MACHINE — ISO-PERIMETRE ══════════════════
     *
     * Le legacy les offrait ; ils avaient ete perdus par un arbitrage que
     * l'exploitant a annule (« portage a iso-perimetre »). `install_all`
     * etait deja porte : le geste le plus LARGE existait, le plus ETROIT
     * manquait — l'inverse de l'ordre de risque.
     */
    'installer' => "Installer Fail2ban",
    'redemarrer' => "Redémarrer le service",
    'conf_titre_install' => "Installer Fail2ban sur :machine ?",
    'conf_texte_install' => "Le paquet sera installé sur :machine seulement, par son gestionnaire de paquets. Cela peut prendre une minute et ne se défait pas depuis cette page.",
    'conf_titre_restart' => "Redémarrer Fail2ban sur :machine ?",
    'conf_texte_restart' => "Le service sera redémarré sur :machine seulement et relira sa configuration. ⚠ Les bans en cours sur cette machine seront perdus.",

];
