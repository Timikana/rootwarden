<?php

/*
 * Module `supervision/` — sous-lot V1 : la page et ses quatre onglets.
 *
 * TOUT CE QUE LE SCRIPT AFFICHE EST ICI, dans le meme fichier que ce que la page
 * affiche. C'est la reponse a la dette du legacy : la-bas, le JS lit ses libelles
 * dans un second catalogue (`js.php`) ou onze cles du module manquent, et
 * `head.php` rend alors la CLE elle-meme a l'ecran — `editor_select_server`.
 * Comme une cle est une chaine non vide, `__('x') || 'repli'` ne replie jamais :
 * la panne est silencieuse. Un seul catalogue, et elle ne peut plus se reformer.
 */

return [
    'titre' => 'Supervision',
    'sous_titre' => 'Deploiement et configuration des agents de supervision',
    'description' => "Cette page rassemble la configuration des agents, le catalogue de profils, le deploiement sur le parc et l'edition du fichier de configuration distant.",

    'plateforme' => 'Plateforme',

    'onglet_config' => 'Configuration globale',
    'onglet_profiles' => 'Profils',
    'onglet_deploy' => 'Deploiement agents',
    'onglet_editor' => 'Editeur de configuration',

    'config_titre' => 'Configuration du modele d\'agent',
    'config_description' => 'Ces parametres servent de modele a tous les deploiements. Chaque serveur peut porter ses propres valeurs.',

    // ── La configuration globale, sous-lot V3 (lecture seule) ────────────
    'config_aucune' => 'Aucune configuration globale enregistree',
    'config_aucune_aide' => 'Aucune configuration globale n\'est enregistree pour :plateforme. Les valeurs par defaut du modele d\'agent s\'appliqueront au prochain deploiement.',
    // « LA » CONFIGURATION GLOBALE N'EXISTE PAS : la table n'a aucune contrainte
    // d'unicite sur la plateforme, et les deux portails lisent la ligne d'`id` le
    // plus grand. Le dire, plutot que de laisser croire a un enregistrement unique.
    'config_plus_recente' => 'Plusieurs configurations peuvent coexister pour une meme plateforme : c\'est la plus recemment enregistree qui s\'applique, et c\'est celle affichee ici.',
    'champ_vide' => 'Non renseigne',
    'champ_type_agent' => 'Type d\'agent',
    'champ_version_agent' => 'Version de l\'agent',
    'champ_serveur' => 'Serveur',
    'champ_serveur_actif' => 'Serveur actif',
    'champ_port' => 'Port d\'ecoute',
    'champ_motif_nom' => 'Motif du nom d\'hote',
    'champ_tls_connexion' => 'TLS en connexion',
    'champ_tls_acceptation' => 'TLS en acceptation',
    'champ_psk_identite' => 'Identite PSK',
    'champ_psk_valeur' => 'Cle PSK',
    'champ_metadonnees' => 'Modele de metadonnees d\'hote',
    'champ_config_supplementaire' => 'Lignes supplementaires',
    'champ_centreon_hote' => 'Hote Centreon',
    'champ_centreon_port' => 'Port Centreon',
    'champ_prometheus_ecoute' => 'Adresse d\'ecoute',
    'champ_prometheus_collecteurs' => 'Collecteurs',
    'champ_telegraf_url' => 'URL de sortie',
    'champ_telegraf_organisation' => 'Organisation',
    'champ_telegraf_seau' => 'Seau',
    'champ_telegraf_entrees' => 'Entrees',
    'champ_telegraf_jeton' => 'Jeton de sortie',
    'secret_pose' => 'Defini',
    'secret_absent' => 'Non defini',
    'secret_jamais_affiche' => 'La valeur reste en base : ce portail ne la lit pas.',
    // ── L'enregistrement, sous-lot V4 ─────────────────────────────────────
    'secret_conserve' => 'Laisser vide conserve la cle deja enregistree. Ce portail ne la lit jamais.',
    'secret_jeton_non_porte' => 'La modification de ce jeton n\'est pas encore portee : elle reste sur l\'ancien portail.',
    'enregistrer' => 'Enregistrer',
    // LA PORTEE DE L'ENREGISTREMENT SE DIT. Le legacy ecrit dans la ligne la plus
    // recente SANS filtre de plateforme : enregistrer Zabbix y ecrase une ligne
    // Centreon. Ici l'ecriture est cloisonnee, et l'ecran l'annonce.
    'enregistrement_portee' => 'Cet enregistrement ne modifie que la configuration de :plateforme.',
    'enregistrement_fait' => 'Configuration de :plateforme enregistree.',
    'enregistrement_champ_exige' => 'Le champ « :champ » est indispensable : sans lui, la configuration deployee serait inerte.',
    'enregistrement_plateforme_inconnue' => 'Plateforme inconnue : rien n\'a ete enregistre.',

    'profils_titre' => 'Profils de supervision',
    // ── Le catalogue, sous-lot V2 (lecture seule) ─────────────────────────
    'profil_nom' => 'Nom',
    'profil_actions' => 'Actions',
    // ── Le CRUD, sous-lot V5 ──────────────────────────────────────────────
    'champ_profil_nom' => 'Nom',
    'champ_profil_description' => 'Description',
    'champ_profil_metadonnees' => 'HostMetadata',
    'champ_profil_serveur' => 'Serveur',
    'champ_profil_serveur_actif' => 'Serveur actif',
    'champ_profil_mandataire' => 'Mandataire',
    'champ_profil_port' => 'Port d\'ecoute',
    'champ_profil_notes' => 'Notes',
    'profil_modifier' => 'Modifier',
    'profil_supprimer' => 'Supprimer',
    'profil_nouveau' => 'Nouveau profil',
    'profil_titre_nouveau' => 'Nouveau profil',
    'profil_titre_modifier' => 'Modifier le profil :nom',
    'profil_nom_exige' => 'Le nom est indispensable : c\'est lui qui relie le profil a une regle d\'auto-enregistrement.',
    // LA CONTRAINTE EST EN BASE (`uk_platform_name`), verifiee au schema : le
    // refus n'est pas une politesse d'interface, c'est une propriete de la donnee.
    'profil_doublon' => 'Un profil nomme « :nom » existe deja pour :plateforme. Les noms sont uniques par plateforme.',
    'profil_introuvable' => 'Ce profil n\'existe pas, ou plus.',
    'profil_cree' => 'Profil « :nom » cree.',
    'profil_modifie' => 'Profil « :nom » modifie.',
    'profil_supprime' => 'Profil « :nom » supprime. :machines serveur(s) retombent sur la configuration globale.',
    'profil_supprimer_titre' => 'Supprimer le profil « :nom » ?',
    // LE COUT EST ANNONCE AVANT LE GESTE, pas constate apres.
    'profil_supprimer_cout' => ':machines serveur(s) perdront ce profil et retomberont sur la configuration globale au prochain deploiement. Cette suppression ne se defait pas.',
    'profil_supprimer_confirmer' => 'Supprimer definitivement',
    'annuler' => 'Annuler',
    // L'ASSIGNATION N'EST PAS PORTEE, et c'est une decision : son point d'entree
    // est le tableau de deploiement, et l'inverser (choisir des machines pour un
    // profil) serait concevoir, pas migrer.
    'profils_assignation_ailleurs' => 'Rattacher un serveur a un profil se fait depuis le tableau de deploiement, qui n\'est pas encore porte.',
    'profil_metadonnees' => 'HostMetadata',
    'profil_serveur' => 'Serveur',
    'profil_mandataire' => 'Mandataire',
    'profil_machines' => 'Machines',
    // UNE VALEUR ABSENTE DIT CE QU'ELLE SIGNIFIE. Le legacy ecrit « - », qui
    // n'apprend rien : ici, l'absence veut dire que la configuration globale
    // s'applique, et c'est ce qui est ecrit.
    'profil_herite' => 'Configuration globale',
    'profils_aucun' => 'Aucun profil pour cette plateforme',
    'profils_aucun_aide' => 'Aucun profil de supervision n\'est defini pour :plateforme. Les profils sont propres a chaque plateforme.',
    'profils_interpolation' => 'Les valeurs peuvent contenir {machine.name} ou {machine.ip} : elles sont remplacees au moment du deploiement.',
    'profils_description' => "Reglages reutilisables (metadonnees d'hote, serveur, mandataire). Le catalogue est ecrit une fois, puis chaque serveur est rattache a un profil.",

    'deploiement_titre' => 'Deploiement des agents',
    'deploiement_description' => 'Installation, reconfiguration et desinstallation de l\'agent sur les serveurs du parc.',

    'editeur_titre' => 'Editeur de configuration distante',
    'editeur_description' => "Lire, modifier et enregistrer le fichier de configuration de l'agent sur un serveur.",
    'editeur_serveur' => 'Serveur',
    'editeur_choisir_serveur' => 'Choisir un serveur',
    'editeur_lire' => 'Lire la configuration',
    // ── L'editeur distant, sous-lot V7 (lecture seule) ────────────────────
    // LE CHEMIN ANNONCE VIENT DE LA MEME SOURCE QUE CELUI QUI SERA LU. Le legacy
    // affiche un chemin ecrit en dur cote client : voir PARITE E-79.
    // AVANT LA LECTURE, LA PAGE NE PEUT PAS DIRE « LU » : rien ne l'a ete. Deux
    // libelles, et le script passe du premier au second quand la lecture aboutit.
    // Vu a l'image — meme famille qu'un texte qui devient faux.
    'editeur_chemin' => 'Fichier a lire :',
    'editeur_chemin_lu' => 'Fichier lu :',
    'editeur_contenu' => 'Contenu du fichier',
    'editeur_vide' => 'Choisissez un serveur puis lisez sa configuration pour l\'afficher ici.',
    'editeur_lecture_en_cours' => 'Lecture du fichier sur :nom en cours...',
    'editeur_lu' => 'Fichier :chemin lu sur :nom.',
    // TROIS CAS SEPARES : un fichier absent est une REPONSE, pas une panne.
    'editeur_absent' => 'Le fichier :chemin n\'existe pas sur :nom. Aucun agent n\'y est probablement installe.',
    'editeur_refus' => 'La lecture a ete refusee (statut :statut). Aucune conclusion ne peut en etre tiree.',
    'editeur_echec' => 'La lecture n\'a pas abouti : le serveur est peut-etre injoignable.',
    'sauvegardes_titre' => 'Sauvegardes du fichier sur le serveur.',
    'sauvegardes_lister' => 'Lister les sauvegardes',
    'sauvegardes_aucune' => 'Aucune sauvegarde sur ce serveur.',
    'sauvegardes_nombre' => ':nombre sauvegarde(s) :',
    // LE GARDE QUE V1 FERME. Cote legacy, ce message est la cle
    // `editor_select_server` affichee telle quelle, en clair, dans une boite.
    'editeur_sans_serveur' => 'Choisissez d\'abord un serveur : sans serveur, il n\'y a aucune configuration a lire.',

    'aucune_machine' => 'Aucun serveur dans le parc',
    // ── Le parc et la detection de version, sous-lot V6 ───────────────────
    'machine_nom' => 'Serveur',
    'machine_adresse' => 'Adresse',
    'machine_environnement' => 'Environnement',
    'machine_agents' => 'Agents releves',
    // UNE ABSENCE D'AGENT EST UN CONSTAT, pas un silence : une detection qui ne
    // trouve rien supprime la ligne enregistree.
    'agent_aucun' => 'Aucun releve',
    'version_detecter' => 'Detecter la version',
    'version_en_cours' => 'Lecture de la version sur :nom en cours...',
    'version_trouvee' => 'Version detectee sur :nom : :version.',
    'version_absente' => 'Aucun agent installe sur :nom. Le releve precedent a ete efface.',
    // UN REFUS NE SE CONFOND PAS AVEC « AUCUN AGENT » : un client qui ne lit pas
    // le statut conclurait « rien d'installe » sans avoir rien mesure.
    'version_refus' => 'La lecture a ete refusee (statut :statut). Aucune conclusion ne peut en etre tiree.',
    'version_echec' => 'La lecture n\'a pas abouti : le serveur est peut-etre injoignable.',
    'aucune_machine_aide' => 'Toutes les machines sont archivees, ou le parc est vide.',

    // Ce que V1 ne porte pas encore le DIT, plutot que de laisser un panneau nu.
    // Le titre de l'etat vide ne REPETE pas celui du panneau : vu a l'image, le
    // meme intitule deux fois de suite se lit comme un defaut d'affichage.
    'pas_encore_porte' => 'Pas encore porte sur ce portail',
    'a_venir_config' => 'La lecture et l\'enregistrement de cette configuration arrivent avec les sous-lots suivants. En attendant, ils restent sur l\'ancien portail.',
    'a_venir_profils' => 'Le catalogue de profils et son assignation arrivent avec les sous-lots suivants. En attendant, ils restent sur l\'ancien portail.',
    // UN TEXTE PEUT DEVENIR FAUX SANS QU'AUCUN TEST NE LE VOIE : le tableau du
    // parc est porte depuis V6, la phrase qui l'annoncait « pour plus tard » ne
    // l'etait plus. Vu a l'image.
    'a_venir_deploiement' => "Installer, reconfigurer et desinstaller un agent arrivent avec les sous-lots suivants : ces gestes MODIFIENT les serveurs. En attendant, ils restent sur l'ancien portail.",
    'a_venir_editeur' => 'La lecture et l\'ecriture du fichier distant arrivent avec les sous-lots suivants. En attendant, elles restent sur l\'ancien portail.',
    'vers_legacy' => 'Ouvrir sur l\'ancien portail',

    // ── Sous-lot V8 : le releve du parc en tache de fond ──────────────────
    'releve_titre' => 'Relever les agents de tout le parc',
    'releve_description' => "Interroge chaque serveur pour savoir quels agents de supervision y sont installes, et en quelle version. C'est une LECTURE : rien n'est installe, rien n'est reconfigure, rien n'est redemarre. Le releve part en tache de fond et son avancement se suit dans le centre de taches.",
    'releve_bouton' => 'Relever le parc',
    'releve_cout' => ':machines machine(s), :plateformes plateforme(s), :sessions session(s) SSH — une par machine, pas une par plateforme.',
    'releve_production' => 'Machines de PRODUCTION concernees : :machines.',
    'releve_aide_fond' => "Le releve ne bloque pas cette page : la reponse est immediate et le balayage continue en arriere-plan, un serveur apres l'autre.",
    'releve_annuler' => 'Annuler',
    'releve_confirmer' => 'Lancer le releve',
    'releve_en_cours' => 'Mise en file du releve...',
    'releve_lance' => 'Releve lance sur :machines machine(s) — tache n° :tache.',
    'releve_aucune' => 'Aucune machine a relever.',
    'releve_refus' => 'Releve refuse (statut :statut).',
    'releve_echec' => "Le releve n'a pas pu etre lance.",
    'releve_voir_taches' => 'Suivre dans le centre de taches',
];
