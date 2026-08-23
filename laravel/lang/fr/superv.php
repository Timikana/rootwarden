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
    'editeur_chemin' => 'Fichier cible :',
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

    // ── Sous-lot V9 : l'ecriture distante et la restauration ──────────────
    'editeur_sauver' => 'Enregistrer sur le serveur',
    'editeur_sauver_vide' => "Le contenu est vide : rien ne sera ecrit. Lisez d'abord le fichier, ou saisissez une configuration.",
    'editeur_sauver_cout' => 'Ce geste porte sur :chemin, sur le serveur choisi.',
    'editeur_effet_sauvegarde' => "une copie datee du fichier actuel est creee sur le serveur, avant toute ecriture",
    'editeur_effet_ecriture' => 'le fichier est remplace par le contenu affiche ci-dessus',
    'editeur_effet_redemarrage' => "l'agent de supervision est redemarre pour prendre la nouvelle configuration",
    'editeur_sauver_annuler' => 'Annuler',
    'editeur_sauver_confirmer' => 'Ecrire et redemarrer',
    'editeur_sauver_en_cours' => 'Ecriture en cours...',
    'editeur_sauve_et_redemarre' => "Fichier ecrit et agent redemarre.",
    'editeur_sauve_sans_redemarrage' => "Fichier ecrit, mais l'agent n'a PAS redemarre. La configuration est en place et le service ne tourne pas : verifiez-le avant de compter sur la supervision de ce serveur.",
    'editeur_sauver_refus' => "Ecriture refusee (statut :statut).",
    'editeur_sauver_echec' => "Le fichier n'a pas ete ecrit.",
    'restaurer_bouton' => 'Restaurer',
    'restaurer_cout' => 'Restaurer :nom ecrasera :chemin sur le serveur choisi.',
    'restaurer_aide' => "Le fichier actuel est d'abord copie, lui aussi : une restauration se defait donc. L'agent est redemarre ensuite.",
    'restaurer_annuler' => 'Annuler',
    'restaurer_confirmer' => 'Restaurer et redemarrer',
    'restaurer_en_cours' => 'Restauration de :nom...',
    'restaure_et_redemarre' => ':nom restaure et agent redemarre.',
    'restaure_sans_redemarrage' => ":nom restaure, mais l'agent n'a PAS redemarre. Le fichier est en place et le service ne tourne pas.",
    'restaurer_refus' => 'Restauration refusee (statut :statut).',
    'restaurer_echec' => "La restauration n'a pas abouti.",
    'editeur_change_serveur' => "Serveur change : la zone d'edition a ete videe. Ce qui y etait tape n'a pas ete enregistre.",

    // ── Sous-lot V10a : les reglages par machine ──────────────────────────
    'reglages_lien' => 'Reglages',
    'reglages_titre' => 'Reglages par machine',
    'reglages_description' => "Ces reglages ne valent que pour UN serveur et l'emportent sur son profil et sur la configuration globale. Un champ laisse vide signifie « herite » : le serveur prend alors la valeur de son profil, ou celle de la configuration globale.",
    'reglages_aucune_machine' => 'Aucun serveur choisi',
    'reglages_aucune_machine_aide' => "Utilisez le bouton « Reglages » d'une ligne du tableau ci-dessus pour ouvrir ses reglages.",
    'reglages_pour' => 'Reglages du serveur :nom.',
    'reglages_effet_differe' => "Enregistrer ne joint AUCUN serveur : ces valeurs vivent en base et ne partiront sur la machine qu'a la prochaine reconfiguration.",
    'reglages_herite' => 'herite',
    'reglages_fermer' => 'Fermer',
    'reglages_enregistrer' => 'Enregistrer les reglages',
    'reglages_vide_efface' => "Vider un champ SUPPRIME le reglage : le serveur retombe sur son profil ou sur la configuration globale. Un reglage enregistre vide produirait une ligne sans valeur dans le fichier de configuration.",
    'reglages_hors_liste' => "Ce serveur porte aussi des reglages hors de cette liste, poses par un autre moyen : :champs. Ils agissent, et cet ecran ne permet pas de les modifier.",
    'reglages_enregistres' => 'Reglages de :nom enregistres.',
    'reglages_refuses' => 'Reglages refuses car leur valeur est invalide : :champs. Les autres ont ete enregistres.',
    'reglages_machine_inconnue' => 'Serveur inconnu ou archive : rien n\'a ete enregistre.',
    'override_hostname' => 'Nom d\'hote declare',
    'override_hostname_aide' => "Le nom sous lequel l'agent se presente au serveur de supervision.",
    'override_serveur' => 'Serveur de supervision',
    'override_serveur_aide' => "L'adresse a laquelle l'agent accepte les requetes.",
    'override_serveur_actif' => 'Serveur en mode actif',
    'override_serveur_actif_aide' => "L'adresse a laquelle l'agent envoie ses mesures de lui-meme.",
    'override_metadonnees' => 'Metadonnees d\'hote',
    'override_metadonnees_aide' => 'Sert au serveur a ranger ce poste automatiquement.',
    'override_port' => 'Port d\'ecoute',
    'override_port_aide' => 'Entre 1 et 65535. Par defaut 10050.',
    'override_tls_connect' => 'Chiffrement des connexions sortantes',
    'override_tls_connect_aide' => "Comment l'agent chiffre ce qu'il envoie.",
    'override_tls_accept' => 'Chiffrement des connexions entrantes',
    'override_tls_accept_aide' => "Ce que l'agent accepte de recevoir.",
    'override_psk_identite' => 'Identite PSK',
    'override_psk_identite_aide' => "Le nom de la cle partagee. La cle elle-meme reste dans la configuration globale et n'est jamais affichee ici.",

    // ── Sous-lot V10 : la reconfiguration ─────────────────────────────────
    'reconf_bouton' => 'Reconfigurer',
    'reconf_titre' => "Reconfigurer l'agent d'un serveur",
    'reconf_description' => "Re-pousse la configuration calculee par le portail — configuration globale, profil du serveur et reglages par machine — sans reinstaller l'agent. Le geste porte sur UN serveur, celui de la ligne choisie.",
    'reconf_sans_config' => 'Aucune configuration globale enregistree',
    'reconf_sans_config_aide' => "La reconfiguration est refusee tant qu'aucune configuration globale n'existe : il n'y aurait rien a pousser. Renseignez-la dans l'onglet « Configuration globale », puis revenez ici.",
    'reconf_cout' => 'Reconfigurer :nom remplacera les reglages connus dans :chemin sur ce serveur.',
    'reconf_effet_sauvegarde' => "une copie datee du fichier actuel est creee sur le serveur, avant toute ecriture",
    'reconf_effet_fusion' => "les cles connues sont remplacees une a une dans :chemin — les lignes que le portail ne gere pas SURVIVENT, contrairement a l'editeur qui reecrit tout le fichier",
    'reconf_effet_psk' => "la cle partagee est reecrite sur le serveur, dans un fichier a part",
    'reconf_effet_redemarrage' => "l'agent de supervision est redemarre pour prendre la nouvelle configuration",
    'reconf_annuler' => 'Annuler',
    'reconf_confirmer' => 'Reconfigurer et redemarrer',
    'reconf_en_cours' => 'Reconfiguration de :nom en cours...',
    'reconf_reussie' => 'Configuration poussee sur :nom et agent redemarre.',
    'reconf_partielle' => "Configuration poussee sur :nom, mais une commande distante a ECHOUE (code :codes). Le fichier est en place et le service ne tourne peut-etre pas : lisez le journal ci-dessous avant de compter sur la supervision de ce serveur.",
    'reconf_echouee' => 'La reconfiguration de :nom a echoue.',
    'reconf_inachevee' => "La reconfiguration de :nom ne s'est pas terminee : le journal est incomplet.",
    'reconf_avertissements' => ':nombre avertissement(s) dans le journal.',
    'reconf_refus' => 'Reconfiguration refusee (statut :statut).',
    'reconf_echec' => "La reconfiguration n'a pas pu etre lancee.",
];
