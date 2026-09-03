<?php
// lang/fr/policies.php - Cles pour la gestion des politiques sudo + SFTP par utilisateur
return [
    'nav.policies' => 'Politiques sudo/SFTP',
    'nav.tip_policies' => 'Configurer sudo et SFTP par utilisateur distant (superadmin)',

    'policies.title' => 'Politiques sudo / SFTP par utilisateur',
    'policies.subtitle' => 'Gestion fine des droits sudo et acces SFTP/SSH des comptes Linux sur chaque serveur (superadmin uniquement).',
    'policies.superadmin_badge' => 'Superadmin only',
    'policies.server_label' => 'Serveur',
    'policies.user_label' => 'Utilisateur distant',
    'policies.no_users' => '(aucun utilisateur connu - scanner depuis Utilisateurs distants)',

    'policies.tab_sudo' => 'Sudo',
    'policies.tab_sftp' => 'SFTP / SSH',
    'policies.tab_history' => 'Historique',

    'policies.sudo_title' => 'Politique sudo',
    'policies.sudo_preset' => 'Preset',
    'policies.preset_all_nopasswd' => 'Acces root complet (NOPASSWD: ALL) - comptes de service uniquement',
    'policies.preset_restart_services' => 'Redemarrer/recharger des services systemd (tous)',
    'policies.preset_apt_only' => 'Mises a jour APT (update, upgrade, install)',
    'policies.preset_read_logs' => 'Lecture seule des logs (tail, less, journalctl)',
    'policies.preset_systemctl_specific' => 'Services systemctl specifiques (liste blanche)',
    'policies.preset_custom' => 'Custom (lignes sudoers brutes)',
    'policies.preset_hint_all_nopasswd' => 'DANGEREUX : equivaut a root sans password. A reserver aux comptes de service automatises.',
    'policies.preset_hint_restart_services' => 'Autorise systemctl restart/reload/status sur N\'IMPORTE QUEL service. Pour restreindre, utiliser le preset systemctl specifiques.',
    'policies.preset_hint_apt_only' => 'Pour operateurs DEJA DE CONFIANCE : ce prereglage EQUIVAUT A ROOT. Un paquet construit permet d\'obtenir un shell root.',
    'policies.preset_hint_read_logs' => 'Utilisateurs ops qui consultent /var/log/* sans pouvoir modifier le systeme.',
    'policies.preset_hint_systemctl_specific' => 'Liste blanche de services autorises. Saisir les noms separes par virgule ou espace.',
    'policies.preset_hint_custom' => 'Lignes sudoers brutes - sera validee par visudo -cf cote serveur. ATTENTION : potentiel de prise de pouvoir.',

    'policies.custom_rules' => 'Regles sudoers (custom)',
    'policies.custom_warning' => 'Sera validee par visudo -cf avant ecriture. Echec = aucune modification.',
    'policies.services_list' => 'Liste des services autorises',
    'policies.services_hint' => 'Separes par virgule ou espace. Caracteres autorises : a-z A-Z 0-9 @ . _ -',
    'policies.nopasswd' => 'NOPASSWD (sans mot de passe)',
    'policies.runas' => 'Executer en tant que :',

    'policies.sftp_title' => 'Politique SFTP / SSH',
    'policies.sftp_only' => 'SFTP uniquement (ForceCommand internal-sftp)',
    'policies.sftp_only_hint' => 'Empeche tout shell interactif - utile pour les comptes de transfert de fichiers.',
    'policies.chroot_dir' => 'ChrootDirectory',
    'policies.chroot_warning' => 'Le dossier doit exister, etre owned par root et avoir le mode 0755 - cf documentation OpenSSH.',
    'policies.working_dir' => 'Dossier de travail (working directory)',
    'policies.working_dir_hint' => 'Pour SFTP : sera utilise via ForceCommand internal-sftp -d. Pour shell : informatif seulement.',
    'policies.allow_password' => 'PasswordAuthentication',
    'policies.allow_tcp_fwd' => 'AllowTcpForwarding',
    'policies.allow_agent_fwd' => 'AllowAgentForwarding',
    'policies.allow_x11' => 'X11Forwarding',

    'policies.btn_deploy' => 'Deployer',
    'policies.btn_audit' => 'Auditer (lire serveur)',
    'policies.btn_remove' => 'Supprimer',
    'policies.btn_rollback' => 'Restaurer cette version',
    'policies.last_deployed' => 'Dernier deploy',
    'policies.status_enabled' => 'actif',
    'policies.status_disabled' => 'desactive',

    'policies.history_title' => 'Historique des deploiements',
    'policies.history_filter' => 'Filtrer par type',
    'policies.history_all' => '(tous)',
    'policies.history_empty' => 'Aucun deploiement pour cet utilisateur sur ce serveur.',
    'policies.rollback_reason' => 'Raison du rollback (audit)',

    'policies.confirm_remove' => 'Supprimer le fichier de politique sur le serveur ? Cela peut couper l\'acces (sudo) ou les overrides ssh.',
    'policies.confirm_rollback' => 'Restaurer le contenu de cette version ? Le contenu actuel sera ecrase.',
    'policies.deploy_success' => 'Deploiement reussi.',
    'policies.deploy_fail' => 'Echec du deploiement',
    'policies.net_error' => 'Erreur reseau',
    'policies.audit_found' => 'Fichier de politique trouve sur le serveur.',
    'policies.audit_not_found' => 'Aucun fichier de politique sur le serveur.',
    'policies.remove_success' => 'Politique supprimee du serveur.',

    // ───────────────────────────────────────────────────────────────────
    // Pages separees Sudo / SFTP (v1.36.0) + explications en clair
    // ───────────────────────────────────────────────────────────────────
    'nav.sudo_policies' => 'Droits sudo',
    'nav.tip_sudo_policies' => 'Donner des droits admin precis a un utilisateur sur un serveur (superadmin)',
    'nav.sftp_policies' => 'Acces SFTP/SSH',
    'nav.tip_sftp_policies' => 'Limiter comment un utilisateur se connecte a un serveur (superadmin)',

    'sudopol.title' => 'Droits sudo par utilisateur',
    'sudopol.intro_title' => 'A quoi sert cette page ?',
    'sudopol.intro' => 'Le « sudo » permet a un utilisateur normal d\'executer certaines commandes en tant qu\'administrateur (root). Ici tu choisis, pour UN utilisateur sur UN serveur, CE QU\'IL a le droit de faire en admin — sans lui donner tous les pouvoirs. Choisis un modele pret a l\'emploi, puis clique « Deployer ».',
    'sudopol.choose' => '1. Choisis ce que l\'utilisateur peut faire',

    'sftppol.title' => 'Acces SFTP / SSH par utilisateur',
    'sftppol.intro_title' => 'A quoi sert cette page ?',
    'sftppol.intro' => 'Ici tu controles COMMENT un utilisateur se connecte a UN serveur : le limiter au simple transfert de fichiers, l\'enfermer dans un seul dossier, l\'obliger a utiliser une cle plutot qu\'un mot de passe, etc. Coche les options voulues, puis clique « Deployer ».',
    'sftppol.options' => '1. Choisis les restrictions de connexion',

    // Explications detaillees des presets sudo (phrase concrete + consequence)
    'policies.preset_help_all_nopasswd' => 'L\'utilisateur devient administrateur TOTAL (root) et peut TOUT faire, sans meme taper de mot de passe. A reserver aux comptes automatiques (robots), jamais a une personne.',
    'policies.preset_help_restart_services' => 'L\'utilisateur peut demarrer / arreter / redemarrer n\'importe quel service (ex : le serveur web, la base de donnees). Il ne peut rien faire d\'autre en admin.',
    'policies.preset_help_apt_only' => 'L\'utilisateur peut installer et mettre a jour des logiciels (commande « apt »). ATTENTION : cela EQUIVAUT A ROOT — « apt install » execute des scripts de mainteneur en root, donc un paquet construit donne un shell root. Il n\'existe pas de moyen sur de limiter a apt sans donner root.',
    'policies.preset_help_read_logs' => 'L\'utilisateur peut seulement LIRE les journaux du serveur (dossier /var/log). Il ne peut RIEN modifier. Ideal pour du support / supervision.',
    'policies.preset_help_systemctl_specific' => 'Comme « redemarrer des services », mais uniquement pour la liste de services que TU choisis (ex : seulement « nginx »). Plus precis et plus sur.',
    'policies.preset_help_custom' => 'Pour experts : tu ecris toi-meme les regles. Le serveur les verifie (visudo) avant de les appliquer ; si elles sont invalides, rien n\'est change.',

    // SFTP : libelles humains + explications
    'sftppol.f_sftp_only' => 'Transfert de fichiers uniquement (pas de terminal)',
    'sftppol.h_sftp_only' => 'Si coche : l\'utilisateur peut SEULEMENT envoyer et telecharger des fichiers (SFTP). Il ne peut PAS ouvrir un terminal pour taper des commandes. Parfait pour un compte qui ne sert qu\'a deposer/recuperer des fichiers.',
    'sftppol.f_chroot' => 'Enfermer dans un dossier (« cage » chroot)',
    'sftppol.h_chroot' => 'Une « cage » : l\'utilisateur ne voit QUE ce dossier (et ce qu\'il contient), comme s\'il etait seul sur le serveur. Impossible pour lui d\'aller voir ailleurs (les fichiers systeme, les dossiers des autres...). Exemple : /srv/sftp/jean. Laisser vide = pas de cage. Note technique : le dossier doit deja exister, appartenir a root et avoir les droits 0755, sinon SSH refuse (regle de securite).',
    'sftppol.f_working' => 'Dossier d\'arrivee',
    'sftppol.h_working' => 'Le dossier dans lequel l\'utilisateur arrive directement quand il se connecte (ex : /upload). Confort, pas une securite.',
    'sftppol.f_password' => 'Autoriser la connexion par mot de passe',
    'sftppol.h_password' => 'Coche : l\'utilisateur peut se connecter avec un mot de passe. Decoche : il DOIT utiliser une cle SSH (nettement plus sur, recommande).',
    'sftppol.f_tcp' => 'Autoriser les tunnels reseau (port forwarding)',
    'sftppol.h_tcp' => 'Permet a l\'utilisateur de faire passer d\'autres connexions reseau a travers SSH (ex : atteindre une base de donnees interne). Si ce n\'est pas necessaire, decoche : c\'est plus sur.',
    'sftppol.f_agent' => 'Autoriser le rebond de cle (agent forwarding)',
    'sftppol.h_agent' => 'Permet a l\'utilisateur de reutiliser sa cle SSH pour rebondir vers un autre serveur depuis celui-ci. Si ce n\'est pas necessaire, decoche.',
    'sftppol.f_x11' => 'Autoriser les applications graphiques (X11)',
    'sftppol.h_x11' => 'Permet d\'afficher une fenetre d\'application graphique du serveur sur le poste de l\'utilisateur. Tres rarement utile : laisse decoche.',

    // Aide commune (boutons)
    'policies.help_deploy' => 'Applique la configuration sur le serveur (apres verification automatique).',
    'policies.help_audit' => 'Lit le fichier reellement present sur le serveur, pour verifier l\'etat actuel.',
    'policies.help_remove' => 'Supprime cette configuration du serveur (retour au comportement par defaut).',
    'policies.history_toggle' => 'Historique & restauration',
];
