<?php
return [
    'tip.default_title' => 'Comment ca marche ?',

    // Page Cles SSH (deploy)
    'tip.ssh_title' => 'Comment deployer les cles SSH ?',
    'tip.ssh_step1' => '<strong>Prerequis :</strong> ajoutez votre cle SSH publique dans <a href="/profile.php" class="text-blue-600 underline">votre profil</a>.',
    'tip.ssh_step2' => '<strong>Scannez</strong> les utilisateurs du serveur dans <a href="/adm/server_users.php" class="text-blue-600 underline">Utilisateurs distants</a> et classifiez chaque compte.',
    'tip.ssh_step3' => '<strong>Cochez</strong> les serveurs cibles dans la liste ci-dessous.',
    'tip.ssh_step4' => '<strong>Cliquez</strong> sur "Deployer les cles" — le preflight verifie la connexion et affiche l\'inventaire des comptes.',
    'tip.ssh_step5' => 'Le deploiement ne <strong>supprime jamais</strong> de compte. Il deploie uniquement les cles SSH des utilisateurs autorises.',

    // Page Utilisateurs distants
    'tip.users_title' => 'Workflow de classification des comptes',
    'tip.users_step1' => '<strong>Scannez</strong> un serveur pour decouvrir tous les comptes Linux existants.',
    'tip.users_step2' => '<strong>Classifiez</strong> chaque compte : <span class="text-green-600 font-medium">Gere</span> (RootWarden deploie les cles), <span class="text-blue-600 font-medium">Exclu</span> (jamais touche), ou <span class="text-gray-500 font-medium">Non gere</span> (ignore).',
    'tip.users_step3' => 'Tant que des comptes sont en <span class="text-orange-600 font-medium">attente de classification</span>, le deploiement SSH est bloque.',
    'tip.users_step4' => 'La suppression d\'un compte se fait <strong>uniquement</strong> via le bouton "Supprimer" (action explicite, jamais automatique).',

    // Page Admin
    'tip.admin_title' => 'Premier demarrage — les etapes',
    'tip.admin_step1' => '<strong>Ajoutez</strong> vos serveurs dans l\'onglet "Serveurs" (IP, port, identifiants SSH).',
    'tip.admin_step2' => '<strong>Creez</strong> les utilisateurs dans l\'onglet "Utilisateurs" et attribuez leurs cles SSH.',
    'tip.admin_step3' => '<strong>Assignez</strong> les serveurs a chaque utilisateur dans "Acces & Permissions".',
    'tip.admin_step4' => '<strong>Configurez</strong> les notifications email dans "Acces & Permissions > Notifications".',
    'tip.admin_step5' => 'Allez dans <a href="/adm/server_users.php" class="text-blue-600 underline">Utilisateurs distants</a> pour scanner et classifier les comptes existants.',

    // Page Scan CVE
    'tip.cve_title' => 'Comment fonctionne le scan CVE ?',
    'tip.cve_step1' => 'Le scan se connecte en SSH a chaque serveur et liste les paquets installes (<code class="text-xs bg-gray-200 dark:bg-gray-700 px-1 rounded">dpkg -l</code>).',
    'tip.cve_step2' => 'Les paquets sont compares a la base <strong>OpenCVE</strong> pour detecter les vulnerabilites connues.',
    'tip.cve_step3' => 'Filtrez par severite CVSS (seuil configurable) et exportez en CSV.',
    'tip.cve_step4' => 'Planifiez des scans automatiques dans la section "Scans planifies".',

    // Guide demarrage (documentation.php)
    'guide.title' => 'Prise en main',
    'guide.intro' => 'Suivez ces etapes pour configurer RootWarden apres l\'installation.',
    'guide.step1_title' => '1. Connexion et securisation du compte',
    'guide.step1_text' => 'Connectez-vous avec les identifiants generes au premier demarrage (affiches dans les logs Docker). Changez votre mot de passe et configurez le 2FA obligatoire.',
    'guide.step2_title' => '2. Ajouter vos serveurs',
    'guide.step2_text' => 'Dans <strong>Admin > Serveurs</strong>, ajoutez chaque serveur Linux avec son IP, port SSH, utilisateur et mot de passe. Les identifiants sont chiffres en AES-256 en base de donnees.',
    'guide.step3_title' => '3. Scanner les utilisateurs distants',
    'guide.step3_text' => 'Dans <strong>Utilisateurs distants</strong>, scannez chaque serveur pour decouvrir les comptes existants. Classifiez chaque compte (gere / exclu / non gere). Cette etape est <strong>obligatoire</strong> avant tout deploiement.',
    'guide.step4_title' => '4. Configurer votre cle SSH',
    'guide.step4_text' => 'Dans <strong>Mon Profil</strong>, collez votre cle publique SSH (ed25519 ou RSA). Elle sera deployee sur les serveurs qui vous sont assignes.',
    'guide.step5_title' => '5. Assigner les acces',
    'guide.step5_text' => 'Dans <strong>Admin > Acces & Permissions</strong>, attribuez les serveurs a chaque utilisateur et configurez les droits fonctionnels (deploiement, mises a jour, iptables, etc.).',
    'guide.step6_title' => '6. Deployer les cles SSH',
    'guide.step6_text' => 'Dans <strong>Cles SSH</strong>, cochez les serveurs et cliquez "Deployer". Le preflight verifie la connexion et affiche l\'inventaire des comptes. Aucun compte n\'est supprime automatiquement.',
    'guide.step7_title' => '7. Configurer les notifications',
    'guide.step7_text' => 'Dans <strong>Admin > Acces & Permissions > Notifications email</strong>, configurez qui recoit les alertes pour chaque type d\'evenement (scan CVE, audit SSH, etc.).',
    'guide.security_title' => 'Principes de securite',
    'guide.sec_1' => 'Aucun mot de passe n\'est stocke en clair — chiffrement AES-256 + libsodium.',
    'guide.sec_2' => 'Le deploiement ne supprime <strong>jamais</strong> de compte automatiquement.',
    'guide.sec_3' => 'Chaque action est tracee dans le journal d\'audit.',
    'guide.sec_4' => 'L\'authentification 2FA (TOTP) est obligatoire pour tous les comptes.',
    'guide.sec_5' => 'Les comptes serveur doivent etre classifies avant tout deploiement.',

    // Page Mises a jour
    'tip.updates_title' => 'Comment fonctionnent les mises a jour ?',
    'tip.updates_step1' => '<strong>Selectionnez</strong> les serveurs a mettre a jour en cochant les cases.',
    'tip.updates_step2' => '<strong>MaJ APT</strong> lance un <code class="text-xs bg-gray-200 dark:bg-gray-700 px-1 rounded">apt update && apt upgrade</code> complet.',
    'tip.updates_step3' => '<strong>MaJ Secu</strong> installe uniquement les correctifs de securite (<code class="text-xs bg-gray-200 dark:bg-gray-700 px-1 rounded">unattended-upgrades</code>).',
    'tip.updates_step4' => '<strong>Planifier</strong> permet de programmer des mises a jour automatiques via cron.',

    // Page Iptables
    'tip.iptables_title' => 'Comment gerer les regles iptables ?',
    'tip.iptables_step1' => '<strong>Selectionnez</strong> un serveur dans la liste deroulante.',
    'tip.iptables_step2' => '<strong>Charger</strong> recupere les regles IPv4/IPv6 actuelles du serveur.',
    'tip.iptables_step3' => 'Modifiez les regles dans l\'editeur, puis <strong>Valider</strong> verifie la syntaxe sans appliquer.',
    'tip.iptables_step4' => '<strong>Appliquer</strong> envoie les regles sur le serveur. <strong>Sauvegarder</strong> les persiste en BDD pour restauration.',

    // Page Fail2ban
    'tip.fail2ban_title' => 'Comment gerer Fail2ban ?',
    'tip.fail2ban_step1' => '<strong>Selectionnez</strong> un serveur et cliquez "Charger le statut".',
    'tip.fail2ban_step2' => 'Visualisez les <strong>jails actives</strong>, les IPs bannies et l\'historique des bans.',
    'tip.fail2ban_step3' => 'Debannissez une IP ou ajoutez-la en whitelist directement depuis l\'interface.',

    // Page Services
    'tip.services_title' => 'Comment gerer les services systemd ?',
    'tip.services_step1' => '<strong>Selectionnez</strong> un serveur et cliquez "Charger les services".',
    'tip.services_step2' => 'Visualisez l\'etat de chaque service (actif, inactif, en echec).',
    'tip.services_step3' => '<strong>Demarrez</strong>, <strong>arretez</strong> ou <strong>redemarrez</strong> un service en un clic.',

    // Page Audit SSH
    'tip.audit_title' => 'Comment fonctionne l\'audit SSH ?',
    'tip.audit_step1' => 'Le scan analyse la configuration <code class="text-xs bg-gray-200 dark:bg-gray-700 px-1 rounded">sshd_config</code> de chaque serveur.',
    'tip.audit_step2' => 'Chaque parametre est evalue et un <strong>score de securite</strong> (A a F) est attribue.',
    'tip.audit_step3' => 'Les <strong>politiques d\'audit</strong> permettent de personnaliser les seuils par parametre.',
    'tip.audit_step4' => '<strong>Scanner tous</strong> lance l\'audit sur l\'ensemble du parc en une fois.',

    // Page Supervision
    'tip.supervision_title' => 'Comment deployer les agents de monitoring ?',
    'tip.supervision_step1' => '<strong>Choisissez</strong> la plateforme (Zabbix, Centreon, Prometheus, Telegraf) en haut a droite.',
    'tip.supervision_step2' => 'Configurez le <strong>template global</strong> (serveur, port, TLS) dans l\'onglet Configuration.',
    'tip.supervision_step3' => 'Dans l\'onglet <strong>Deploiement</strong>, selectionnez les serveurs et deployez l\'agent.',
    'tip.supervision_step4' => 'L\'<strong>editeur de configuration</strong> permet de modifier le fichier de config a distance.',

    // Page Cle SSH plateforme
    'tip.platform_title' => 'Comment fonctionne la cle plateforme ?',
    'tip.platform_step1' => 'La <strong>keypair Ed25519</strong> est generee automatiquement et stockee de facon persistante.',
    'tip.platform_step2' => '<strong>Deployer keypair</strong> installe la cle publique sur les serveurs selectionnes.',
    'tip.platform_step3' => 'Une fois deployee, RootWarden se connecte <strong>sans mot de passe</strong> (authentification par cle).',
    'tip.platform_step4' => '<strong>Supprimer le password</strong> desactive l\'authentification par mot de passe sur le serveur (plus securise).',

    // Page Conformite
    'tip.compliance_title' => 'A quoi sert le rapport de conformite ?',
    'tip.compliance_step1' => 'Le rapport agrege les donnees de securite de tout votre parc : CVE, SSH, 2FA, cles.',
    'tip.compliance_step2' => '<strong>Export PDF</strong> genere un document A4 paysage avec hash SHA-256 (preuve d\'integrite).',
    'tip.compliance_step3' => '<strong>Export CSV</strong> permet l\'import dans des outils tiers (SIEM, tableur).',

    // Page Notifications
    'tip.notif_title' => 'Comment fonctionnent les notifications ?',
    'tip.notif_step1' => 'Les notifications in-app apparaissent via l\'icone cloche dans la barre de navigation.',
    'tip.notif_step2' => 'Filtrez par type (CVE, audit, securite) ou par statut (lue / non lue).',
    'tip.notif_step3' => 'Les preferences email se configurent dans <a href="/adm/admin_page.php" class="text-blue-600 underline">Admin > Acces & Permissions</a>.',

    // Page Profil
    'tip.profile_title' => 'Comment configurer votre profil ?',
    'tip.profile_step1' => 'Ajoutez votre <strong>email</strong> pour recevoir les notifications (scan CVE, alertes securite).',
    'tip.profile_step2' => 'Collez votre <strong>cle SSH publique</strong> (ed25519 ou RSA) — elle sera deployee sur vos serveurs assignes.',
    'tip.profile_step3' => 'Changez votre <strong>mot de passe</strong> regulierement (politique d\'expiration configurable par l\'admin).',
];
