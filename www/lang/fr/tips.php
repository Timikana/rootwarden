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
];
