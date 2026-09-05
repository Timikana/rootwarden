<?php

/*
 * LES CONDITIONS D'UTILISATION, PORTEES DEPUIS LE LEGACY LE 2026-09-05.
 *
 * ⚠ La page `/cgu` du portage affichait son TITRE, son fil d'etapes et ses
 * deux boutons — et AUCUN texte de conditions. On demandait d'accepter ce
 * qu'on ne montrait pas. Un consentement a des termes invisibles n'est pas
 * un consentement, et une page d'engagement n'existe que pour etre
 * opposable.
 *
 * Source : `legacy/lang/fr/terms.php`, 36 cles, portees sans
 * reecriture — le texte engage, il ne se paraphrase pas.
 */

return [
    'page_title' => 'Conditions Generales d\'Utilisation',
    'accept' => 'J\'accepte les conditions',
    'last_updated' => 'Derniere mise a jour :',
    's1_title' => '1. Objet',
    's1_p1' => 'Les presentes Conditions Generales d\'Utilisation (CGU) regissent l\'acces et l\'utilisation de la plateforme RootWarden, outil interne de gestion centralisee de l\'infrastructure Linux (cles SSH, mises a jour, pare-feu, services, vulnerabilites).',
    's1_p2' => 'En accedant a la plateforme, vous acceptez d\'etre lie par ces conditions. Si vous n\'acceptez pas, veuillez ne pas utiliser la plateforme.',
    's2_title' => '2. Acces et authentification',
    's2_l1' => 'L\'acces est reserve aux utilisateurs disposant d\'un compte attribue par un administrateur.',
    's2_l2' => 'L\'authentification a deux facteurs (TOTP) est obligatoire. Aucun contournement n\'est autorise.',
    's2_l3' => 'Les identifiants (mot de passe, secret TOTP) sont strictement personnels et ne doivent jamais etre partages.',
    's2_l4' => 'Les mots de passe doivent respecter la politique de securite : minimum 15 caracteres, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractere special.',
    's2_l5' => 'Toute connexion est journalisee (adresse IP, user-agent, horodatage).',
    's3_title' => '3. Responsabilites de l\'utilisateur',
    's3_l1' => 'Vous etes responsable de toutes les actions effectuees via votre compte, y compris les deploiements de cles SSH, les mises a jour systeme et les modifications de pare-feu.',
    's3_l2' => 'Vous vous engagez a utiliser la plateforme uniquement dans le cadre de vos fonctions professionnelles et des autorisations qui vous ont ete attribuees.',
    's3_l3' => 'Toute anomalie ou suspicion de compromission doit etre signalee immediatement a l\'equipe d\'administration.',
    's3_l4' => 'Vous ne devez pas tenter d\'acceder a des serveurs, donnees ou fonctionnalites pour lesquels vous n\'avez pas recu d\'autorisation explicite.',
    's4_title' => '4. Activites interdites',
    's4_l1' => 'Tenter de contourner les mecanismes d\'authentification ou d\'escalader ses privileges.',
    's4_l2' => 'Utiliser la plateforme pour des actions malveillantes, destructrices ou non autorisees sur les serveurs geres.',
    's4_l3' => 'Modifier, supprimer ou exfiltrer des donnees sans autorisation (cles SSH, configurations, credentials).',
    's4_l4' => 'Partager ses identifiants ou son acces avec des tiers, y compris des collegues.',
    's4_l5' => 'Desactiver ou contourner les mecanismes de journalisation et d\'audit.',
    's5_title' => '5. Tracabilite et audit',
    's5_p1' => 'Toutes les actions effectuees sur la plateforme sont enregistrees dans un journal d\'audit : connexions, modifications de permissions, deploiements, scans de securite, etc.',
    's5_p2' => 'Ces journaux sont conserves a des fins de securite, de conformite et de resolution d\'incidents. Ils peuvent etre consultes par les administrateurs autorises.',
    's6_title' => '6. Limites de responsabilite',
    's6_l1' => 'La plateforme est fournie "en l\'etat". L\'equipe d\'administration s\'efforce d\'assurer sa disponibilite mais ne garantit pas un fonctionnement ininterrompu.',
    's6_l2' => 'L\'equipe d\'administration ne saurait etre tenue responsable des dommages resultant d\'une mauvaise utilisation de la plateforme ou du non-respect des presentes CGU.',
    's6_l3' => 'Les operations effectuees sur les serveurs distants (mises a jour, modifications iptables, redemarrage de services) sont sous la responsabilite de l\'utilisateur qui les initie.',
    's7_title' => '7. Modifications',
    's7_p1' => 'Ces conditions peuvent etre mises a jour a tout moment. Les utilisateurs seront informes des modifications significatives. L\'utilisation continue de la plateforme vaut acceptation des nouvelles conditions.',
    's8_title' => '8. Contact',
    's8_p1' => 'Pour toute question relative a ces conditions ou pour signaler un incident de securite, contactez l\'equipe d\'administration :',
    'support_title' => 'Soutenir le projet',
    'support_desc' => 'RootWarden est un projet open-source independant. Si vous l\'utilisez et qu\'il vous fait gagner du temps, vous pouvez soutenir son developpement.',
];
