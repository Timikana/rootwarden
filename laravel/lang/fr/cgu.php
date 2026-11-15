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
    'page_title' => "Conditions Générales d'Utilisation",
    'accept' => 'J\'accepte les conditions',
    'last_updated' => "Dernière mise à jour :",
    's1_title' => '1. Objet',
    's1_p1' => "Les présentes Conditions Générales d'Utilisation (CGU) régissent l'accès et l'utilisation de la plateforme :nom, outil interne de gestion centralisée de l'infrastructure Linux (clés SSH, mises à jour, pare-feu, services, vulnérabilités).",
    's1_p2' => "En accédant à la plateforme, vous acceptez d'être lié par ces conditions. Si vous n'acceptez pas, veuillez ne pas utiliser la plateforme.",
    's2_title' => "2. Accès et authentification",
    's2_l1' => "L'accès est réservé aux utilisateurs disposant d'un compte attribué par un administrateur.",
    's2_l2' => "L'authentification à deux facteurs (TOTP) est obligatoire. Aucun contournement n'est autorisé.",
    's2_l3' => "Les identifiants (mot de passe, secret TOTP) sont strictement personnels et ne doivent jamais être partagés.",
    's2_l4' => "Les mots de passe doivent respecter la politique de sécurité : minimum 15 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial.",
    's2_l5' => "Toute connexion est journalisée (adresse IP, user-agent, horodatage).",
    's3_title' => "3. Responsabilités de l'utilisateur",
    's3_l1' => "Vous êtes responsable de toutes les actions effectuées via votre compte, y compris les déploiements de clés SSH, les mises à jour système et les modifications de pare-feu.",
    's3_l2' => "Vous vous engagez à utiliser la plateforme uniquement dans le cadre de vos fonctions professionnelles et des autorisations qui vous ont été attribuées.",
    's3_l3' => "Toute anomalie ou suspicion de compromission doit être signalée immédiatement à l'équipe d'administration.",
    's3_l4' => "Vous ne devez pas tenter d'accéder à des serveurs, données ou fonctionnalités pour lesquels vous n'avez pas reçu d'autorisation explicite.",
    's4_title' => "4. Activités interdites",
    's4_l1' => "Tenter de contourner les mécanismes d'authentification ou d'escalader ses privilèges.",
    's4_l2' => "Utiliser la plateforme pour des actions malveillantes, destructrices ou non autorisées sur les serveurs gérés.",
    's4_l3' => "Modifier, supprimer ou exfiltrer des données sans autorisation (clés SSH, configurations, credentials).",
    's4_l4' => "Partager ses identifiants ou son accès avec des tiers, y compris des collègues.",
    's4_l5' => "Désactiver ou contourner les mécanismes de journalisation et d'audit.",
    's5_title' => "5. Traçabilité et audit",
    's5_p1' => "Toutes les actions effectuées sur la plateforme sont enregistrées dans un journal d'audit : connexions, modifications de permissions, déploiements, scans de sécurité, etc.",
    's5_p2' => "Ces journaux sont conservés à des fins de sécurité, de conformité et de résolution d'incidents. Ils peuvent être consultés par les administrateurs autorisés.",
    's6_title' => "6. Limites de responsabilité",
    's6_l1' => "La plateforme est fournie \"en l'état\". L'équipe d'administration s'efforce d'assurer sa disponibilité mais ne garantit pas un fonctionnement ininterrompu.",
    's6_l2' => "L'équipe d'administration ne saurait être tenue responsable des dommages résultant d'une mauvaise utilisation de la plateforme ou du non-respect des présentes CGU.",
    's6_l3' => "Les opérations effectuées sur les serveurs distants (mises à jour, modifications iptables, redémarrage de services) sont sous la responsabilité de l'utilisateur qui les initie.",
    's7_title' => '7. Modifications',
    's7_p1' => "Ces conditions peuvent être mises à jour à tout moment. Les utilisateurs seront informés des modifications significatives. L'utilisation continue de la plateforme vaut acceptation des nouvelles conditions.",
    's8_title' => '8. Contact',
    's8_p1' => "Pour toute question relative à ces conditions ou pour signaler un incident de sécurité, contactez l'équipe d'administration :",
    'support_title' => 'Soutenir le projet',
    'support_desc' => ":nom est un projet open-source indépendant. Si vous l'utilisez et qu'il vous fait gagner du temps, vous pouvez soutenir son développement.",
];
