<?php

/**
 * Cle de plateforme — sous-lot P1.
 *
 * Aucun texte de cette page ne doit annoncer un acces plus strict que celui
 * qui est applique : l'en-tete du legacy annonce « superadmin uniquement »
 * alors que sa garde admet tout role portant la permission (E-36, cinquieme
 * occurrence). Et aucun ne doit laisser croire que « migration terminee »
 * est un aboutissement neutre : c'est l'etat ou la rotation est sans retour.
 */

return [
    'titre' => "Clé SSH de plateforme",
    'intro' => "Une paire de clés Ed25519, une seule pour tout le parc et pour les deux comptes. RootWarden s'en sert pour s'authentifier sur chaque machine sans mot de passe.",
    'garde_reelle' => "Cette page est ouverte à tout rôle portant la permission « gérer la clé de plateforme » — c'est la garde réellement appliquée. L'ancien portail annonce « superadmin uniquement » : son en-tête est faux.",
    'cle_titre' => "Clé publique",
    'cle_aide' => "C'est la partie publique : elle est faite pour être lue et copiée. C'est elle qui est écrite dans les fichiers authorized_keys des machines.",
    'cle_chargement' => "Lecture de la clé publique…",
    'cle_echec' => "La clé publique n'a pas pu être lue. Ce n'est pas « il n'y a pas de clé » : la lecture a échoué.",
    'cle_absente_titre' => "Aucune paire de clés n'existe encore",
    'cle_absente' => "Le backend n'a pas de clé de plateforme. Elle se crée au premier déploiement.",
    'cle_copier' => "Copier",
    'cle_copiee' => "Copiée.",
    'stat_cle' => "Clé déployée",
    'stat_compte_service' => "Compte d'administration",
    'stat_en_attente' => "En attente",
    'stat_sans_mot_de_passe' => "Sans mot de passe connu",
    'progression_titre' => "Progression de la migration",
    'progression_reste' => "Il reste :nb machine(s) sans la clé.",
    'progression_cle_ok' => "La clé est partout. L'étape suivante de l'ancien portail est d'effacer les mots de passe.",
    'progression_finie' => "Migration terminée au sens de l'ancien portail.",
    'legende_mot_de_passe' => "mot de passe seul",
    'legende_les_deux' => "clé et mot de passe",
    'legende_cle' => "clé seule",
    'avert_titre' => "Ce que « migration terminée » veut dire",
    'avert_texte' => "Effacer les mots de passe ne les retire pas des machines : il retire la COPIE que RootWarden en garde. Une machine dont la clé est déployée et dont plus aucun mot de passe n'est connu n'a plus qu'une voie d'accès — cette clé. La faire tourner détruit la clé privée SANS COPIE : pour ces machines-là, la rotation est sans retour. L'état que l'ancien portail présente comme l'aboutissement de la migration est exactement celui-là.",
    'sans_retour_titre' => "Machines dont la clé est le seul accès",
    'sans_retour_aucune' => "Aucune machine n'est dans ce cas aujourd'hui : chacune garde au moins un mot de passe connu de RootWarden. C'est calculé, pas supposé.",
    'sans_retour_liste' => "Machines concernées — :nb au total : :noms. Une rotation de la clé leur couperait l'accès sans retour.",
    'divergence_titre' => "L'ancien portail compte autrement, et il se trompe",
    'divergence_texte' => "L'ancien portail compte « mot de passe supprimé » sur un drapeau (ssh_password_required), pas sur les colonnes. Or la page Serveurs est le seul chemin qui REMPLIT le mot de passe root, et elle ne touche pas ce drapeau : restaurer un mot de passe là-bas laisse cette ligne annoncée comme effacée. Machines où le drapeau contredit les colonnes — :nb au total : :noms. Cette page compte les colonnes.",
    'th_machine' => "Machine",
    'th_adresse' => "Adresse",
    'th_auth' => "Authentification",
    'th_compte_service' => "Compte d'administration",
    'th_mot_de_passe' => "Mots de passe connus",
    'th_depuis' => "Clé déployée le",
    'th_actions' => "Test",
    'etat_cle_seule' => "clé seule",
    'etat_cle_et_mot_de_passe' => "clé et mot de passe",
    'etat_mot_de_passe_seul' => "mot de passe seul",
    'compte_service_pose' => "rootwarden",
    'compte_service_absent' => "absent",
    'compte_service_aide' => "Ce compte porte « NOPASSWD: ALL » : il peut tout exécuter en root sans mot de passe. Le déploiement de la clé l'accorde en même temps, sans que son libellé le dise.",
    'mdp_les_deux' => "utilisateur et root",
    'mdp_utilisateur' => "utilisateur seul",
    'mdp_root' => "root seul",
    'mdp_aucun' => "aucun",
    'mdp_aide_partiel' => "Effacer les mots de passe efface les DEUX. « Ressaisir » n'en restaure qu'un : le mot de passe root ne se réécrit que depuis la page Serveurs. Le retour offert est donc la moitié du geste.",
    'jamais' => "jamais",
    'sensible' => "Production",
    'vide_titre' => "Aucune machine au parc",
    'vide_texte' => "Aucune machine n'est enregistrée. La clé de plateforme n'a rien à protéger tant que le parc est vide.",
    'non_porte_titre' => "Les gestes de cette page ne sont pas encore portés",
    'non_porte_texte' => "Déployer la clé, déployer le compte d'administration, tester une connexion, relever les comptes, effacer ou ressaisir un mot de passe, et faire tourner la clé se font encore depuis l'ancien portail. Cette page porte l'état, ses compteurs et ses gardes.",
    'non_porte_lien' => "Ouvrir la clé de plateforme dans l'ancien portail",

    // ── Sous-lot P2 : le test de connexion ───────────────────────────────
    // QUATRE situations, et le legacy les replie sur un rouge unique. « Cle non
    // deployee » est un ETAT, pas un echec ; et le backend ne distingue pas
    // « refusee » d'« injoignable » — les deux rendent `auth_method: password`.
    // L'ecran ne pretend donc pas savoir laquelle, il dit les deux.
    'tester' => "Tester la connexion",
    'tester_aide' => "Ouvre une session SSH vers la machine avec la clé, et la referme. Rien n'est écrit, ni sur la machine ni en base.",
    'test_en_cours' => "Connexion en cours vers :machine…",
    'test_ok' => "La clé fonctionne sur :machine.",
    'test_rien_a_tester' => "Rien à tester sur :machine : la clé n'y est pas déployée. Ce n'est pas un échec — c'est l'étape d'avant.",
    'test_echec' => "La clé n'a pas fonctionné sur :machine. Deux causes possibles que le backend ne distingue pas : elle est refusée par la machine, ou la machine est injoignable. Ce que le serveur rapporte : :message",
    'test_indecis' => "Le test n'a pas rendu de verdict sur :machine. Ce n'est ni une réussite ni un échec de la clé : la réponse n'a pas pu être lue.",
    'test_journal' => "Journal des tests",
    'test_journal_vide' => "Aucun test n'a encore été lancé sur cette page.",

    // ── Le guide de procedure, PORTE et CORRIGE ──────────────────────────
    // Le legacy affiche un guide en quatre etapes (`howto_tip.php`, page :50).
    // Mon premier jet de P1 l'avait LAISSE TOMBER — un acquis du legacy perdu
    // sans que rien ne le signale, parce que personne n'ouvre `lang/`. Il est
    // porte ici, et DEUX de ses quatre etapes sont corrigees : elles disaient
    // faux, et l'une des deux dans le sens rassurant.
    'guide_titre' => "Comment la clé de plateforme fonctionne, dans l'ordre",
    'guide_etape1' => "La paire de clés Ed25519 est générée automatiquement et conservée côté serveur. Il en existe UNE pour tout le parc et pour les deux comptes — pas une par machine.",
    'guide_etape2' => "« Déployer la paire » installe la clé publique sur les machines choisies — ET crée le compte d'administration « rootwarden » avec NOPASSWD: ALL. Les deux gestes n'en font qu'un, et le libellé de l'ancien portail ne le dit pas.",
    'guide_etape3' => "Une fois déployée, RootWarden se connecte sans mot de passe. Le bouton « Tester » le vérifie sans rien écrire.",
    'guide_etape4' => "« Effacer les mots de passe » n'agit PAS sur la machine : il efface la copie que RootWarden en garde. Le compte Unix garde son mot de passe, et qui le connaît entre encore. Ce que RootWarden perd, c'est son propre recours si la clé cesse de fonctionner.",
    'guide_corrige' => "Deux de ces quatre étapes corrigent le guide de l'ancien portail, mesure en main. Il annonçait que « Déployer keypair installe la clé publique » sans mentionner le compte NOPASSWD: ALL ; et que « Supprimer le password désactive l'authentification par mot de passe SUR LE SERVEUR (plus sécurisé) », ce qui est faux dans les deux langues — la route ne touche pas la machine.",
];
