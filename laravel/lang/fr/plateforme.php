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
    'non_porte_titre' => "Un seul geste n'est pas porté : la rotation de la clé",
    'non_porte_texte' => "Faire tourner la clé de plateforme — la régénérer — se fait encore depuis l'ancien portail. C'est le geste le plus large du portail : il agit sur tout le parc à la fois, sans viser de machine, et il détruit la clé privée en cours. Tous les autres gestes de cette page sont portés ici.",
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
    // ══ P3 — LES GESTES QUI ECRIVENT ═════════════════════════════════════
    'btn_deployer' => "Déployer",
    'btn_compte_service' => "Reprendre le compte d'administration",
    'btn_effacer' => "Effacer les mots de passe",
    'btn_ressaisir' => "Ressaisir un mot de passe",

    'parc_titre' => "Les mêmes gestes, à l'échelle du parc",
    'parc_aide' => "Chaque bouton annonce le nombre de machines de SA propre liste, et agit sur exactement celles-là. L'ancien portail affichait une soustraction de compteurs calculés autrement : le nombre annoncé et le nombre traité pouvaient différer.",
    'parc_btn_deployer' => "Déployer sur les :n machines sans clé",
    'parc_btn_compte_service' => "Reprendre le compte d'administration sur :n machine(s)",
    'parc_btn_effacer' => "Effacer les mots de passe de :n machine(s)",
    'parc_rien' => "Aucun geste de parc n'a d'objet : toutes les machines ont leur clé et leur compte d'administration, et aucune ne porte plus de mot de passe connu de RootWarden.",

    'refusees_titre' => ":n machine(s) que l'effacement de masse écarte",
    'refusees_texte' => "Ces machines ont une clé et un mot de passe, mais pas de compte d'administration : le backend refuse d'effacer leur mot de passe, parce que RootWarden n'aurait alors plus aucun moyen de passer root. Elles ne sont pas « déjà faites », elles sont bloquées — et c'est le geste du compte d'administration qui les débloque. L'ancien portail les proposait quand même et comptait le refus comme rien.",

    'champ_mdp' => "Mot de passe SSH à réenregistrer",
    'champ_mdp_aide' => "Il est enregistré chiffré, et il n'est jamais réaffiché. Ce geste restaure le mot de passe de l'utilisateur SSH ; il ne restaure PAS le mot de passe root, qui ne se réécrit que depuis la page Serveurs.",
    'annuler' => "Annuler",
    'confirmer' => "Confirmer",

    'recharger' => "Recharger la page pour lire l'état réel",
    'geste_journal' => "Journal des gestes",
    'geste_journal_vide' => "Aucun geste n'a encore été lancé depuis cette page.",
    'geste_en_cours' => "En cours sur :cibles…",
    'geste_echec_reseau' => "La requête n'est pas partie ou n'est pas revenue : :message. Aucune conclusion n'est possible sur ce qui a été écrit — il faut recharger la page pour lire l'état réel.",
    'geste_sans_verdict' => "Le serveur a répondu sans verdict lisible. Ce n'est ni une réussite ni un échec : l'état doit être relu.",
    'geste_ligne_ok' => ":machine : réussi — :message",
    'geste_ligne_echec' => ":machine : échoué — :message",
    'geste_bilan' => ":ok réussite(s) sur :total. Les machines en échec sont nommées ci-dessus, une par ligne.",
    'ressaisie_mdp_vide' => "Aucun mot de passe saisi : rien n'a été envoyé.",
    'confirmer_saisie_manquante' => "Remplis le champ avant de confirmer.",
    'effacement_bilan' => ":ok effacement(s) sur :total.",
    'effacement_interrompu' => "Interrompu après :fait machine(s) sur :total. Ce geste part en autant de requêtes qu'il y a de machines : les suivantes n'ont PAS été envoyées, et le parc est à moitié migré.",

    // Les panneaux de decision, un par geste. Chacun NOMME sa consequence.
    'panneaux' => [
        'deployer' => [
            'titre' => "Déployer la clé de plateforme",
            'texte' => "Ce geste ouvre une session SSH par mot de passe et écrit sur la machine. Il fait deux choses, et l'ancien portail n'en annonçait qu'une.",
            'effets' => [
                "ajoute la clé publique dans authorized_keys de l'utilisateur SSH et de root",
                "crée le compte Unix « rootwarden » et lui accorde NOPASSWD: ALL via /etc/sudoers.d",
                "reprendre cet accès n'a aucun bouton dans le portail : c'est un geste d'exploitation hors portail",
            ],
        ],
        'compte_service' => [
            'titre' => "Reprendre le compte d'administration",
            'texte' => "Ce n'est pas l'étape suivante du déploiement : le déploiement de la clé a DÉJÀ tenté de créer ce compte, dans la même requête, et cette tentative a échoué. Ce geste la reprend.",
            'effets' => [
                "crée le compte Unix « rootwarden » s'il manque",
                "lui accorde NOPASSWD: ALL via /etc/sudoers.d",
                "vérifie ensuite que « sudo whoami » répond root, et n'enregistre la réussite que dans ce cas",
            ],
        ],
        'effacer' => [
            'titre' => "Effacer les mots de passe connus de RootWarden",
            'texte' => "Ce geste NE TOUCHE PAS la machine. Il efface la copie que RootWarden garde des deux mots de passe. Le compte Unix garde le sien, et qui le connaît entre encore.",
            'effets' => [
                "efface le mot de passe SSH ET le mot de passe root de la base RootWarden",
                "après ce geste, le seul accès de RootWarden à cette machine est la clé de plateforme",
                "« Ressaisir » ne rend que le mot de passe SSH : le mot de passe root ne se réécrit que depuis la page Serveurs",
            ],
        ],
        'ressaisir' => [
            'titre' => "Réenregistrer un mot de passe SSH",
            'texte' => "Ce geste écrit en base et ne touche pas la machine. Il ne restaure que la moitié de ce que l'effacement a retiré.",
            'effets' => [
                "réenregistre le mot de passe de l'utilisateur SSH, chiffré",
                "ne réenregistre PAS le mot de passe root — aucune route du backend ne l'écrit",
                "le mot de passe root se ressaisit depuis la page Serveurs de l'ancien portail",
            ],
        ],
    ],
    'panneau_cible_une' => "Machine visée : :nom",
    'panneau_cible_n' => ":n machines visées : :noms",
    'panneau_prod' => "⚠ Cette portée contient de la PRODUCTION : :noms",
];
