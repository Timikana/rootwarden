<?php

/**
 * Cle de plateforme.
 *
 * Regles de redaction : docs/REDACTION-INTERFACE.md. Ce qui est irreversible
 * reste visible et court ; le detail technique va dans un bloc repliable.
 */

return [
    'titre' => "Clé SSH de plateforme",
    'intro' => "Une seule paire de clés Ed25519 permet à RootWarden de se connecter à toutes les machines sans mot de passe.",
    'cle_titre' => "Clé publique",
    'cle_aide' => "C'est elle qui est écrite dans les fichiers authorized_keys des machines.",
    'cle_chargement' => "Lecture de la clé publique…",
    'cle_echec' => "Impossible de lire la clé publique.",
    'cle_absente_titre' => "Aucune paire de clés n'existe encore",
    'cle_absente' => "Elle sera créée au premier déploiement.",
    'cle_copier' => "Copier",
    'cle_copiee' => "Copiée.",
    'stat_cle' => "Clé déployée",
    'stat_compte_service' => "Compte d'administration",
    'stat_en_attente' => "En attente",
    'stat_sans_mot_de_passe' => "Sans mot de passe connu",
    'progression_titre' => "Progression",
    'progression_reste' => "Il reste :nb machine(s) sans la clé.",
    'progression_cle_ok' => "La clé est déployée partout.",
    'progression_finie' => "La clé est déployée partout et plus aucun mot de passe n'est conservé.",
    'legende_mot_de_passe' => "mot de passe seul",
    'legende_les_deux' => "clé et mot de passe",
    'legende_cle' => "clé seule",
    'legende_aucun_acces' => "ni clé ni mot de passe",
    'avert_titre' => "Avant d'effacer les mots de passe",
    'avert_texte' => "Une machine sans mot de passe connu n'est plus joignable que par cette clé. Pour elle, une rotation de la clé est sans retour.",
    'sans_retour_titre' => "Machines dont la clé est le seul accès",
    'sans_retour_aucune' => "Aucune : chaque machine garde au moins un mot de passe connu.",
    'sans_retour_liste' => ":nb machine(s) : :noms. Une rotation de la clé leur couperait l'accès sans retour.",
    'th_machine' => "Machine",
    'th_adresse' => "Adresse",
    'th_auth' => "Authentification",
    'th_compte_service' => "Compte d'administration",
    'th_mot_de_passe' => "Mots de passe connus",
    'th_depuis' => "Clé déployée le",
    'th_actions' => "Actions",
    'etat_cle_seule' => "clé seule",
    'etat_cle_et_mot_de_passe' => "clé et mot de passe",
    'etat_mot_de_passe_seul' => "mot de passe seul",
    'etat_aucun_acces' => "ni clé ni mot de passe",
    'compte_service_pose' => "rootwarden",
    'compte_service_absent' => "absent",
    'compte_service_aide' => "Le compte « rootwarden » a un accès root sans mot de passe (NOPASSWD: ALL). Le déploiement de la clé le crée.",
    'mdp_les_deux' => "utilisateur et root",
    'mdp_utilisateur' => "utilisateur seul",
    'mdp_root' => "root seul",
    'mdp_aucun' => "aucun",
    'mdp_aide_partiel' => "« Ressaisir » ne rend que le mot de passe SSH. Le mot de passe root se ressaisit depuis la page Serveurs.",
    'jamais' => "jamais",
    'sensible' => "Production",
    'vide_titre' => "Aucune machine au parc",
    'vide_texte' => "Ajoutez une machine depuis la page Serveurs.",
    'details' => "Détails",

    // ── Le test de connexion ─────────────────────────────────────────────
    'tester' => "Tester la connexion",
    'tester_aide' => "« Tester » ouvre puis referme une session SSH avec la clé, sans rien écrire.",
    'test_en_cours' => "Connexion en cours vers :machine…",
    'test_ok' => "La clé fonctionne sur :machine.",
    'test_rien_a_tester' => ":machine : la clé n'y est pas encore déployée.",
    'test_echec' => "La clé n'a pas fonctionné sur :machine (refusée ou machine injoignable) : :message",
    'test_indecis' => ":machine : réponse illisible, aucun verdict.",
    'test_journal' => "Journal des tests",
    'test_journal_vide' => "Aucun test lancé.",

    // ── Le guide, dans l'ordre ───────────────────────────────────────────
    'guide_titre' => "Comment ça marche",
    'guide_etape1' => "Une seule paire de clés sert pour tout le parc. Elle est générée et conservée par RootWarden.",
    'guide_etape2' => "« Déployer » installe la clé publique et crée le compte d'administration « rootwarden » (root sans mot de passe).",
    'guide_etape3' => "« Tester » vérifie que la connexion par clé fonctionne.",
    'guide_etape4' => "« Effacer les mots de passe » supprime la copie gardée par RootWarden. Les mots de passe restent valables sur la machine.",

    // ── Les gestes qui ecrivent ──────────────────────────────────────────
    'btn_deployer' => "Déployer",
    'btn_compte_service' => "Reprendre le compte d'administration",
    'btn_effacer' => "Effacer les mots de passe",
    'btn_ressaisir' => "Ressaisir un mot de passe",

    'parc_titre' => "Sur tout le parc",
    'parc_aide' => "Chaque bouton agit exactement sur le nombre de machines qu'il affiche.",
    'parc_btn_deployer' => "Déployer sur les :n machines sans clé",
    'parc_btn_compte_service' => "Reprendre le compte d'administration sur :n machine(s)",
    'parc_btn_effacer' => "Effacer les mots de passe de :n machine(s)",
    'parc_rien' => "Rien à faire : toutes les machines ont la clé et le compte d'administration, sans mot de passe conservé.",

    'refusees_titre' => ":n machine(s) exclue(s) de l'effacement",
    'refusees_texte' => "Elles n'ont pas de compte d'administration : sans mot de passe, RootWarden ne pourrait plus y passer root. Reprenez d'abord le compte d'administration.",

    'champ_mdp' => "Mot de passe SSH à réenregistrer",
    'champ_mdp_aide' => "Enregistré chiffré, jamais réaffiché. Le mot de passe root se ressaisit depuis la page Serveurs.",
    'annuler' => "Annuler",
    'confirmer' => "Confirmer",

    'recharger' => "Recharger la page",
    'geste_journal' => "Journal des actions",
    'geste_journal_vide' => "Aucune action lancée.",
    'geste_en_cours' => "En cours sur :cibles…",
    'geste_echec_reseau' => "Pas de réponse (:message). L'action peut être encore en cours : ne la relancez pas. Rechargez la page, puis testez la machine.",
    'geste_sans_verdict' => "Réponse illisible : l'action a peut-être eu lieu. Ne la relancez pas. Rechargez la page, puis testez la machine.",
    'geste_ligne_ok' => ":machine : réussi — :message",
    'geste_ligne_echec' => ":machine : échoué — :message",
    'geste_bilan' => ":ok réussite(s) sur :total.",
    'ressaisie_mdp_vide' => "Aucun mot de passe saisi : rien n'a été envoyé.",
    'confirmer_saisie_manquante' => "Remplissez le champ avant de confirmer.",
    'effacement_bilan' => ":ok effacement(s) sur :total.",
    'effacement_interrompu' => "Interrompu après :fait machine(s) sur :total : les suivantes n'ont pas été traitées.",

    // Les panneaux de decision : chacun nomme sa consequence.
    'panneaux' => [
        'deployer' => [
            'titre' => "Déployer la clé de plateforme",
            'bouton' => "Déployer la clé",
            'texte' => "Se connecte par mot de passe et écrit sur la machine.",
            'effets' => [
                "ajoute la clé publique pour l'utilisateur SSH et pour root",
                "crée le compte « rootwarden » avec un accès root sans mot de passe",
            ],
        ],
        'compte_service' => [
            'titre' => "Reprendre le compte d'administration",
            'bouton' => "Recréer le compte",
            'texte' => "Le déploiement n'a pas réussi à créer ce compte : cette action recommence.",
            'effets' => [
                "crée le compte « rootwarden » s'il manque, avec un accès root sans mot de passe",
                "ne valide que si « sudo whoami » répond root",
            ],
        ],
        'effacer' => [
            'titre' => "Effacer les mots de passe connus de RootWarden",
            'bouton' => "Effacer les mots de passe",
            'texte' => "Ne touche pas la machine : supprime la copie gardée par RootWarden.",
            'effets' => [
                "supprime le mot de passe SSH et le mot de passe root conservés",
                "RootWarden n'accède plus à la machine que par la clé",
            ],
        ],
        'rotation' => [
            'titre' => "Faire tourner la clé de plateforme",
            'bouton' => "Faire tourner la clé",
            'texte' => "Remplace la clé de tout le parc en une fois.",
            'effets' => [
                "détruit la clé privée actuelle et en génère une nouvelle",
                "marque la clé comme non déployée sur les :total machines : il faudra redéployer",
                "l'ancienne clé publique reste sur les machines tant qu'elle n'est pas retirée",
                "réversible pendant :jours jours depuis l'archive, si le volume qui la contient n'est pas perdu",
                "exige la validation d'un second administrateur",
            ],
        ],
        'revoquer' => [
            'titre' => "Supprimer le compte d'administration",
            'bouton' => "Supprimer le compte",
            'texte' => "Supprime le compte « rootwarden » de la machine. Seul un nouveau déploiement le recrée.",
            'effets' => [
                "retire ses droits sudo, puis supprime le compte et son répertoire",
                "la clé reste autorisée pour l'utilisateur SSH et pour root",
                "en cas de clé compromise, faites plutôt tourner la clé",
                "exige la validation d'un second administrateur",
            ],
        ],
        'ressaisir' => [
            'titre' => "Réenregistrer un mot de passe SSH",
            'bouton' => "Enregistrer le mot de passe",
            'texte' => "Écrit dans RootWarden, ne touche pas la machine.",
            'effets' => [
                "réenregistre le mot de passe de l'utilisateur SSH, chiffré",
                "le mot de passe root se ressaisit depuis la page Serveurs",
            ],
        ],
    ],
    'panneau_cible_une' => "Machine visée : :nom",
    'panneau_cible_n' => ":n machines visées : :noms",
    'panneau_prod' => "⚠ Production : :noms",

    'btn_revoquer' => "Supprimer le compte d'administration",
    'parc_btn_revoquer' => "Supprimer le compte d'administration sur :n machine(s)",
    'champ_motif' => "Motif",
    'champ_motif_aide' => "Inscrit au journal d'audit (200 caractères maximum).",
    'motif_vide' => "Indiquez un motif : rien n'a été envoyé.",
    'geste_approbation_attente' => "Demande de validation envoyée à un second administrateur (page Approbations). Rien n'a encore été retiré.",
    'geste_approbation_absente' => "Bloqué : cette action exige un second administrateur, et aucun n'est disponible. :message",
    'revoquer_asymetrie' => "Votre rôle peut accorder ce compte d'administration, mais seul un superadmin peut le supprimer.",

    // Les limites de chaque geste, affichees dans son panneau.
    'bornes' => [
        'rotation' => "L'archive de l'ancienne clé est dans le même volume Docker que la clé actuelle, et ce volume n'est pas sauvegardé par RootWarden.",
        'revoquer' => "Si le serveur refuse la connexion du compte « rootwarden » (sshd durci) et que le mot de passe root a été effacé, la suppression échoue. Elle peut être relancée sans risque.",
        'compte_service' => "Échoue si le compte a été supprimé après l'effacement des mots de passe : RootWarden n'a alors plus aucun moyen de passer root. Ressaisissez d'abord le mot de passe root depuis la page Serveurs.",
    ],

    // Ce que le backend, seul a pouvoir dechiffrer, dit des mots de passe.
    'credential_titre' => "Vérification des mots de passe",
    'credential_aide' => "Le tableau compte les mots de passe enregistrés. RootWarden vérifie aussi s'ils sont vides une fois déchiffrés.",
    'credential_borne_root' => "La vérification porte sur le mot de passe SSH et sur le mot de passe root.",
    'credential_divergence' => ":n machine(s) avec un mot de passe SSH enregistré mais vide : :noms.",
    'credential_indetermine' => ":n machine(s) dont le mot de passe SSH n'a pas pu être déchiffré : :noms.",
    'credential_accord' => "Vérification faite : aucun écart.",
    'credential_echec' => "Vérification impossible : les nombres affichés n'ont pas été contrôlés.",
    'badge_mdp_vide_reel' => "vide en réalité",
    'badge_mdp_illisible' => "illisible",

    // ── La rotation ──────────────────────────────────────────────────────
    'rotation_titre' => "Faire tourner la clé",
    'rotation_aide' => "Agit sur tout le parc en une fois. Réservé aux superadmins, avec validation d'un second administrateur.",
    'btn_rotation' => "Faire tourner la clé de plateforme",
    'rotation_remede' => "La rotation ne retire pas l'ancienne clé des machines. Si la clé est compromise, retirez aussi l'ancienne, machine par machine.",
    'rotation_remede_ou' => "Le retrait se fait depuis la page Comptes distants, clé par clé. RootWarden refuse par défaut d'y retirer la clé de plateforme active.",
    'rotation_remede_parc' => "Il n'y a volontairement pas de retrait sur tout le parc : il couperait l'accès de RootWarden à toutes les machines.",
    'rotation_jamais_exercee' => "Cette action n'a jamais été testée en conditions réelles.",
    'rotation_sans_retour' => "⚠ :n machine(s) n'ont plus que cette clé pour accès : :noms. Si le redéploiement échoue, elles deviennent injoignables.",
    'rotation_sans_retour_aucune' => "Aucune machine ne dépend uniquement de cette clé.",
    'rotation_jours_inconnus' => "Durée de l'archive inconnue : considérez cette action comme sans retour.",
    'credential_divergence_root' => ":n machine(s) avec un mot de passe root enregistré mais vide : :noms. À ressaisir depuis la page Serveurs.",
    'credential_indetermine_root' => ":n machine(s) dont le mot de passe root n'a pas pu être déchiffré : :noms.",
    'badge_root_vide_reel' => "root vide en réalité",
    'badge_root_illisible' => "root illisible",

    'geste_sudoers_orphelin' => "⚠ :machine : compte supprimé, mais ses droits sudo sont restés sur la machine. Relancez l'action pour les retirer.",
    'champ_recopie' => "Pour confirmer, recopie le nombre de machines concernées",
    'champ_recopie_aide' => "Le bouton s'active quand le nombre correspond.",
];
