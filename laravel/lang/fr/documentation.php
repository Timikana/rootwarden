<?php

/*
 * Documentation du portail.
 *
 * ══ CE QUI EST PORTE, ET CE QUI NE L'EST PAS ═════════════════════════════
 *
 * Les 22 cles `guide.*` sont la SEULE partie traduite des 1 756 lignes de
 * `legacy/documentation.php` — le reste est de la prose ecrite a la main, en
 * francais seulement. Elles sont donc portees ici ; la prose ne l'est pas.
 *
 * ══ LE MARQUAGE EST RETIRE ════════════════════════════════════════════════
 *
 * Le legacy place des `<strong>` DANS ses chaines de catalogue. Les rendre
 * demanderait `{!! !!}` — on n'ouvre pas une porte a du HTML venu d'un
 * catalogue pour de l'emphase. Les mots sont conserves, les balises non.
 * L'emphase designait des chemins de menu ; ils restent lisibles en clair.
 */
return [
    'title' => 'Prise en main',
    'intro' => 'Suivez ces étapes pour configurer RootWarden après l\'installation.',
    'step1_title' => 'Connexion et sécurisation du compte',
    'step1_text' => 'Connectez-vous avec les identifiants générés au premier démarrage (affichés dans les journaux Docker). Changez votre mot de passe et configurez le second facteur, qui est obligatoire.',
    'step2_title' => 'Ajouter vos serveurs',
    'step2_text' => 'Dans Admin > Serveurs, ajoutez chaque serveur Linux avec son adresse, son port SSH, son utilisateur et son mot de passe. Les identifiants sont chiffrés en AES-256 en base de données.',
    'step3_title' => 'Relever les comptes distants',
    'step3_text' => 'Dans Utilisateurs distants, relevez chaque serveur pour découvrir les comptes existants, puis classez-les (géré, exclu, non géré). Cette étape est obligatoire avant tout déploiement.',
    'step4_title' => 'Configurer votre clé SSH',
    'step4_text' => 'Dans Mon profil, collez votre clé publique SSH (ed25519 ou RSA). Elle sera déployée sur les serveurs qui vous sont attribués.',
    'step5_title' => 'Attribuer les accès',
    'step5_text' => 'Dans Admin > Accès et permissions, attribuez les serveurs à chaque compte et réglez les droits fonctionnels (déploiement, mises à jour, pare-feu, etc.).',
    'step6_title' => 'Déployer les clés SSH',
    'step6_text' => 'Dans Clés SSH, cochez les serveurs et lancez le déploiement. La vérification préalable contrôle la connexion et affiche l\'inventaire des comptes. Aucun compte n\'est supprimé automatiquement.',
    'step7_title' => 'Configurer les notifications',
    'step7_text' => 'Dans Admin > Accès et permissions > Notifications, réglez qui reçoit les alertes pour chaque type d\'événement (scan CVE, audit SSH, etc.).',
    'security_title' => 'Principes de sécurité',
    'sec_1' => 'Aucun mot de passe n\'est stocké en clair — chiffrement AES-256 et libsodium.',
    'sec_2' => 'Le déploiement ne supprime jamais de compte automatiquement.',
    'sec_3' => 'Chaque action est tracée dans le journal d\'audit.',
    'sec_4' => 'Le second facteur (TOTP) est obligatoire pour tous les comptes.',
    'sec_5' => 'Les comptes serveur doivent être classés avant tout déploiement.',

    // ── LA PAGE ELLE-MEME ────────────────────────────────────────────────
    'titre' => 'Documentation',
    'desc'  => "Prise en main du portail, et où trouver le reste.",

    /*
     * ⚠ LA GARDE DE CETTE PAGE EST UN SEUIL DE ROLE, PAS UNE PERMISSION.
     *
     * `legacy/documentation.php:11` pose `checkAuth([1,2,3])` et **aucun**
     * `checkPermission` — la seule occurrence du fichier (`:295`) est dans un
     * EXEMPLE DE CODE. Le seul cloisonnement est `$isAdmin = $role >= 2`
     * (`:16`), qui enclot six blocs et cinq sections.
     *
     * L'entree de menu porte `'garde' => 'tous'` : vrai de la PAGE, faux de
     * son CONTENU. Un lecteur qui cherche une permission n'en trouvera pas et
     * conclura que tout est ouvert. Le dire est le seul moyen que la garde se
     * lise la ou elle est.
     */
    'seuil_titre' => 'Ce que votre rôle vous ouvre',
    'seuil_role1' => "Votre rôle donne accès à la documentation fonctionnelle. Cinq sections décrivant l'infrastructure et la surface d'API sont réservées à l'administration — c'est une décision, pas un oubli.",
    'seuil_admin' => "Votre rôle donne accès à l'ensemble de la documentation, y compris les sections d'infrastructure et d'API.",

    // ── CE QUI N'EST PAS RECOPIE, ET POURQUOI ────────────────────────────
    'reste_titre' => 'La documentation de référence',
    'reste_texte' => "Le reste de la documentation — architecture, chiffrement, sessions, procédures — vit encore sur l'ancien portail et n'est pas recopié ici.",
    /*
     * Mesures de l'inventaire (2026-09-01), et elles justifient de NE PAS
     * recopier : la page du legacy ne fait AUCUNE requete (`grep -c '$pdo'`
     * -> 0). Tout ce qu'elle affirme sur les routes et les droits est du HTML
     * ecrit a la main, qu'aucun mecanisme ne regenere.
     */
    'reste_perime' => "Elle porte des références mesurées comme périmées : douze chemins de page qui ne répondent plus, et deux routes citées qui n'existent pas. Onze de ses sections décrivent des parties déjà retirées du produit.",
    'reste_cache'  => "Cette page-ci ne la recopie pas : reproduire un texte que rien ne régénère reviendrait à figer un cache. Ce qui peut être dérivé l'est ailleurs, à partir de la source.",
    'reste_ouvrir' => "Ouvrir la documentation de référence",

    // ── LA DERIVATION, PLUTOT QUE L'AFFIRMATION ──────────────────────────
    'derive_titre' => 'Les routes et les droits, dérivés',
    'derive_texte' => "La liste des routes accessibles et des droits qu'elles exigent n'est pas écrite à la main : elle est dérivée de la configuration réelle de la passerelle. C'est la seule forme qui ne puisse pas se périmer en silence.",
    'derive_lien'  => 'Voir les autorisations de la passerelle',
    'derive_reserve' => "Une affirmation d'autorisation ne se dérive pas d'une seule couche : le produit en compte trois, et elles ne coïncident pas toujours.",

    // ── LA CONSOLE D'API : NON PORTEE, ET C'EST VOULU ────────────────────
    'console_titre' => "La console d'API n'est pas reprise",
    'console_texte' => "L'ancien portail offre un champ libre qui compose une requête vers n'importe quelle route du produit. Elle n'élève aucun privilège — les gardes s'appliquent quand même — mais elle contourne l'interface : aucun panneau de décision, aucun nom de machine annoncé, pour des gestes qui en portent un sur leurs pages propres.",

];
