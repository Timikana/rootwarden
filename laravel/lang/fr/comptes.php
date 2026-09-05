<?php

/**
 * Comptes du portail — module `adm/`, sous-lot D3. Français.
 *
 * Parité stricte avec lang/en/comptes.php.
 *
 * ATTENTION EN RELISANT : ces chaînes contiennent des apostrophes, et c'est
 * SANS DANGER ici — elles sont posées par `textContent` et par Blade, jamais
 * dans un littéral JavaScript. C'est précisément le défaut E-114 du legacy, où
 * `L'utilisateur` placé dans un `confirm('…')` désarmait deux confirmations
 * d'action destructrice.
 */
return [

    'title' => 'Comptes du portail',
    'desc' => "Créer un compte, fixer un mot de passe, déverrouiller un accès, réinitialiser un second facteur.",

    'col_nom' => 'Nom',
    'col_courriel' => 'Courriel',
    'col_societe' => 'Société',
    'col_role' => 'Rôle',
    'col_etat' => 'État',
    'col_mdp' => 'Mot de passe',
    'col_actions' => 'Actions',

    'role_1' => 'Utilisateur',
    'role_2' => 'Administrateur',
    'role_3' => 'Super-administrateur',

    'actif' => 'Actif',
    'inactif' => 'Inactif',
    'verrouille' => 'Verrouillé',
    'sans_2fa' => 'Sans second facteur',
    'sans_2fa_aide' => "Ce compte n'a pas encore enrôlé d'authentificateur.",

    'creer_titre' => 'Créer un compte',
    'creer' => 'Créer',
    'cree' => "Compte « :nom » créé (identifiant :id). Il devra changer ce mot de passe à sa première connexion.",

    'mdp_placeholder' => ':minimum car. min.',
    'mdp_poser' => 'Enregistrer',
    'mdp_generer' => 'Générer',
    'mdp_change' => 'Mot de passe enregistré. Le compte devra le changer à la prochaine connexion.',

    'secret_titre' => 'Mot de passe généré — il ne sera plus affiché.',
    'secret_aide' => "Transmettez-le par un canal sûr. Il n'est écrit ni dans la page, ni dans le journal.",
    'compris' => "J'ai noté",

    'deverrouiller' => 'Déverrouiller',
    'deverrouille' => 'Compte déverrouillé.',

    'totp_reinitialiser' => 'Réinitialiser la 2FA',
    'totp_question' => "Réinitialiser le second facteur de « :nom » ? L'utilisateur devra enrôler un nouvel authentificateur avant de pouvoir se connecter.",
    'totp_confirmer' => 'Réinitialiser',
    'totp_reinitialise' => 'Second facteur réinitialisé.',
    'annuler' => 'Annuler',

    'imp_titre' => 'Importer des comptes depuis un fichier CSV',
    'imp_aide' => 'Le fichier doit porter une ligne d\'en-tête. Les colonnes :colonnes sont obligatoires ; :facultatives sont facultatives.',
    'imp_champ' => 'fichier CSV',
    'imp_fichier' => 'Fichier CSV (:ko kio au plus)',
    /*
     * ══ L'EXEMPTION D'EXPIRATION DE MOT DE PASSE ═════════════════════════
     *
     * TROIS valeurs, et « vide » n'est pas « zéro » : `null` suit la règle
     * globale, `0` exempte, `N` fixe une durée propre au compte. Les libellés
     * le disent, parce qu'un menu qui offrirait « aucune » deux fois ne
     * laisserait pas choisir.
     */
    'exp_titre'   => "Expiration du mot de passe",
    'exp_aide'    => "Réservé au superadministrateur, et jamais sur son propre compte.",
    'exp_globale' => "Suivre la règle globale",
    'exp_exempte' => "Exempter ce compte",
    'exp_jours'   => "Durée propre au compte (en jours)",
    'exp_valider' => "Enregistrer",
    'exp_pose'    => "Expiration enregistrée. L'échéance est recalculée depuis la date du dernier changement de mot de passe.",
    'exp_valeur'  => "Valeur d'expiration invalide : attendu une durée positive, zéro pour exempter, ou rien pour suivre la règle globale.",
    /*
     * ⚠ CE REFUS EST UN GESTE PORTE, PAS UNE REPRISE. Le legacy annonce
     * l'anti-auto-édition dans un commentaire (`update_user.php:42`) et ne la
     * fait pas — zéro comparaison avec l'identifiant de session dans tout le
     * fichier. Le message dit la raison, pas seulement le refus.
     */
    'exp_pas_soi' => "Vous ne pouvez pas modifier l'expiration de votre propre mot de passe : s'exempter soi-même d'une règle de sécurité doit passer par quelqu'un d'autre.",

    'imp_valider' => 'Importer les comptes',
    'imp_roles_aide' => 'La colonne « role » accepte : :roles. Toute autre valeur donne le rôle le plus faible.',
    'imp_courriel_exige' => 'L\'adresse de courriel est OBLIGATOIRE ici, alors que l\'ancien portail l\'acceptait vide — un compte sans adresse et sans mot de passe connu n\'a ni accès ni récupération.',
    'imp_mdp_avert' => 'Le mot de passe de chaque compte créé est affiché UNE SEULE FOIS ci-dessous. Il n\'est enregistré nulle part et ne sera plus jamais affiché : recopiez-le avant de quitter cette page. La personne devra le changer à sa première connexion — il a transité par cet écran, il ne doit pas rester le sien.',
    'imp_bilan_titre' => 'Bilan de l\'import',
    'imp_lues' => ':n ligne(s) lue(s).',
    'imp_crees' => ':n compte(s) créé(s).',
    'imp_tronque' => 'Le fichier dépasse :max lignes : les suivantes n\'ont PAS été traitées.',
    'imp_manquantes' => 'Colonnes obligatoires absentes de l\'en-tête : :colonnes. Rien n\'a été importé.',
    'imp_erreurs_titre' => ':n ligne(s) à signaler',
    'imp_ligne' => 'Ligne :n',
    'imp_secrets_titre' => 'Mots de passe des comptes créés — affichés une seule fois',
    'imp_doublon' => 'Un compte porte déjà ce nom : ligne ignorée.',
    'imp_err_illisible' => 'Le fichier n\'a pas pu être ouvert.',
    'imp_err_vide' => 'Le fichier est vide ou sans ligne d\'en-tête.',
    'imp_err_courriel' => 'Adresse de courriel absente ou invalide : ligne ignorée.',
    'imp_err_ecriture' => 'La création a échoué en base : ligne ignorée.',
    'imp_err_role' => 'La valeur « :valeur » de la colonne « role » n\'est pas un rôle : le compte a été créé avec le rôle « Utilisateur ». Valeurs acceptées : :roles.',
    'imp_rang_ramene' => 'Compte créé, mais avec le rôle « Utilisateur » : vous ne pouvez créer qu\'un rôle inférieur au vôtre.',
    'imp_sudo_refuse' => 'Compte créé SANS sudo : accorder sudo demande le rôle « Superadministrateur ».',
    'err_nom' => "Le nom est obligatoire et ne peut dépasser 255 caractères.",
    'err_nom_pris' => 'Ce nom est déjà utilisé par un autre compte.',
    'err_inconnu' => "Ce compte n'existe pas.",
    'err_hierarchie' => "Un administrateur ne peut pas modifier un super-administrateur.",
    'err_mdp_vide' => 'Saisissez un mot de passe, ou utilisez « Générer ».',
    'err_mdp_longueur' => 'Le mot de passe doit faire au moins :minimum caractères.',
    'err_mdp_classes' => 'Le mot de passe doit mêler minuscules, majuscules, chiffres et symboles.',
    'err_mdp_reutilise' => "Ce mot de passe a déjà été utilisé par ce compte : choisissez-en un autre.",
    'err_cle_forme' => "Une clé SSH publique s'écrit « algorithme corps [commentaire] ».",
    'err_cle_algo' => "Cet algorithme de clé n'est pas accepté.",
    'err_cle_base64' => "Le corps de la clé n'est pas du base64 valide.",
    'err_cle_lignes' => 'Une clé publique tient sur une seule ligne.',
    'cle_enregistree' => 'Clé SSH enregistrée.',
    'err_reseau' => "Le portail n'a pas répondu (statut :statut). Rien n'a été modifié.",

    // Suppression et anonymisation — sous-lot D4
    'supprimer' => 'Supprimer',
    'anonymiser' => 'Anonymiser',
    'anonymiser_plutot' => 'Anonymiser à la place',
    'suppr_question' => 'Supprimer le compte « :nom » ?',
    'suppr_sans_journal' => "Ce compte ne porte aucune ligne de journal : sa suppression n'emporte rien d'autre.",
    'suppr_avec_journal' => "Ce compte porte :nombre ligne(s) de journal d'audit. Les supprimer romprait la chaîne de scellement — la suppression est donc refusée. L'anonymisation efface les données personnelles et conserve le journal.",
    'suppr_consigne' => 'Pour confirmer, saisissez exactement : :nom',
    'anon_question' => "Anonymiser le compte « :nom » ? Les données personnelles seront effacées ; le journal d'audit sera conservé.",
    'supprime' => 'Compte « :nom » supprimé.',
    'anonymise' => "Compte « :nom » anonymisé. :nombre ligne(s) de journal conservée(s).",
    'err_soi_meme' => "Vous ne pouvez pas agir sur votre propre compte.",
    'cree_valeur_role' => 'La valeur de rôle soumise n\'est pas un rôle : le rôle « Utilisateur » a été posé.',
    'cree_rang_ramene' => 'Compte « :nom » créé (identifiant :id) — mais avec le rôle « Utilisateur » : vous ne pouvez créer qu\'un rôle inférieur au vôtre.',
    'err_rang' => "Impossible d'agir sur un compte de rôle égal ou supérieur au vôtre.",
    'err_dernier_sa' => "C'est le dernier super-administrateur actif : il ne peut pas être retiré.",
    'err_journal_present' => "Ce compte porte :nombre ligne(s) de journal d'audit : la suppression les emporterait et romprait la chaîne. Anonymisez-le.",
    'err_step_up' => "Cette action demande une confirmation par votre second facteur.",
    'step_up_titre' => 'Confirmez avec votre second facteur',
    'step_up_aide' => "Ce geste est irréversible. Saisissez le code à six chiffres de votre authentificateur.",
    'step_up_code' => 'Code à six chiffres',
    'step_up_valider' => 'Confirmer',
    'lien_cles_api' => "Gérer les clés d'API",
];
