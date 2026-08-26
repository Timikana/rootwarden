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

    'reste_titre' => "Une capacité de cet onglet n'est pas encore portée.",
    'reste_texte' => "L'import de comptes par fichier CSV vit toujours sur l'ancien portail. Les trois onglets de la page d'administration, eux, sont portés : ils se rejoignent par les onglets ci-dessus.",
    'reste_lien' => "Ouvrir l'ancien portail",

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
    'cree' => "Compte « :nom » créé (identifiant :id). Il devra fixer son mot de passe à la première connexion.",

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
    'err_rang' => "Impossible d'agir sur un compte de rôle égal ou supérieur au vôtre.",
    'err_dernier_sa' => "C'est le dernier super-administrateur actif : il ne peut pas être retiré.",
    'err_journal_present' => "Ce compte porte :nombre ligne(s) de journal d'audit : la suppression les emporterait et romprait la chaîne. Anonymisez-le.",
    'err_step_up' => "Cette action demande une confirmation par votre second facteur.",
    'step_up_titre' => 'Confirmez avec votre second facteur',
    'step_up_aide' => "Ce geste est irréversible. Saisissez le code à six chiffres de votre authentificateur.",
    'step_up_code' => 'Code à six chiffres',
    'step_up_valider' => 'Confirmer',
];
