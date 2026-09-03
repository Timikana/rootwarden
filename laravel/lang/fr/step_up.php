<?php

/*
 * La re-authentification ponctuelle. Les messages de refus restent volontairement
 * peu bavards : ils disent qu'on refuse, pas ce qui manquerait pour reussir.
 */
return [
    'valide'               => 'Re-authentification validée.',
    'code_invalide'        => 'Code à six chiffres invalide.',
    'code_deja_utilise'    => 'Ce code a déjà été utilisé. Attendez le suivant.',
    'trop_de_tentatives'   => 'Trop de tentatives. Patientez une minute.',
    'action_inconnue'      => 'Cette action n’exige pas de re-authentification.',
    'sans_second_facteur'  => 'Aucun second facteur n’est configuré sur ce compte.',
    'revoque'              => 'Privilèges rendus.',
    'session_absente'      => 'Session expirée. Reconnectez-vous.',

    // ══ LES LIBELLES DU PANNEAU, ICI ET PAS DANS CHAQUE MODULE ═══════════
    //
    // `comptes` et `permissions` portent les leurs dans leur propre catalogue
    // (`comptes.step_up_titre`, …). Les deux nouveaux consommateurs —
    // `politiques` et `acces-sftp` — les lisent ICI : quatre copies d'un meme
    // libelle divergent, et celui-ci decrit une garde.
    'panneau_titre'   => 'Confirmez avec votre second facteur',
    'panneau_aide'    => "Ce geste écrit une règle sur une machine réelle. Saisissez le code à six chiffres de votre authentificateur : la re-authentification vaut quinze minutes, et pour CETTE action seulement.",
    'panneau_code'    => 'Code à six chiffres',
    'panneau_valider' => 'Confirmer',
    'panneau_annuler' => 'Annuler',
    'panneau_echec'   => "La re-authentification n'a pas abouti.",
];
