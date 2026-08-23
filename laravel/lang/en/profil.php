<?php

/**
 * Profile — English. Strict parity with lang/fr/profil.php.
 */
return [

    'compte_titre' => 'Account',
    'compte_texte' => 'Signed in as :nom, with the :role role.',

    'second_facteur_titre'  => 'Second factor',
    'second_facteur_valeur' => 'Active',
    'second_facteur_texte'  => 'A single-use code is required at every sign-in. There is no access without a second factor.',

    'non_porte_titre' => 'Not here yet',
    'non_porte_texte' => 'Open sessions and remembered logins are not listed here yet: the legacy portal shows them. The password change itself now happens on this page.',
    /*
     * ── SUB-LOT A2: PASSWORD CHANGE ──────────────────────────────────────
     *
     * The policy mirrors the legacy one exactly: both portals share the
     * database, so a laxer rule on one side would be a bypass of the other.
     * The legacy returns ONE key for all five complexity rules - we keep that
     * choice: naming WHICH rule failed informs the attacker as much as the
     * person.
     */
    'mdp_titre' => 'Change password',
    'mdp_politique' => 'At least :longueur characters, including a lowercase letter, an uppercase letter, a digit and a special character. The last :historique passwords are refused, as is the current one.',
    'mdp_actuel' => 'Current password',
    'mdp_nouveau' => 'New password',
    'mdp_confirmation' => 'Confirm new password',
    'mdp_enregistrer' => 'Change password',
    'mdp_effet_sessions' => 'Your other open sessions will be closed, and remembered logins forgotten. This one stays open.',
    'mdp_ok' => 'Password changed successfully.',
    'mdp_erreur_actuel' => 'Current password is incorrect.',
    'mdp_erreur_correspondance' => 'The passwords do not match.',
    'mdp_erreur_politique' => 'The password must be at least 15 characters long and contain an uppercase letter, a lowercase letter, a digit and a special character.',
    'mdp_erreur_historique' => 'This password has already been used. Choose a different one.',
    'mdp_erreur_fuite' => 'This password appears in a public data breach. Choose a different one.',
    'mdp_erreur_compte' => 'Account not found.',
];
