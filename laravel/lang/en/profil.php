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
    // E-203: sessions ARE listed now — see fr.
    'non_porte_texte' => 'Remembered logins are not listed here yet: the legacy portal shows them. The password change and open sessions are now handled on this page.',
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
    'mdp_effet_sessions' => "Your other sessions will be closed, on this portal as on the old one — both check on every request — and remembered logins forgotten.",
    'mdp_ok' => 'Password changed successfully.',
    'mdp_erreur_actuel' => 'Current password is incorrect.',
    'mdp_erreur_correspondance' => 'The passwords do not match.',
    'mdp_erreur_politique' => 'The password must be at least 15 characters long and contain an uppercase letter, a lowercase letter, a digit and a special character.',
    'mdp_erreur_historique' => 'This password has already been used. Choose a different one.',
    'mdp_erreur_fuite' => 'This password appears in a public data breach. Choose a different one.',
    'mdp_erreur_compte' => 'Account not found.',

    // E-203: open sessions.
    'sessions_titre' => 'Your open sessions',
    'sessions_aide'  => 'Each login to this portal or the old one opens a session. Closing a session logs it out immediately, on both sides.',
    'sessions_vide'  => 'No session recorded — not even this one, which is not normal.',
    'sessions_err'   => 'Your sessions could not be read. This is not "no session": the list did not answer.',
    'sessions_actuelle' => 'current session',
    'sessions_depuis' => 'opened on :date',
    'sessions_vue'    => 'seen on :date',
    'sessions_bornee' => 'The :n most recent, out of :total recorded.',
    'sessions_vestiges' => 'The old portal records one row per login and never removes any: the oldest no longer correspond to an open access.',
    'sessions_revoquer' => 'Close',
    'sessions_empreinte' => 'fingerprint :valeur',
    'sessions_revoquee'  => 'Session closed.',
    'sessions_introuvable' => 'This session no longer exists — it may already have been closed.',
    'sessions_pas_la_sienne' => 'To close the current session, use "Log out".',
];
