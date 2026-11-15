<?php

/**
 * Profile — English. Strict parity with lang/fr/profil.php.
 */
return [

    'compte_titre' => 'Account',
    'compte_texte' => 'Signed in as :nom, with the :role role.',

    'second_facteur_titre'  => 'Second factor',
    'second_facteur_valeur' => 'Active',
    'second_facteur_texte'  => 'A single-use code is required at every sign-in.',

    /*
     * The policy mirrors the legacy one exactly. One key for all five
     * complexity rules: naming WHICH rule failed informs the attacker as much
     * as the person. `mdp_politique` is also used by the reset page.
     */
    'mdp_titre' => 'Change password',
    'mdp_politique' => 'At least :longueur characters, including a lowercase letter, an uppercase letter, a digit and a special character. The last :historique passwords are refused, as is the current one.',
    'mdp_actuel' => 'Current password',
    'mdp_nouveau' => 'New password',
    'mdp_confirmation' => 'Confirm new password',
    'mdp_enregistrer' => 'Change password',
    'mdp_effet_sessions' => 'Your other sessions and remembered logins will be closed.',
    'mdp_ok' => 'Password changed.',
    'mdp_erreur_actuel' => 'Current password is incorrect.',
    'mdp_erreur_correspondance' => 'The passwords do not match.',
    'mdp_erreur_politique' => 'The password must be at least 15 characters long and contain an uppercase letter, a lowercase letter, a digit and a special character.',
    'mdp_erreur_historique' => 'This password has already been used. Choose a different one.',
    'mdp_erreur_fuite' => 'This password appears in a public data breach. Choose a different one.',
    'mdp_erreur_compte' => 'Account not found.',

    // ── Personal data (GDPR) ─────────────────────────────────────────────
    'rgpd_titre' => 'Your personal data',
    'rgpd_aide' => 'Download, as JSON, all the data this portal holds about you (GDPR, articles 15 and 20).',
    'rgpd_bouton' => 'Download my data',
    'rgpd_details' => 'What the file contains',
    'rgpd_contenu' => 'Your profile, your rights, your server access, your action and sign-in histories, your sessions, your notification preferences and your password change dates.',
    'rgpd_protege' => 'Left out: the hashes of your former passwords, and your full session identifiers (cut to eight characters).',
    'rgpd_borne' => 'The action and sign-in histories are capped; beyond the cap, the file gives the total row count.',
    'rgpd_trace' => 'Each download is recorded in the audit log.',

    // ── Open sessions ────────────────────────────────────────────────────
    'sessions_titre' => 'Your open sessions',
    'sessions_aide'  => 'Closing a session signs it out immediately.',
    'sessions_vide'  => 'No session recorded, not even this one: this is not normal.',
    'sessions_err'   => 'Unable to read your sessions.',
    'sessions_actuelle' => 'current session',
    'sessions_vue'    => 'seen on :date',
    'sessions_bornee' => 'The :n most recent, out of :total recorded.',
    'sessions_vestiges' => 'A session that expired without signing out stays listed for up to seven days.',
    'sessions_revoquer' => 'Close',
    'sessions_empreinte' => 'fingerprint :valeur',
    'sessions_revoquee'  => 'Session closed.',
    'sessions_introuvable' => 'This session no longer exists: it may already have been closed.',
    'sessions_pas_la_sienne' => 'To close the current session, use "Log out".',

    // ── Address, SSH keys, erasure ───────────────────────────────────────
    'courriel_titre' => 'Email address',
    'courriel_aide' => 'It receives the password reset link.',
    'courriel_label' => 'New address',
    'courriel_enregistrer' => 'Save address',
    'courriel_ok' => 'Email address saved.',
    'err_courriel_vide' => 'An address is required to reset your password. To remove it, erase your account.',
    'err_courriel_long' => 'Address too long (255 characters at most).',
    'err_courriel_forme' => 'This address is not a valid form.',
    'err_courriel_pris' => 'This address already belongs to another account.',
    'cle_label' => 'Public key',
    'cle_retiree' => 'SSH key removed.',
    'eff_titre' => 'Erase my account',
    'eff_aide' => 'Erases your personal data (name, address, company, SSH keys, second factor) and deactivates the account.',
    'eff_prevenu' => 'Irreversible: you will be signed out immediately. The audit log is kept, without your identity.',
    'eff_confirmation_label' => 'To confirm, type your account name: :nom',
    'eff_code_label' => 'Code from your authenticator app (six digits)',
    'eff_code_aide'  => 'The name guards against a slip; the code, against a stolen session.',
    'eff_bouton' => 'Permanently erase my account',
    'eff_err_confirmation' => 'The name you typed does not match the account name. Nothing was erased.',
    'eff_fait' => 'Your account has been erased. The audit log is kept without your identity.',

    // Several SSH keys per account (migration 067)
    'cles_titre' => 'Your SSH keys',
    'cles_aide' => 'Format « algorithm base64 [comment] ». Each key is installed at the next deployment, on all your machines or on the ones you check.',
    'cles_aucune' => 'No key saved: nothing will be installed for you. Add one below.',
    'cles_th_nom' => 'Name',
    'cles_th_empreinte' => 'Fingerprint',
    'cles_th_portee' => 'Scope',
    'cles_th_ajoutee' => 'Added on',
    'cles_portee_toutes' => 'All my machines',
    'cles_portee_machines' => 'Only the checked machines',
    'cles_portee_aide' => 'Only machines you have access to are listed.',
    'cles_sans_acces' => 'You have access to no machine: your keys will not be installed anywhere until an administrator grants you access.',
    'cles_retirer' => 'Remove',
    'cles_ajout_titre' => 'Add a key',
    'cles_nom' => 'Key name',
    'cles_nom_exemple' => 'laptop, desktop, automation-srv-web01…',
    'cles_ajouter' => 'Add the key',
    'cle_ajoutee' => 'SSH key added. It will be installed at the next deployment.',
    'err_cle_vide' => 'Paste a public key.',
    'err_cle_libelle' => 'Give the key a name (100 characters at most).',
    'err_cle_doublon' => 'This key is already saved on your account.',
    'err_cle_portee_vide' => 'Check at least one machine, or choose « All my machines ».',
    'err_cle_portee_hors_acces' => 'One of the checked machines is not reachable by your account: nothing was saved.',
    'err_cle_introuvable' => 'This key does not exist on your account.',
];
