<?php

/**
 * Authentication foundation — English.
 *
 * Strict parity with lang/fr/auth.php: same key set, same commit.
 * A missing key raises no error — it prints its own IDENTIFIER on screen,
 * which is easy to miss when proofreading.
 */
return [

    // Sign-in steps — announce the journey rather than let it be discovered
    'etape_identifiants'   => 'Credentials',
    'etape_second_facteur' => 'Second factor',
    'etape_acces'          => 'Access',
    'revenir'              => 'Back',

    // Sign in
    'connexion_titre'        => 'Sign in',
    'connexion_sous_titre'   => 'Sign in to the portal',
    'connexion_identifiant'  => 'Username',
    'connexion_mot_de_passe' => 'Password',
    'connexion_valider'      => 'Sign in',
    'connexion_aide'         => 'A single-use code will be requested at the next step.',

    // Second factor
    'second_facteur_titre'       => 'Two-step verification',
    'second_facteur_sous_titre'  => 'TOTP code',
    'second_facteur_instruction' => 'Enter the 6-digit code from your authenticator app.',
    'second_facteur_valider'     => 'Verify',
    'second_facteur_aide'        => 'The code changes every 30 seconds. A code already used is refused: wait for the next one.',

    // Enrolment
    'enrolement_titre'       => 'Second factor required',
    'enrolement_explication' => 'This account has no second factor yet. Enrolment is not available on this interface yet: complete it from the previous portal, then come back here.',

    // Terms of use
    'cgu_titre'      => 'Terms of use',
    'cgu_sous_titre' => 'Last step before reaching the portal.',
    'cgu_accepter'   => 'I accept',
    'cgu_refuser'    => 'Decline and sign out',

    // Portal
    'accueil_titre'        => 'Home',
    'profil_titre'         => 'Profile',
    'deconnexion'          => 'Sign out',
    'connecte_en_tant_que' => 'Signed in as',

    // Errors
    'erreur_identifiants'       => 'Incorrect username or password.',
    'erreur_verrouille'         => 'Account temporarily locked. Try again later.',
    'erreur_code_invalide'      => 'Invalid TOTP code. Please try again.',
    'erreur_code_deja_utilise'  => 'This code has already been used. Wait for the next one.',
    'erreur_trop_de_tentatives' => 'Too many attempts. Wait one minute.',
    'erreur_sans_secret'        => 'No second factor is configured on this account.',
    'changement_requis'         => 'Your password must be changed. This page is not ported yet: change it from the previous portal.',

    // Migration
    'socle_avertissement'   => 'Only the authentication foundation has been ported. Portal pages remain on the previous interface.',
    'ouvrir_ancien_portail' => 'Open the previous portal',
];
