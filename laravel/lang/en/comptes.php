<?php

/**
 * Portal accounts — `adm/` module, sub-lot D3. English.
 *
 * Strict parity with lang/fr/comptes.php.
 *
 * NOTE WHEN REVIEWING: these strings contain apostrophes, and that is SAFE here
 * — they are placed via `textContent` and Blade, never inside a JavaScript
 * literal. That is precisely the legacy's E-114 defect, where `L'utilisateur`
 * inside a `confirm('…')` disarmed two destructive-action confirmations.
 */
return [

    'title' => 'Portal accounts',
    'desc' => 'Create an account, set a password, unlock an access, reset a second factor.',

    'reste_titre' => 'Two tabs are not ported yet.',
    'reste_texte' => 'The old portal administration page also carries servers and access & permissions. They still live there; only accounts are ported here.',
    'reste_lien' => 'Open the old portal',

    'col_nom' => 'Name',
    'col_courriel' => 'Email',
    'col_societe' => 'Company',
    'col_role' => 'Role',
    'col_etat' => 'Status',
    'col_mdp' => 'Password',
    'col_actions' => 'Actions',

    'role_1' => 'User',
    'role_2' => 'Administrator',
    'role_3' => 'Super administrator',

    'actif' => 'Active',
    'inactif' => 'Inactive',
    'verrouille' => 'Locked',
    'sans_2fa' => 'No second factor',
    'sans_2fa_aide' => 'This account has not enrolled an authenticator yet.',

    'creer_titre' => 'Create an account',
    'creer' => 'Create',
    'cree' => 'Account ":nom" created (id :id). It will have to set its password on first sign-in.',

    'mdp_placeholder' => ':minimum chars min.',
    'mdp_poser' => 'Save',
    'mdp_generer' => 'Generate',
    'mdp_change' => 'Password saved. The account will have to change it on next sign-in.',

    'secret_titre' => 'Generated password — it will not be shown again.',
    'secret_aide' => 'Pass it on through a safe channel. It is written neither in the page nor in the log.',
    'compris' => 'Noted',

    'deverrouiller' => 'Unlock',
    'deverrouille' => 'Account unlocked.',

    'totp_reinitialiser' => 'Reset 2FA',
    'totp_question' => 'Reset the second factor for ":nom"? The user will have to enrol a new authenticator before signing in.',
    'totp_confirmer' => 'Reset',
    'totp_reinitialise' => 'Second factor reset.',
    'annuler' => 'Cancel',

    'err_nom' => 'The name is required and cannot exceed 255 characters.',
    'err_nom_pris' => 'That name is already used by another account.',
    'err_inconnu' => 'That account does not exist.',
    'err_hierarchie' => 'An administrator cannot modify a super administrator.',
    'err_mdp_vide' => 'Type a password, or use "Generate".',
    'err_mdp_longueur' => 'The password must be at least :minimum characters long.',
    'err_mdp_classes' => 'The password must mix lower case, upper case, digits and symbols.',
    'err_mdp_reutilise' => 'This account has already used that password: choose another one.',
    'err_cle_forme' => 'An SSH public key reads "algorithm body [comment]".',
    'err_cle_algo' => 'That key algorithm is not accepted.',
    'err_cle_base64' => 'The key body is not valid base64.',
    'err_cle_lignes' => 'A public key fits on a single line.',
    'cle_enregistree' => 'SSH key saved.',
    'err_reseau' => 'The portal did not answer (status :statut). Nothing was changed.',
];
