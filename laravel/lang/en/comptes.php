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

    // Deletion and anonymisation — sub-lot D4
    'supprimer' => 'Delete',
    'anonymiser' => 'Anonymise',
    'anonymiser_plutot' => 'Anonymise instead',
    'suppr_question' => 'Delete account ":nom"?',
    'suppr_sans_journal' => 'This account carries no audit log line: deleting it takes nothing else with it.',
    'suppr_avec_journal' => 'This account carries :nombre audit log line(s). Deleting them would break the sealing chain — deletion is therefore refused. Anonymising erases the personal data and keeps the log.',
    'suppr_consigne' => 'To confirm, type exactly: :nom',
    'anon_question' => 'Anonymise account ":nom"? Personal data will be erased; the audit log will be kept.',
    'supprime' => 'Account ":nom" deleted.',
    'anonymise' => 'Account ":nom" anonymised. :nombre audit log line(s) kept.',
    'err_soi_meme' => 'You cannot act on your own account.',
    'err_rang' => 'You cannot act on an account whose role is equal to or above yours.',
    'err_dernier_sa' => 'This is the last active super administrator: it cannot be removed.',
    'err_journal_present' => 'This account carries :nombre audit log line(s): deleting it would take them along and break the chain. Anonymise it instead.',
    'err_step_up' => 'This action requires confirmation with your second factor.',
    'step_up_titre' => 'Confirm with your second factor',
    'step_up_aide' => 'This gesture is irreversible. Type the six-digit code from your authenticator.',
    'step_up_code' => 'Six-digit code',
    'step_up_valider' => 'Confirm',
];
