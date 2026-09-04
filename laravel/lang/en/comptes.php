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

    'imp_titre' => 'Import accounts from a CSV file',
    'imp_aide' => 'The file must carry a header row. Columns :colonnes are required; :facultatives are optional.',
    'imp_champ' => 'CSV file',
    'imp_fichier' => 'CSV file (:ko KiB at most)',
    'imp_valider' => 'Import the accounts',
    'imp_roles_aide' => 'The "role" column accepts: :roles. Any other value yields the lowest role.',
    'imp_courriel_exige' => 'The email address is REQUIRED here, whereas the legacy portal accepted it empty — an account with no address and no known password has neither access nor recovery.',
    'imp_mdp_avert' => 'Each created account\'s password is shown ONCE below, right after the import. It is stored nowhere and will never be shown again: copy it before leaving this page.',
    'imp_bilan_titre' => 'Import summary',
    'imp_lues' => ':n row(s) read.',
    'imp_crees' => ':n account(s) created.',
    'imp_tronque' => 'The file exceeds :max rows: the rest was NOT processed.',
    'imp_manquantes' => 'Required columns missing from the header: :colonnes. Nothing was imported.',
    'imp_erreurs_titre' => ':n row(s) to report',
    'imp_ligne' => 'Row :n',
    'imp_secrets_titre' => 'Passwords of the created accounts — shown once',
    'imp_doublon' => 'An account already carries this name: row skipped.',
    'imp_err_illisible' => 'The file could not be opened.',
    'imp_err_vide' => 'The file is empty or has no header row.',
    'imp_err_courriel' => 'Email address missing or invalid: row skipped.',
    'imp_err_ecriture' => 'Creation failed in the database: row skipped.',
    'imp_rang_ramene' => 'Account created, but with the "User" role: you may only create a role below your own.',
    'imp_sudo_refuse' => 'Account created WITHOUT sudo: granting sudo requires the "Superadmin" role.',
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
    'cree_rang_ramene' => 'Account ":nom" created (id :id) — but with the "User" role: you may only create a role below your own.',
    'err_rang' => 'You cannot act on an account whose role is equal to or above yours.',
    'err_dernier_sa' => 'This is the last active super administrator: it cannot be removed.',
    'err_journal_present' => 'This account carries :nombre audit log line(s): deleting it would take them along and break the chain. Anonymise it instead.',
    'err_step_up' => 'This action requires confirmation with your second factor.',
    'step_up_titre' => 'Confirm with your second factor',
    'step_up_aide' => 'This gesture is irreversible. Type the six-digit code from your authenticator.',
    'step_up_code' => 'Six-digit code',
    'step_up_valider' => 'Confirm',
    'lien_cles_api' => 'Manage API keys',
];
