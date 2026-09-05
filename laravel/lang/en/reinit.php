<?php

/*
 * Password reset by email. The key set must stay identical to
 * `lang/fr/reinit.php`. See fr for why the message says "prepared" and not
 * "sent", and why it lives outside the branch that tests the account.
 */
return [
    'titre'       => 'Forgotten password',
    'sous_titre'  => 'Enter your account email address. If it matches an active account, a reset link will be prepared for it.',
    'champ_email' => 'Email address',
    'envoyer'     => 'Request a link',
    'retour'      => 'Back to sign-in',

    'demande_recue' => 'If that address matches an active account, a reset link has been prepared for it. It is valid for one hour and can be used only once.',

    'trop_de_demandes' => 'Too many requests from this address. Try again in an hour.',

    'jeton_invalide' => 'This link is no longer valid: it has expired, it has already been used, or a more recent request replaced it. Request a new one.',

    'reinit_titre'      => 'Choose a new password',
    'reinit_sous_titre' => 'This link works only once. After saving, you will sign in as usual — the second factor is still required.',
    'champ_mot_de_passe' => 'New password',
    'champ_confirmation' => 'Confirm the password',
    'valider'            => 'Save the password',

    'mot_de_passe_pose' => 'Password saved. You can now sign in.',

    'consequence' => 'Saving a new password closes every open session of this account and revokes remembered sign-ins, on all devices.',

    'courriel_sujet' => 'RootWarden — resetting your password',
    'courriel_corps' => <<<'TXT'
Hello :nom,

A password reset was requested for your RootWarden account.

Open this link to choose a new password:

:lien

This link is valid for :heures hour and can be used only once. Any more recent
request invalidates it.

If you did not make this request, there is nothing to do: without this link,
your password stays unchanged.
TXT,
];
