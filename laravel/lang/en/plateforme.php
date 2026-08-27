<?php

/**
 * Cle de plateforme — sous-lot P1.
 *
 * Aucun texte de cette page ne doit annoncer un acces plus strict que celui
 * qui est applique : l'en-tete du legacy annonce « superadmin uniquement »
 * alors que sa garde admet tout role portant la permission (E-36, cinquieme
 * occurrence). Et aucun ne doit laisser croire que « migration terminee »
 * est un aboutissement neutre : c'est l'etat ou la rotation est sans retour.
 */

return [
    'titre' => "Platform SSH key",
    'intro' => "One Ed25519 key pair, a single one for the whole fleet and for both accounts. RootWarden uses it to authenticate on each machine without a password.",
    'garde_reelle' => "This page is open to any role holding the « manage platform key » permission — that is the guard actually applied. The legacy portal claims « superadmin only »: its header is wrong.",
    'cle_titre' => "Public key",
    'cle_aide' => "This is the public half: it is meant to be read and copied. It is what gets written into the machines' authorized_keys files.",
    'cle_chargement' => "Reading the public key…",
    'cle_echec' => "The public key could not be read. This is not « there is no key »: the read failed.",
    'cle_absente_titre' => "No key pair exists yet",
    'cle_absente' => "The backend has no platform key. It is created on the first deployment.",
    'cle_copier' => "Copy",
    'cle_copiee' => "Copied.",
    'stat_cle' => "Key deployed",
    'stat_compte_service' => "Administration account",
    'stat_en_attente' => "Pending",
    'stat_sans_mot_de_passe' => "No known password",
    'progression_titre' => "Migration progress",
    'progression_reste' => "There are :nb machine(s) left without the key.",
    'progression_cle_ok' => "The key is everywhere. The legacy portal's next step is to erase the passwords.",
    'progression_finie' => "Migration complete in the legacy portal's sense.",
    'legende_mot_de_passe' => "password only",
    'legende_les_deux' => "key and password",
    'legende_cle' => "key only",
    'avert_titre' => "What « migration complete » means",
    'avert_texte' => "Erasing the passwords does not remove them from the machines: it removes the COPY that RootWarden keeps. A machine whose key is deployed and for which no password is known any more has only one way in — that key. Rotating it destroys the private key WITH NO COPY: for those machines, rotation has no way back. The state the legacy portal presents as the end of the migration is exactly that one.",
    'sans_retour_titre' => "Machines for which the key is the only access",
    'sans_retour_aucune' => "No machine is in that case today: each one still has at least one password known to RootWarden. This is computed, not assumed.",
    'sans_retour_liste' => "Machines concerned — :nb in total: :noms. Rotating the key would cut their access with no way back.",
    'divergence_titre' => "The legacy portal counts differently, and it is wrong",
    'divergence_texte' => "The legacy portal counts « password removed » from a flag (ssh_password_required), not from the columns. But the Servers page is the only path that FILLS the root password, and it does not touch that flag: restoring a password there leaves this row announced as erased. Machines where the flag contradicts the columns — :nb in total: :noms. This page counts the columns.",
    'th_machine' => "Machine",
    'th_adresse' => "Address",
    'th_auth' => "Authentication",
    'th_compte_service' => "Administration account",
    'th_mot_de_passe' => "Known passwords",
    'th_depuis' => "Key deployed on",
    'th_actions' => "Test",
    'etat_cle_seule' => "key only",
    'etat_cle_et_mot_de_passe' => "key and password",
    'etat_mot_de_passe_seul' => "password only",
    'compte_service_pose' => "rootwarden",
    'compte_service_absent' => "absent",
    'compte_service_aide' => "This account carries « NOPASSWD: ALL »: it can run anything as root without a password. Deploying the key grants it at the same time, without its label saying so.",
    'mdp_les_deux' => "user and root",
    'mdp_utilisateur' => "user only",
    'mdp_root' => "root only",
    'mdp_aucun' => "none",
    'mdp_aide_partiel' => "Erasing the passwords erases BOTH. « Re-enter » restores only one: the root password can only be rewritten from the Servers page. The way back offered is therefore half the action.",
    'jamais' => "never",
    'sensible' => "Production",
    'vide_titre' => "No machine in the fleet",
    'vide_texte' => "No machine is registered. The platform key has nothing to protect while the fleet is empty.",
    'non_porte_titre' => "This page's actions are not ported yet",
    'non_porte_texte' => "Deploying the key, deploying the administration account, testing a connection, reading the accounts, erasing or re-entering a password, and rotating the key are still done from the legacy portal. This page carries the state, its counters and its guards.",
    'non_porte_lien' => "Open the platform key in the legacy portal",

    // ── Sous-lot P2 : le test de connexion ───────────────────────────────
    // QUATRE situations, et le legacy les replie sur un rouge unique. « Cle non
    // deployee » est un ETAT, pas un echec ; et le backend ne distingue pas
    // « refusee » d'« injoignable » — les deux rendent `auth_method: password`.
    // L'ecran ne pretend donc pas savoir laquelle, il dit les deux.
    'tester' => "Test the connection",
    'tester_aide' => "Opens an SSH session to the machine with the key, then closes it. Nothing is written, neither on the machine nor in the database.",
    'test_en_cours' => "Connecting to :machine…",
    'test_ok' => "The key works on :machine.",
    'test_rien_a_tester' => "Nothing to test on :machine: the key is not deployed there. This is not a failure — it is the previous step.",
    'test_echec' => "The key did not work on :machine. Two possible causes the backend does not tell apart: it is refused by the machine, or the machine is unreachable. What the server reports: :message",
    'test_indecis' => "The test returned no verdict on :machine. This is neither a success nor a key failure: the answer could not be read.",
    'test_journal' => "Test log",
    'test_journal_vide' => "No test has been run on this page yet.",
];
