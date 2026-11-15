<?php

/**
 * Platform key.
 *
 * Writing rules: docs/REDACTION-INTERFACE.md. What is irreversible stays
 * visible and short; technical detail goes into a collapsible block.
 */

return [
    'titre' => "Platform SSH key",
    'intro' => "A single Ed25519 key pair lets RootWarden connect to every machine without a password.",
    'cle_titre' => "Public key",
    'cle_aide' => "This is the key written to the machines' authorized_keys files.",
    'cle_chargement' => "Reading the public key…",
    'cle_echec' => "The public key could not be read.",
    'cle_absente_titre' => "No key pair exists yet",
    'cle_absente' => "It will be created on the first deployment.",
    'cle_copier' => "Copy",
    'cle_copiee' => "Copied.",
    'stat_cle' => "Key deployed",
    'stat_compte_service' => "Administration account",
    'stat_en_attente' => "Pending",
    'stat_sans_mot_de_passe' => "No known password",
    'progression_titre' => "Progress",
    'progression_reste' => ":nb machine(s) still without the key.",
    'progression_cle_ok' => "The key is deployed everywhere.",
    'progression_finie' => "The key is deployed everywhere and no password is stored any more.",
    'legende_mot_de_passe' => "password only",
    'legende_les_deux' => "key and password",
    'legende_cle' => "key only",
    'avert_titre' => "Before erasing passwords",
    'avert_texte' => "A machine with no known password can only be reached with this key. For it, rotating the key cannot be undone.",
    'sans_retour_titre' => "Machines where the key is the only access",
    'sans_retour_aucune' => "None: every machine still has at least one known password.",
    'sans_retour_liste' => ":nb machine(s): :noms. Rotating the key would cut their access for good.",
    'th_machine' => "Machine",
    'th_adresse' => "Address",
    'th_auth' => "Authentication",
    'th_compte_service' => "Administration account",
    'th_mot_de_passe' => "Known passwords",
    'th_depuis' => "Key deployed on",
    'th_actions' => "Actions",
    'etat_cle_seule' => "key only",
    'etat_cle_et_mot_de_passe' => "key and password",
    'etat_mot_de_passe_seul' => "password only",
    'compte_service_pose' => "rootwarden",
    'compte_service_absent' => "absent",
    'compte_service_aide' => "The “rootwarden” account has passwordless root access (NOPASSWD: ALL). Deploying the key creates it.",
    'mdp_les_deux' => "user and root",
    'mdp_utilisateur' => "user only",
    'mdp_root' => "root only",
    'mdp_aucun' => "none",
    'mdp_aide_partiel' => "“Re-enter” only restores the SSH password. The root password is re-entered from the Servers page.",
    'jamais' => "never",
    'sensible' => "Production",
    'vide_titre' => "No machines in the fleet",
    'vide_texte' => "Add a machine from the Servers page.",
    'details' => "Details",

    // ── Connection test ──────────────────────────────────────────────────
    'tester' => "Test connection",
    'tester_aide' => "“Test” opens and closes an SSH session with the key, without writing anything.",
    'test_en_cours' => "Connecting to :machine…",
    'test_ok' => "The key works on :machine.",
    'test_rien_a_tester' => ":machine: the key is not deployed there yet.",
    'test_echec' => "The key did not work on :machine (refused or machine unreachable): :message",
    'test_indecis' => ":machine: unreadable response, no verdict.",
    'test_journal' => "Test log",
    'test_journal_vide' => "No test run yet.",

    // ── The guide, in order ──────────────────────────────────────────────
    'guide_titre' => "How it works",
    'guide_etape1' => "A single key pair serves the whole fleet. RootWarden generates and stores it.",
    'guide_etape2' => "“Deploy” installs the public key and creates the “rootwarden” administration account (passwordless root).",
    'guide_etape3' => "“Test” checks that key-based login works.",
    'guide_etape4' => "“Erase passwords” deletes the copy RootWarden keeps. The passwords remain valid on the machine.",

    // ── Actions that write ───────────────────────────────────────────────
    'btn_deployer' => "Deploy",
    'btn_compte_service' => "Retry the administration account",
    'btn_effacer' => "Erase passwords",
    'btn_ressaisir' => "Re-enter a password",

    'parc_titre' => "Across the fleet",
    'parc_aide' => "Each button acts on exactly the number of machines it shows.",
    'parc_btn_deployer' => "Deploy to the :n machines without the key",
    'parc_btn_compte_service' => "Retry the administration account on :n machine(s)",
    'parc_btn_effacer' => "Erase passwords on :n machine(s)",
    'parc_rien' => "Nothing to do: every machine has the key and the administration account, with no stored password.",

    'refusees_titre' => ":n machine(s) excluded from erasing",
    'refusees_texte' => "They have no administration account: without a password, RootWarden could no longer become root on them. Retry the administration account first.",

    'champ_mdp' => "SSH password to store again",
    'champ_mdp_aide' => "Stored encrypted, never shown again. The root password is re-entered from the Servers page.",
    'annuler' => "Cancel",
    'confirmer' => "Confirm",

    'recharger' => "Reload the page",
    'geste_journal' => "Action log",
    'geste_journal_vide' => "No action run yet.",
    'geste_en_cours' => "Running on :cibles…",
    'geste_echec_reseau' => "No response (:message). The action may still be running: do not start it again. Reload the page, then “Test” the machine.",
    'geste_sans_verdict' => "Unreadable response: the action may have happened. Do not start it again. Reload the page, then “Test” the machine.",
    'geste_ligne_ok' => ":machine: succeeded — :message",
    'geste_ligne_echec' => ":machine: failed — :message",
    'geste_bilan' => ":ok success(es) out of :total.",
    'ressaisie_mdp_vide' => "No password entered: nothing was sent.",
    'confirmer_saisie_manquante' => "Fill in the field before confirming.",
    'effacement_bilan' => ":ok erasure(s) out of :total.",
    'effacement_interrompu' => "Stopped after :fait machine(s) out of :total: the remaining ones were not processed.",

    // Decision panels: each names its consequence.
    'panneaux' => [
        'deployer' => [
            'titre' => "Deploy the platform key",
            'bouton' => "Deploy the key",
            'texte' => "Logs in with a password and writes to the machine.",
            'effets' => [
                "adds the public key for the SSH user and for root",
                "creates the “rootwarden” account with passwordless root access",
            ],
        ],
        'compte_service' => [
            'titre' => "Retry the administration account",
            'bouton' => "Recreate the account",
            'texte' => "The deployment did not manage to create this account: this action tries again.",
            'effets' => [
                "creates the “rootwarden” account if missing, with passwordless root access",
                "only succeeds if “sudo whoami” answers root",
            ],
        ],
        'effacer' => [
            'titre' => "Erase the passwords known to RootWarden",
            'bouton' => "Erase the passwords",
            'texte' => "Does not touch the machine: deletes the copy RootWarden keeps.",
            'effets' => [
                "deletes the stored SSH password and root password",
                "RootWarden can then reach the machine only with the key",
            ],
        ],
        'rotation' => [
            'titre' => "Rotate the platform key",
            'bouton' => "Rotate the key",
            'texte' => "Replaces the key for the whole fleet at once.",
            'effets' => [
                "destroys the current private key and generates a new one",
                "marks the key as not deployed on the :total machines: you will need to redeploy",
                "the old public key stays on the machines until it is removed",
                "can be undone for :jours days from the archive, unless the volume holding it is lost",
                "requires approval from a second administrator",
            ],
        ],
        'revoquer' => [
            'titre' => "Delete the administration account",
            'bouton' => "Delete the account",
            'texte' => "Deletes the “rootwarden” account from the machine. Only a new deployment recreates it.",
            'effets' => [
                "removes its sudo rights, then deletes the account and its home directory",
                "the key remains authorised for the SSH user and for root",
                "if the key is compromised, rotate the key instead",
                "requires approval from a second administrator",
            ],
        ],
        'ressaisir' => [
            'titre' => "Store an SSH password again",
            'bouton' => "Save the password",
            'texte' => "Writes to RootWarden, does not touch the machine.",
            'effets' => [
                "stores the SSH user's password again, encrypted",
                "the root password is re-entered from the Servers page",
            ],
        ],
    ],
    'panneau_cible_une' => "Target machine: :nom",
    'panneau_cible_n' => ":n target machines: :noms",
    'panneau_prod' => "⚠ Production: :noms",

    'btn_revoquer' => "Delete the administration account",
    'parc_btn_revoquer' => "Delete the administration account on :n machine(s)",
    'champ_motif' => "Reason",
    'champ_motif_aide' => "Recorded in the audit log (200 characters max).",
    'motif_vide' => "Enter a reason: nothing was sent.",
    'geste_approbation_attente' => "Approval request sent to a second administrator (Approvals page). Nothing has been removed yet.",
    'geste_approbation_absente' => "Blocked: this action requires a second administrator and none is available. :message",
    'revoquer_asymetrie' => "Your role can grant this administration account, but only a superadmin can delete it.",

    // Each action's limits, shown in its panel.
    'bornes' => [
        'rotation' => "The old key's archive sits in the same Docker volume as the current key, and RootWarden does not back that volume up.",
        'revoquer' => "If the server refuses the “rootwarden” account's login (hardened sshd) and the root password was erased, deletion fails. It can safely be run again.",
        'compte_service' => "Fails if the account was deleted after the passwords were erased: RootWarden then has no way left to become root. Re-enter the root password from the Servers page first.",
    ],

    // What the backend, the only one able to decrypt, says about passwords.
    'credential_titre' => "Password check",
    'credential_aide' => "The table counts stored passwords. RootWarden also checks whether they are empty once decrypted.",
    'credential_borne_root' => "The check covers both the SSH password and the root password.",
    'credential_divergence' => ":n machine(s) with a stored but empty SSH password: :noms.",
    'credential_indetermine' => ":n machine(s) whose SSH password could not be decrypted: :noms.",
    'credential_accord' => "Check done: no discrepancy.",
    'credential_echec' => "Check unavailable: the numbers shown have not been verified.",
    'badge_mdp_vide_reel' => "actually empty",
    'badge_mdp_illisible' => "unreadable",

    // ── Rotation ─────────────────────────────────────────────────────────
    'rotation_titre' => "Rotate the key",
    'rotation_aide' => "Acts on the whole fleet at once. Superadmins only, with approval from a second administrator.",
    'btn_rotation' => "Rotate the platform key",
    'rotation_remede' => "Rotation does not remove the old key from the machines. If the key is compromised, also remove the old one, machine by machine.",
    'rotation_remede_ou' => "Removal is done from the Remote accounts page, key by key. By default RootWarden refuses to remove the active platform key there.",
    'rotation_remede_parc' => "There is deliberately no fleet-wide removal: it would cut RootWarden off from every machine.",
    'rotation_jamais_exercee' => "This action has never been tested in real conditions.",
    'rotation_sans_retour' => "⚠ :n machine(s) can only be reached with this key: :noms. If redeployment fails, they become unreachable.",
    'rotation_sans_retour_aucune' => "No machine depends on this key alone.",
    'rotation_jours_inconnus' => "Archive retention unknown: treat this action as irreversible.",
    'credential_divergence_root' => ":n machine(s) with a stored but empty root password: :noms. Re-enter it from the Servers page.",
    'credential_indetermine_root' => ":n machine(s) whose root password could not be decrypted: :noms.",
    'badge_root_vide_reel' => "root actually empty",
    'badge_root_illisible' => "root unreadable",

    'geste_sudoers_orphelin' => "⚠ :machine: account deleted, but its sudo rights remain on the machine. Run the action again to remove them.",
    'champ_recopie' => "To confirm, type the number of machines affected",
    'champ_recopie_aide' => "The button becomes active when the number matches.",
];
