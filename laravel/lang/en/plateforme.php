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
    'non_porte_titre' => "Only one action is not ported: key rotation",
    'non_porte_texte' => "Rotating the platform key — regenerating it — is still done from the legacy portal. It is the broadest action in the portal: it acts on the whole fleet at once, without targeting any machine, and it destroys the current private key. Every other action on this page is ported here.",
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

    // ── Le guide de procedure, PORTE et CORRIGE ──────────────────────────
    // Le legacy affiche un guide en quatre etapes (`howto_tip.php`, page :50).
    // Mon premier jet de P1 l'avait LAISSE TOMBER — un acquis du legacy perdu
    // sans que rien ne le signale, parce que personne n'ouvre `lang/`. Il est
    // porte ici, et DEUX de ses quatre etapes sont corrigees : elles disaient
    // faux, et l'une des deux dans le sens rassurant.
    'guide_titre' => "How the platform key works, in order",
    'guide_etape1' => "The Ed25519 key pair is generated automatically and kept on the server side. There is ONE for the whole fleet and for both accounts — not one per machine.",
    'guide_etape2' => "« Deploy the pair » installs the public key on the chosen machines — AND creates the « rootwarden » administration account with NOPASSWD: ALL. The two actions are one, and the legacy portal's label does not say so.",
    'guide_etape3' => "Once deployed, RootWarden connects without a password. The « Test » button checks it without writing anything.",
    'guide_etape4' => "« Erase the passwords » does NOT act on the machine: it erases the copy RootWarden keeps. The Unix account keeps its password, and whoever knows it still gets in. What RootWarden loses is its own fallback if the key stops working.",
    'guide_corrige' => "Two of these four steps correct the legacy portal's guide, measurement in hand. It claimed that « Deploy keypair installs the public key » without mentioning the NOPASSWD: ALL account; and that « Remove password disables password authentication ON THE SERVER (more secure) », which is false in both languages — the route does not touch the machine.",
    // ══ P3 — THE ACTIONS THAT WRITE ══════════════════════════════════════
    'btn_deployer' => "Deploy",
    'btn_compte_service' => "Retry the administration account",
    'btn_effacer' => "Erase the passwords",
    'btn_ressaisir' => "Re-enter a password",

    'parc_titre' => "The same actions, fleet-wide",
    'parc_aide' => "Each button announces the number of machines in ITS own list, and acts on exactly those. The legacy portal displayed a subtraction of counters computed differently: the number announced and the number processed could differ.",
    'parc_btn_deployer' => "Deploy on the :n machines without a key",
    'parc_btn_compte_service' => "Retry the administration account on :n machine(s)",
    'parc_btn_effacer' => "Erase the passwords of :n machine(s)",
    'parc_rien' => "No fleet-wide action has anything to act on: every machine has its key and its administration account, and none still holds a password known to RootWarden.",

    'refusees_titre' => ":n machine(s) that bulk erasure leaves out",
    'refusees_texte' => "These machines have a key and a password, but no administration account: the backend refuses to erase their password, because RootWarden would then have no way left to become root. They are not « already done », they are blocked — and the administration-account action is what unblocks them. The legacy portal offered them anyway and counted the refusal as nothing.",

    'champ_mdp' => "SSH password to store again",
    'champ_mdp_aide' => "It is stored encrypted, and never displayed again. This action restores the SSH user's password; it does NOT restore the root password, which can only be rewritten from the Servers page.",
    'annuler' => "Cancel",
    'confirmer' => "Confirm",

    'recharger' => "Reload the page to read the real state",
    'geste_journal' => "Action log",
    'geste_journal_vide' => "No action has been started from this page yet.",
    'geste_en_cours' => "Running on :cibles…",
    'geste_echec_reseau' => "No verdict: the request did not come back (:message). The action may still be RUNNING on the server side. DO NOT RETRY — a second attempt would grant fresh root access while the first one may be finishing. Reload the page, then use « Test » on the machine to find out where it stands.",
    'geste_sans_verdict' => "The server answered without a readable verdict. This is neither a success nor a failure, and the write may have happened. DO NOT RETRY. Reload the page, then use « Test » on the machine.",
    'geste_ligne_ok' => ":machine: succeeded — :message",
    'geste_ligne_echec' => ":machine: failed — :message",
    'geste_bilan' => ":ok success(es) out of :total. Failed machines are named above, one per line.",
    'ressaisie_mdp_vide' => "No password entered: nothing was sent.",
    'confirmer_saisie_manquante' => "Fill in the field before confirming.",
    'effacement_bilan' => ":ok erasure(s) out of :total.",
    'effacement_interrompu' => "Interrupted after :fait machine(s) out of :total. This action leaves as one request per machine: the remaining ones were NOT sent, and the fleet is half migrated.",

    // The decision panels, one per action. Each NAMES its consequence.
    'panneaux' => [
        'deployer' => [
            'titre' => "Deploy the platform key",
            'texte' => "This action opens an SSH session using the password and writes on the machine. It does two things, and the legacy portal announced only one.",
            'effets' => [
                "adds the public key to authorized_keys of both the SSH user and root",
                "creates the Unix account « rootwarden » and grants it NOPASSWD: ALL through /etc/sudoers.d",
                "taking that access back has no button in the portal: it is an operations action outside the portal",
            ],
        ],
        'compte_service' => [
            'titre' => "Retry the administration account",
            'texte' => "This is not the next step of the deployment: deploying the key ALREADY tried to create this account, in the same request, and that attempt failed. This action retries it.",
            'effets' => [
                "creates the Unix account « rootwarden » if it is missing",
                "grants it NOPASSWD: ALL through /etc/sudoers.d",
                "then checks that « sudo whoami » answers root, and records success only in that case",
            ],
        ],
        'effacer' => [
            'titre' => "Erase the passwords known to RootWarden",
            'texte' => "This action DOES NOT TOUCH the machine. It erases the copy RootWarden keeps of both passwords. The Unix account keeps its own, and whoever knows it still gets in.",
            'effets' => [
                "erases both the SSH password and the root password from the RootWarden database",
                "after this action, RootWarden's only access to this machine is the platform key",
                "« Re-enter » gives back only the SSH password: the root password can only be rewritten from the Servers page",
            ],
        ],
        'revoquer' => [
            'titre' => "Take back the root administration access",
            'texte' => "This action opens an SSH session and DELETES the administration account on the machine. It is the counterpart of the deployment, and it cannot be undone without deploying again.",
            'effets' => [
                "removes /etc/sudoers.d/rootwarden, then deletes the Unix account « rootwarden » and its home directory",
                "THEN checks that the account is really gone, and records success only in that case — the verdict comes from the effect, not from the deletion's return code",
                "after this action RootWarden can no longer become root THROUGH THAT ACCOUNT; if the root password was erased, nothing on this page gives it back",
                "WHAT THE ACTION LEAVES IN PLACE: the platform key stays authorized on the nominal account AND on root, because the deployment writes it there too. It removes ONE door out of THREE.",
                "it therefore does NOT answer a compromised key, despite what its name suggests: the only remedy for a compromised key is to rotate it, and that action is not ported here",
                "the action requires a second administrator's approval",
            ],
        ],
        'ressaisir' => [
            'titre' => "Store an SSH password again",
            'texte' => "This action writes to the database and does not touch the machine. It restores only half of what the erasure removed.",
            'effets' => [
                "stores the SSH user's password again, encrypted",
                "does NOT store the root password again — no backend route writes it",
                "the root password is re-entered from the Servers page of the legacy portal",
            ],
        ],
    ],
    'panneau_cible_une' => "Target machine: :nom",
    'panneau_cible_n' => ":n target machines: :noms",
    'panneau_prod' => "⚠ This scope contains PRODUCTION: :noms",
    // ── Taking back the administration account ───────────────────────────
    // The route has existed in the backend since the A04-INSEC-N5 fix and had
    // NO caller at all. Since P3 makes the grant available in one click, so is
    // taking it back: shipping one without the other ships a door with no
    // handle on the inside.
    'btn_revoquer' => "Delete the administration account",
    'parc_btn_revoquer' => "Delete the administration account on :n machine(s)",
    'champ_motif' => "Reason for taking it back",
    'champ_motif_aide' => "It is recorded in the audit log together with the machine name. The backend truncates it at 200 characters.",
    'motif_vide' => "No reason entered: nothing was sent. This action removes an access; it is not recorded without a reason.",
    'geste_approbation_attente' => "Nothing has been removed yet: this action requires a second administrator's approval. The request has been created — it is handled from the Approvals page.",
    'geste_approbation_absente' => "Nothing was removed, and the action is BLOCKED: dual approval is required for it and no second administrator is available to give it. What the server reports: :message",
    'revoquer_asymetrie' => "This page can GRANT permanent root access from role 1 upwards, with the permission. Taking it back is restricted to role 3: the backend route requires it. Your account can therefore grant that access and cannot remove it — this is an asymmetry in the application, it is not fixed here, and it is stated rather than left to be discovered.",
    // ── THE LIMITS, PER ACTION ───────────────────────────────────────────
    // Stated INSIDE the decision panel, not in a log: a warning that arrives
    // after the click has not warned.
    'bornes' => [
        'revoquer' => "This action may FAIL precisely on the machines it exists to protect. It connects with the nominal account's key, never with the administration account, then elevates using the root password — and the only state in which that password is empty is exactly the state in which the administration account exists: the erasure REFUSES to run until that account is deployed. The two conditions are therefore not independent, they are linked. This is not a risk to the machine: the command is sent as a single block and stops at the first error, so either everything is removed or nothing is, and the screen says which. It is an unavailability of the action, not a half-done action. Reported to the backend owner.",
        'compte_service' => "This retry may FAIL on a machine whose administration account was deleted AFTER the passwords were erased: neither a root password nor an administration account is then left to elevate through. The « delete then redeploy » round trip is not symmetric. Same cause as above, same report.",
    ],
];
