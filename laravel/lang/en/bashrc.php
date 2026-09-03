<?php

/**
 * Standardised `.bashrc` deployment — sub-batch B1.
 *
 * This module has NO security defect (see `MODULE-BASHRC.md` §3). The three
 * corrections the port makes are about PRESENTATION, and these strings carry two
 * of them: telling the production machine apart, and stating a zero counter
 * rather than showing it as a digit.
 */

return [
    'titre'       => '.bashrc deployment',
    'intro'       => 'This page installs a standardised `.bashrc` file on the accounts of the '
                     . 'machines you choose. That file runs on EVERY login of those accounts.',
    'onglet_deploiement' => 'Deployment',
    'onglet_historique'  => 'History',
    'onglet_gabarit'     => 'Template',

    // ── THE ESTATE ─────────────────────────────────────────────────────────
    'machines'        => 'Target machines',
    'col_nom'         => 'Machine',
    'col_ip'          => 'Address',
    'col_etat'        => 'Last deployment',
    'jamais'          => 'never deployed',
    'simule_le'       => 'simulated on :date by :auteur — nothing was written',
    'deploye_le'      => 'deployed on :date by :auteur',

    // ── THE SENSITIVE MACHINE, WHICH MUST NOT BLEND INTO THE LIST ─────────
    'sensible'        => 'Production',
    'sensible_titre'  => 'Production or critical machine',
    'sensible_aide'   => 'Deploying to this machine replaces the `.bashrc` of the chosen accounts, '
                         . 'including `root`\'s if it is selected.',
    'avert_titre'     => 'A production machine is in this list',
    'avert_un'        => 'One of the :total machines offered is in production or marked critical. '
                         . 'It is flagged in the table.',
    'avert_plusieurs' => ':nb of the :total machines offered are in production or marked critical. '
                         . 'They are flagged in the table.',

    // ── THE COUNTER, WHICH IS STATED ───────────────────────────────────────
    'aucune_selection' => 'No machine selected — a deployment would deploy nothing.',
    'selection_une'    => '1 machine selected.',
    'selection_n'      => ':nb machines selected.',
    'selection_prod'   => ':nb machines selected, :prod of them in production.',

    'vide_titre'  => 'No machine in the estate',
    'vide_texte'  => 'No active machine is registered. Add one from server administration before '
                     . 'deploying anything.',
    'vide_action' => 'Open servers',

    'comptes_titre' => 'Machine accounts',
    'comptes_choisir' => 'Tick one machine above to read its accounts.',
    'comptes_plusieurs' => 'Several machines are ticked. Accounts are read one machine at a time: tick only one.',
    'comptes_chargement' => 'Reading accounts on the machine…',
    'comptes_echec' => 'The accounts could not be read. Is the machine reachable?',
    'comptes_aucun' => 'This machine exposes no eligible account (UID 0 or >= 1000, with a shell).',
    'col_compte' => 'Account',
    'col_uid' => 'UID',
    'col_home' => 'Home directory',
    'col_bashrc' => 'Current file',
    'bashrc_absent' => 'absent',
    'tout' => 'Tick all',
    'tout_avec_root' => '"Tick all" also selects root.',
    'compte_root' => 'administrator',
    'compte_root_aide' => 'The machine\'s administrator account. Deploying to root replaces the file that runs on every administrator login.',
    'apercu' => 'Preview (diff)',
    'apercu_aide' => 'Reads the file present on the machine and shows what would change. Writes nothing.',
    'apercu_titre' => 'What would change',
    'apercu_chargement' => 'Reading the remote file…',
    'apercu_echec' => 'The preview could not be built.',
    'apercu_vide' => 'Tick at least one account to see what would change.',
    'apercu_taille' => ':avant o → :apres o',

    'perso' => 'customised',
    'perso_aide' => 'This account has blocks marked "USER CUSTOM" in its file. In "merge" mode those are the ONLY parts kept; everything else is replaced.',

    'gabarit_titre' => 'The deployed template',
    'gabarit_intro' => 'This file is the one every machine will receive at the next deployment. It runs on every login of the accounts concerned.',
    'gabarit_lignes' => 'Lines',
    'gabarit_octets' => 'Bytes',
    'gabarit_sha' => 'Fingerprint',
    'gabarit_chargement' => 'Reading the template…',
    'gabarit_echec' => 'The template could not be read.',
    'gabarit_modifie' => 'Unsaved changes.',
    'gabarit_enregistrer' => 'Save',
    'gabarit_annuler' => 'Discard changes',
    'gabarit_enregistre' => 'Template saved.',
    'gabarit_erreur' => 'Saving failed.',
    'gabarit_encours' => 'Saving…',
    'gabarit_confirmer' => 'Save this template? Every machine will receive it at the next deployment.',
    'danger_titre' => 'Forms recognised as destructive',
    'danger_reconnu' => 'Recognised:',
    'danger_portee' => 'This recognition covers eight known forms. It checks neither what the rest of the file does, nor what this one will do once deployed — only its syntax is checked on saving.',
    'danger_confirmer' => 'This template contains forms recognised as destructive. Save it anyway?',

    /* See the note in `lang/fr/bashrc.php`: the enumeration is the single
     * source, and it is paired against the 7 routes of
     * `backend/routes/bashrc.py`. Called by this page: `users`, `preview`,
     * `template`. Called by nobody, hence absent: `deploy`, `prerequisites`
     * (POST -- it INSTALLS), `restore`, `backups`. */
    'non_porte_titre' => 'The deployment gestures are not ported yet',
    'non_porte_texte' => 'Deploying itself, installing the prerequisites, restoring an earlier '
                         . 'version and listing the backups are done from the legacy portal for '
                         . 'now.',
    'non_porte_lien'  => 'Open deployment in the legacy portal',
];
