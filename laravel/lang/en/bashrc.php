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

    'non_porte_titre' => 'The deployment gestures are not ported yet',
    'non_porte_texte' => 'Choosing accounts, previewing the file and deploying it are done from the '
                         . 'legacy portal for now. This page carries the inventory and the access '
                         . 'guards; the gestures follow.',
    'non_porte_lien'  => 'Open deployment in the legacy portal',
];
