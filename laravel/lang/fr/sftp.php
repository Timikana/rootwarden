<?php

/**
 * Acces SFTP/SSH par compte distant.
 *
 * ATTENTION AVANT DE MODIFIER UNE AIDE. `tests/e2e/go-adm-sftp.mjs` apparie
 * chaque case a SON aide dans le DOM et refuse qu'une aide recommandant de
 * decocher accompagne une case cochee : l'ecran ne doit pas conseiller
 * l'inverse de ce qu'il livre. Redaction : docs/REDACTION-INTERFACE.md.
 */

return [
    'titre'        => 'Accès SFTP par compte distant',
    'intro'        => "Réglez ce qu'un compte distant peut faire en SSH : transfert de fichiers ou terminal, mot de passe, tunnels.",
    'machine'      => 'Machine',
    'compte'       => 'Compte distant',
    'aucun_compte' => 'Aucun compte géré sur cette machine',
    'vide_titre'   => 'Aucun compte à qui régler un accès',
    'vide_texte'   => "Cette machine n'a aucun compte « géré » ou « à examiner ». Lancez un inventaire depuis les comptes distants, puis classez les comptes.",
    'vide_action'  => 'Ouvrir les comptes distants',

    'options'      => 'Ce que le compte pourra faire en se connectant',

    // ── Ce que chaque reglage produit ──────────────────────────────────────
    'f_sftp_only'  => 'Transfert de fichiers uniquement (pas de terminal)',
    'h_sftp_only'  => "Le compte peut seulement envoyer et télécharger des fichiers.",
    'f_chroot'     => 'Cage (dossier racine)',
    'h_chroot'     => "Le compte ne voit que ce dossier. Chemin absolu, sans « .. » ; vide : pas de cage.",
    'f_working'    => "Dossier d'arrivée",
    // sftp_manager.py : en mode terminal, le dossier n'est inscrit qu'en commentaire.
    'h_working'    => "Appliqué seulement en transfert de fichiers uniquement.",
    'f_password'   => 'Autoriser la connexion par mot de passe',
    'h_password'   => "Inactif, une clé SSH est obligatoire.",
    'f_tcp'        => 'Autoriser les tunnels réseau (port forwarding)',
    'h_tcp'        => "Permet de faire passer d'autres connexions réseau à travers SSH.",
    'f_agent'      => 'Autoriser le rebond de clé (agent forwarding)',
    'h_agent'      => "Permet de réutiliser sa clé SSH pour rebondir vers une autre machine.",
    'f_x11'        => "Autoriser l'affichage graphique distant (X11)",
    'h_x11'        => "Permet d'ouvrir des fenêtres graphiques à travers SSH.",

    // ── L'etat de depart (AccesSftp::initial) ──────────────────────────────
    'neuve_titre'  => "Aucun accès n'est encore réglé pour ce compte",
    'neuve_texte'  => "Les réglages partent de la position la plus fermée : transfert de fichiers seul, clé SSH obligatoire, aucun tunnel.",
    'ouvre'        => "Élargit l'accès",
    'restreint'    => "Restreint l'accès",

    // ── Les gestes ─────────────────────────────────────────────────────────
    'deployer'      => 'Déployer…',
    'auditer'       => 'Auditer',
    'retirer'       => 'Retirer…',
    'aide_deployer' => "Écrit le bloc sur la machine, après validation de la configuration.",
    'aide_auditer'  => "Lit le bloc présent sur la machine. Ne modifie rien.",
    'aide_retirer'  => "Supprime ce bloc de la machine.",

    // ── Les confirmations ──────────────────────────────────────────────────
    'confirmer_titre'   => 'Confirmer le déploiement',
    'confirmer_intro'   => "Un bloc de configuration SSH va être écrit sur la machine. Pour ce compte, il remplace la configuration générale du serveur.",
    'confirmer_machine' => 'Machine',
    'confirmer_compte'  => 'Compte',
    'confirmer_effet'   => 'Ce que cela ouvre',
    'confirmer_ouvre'   => "Ces réglages élargissent l'accès de ce compte",
    'aucun_reglage_ouvert' => "aucun réglage n'élargit l'accès",
    'confirmer_valider' => 'Déployer sur la machine',
    'confirmer_annuler' => 'Annuler',
    'retirer_titre'     => 'Confirmer le retrait',
    'retirer_intro'     => "Le bloc de ce compte sera supprimé de la machine. Le compte retombera sur la configuration générale du serveur, qui peut être plus permissive.",
    'retirer_valider'   => 'Retirer de la machine',
    'reauth'            => "Une re-authentification vous sera demandée avant l'envoi.",

    // ── L'historique ───────────────────────────────────────────────────────
    'historique'       => 'Historique et restauration',
    'hist_date'        => 'Date',
    'hist_auteur'      => 'Par',
    'hist_etat'        => 'État',
    'hist_bloc'        => 'Bloc écrit',
    'hist_vide'        => 'Aucun déploiement enregistré pour ce compte.',
    'etat_applied'     => 'Appliqué',
    'etat_rolled_back' => 'Annulé',
    'etat_failed'      => 'Échoué',
    'etat_superseded'  => 'Remplacé',
    'derniere'         => 'Dernière écriture',
    'jamais'           => 'jamais déployé',
    'resultat'         => 'Résultat',
    'rollback_titre'   => 'Restaurer une version antérieure',
    'rollback_texte'   => "Réécrit sur la machine le bloc SSH exact d'avant ce déploiement. Re-authentification exigée.",
    'rollback' => 'Annuler',
    'rollback_confirme' => "Annuler ce déploiement et réécrire sur la machine le bloc SSH précédent ? Une re-authentification sera demandée.",
];
