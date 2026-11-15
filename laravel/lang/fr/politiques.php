<?php

/**
 * Droits sudo par compte distant.
 *
 * ATTENTION AVANT DE MODIFIER UNE AIDE DE PREREGLAGE. Ces textes decrivent une
 * portee de privileges. `tests/e2e/go-adm-politiques.mjs` relit
 * `backend/sudo_manager.py` dans le conteneur a chaque execution et refuse que
 * l'ecran le contredise : l'aide d'un prereglage classe 'root' doit dire root.
 * Redaction : docs/REDACTION-INTERFACE.md.
 */

return [
    'titre'          => 'Droits sudo par compte distant',
    'intro'          => "Choisissez ce qu'un compte distant peut exécuter en root sur une machine. Rien n'est écrit avant votre confirmation.",
    'machine'        => 'Machine',
    'compte'         => 'Compte distant',
    'aucun_compte'   => 'Aucun compte géré sur cette machine',
    'vide_titre'     => 'Aucun compte à qui accorder des droits',
    'vide_texte'     => "Cette machine n'a aucun compte « géré » ou « à examiner ». Lancez un inventaire depuis les comptes distants, puis classez les comptes.",
    'vide_action'    => 'Ouvrir les comptes distants',

    'choix'          => 'Ce que le compte pourra faire',
    'prereglage'     => 'Préréglage',
    'regles_libres'  => 'Règles saisies',
    'regles_aide'    => "Une règle par ligne, au format sudoers. Seule la syntaxe est vérifiée, pas la portée.",
    'services'       => 'Services autorisés',
    'services_aide'  => 'Séparés par des virgules.',
    'nopasswd'       => 'Sans demander de mot de passe (NOPASSWD)',
    'nopasswd_aide'  => "Aucun mot de passe ne sera demandé pour ces commandes.",
    'runas'          => 'Exécuter en tant que',

    // ── La portee, telle que sudo_manager.py la documente ──────────────────
    'portee_root'         => 'Donne un accès root',
    'portee_root_detail'  => "Ce préréglage permet d'obtenir les pleins pouvoirs sur la machine.",
    'portee_borne'        => 'Portée bornée',
    'portee_borne_detail' => 'Liste de commandes fermée.',
    'portee_inconnu'         => 'Portée non analysée',
    'portee_inconnu_detail'  => 'Vous écrivez la règle ; seule sa syntaxe est vérifiée.',

    'aide_all_nopasswd'       => "Toutes les commandes en root. À réserver aux comptes de service.",
    'aide_apt_only'           => "Autorise apt à installer et mettre à jour des logiciels. Équivaut à un accès root : un paquet fabriqué peut ouvrir un interpréteur root.",
    'aide_restart_services'   => "Redémarrer, recharger et consulter l'état de n'importe quel service systemd.",
    'aide_read_logs'          => "Lecture des journaux : tail et cat sous /var/log, journalctl sans pagination.",
    'aide_systemctl_specific' => "Redémarrer, recharger et consulter l'état des seuls services nommés ci-dessous.",
    'aide_custom'             => "Règles écrites à la main. Leur portée n'est pas analysée : elles peuvent donner root sans que rien ne le signale.",

    'preset_all_nopasswd'       => 'Accès root complet',
    'preset_restart_services'   => 'Redémarrage de services',
    'preset_apt_only'           => 'Mises à jour APT',
    'preset_read_logs'          => 'Lecture des journaux',
    'preset_systemctl_specific' => 'Services nommés',
    'preset_custom'             => 'Règles libres',

    // ── Les gestes ─────────────────────────────────────────────────────────
    'deployer'       => 'Déployer…',
    'auditer'        => 'Auditer',
    'retirer'        => 'Retirer…',
    'aide_deployer'  => "Écrit la configuration sur la machine, après validation de sa syntaxe.",
    'aide_auditer'   => "Lit le fichier présent sur la machine. Ne modifie rien.",
    'aide_retirer'   => "Supprime cette configuration de la machine ; le compte perd ces droits.",

    // ── Les confirmations ──────────────────────────────────────────────────
    'confirmer_titre'   => 'Confirmer le déploiement',
    'confirmer_intro'   => "Un fichier sudoers va être écrit sur la machine.",
    'confirmer_machine' => 'Machine',
    'confirmer_compte'  => 'Compte',
    'confirmer_portee'  => 'Ce que cela accorde',
    'confirmer_root'    => 'Ce préréglage donne un accès root à ce compte.',
    'confirmer_valider' => 'Déployer sur la machine',
    'confirmer_annuler' => 'Annuler',
    'retirer_titre'     => 'Confirmer le retrait',
    'retirer_intro'     => "Le fichier sudoers de ce compte sera supprimé de la machine. Le compte perdra ces droits.",
    'retirer_valider'   => 'Retirer de la machine',
    'reauth'            => "Une re-authentification vous sera demandée avant l'envoi.",

    // ── L'historique ───────────────────────────────────────────────────────
    'historique'        => 'Historique et restauration',
    'hist_date'         => 'Date',
    'hist_auteur'       => 'Par',
    'hist_etat'         => 'État',
    'hist_regle'        => 'Règle écrite',
    'hist_vide'         => 'Aucun déploiement enregistré pour ce compte.',
    'etat_applied'      => 'Appliquée',
    'etat_rolled_back'  => 'Annulée',
    'etat_failed'       => 'Échouée',
    'etat_superseded'   => 'Remplacée',
    'derniere'          => 'Dernière écriture',
    'jamais'            => 'jamais déployée',
    'rollback_titre' => 'Restaurer une version antérieure',
    'rollback_texte' => "Réécrit sur la machine le sudoers exact d'avant ce déploiement. Re-authentification exigée.",
    'resultat'          => 'Résultat',
    'rollback' => 'Annuler',
    'rollback_confirme' => "Annuler ce déploiement et réécrire sur la machine le sudoers précédent ? Une re-authentification sera demandée.",
];
