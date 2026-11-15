<?php

/*
 * Cles SSH : deploiement des cles publiques sur le parc.
 *
 * `serveurs_disponibles` porte un jeton `:nombre` REELLEMENT substitue.
 * Redaction : docs/REDACTION-INTERFACE.md.
 */

return [
    'titre' => 'Déploiement des clés SSH',
    'description' => "Sélectionnez les serveurs, vérifiez les prérequis, puis déployez les clés publiques des comptes habilités.",
    'serveurs_disponibles' => ':nombre serveur(s) disponible(s)',

    'aucun_serveur' => 'Aucun serveur accessible',
    'aucun_serveur_aide' => "Aucune machine ne vous est attribuée, ou toutes celles du parc sont archivées.",

    'filtre_tag' => 'Étiquette',
    'filtre_env' => 'Environnement',
    'tous_tags' => 'Toutes les étiquettes',
    'tous_envs' => 'Tous les environnements',
    'cocher_filtre' => 'Cocher le filtre',
    'cocher_tout' => 'Cocher tout',
    'decocher_tout' => 'Tout décocher',

    'aucune_selection' => 'Aucun serveur sélectionné',
    'selection' => ':nombre serveur(s) sélectionné(s)',

    'deployer' => 'Déployer les clés',
    'annuler' => 'Annuler',
    'confirmer_titre' => 'Déployer les clés SSH sur ces serveurs ?',
    'confirmer_avertissement' => "Sur chaque serveur coché, en root : sudo est installé s'il manque, les comptes habilités sont créés, leur authorized_keys est réécrit et une politique sudoers est posée. Les clés des comptes qui ont perdu leur habilitation sont révoquées, sans retour possible depuis cette page.",

    // ── Le constat avant deploiement ────────────────────────────────────────
    'verifier' => 'Vérifier les prérequis',
    'verifier_aide' => "Interroge les serveurs cochés en lecture seule. Ne déploie rien.",
    'verif_en_cours' => 'Vérification en cours…',
    'verif_echec' => 'La vérification a échoué (code :statut)',
    'verif_non_concluante' => "Vérification non concluante : le serveur n'a pas rendu de verdict.",
    'verif_pret' => 'Aucun prérequis manquant',
    'verif_bloque' => ':nombre serveur(s) bloqué(s) : corrigez ci-dessous ou décochez-les',
    // DeploiementCles refuse le deploiement quand `users_with_keys` vaut zero.
    'cles_aucune' => "Aucun compte actif ne porte de clé SSH : le déploiement sera refusé. Ajoutez une clé à au moins un compte.",
    'cles_nombre' => ':nombre compte(s) actif(s) avec une clé SSH',
    'inventaire' => ':nombre compte(s) inventorié(s) sur ce serveur',
    'revoques_synthese' => "Accès qui seront révoqués sur les serveurs cochés — :nombre au total : :noms",
    'inventaire_non_lu' => "L'inventaire des comptes n'a pas pu être lu sur cette machine : les accès qui seraient révoqués sont inconnus.",
    'machines_sans_resultat' => "Machines cochées sans résultat : :nombre. Elles ne sont comptées ni bloquantes ni prêtes.",
    'badge_ok' => "OK",
    'badge_echec' => "ÉCHEC",
    'badge_partiel' => "PARTIEL",
    'a_creer' => 'Comptes qui seront créés :',
    'a_revoquer' => 'Accès qui seront révoqués (clé retirée, compte conservé) :',
    'sans_cle' => 'Comptes autorisés sans clé pour cette machine — leurs clés y seront retirées :',
    'lien_comptes_distants' => 'Ouvrir les comptes distants',

    // ── Le journal du deploiement ───────────────────────────────────────────
    'journal' => 'Voir le journal du dernier déploiement',
    'journal_aide' => "Lit le journal déjà écrit. Ne joint aucun serveur.",
    'journal_ouverture' => 'Lecture du journal…',
    'journal_vide' => "Le journal est vide : aucun déploiement n'a encore été lancé.",
    'journal_fin' => '— fin du journal —',
    'journal_refus' => 'Le journal a été refusé par le serveur (code :statut)',
    'journal_interrompu' => "Le flux s'est interrompu avant la fin du journal : ce qui précède est incomplet.",

    // ── Les refus du declenchement ──────────────────────────────────────────
    // Chaque message dit ce qui n'a PAS ete fait : relancer a l'aveugle peut
    // revoquer des acces.
    'err_aucune_machine' => "Aucune machine sélectionnée.",
    'err_backend_injoignable' => "Le service de déploiement est injoignable. Rien n'a été déployé.",
    'err_preflight_refuse' => "La vérification avant déploiement a été refusée. Rien n'a été déployé.",
    'err_preflight_sans_resultat' => "La vérification avant déploiement n'a rendu aucun résultat. Rien n'a été déployé.",
    'err_preflight_echoue' => "Vérification en échec pour : :machines. Rien n'a été déployé : corrigez ces machines ou décochez-les.",
    'err_aucun_compte_avec_cle' => "Aucun compte actif ne porte de clé SSH sur ce parc : le déploiement retirerait tous les accès. Rien n'a été déployé ; ajoutez une clé à au moins un compte.",
];
