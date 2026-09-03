<?php

/*
 * Module `ssh/` — « Cles SSH ». Sous-lot K1 : la page nue.
 *
 * `serveurs_disponibles` porte un jeton `:nombre` REELLEMENT substitue. Le legacy
 * ecrit `count($machines)` puis `t('ssh.servers_available')`, dont la valeur est
 * « :count serveur(s) disponible(s) » : le jeton reste en clair a l'ecran.
 */

return [
    'titre' => 'Deploiement des cles SSH',
    'description' => "Selectionnez les serveurs sur lesquels deployer les cles publiques des comptes habilites. Le deploiement lui-meme reste sur l'ancien portail.",
    'serveurs_disponibles' => ':nombre serveur(s) disponible(s)',

    'aucun_serveur' => 'Aucun serveur accessible',
    'aucun_serveur_aide' => "Aucune machine ne vous est attribuee, ou toutes celles du parc sont archivees.",

    'filtre_tag' => 'Etiquette',
    'filtre_env' => 'Environnement',
    'tous_tags' => 'Toutes les etiquettes',
    'tous_envs' => 'Tous les environnements',
    'cocher_filtre' => 'Cocher le filtre',
    'cocher_tout' => 'Cocher tout',
    'decocher_tout' => 'Tout decocher',

    'aucune_selection' => 'Aucun serveur selectionne',
    'selection' => ':nombre serveur(s) selectionne(s)',

    'deployer' => 'Deployer les cles',
    'annuler' => 'Annuler',
    'confirmer_titre' => 'Deployer les cles SSH sur ces serveurs ?',
    'confirmer_avertissement' => "Sur chaque serveur coche, et en tant que root : le paquet sudo est installe s'il manque, les comptes habilites sont crees, leur fichier authorized_keys est REECRIT, et une politique sudoers est posee. Les cles de tout compte ayant perdu son habilitation sont REVOQUEES. Rien de tout cela n'est reversible depuis cette page.",
    /*
     * ⚠ UNE CONJONCTION DONT UN MEMBRE EST DEVENU FAUX.
     *
     *   avant  « Le declenchement du deploiement ET LA LECTURE DE SON JOURNAL
     *            ne sont pas encore portes. »
     *
     *   mesure du 2026-09-03, croisement geste par geste :
     *     /deploy   NON appelee   -> la premiere moitie est VRAIE
     *     /logs     EXACTE        -> la seconde est FAUSSE
     *       `ClesSshController.php:93`  'url_journal' => url('/api/gateway/logs')
     *       `cles-ssh.js:390`           await fetch(L.url_journal, …)
     *
     * **Une phrase qui dit « A et B ne sont pas portes » se lit comme
     * entierement vraie quand seul A l'est encore.** Septieme occurrence de
     * cette forme, apres `serveurs`, `bashrc`, `fail2ban`, `ssh_audit`,
     * `groups` et `superv`.
     *
     * ⚠ ET UNE URL FOURNIE N'EST PAS UNE URL LUE — la distinction a deja
     * coute une mesure. C'est le `fetch` qui tranche, pas le passage de la
     * variable au gabarit.
     *
     * `description` porte la meme idee en plus court — « le deploiement
     * lui-meme reste sur l'ancien portail » — et elle est JUSTE. *La
     * formulation qui a survecu est celle qui n'affirmait qu'UNE chose : une
     * conjonction est un pari sur la stabilite de DEUX faits.*
     */
    'non_porte' => "Le declenchement du deploiement n'est pas encore porte : il reste sur l'ancien portail.",
    'non_porte_lien' => "Les lancer depuis l'ancien portail",
    // ── Le constat avant deploiement (sous-lot K2) ──────────────────────────
    'verifier' => 'Verifier les prerequis',
    'verifier_aide' => "Interroge les serveurs coches en LECTURE seule et rend un constat. Ne deploie rien.",
    'verif_en_cours' => 'Verification en cours...',
    'verif_echec' => 'La verification a echoue (code :statut)',
    'verif_non_concluante' => "La verification n'est pas concluante : le serveur n'a pas rendu de verdict. Rien n'est affiche ci-dessous, parce qu'un resultat partiel se lirait comme une verification reussie.",
    'verif_pret' => 'Aucun prerequis manquant',
    'verif_bloque' => ':nombre serveur(s) bloque(s) : corrigez ci-dessous ou decochez-les',
    'cles_aucune' => "ATTENTION : aucun compte actif ne porte de cle SSH. Un deploiement ne POSERAIT aucune cle — mais il REVOQUERAIT quand meme les acces listes ci-dessous : la revocation ne depend d'aucune cle.",
    'cles_nombre' => ':nombre compte(s) actif(s) avec une cle SSH',
    'inventaire' => ':nombre compte(s) inventorie(s) sur ce serveur',
    'revoques_synthese' => "Acces qui seront REVOQUES sur le parc coche — :nombre au total : :noms",
    'inventaire_non_lu' => "L'inventaire des comptes n'a pas pu etre lu sur cette machine : on ne sait pas quels acces seraient revoques. L'absence de liste ci-dessous ne veut donc PAS dire qu'il n'y en a aucun.",
    'machines_sans_resultat' => "Machines cochees sans resultat : :nombre. Elles ne sont comptees ni bloquantes ni pretes.",
    'badge_ok' => "OK",
    'badge_echec' => "ECHEC",
    'badge_partiel' => "PARTIEL",
    'a_creer' => 'Comptes qui seront crees :',
    'a_revoquer' => 'Acces qui seront REVOQUES (cle retiree, compte conserve) :',
    'lien_comptes_distants' => 'Ouvrir Utilisateurs distants',
    // ── Le journal du deploiement (sous-lot K3) ─────────────────────────────
    'journal' => 'Voir le journal du dernier deploiement',
    'journal_aide' => "Lit le journal deja ecrit. Ne joint aucun serveur et ne declenche rien.",
    'journal_ouverture' => 'Lecture du journal...',
    'journal_vide' => 'Le journal est vide : aucun deploiement n\'a encore ete lance.',
    'journal_fin' => '— fin du journal —',
    'journal_refus' => 'Le journal a ete refuse par le serveur (code :statut)',
    'journal_interrompu' => "Le flux s'est interrompu avant la fin du journal : ce qui precede est incomplet",
];
