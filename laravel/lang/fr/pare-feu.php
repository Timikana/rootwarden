<?php

/**
 * Pare-feu iptables. Regles de redaction : docs/REDACTION-INTERFACE.md.
 *
 * Aucun texte ne doit annoncer un acces plus strict que celui qui est applique.
 */

return [
    'titre' => 'Pare-feu',
    'intro' => "Relever, valider, appliquer et restaurer les règles iptables d'une machine.",

    // ── Le choix de la machine ──────────────────────────────────────────
    'serveur' => 'Machine',
    'choisir' => 'Choisissez une machine, puis relevez ses règles.',
    'relever' => 'Relever les règles',
    'aucune_machine_choisie' => 'Choisissez d\'abord une machine.',
    'machines_aucune_titre' => 'Aucune machine ne vous est accessible',
    'machines_aucune' => 'Demandez un accès à un administrateur.',

    // ── Ce que la page annonce AVANT le geste ───────────────────────────
    'sensible' => 'Production',
    'sensible_avert' => 'Machine en production ou critique : relever ses règles ne les modifie pas, les gestes suivants si.',
    'avert_titre' => 'Une machine de production figure dans cette liste',
    'avert_un' => 'Une des :total machines est en production ou critique.',
    'avert_plusieurs' => ':nb des :total machines sont en production ou critiques.',

    /*
     * Le port SSH est annoncé au moment du choix, et il vient de la BASE.
     * Les gabarits de règles du legacy supposent 22 ; les trois machines du parc
     * écoutent sur 22, donc le défaut n'est pas armé — et c'est ce qui le rend
     * invisible. L'annoncer maintenant, c'est refuser de le reproduire plus tard.
     */
    'port_ssh_annonce' => "Accès SSH de cette machine : port :port. Un jeu de règles qui ferme ce port couperait l'accès, y compris celui de RootWarden.",

    // ── Le relevé ───────────────────────────────────────────────────────
    'chargement' => 'Lecture des règles sur la machine…',
    'releve_ok' => 'Règles relevées sur :machine.',
    'releve_le' => 'Relevé le :date',
    'echec' => 'Les règles n\'ont pas pu être lues. La machine est-elle joignable ?',
    'echec_reseau' => "La requête n'a pas abouti : rien n'a été lu.",

    // ── Les quatre blocs ────────────────────────────────────────────────
    'bloc_actives_v4' => 'Règles actives (IPv4)',
    'bloc_actives_v6' => 'Règles actives (IPv6)',
    'bloc_fichier_v4' => 'Fichier rules.v4',
    'bloc_fichier_v6' => 'Fichier rules.v6',

    /*
     * Trois issues, pas deux : la lecture échoue, le fichier est absent, le
     * fichier existe et il est vide. Le legacy n'en distingue aucune — il pose
     * la réponse dans un bloc et le marqueur fabriqué par le shell y devient le
     * contenu du fichier (même défaut qu'E-161 sur fail2ban).
     */
    'bloc_vide_titre' => 'Aucune règle',
    'bloc_vide' => 'La machine n\'applique aucune règle sur cette pile. Tout est accepté par défaut.',
    'fichier_absent_titre' => 'Fichier absent',
    'fichier_absent' => "Ce fichier n'existe pas sur la machine : les règles actives ne seront pas rétablies au redémarrage.",

    // ── I2 : la copie en base ───────────────────────────────────────────
    'copie_titre' => 'Copie enregistrée',
    'copie_intro' => "Le portail peut garder une copie des règles d'une machine. L'enregistrer ne la valide pas et ne l'applique pas.",
    'copie_charger' => 'Charger la copie',
    'copie_enregistrer' => 'Enregistrer ces règles',
    'copie_absente' => 'Aucune copie enregistrée pour cette machine.',
    'copie_le' => 'Copie enregistrée le :date',
    'copie_enregistree' => 'Copie enregistrée pour :machine. Elle n\'a été ni validée, ni appliquée.',
    'copie_rien_a_enregistrer' => 'Relevez d\'abord les règles : il n\'y a rien à enregistrer.',
    'copie_v4_vide' => "Les règles IPv4 sont vides : une copie vide ne pourrait pas être restaurée, elle n'est pas enregistrée.",
    'copie_trop_grande' => "Les règles dépassent la taille maximale (:max octets). Rien n'a été enregistré.",
    'champs_manquants' => 'Requête incomplète : les deux jeux de règles sont attendus, même vides.',
    'machine_refusee' => 'Machine inconnue ou hors de votre périmètre.',
    'copie_lignes_multiples' => 'Attention : :nb copies existent pour cette machine. La plus récente est affichée.',
    'copie_bloc_v4' => 'Copie IPv4',
    'copie_bloc_v6' => 'Copie IPv6',

    // ── I3 : l'historique des versions archivées ────────────────────────
    'histo_titre' => 'Versions archivées',
    'histo_intro' => "Chaque application archive les règles qu'elle remplace, sauf si elles étaient vides. Toutes les versions listées sont restaurables.",
    'histo_chargement' => 'Lecture de l\'historique…',
    'histo_vide_titre' => 'Aucune version archivée',
    'histo_vide' => "Aucune règle n'a encore été appliquée sur cette machine depuis ce portail : rien à restaurer.",
    'histo_echec_titre' => 'Historique illisible',
    'histo_echec' => "L'historique n'a pas pu être lu : ne concluez pas qu'il n'y a rien à restaurer.",
    'histo_tout' => ':nb version(s) archivée(s).',
    'histo_tronque' => 'Les :affichees plus récentes, sur :total au total.',
    'histo_col_date' => 'Archivée le',
    'histo_col_auteur' => 'Par',
    'histo_col_motif' => 'Motif',
    'histo_auteur_inconnu' => 'Auteur non enregistré',
    'histo_auteur_supprime' => 'Compte supprimé (n° :id)',
    'histo_sans_motif' => 'Aucun motif indiqué',

    // ── I4 : la validation à blanc ──────────────────────────────────────
    'valid_titre' => 'Validation à blanc',
    'valid_intro' => "Vérifie qu'un jeu de règles est applicable, sans l'appliquer.",
    'valid_bouton' => 'Valider la copie à blanc',
    'valid_avant' => "Ce contrôle ouvre une session SSH et écrit un fichier temporaire sur la machine ; il ne modifie pas le pare-feu.",
    'valid_limite' => "Seules les règles IPv4 sont vérifiées : une erreur dans l'IPv6 passerait ce contrôle et échouerait à l'application.",
    'valid_v4_vide' => "Cette copie ne porte aucune règle IPv4 : rien à valider.",
    'valid_sans_copie' => 'Chargez d\'abord la copie en base : c\'est elle qui est validée.',
    'valid_en_cours' => 'Validation en cours sur la machine…',
    'valid_ok' => 'Le serveur déclare ces règles applicables.',
    'valid_invalide_court' => 'Le serveur déclare ces règles invalides : lisez la sortie ci-dessous.',
    'valid_invalide_titre' => 'Règles déclarées invalides',
    'valid_invalide' => 'Le serveur déclare ces règles invalides. Lisez la sortie avant de corriger.',
    'valid_echec_titre' => 'Contrôle non abouti',
    'valid_echec' => "Le contrôle n'a pas abouti : rien n'a été vérifié.",
    'valid_sortie' => 'Sortie du serveur',

    /* ══ Q3 — LES HUIT TITRES QUE `rwRetourPareFeu()` RENVOIE ══════════════════
     *
     * ⚠ CES HUIT CLES ETAIENT CITEES PAR `pare-feu-retour-visible.js` ET
     * N'EXISTAIENT NULLE PART. Mesure du 2026-09-08 : 8 citees, 0 au catalogue.
     * Q3 est « totale » — elle rend toujours un titre — mais un titre qui ne
     * DESIGNE rien satisfait toute assertion de forme tout en s'affichant nu.
     *
     * Chaque libelle DECRIT LE CALCUL de son cas, pas l'humeur du moment :
     *   inabouti / refus / erreur_serveur / corps_illisible  ->  `sur: false`
     *   -> ces quatre disent « je ne sais pas », JAMAIS « ca a echoue ».
     */
    'ipt_retour_succes'           => 'Les règles ont été appliquées.',
    'ipt_retour_regles_invalides' => "Le serveur a refusé ces règles : rien n'a été appliqué, et l'état de la machine n'a pas changé.",
    'ipt_retour_refus'            => "La demande a été refusée avant tout contrôle des règles. Rien n'a été appliqué.",
    'ipt_retour_erreur_serveur'   => "Le serveur a échoué avant de répondre. Rien ne permet de dire si les règles ont été appliquées : relevez l'état de la machine avant de réessayer.",
    'ipt_retour_corps_illisible'  => "Le serveur a répondu, mais sa réponse est illisible. Le geste est peut-être passé : relevez l'état de la machine avant de réessayer.",
    'ipt_retour_inabouti'         => "La demande n'est pas partie. Rien n'a été appliqué.",
    'ipt_retour_doute_marqueur'   => "Le serveur signale que son verdict n'est pas fondé. Ne le lisez ni comme un succès ni comme un échec : relevez l'état de la machine.",
    'ipt_retour_contrat_inconnu'  => "La réponse ne correspond à aucun cas prévu. Relevez l'état de la machine plutôt que de supposer.",

    /* ══ I5 — L'ECRAN D'APPLICATION ════════════════════════════════════════════ */
    'appl_titre'      => 'Appliquer un jeu de règles',
    'appl_intro'      => "Le jeu choisi remplace toutes les règles de la machine (iptables-restore). La version précédente est archivée avant l'écriture.",
    'appl_gabarit'    => 'Jeu de règles',
    'appl_gabarit_aide' => 'Le port SSH vient de la machine choisie, il n\'est jamais supposé à 22.',
    'appl_apercu'     => 'Ce qui sera appliqué',
    'appl_ssh_ouvert' => 'Le port SSH :port reste joignable avec ce jeu.',
    'appl_ssh_ferme'  => "⛔ Ce jeu ferme le port SSH :port : appliqué, il vous couperait l'accès, et seule une console physique permettrait de revenir.",
    'appl_ssh_doute'  => "⛔ Impossible de dire si le port SSH :port reste ouvert avec ce jeu : l'application est refusée.",
    'appl_bouton'     => 'Appliquer sur la machine',
    'appl_en_cours'   => 'Application en cours…',
    'appl_conf_titre' => 'Remplacer les règles de :machine ?',
    'appl_conf_texte' => "Toutes les règles actuelles de :machine seront remplacées par le jeu « :gabarit ». La version précédente est archivée et restaurable depuis l'historique.",
    'appl_conf_ok'    => 'Remplacer les règles',
    'appl_conf_non'   => 'Annuler',
    'appl_annule'     => "Annulé — aucune requête n'a été envoyée.",

    /* ══ I6 — LE RETOUR ARRIERE ════════════════════════════════════════════════
     *
     * ⚠ POURQUOI CE GESTE EST PLUS DANGEREUX QUE L'APPLICATION, ET NON MOINS.
     *
     *   APPLIQUER       l'operateur ECRIT les regles : il les a sous les yeux
     *   RETOUR ARRIERE  l'operateur choisit une DATE : il ne peut pas se relire
     *
     * `iptables_history` ne porte AUCUN port, et une version archivee etait valide
     * LE JOUR DE SON ARCHIVAGE. Si le port SSH a change depuis — c'est-a-dire si
     * quelqu'un a suivi le durcissement qu'on prescrit — la restaurer FERME
     * l'acces. Q2 se calcule donc sur le port ACTUEL, jamais sur celui de
     * l'archive.
     *
     * Les deux premieres cles sont rendues par le SERVEUR (message JSON) : elles
     * n'ont pas a voyager jusqu'au JS.
     */
    'rb_version_absente'     => 'Aucune version désignée.',
    'rb_version_introuvable' => "Cette version est introuvable pour cette machine.",
    'rb_titre'      => 'Retour arrière',
    'rb_bouton'     => 'Revenir à cette version',
    'rb_lecture'    => 'Lecture de la version archivée…',
    'rb_lecture_echec' => "La version n'a pas pu être lue. Rien n'a été restauré.",
    'rb_apercu'     => 'Ce qui sera restauré',
    'rb_archive_le' => 'Version archivée le :date',
    'rb_ssh_ouvert' => "Le port SSH :port, celui de la machine aujourd'hui, reste joignable avec cette version.",
    'rb_ssh_ferme'  => "⛔ Cette version ferme le port SSH actuel :port : restaurée maintenant, elle vous couperait l'accès.",
    'rb_ssh_doute'  => "⛔ Impossible de dire si cette version laisse le port SSH :port ouvert : la restauration est refusée.",
    'rb_conf_titre' => 'Restaurer la version du :date sur :machine ?',
    'rb_conf_texte' => "Les règles actuelles de :machine seront remplacées par cette version. L'état actuel est archivé avant l'écriture : ce retour arrière se défait.",
    'rb_conf_ok'    => 'Restaurer cette version',
    'rb_conf_non'   => 'Annuler',
    /*
     * LA VALIDATION AVANT LE RETOUR ARRIERE — DEUX REFUS, DEUX PHRASES.
     *
     * « invalide » est une ACCUSATION : elle porte sur les regles, et elle doit
     * etre vraie. « indecidable » est un AVEU : rien n'a ete verifie. Les deux
     * refusent ; les confondre userait la garde, parce que l'operateur qui sait
     * son jeu bon apprendrait qu'elle se trompe.
     */
    'rb_valid_en_cours'   => 'Vérification de cette version sur la machine…',
    'rb_valid_invalide'   => "⛔ Version refusée : la machine ne peut pas la charger. Restaurée, elle écraserait le fichier de règles et la machine redémarrerait sans pare-feu. Rien n'a été appliqué.",
    'rb_valid_indecidable' => "⚠ Restauration refusée : la vérification n'a pas abouti (:motif). Rien n'a été appliqué.",
    'rb_en_cours'   => 'Restauration en cours…',
    'rb_annule'     => "Annulé — aucune requête n'a été envoyée.",
];
