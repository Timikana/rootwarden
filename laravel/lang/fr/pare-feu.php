<?php

/**
 * Pare-feu iptables — sous-lot I1.
 *
 * L'en-tete du legacy annonce « superadmin (role_id = 3) uniquement — accès
 * refusé à tous les autres rôles », deux fois, alors que sa garde admet le
 * rôle 1 (motif E-36, quatrième occurrence). Aucun texte de cette page ne doit
 * annoncer un accès plus strict que celui qui est appliqué.
 *
 * Et aucun ne doit laisser croire que `can_manage_iptables` protège les GESTES :
 * sur les 23 routes des deux modules de filtrage, deux seulement la vérifiaient
 * avant le correctif d'E-152. Elle protège l'écran.
 */

return [
    'titre' => 'Pare-feu',
    'intro' => 'Le pare-feu iptables décide quelles connexions une machine accepte. Cette page relève les règles actuellement en vigueur, sans rien modifier.',

    // ── Le choix de la machine ──────────────────────────────────────────
    'serveur' => 'Machine',
    'choisir' => 'Choisissez une machine, puis relevez ses règles.',
    'relever' => 'Relever les règles',
    'aucune_machine_choisie' => 'Choisissez d\'abord une machine.',
    'machines_aucune_titre' => 'Aucune machine ne vous est accessible',
    'machines_aucune' => 'Cette page ne propose que les machines auxquelles votre compte a accès. Demandez un accès à un administrateur.',

    // ── Ce que la page annonce AVANT le geste ───────────────────────────
    'sensible' => 'Production',
    'sensible_avert' => 'Cette machine est en production ou marquée critique. Relever ses règles ne les modifie pas — mais c\'est sur elle que porteront les gestes suivants.',
    'avert_titre' => 'Une machine de production figure dans cette liste',
    'avert_un' => 'Une des :total machines proposées est en production ou marquée critique.',
    'avert_plusieurs' => ':nb des :total machines proposées sont en production ou marquées critiques.',

    /*
     * Le port SSH est annoncé au moment du choix, et il vient de la BASE.
     * Les gabarits de règles du legacy supposent 22 ; les trois machines du parc
     * écoutent sur 22, donc le défaut n'est pas armé — et c'est ce qui le rend
     * invisible. L'annoncer maintenant, c'est refuser de le reproduire plus tard.
     */
    'port_ssh_annonce' => 'Accès SSH de cette machine : port :port. Un jeu de règles qui ne laisse pas ce port ouvert couperait l\'accès, y compris celui de RootWarden.',

    // ── Le relevé ───────────────────────────────────────────────────────
    'chargement' => 'Lecture des règles sur la machine…',
    'releve_ok' => 'Règles relevées sur :machine.',
    'releve_le' => 'Relevé le :date',
    'echec' => 'Les règles n\'ont pas pu être lues. La machine est-elle joignable ?',
    'echec_reseau' => 'La requête n\'a pas abouti. Ni succès, ni refus : rien n\'a été lu.',

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
    'fichier_absent' => 'Ce fichier n\'existe pas sur la machine. Les règles actives ne seront donc pas rétablies au redémarrage.',

    // ── Ce que I1 ne fait pas, dit à l'écran plutôt qu'absent en silence ──
    'suite_titre' => 'Cette page ne modifie rien',
    /*
     * ⚠ CORRIGE le 2026-09-02 (E-318). Ce libelle declarait la validation a blanc
     * NON PORTEE. Elle l'est : `pare-feu.js:710` appelle `/iptables-validate`, et
     * la ligne 106 de CE fichier la documente — le catalogue se contredisait
     * lui-meme. L'erreur venait d'un reperage par ROUTE LARAVEL : I4 n'y apparait
     * pas, parce qu'il passe par la PASSERELLE. *Mesurer les routes Laravel n'est
     * pas mesurer les capacites.*
     *
     * Une page qui renvoie vers l'ancien portail pour un geste qu'elle sait faire
     * ENTRETIENT le legacy qu'on veut eteindre : l'erreur va dans le sens sur UNE
     * SEULE FOIS, puis se paie a chaque usage. *Un manque declare a tort est une
     * capacite perdue sans que rien ne la retire.*
     *
     * La reserve sur le backend est CONSERVEE et dite : `iptables.py` est l'un des
     * modules que le processus servi n'a pas recharges, donc que le JS appelle la
     * route ne dit pas qu'elle repond. A remesurer apres le redemarrage.
     */
    'suite' => "Le relevé, la copie en base, la validation à blanc et l'APPLICATION des règles sont portés ici. Seul le retour arrière — restaurer une version archivée — reste sur l'ancien portail. L'historique ci-dessus liste les versions ; c'est de là que le retour arrière partira quand il sera porté.",
    'suite_lien' => 'Ouvrir le pare-feu sur l\'ancien portail',

    // ── I2 : la copie en base ───────────────────────────────────────────
    'copie_titre' => 'Copie enregistrée en base',
    'copie_intro' => 'Le portail peut garder une copie des règles d\'une machine, pour les retrouver plus tard. Enregistrer une copie NE la valide pas et NE l\'applique pas.',
    'copie_charger' => 'Charger la copie',
    'copie_enregistrer' => 'Enregistrer ces règles',
    'copie_absente' => 'Aucune copie enregistrée pour cette machine.',
    'copie_le' => 'Copie enregistrée le :date',
    'copie_enregistree' => 'Copie enregistrée pour :machine. Elle n\'a été ni validée, ni appliquée.',
    'copie_rien_a_enregistrer' => 'Relevez d\'abord les règles : il n\'y a rien à enregistrer.',
    'copie_v4_vide' => 'Les règles IPv4 sont vides. Une copie vide serait refusée au moment de la restaurer : elle n\'est donc pas enregistrée.',
    'copie_trop_grande' => 'Les règles dépassent la taille que la colonne peut contenir (:max octets). Rien n\'a été enregistré.',
    'champs_manquants' => 'Requête incomplète : les deux jeux de règles sont attendus, même vides.',
    'machine_refusee' => 'Machine inconnue ou hors de votre périmètre.',
    'copie_lignes_multiples' => 'Attention : :nb copies existent pour cette machine. La plus récente est affichée.',
    'copie_bloc_v4' => 'Copie IPv4',
    'copie_bloc_v6' => 'Copie IPv6',

    // ── I3 : l'historique des versions archivées ────────────────────────
    'histo_titre' => 'Versions archivées',
    'histo_intro' => 'Chaque application de règles archive celles qu\'elle remplace. Une version vide n\'est jamais archivée : toutes celles listées ici sont restaurables.',
    'histo_chargement' => 'Lecture de l\'historique…',
    'histo_vide_titre' => 'Aucune version archivée',
    'histo_vide' => 'Aucune application de règles n\'a encore eu lieu sur cette machine depuis ce portail. Il n\'y a donc rien à restaurer.',
    'histo_echec_titre' => 'Historique illisible',
    'histo_echec' => 'L\'historique n\'a pas pu être lu. Ce n\'est pas la même chose qu\'un historique vide : ne concluez pas qu\'il n\'y a rien à restaurer.',
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
    'valid_intro' => 'Le serveur peut vérifier qu\'un jeu de règles est syntaxiquement applicable, sans l\'appliquer.',
    'valid_bouton' => 'Valider la copie à blanc',
    'valid_avant' => 'Ce contrôle OUVRE une session SSH sur la machine et y écrit un fichier temporaire. Il ne modifie aucune table du pare-feu.',
    'valid_limite' => 'La validation ne porte QUE sur les règles IPv4. Une copie dont l\'IPv6 est mal formé passerait ce contrôle et échouerait à l\'application.',
    'valid_v4_vide' => 'Cette copie ne porte aucune règle IPv4. Il n\'y a rien à valider : la validation ne connaît que l\'IPv4, et refuse une copie vide.',
    'valid_sans_copie' => 'Chargez d\'abord la copie en base : c\'est elle qui est validée.',
    'valid_en_cours' => 'Validation en cours sur la machine…',
    'valid_ok' => 'Le serveur déclare ces règles applicables.',
    'valid_invalide_court' => 'Le serveur declare ces regles invalides — verdict a relire ci-dessous.',
    'valid_invalide_titre' => 'Déclarées invalides — verdict à relire',
    'valid_invalide' => 'Le serveur déclare ces règles invalides. Ce verdict N\'EST PAS FIABLE sur une sortie longue : la détection du code de sortie le cherche dans des fragments de 4096 octets, et un jeu de règles VALIDE peut être déclaré invalide lorsque le marqueur tombe à cheval. Lisez la sortie avant de conclure.',
    'valid_echec_titre' => 'Contrôle non abouti',
    'valid_echec' => 'Le contrôle n\'a pas abouti. Ce n\'est ni « valide » ni « invalide » : rien n\'a été vérifié.',
    'valid_sortie' => 'Sortie du serveur',

    /*
     * ══ UNE NON-MESURE ANNONCEE A L'AVANCE ══════════════════════════════
     *
     * `/pare-feu/copie/enregistrer` ecrit des regles de pare-feu sur une
     * machine reelle. **Ce geste n'a jamais ete exerce** — mesure :
     * `tests/e2e/go-page-pare-feu.mjs:65` dit que les requetes vers cette
     * route sont « AVORTEES sans condition ». La suite mesure qu'on peut
     * CLIQUER, jamais que le geste ABOUTIT.
     *
     * Sur la PAGE et au-dessus du bouton, pas en pied ni au seul registre :
     * c'est la personne qui va cliquer qui a besoin de l'information.
     * Une non-mesure annoncee a l'avance est une reserve ; annoncee apres
     * coup, c'est une excuse.
     */
    'copie_jamais_exercee' => "L'enregistrement d'une copie de règles n'a encore jamais été exercé depuis cette interface : le geste est câblé et confirmé, mais son aboutissement n'a pas été observé sur une machine. L'ancien portail reste la seule voie éprouvée.",

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
    'ipt_retour_refus'            => "La demande a été refusée avant tout contrôle des règles. Rien n'a été appliqué — et on ne sait pas si ces règles sont valides.",
    'ipt_retour_erreur_serveur'   => "Le serveur a échoué avant de répondre. Rien ne permet de dire si les règles ont été appliquées : relevez l'état de la machine avant de réessayer.",
    'ipt_retour_corps_illisible'  => "Le serveur a répondu, mais sa réponse est illisible. Le geste est peut-être passé : relevez l'état de la machine avant de réessayer.",
    'ipt_retour_inabouti'         => "La demande n'est pas partie. Rien n'a été appliqué.",
    'ipt_retour_doute_marqueur'   => "Le serveur signale que son verdict n'est pas fondé. Ne le lisez ni comme un succès ni comme un échec : relevez l'état de la machine.",
    'ipt_retour_contrat_inconnu'  => "La réponse ne correspond à aucun cas prévu. Relevez l'état de la machine plutôt que de supposer.",

    /* ══ I5 — L'ECRAN D'APPLICATION ════════════════════════════════════════════ */
    'appl_titre'      => 'Appliquer un jeu de règles',
    'appl_intro'      => "Le jeu choisi REMPLACE toutes les règles de la machine d'un seul geste : `iptables-restore` écrase les tables, il n'ajoute rien. La version précédente est archivée avant l'écriture.",
    'appl_gabarit'    => 'Jeu de règles',
    'appl_gabarit_aide' => "Le port SSH est lu sur la machine choisie, jamais supposé à 22 — c'est ce qui empêche un gabarit de vous enfermer dehors.",
    'appl_apercu'     => 'Ce qui sera appliqué',
    'appl_ssh_ouvert' => 'Le port SSH :port reste joignable avec ce jeu.',
    'appl_ssh_ferme'  => "⛔ Ce jeu FERME le port SSH :port. Appliqué, il vous couperait l'accès à la machine — et il faudrait une console physique pour revenir.",
    'appl_ssh_doute'  => "⛔ Impossible de dire si le port SSH :port reste ouvert avec ce jeu. On refuse plutôt que de parier : un doute sur cette question se paie en accès perdu.",
    'appl_bouton'     => 'Appliquer sur la machine',
    'appl_en_cours'   => 'Application en cours…',
    'appl_conf_titre' => 'Remplacer les règles de :machine ?',
    'appl_conf_texte' => "Toutes les règles actuelles de :machine seront REMPLACÉES par le jeu « :gabarit ». La version précédente est archivée et reste restaurable depuis l'historique. Aucune requête n'a encore été envoyée.",
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
    'rb_ssh_ouvert' => 'Le port SSH :port — celui de la machine AUJOURD\'HUI — reste joignable avec cette version.',
    'rb_ssh_ferme'  => "⛔ Cette version FERME le port SSH :port, qui est celui de la machine aujourd'hui. Elle était peut-être valide le jour de son archivage : restaurée maintenant, elle vous couperait l'accès.",
    'rb_ssh_doute'  => "⛔ Impossible de dire si cette version laisse le port SSH :port ouvert. On refuse plutôt que de parier — et la reprise passerait elle aussi par SSH.",
    'rb_conf_titre' => 'Restaurer la version du :date sur :machine ?',
    'rb_conf_texte' => "Les règles actuelles de :machine seront REMPLACÉES par cette version archivée. L'état actuel est archivé avant l'écriture, donc ce retour arrière est lui-même réversible. Aucune requête n'a encore été envoyée.",
    'rb_conf_ok'    => 'Restaurer cette version',
    'rb_conf_non'   => 'Annuler',
    'rb_en_cours'   => 'Restauration en cours…',
    'rb_annule'     => "Annulé — aucune requête n'a été envoyée.",
];
