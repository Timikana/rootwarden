<?php

/**
 * Droits sudo par compte distant — sous-lot D9a.
 *
 * ATTENTION AVANT DE MODIFIER UNE AIDE DE PREREGLAGE. Ces textes decrivent une
 * portee de privileges. Le legacy affirmait sous `apt_only` « Il ne peut pas
 * toucher au reste du systeme » alors que `backend/sudo_manager.py:80-84`
 * documente le contraire — « ce preset est EQUIVALENT ROOT ».
 *
 * `tests/e2e/go-adm-politiques.mjs` relit ce module dans le conteneur a chaque
 * execution et refuse que l'ecran le contredise. Une aide qui adoucit la portee
 * d'un prereglage classe 'root' fait donc ECHOUER le LOT — c'est voulu.
 */

return [
    'titre'          => 'Droits sudo par compte distant',
    'intro_titre'    => 'A quoi sert cette page ?',
    'intro'          => 'Le « sudo » permet a un compte ordinaire d\'executer certaines commandes '
                        . 'en tant qu\'administrateur (root). Vous choisissez ici, pour UN compte sur '
                        . 'UNE machine, ce qu\'il aura le droit de faire — puis vous confirmez avant '
                        . 'que quoi que ce soit ne soit ecrit sur la machine.',
    'machine'        => 'Machine',
    'compte'         => 'Compte distant',
    'aucun_compte'   => 'Aucun compte gere sur cette machine',
    'vide_titre'     => 'Aucun compte a qui accorder des droits',
    'vide_texte'     => 'Cette machine n\'a aucun compte au statut « gere » ou « a examiner ». '
                        . 'Lancez un inventaire depuis les comptes distants, puis classez '
                        . 'les comptes concernes.',
    'vide_action'    => 'Ouvrir les comptes distants',

    'choix'          => 'Ce que le compte pourra faire',
    'prereglage'     => 'Prereglage',
    'regles_libres'  => 'Regles saisies',
    'regles_aide'    => 'Une ligne par regle, au format sudoers. Seule la SYNTAXE sera verifiee '
                        . '(`visudo -cf`) : la portee reelle de ce que vous ecrivez n\'est pas analysee.',
    'services'       => 'Services autorises',
    'services_aide'  => 'Separes par des virgules. Exemple : nginx, php8.2-fpm, redis-server',
    'nopasswd'       => 'Sans demander de mot de passe (NOPASSWD)',
    'nopasswd_aide'  => 'Coche, le compte n\'aura aucun mot de passe a saisir pour ces commandes.',
    'runas'          => 'Executer en tant que',

    // ── LA PORTEE, telle que le module la documente ────────────────────────
    'portee_root'         => 'Donne un acces root',
    'portee_root_detail'  => 'Ce prereglage permet a terme d\'obtenir les pleins pouvoirs sur la machine.',
    'portee_borne'        => 'Portee bornee',
    'portee_borne_detail' => 'Liste de commandes fermee, durcie par le module qui la produit.',
    'portee_inconnu'         => 'Portee non analysee',
    'portee_inconnu_detail'  => 'Vous ecrivez la regle vous-meme ; seule sa syntaxe sera verifiee.',

    'aide_all_nopasswd'       => 'Acces root complet, sans mot de passe : la regle ecrite est '
                                 . 'litteralement « tout, en tant que root ». A reserver aux comptes de service.',
    'aide_apt_only'           => 'Autorise « apt » a installer et mettre a jour des logiciels. '
                                 . 'CELA EQUIVAUT A UN ACCES ROOT : l\'installation d\'un paquet execute '
                                 . 'ses scripts de mainteneur en tant que root, ce qui permet d\'obtenir '
                                 . 'un interpreteur root via un paquet fabrique pour cela. Il n\'existe pas '
                                 . 'de moyen sur de « limiter a apt ». A n\'accorder qu\'a des operateurs '
                                 . 'a qui vous confieriez deja root.',
    'aide_restart_services'   => 'Autorise a redemarrer, recharger et consulter l\'etat de services systemd, '
                                 . 'sans restriction sur lesquels.',
    'aide_read_logs'          => 'Lecture des journaux seulement : « tail » et « cat » sous /var/log, et '
                                 . '« journalctl » sans pagination. Le module a retire « less », qui '
                                 . 'permettait d\'ouvrir un interpreteur root.',
    'aide_systemctl_specific' => 'Redemarrer, recharger et consulter l\'etat des SEULS services que vous '
                                 . 'nommez ci-dessous.',
    'aide_custom'             => 'Regles ecrites a la main. Leur portee n\'est pas analysee : elles peuvent '
                                 . 'donner root sans que rien ne le signale.',

    'preset_all_nopasswd'       => 'Acces root complet',
    'preset_restart_services'   => 'Redemarrage de services',
    'preset_apt_only'           => 'Mises a jour APT',
    'preset_read_logs'          => 'Lecture des journaux',
    'preset_systemctl_specific' => 'Services nommes',
    'preset_custom'             => 'Regles libres',

    // ── LES GESTES ─────────────────────────────────────────────────────────
    'deployer'       => 'Deployer…',
    'auditer'        => 'Auditer',
    'retirer'        => 'Retirer…',
    'aide_deployer'  => 'Ecrit la configuration sur la machine, apres validation de sa syntaxe.',
    'aide_auditer'   => 'Lit le fichier reellement present sur la machine. Ne modifie rien.',
    'aide_retirer'   => 'Supprime cette configuration de la machine ; le compte perd ces droits.',

    // ── LA CONFIRMATION, QUI MANQUAIT ──────────────────────────────────────
    'confirmer_titre'   => 'Confirmer le deploiement',
    'confirmer_intro'   => 'Ceci va ecrire un fichier sudoers sur la machine. Verifiez avant de valider :',
    'confirmer_machine' => 'Machine',
    'confirmer_compte'  => 'Compte',
    'confirmer_portee'  => 'Ce que cela accorde',
    'confirmer_root'    => 'Ce prereglage donne un acces root a ce compte.',
    'confirmer_valider' => 'Deployer sur la machine',
    'confirmer_annuler' => 'Annuler',
    'retirer_titre'     => 'Confirmer le retrait',
    'retirer_intro'     => 'Le fichier sudoers de ce compte sera supprime de la machine. '
                           . 'Le compte perdra les droits qu\'il accordait.',
    'retirer_valider'   => 'Retirer de la machine',
    'reauth'            => 'Une re-authentification vous sera demandee avant l\'envoi.',

    // ── L'HISTORIQUE ───────────────────────────────────────────────────────
    'historique'        => 'Historique et restauration',
    'hist_date'         => 'Date',
    'hist_auteur'       => 'Par',
    'hist_etat'         => 'Etat',
    'hist_fichier'      => 'Fichier',
    'hist_regle'        => 'Regle ecrite',
    'hist_vide'         => 'Aucun deploiement enregistre pour ce compte.',
    'etat_applied'      => 'Appliquee',
    'etat_rolled_back'  => 'Annulee',
    'etat_failed'       => 'Echouee',
    'etat_superseded'   => 'Remplacee',
    'derniere'          => 'Derniere ecriture',
    'jamais'            => 'jamais deployee',
    'rollback_titre' => 'Restaurer une version anterieure',
    'rollback_texte' => 'L\'annulation d\'un deploiement n\'est pas encore portee. Elle reecrit un fichier sudoers sur la machine, et se fait pour l\'instant depuis l\'ancien portail.',
    'rollback_lien' => 'Annuler ce deploiement dans l\'ancien portail',
    'resultat'          => 'Resultat',
];
