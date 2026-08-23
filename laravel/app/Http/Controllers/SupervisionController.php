<?php

namespace App\Http\Controllers;

use App\Services\Supervision;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Supervision — module `supervision/`.
 *
 * Sous-lot V1 : la page et ses quatre onglets. Sous-lot V2 : le catalogue de
 * profils, en LECTURE — le CRUD et l'assignation restent a V5.
 *
 * La garde vit DANS LA ROUTE et nulle part ailleurs : `role:2` +
 * `perm:can_manage_supervision`, REPRISE TELLE QUELLE du legacy
 * (`supervision/index.php:17-18`, `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` puis
 * `checkPermission('can_manage_supervision')`).
 *
 * AUCUN ECART A DECLARER SUR LA GARDE, et c'est assez rare pour etre dit :
 * contrairement a `ssh/` et a `security/`, l'en-tete de ce fichier legacy annonce
 * « Permissions : admin (2) + superadmin (3) + can_manage_supervision » et son
 * code applique exactement cela.
 *
 * V1 N'APPELLE AUCUNE ROUTE DU BACKEND. Le legacy, lui, en appelle deux des le
 * chargement et les rejoue a chaque bascule d'onglet : le catalogue de profils
 * arrive d'emblee. Ici tout est peint cote serveur, et le script ne fait que
 * montrer et cacher des panneaux deja rendus.
 */
class SupervisionController extends Controller
{
    /**
     * Ce que chaque plateforme affiche, dans l'ordre : cle de colonne => cle i18n.
     *
     * `hostname_pattern` et `extra_config` sont communs aux quatre. Les deux
     * secrets (`tls_psk_value`, `telegraf_output_token`) n'y figurent PAS : ils ne
     * sont meme pas lus en base, seule leur presence l'est.
     *
     * `updated_at` n'est volontairement pas affiche : il est ecrit par MySQL, donc
     * dans le fuseau du conteneur de base, et l'afficher ferait entrer dans cette
     * page le decalage declare en PARITE E-73. V3 montre la configuration, pas sa
     * piste d'audit.
     */
    /**
     * Les colonnes a CHOIX FERME, et leurs valeurs admises.
     *
     * `tls_connect` et `tls_accept` sont des `enum` EN BASE
     * (`enum('unencrypted','psk','cert')`) : un champ de texte libre par-dessus
     * une colonne enumeree laisse taper une valeur que MySQL refusera — une
     * erreur d'ecriture la ou l'utilisateur attendait un enregistrement. Vu a
     * l'image sur la premiere version de ce formulaire.
     *
     * `agent_type` et `agent_version` sont des `varchar`, mais le legacy n'y offre
     * que deux valeurs chacun : les laisser libres inviterait a inventer un nom
     * d'agent que le deploiement ne saurait pas installer.
     */
    private const CHOIX_PAR_COLONNE = [
        'agent_type' => ['zabbix-agent', 'zabbix-agent2'],
        'agent_version' => ['7.0', '7.2'],
        'tls_connect' => ['unencrypted', 'psk', 'cert'],
        'tls_accept' => ['unencrypted', 'psk', 'cert'],
    ];

    /**
     * Les champs d'un profil, dans l'ordre du formulaire : colonne => cle i18n.
     *
     * Ce sont ceux de la boite de dialogue du legacy. `platform` n'y est pas : elle
     * vient du bloc dans lequel le formulaire vit, pas d'un champ que l'on pourrait
     * changer en cours de route — deplacer un profil d'une plateforme a l'autre
     * n'est pas une modification, c'est une autre operation, et le legacy ne
     * l'offre pas non plus.
     */
    private const CHAMPS_PROFIL = [
        'name' => 'profil_nom',
        'description' => 'profil_description',
        'host_metadata' => 'profil_metadonnees',
        'zabbix_server' => 'profil_serveur',
        'zabbix_server_active' => 'profil_serveur_actif',
        'zabbix_proxy' => 'profil_mandataire',
        'listen_port' => 'profil_port',
        'notes' => 'profil_notes',
    ];

    /**
     * LES HUIT REGLAGES PAR MACHINE — sous-lot V10a. LISTE FERMEE.
     *
     * Ce sont EXACTEMENT les huit noms que `_build_config_lines` traite par leur
     * nom, dans l'ordre ou il les lit. Rien de plus : le backend accepte aussi
     * des noms libres, qu'il injecte tels quels dans le fichier de configuration
     * — c'est par cette porte qu'un saut de ligne dans la valeur produisait une
     * directive autonome (E-85, corrige en v1.37.41). Le portage ne l'installe
     * pas : pas de champ de nom, donc pas de nom arbitraire.
     *
     * `nature` dit comment le champ se rend et se valide :
     *   texte   saisie libre sur UNE ligne
     *   port    entier borne
     *   liste   `<select>` sur `CHOIX_PAR_COLONNE`
     */
    private const CHAMPS_OVERRIDE = [
        'Hostname' => ['cle' => 'override_hostname', 'nature' => 'texte'],
        'Server' => ['cle' => 'override_serveur', 'nature' => 'texte'],
        'ServerActive' => ['cle' => 'override_serveur_actif', 'nature' => 'texte'],
        'HostMetadata' => ['cle' => 'override_metadonnees', 'nature' => 'texte'],
        'ListenPort' => ['cle' => 'override_port', 'nature' => 'port'],
        'TLSConnect' => ['cle' => 'override_tls_connect', 'nature' => 'liste',
                         'colonne' => 'tls_connect'],
        'TLSAccept' => ['cle' => 'override_tls_accept', 'nature' => 'liste',
                        'colonne' => 'tls_accept'],
        'TLSPSKIdentity' => ['cle' => 'override_psk_identite', 'nature' => 'texte'],
    ];

    private const CHAMPS_PAR_PLATEFORME = [
        'zabbix' => [
            'agent_type' => 'type_agent',
            'agent_version' => 'version_agent',
            'zabbix_server' => 'serveur',
            'zabbix_server_active' => 'serveur_actif',
            'listen_port' => 'port',
            'hostname_pattern' => 'motif_nom',
            'tls_connect' => 'tls_connexion',
            'tls_accept' => 'tls_acceptation',
            'tls_psk_identity' => 'psk_identite',
            'host_metadata_template' => 'metadonnees',
            'extra_config' => 'config_supplementaire',
        ],
        'centreon' => [
            'centreon_host' => 'centreon_hote',
            'centreon_port' => 'centreon_port',
            'hostname_pattern' => 'motif_nom',
            'extra_config' => 'config_supplementaire',
        ],
        'prometheus' => [
            'prometheus_listen' => 'prometheus_ecoute',
            'prometheus_collectors' => 'prometheus_collecteurs',
            'hostname_pattern' => 'motif_nom',
            'extra_config' => 'config_supplementaire',
        ],
        'telegraf' => [
            'telegraf_output_url' => 'telegraf_url',
            'telegraf_output_org' => 'telegraf_organisation',
            'telegraf_output_bucket' => 'telegraf_seau',
            'telegraf_inputs' => 'telegraf_entrees',
            'hostname_pattern' => 'motif_nom',
            'extra_config' => 'config_supplementaire',
        ],
    ];

    public function __construct(private Supervision $supervision)
    {
    }

    public function __invoke(Request $requete): View
    {
        return view('supervision', [
            'onglets' => $this->supervision->onglets(),
            'plateformes' => $this->supervision->plateformes(),
            'machines' => $this->supervision->machines(),
            'profils' => $this->supervision->profilsParPlateforme(),
            'configuration' => $this->supervision->configurationParPlateforme(),
            /*
             * Les champs a rendre, PAR PLATEFORME. Une liste explicite plutot
             * qu'un parcours des colonnes : `supervision_config` porte les
             * colonnes des QUATRE plateformes sur la meme ligne, et les afficher
             * toutes ferait lire a un exploitant de Centreon des reglages Zabbix
             * qui ne s'appliquent pas a lui.
             */
            'champs' => self::CHAMPS_PAR_PLATEFORME,
            'choix' => self::CHOIX_PAR_COLONNE,
            'champsProfil' => self::CHAMPS_PROFIL,
            /*
             * LE PROFIL EN COURS DE MODIFICATION VIENT DE L'ADRESSE, pas du DOM.
             * `?profil=<id>` : le serveur pre-remplit le formulaire. Le legacy, lui,
             * serialise le profil entier dans un attribut `onclick` — 671 caracteres
             * mesures, `notes` comprise.
             */
            'profilModifie' => $this->profilDemande($requete),
            'agents' => $this->supervision->agentsParMachine(),
            'cheminsConfig' => $this->supervision->cheminsConfiguration(),
            /*
             * LE COUT DU RELEVE DE PARC VIENT DU SERVEUR — sous-lot V8. Nombre de
             * machines, de plateformes, de sessions SSH, et le NOM des machines de
             * production concernees. Le calculer cote client reviendrait a compter
             * les lignes du tableau : c'est exactement l'erreur du legacy, dont le
             * releve ignore le filtre et joint des machines qui ne sont plus a
             * l'ecran.
             */
            'coutReleve' => $this->supervision->coutDuReleve(),
            /*
             * LA MACHINE DONT ON REGLE LES OVERRIDES VIENT DE L'ADRESSE — meme
             * principe qu'en V5 pour les profils : `?reglages=<id>`, et le
             * serveur pre-remplit. Rien n'est serialise dans le DOM.
             */
            'champsOverride' => self::CHAMPS_OVERRIDE,
            'machineReglee' => $this->machineReglee($requete),
            'overrides' => $this->overridesDemandes($requete),
            'libelles' => $this->libelles(),
        ]);
    }

    /**
     * Enregistre la configuration globale d'une plateforme — sous-lot V4.
     *
     * UNE SOUMISSION DE FORMULAIRE, PAS UN APPEL CLIENT. Le portage n'ouvre
     * aucune requete depuis le navigateur : le formulaire part en POST, le
     * controleur ecrit, et la page revient avec son message. Trois suites du
     * module assertent qu'aucun appel client ne partait de cette page — cette
     * propriete reste vraie.
     *
     * LES CHAMPS ECRITS SONT CEUX DE `CHAMPS_PAR_PLATEFORME`, et eux seuls. Le
     * legacy, lui, force `hostname_pattern` et `extra_config` pour les trois
     * plateformes non-Zabbix (`main.js:186`) : deux champs que l'utilisateur
     * remplit et que l'enregistrement jette. Ici ce qui est affiche est ce qui est
     * ecrit.
     */
    public function enregistrer(Request $requete): RedirectResponse
    {
        $plateforme = (string) $requete->input('plateforme', '');
        if (! array_key_exists($plateforme, self::CHAMPS_PAR_PLATEFORME)) {
            return redirect()->route('supervision')
                ->with('superv_erreur', __('superv.enregistrement_plateforme_inconnue'));
        }

        // LE CHAMP EXIGE, PAR PLATEFORME. Le legacy refuse un `zabbix_server`
        // vide ; le meme raisonnement vaut pour l'hote Centreon, qui sans valeur
        // produirait une configuration d'agent inerte.
        $exiges = ['zabbix' => 'zabbix_server', 'centreon' => 'centreon_host'];
        $exige = $exiges[$plateforme] ?? null;
        if ($exige !== null && trim((string) $requete->input($exige, '')) === '') {
            return redirect()->route('supervision')
                ->with('superv_erreur', __('superv.enregistrement_champ_exige', [
                    'champ' => __('superv.champ_' . self::CHAMPS_PAR_PLATEFORME[$plateforme][$exige]),
                ]));
        }

        $valeurs = [];
        foreach (array_keys(self::CHAMPS_PAR_PLATEFORME[$plateforme]) as $colonne) {
            $brut = $requete->input($colonne);
            $brut = is_string($brut) ? trim($brut) : $brut;
            // Une colonne nullable vide se stocke a NULL, pas a la chaine vide :
            // la lecture (V3) distingue « non renseigne » de « renseigne vide »,
            // et l'ecriture doit lui donner de quoi le faire.
            $valeurs[$colonne] = ($brut === '' || $brut === null) ? null : $brut;

            /*
             * UNE COLONNE A CHOIX FERME NE PREND QUE SES VALEURS. La liste est
             * cote serveur : un `<select>` empeche la faute a l'ecran, il
             * n'empeche rien du tout dans une requete forgee — et derriere il y a
             * un `enum` MySQL qui refuserait l'ecriture, donc une erreur au lieu
             * d'un refus lisible. Hors liste : on garde la valeur DEJA en base.
             */
            if (isset(self::CHOIX_PAR_COLONNE[$colonne])
                && ! in_array($valeurs[$colonne], self::CHOIX_PAR_COLONNE[$colonne], true)) {
                unset($valeurs[$colonne]);
            }
        }
        // `listen_port` et `centreon_port` sont des entiers en base : une chaine
        // vide y deviendrait 0, un port qui n'existe pas.
        foreach (['listen_port', 'centreon_port'] as $entier) {
            if (array_key_exists($entier, $valeurs)) {
                $valeurs[$entier] = $valeurs[$entier] === null ? null : (int) $valeurs[$entier];
            }
        }

        $this->supervision->enregistreConfiguration(
            $plateforme,
            $valeurs,
            // Un PSK vide veut dire « ne change rien », jamais « efface ».
            $plateforme === 'zabbix' ? (string) $requete->input('tls_psk_value', '') : null,
            (int) $requete->session()->get('user_id', 0),
        );

        return redirect()->route('supervision')
            ->with('superv_message', __('superv.enregistrement_fait', [
                'plateforme' => ucfirst($plateforme),
            ]));
    }

    /**
     * Le profil que l'adresse demande a modifier, s'il existe vraiment.
     *
     * FAIL-CLOSED : un identifiant inconnu ou d'une autre plateforme rend null, et
     * le formulaire repart en creation. Pre-remplir avec « rien » vaut mieux que
     * pre-remplir avec la ligne d'un autre.
     */
    private function profilDemande(Request $requete): ?object
    {
        $id = (int) $requete->query('profil', 0);
        if ($id <= 0) {
            return null;
        }

        return $this->supervision->profil($id);
    }

    /**
     * Cree ou modifie un profil — sous-lot V5.
     *
     * LA GARDE EST DANS LA ROUTE, comme partout. Et c'est ce qui change par rapport
     * au legacy : ses quatre routes de profils (`supervision.py` 1734, 1760, 1801,
     * 1817) portent `@require_permission` mais **aucun `@require_role`** — la
     * cinquieme, elle, porte `@require_role(2)` avec un commentaire « Patch A01 ».
     * Le correctif a ete applique a une route et pas a ses voisines. Ici l'ecriture
     * se fait en base derriere la garde de la PAGE, donc la permission garde enfin
     * la REQUETE. Poser `@require_role(2)` sur les quatre routes backend reste une
     * decision d'exploitant : non faite, declaree.
     */
    public function enregistrerProfil(Request $requete): RedirectResponse
    {
        $plateforme = (string) $requete->input('plateforme', '');
        if (! array_key_exists($plateforme, self::CHAMPS_PAR_PLATEFORME)) {
            return redirect()->route('supervision')
                ->with('superv_profil_erreur', __('superv.enregistrement_plateforme_inconnue'));
        }

        $nom = trim((string) $requete->input('name', ''));
        if ($nom === '') {
            return redirect()->route('supervision')
                ->with('superv_profil_erreur', __('superv.profil_nom_exige'));
        }

        $valeurs = [];
        foreach (array_keys(self::CHAMPS_PROFIL) as $colonne) {
            $brut = $requete->input($colonne);
            $brut = is_string($brut) ? trim($brut) : $brut;
            $valeurs[$colonne] = ($brut === '' || $brut === null) ? null : $brut;
        }
        $valeurs['name'] = $nom;
        // `listen_port` est un entier nullable : une chaine vide y deviendrait 0.
        $valeurs['listen_port'] = $valeurs['listen_port'] === null
            ? null : (int) $valeurs['listen_port'];

        $id = (int) $requete->input('id', 0);
        $verdict = $this->supervision->enregistreProfil(
            $plateforme, $valeurs, $id > 0 ? $id : null);

        if ($verdict === 'doublon') {
            return redirect()->route('supervision')
                ->with('superv_profil_erreur',
                    __('superv.profil_doublon', ['nom' => $nom, 'plateforme' => ucfirst($plateforme)]));
        }
        if ($verdict === 'inconnu') {
            return redirect()->route('supervision')
                ->with('superv_profil_erreur', __('superv.profil_introuvable'));
        }

        return redirect()->route('supervision')
            ->with('superv_profil_message', $id > 0
                ? __('superv.profil_modifie', ['nom' => $nom])
                : __('superv.profil_cree', ['nom' => $nom]));
    }

    /**
     * Supprime un profil — sous-lot V5. GESTE DESTRUCTEUR.
     *
     * `ON DELETE CASCADE` VERIFIE au schema : les assignations partent avec le
     * profil, donc les serveurs concernes retombent sur la configuration globale.
     * Le nombre de machines touchees est annonce AVANT le geste, dans le panneau de
     * decision — le legacy, lui, le dit dans un `confirm()` natif dont le texte est
     * ecrit en francais en dur.
     */
    public function supprimerProfil(Request $requete): RedirectResponse
    {
        $plateforme = (string) $requete->input('plateforme', '');
        $id = (int) $requete->input('id', 0);

        if ($id <= 0 || ! array_key_exists($plateforme, self::CHAMPS_PAR_PLATEFORME)) {
            return redirect()->route('supervision')
                ->with('superv_profil_erreur', __('superv.profil_introuvable'));
        }

        $profil = $this->supervision->profil($id);
        $nom = $profil->name ?? '';
        $machines = $this->supervision->machinesAssignees($id);
        $supprimees = $this->supervision->supprimeProfil($id, $plateforme);

        if ($supprimees === 0) {
            return redirect()->route('supervision')
                ->with('superv_profil_erreur', __('superv.profil_introuvable'));
        }

        return redirect()->route('supervision')
            ->with('superv_profil_message', __('superv.profil_supprime', [
                'nom' => $nom,
                'machines' => $machines,
            ]));
    }

    /**
     * Les libelles consommes par le script, POSES EN DONNEES.
     *
     * C'EST ICI QUE V1 FERME LA DETTE i18n DU MODULE. Cote legacy, le JS lit ses
     * libelles dans `window._i18n`, alimente par `getJsTranslations('js.')` : onze
     * cles du module vivent dans `supervision.php` et pas dans `js.php`, et
     * `head.php` rend alors la CLE elle-meme. Comme une cle est une chaine non
     * vide, l'idiome `__('x') || 'repli'` ne replie jamais — la panne est
     * silencieuse et l'ecran affiche `editor_select_server`.
     *
     * Ici il n'y a pas deux catalogues : les libelles partent du MEME
     * `lang/<langue>/superv.php` que la page, en donnees, sur UNE ligne (`@json`
     * multiligne casse le PHP compile). Le defaut ne peut donc pas se reformer.
     *
     * @return array<string,string>
     */
    /**
     * La machine dont l'adresse demande les reglages, ou null — sous-lot V10a.
     *
     * VERIFIER QUE LA MACHINE EXISTE ET N'EST PAS ARCHIVEE, plutot que de faire
     * confiance a l'identifiant de l'adresse : `?reglages=999` ne doit pas
     * ouvrir un formulaire sur une machine inexistante, ni `?reglages=<archivee>`
     * sur une machine qu'on a retiree du parc.
     */
    private function machineReglee(Request $requete): ?object
    {
        $demande = $requete->query('reglages');

        if ($demande === null || ! ctype_digit((string) $demande)) {
            return null;
        }

        foreach ($this->supervision->machines() as $machine) {
            if ((int) $machine->id === (int) $demande) {
                return $machine;
            }
        }

        return null;
    }

    /**
     * Les reglages de la machine demandee — sous-lot V10a.
     *
     * @return array<string, string>
     */
    private function overridesDemandes(Request $requete): array
    {
        $machine = $this->machineReglee($requete);

        return $machine === null
            ? []
            : $this->supervision->overridesDeLaMachine((int) $machine->id);
    }

    /**
     * Enregistre les reglages d'une machine — sous-lot V10a.
     *
     * UNE SOUMISSION DE FORMULAIRE, PAS UN APPEL CLIENT : le portage n'ouvre
     * aucune requete depuis le navigateur pour ce geste. Il n'y a d'ailleurs rien
     * a joindre — ces reglages vivent en base et ne prennent effet qu'a la
     * prochaine reconfiguration. La page le DIT, plutot que de laisser croire
     * qu'enregistrer modifie le serveur.
     *
     * LES CLES SONT CELLES DE `CHAMPS_OVERRIDE`, ET ELLES SEULES. Un nom envoye
     * hors de cette liste n'est pas « refuse » : il n'est jamais regarde. C'est
     * la difference entre valider une entree libre et ne pas offrir d'entree
     * libre — et c'est ce qui empeche de rouvrir E-85 par le formulaire.
     */
    public function enregistrerOverrides(Request $requete): RedirectResponse
    {
        $idMachine = (int) $requete->input('machine_id');

        $machine = null;
        foreach ($this->supervision->machines() as $candidate) {
            if ((int) $candidate->id === $idMachine) {
                $machine = $candidate;
                break;
            }
        }

        if ($machine === null) {
            return redirect()->route('supervision')
                ->with('superv_reglages_erreur', __('superv.reglages_machine_inconnue'));
        }

        $valeurs = [];
        $refuses = [];

        foreach (self::CHAMPS_OVERRIDE as $nom => $champ) {
            $champHtml = 'override_' . $nom;

            /*
             * `has()` ET NON `input() !== null`. Laravel place
             * `ConvertEmptyStringsToNull` dans le groupe `web` : une chaine vide
             * arrive donc en `null`, exactement comme un champ ABSENT. Or les deux
             * ne veulent pas dire la meme chose ici — vide signifie « supprime ce
             * reglage », absent signifie « ne le touche pas ». Mesure du
             * 2026-08-22 : `input('a')` rend `null` pour `a=""`, alors que
             * `has('a')` rend `true`. Le premier jet testait `=== null` et ne
             * supprimait donc JAMAIS rien — trouve par la suite, pas a la
             * relecture.
             */
            if (! $requete->has($champHtml)) {
                continue;
            }

            $valeur = trim((string) ($requete->input($champHtml) ?? ''));

            /*
             * MEME MOTIF QUE LE BACKEND, REVALIDE ICI. Une valeur de
             * configuration agent tient sur UNE ligne : un saut de ligne y
             * produirait une directive autonome (E-85). Le champ est un
             * `<input>`, donc en pratique il n'en porte pas — mais une requete
             * forgee, elle, en porterait.
             */
            if (preg_match('/[\x00-\x1f\x7f]/', $valeur) === 1) {
                $refuses[] = $nom;

                continue;
            }

            if ($champ['nature'] === 'liste') {
                $permis = self::CHOIX_PAR_COLONNE[$champ['colonne']] ?? [];
                if ($valeur !== '' && ! in_array($valeur, $permis, true)) {
                    $refuses[] = $nom;

                    continue;
                }
            }

            if ($champ['nature'] === 'port' && $valeur !== '') {
                $entier = filter_var($valeur, FILTER_VALIDATE_INT,
                    ['options' => ['min_range' => 1, 'max_range' => 65535]]);
                if ($entier === false) {
                    $refuses[] = $nom;

                    continue;
                }
                $valeur = (string) $entier;
            }

            $valeurs[$nom] = $valeur;
        }

        $this->supervision->enregistreOverrides($idMachine, $valeurs);

        // UN REFUS SE DIT, il ne se devine pas — meme lecon que le correctif
        // backend de v1.37.41, ou un rejet silencieux passait pour un succes.
        if ($refuses !== []) {
            return redirect()->route('supervision', ['reglages' => $idMachine])
                ->with('superv_reglages_erreur', __('superv.reglages_refuses', [
                    'champs' => implode(', ', $refuses),
                ]));
        }

        return redirect()->route('supervision', ['reglages' => $idMachine])
            ->with('superv_reglages_message', __('superv.reglages_enregistres', [
                'nom' => $machine->name,
            ]));
    }

    /**
     * Les routes de la passerelle, PAR PLATEFORME — correctif de V7, porte en V9.
     *
     * Sept gestes par plateforme : lire le fichier, lister les sauvegardes,
     * ecrire, restaurer, reconfigurer, desinstaller, et RELIRE LA VERSION —
     * cette derniere sert a VERIFIER une desinstallation apres coup (V11). Le backend expose une route statique pour Zabbix et une
     * route generique pour les trois autres ; les deux formes rendent le meme
     * verdict, mais il faut viser la bonne — une URL figee sur Zabbix lit le
     * fichier de Zabbix quelle que soit la plateforme affichee.
     *
     * @return array<string, array<string, string>>
     */
    private function routesParPlateforme(): array
    {
        $routes = [];

        foreach ($this->supervision->plateformes() as $plateforme) {
            $routes[$plateforme] = [
                'lecture' => url("/api/gateway/supervision/{$plateforme}/config/read"),
                'sauvegardes' => url("/api/gateway/supervision/{$plateforme}/backups"),
                'ecriture' => url("/api/gateway/supervision/{$plateforme}/config/save"),
                'restauration' => url("/api/gateway/supervision/{$plateforme}/restore"),
                'reconfiguration' => url("/api/gateway/supervision/{$plateforme}/reconfigure"),
                'desinstallation' => url("/api/gateway/supervision/{$plateforme}/uninstall"),
                'version' => url("/api/gateway/supervision/{$plateforme}/version"),
            ];
        }

        return $routes;
    }

    private function libelles(): array
    {
        return [
            'editeur_sans_serveur' => __('superv.editeur_sans_serveur'),
            // ── Sous-lot V6 : la detection de version ─────────────────────
            'url_version' => url('/api/gateway/supervision/zabbix/version'),
            /*
             * TOUS LES JETONS SONT SUBSTITUES, y compris ceux que le script
             * remplacera. `__('x')` sans son argument laisse `:nom` EN CLAIR a
             * l'ecran — le module `ssh/` l'a paye : « 3 :count serveur(s)
             * disponible(s) », et aucun controle d'i18n ne le voyait, puisqu'ils
             * cherchent des identifiants `module.cle`, pas des jetons.
             */
            'version_en_cours' => __('superv.version_en_cours', ['nom' => '{nom}']),
            'version_trouvee' => __('superv.version_trouvee', [
                'version' => '{version}', 'nom' => '{nom}',
            ]),
            'version_absente' => __('superv.version_absente', ['nom' => '{nom}']),
            'version_refus' => __('superv.version_refus', ['statut' => '{statut}']),
            'version_echec' => __('superv.version_echec'),
            // ── Sous-lot V7 : la lecture du fichier distant ────────────────
            /*
             * LES QUATRE CHEMINS SONT POSES EN DONNEES : le script suit la
             * plateforme choisie, comme le legacy le fait pour son badge — a une
             * difference pres, qui est tout le sujet de E-79 : ici ils viennent du
             * SERVEUR, donc de la meme source que celle que le backend lira.
             */
            'chemins_config' => json_encode($this->supervision->cheminsConfiguration()),
            /*
             * LES ROUTES SUIVENT LA PLATEFORME, comme les chemins — ET C'EST UN
             * CORRECTIF DE MON PROPRE PORTAGE DE V7. Ces quatre URL etaient
             * FIGEES sur `/supervision/zabbix/...` alors que le chemin affiche,
             * lui, suivait le selecteur de plateforme. Choisir Telegraf faisait
             * donc annoncer `/etc/telegraf/telegraf.conf` et lire
             * `/etc/zabbix/zabbix_agent2.conf` : exactement le defaut E-79 que V7
             * reprochait au legacy, reintroduit par une porte que je n'avais pas
             * regardee — le CHEMIN venait du serveur, la ROUTE non.
             *
             * La suite de V7 ne pouvait pas le voir : elle n'exercait que Zabbix,
             * la seule plateforme ou l'URL figee se trouvait etre la bonne.
             *
             * Chemins et routes viennent desormais de la MEME source, indexes par
             * la meme cle : ils ne peuvent plus diverger.
             */
            'routes_machine' => json_encode($this->routesParPlateforme()),
            'url_sauvegardes' => url('/api/gateway/supervision/zabbix/backups'),
            'editeur_chemin_lu' => __('superv.editeur_chemin_lu'),
            'editeur_lecture_en_cours' => __('superv.editeur_lecture_en_cours', ['nom' => '{nom}']),
            'editeur_lu' => __('superv.editeur_lu', ['chemin' => '{chemin}', 'nom' => '{nom}']),
            'editeur_absent' => __('superv.editeur_absent', ['chemin' => '{chemin}', 'nom' => '{nom}']),
            'editeur_refus' => __('superv.editeur_refus', ['statut' => '{statut}']),
            'editeur_echec' => __('superv.editeur_echec'),
            'sauvegardes_aucune' => __('superv.sauvegardes_aucune'),
            'sauvegardes_nombre' => __('superv.sauvegardes_nombre', ['nombre' => '{nombre}']),
            // ── Sous-lot V8 : le releve du parc en tache de fond ───────────
            'url_releve_parc' => url('/api/gateway/supervision/scan-all'),
            'url_taches' => route('taches'),
            'releve_en_cours' => __('superv.releve_en_cours'),
            'releve_lance' => __('superv.releve_lance', [
                'machines' => '{machines}', 'tache' => '{tache}',
            ]),
            'releve_aucune' => __('superv.releve_aucune'),
            'releve_refus' => __('superv.releve_refus', ['statut' => '{statut}']),
            'releve_echec' => __('superv.releve_echec'),
            'releve_voir_taches' => __('superv.releve_voir_taches'),
            // ── Sous-lot V9 : l'ecriture distante et la restauration ───────
            'editeur_change_serveur' => __('superv.editeur_change_serveur'),
            'editeur_sauver_vide' => __('superv.editeur_sauver_vide'),
            'editeur_sauver_cout' => __('superv.editeur_sauver_cout', ['chemin' => '{chemin}']),
            'editeur_sauver_en_cours' => __('superv.editeur_sauver_en_cours'),
            /*
             * LE MESSAGE DU BACKEND N'EST PAS REPRIS TEL QUEL. Il est en francais
             * uniquement et porte la sortie d'erreur brute de la commande
             * distante (« sh: 1: systemctl: not found »). Le portage dit l'ISSUE,
             * traduite, et lit le BOOLEEN `restarted` plutot qu'une phrase.
             */
            'editeur_sauve_et_redemarre' => __('superv.editeur_sauve_et_redemarre'),
            'editeur_sauve_sans_redemarrage' => __('superv.editeur_sauve_sans_redemarrage'),
            'editeur_sauver_refus' => __('superv.editeur_sauver_refus', ['statut' => '{statut}']),
            'editeur_sauver_echec' => __('superv.editeur_sauver_echec'),
            'restaurer_bouton' => __('superv.restaurer_bouton'),
            'restaurer_cout' => __('superv.restaurer_cout', [
                'nom' => '{nom}', 'chemin' => '{chemin}',
            ]),
            'restaurer_en_cours' => __('superv.restaurer_en_cours', ['nom' => '{nom}']),
            'restaure_et_redemarre' => __('superv.restaure_et_redemarre', ['nom' => '{nom}']),
            'restaure_sans_redemarrage' => __('superv.restaure_sans_redemarrage', ['nom' => '{nom}']),
            'restaurer_refus' => __('superv.restaurer_refus', ['statut' => '{statut}']),
            'restaurer_echec' => __('superv.restaurer_echec'),
            // ── Sous-lot V10 : la reconfiguration ──────────────────────────
            'reconf_cout' => __('superv.reconf_cout', ['nom' => '{nom}', 'chemin' => '{chemin}']),
            'reconf_effet_fusion' => __('superv.reconf_effet_fusion', ['chemin' => '{chemin}']),
            'reconf_en_cours' => __('superv.reconf_en_cours', ['nom' => '{nom}']),
            /*
             * QUATRE ISSUES, tirees du CONTENU du flux et non de son dernier
             * marqueur — qui annonce `SUCCESS_MACHINE::` deux lignes apres un
             * `code 127` (PARITE E-85). `reconf_partielle` est celle que le
             * legacy perd entierement.
             */
            'reconf_reussie' => __('superv.reconf_reussie', ['nom' => '{nom}']),
            'reconf_partielle' => __('superv.reconf_partielle', [
                'nom' => '{nom}', 'codes' => '{codes}',
            ]),
            'reconf_echouee' => __('superv.reconf_echouee', ['nom' => '{nom}']),
            'reconf_inachevee' => __('superv.reconf_inachevee', ['nom' => '{nom}']),
            'reconf_avertissements' => __('superv.reconf_avertissements', ['nombre' => '{nombre}']),
            'reconf_refus' => __('superv.reconf_refus', ['statut' => '{statut}']),
            'reconf_echec' => __('superv.reconf_echec'),
            // ── Sous-lot V11 : la desinstallation ──────────────────────────
            'desinst_cout' => __('superv.desinst_cout', ['nom' => '{nom}', 'chemin' => '{chemin}']),
            'desinst_production' => __('superv.desinst_production', ['nom' => '{nom}']),
            'desinst_en_cours' => __('superv.desinst_en_cours', ['nom' => '{nom}']),
            /*
             * CINQ ISSUES. Le backend ne peut plus mentir depuis v1.37.44, mais
             * il ne peut pas non plus tout garantir : « rien a purger » n'est pas
             * « desinstalle », et un succes annonce n'est pas un succes VERIFIE.
             * Le portage rejoue donc la detection de version APRES le geste.
             */
            'desinst_purge' => __('superv.desinst_purge', ['nom' => '{nom}', 'paquets' => '{paquets}']),
            'desinst_rien' => __('superv.desinst_rien', ['nom' => '{nom}']),
            'desinst_echouee' => __('superv.desinst_echouee', ['nom' => '{nom}', 'codes' => '{codes}']),
            'desinst_inachevee' => __('superv.desinst_inachevee', ['nom' => '{nom}']),
            'desinst_refus' => __('superv.desinst_refus', ['statut' => '{statut}']),
            'desinst_echec' => __('superv.desinst_echec'),
            'desinst_verif_en_cours' => __('superv.desinst_verif_en_cours'),
            'desinst_verif_absent' => __('superv.desinst_verif_absent'),
            'desinst_verif_present' => __('superv.desinst_verif_present', ['version' => '{version}']),
            'desinst_verif_impossible' => __('superv.desinst_verif_impossible'),
        ];
    }
}
