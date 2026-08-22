<?php

namespace App\Services;

use App\Support\SecretSupervision;
use Illuminate\Support\Facades\DB;

/**
 * Le module `supervision/`, sous-lot V1 : la page et ses quatre onglets.
 *
 * V1 NE JOINT AUCUNE MACHINE ET N'APPELLE AUCUNE ROUTE DU BACKEND. C'est ce qui
 * en fait le bon point d'entree d'un module dont les quatre derniers sous-lots
 * ecrivent sur des serveurs distants, en desinstallent l'agent ou en redemarrent
 * le service.
 *
 * DIFFERENCE MESUREE AVEC LE LEGACY, ET ELLE EST LE POINT DE V1. La page legacy
 * emet DEUX requetes backend des son chargement — `GET /supervision/profiles` et
 * `GET /supervision/profiles/assignments` — puis les rejoue a CHAQUE bascule
 * d'onglet. Le catalogue de profils est donc charge d'emblee, pas a l'ouverture
 * de son onglet : la frontiere V1/V2 n'existe pas cote legacy. Ici, la page se
 * peint entierement cote serveur (decision S3/S4) et son script ne parle a
 * personne.
 *
 * La garde de la page etant `role:2`, il n'y a PAS de cloisonnement par
 * `user_machine_access` a porter : le legacy n'en fait aucun non plus, et aucun
 * role 1 ne peut ouvrir cette page. Le filtre de cycle de vie, lui, est repris
 * tel quel — les machines archivees n'apparaissent pas.
 */
class Supervision
{
    /**
     * Les plateformes d'agent que le module connait, dans l'ordre du legacy.
     *
     * Liste FERMEE et posee en dur : elle sert de liste blanche au bloc de
     * configuration visible. Une plateforme lue d'une requete serait un
     * identifiant venu de la base injecte dans un `id=` de la page.
     *
     * @return list<string>
     */
    public function plateformes(): array
    {
        return ['zabbix', 'centreon', 'prometheus', 'telegraf'];
    }

    /**
     * Les quatre onglets, dans l'ordre du legacy.
     *
     * @return list<string>
     */
    public function onglets(): array
    {
        return ['config', 'profiles', 'deploy', 'editor'];
    }

    /**
     * Un profil precis, ou null — sous-lot V5, pour pre-remplir le formulaire.
     *
     * PRE-REMPLIR COTE SERVEUR PLUTOT QUE PORTER L'ENREGISTREMENT DANS LE DOM.
     * Le legacy serialise le profil ENTIER dans un attribut `onclick`
     * (652 et 671 caracteres mesures, `notes` d'exploitation comprise). Ici,
     * modifier un profil est une ADRESSE : `?profil=<id>`, et le formulaire arrive
     * rempli par le serveur. L'enregistrement n'est donc jamais dans la page deux
     * fois, et jamais dans un attribut de gestionnaire.
     */
    public function profil(int $id): ?object
    {
        return DB::table('supervision_metadata_profiles')
            ->select('id', 'platform', 'name', 'description', 'host_metadata',
                     'zabbix_server', 'zabbix_server_active', 'zabbix_proxy',
                     'listen_port', 'notes')
            ->where('id', $id)
            ->first();
    }

    /**
     * Cree ou met a jour un profil — sous-lot V5.
     *
     * LE DOUBLON EST REFUSE PAR LA BASE, PAS PAR UNE POLITESSE D'INTERFACE.
     * `supervision_metadata_profiles` porte `UNIQUE KEY uk_platform_name
     * (platform, name)` — verifie au schema, pas suppose : le message du backend
     * doute de lui-meme (« nom deja pris ? ») mais il a raison. On tente donc
     * l'ecriture et on RATTRAPE la violation, au lieu de la devancer par un
     * `SELECT` : entre les deux, un autre enregistrement peut passer.
     *
     * @param  array<string,mixed>  $valeurs
     * @return 'ok'|'doublon'|'inconnu'
     */
    public function enregistreProfil(string $plateforme, array $valeurs, ?int $id): string
    {
        if (! in_array($plateforme, $this->plateformes(), true)) {
            return 'inconnu';
        }

        try {
            if ($id === null) {
                $valeurs['platform'] = $plateforme;
                DB::table('supervision_metadata_profiles')->insert($valeurs);

                return 'ok';
            }

            // La plateforme est dans le filtre, comme pour la configuration : un
            // `id` suffirait, mais une relecture doit constater le cloisonnement
            // sans remonter a la requete qui a choisi cet `id`.
            $touchees = DB::table('supervision_metadata_profiles')
                ->where('id', $id)
                ->where('platform', $plateforme)
                ->update($valeurs);

            return $touchees > 0 ? 'ok' : 'inconnu';
        } catch (\Illuminate\Database\QueryException $e) {
            // 23000 : violation de contrainte d'integrite — ici, l'unicite du
            // couple (plateforme, nom). Toute autre erreur remonte.
            if ($e->getCode() === '23000') {
                return 'doublon';
            }
            throw $e;
        }
    }

    /**
     * Supprime un profil — sous-lot V5. GESTE DESTRUCTEUR.
     *
     * `fk_msp_profile` porte un `ON DELETE CASCADE` VERIFIE au schema : supprimer
     * un profil emporte ses assignations, donc les serveurs concernes retombent
     * sur la configuration globale au prochain deploiement. Ce n'est pas un effet
     * de bord, c'est l'effet — et il doit etre annonce AVANT le geste, pas
     * constate apres.
     *
     * @return int nombre de lignes supprimees
     */
    public function supprimeProfil(int $id, string $plateforme): int
    {
        if (! in_array($plateforme, $this->plateformes(), true)) {
            return 0;
        }

        return DB::table('supervision_metadata_profiles')
            ->where('id', $id)
            ->where('platform', $plateforme)
            ->delete();
    }

    /** Combien de machines perdraient leur profil si celui-ci disparaissait. */
    public function machinesAssignees(int $idProfil): int
    {
        return DB::table('machine_supervision_profile')
            ->where('profile_id', $idProfil)
            ->count();
    }

    /**
     * Enregistre la configuration globale d'UNE plateforme — sous-lot V4.
     *
     * `WHERE platform = ?` — ET C'EST TOUT LE SUJET. Le backend
     * (`supervision.py:508`) fait `SELECT id ... ORDER BY id DESC LIMIT 1` SANS
     * filtre de plateforme puis `UPDATE ... WHERE id`. Mesure du 2026-08-22 :
     * enregistrer le formulaire Zabbix a ecrit la valeur tapee DANS LA LIGNE
     * CENTREON, et laisse la ligne Zabbix intacte — l'exploitant voit un succes,
     * sa configuration Zabbix n'a pas bouge, et celle de Centreon est corrompue.
     * Ecrire en base plutot que par cette route, c'est ne pas heriter du defaut.
     *
     * LE SECRET SUIT LA REGLE DU LEGACY, POUR LA MEME RAISON. Un PSK absent du
     * formulaire veut dire « ne change rien », jamais « efface » : le champ porte
     * un masque, pas la valeur, donc un enregistrement de routine ne doit pas
     * effacer un secret que personne n'a voulu toucher.
     *
     * @param  array<string,mixed>  $valeurs  colonnes deja bornees par l'appelant
     */
    public function enregistreConfiguration(string $plateforme, array $valeurs,
                                            ?string $pskClair, int $idCompte): void
    {
        if (! in_array($plateforme, $this->plateformes(), true)) {
            // Liste FERMEE : une plateforme venue d'une requete n'ecrit rien.
            return;
        }

        $chiffre = SecretSupervision::chiffre($pskClair);
        if ($chiffre !== null) {
            $valeurs['tls_psk_value'] = $chiffre;
        }
        $valeurs['updated_by'] = $idCompte > 0 ? $idCompte : null;

        // La ligne COURANTE de cette plateforme, au sens ou les deux portails
        // l'entendent : la plus recente. Pas « la » ligne — il n'y a aucune
        // contrainte d'unicite sur `platform` (voir PARITE E-75).
        $courante = DB::table('supervision_config')
            ->where('platform', $plateforme)
            ->orderByDesc('id')
            ->value('id');

        if ($courante === null) {
            $valeurs['platform'] = $plateforme;
            DB::table('supervision_config')->insert($valeurs);

            return;
        }

        DB::table('supervision_config')
            ->where('id', $courante)
            // La plateforme est REPETEE dans le filtre : `id` suffirait, mais une
            // relecture doit pouvoir constater le cloisonnement sans remonter a
            // la requete qui a choisi cet `id`.
            ->where('platform', $plateforme)
            ->update($valeurs);
    }

    /**
     * La configuration globale, par plateforme — sous-lot V3, LECTURE SEULE.
     *
     * « LA » CONFIGURATION GLOBALE N'EXISTE PAS : C'EST LA PLUS RECENTE.
     * `supervision_config` n'a **aucune contrainte d'unicite** sur `platform` —
     * sa cle primaire est `id` seul. Le backend (`supervision.py:132`) et la page
     * legacy lisent tous deux `ORDER BY id DESC LIMIT 1` : rien n'empeche
     * d'accumuler des lignes pour une meme plateforme, et c'est la derniere ecrite
     * qui gagne. Le portage reproduit ce choix — le corriger serait une migration,
     * donc une decision d'exploitant — mais il le NOMME au lieu de le supposer.
     *
     * LES DEUX SECRETS NE SONT JAMAIS SELECTIONNES. `tls_psk_value` et
     * `telegraf_output_token` ne sortent pas de la base : la requete rend un
     * BOOLEEN qui dit s'ils sont poses. Masquer une valeur deja chargee laisse
     * cette valeur en memoire, dans la vue, et a portee du premier gabarit qui
     * l'affichera par megarde ; ne pas la lire ferme la question.
     *
     * @return array<string,?object> indexe par plateforme, null si rien d'enregistre
     */
    public function configurationParPlateforme(): array
    {
        // La ligne la plus recente de CHAQUE plateforme, en une requete.
        $derniers = DB::table('supervision_config')
            ->selectRaw('MAX(id) as id')
            ->groupBy('platform')
            ->pluck('id')
            ->all();

        $configuration = array_fill_keys($this->plateformes(), null);

        if ($derniers === []) {
            return $configuration;
        }

        $lignes = DB::table('supervision_config')
            ->select('id', 'platform', 'agent_type', 'agent_version', 'zabbix_server',
                     'zabbix_server_active', 'listen_port', 'hostname_pattern',
                     'tls_connect', 'tls_accept', 'tls_psk_identity',
                     'host_metadata_template', 'extra_config',
                     'centreon_host', 'centreon_port',
                     'prometheus_listen', 'prometheus_collectors',
                     'telegraf_output_url', 'telegraf_output_org',
                     'telegraf_output_bucket', 'telegraf_inputs')
            // LES DEUX SECRETS RESTENT EN BASE : on ne lit que leur PRESENCE.
            ->selectRaw("(tls_psk_value IS NOT NULL AND tls_psk_value <> '') as psk_pose")
            ->selectRaw("(telegraf_output_token IS NOT NULL AND telegraf_output_token <> '') as jeton_pose")
            ->whereIn('id', $derniers)
            ->get();

        foreach ($lignes as $ligne) {
            $plateforme = (string) $ligne->platform;
            if (array_key_exists($plateforme, $configuration)) {
                $configuration[$plateforme] = $ligne;
            }
        }

        return $configuration;
    }

    /**
     * Le catalogue de profils, par plateforme — sous-lot V2, LECTURE SEULE.
     *
     * LE SCHEMA A ETE MESURE AVANT D'ECRIRE CETTE REQUETE, et il a corrige deux
     * suppositions : la table s'appelle `supervision_metadata_profiles` (pas
     * `supervision_profiles`), et le nombre de machines assignees ne vit pas dans
     * une colonne de `machines` mais dans `machine_supervision_profile`, dont la
     * cle primaire est `(machine_id, platform)` — une machine porte donc UN profil
     * PAR PLATEFORME, et le compte se filtre par plateforme.
     *
     * LES COLONNES SONT NOMMEES, jamais `SELECT *`. La route backend, elle, fait
     * `SELECT *` et envoie au navigateur `notes`, `tls_connect`, `tls_accept`,
     * `created_at` et `updated_at` alors que son tableau n'affiche que cinq
     * colonnes. Ici la page ne recoit que ce qu'elle montre.
     *
     * @return array<string,list<object>> indexe par plateforme
     */
    public function profilsParPlateforme(): array
    {
        $comptes = DB::table('machine_supervision_profile')
            ->select('profile_id', 'platform')
            ->selectRaw('COUNT(*) as machines')
            ->groupBy('profile_id', 'platform')
            ->get();

        $parProfil = [];
        foreach ($comptes as $ligne) {
            $parProfil[(int) $ligne->profile_id][(string) $ligne->platform] = (int) $ligne->machines;
        }

        $catalogue = array_fill_keys($this->plateformes(), []);

        $profils = DB::table('supervision_metadata_profiles')
            ->select('id', 'platform', 'name', 'description', 'host_metadata',
                     'zabbix_server', 'zabbix_server_active', 'zabbix_proxy', 'listen_port')
            ->whereIn('platform', $this->plateformes())
            ->orderBy('name')
            ->get();

        foreach ($profils as $p) {
            $plateforme = (string) $p->platform;
            // La plateforme vient d'une colonne de la base : on ne cree JAMAIS
            // une entree pour une valeur inattendue, sinon un enregistrement
            // decide de la structure de la page.
            if (! array_key_exists($plateforme, $catalogue)) {
                continue;
            }
            $p->machines = $parProfil[(int) $p->id][$plateforme] ?? 0;
            $catalogue[$plateforme][] = $p;
        }

        return $catalogue;
    }

    /**
     * Le chemin du fichier de configuration d'agent, par plateforme — sous-lot V7.
     *
     * CE CALCUL EST UN DOUBLON ASSUME DE `_config_file_path` (`supervision.py:281`),
     * ET LE TEST EN FAIT LA CONDITION. Le legacy, lui, affiche un chemin ECRIT EN
     * DUR cote client (`main.js:27-32`) : des que la configuration globale designe
     * l'agent historique, sa page nomme `zabbix_agent2.conf` alors que le portail
     * lit `zabbix_agentd.conf`. Mesure faite — voir PARITE E-79 : l'exploitant
     * croit editer un fichier et voit le contenu d'un autre.
     *
     * Ici le chemin vient de la MEME source que celle du backend (`agent_type` en
     * base), et la suite asserte que le chemin ANNONCE est bien celui qui a ete LU.
     * Un doublon mesure vaut mieux qu'une valeur en dur que rien ne confronte.
     *
     * @return array<string,string>
     */
    public function cheminsConfiguration(): array
    {
        $configuration = $this->configurationParPlateforme();
        // Le legacy retient `zabbix-agent2` quand rien n'est enregistre : la
        // colonne porte ce meme defaut, et le backend l'applique aussi.
        $typeZabbix = $configuration['zabbix']->agent_type ?? 'zabbix-agent2';

        return [
            'zabbix' => $typeZabbix === 'zabbix-agent'
                ? '/etc/zabbix/zabbix_agentd.conf'
                : '/etc/zabbix/zabbix_agent2.conf',
            'centreon' => '/etc/centreon-monitoring-agent/centagent.yaml',
            'prometheus' => '/etc/default/prometheus-node-exporter',
            'telegraf' => '/etc/telegraf/telegraf.conf',
        ];
    }

    /**
     * Les agents releves, par machine puis par plateforme — sous-lot V6.
     *
     * CETTE TABLE EST UN INVENTAIRE, PAS UNE VERITE. `supervision_agents` n'est
     * ecrite que par une detection : elle dit ce que le portail a CONSTATE la
     * derniere fois qu'on lui a demande, pas ce qui tourne a l'instant. Une
     * detection qui ne trouve rien SUPPRIME la ligne (`_remove_agent`), donc
     * l'absence d'agent y est un fait, pas un silence.
     *
     * @return array<int,array<string,string>> [machine_id][plateforme] => version
     */
    public function agentsParMachine(): array
    {
        $parMachine = [];
        foreach (DB::table('supervision_agents')
            ->select('machine_id', 'platform', 'agent_version')
            ->get() as $ligne) {
            $parMachine[(int) $ligne->machine_id][(string) $ligne->platform]
                = (string) ($ligne->agent_version ?? '');
        }

        return $parMachine;
    }

    /**
     * Le parc que la page a le droit de montrer : tout, sauf les archivees.
     *
     * Le filtre de cycle de vie est pose UNE FOIS et non dans une branche : le
     * mettre par branche, c'est l'oublier dans l'une d'elles le jour ou une
     * troisieme apparait (lecon E-46).
     *
     * @return list<object>
     */
    /**
     * LES REGLAGES PAR MACHINE, TELS QUE LE BACKEND LES LIT — sous-lot V10a.
     *
     * `supervision_overrides` est une table LIBRE : `param_name varchar(100)`,
     * `param_value text`, sans contrainte sur le contenu. Le backend, lui, ne
     * traite par leur nom que HUIT parametres ; tout le reste passe par une
     * boucle d'« overrides libres » qui les injecte tels quels dans le fichier.
     *
     * MESURE DU 2026-08-22 (PARITE.md E-85) : la valeur n'etait pas validee, et
     * un saut de ligne y produisait une DIRECTIVE AUTONOME dans le `.conf` — sur
     * un agent Zabbix reel, un `UserParameter`, donc l'execution d'une commande
     * arbitraire. Le backend valide desormais la valeur (v1.37.41).
     *
     * LE PORTAGE VA PLUS LOIN, ET C'EST DELIBERE : il n'ecrit QUE les huit
     * parametres nommes. Pas de champ libre, donc pas de nom arbitraire a
     * valider — la seule facon de ne pas rouvrir la porte est de ne pas
     * l'installer. Un reglage pose hors de cette liste par une autre voie reste
     * LU et AFFICHE (on ne cache pas ce qui existe), mais l'ecran ne permet pas
     * d'en creer.
     *
     * @return array<string, string>
     */
    public function overridesDeLaMachine(int $idMachine): array
    {
        $valeurs = [];

        foreach (DB::table('supervision_overrides')
            ->select('param_name', 'param_value')
            ->where('machine_id', $idMachine)
            ->orderBy('param_name')
            ->get() as $ligne) {
            $valeurs[(string) $ligne->param_name] = (string) $ligne->param_value;
        }

        return $valeurs;
    }

    /**
     * Enregistre les reglages d'une machine — sous-lot V10a.
     *
     * ECRITURE EN BASE, PAS PAR LA PASSERELLE. Meme raison qu'en V4 pour la
     * configuration globale : la route backend correspondante
     * (`POST /supervision/overrides/<id>`) est la SEULE route du module touchant
     * une machine sans `@require_machine_access` (E-85, declare et non corrige).
     * Ecrire ici, avec une liste fermee, c'est ne pas heriter de cette laxite.
     *
     * UN REGLAGE VIDE EST UNE SUPPRESSION, pas une valeur vide. Un
     * `param_value` vide serait relu par le backend comme une ligne
     * `Cle=` dans le fichier — donc une directive sans valeur. Le vide efface
     * la ligne : c'est la seule lecture qui ne fabrique rien.
     *
     * @param  array<string, string>  $valeurs  cles DEJA restreintes par l'appelant
     */
    public function enregistreOverrides(int $idMachine, array $valeurs): void
    {
        DB::transaction(function () use ($idMachine, $valeurs) {
            foreach ($valeurs as $nom => $valeur) {
                $valeur = trim((string) $valeur);

                if ($valeur === '') {
                    DB::table('supervision_overrides')
                        ->where('machine_id', $idMachine)
                        ->where('param_name', $nom)
                        ->delete();

                    continue;
                }

                DB::table('supervision_overrides')->updateOrInsert(
                    ['machine_id' => $idMachine, 'param_name' => $nom],
                    ['param_value' => $valeur],
                );
            }
        });
    }

    /**
     * CE QU'UN RELEVE DE PARC COUTE, CALCULE PAR LE SERVEUR — sous-lot V8.
     *
     * Le legacy ne dit rien de ce coût : son bouton « Scanner tous les agents »
     * boucle sur toutes les lignes du tableau x quatre plateformes et lance tout
     * en parallele. Mesure du 2026-08-22 : **le filtre de la table ne borne pas
     * le releve**. Filtre saisi sur `Test-Server`, une seule ligne visible, et
     * TROIS machines jointes — dont la production. Quelqu'un qui a reduit son
     * tableau pour n'agir que sur une machine en touche trois sans le savoir.
     *
     * Ici le coût est enonce AVANT le geste, et il est enonce par la meme source
     * que le tableau : le nombre de machines, le nombre de plateformes, le nombre
     * de sessions SSH, et **le nom des machines de production qui seront
     * jointes**. Nommer la production plutot que la compter est le point : « 3
     * machines » ne previent personne, « dont srv-zabbix (PROD) » previent.
     *
     * @return array{machines: int, plateformes: int, sessions: int, production: list<string>}
     */
    public function coutDuReleve(): array
    {
        $machines = $this->machines();
        $production = [];

        foreach ($machines as $machine) {
            /*
             * Le critere est celui de la colonne, pas une liste d'identifiants
             * ecrite ici : une machine promue en production doit apparaitre dans
             * cet avertissement sans qu'on ait a y penser.
             */
            if (strtoupper((string) ($machine->environment ?? '')) === 'PROD') {
                $production[] = (string) $machine->name;
            }
        }

        return [
            'machines' => count($machines),
            'plateformes' => count($this->plateformes()),
            /*
             * UNE session SSH par machine, pas une par plateforme. C'est ce que
             * le passage en tache de fond permet, et c'est MESURE : le journal
             * paramiko d'un releve montre un transport authentifie unique
             * portant les canaux 0 a 3, un par commande de version. Le legacy, en
             * lancant quatre requetes, ouvre quatre sessions par machine.
             */
            'sessions' => count($machines),
            'production' => $production,
        ];
    }

    public function machines(): array
    {
        return DB::table('machines')
            ->select('machines.id', 'machines.name', 'machines.ip', 'machines.port',
                     'machines.environment')
            ->where(function ($q) {
                $q->whereNull('machines.lifecycle_status')
                  ->orWhere('machines.lifecycle_status', '!=', 'archived');
            })
            ->orderBy('machines.name')
            ->get()
            ->all();
    }
}
