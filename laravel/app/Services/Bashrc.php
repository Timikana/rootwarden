<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Le deploiement du `.bashrc` standardise — module `bashrc/`, sous-lot B1.
 *
 * Porte `legacy/bashrc/index.php`. B1 ne couvre que **la page** : ses trois
 * onglets, ses gardes, son inventaire de machines. Les lectures distantes sont
 * B2, le gabarit B3, et les ecritures distantes B4.
 *
 * ══ CE MODULE N'A AUCUN DEFAUT DE SECURITE, ET IL FAUT LE DIRE ════════════
 *
 * L'inventaire (`MODULE-BASHRC.md` §3) l'etablit, et B1 l'a mesure :
 *
 * - les **huit** routes backend portent la pile complete de decorateurs, et le
 *   contournement du role 3 est IDENTIQUE cote PHP et cote Python ;
 * - l'en-tete du fichier legacy **dit vrai** — quatre autres modules du depot
 *   annoncent un acces plus strict qu'ils n'appliquent ;
 * - aucune valeur client ne s'interpole nue : contenu en base64, nom de compte
 *   valide par `^[a-z_][a-z0-9_-]{0,31}$`, et le home venu du `/etc/passwd`
 *   **DISTANT** valide par `^/[A-Za-z0-9._/-]{1,128}$` ;
 * - tous les gestes destructeurs confirment, et le deploiement multi-machines
 *   ENUMERE les machines par leur nom.
 *
 * ══ CE QUE LE PORTAGE CORRIGE EST DONC DE PRESENTATION ═══════════════════
 *
 * Trois defauts, tous vus A L'IMAGE et invisibles a toute assertion DOM :
 *
 * 1. **`srv-zabbix` est une ligne comme les autres.** La machine de PRODUCTION
 *    porte la meme case a cocher que les deux machines d'essai. Rien ne la
 *    distingue — et `_list_users` propose `root` (`UID == 0`), donc la page
 *    permet de cocher production + `root` et de deployer.
 *
 * 2. **« Deployer » est le bouton VERT** — la couleur la moins alarmante de la
 *    palette, donnee au geste qui ecrit sur toutes les machines cochees, tandis
 *    que « Deployer multi » est violet. Le codage n'est pas seulement
 *    arbitraire : **il est inverse par rapport au risque.**
 *
 * 3. **« Serveurs cibles 0 »** — un compteur a zero affiche comme un chiffre.
 *
 * C'est precisement le registre ou ce chantier a trouve ses defauts les plus
 * couteux : D9a (une aide qui disait faux), D9b (une aide qui recommandait
 * l'inverse de ce qui etait livre), et le « fusionner » de ce module-ci, dont le
 * terme porteur n'est defini nulle part.
 */
class Bashrc
{
    /**
     * Les motifs que l'editeur de gabarit RECONNAIT — et rien de plus.
     *
     * ══ CE QUE CECI EST, ET CE QUE CE N'EST PAS ══════════════════════════
     *
     * **Ce n'est pas un controle.** Le backend ne valide que la SYNTAXE du
     * gabarit (`bash -n`) et sa TAILLE (512 Ko) : une requete forgee vers
     * `POST /bashrc/template` ne voit aucun de ces motifs. Et ce n'est pas une
     * faille — quiconque atteint cette route detient deja `can_manage_bashrc`,
     * c'est-a-dire l'autorisation explicite d'ecrire le fichier qui s'execute a
     * chaque connexion sur le parc.
     *
     * C'est un **garde-fou pour la personne qui edite** : huit formes connues,
     * reconnues au vol, nommees. Rien d'autre.
     *
     * L'ecran ne doit donc jamais parler de « contenu valide » ou « verifie » :
     * ce serait promettre une barriere qui n'existe pas. `go-bashrc-b3.mjs`
     * l'asserte — et le legacy, mesure, le fait deja correctement.
     *
     * ══ POURQUOI ICI ET PAS DANS LE JS ═══════════════════════════════════
     *
     * Une seule source pour le portage. Le legacy garde la sienne dans
     * `js/bashrc.js` : deux portails, deux listes, c'est inevitable pendant la
     * migration — mais chaque portail n'en a qu'une.
     */
    public const MOTIFS_DANGEREUX = [
        'rm -rf /'              => '\\brm\\s+-[rRf]+\\s+/(\\s|$)',
        'dd vers un disque'     => '\\bdd\\s+if=.*of=/dev/[sh]d[a-z]',
        'bombe a fourche'       => ':\\(\\)\\s*\\{[^}]*\\|\\s*:\\s*&[^}]*\\};\\s*:',
        'mkfs'                  => '\\bmkfs\\.\\w+\\s+/dev/',
        // PAS de `\b` devant le `>`. Le legacy en met un — et `\b` exige un
        // caractere de MOT juste avant. Dans `cat x > /dev/sda`, la forme
        // normale, il y a un espace : pas de frontiere, donc pas de detection.
        // Seul `x> /dev/sda`, colle, declenche. **Un des huit motifs du legacy
        // est ainsi largement inerte** (E-148).
        'redirection sur disque' => '>\\s*/dev/[sh]d[a-z]',
        'chmod 777 /'           => '\\bchmod\\s+-R\\s+0*777\\s+/',
        'curl | sh'             => '\\bcurl[^|]*\\|\\s*(sudo\\s+)?(ba)?sh\\b',
        'wget | sh'             => '\\bwget[^|]*\\|\\s*(sudo\\s+)?(ba)?sh\\b',
    ];

    /**
     * Le gabarit en vigueur, lu EN BASE.
     *
     * Repli sur le fichier du backend si la table est vide — c'est ce que fait
     * `_load_template` cote Python, et la table est amorcee a partir de lui.
     * Rendre une chaine vide ferait croire a un gabarit vide, ce qui est faux.
     */
    public function gabarit(string $nom = 'default'): ?string
    {
        $lignes = DB::select('SELECT content FROM bashrc_templates WHERE name = ?', [$nom]);

        return $lignes[0]->content ?? null;
    }

    /** Les machines proposables comme cibles.
     *
     * `criticality` est retenue avec le reste : c'est elle qui permet a l'ecran
     * de DISTINGUER la production au lieu de la noyer. Le legacy la lit aussi —
     * il ne l'affiche simplement pas sur cette page.
     */
    public function machines(): array
    {
        return DB::select(
            'SELECT id, name, ip, port, environment, criticality '
            . 'FROM machines '
            . "WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' "
            . 'ORDER BY name'
        );
    }

    /**
     * Cette machine demande-t-elle une attention particuliere ?
     *
     * DEUX sources, et il faut les deux : `environment = 'PROD'` OU
     * `criticality = 'CRITIQUE'`. Une machine peut etre critique sans etre en
     * production, et l'inverse ; se fier a une seule colonne laisserait passer
     * la moitie des cas.
     *
     * **Les deux colonnes sont des `enum`**, releves en base le 2026-08-26 :
     * `environment` vaut `PROD|DEV|TEST|OTHER`, `criticality` vaut
     * `CRITIQUE|NON CRITIQUE`. Une premiere redaction de ce bloc affirmait qu'il
     * s'agissait de texte libre — c'etait faux, et laisser un commentaire qui
     * dit l'inverse du schema serait exactement le defaut que ce chantier
     * traque. La normalisation en majuscules ne coute rien et reste, mais elle
     * ne se justifie plus par une contrainte absente : c'est une precaution.
     *
     * **`OTHER` est traite comme SENSIBLE, et c'est un choix.** Il ne veut pas
     * dire « pas de production » : il veut dire « on ne sait pas ». Sur une page
     * qui ecrit un fichier execute a chaque connexion, un environnement inconnu
     * ne doit pas etre silencieusement rangé du cote sur. Aucune machine ne
     * porte cette valeur aujourd'hui (trois machines : PROD/CRITIQUE,
     * DEV/NON CRITIQUE, DEV/NON CRITIQUE) — la regle est ecrite pour le jour ou
     * l'une la portera, pas pour l'etat present.
     */
    public function estSensible(object $machine): bool
    {
        $env = strtoupper(trim((string) ($machine->environment ?? '')));
        $crit = strtoupper(trim((string) ($machine->criticality ?? '')));

        // Un environnement vide est inconnu, donc sensible : meme raison
        // qu'`OTHER`. Fail-closed sur l'avertissement.
        return $env === 'PROD' || $env === 'OTHER' || $env === ''
            || $crit === 'CRITIQUE';
    }

    /** Le nombre de machines sensibles au parc, pour l'annonce d'ensemble. */
    public function compteSensibles(array $machines): int
    {
        return count(array_filter($machines, fn ($m) => $this->estSensible($m)));
    }

    /**
     * Le dernier deploiement REEL par machine, et separement la derniere
     * simulation.
     *
     * ══ PARITE : LE MOTIF EST CELUI DU LEGACY, AU CARACTERE PRES ═════════
     *
     * `legacy/bashrc/index.php:26-36` joint `user_logs` sur
     *     action LIKE CONCAT('[bashrc] deploy%machine_id=', m.id, '%')
     *     AND action NOT LIKE '%dry_run=True%'
     *
     * Deux contraintes, et une premiere redaction de cette methode n'en avait
     * AUCUNE des deux :
     *
     * 1. **`deploy` explicitement.** Elle acceptait tout `[bashrc]` portant un
     *    `machine_id` — donc `restore`, `install_figlet`. Une restauration se
     *    serait affichee comme un deploiement ;
     * 2. **les simulations exclues.** Elle les comptait comme des deploiements.
     *    La seule ligne presente en base au 2026-08-26 en est une : la colonne
     *    aurait annonce un deploiement sur `srv-zabbix` alors que RIEN n'y a
     *    jamais ete ecrit. Un mensonge sur la production.
     *
     * ══ CE QUE LE PORTAGE AJOUTE, ET QUI EST DECLARE ═════════════════════
     *
     * La derniere SIMULATION est rendue a part. Le legacy la jette : sa colonne
     * dit « jamais deploye », ce qui est vrai, mais perd que quelqu'un a
     * simule un deploiement sur cette machine. Sur `srv-zabbix`, c'est une
     * information qui merite d'exister — a condition de ne JAMAIS etre
     * presentee comme un deploiement. D'ou deux champs distincts, pas un champ
     * ambigu.
     */
    public function derniersDeploiements(): array
    {
        $lignes = DB::select(
            'SELECT l.action, l.created_at, u.name AS auteur '
            . 'FROM user_logs l LEFT JOIN users u ON u.id = l.user_id '
            . "WHERE l.action LIKE '[bashrc] deploy%' "
            . 'ORDER BY l.created_at DESC LIMIT 200'
        );

        $parMachine = [];
        foreach ($lignes as $l) {
            $action = (string) $l->action;
            if (! preg_match('/machine_id=(\d+)/', $action, $m)) {
                continue;
            }
            $id = (int) $m[1];
            // Le legacy teste `dry_run=True` litteralement ; on fait de meme
            // plutot que d'inventer une autre forme.
            $cle = str_contains($action, 'dry_run=True') ? 'simulation' : 'deploiement';
            // La requete est triee du plus recent au plus ancien : la premiere
            // vue pour un couple (machine, nature) est la bonne.
            if (! isset($parMachine[$id][$cle])) {
                $parMachine[$id][$cle] = [
                    'date'   => $l->created_at,
                    'auteur' => $l->auteur,
                ];
            }
        }

        return $parMachine;
    }
}
