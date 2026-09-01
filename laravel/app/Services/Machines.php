<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Liste de reference des machines du parc, pour les selecteurs et les filtres.
 *
 * Deux pages en avaient besoin — le journal des commandes et les tickets — et
 * la seconde allait recopier la premiere. Une decision recopiee finit par
 * diverger : elle vit donc a un seul endroit.
 *
 * AUCUN FILTRE D'ACCES ICI. Les pages qui s'en servent sont reservees a
 * l'administration, qui a vocation a voir le parc entier ; c'est le meme choix
 * que le legacy, et il est delibere. Il ne doit PAS etre repris pour une page
 * ouverte a des comptes sans permission — c'est precisement le defaut du
 * tableau de bord du legacy, qui sert ces memes donnees a tout le monde.
 */
class Machines
{
    /** @return list<object> */
    public function liste(): array
    {
        try {
            return DB::table('machines')->select('id', 'name')->orderBy('name')->get()->all();
        } catch (\Throwable) {
            // Une liste de reference est un confort : son indisponibilite ne
            // doit pas empecher la consultation de la page.
            return [];
        }
    }

    /**
     * Le parc tel que la page des mises a jour l'affiche : treize colonnes.
     *
     * CLOISONNEMENT REPRIS DU LEGACY. `update/index.php` admet le role 1 s'il
     * porte `can_update_linux`, et ne lui montre alors que les machines de
     * `user_machine_access`. C'est un cloisonnement REEL — contrairement au
     * tableau de bord du legacy, qui sert le parc entier a tout le monde. Il est
     * reproduit ici a l'identique.
     *
     * LES MACHINES ARCHIVEES SONT EXCLUES, comme le fait `/filter_servers`, qui
     * sert les relectures de la meme page. Sans ce filtre les deux sources ne
     * montraient pas le meme parc : une machine archivee s'affichait au premier
     * rendu, etait cochable, pouvait recevoir un `apt full-upgrade` ou un
     * redemarrage — puis disparaissait sans un mot au premier « Rafraichir »,
     * le nombre de lignes changeant tout seul. Le rendu est commun aux deux
     * sources ; les DONNEES doivent l'etre aussi.
     *
     * @return list<object>
     */
    public function pourMisesAJour(int $roleId, int $userId): array
    {
        try {
            $requete = DB::table('machines as m')->select(
                'm.id', 'm.name', 'm.ip', 'm.port', 'm.linux_version', 'm.last_checked',
                'm.online_status', 'm.maj_secu_date', 'm.maj_secu_last_exec_date',
                'm.last_reboot', 'm.environment', 'm.criticality', 'm.network_type',
            )->where(function ($q) {
                $q->whereNull('m.lifecycle_status')
                  ->orWhere('m.lifecycle_status', '!=', 'archived');
            });

            if ($roleId < 2) {
                $requete->join('user_machine_access as uma', 'm.id', '=', 'uma.machine_id')
                        ->where('uma.user_id', $userId);
            }

            return $requete->orderBy('m.name')->get()->all();
        } catch (\Throwable $e) {
            // Une base injoignable rend EXACTEMENT le meme ecran qu'un parc vide,
            // texte d'aide compris. L'ancien commentaire pretendait le contraire
            // (« son indisponibilite se voit ») : elle ne se voyait pas, et rien
            // n'en gardait trace. Au moins la journaliser.
            Log::error('[Machines::pourMisesAJour] parc illisible : ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Le parc VU PAR CE COMPTE, et le parc entier — les deux, jamais l'un seul.
     *
     * ══ E-208 : LE TABLEAU DE BORD DU LEGACY NE CLOISONNE PAS ════════════
     *
     * `legacy/index.php` sert la taille du parc a tout le monde, sans filtrer
     * selon les machines auxquelles le compte a acces. Porter fidelement
     * reproduirait la fuite ; porter borne sans rien dire retirerait une
     * visibilite. L'arbitrage rendu est : **borner, ET dire le total.**
     *
     * D'ou DEUX nombres. « 1 de vos machines » seul laisserait croire que le
     * parc en compte une ; « 3 au parc » seul serait la fuite. Ensemble, ils
     * disent la borne sans la cacher : un compte qui ne voit qu'une machine sur
     * trois DOIT savoir que le parc en compte trois, sinon le tableau de bord
     * mentirait par omission au lieu de fuir.
     *
     * Le predicat de bornage est celui de `pourMisesAJour` ci-dessus, et celui
     * d'`Iptables::machines` et `Fail2ban::machines` : role >= 2 voit le parc,
     * role 1 est joint a `user_machine_access`. On le REPREND, on ne le
     * reinvente pas — trois implementations d'une meme regle finissent par
     * diverger.
     *
     * Cout mesure de la borne : un seul compte reel la subit, et les deux
     * machines qu'il cesse de voir sont deux machines auxquelles il n'a aucun
     * acces.
     *
     * @return array{perimetre:int,parc:int,borne:bool,lisible:bool}
     */
    public function compteursPerimetre(int $roleId, int $userId): array
    {
        $actives = $this->predicatActives();

        try {
            $parc = DB::table('machines as m')->where($actives)->count();

            if ($roleId >= 2) {
                // Pas de jointure : le perimetre EST le parc. Le dire ainsi
                // evite un compte redondant et rend `borne` faux, ce qui permet
                // a l'ecran de ne pas afficher une reserve sans objet.
                return ['perimetre' => $parc, 'parc' => $parc, 'borne' => false, 'mord' => false, 'lisible' => true];
            }

            $perimetre = $this->requeteBornee($roleId, $userId)->count();

            return [
                'perimetre' => $perimetre,
                'parc'      => $parc,
                'borne'     => true,
                /*
                 * ══ « LA BORNE EXISTE » N'EST PAS « LA BORNE MORD » ═══════════
                 *
                 * E-263. `borne` dit qu'un perimetre s'applique (role 1) ;
                 * `mord` dit qu'il RETIRE quelque chose. Les deux ne coincident
                 * pas : un role 1 a qui TOUTES les machines sont attribuees est
                 * borne sans rien perdre, et l'ecran lui affichait alors
                 * « 3 de vos machines · 3 au parc » suivi d'une reserve
                 * annoncant une restriction qui ne restreint rien.
                 *
                 * C'est le meme defaut que celui du role >= 2, par l'autre bout :
                 * la-bas le possessif mentait, ici c'est la reserve. Un seul
                 * discriminant les couvre tous les deux.
                 */
                'mord'      => $perimetre < $parc,
                'lisible'   => true,
            ];
        } catch (\Throwable $e) {
            // UNE BASE INJOIGNABLE N'EST PAS UN PARC VIDE. Rendre des zeros
            // afficherait « 0 de vos machines · 0 au parc », ce qui se lit comme
            // un fait. `lisible` a faux laisse l'ecran DIRE qu'il n'a pas su
            // lire — c'est le defaut que le commentaire de `pourMisesAJour`
            // signale juste au-dessus, et qu'on ne refait pas ici.
            Log::error('[Machines::compteursPerimetre] parc illisible : ' . $e->getMessage());

            return ['perimetre' => 0, 'parc' => 0, 'borne' => false, 'mord' => false, 'lisible' => false];
        }
    }

    /**
     * Le predicat « machine active », en UN seul endroit.
     *
     * Il etait ecrit deux fois dans ce fichier et quatre fois dans le portage.
     * Factorise ICI plutot que recopie une cinquieme fois : *trois
     * implementations d'une meme regle finiront par diverger.*
     */
    private function predicatActives(): callable
    {
        return function ($q) {
            $q->whereNull('m.lifecycle_status')
              ->orWhere('m.lifecycle_status', '!=', 'archived');
        };
    }

    /**
     * Une requete sur `machines` DEJA BORNEE au perimetre du compte.
     *
     * Role >= 2 : le perimetre EST le parc, aucune jointure. Role 1 : jointure
     * sur `user_machine_access`. C'est le meme predicat que `pourMisesAJour`,
     * `Iptables::machines` et `Fail2ban::machines` — repris, pas reecrit.
     *
     * Tous les indicateurs de `indicateurs()` partent de cette requete : c'est
     * ce qui garantit qu'aucun d'eux ne peut oublier la borne. Un indicateur
     * ajoute plus tard l'hérite sans y penser.
     */
    private function requeteBornee(int $roleId, int $userId)
    {
        $requete = DB::table('machines as m')->where($this->predicatActives());

        if ($roleId < 2) {
            $requete->join('user_machine_access as uma', 'm.id', '=', 'uma.machine_id')
                    ->where('uma.user_id', $userId);
        }

        return $requete;
    }

    /**
     * Les indicateurs de parc du tableau de bord, TOUS bornes au perimetre.
     *
     * ══ CE QUE LE LEGACY COMPTE, ET CE QU'IL EN DIT DE FAUX ══════════════
     *
     * `legacy/index.php:78-104` calcule ces valeurs SANS aucune borne : un
     * compte qui n'a acces a aucune machine lit quand meme la taille du parc,
     * son nombre de CVE critiques et la date du dernier scan. C'est la fuite que
     * `DECISIONS-DSI.md` §1 a tranchee — borner dans le portage, et DIRE le
     * total quand la borne mord.
     *
     * ══ TROIS ETATS D'ETAT RESEAU, PAS DEUX ══════════════════════════════
     *
     * Le legacy compte `= 'Online'` d'un cote et `!= 'ONLINE'` de l'autre.
     * Mesure du 2026-09-01 : la colonne contient `ONLINE` (1 machine) et
     * `Inconnu` (2). La collation est `utf8mb4_0900_ai_ci`, donc la difference
     * de casse n'a AUCUN effet en SQL — `'ONLINE' = 'Online'` rend vrai.
     *
     * **Ce que la casse masquait, c'est que `!= 'ONLINE'` compte les machines
     * d'etat INCONNU comme hors ligne.** Les deux compteurs somment au total, ce
     * qui les fait PARAITRE coherents — et c'est ce qui rend le defaut
     * invisible. Deux machines sur trois etaient annoncees « hors ligne » alors
     * que le produit ne sait pas.
     *
     * `Inconnu` existe DEJA dans la donnee : ce troisieme compteur n'ajoute donc
     * rien, il cesse de sommer ce que la colonne distingue.
     *
     * ⚠ ET LA COMPARAISON RESTE EN SQL. La porter en PHP avec `===` la rendrait
     * sensible a la casse et donnerait un resultat different du legacy — le
     * piege est la, pas dans la requete.
     *
     * ══ « ZERO MESURE » ET « RIEN LU » NE SONT PAS LE MEME ETAT ══════════
     *
     * `lisible` a faux quand la lecture echoue. Sans ca, un `cve_scans`
     * injoignable se rendrait « aucune CVE » — la direction rassurante, celle
     * que personne ne remesure.
     *
     * @return array{lisible:bool,borne:bool,machines:int,en_ligne:int,hors_ligne:int,inconnu:int,cle:int}
     */
    public function indicateurs(int $roleId, int $userId): array
    {
        try {
            $base = fn () => $this->requeteBornee($roleId, $userId);

            return [
                'lisible'    => true,
                'borne'      => $roleId < 2,
                'machines'   => $base()->count(),
                // LA CASSE EST CELLE DE LA DONNEE, pas celle du legacy : on
                // compare a ce que la colonne contient reellement.
                'en_ligne'   => $base()->where('m.online_status', 'ONLINE')->count(),
                'hors_ligne' => $base()->where('m.online_status', 'OFFLINE')->count(),
                // TOUT LE RESTE EST INCONNU, y compris `NULL`. Ecrire la liste
                // des valeurs « inconnues » aurait demande de la tenir a jour ;
                // le complement ne se perime pas.
                'inconnu'    => $base()
                    ->where(function ($q) {
                        $q->whereNull('m.online_status')
                          ->orWhereNotIn('m.online_status', ['ONLINE', 'OFFLINE']);
                    })->count(),
                'cle'        => $base()->where('m.platform_key_deployed', 1)->count(),
            ];
        } catch (\Throwable $e) {
            Log::error('[Machines::indicateurs] parc illisible : ' . $e->getMessage());

            return ['lisible' => false, 'borne' => false, 'machines' => 0,
                'en_ligne' => 0, 'hors_ligne' => 0, 'inconnu' => 0, 'cle' => 0];
        }
    }

    /**
     * Les indicateurs de vulnerabilites, BORNES au perimetre.
     *
     * ══ LE DSI LES DONNAIT POUR NON BORNABLES ; LA DONNEE DIT LE CONTRAIRE ══
     *
     * `SHOW COLUMNS FROM cve_scans` rend `machine_id`. Les trois valeurs se
     * bornent donc avec le prédicat existant. Elles n'etaient pas « non
     * bornees » : elles etaient non bornees DANS LA REQUETE DU LEGACY, ce qui
     * n'est pas la meme chose.
     *
     * L'enjeu est concret : la seule ligne de `cve_scans` de cette installation
     * porte 1458 CVE sur `srv-zabbix`. Un role 1 qui n'a pas cette machine ne
     * doit pas lire son compte.
     *
     * ══ TROIS ISSUES, PAS DEUX ══════════════════════════════════════════
     *
     * `aucun_scan` distingue « aucun scan dans mon perimetre » de « je n'ai pas
     * su lire ». Un `null` rendu comme zero se lirait « aucune CVE », et un parc
     * sans vulnerabilite connue est exactement ce qu'on aimerait croire.
     *
     * @return array{lisible:bool,aucun_scan:bool,date:string,cve:int,critiques:int}
     */
    public function indicateursCve(int $roleId, int $userId): array
    {
        try {
            // Les identifiants du perimetre, une fois — puis deux agregats
            // dessus. Refaire la jointure dans chaque requete marcherait, mais
            // la borne serait ecrite deux fois de plus.
            $ids = $this->requeteBornee($roleId, $userId)->pluck('m.id')->all();

            if ($ids === []) {
                // AUCUNE MACHINE AU PERIMETRE : ce n'est pas « aucun scan », et
                // ce n'est pas une erreur. L'ecran le dira comme tel.
                return ['lisible' => true, 'aucun_scan' => true, 'date' => '', 'cve' => 0, 'critiques' => 0, 'machine' => ''];
            }

            /*
             * ══ UN « DERNIER SCAN » QUI PEUT AVOIR ECHOUE N'EST PAS UNE DATE ══
             *
             * E-269. Ces deux valeurs n'avaient AUCUN filtre de statut : un scan
             * `running` ou `failed` devenait « le dernier scan », avec sa date et
             * son `cve_count` (souvent 0). L'ecran annoncait alors un constat la
             * ou il n'y avait qu'une TENTATIVE.
             *
             * ── ET LA FAUTE D'ECHELLE, QUI EST PLUS LARGE QUE SA CONDITION ────
             *
             * `date` et `cve` viennent d'UNE ligne de scan, donc d'UNE machine.
             * Le titre de section porte le parc : « 1458 CVE au dernier scan »
             * se lit comme un total de parc alors que c'est le compte d'une
             * seule machine. L'arbitrage demandait de nommer la machine « quand
             * le perimetre en compte une seule » ; on la nomme DES QU'ON LA
             * CONNAIT, parce que le motif invoque — la faute d'echelle — est
             * PIRE quand le perimetre est grand, pas quand il vaut un. La
             * condition contredisait sa propre raison.
             *
             * `critiques`, lui, somme le dernier scan complete de CHAQUE machine :
             * c'est le seul des trois qui porte reellement sur le perimetre, et
             * il ne nomme donc personne.
             */
            $dernier = DB::table('cve_scans as s')
                ->leftJoin('machines as m', 'm.id', '=', 's.machine_id')
                ->whereIn('s.machine_id', $ids)
                ->where('s.status', 'completed')
                ->orderByDesc('s.scan_date')
                ->first(['s.scan_date', 's.cve_count', 'm.name as machine']);

            /*
             * ══ LE DERNIER SCAN COMPLETE PAR MACHINE, PAS TOUS LES SCANS ═════
             *
             * E-265. Cette somme portait sur TOUTES les lignes de `cve_scans`
             * du perimetre, sans filtre de statut. Deux ecarts avec le legacy
             * (`legacy/index.php:102-106`), qui joint sur
             * `MAX(id) … WHERE status='completed' GROUP BY machine_id` :
             *
             *  1. un second scan de la meme machine s'AJOUTAIT au premier, au
             *     lieu de le remplacer — le nombre gonflait a chaque passage ;
             *  2. un scan `running` ou `failed` etait compte comme un constat.
             *
             * Les deux etaient INVISIBLES sur ce banc, et pour une raison qu'il
             * faut ecrire : la base ne contient qu'UNE ligne de scan
             * (`id=2, machine=1, completed`). Les deux definitions rendent donc
             * 103 toutes les deux, et la coincidence tenait a la donnee, pas au
             * code. Mesure du 2026-09-01, en vertu de « un nombre trop propre
             * est le premier signe » — releve en portant ce nombre dans une
             * alerte rouge, ou une somme gonflee ne serait pas restee un detail.
             */
            $derniersComplets = DB::table('cve_scans')
                ->selectRaw('MAX(id) as id')
                ->whereIn('machine_id', $ids)
                ->where('status', 'completed')
                ->groupBy('machine_id');

            $critiques = DB::table('cve_scans as s')
                ->joinSub($derniersComplets, 'l', 's.id', '=', 'l.id')
                ->sum('s.critical_count');

            return [
                'lisible'    => true,
                'aucun_scan' => $dernier === null,
                'date'       => (string) ($dernier->scan_date ?? ''),
                'cve'        => (int) ($dernier->cve_count ?? 0),
                // Le NOM de la machine dont vient ce scan. Vide si inconnu : le
                // libelle retombe alors sur sa forme sans nom, il ne rend pas
                // « de  » avec un trou.
                'machine'    => (string) ($dernier->machine ?? ''),
                'critiques'  => (int) $critiques,
            ];
        } catch (\Throwable $e) {
            Log::error('[Machines::indicateursCve] lecture impossible : ' . $e->getMessage());

            return ['lisible' => false, 'aucun_scan' => false, 'date' => '', 'cve' => 0, 'critiques' => 0, 'machine' => ''];
        }
    }

    /*
     * ══ LES DEUX FAITS DE SUIVI QU'AUCUNE TUILE N'AFFICHE ═══════════════
     *
     * E-264. Les autres alertes de machines se DERIVENT de `indicateurs()` et
     * `indicateursCve()` : elles sont deja a l'ecran, borner deux fois
     * n'apporterait rien et divergerait un jour. Ces deux-la, non — il faut
     * les lire, donc il faut les borner.
     *
     * `legacy/index.php:111` et `:133` les lisent sur le PARC ENTIER, et le
     * second dans un `catch (\Exception $e) {}` vide : sur une base muette
     * l'alerte disparait en silence.
     */
    public function alertesParc(int $roleId, int $userId): array
    {
        try {
            $ids = $this->requeteBornee($roleId, $userId)->pluck('m.id')->all();

            if ($ids === []) {
                // Aucune machine au perimetre : pas d'alerte, et ce n'est pas
                // une erreur non plus.
                return ['lisible' => true, 'maj_ancienne' => 0, 'ssh_faible' => 0];
            }

            // `last_checked IS NOT NULL` est dans le predicat du legacy et on le
            // garde : une machine jamais relevee n'est pas « relevee il y a
            // longtemps ». C'est un fait different, et il n'a pas d'alerte.
            $majAncienne = DB::table('machines')
                ->whereIn('id', $ids)
                ->whereNotNull('last_checked')
                ->where('last_checked', '<', now()->subDays(30))
                ->count();

            /*
             * Le dernier audit PAR machine, puis le predicat sur son score.
             * `MAX(id)` et non `MAX(date)` : c'est ce que fait le legacy, et
             * changer la definition d'un « dernier » en meme temps qu'on borne
             * la requete rendrait un ecart de nombre inexplicable.
             */
            $dernierParMachine = DB::table('ssh_audit_results')
                ->selectRaw('MAX(id) as id')
                ->whereIn('machine_id', $ids)
                ->groupBy('machine_id');

            $sshFaible = DB::table('ssh_audit_results as r')
                ->joinSub($dernierParMachine, 'l', 'r.id', '=', 'l.id')
                ->where('r.score', '<', 50)
                ->count();

            return [
                'lisible'      => true,
                'maj_ancienne' => $majAncienne,
                'ssh_faible'   => $sshFaible,
            ];
        } catch (\Throwable $e) {
            // PAS de catch vide. Une lecture ratee remonte comme illisible, et
            // l'ecran DIT qu'il n'a pas su lire plutot que de rester muet.
            Log::error('[Machines::alertesParc] lecture impossible : ' . $e->getMessage());

            return ['lisible' => false, 'maj_ancienne' => 0, 'ssh_faible' => 0];
        }
    }

    /**
     * Les etiquettes posees sur le parc, pour alimenter le filtre.
     *
     * Elles sont ecrites par le module `adm/`, non porte : cette page ne fait
     * que les lire. Une liste vide est un etat normal — le filtre s'affiche
     * alors sans rien a proposer, ce que la page DIT plutot que de masquer le
     * champ.
     *
     * @return list<string>
     */
    public function etiquettes(): array
    {
        try {
            return DB::table('machine_tags')->distinct()->orderBy('tag')->pluck('tag')->all();
        } catch (\Throwable) {
            return [];
        }
    }
}
