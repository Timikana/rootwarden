<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Fail2ban sur les machines distantes — sous-lot F1 : statut et jails.
 *
 * Porte `legacy/fail2ban/index.php`. F1 ne couvre que **la page, son statut et
 * ses jails**. L'historique est F2, la configuration F3, les bans F4, les jails
 * et la liste blanche F5, les gestes sur tout le parc F6.
 *
 * ══ L'EN-TETE DU LEGACY MENT, CELUI-CI NON ═══════════════════════════════
 *
 * `legacy/fail2ban/index.php:5` annonce « Permissions : admin (2), superadmin
 * (3) ». Sa ligne 10 applique `checkAuth([ROLE_USER, ROLE_ADMIN,
 * ROLE_SUPERADMIN])` : **le role 1 est admis**. Troisieme occurrence du motif
 * E-36 — un en-tete qui annonce un acces plus strict que le code.
 *
 * **La garde reelle, portee telle quelle : role 1 ET `can_manage_fail2ban`.**
 * Le role est un choix assume du projet (`CHANGELOG.md:3078-3085` : « un role 1
 * inscrit dans `user_machine_access` est operateur de ses machines »). On le
 * porte donc — mais on l'ECRIT.
 *
 * ══ E-152 : LA PERMISSION N'EXISTE QU'A L'AFFICHAGE ══════════════════════
 *
 * Sur les 23 routes d'`iptables/` et `fail2ban/`, **deux** portent un
 * `@require_permission` — et ce sont les deux gestes les plus faibles.
 * `/fail2ban/ban`, `/enable_jail` et `/whitelist`, qui ecrivent **et redemarrent
 * le service**, n'ont ni role ni permission. Ni le proxy ni la passerelle ne
 * citent `/fail2ban/` dans leurs listes d'administration.
 *
 * **Le portage ne referme pas ce trou** : il faudrait `@require_permission` sur
 * les 21 routes qui en manquent, donc toucher la production. Porte au §7 du
 * plan avec cinq autres correctifs backend de la meme famille.
 *
 * ══ F1 N'EST PAS UN LOT EN LECTURE SEULE ═════════════════════════════════
 *
 * `/fail2ban/status` appelle `_update_status_cache`, qui ecrit dans
 * `fail2ban_status`. C'est un cache de tableau de bord, une ligne par machine :
 * la page ne le lit pas, elle le REMPLIT. La lecture d'un statut a donc un effet
 * de bord, et `go-fail2ban-f1.mjs` en prend une copie avant de mesurer.
 */
class Fail2ban
{
    /**
     * Les trois etats qu'une machine peut presenter, dans l'ordre ou on les
     * rencontre. Chacun appelle un geste DIFFERENT — et c'est pourquoi ils ne se
     * replient pas sur un booleen « ca marche / ca ne marche pas ».
     */
    public const ETATS = ['absent', 'arrete', 'actif'];

    /**
     * Les machines proposables — archivees exclues, ET BORNEES PAR LE ROLE.
     *
     * ══ E-205 : LE PORTAGE AVAIT PERDU LA REGLE DE ROLE ══════════════════
     *
     * `legacy/fail2ban/index.php:14-20` charge le parc EN DEUX BRANCHES : tout
     * le parc des le role 2, et une jointure sur `user_machine_access` en
     * dessous. `legacy/iptables/index.php:52-58` fait exactement la meme chose.
     * Les deux pages portaient la regle ; ce portage avait repris la page et
     * perdu la regle — un role 1 porteur de la permission voyait TOUT le parc.
     *
     * **Ce n'est pas son effet actuel qui le classe.** Aucun compte de role 1 ne
     * detient `can_manage_fail2ban` : l'ecart etait donc reel et SANS PORTEUR. Il
     * s'armait a la premiere attribution de cette permission — un geste
     * d'administration ordinaire, depuis `/comptes`, par quelqu'un qui n'a
     * aucune raison de savoir ce qu'il ouvre. *Une propriete qui tient parce que
     * personne n'exerce le chemin n'est pas une propriete : c'est un accident de
     * configuration.*
     *
     * La signature est celle d'`App\Services\Iptables::machines()` — meme
     * regle, meme forme, ecrite deux fois a l'identique pour que personne ne
     * recopie le mauvais des deux precedents. Trouve par la session 5 en portant
     * `iptables`, dans un module qui n'est pas le sien.
     *
     * Le troisieme porteur possible est `groups/`, dont le portage reste a
     * faire : sa page legacy, elle, ne filtre PAS (mesure du 2026-08-27,
     * `groups/index.php:22`), et la reprendre fidelement sera donc juste.
     */
    public function machines(int $idCompte, int $roleId): array
    {
        if ($roleId >= 2) {
            return DB::select(
                'SELECT id, name, ip, port, environment, criticality '
                . 'FROM machines '
                . "WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' "
                . 'ORDER BY name'
            );
        }

        return DB::select(
            'SELECT m.id, m.name, m.ip, m.port, m.environment, m.criticality '
            . 'FROM machines m '
            . 'INNER JOIN user_machine_access uma ON uma.machine_id = m.id '
            . 'WHERE uma.user_id = ? '
            . "AND (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived') "
            . 'ORDER BY m.name',
            [$idCompte]
        );
    }

    /**
     * Cette machine demande-t-elle une attention particuliere ?
     *
     * Reprise a l'identique de `Bashrc` et `ServicesSystemd` : `PROD` OU
     * `CRITIQUE`, et **`OTHER` ou une valeur vide comptent comme sensibles** —
     * un environnement inconnu ne se range pas du cote sur.
     *
     * Ici l'enjeu est particulier : **fail2ban protege la machine**. Le
     * desactiver ou vider ses jails sur une machine de production la laisse
     * exposee, et rien dans le legacy ne le signale.
     */
    public function estSensible(object $machine): bool
    {
        $env = strtoupper(trim((string) ($machine->environment ?? '')));
        $crit = strtoupper(trim((string) ($machine->criticality ?? '')));

        return $env === 'PROD' || $env === 'OTHER' || $env === ''
            || $crit === 'CRITIQUE';
    }

    /** Le nombre de machines sensibles, pour l'annonce d'ensemble. */
    public function compteSensibles(array $machines): int
    {
        return count(array_filter($machines, fn ($m) => $this->estSensible($m)));
    }

    /**
     * Combien de lignes d'historique chaque machine porte VRAIMENT.
     *
     * `GET /fail2ban/history` rend **50 lignes au plus** (`LIMIT 50`,
     * `fail2ban.py:313`) et n'annonce aucun total : le legacy affiche donc les
     * cinquante dernieres en ayant l'air exhaustif (E-154). Sur une machine
     * active, un historique de bans depasse cinquante en quelques heures.
     *
     * Ce compte permet a l'ecran de dire « 50 des 312 » plutot que « 50 ». Il
     * coute un `COUNT(*)` groupe, pas une ligne de plus transmise.
     */
    public function totauxHistorique(): array
    {
        $lignes = DB::select(
            'SELECT server_id, COUNT(*) AS n FROM fail2ban_history GROUP BY server_id'
        );
        $parMachine = [];
        foreach ($lignes as $l) {
            $parMachine[(int) $l->server_id] = (int) $l->n;
        }

        return $parMachine;
    }

    /**
     * Les noms des comptes, pour resoudre la colonne « Par ».
     *
     * `_log_ban_action` (`fail2ban.py:106`) enregistre
     * `request.headers.get('X-User-ID', 'admin')` : `performed_by` contient donc
     * un **identifiant numerique**, ou la chaine litterale `'admin'` en repli.
     * Le legacy l'affiche tel quel — la colonne montre « 16 », « 7 », « 3 »
     * (E-157). Le meme defaut a ete corrige dans `iptables/`, avec un
     * commentaire de huit lignes qui l'explique, et laisse ici : **sixieme
     * occurrence du motif « a moitie corrige »**.
     *
     * On resout donc l'identifiant en nom. Ce qui ne se resout pas ne se DEVINE
     * pas : un identifiant absent de la table s'affiche tel quel, dit comme non
     * resolu. Et le repli `'admin'` n'est pas un identifiant — rien ne le
     * distingue d'un compte reellement nomme `admin`, et l'ecran le dit.
     */
    public function nomsUtilisateurs(): array
    {
        $noms = [];
        foreach (DB::select('SELECT id, name FROM users') as $u) {
            $noms[(string) $u->id] = (string) $u->name;
        }

        return $noms;
    }

    /**
     * Le dernier statut connu d'une machine, LU dans le cache.
     *
     * On le lit sans le rafraichir : rafraichir ouvre une session SSH, et
     * afficher la page ne doit pas joindre trois machines. Le cache dit **quand**
     * il a ete releve, et l'ecran le dit aussi — un etat sans sa date se prend
     * pour un etat courant.
     */
    public function dernierStatut(): array
    {
        $lignes = DB::select(
            'SELECT server_id, installed, running, total_banned, last_checked '
            . 'FROM fail2ban_status'
        );
        $parMachine = [];
        foreach ($lignes as $l) {
            $parMachine[(int) $l->server_id] = [
                // `(bool) (int)` : ce sont des `tinyint(1)`, et selon le mode de
                // preparation PDO les rend en entiers ou en chaines. `"0"` est
                // VRAI en PHP faible — une machine arretee s'afficherait active.
                'installe'  => (bool) ((int) $l->installed),
                'actif'     => (bool) ((int) $l->running),
                'bannis'    => (int) $l->total_banned,
                'releve_le' => $l->last_checked,
            ];
        }

        return $parMachine;
    }

    /*
     * ══ F6 : LA PORTEE DES DEUX GESTES DE PARC ═══════════════════════════
     *
     * `POST /fail2ban/ban_all_servers` et `POST /fail2ban/install_all` sont les
     * DEUX SEULES routes du module qui ne prennent aucun `machine_id` : elles
     * choisissent leurs cibles elles-memes, en base, et les joignent TOUTES.
     * L'operateur ne peut donc pas connaitre la portee de son clic — meme en
     * principe, puisque pour l'installation le corps envoye est VIDE (E-173).
     *
     * ══ POURQUOI LE SQL EST RECOPIE ICI PLUTOT QUE DEDUIT ════════════════
     *
     * La regle est APPLIQUEE par le backend. Un portage qui la devinerait —
     * par exemple en lisant l'etat renvoye au dernier releve — repondrait
     * juste tant que les deux raisonnements coincident, et faux le jour ou ils
     * divergent. C'est la lecon de `maintenance/` : quand une regle vit
     * ailleurs, on la REMONTE de la ou elle s'applique, on ne la recalcule pas.
     *
     * Ces deux requetes sont donc celles des routes, clause pour clause
     * (`backend/routes/fail2ban.py:521` et `:680`), lues sur la MEME base.
     * Ce sont des `SELECT` : aucune machine n'est jointe.
     *
     * ══ CE QU'ELLES REVELENT, ET QUI EST LE FOND D'E-172 ════════════════
     *
     * L'installation retient `f.installed IS NULL OR f.installed = 0`. Une
     * machine JAMAIS relevee n'a pas de ligne dans `fail2ban_status` : le
     * `LEFT JOIN` rend `NULL`, et `NULL` passe le `WHERE`. **Ne l'avoir jamais
     * regardee suffit a la faire installer** — et c'est ainsi que `srv-zabbix`,
     * la machine de production, entre dans la portee.
     *
     * Le ban de parc fait l'inverse (`INNER JOIN ... WHERE f.running = 1`) :
     * il ne vise que les machines que le cache dit ACTIVES. Une machine dont
     * fail2ban est tombe depuis le dernier releve y figure encore ; une machine
     * installee depuis n'y figure pas.
     *
     * D'ou la date de releve rendue PAR MACHINE et non un maximum global : un
     * etat sans sa date se prend pour un etat courant, et ici cette date decide
     * du parc atteint par un geste irreversible.
     *
     * ══ UNE CIBLE QUE LE SELECTEUR NE MONTRE PAS ════════════════════════
     *
     * Ni l'une ni l'autre requete ne filtre `lifecycle_status`, alors que le
     * selecteur de cette page ECARTE les machines archivees (`machines()`
     * ci-dessus). Une machine retiree du parc reste donc une cible des gestes
     * de parc, sans figurer nulle part a l'ecran. Aucune machine n'est archivee
     * aujourd'hui — la branche est donc reelle et non exercee —, mais la portee
     * la MARQUE plutot que de la taire : c'est exactement le defaut « deux
     * sources pour la meme table » qui a laisse une machine archivee recevoir
     * un `apt full-upgrade` dans `update/`.
     */

    /** Les cibles de `POST /fail2ban/install_all`, avec le SQL de la route. */
    public function porteeInstallation(): array
    {
        return $this->cibles(
            'SELECT m.id, m.name, m.environment, m.criticality, m.lifecycle_status, '
            . 'f.last_checked, f.server_id '
            . 'FROM machines m '
            . 'LEFT JOIN fail2ban_status f ON m.id = f.server_id '
            . 'WHERE f.installed IS NULL OR f.installed = 0 '
            . 'ORDER BY m.name'
        );
    }

    /** Les cibles de `POST /fail2ban/ban_all_servers`, avec le SQL de la route. */
    public function porteeBan(): array
    {
        return $this->cibles(
            'SELECT m.id, m.name, m.environment, m.criticality, m.lifecycle_status, '
            . 'f.last_checked, f.server_id '
            . 'FROM machines m '
            . 'INNER JOIN fail2ban_status f ON m.id = f.server_id '
            . 'WHERE f.running = 1 '
            . 'ORDER BY m.name'
        );
    }

    /**
     * La portee complete, telle qu'elle voyage vers l'ecran.
     *
     * `parc` est le nombre total de machines de la table — celui sur lequel les
     * deux routes travaillent, donc PAS le nombre d'entrees du selecteur, qui
     * ecarte les archivees. Les deux comptes seraient egaux aujourd'hui ; les
     * confondre serait annoncer un total qui n'est pas celui du geste.
     */
    public function portee(): array
    {
        $total = DB::select('SELECT COUNT(*) AS n FROM machines');

        return [
            'installer' => $this->porteeInstallation(),
            'bannir'    => $this->porteeBan(),
            'parc'      => (int) ($total[0]->n ?? 0),
        ];
    }

    /**
     * Une liste de cibles, decrite par ce dont l'ecran a besoin pour la NOMMER.
     *
     * `jamais` n'est pas « pas de date » : c'est l'absence de LIGNE dans
     * `fail2ban_status`, ce qui est la raison meme pour laquelle la machine est
     * dans la portee d'une installation. On le lit sur `f.server_id`, la cle du
     * `LEFT JOIN`, et non sur `last_checked` — une ligne dont la date serait
     * nulle existerait quand meme.
     */
    private function cibles(string $sql): array
    {
        $cibles = [];
        foreach (DB::select($sql) as $l) {
            $cibles[] = [
                'id'        => (int) $l->id,
                'nom'       => (string) $l->name,
                'env'       => (string) ($l->environment ?? ''),
                'sensible'  => $this->estSensible($l),
                'archivee'  => strtolower(trim((string) ($l->lifecycle_status ?? ''))) === 'archived',
                'jamais'    => $l->server_id === null,
                'releve_le' => $l->last_checked,
            ];
        }

        return $cibles;
    }
}
