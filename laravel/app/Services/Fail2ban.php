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

    /** Les machines proposables — les archivees sont hors du choix. */
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
}
