<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Pare-feu iptables sur les machines distantes — sous-lot I1 : la consultation.
 *
 * Porte `legacy/iptables/index.php`. I1 ne couvre que **le releve des regles
 * actives et leur affichage**. La copie en base est I2, l'historique I3, la
 * validation a blanc I4, l'application et le retour arriere I5.
 *
 * ══ CE MODULE EST LE PLUS DANGEREUX DU CHANTIER APRES `ssh/` ═════════════
 *
 * `iptables-restore` **remplace atomiquement l'integralite des tables**. Un jeu
 * de regles portant `INPUT DROP` sans `ACCEPT` sur le port SSH ferme la session
 * en cours ET toutes les suivantes. Or le seul canal de RootWarden vers une
 * machine est SSH, et `/iptables-rollback` **passe lui aussi par SSH** : la
 * reprise exigerait une console physique.
 *
 * I1 ne fait qu'une LECTURE. Mais tout ce qui suit s'y branche, et c'est
 * pourquoi la garde et l'annonce se posent des maintenant.
 *
 * ══ L'EN-TETE DU LEGACY MENT, CELUI-CI NON ═══════════════════════════════
 *
 * `legacy/iptables/index.php:14` annonce « superadmin (role_id = 3) uniquement
 * — acces refuse a tous les autres roles », et `:44` le repete. Sa ligne 45
 * applique `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` : **le role 1
 * est admis**. Quatrieme occurrence du motif E-36.
 *
 * **La garde reelle, portee telle quelle : role 1 ET `can_manage_iptables`.**
 * Le role est un choix assume du projet (`CHANGELOG.md:3078-3085` : « un role 1
 * inscrit dans `user_machine_access` est operateur de ses machines »). On le
 * porte donc — mais on l'ECRIT, au lieu d'annoncer l'inverse.
 *
 * ══ LA LISTE DES MACHINES EST FILTREE PAR ACCES, ET CE N'EST PAS OPTIONNEL ══
 *
 * `legacy/iptables/index.php:52-58` filtre par `user_machine_access` des que le
 * role est inferieur a 2. **Ce filtrage est repris ici** — et il faut le dire,
 * parce que le portage voisin ne le fait pas : `App\Services\Fail2ban::machines()`
 * rend toutes les machines non archivees quel que soit le role. Aucun compte de
 * role 1 ne portant `can_manage_fail2ban`, l'ecart y est sans porteur ; il n'en
 * reste pas moins un ecart, et il est signale plutot que recopie.
 *
 * Le filtrage de la liste n'est d'ailleurs **pas** la garde : le backend
 * revalide par `@require_machine_access`, qui MORD au role 1 puisque aucune
 * route de ce module ne porte `@require_role`. La liste evite d'offrir ce qui
 * sera refuse ; elle ne protege pas.
 */
class Iptables
{
    /**
     * Les machines proposables, filtrees par acces pour les roles < 2.
     *
     * Les archivees sont hors du choix : les offrir reviendrait a proposer
     * d'ecrire le pare-feu d'une machine retiree du parc.
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
     * Reprise a l'identique de `Bashrc`, `ServicesSystemd` et `Fail2ban` : `PROD`
     * OU `CRITIQUE`, et **`OTHER` ou une valeur vide comptent comme sensibles** —
     * un environnement inconnu ne se range pas du cote sur.
     *
     * L'enjeu est ici plus grand qu'ailleurs : se tromper de machine sur ce
     * module ne degrade pas un service, il **coupe l'acces a la machine**.
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
     * Le port SSH de chaque machine, indexe par identifiant.
     *
     * ══ POURQUOI CETTE TABLE EXISTE DES I1 ═══════════════════════════════
     *
     * Les cinq gabarits de regles du legacy codent **`--dport 22` en dur**
     * (`legacy/iptables/js/main.js`), alors que le port SSH de chaque machine
     * est en base. Le gabarit `deny_all` porte meme le commentaire « seul SSH
     * est ouvert pour ne pas perdre l'acces » : **l'intention est ecrite, et
     * l'implementation suppose 22**.
     *
     * Les trois machines du parc ecoutent aujourd'hui sur 22, donc le defaut
     * n'est pas arme — et c'est precisement ce qui le rend invisible. La table
     * voyage donc avec la page des I1, pour que I4 et I5 s'y adossent au lieu
     * de re-decouvrir le probleme au moment de l'ecrire.
     *
     * @return array<int, int>
     */
    public function portsSsh(array $machines): array
    {
        $ports = [];
        foreach ($machines as $m) {
            $ports[(int) $m->id] = (int) ($m->port ?? 22);
        }

        return $ports;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  SOUS-LOT I2 — LA COPIE EN BASE
    // ══════════════════════════════════════════════════════════════════════

    /**
     * La borne de taille des deux colonnes.
     *
     * `rules_v4` et `rules_v6` sont des `TEXT` MySQL — 65 535 octets. Au-dela,
     * MySQL tronque en mode permissif et leve en mode strict : dans les deux cas
     * l'ecran annoncerait un enregistrement qui n'est pas celui qu'on a demande.
     * On refuse AVANT d'ecrire, et on dit la borne.
     */
    public const OCTETS_MAX = 65535;

    /**
     * Resout une machine ET controle l'acces, en une fois.
     *
     * ══ CONTROLER L'OBJET RESOLU, PAS LE PARAMETRE RECU ══════════════════
     *
     * Le legacy revalide l'acces dans ses handlers (`index.php:74-84`, patch
     * A01) parce que le `<select>` filtre n'est PAS une garde : un `server_id`
     * forge atteignait les regles de n'importe quelle machine. Le controle est
     * repris ici, et il porte sur la machine RETROUVEE EN BASE.
     *
     * Rendre `null` couvre les deux cas — machine inexistante et machine
     * interdite — DELIBEREMENT : distinguer les deux apprendrait a un appelant
     * qu'une machine existe derriere l'identifiant qu'il a essaye.
     */
    public function machineAccessible(int $idCompte, int $roleId, int $machineId): ?object
    {
        if ($roleId >= 2) {
            $lignes = DB::select(
                'SELECT id, name, ip, port FROM machines WHERE id = ? '
                . "AND (lifecycle_status IS NULL OR lifecycle_status != 'archived')",
                [$machineId]
            );

            return $lignes[0] ?? null;
        }

        $lignes = DB::select(
            'SELECT m.id, m.name, m.ip, m.port FROM machines m '
            . 'INNER JOIN user_machine_access uma ON uma.machine_id = m.id '
            . 'WHERE m.id = ? AND uma.user_id = ? '
            . "AND (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')",
            [$machineId, $idCompte]
        );

        return $lignes[0] ?? null;
    }

    /**
     * La copie en base des regles d'une machine, ou `null` s'il n'y en a pas.
     *
     * ══ `ORDER BY id DESC LIMIT 1` N'EST PAS DECORATIF ═══════════════════
     *
     * `iptables_rules` n'a AUCUNE contrainte d'unicite sur `server_id` — mesure
     * du schema : une simple `KEY server_id`, pas d'`UNIQUE`. Plusieurs lignes
     * par machine sont donc possibles.
     *
     * Le legacy fait `SELECT … WHERE server_id = ?` puis `fetch()`, SANS
     * `ORDER BY` : si deux lignes existaient, celle qui est lue ne serait pas
     * determinee. Meme defaut que le `LIMIT 1` sans `ORDER BY` deja releve sur
     * la revocation des cles d'API, ou il rendait la revocation non deterministe.
     *
     * La table est VIDE aujourd'hui (mesure) : aucun porteur. On lit quand meme
     * la plus recente — une lecture deterministe ne coute rien, et « personne
     * n'exerce ce chemin » n'est pas une propriete.
     */
    public function reglesEnBase(int $machineId): ?object
    {
        $lignes = DB::select(
            'SELECT id, rules_v4, rules_v6, updated_at FROM iptables_rules '
            . 'WHERE server_id = ? ORDER BY id DESC LIMIT 1',
            [$machineId]
        );

        return $lignes[0] ?? null;
    }

    /** Combien de lignes cette machine porte-t-elle ? Sert a DIRE l'anomalie. */
    public function compteLignesEnBase(int $machineId): int
    {
        $lignes = DB::select(
            'SELECT COUNT(*) AS n FROM iptables_rules WHERE server_id = ?',
            [$machineId]
        );

        return (int) ($lignes[0]->n ?? 0);
    }

    /**
     * Remplace la copie en base.
     *
     * `DELETE` puis `INSERT`, DANS UNE TRANSACTION, et non un `UPDATE` : sans
     * contrainte d'unicite, un `UPDATE` laisserait vivre d'eventuels doublons
     * anterieurs. Le legacy fait le meme couple, HORS transaction : une panne
     * entre les deux y laisserait la machine SANS AUCUNE copie, apres en avoir
     * eu une. Ici les deux gestes tiennent ou tombent ensemble.
     *
     * ══ CECI N'EST PAS UNE VALIDATION ════════════════════════════════════
     *
     * Enregistrer un jeu de regles ne dit rien de sa validite ni de son
     * innocuite : la verification a blanc est I4, l'application I5. Ce que I2
     * ecrit est une COPIE, et l'ecran doit le dire — sans quoi « enregistre »
     * se lirait « approuve ».
     */
    public function enregistreRegles(int $machineId, string $reglesV4, string $reglesV6): void
    {
        DB::transaction(function () use ($machineId, $reglesV4, $reglesV6) {
            DB::delete('DELETE FROM iptables_rules WHERE server_id = ?', [$machineId]);
            DB::insert(
                'INSERT INTO iptables_rules (server_id, rules_v4, rules_v6) VALUES (?, ?, ?)',
                [$machineId, $reglesV4, $reglesV6]
            );
        });
    }
}
