<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Les cles d'API — module `adm/`, sous-lot D7.
 *
 * ══ LA CLE N'EXISTE EN CLAIR QU'UNE FOIS, ET NULLE PART AILLEURS ══════════
 *
 * La table ne stocke que `key_prefix` (de quoi la reconnaitre a l'oeil) et
 * `key_hash` (SHA-256 de la valeur complete). La valeur elle-meme n'est rendue
 * qu'une fois, par `cree()`, a l'appelant qui l'affichera — et elle ne transite
 * par AUCUN autre stockage.
 *
 * En particulier, elle ne passe PAS par un message de session : le pilote de
 * session est `file`, et un `->with('cle', ...)` la deposerait sur le disque du
 * conteneur, la ou le legacy ne l'ecrit nulle part. Le controleur rend donc la
 * vue DIRECTEMENT en reponse au POST, sans redirection.
 *
 * ══ LA PORTEE EST UNE LISTE FERMEE, ET C'EST UNE DECISION ═════════════════
 *
 * Le legacy offre deux voies : des cases a cocher par module, et un champ libre
 * « Avance : editer les regex manuellement ». Les cases produisent des motifs
 * corrects, tous ancres. Le champ libre, lui, porte DEUX defauts mesures :
 *
 *   E-135  il est valide en PCRE (`preg_match`) et applique en Python
 *          (`re.search`). Mesure du 2026-08-26 : `(?<zone>/cve_.*)` et `(?R)`
 *          passent la validation et cassent l'application. Une portee acceptee
 *          a l'ecriture peut etre incompilable a la lecture, et le journal du
 *          backend annonce alors « API key DB lookup failed » — une panne de
 *          base, pour un motif qu'on vient de saisir.
 *   E-136  `re.search` n'est pas ancre : `/deploy` couvre
 *          `/x/deploy_platform_key`. Une portee se lit plus etroite qu'elle
 *          n'est.
 *
 * **Le portage n'offre que la liste fermee.** Ce n'est pas un appauvrissement
 * de confort : c'est la seule facon de garantir que ce qui est valide ici est
 * compilable la-bas, puisque ce portage ne peut pas compiler du Python. Une
 * entree libre validee se contourne par une requete forgee ; une entree libre
 * absente, non.
 *
 * Les motifs sont ceux du legacy, repris **a l'identique**, et ils sont tous
 * ancres par `^`.
 */
class ClesApi
{
    /**
     * La liste FERMEE des portees, reprise des preselections du legacy
     * (`api_keys.php:361-377`) sans en changer un caractere.
     *
     * @var array<string, list<string>>
     */
    public const MODULES = [
        'monitoring' => ['^/list_machines$', '^/server_status$', '^/linux_version$', '^/last_reboot$', '^/filter_servers$', '^/cve_trends$'],
        'cve' => ['^/cve_'],
        'ssh' => ['^/deploy', '^/preflight_check$', '^/platform_key$', '^/test_platform_key$', '^/scan_server_users$', '^/server_user_'],
        'updates' => ['^/apt_', '^/update', '^/security_updates$', '^/dpkg_repair$', '^/custom_update$', '^/dry_run_update$', '^/pending_packages$', '^/schedule_'],
        'iptables' => ['^/iptables'],
        'fail2ban' => ['^/fail2ban/'],
        'services' => ['^/services/'],
        'ssh_audit' => ['^/ssh-audit/'],
        'supervision' => ['^/supervision/'],
        'bashrc' => ['^/bashrc/'],
        'graylog' => ['^/graylog/'],
        'wazuh' => ['^/wazuh/'],
        'admin' => ['^/admin/', '^/server_lifecycle$', '^/exclude_user$'],
        'reboot' => ['^/reboot_server$'],
        'logs' => ['^/logs$', '^/update-logs$', '^/iptables-logs$'],
    ];

    /** Nom d'une cle : la regle du legacy, a l'identique. */
    public const MOTIF_NOM = '/^[a-zA-Z0-9_-]{3,100}$/';

    /**
     * Les cles, SANS leur hachage.
     *
     * `key_hash` n'est jamais selectionne : il n'a aucune raison de traverser
     * l'application pour finir dans une vue. Le legacy fait le meme choix
     * (`api_keys.php:163`), et il vaut d'etre gardé.
     *
     * @return list<array<string, mixed>>
     */
    public function liste(): array
    {
        return DB::table('api_keys')
            ->select('id', 'name', 'key_prefix', 'scope_json', 'consumer_hint',
                'created_at', 'revoked_at', 'last_used_at', 'last_used_ip', 'auto_generated')
            ->orderByDesc('id')
            ->get()->map(static fn ($k) => (array) $k)->all();
    }

    /**
     * Cree une cle et rend sa valeur EN CLAIR, une seule fois.
     *
     * @param  list<string>  $modules  cles de `MODULES`, hors liste ignorees
     * @return array{erreur?: string, cle?: string, prefixe?: string}
     */
    public function cree(string $nom, array $modules, ?string $indice, int $auteur): array
    {
        $nom = trim($nom);
        if (preg_match(self::MOTIF_NOM, $nom) !== 1) {
            return ['erreur' => 'cles.err_nom'];
        }

        // LISTE FERMEE : tout ce qui n'est pas une cle connue disparait. Il n'y
        // a donc rien a valider — une portee ne peut pas etre autre chose que
        // la reunion de motifs ecrits ici.
        $motifs = [];
        foreach ($modules as $m) {
            foreach (self::MODULES[$m] ?? [] as $motif) {
                $motifs[$motif] = true;
            }
        }
        $motifs = array_keys($motifs);
        if ($motifs === []) {
            // Une portee vide vaut TOUTES LES ROUTES cote backend
            // (`helpers.py:72` : `if scope:`). On refuse de la produire par
            // inadvertance — l'accorder doit etre un geste, pas un oubli.
            return ['erreur' => 'cles.err_portee_vide'];
        }
        sort($motifs);

        $secret = bin2hex(random_bytes(24));
        $prefixe = 'rw_live_' . substr($secret, 0, 6);
        $complete = $prefixe . '_' . substr($secret, 6);

        try {
            DB::table('api_keys')->insert([
                'name' => $nom,
                'key_prefix' => $prefixe,
                'key_hash' => hash('sha256', $complete),
                'scope_json' => json_encode($motifs),
                'consumer_hint' => $indice === null || $indice === '' ? null : mb_substr($indice, 0, 200),
                'created_by' => $auteur,
            ]);
        } catch (\Illuminate\Database\QueryException $e) {
            return ['erreur' => (string) $e->getCode() === '23000' ? 'cles.err_nom_pris' : 'cles.err_creation'];
        }

        $this->assureCleEnvironnement($auteur);

        return ['cle' => $complete, 'prefixe' => $prefixe];
    }

    /**
     * Enregistre la cle d'environnement si elle ne l'est pas DEJA — reconnue
     * par son HACHAGE, jamais par son nom.
     *
     * ══ POURQUOI PAS `INSERT IGNORE` SUR LE NOM ═══════════════════════════
     *
     * C'est ce que fait `api_keys.php:86`, et c'est le defaut E-137. Deux
     * mecanismes enregistrent le meme secret sous deux noms differents —
     * `bootstrap_api_key.py` sous `proxy-internal-legacy-bootstrap-<date>`, la
     * page sous `proxy-internal-legacy` — et `key_hash` n'est pas unique.
     * L'`INSERT IGNORE` ne voit donc pas le premier enregistrement et pose un
     * doublon. Mesure au clic du 2026-08-26 : une ligne de plus, un seul
     * `key_hash` distinct.
     *
     * Ce que cela produit est pire que la redondance :
     * `_validate_api_key_from_db` fait `WHERE key_hash = %s LIMIT 1` **sans
     * `ORDER BY`**. Avec deux lignes, revoquer l'une rend l'authentification
     * NON DETERMINISTE — la cle peut etre refusee alors qu'un enregistrement
     * actif subsiste, ou continuer d'ouvrir alors qu'on vient de la revoquer.
     *
     * Ici on interroge donc le HACHAGE, exactement comme `bootstrap_api_key.py`
     * le fait (`:40`) — le seul des deux mecanismes qui soit idempotent.
     *
     * POURQUOI CET ENREGISTREMENT EXISTE, et il faut le garder : le repli
     * `Config.API_KEY` du backend ne s'active qu'en mode amorcage explicite.
     * Sans cette ligne, la premiere cle creee couperait le proxy PHP, qui
     * envoie toujours `getenv('API_KEY')`.
     */
    public function assureCleEnvironnement(int $auteur): bool
    {
        $brute = (string) (getenv('API_KEY') ?: '');
        if ($brute === '') {
            return false;
        }
        $hachage = hash('sha256', $brute);

        // RECONNAISSANCE PAR LE HACHAGE. Une ligne revoquee ne compte pas : si
        // l'exploitant a revoque cette cle, la reposer irait contre sa decision.
        $deja = DB::table('api_keys')->where('key_hash', $hachage)->exists();
        if ($deja) {
            return false;
        }

        DB::table('api_keys')->insert([
            'name' => 'proxy-internal-legacy-' . substr($hachage, 0, 8),
            'key_prefix' => 'legacy_' . substr(hash('sha256', 'proxy-internal-legacy'), 0, 6),
            'key_hash' => $hachage,
            'scope_json' => null,
            'created_by' => $auteur,
            'auto_generated' => 1,
        ]);

        return true;
    }

    /** Revoque une cle. Rend false si elle n'existe pas ou l'etait deja. */
    public function revoque(int $id): bool
    {
        return DB::table('api_keys')->where('id', $id)->whereNull('revoked_at')
            ->update(['revoked_at' => now()]) > 0;
    }

    /** Le nom d'une cle, pour l'annoncer. */
    public function nom(int $id): ?string
    {
        $n = DB::table('api_keys')->where('id', $id)->value('name');

        return $n === null ? null : (string) $n;
    }
}
