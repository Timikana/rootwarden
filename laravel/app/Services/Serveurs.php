<?php

namespace App\Services;

use App\Support\SecretExploitation;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Le parc de machines, en ECRITURE — module `adm/`, sous-lot D6a.
 *
 * Porte l'onglet « Serveurs » d'`admin_page.php`, c'est-a-dire
 * `legacy/adm/includes/manage_servers.php` : la liste, l'ajout, la modification
 * et la suppression d'une machine. Les tags, les notes, le cycle de vie et le
 * test de connectivite passent par `server_actions.php` et sont le sous-lot D6b.
 *
 * `App\Services\Machines` reste ce qu'il est : une liste de REFERENCE, en
 * lecture seule, pour les selecteurs d'autres pages. Ecrire le parc est un autre
 * metier, avec d'autres gardes — les deux ne se melangent pas.
 *
 * ══ LES LISTES SONT FERMEES, ET ELLES VIENNENT DU LEGACY ═══════════════════
 *
 * `validateInput()` (`manage_servers.php:46`) borne quatre champs par des listes
 * en dur. Elles sont reprises ICI telles quelles, a un caractere pres — ce sont
 * les memes valeurs que le backend Python lit ensuite.
 *
 * ══ LE GARDE SSRF EST PORTE **ET COMPLETE** ════════════════════════════════
 *
 * Le legacy refuse une adresse de bouclage, de lien-local (169.254/16, donc les
 * points de metadonnees AWS et Azure), 0.0.0.0/8 et leurs equivalents IPv6.
 * L'intention est ecrite au-dessus du code, et elle annonce AUSSI le refus du
 * multicast (224/4).
 *
 * **Le code ne verifie pas le multicast.** Mesure du 2026-08-26 : le commentaire
 * de `manage_servers.php:59` le nomme, aucune des sept conditions de
 * `$isLoopbackOrReserved` ne le teste. C'est la forme la plus durable du defaut
 * — celle qu'une relecture d'en-tete CONFIRME. Voir PARITE E-122.
 *
 * Le portage applique donc les huit conditions : les sept du legacy, plus celle
 * que son propre commentaire promettait. Une adresse multicast n'a aucun sens
 * comme cible SSH ; la refuser ne retire aucune capacite reelle.
 *
 * ══ CE QUI N'EST PAS PORTE, ET POURQUOI ════════════════════════════════════
 *
 * `manage_servers.php:218-285` construit une recherche, trois filtres, un tri
 * valide par liste blanche et une pagination — 68 lignes. Elles sont MORTES,
 * deux fois plutot qu'une (mesure du 2026-08-26, PARITE E-121) :
 *
 *   1. aucun controle de la page n'emet `?search=`, `?environment=`, `?network=`,
 *      `?criticality=`, `?sort=` ni `?page=` ;
 *   2. et le jeu de resultats qu'elles produisent est ECRASE trois lignes plus
 *      bas par un `query()` sans clause `WHERE` ni `LIMIT`.
 *
 * Ce qui filtre reellement est un `oninput` cote navigateur, sur les cartes
 * deja rendues. Le portage garde CE comportement — rendre le parc entier puis
 * filtrer a l'affichage — et ne porte pas les 68 lignes. Porter du code mort,
 * ce n'est plus migrer, c'est concevoir.
 */
class Serveurs
{
    /** Reprises de `validateInput()`, sans un caractere de plus. */
    public const ENVIRONNEMENTS = ['PROD', 'DEV', 'TEST', 'OTHER'];

    public const CRITICITES = ['CRITIQUE', 'NON CRITIQUE'];

    public const RESEAUX = ['INTERNE', 'EXTERNE'];

    /**
     * Les colonnes rendues. `password` et `root_password` n'y sont PAS, et c'est
     * le choix du legacy lui-meme, commente sur ses deux requetes : un secret
     * chiffre n'a aucune raison de transiter jusqu'a une vue.
     */
    private const COLONNES = [
        'id', 'name', 'ip', 'port', 'user', 'environment', 'criticality',
        'network_type', 'online_status', 'lifecycle_status', 'retire_date',
        'platform_key_deployed', 'ssh_password_required', 'cleanup_users',
        'last_checked',
    ];

    /**
     * Le parc entier, dans l'ordre des noms.
     *
     * @return list<array<string, mixed>>
     */
    public function liste(): array
    {
        return DB::table('machines')->select(self::COLONNES)->orderBy('name')
            ->get()->map(static fn ($m) => (array) $m)->all();
    }

    /* ═══ Validation ════════════════════════════════════════════════════════ */

    /**
     * Le nom d'une machine.
     *
     * Elargi en v1.37.14 pour accepter « EAU ACTU (backup) » ou « srv+web ». Les
     * metacaracteres de shell et de balisage restent refuses : le nom circule
     * dans des configurations distantes et des messages. Il est certes toujours
     * quote ou echappe en aval, mais c'est une defense en profondeur, et elle se
     * porte avec le reste.
     */
    public function valideNom(string $nom): bool
    {
        return preg_match('/^[a-zA-Z0-9][a-zA-Z0-9 ._+()-]{0,254}$/', $nom) === 1;
    }

    /**
     * L'adresse d'une machine — le garde SSRF, complete.
     *
     * Les adresses privees RFC1918 restent AUTORISEES : un reseau d'entreprise
     * est la cible normale de RootWarden. Ce qui est refuse, c'est ce qui ne
     * designe pas une machine joignable en SSH et sert a faire parler le serveur
     * a lui-meme ou a un point de metadonnees.
     */
    public function valideIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $reserve = str_starts_with($ip, '127.')          // bouclage 127/8
            || str_starts_with($ip, '169.254.')          // lien-local 169.254/16
            || str_starts_with($ip, '0.')                // 0.0.0.0/8
            || $ip === '::1'                             // bouclage IPv6
            || stripos($ip, 'fe80:') === 0               // lien-local IPv6
            || $ip === '::' || $ip === '0:0:0:0:0:0:0:0' // non specifiee
            || $this->estMulticast($ip);                 // 224/4 — ABSENT du legacy

        return ! $reserve;
    }

    /**
     * Multicast IPv4 (224.0.0.0/4) et IPv6 (ff00::/8).
     *
     * La condition que le commentaire du legacy annonce et que son code n'a
     * jamais portee. Comparaison sur le premier octet, pas sur le texte : « 224. »
     * ne dirait rien de 225 a 239.
     */
    private function estMulticast(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $premier = (int) explode('.', $ip)[0];

            return $premier >= 224 && $premier <= 239;
        }

        $brut = @inet_pton($ip);

        return $brut !== false && strlen($brut) === 16 && ord($brut[0]) === 0xFF;
    }

    /**
     * Valide un jeu de champs et rend les cles i18n des champs REFUSES.
     *
     * Rendre la liste des champs fautifs, et non un booleen, est repris du
     * legacy : « Champs invalides : adresse IP, port » se corrige, « echec » non.
     *
     * @param  array<string, mixed>  $brut
     * @return list<string> cles i18n des champs refuses, vide si tout passe
     */
    public function champsRefuses(array $brut): array
    {
        $refuses = [];
        $texte = static fn ($v) => is_scalar($v) ? trim((string) $v) : '';

        if (! $this->valideNom($texte($brut['name'] ?? ''))) {
            $refuses[] = 'serveurs.champ_nom';
        }
        if (! $this->valideIp($texte($brut['ip'] ?? ''))) {
            $refuses[] = 'serveurs.champ_ip';
        }
        if ($texte($brut['user'] ?? '') === '' || mb_strlen($texte($brut['user'] ?? '')) > 255) {
            $refuses[] = 'serveurs.champ_utilisateur';
        }
        $port = filter_var($texte($brut['port'] ?? ''), FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1, 'max_range' => 65535]]);
        if ($port === false) {
            $refuses[] = 'serveurs.champ_port';
        }
        if (! in_array($texte($brut['environment'] ?? ''), self::ENVIRONNEMENTS, true)) {
            $refuses[] = 'serveurs.champ_environnement';
        }
        if (! in_array($texte($brut['criticality'] ?? ''), self::CRITICITES, true)) {
            $refuses[] = 'serveurs.champ_criticite';
        }
        if (! in_array($texte($brut['network_type'] ?? ''), self::RESEAUX, true)) {
            $refuses[] = 'serveurs.champ_reseau';
        }

        return $refuses;
    }

    /* ═══ Ecriture ══════════════════════════════════════════════════════════ */

    /**
     * Ajoute une machine.
     *
     * LE MOT DE PASSE N'EST PAS SOUMIS A LA POLITIQUE DES COMPTES, et c'est le
     * choix du legacy : `encryptPassword($_POST['password'], false)` — le second
     * argument desactive la politique. Un mot de passe de machine est impose par
     * la machine, pas choisi ici ; le refuser rendrait le parc inadministrable.
     *
     * `SecretExploitation::chiffre()` rend `null` sur un secret vide ou sans cle
     * utilisable. A la CREATION, `null` est un refus : les deux colonnes sont
     * `NOT NULL` et sans defaut, et une machine sans identifiants ne se joint
     * pas. C'est a la MODIFICATION que `null` veut dire « ne pas changer ».
     *
     * @param  array<string, mixed>  $brut
     * @return string|null cle i18n de l'erreur, ou null si la machine est creee
     */
    public function ajoute(array $brut): ?string
    {
        $mdp = SecretExploitation::chiffre(trim((string) ($brut['password'] ?? '')));
        $mdpRoot = SecretExploitation::chiffre(trim((string) ($brut['root_password'] ?? '')));
        if ($mdp === null || $mdpRoot === null) {
            return 'serveurs.err_secret';
        }

        try {
            DB::table('machines')->insert([
                'name' => trim((string) $brut['name']),
                'ip' => trim((string) $brut['ip']),
                'user' => trim((string) $brut['user']),
                'password' => $mdp,
                'root_password' => $mdpRoot,
                'port' => (int) $brut['port'],
                'environment' => $brut['environment'],
                'criticality' => $brut['criticality'],
                'network_type' => $brut['network_type'],
            ]);
        } catch (\Illuminate\Database\QueryException $e) {
            if ((string) $e->getCode() === '23000') {
                return 'serveurs.err_doublon';
            }
            Log::error('serveurs: ajout refuse par la base', ['erreur' => $e->getMessage()]);

            return 'serveurs.err_ajout';
        }

        return null;
    }

    /**
     * Modifie une machine.
     *
     * UN CHAMP DE MOT DE PASSE VIDE NE VIDE RIEN. Le legacy relit la valeur
     * stockee et la reecrit telle quelle ; ici on ne touche simplement pas la
     * colonne — meme effet, une lecture de secret en moins.
     *
     * @param  array<string, mixed>  $brut
     * @return string|null cle i18n de l'erreur, ou null si la machine est modifiee
     */
    public function modifie(int $id, array $brut, bool $nettoieComptes): ?string
    {
        if (DB::table('machines')->where('id', $id)->doesntExist()) {
            return 'serveurs.err_introuvable';
        }

        $valeurs = [
            'name' => trim((string) $brut['name']),
            'ip' => trim((string) $brut['ip']),
            'user' => trim((string) $brut['user']),
            'port' => (int) $brut['port'],
            'environment' => $brut['environment'],
            'criticality' => $brut['criticality'],
            'network_type' => $brut['network_type'],
            'cleanup_users' => $nettoieComptes ? 1 : 0,
        ];

        $mdp = SecretExploitation::chiffre(trim((string) ($brut['password'] ?? '')));
        if ($mdp !== null) {
            $valeurs['password'] = $mdp;
        }
        $mdpRoot = SecretExploitation::chiffre(trim((string) ($brut['root_password'] ?? '')));
        if ($mdpRoot !== null) {
            $valeurs['root_password'] = $mdpRoot;
        }

        try {
            DB::table('machines')->where('id', $id)->update($valeurs);
        } catch (\Illuminate\Database\QueryException $e) {
            if ((string) $e->getCode() === '23000') {
                return 'serveurs.err_doublon';
            }
            Log::error('serveurs: modification refusee par la base', ['erreur' => $e->getMessage()]);

            return 'serveurs.err_modification';
        }

        return null;
    }

    /** Le nom d'une machine, pour l'annoncer avant de la detruire. */
    public function nom(int $id): ?string
    {
        $n = DB::table('machines')->where('id', $id)->value('name');

        return $n === null ? null : (string) $n;
    }

    /**
     * Supprime une machine.
     *
     * @return string|null cle i18n de l'erreur, ou null si la machine est supprimee
     */
    public function supprime(int $id): ?string
    {
        if (DB::table('machines')->where('id', $id)->doesntExist()) {
            return 'serveurs.err_introuvable';
        }

        try {
            DB::table('machines')->where('id', $id)->delete();
        } catch (\Illuminate\Database\QueryException $e) {
            Log::error('serveurs: suppression refusee par la base', ['erreur' => $e->getMessage()]);

            return 'serveurs.err_suppression';
        }

        return null;
    }
}
