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

    /** Borne reprise du legacy (`manage_servers.php:518`, `LIMIT 5`). */
    public const NOTES_PAR_MACHINE = 5;

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
     * L'adresse d'une machine — le garde SSRF, sur la forme BINAIRE.
     *
     * ══ POURQUOI PAS `strpos` ═════════════════════════════════════════════
     *
     * Le legacy compare des PREFIXES DE CHAINE : `strpos($ip, '169.254.') === 0`.
     * Le premier jet de ce portage a recopie cette regle — et son angle mort
     * avec. Mesure du 2026-08-26, apres relecture croisee :
     *
     *   169.254.169.254           refusee
     *   ::ffff:169.254.169.254    ACCEPTEE   <- la MEME adresse
     *   ::ffff:a9fe:a9fe          ACCEPTEE   <- la meme encore, en hexadecimal
     *   ::ffff:127.0.0.1          ACCEPTEE
     *   ::ffff:224.0.0.1          ACCEPTEE
     *
     * La notation IPv4-mappee-IPv6 designe exactement la meme machine et ne
     * commence par aucun des prefixes testes. Le commentaire du correctif
     * A10-01 NOMME sa cible — « empecher un admin compromis d'inserer
     * 169.254.169.254 » — et la cible passait, sous un autre nom.
     *
     * C'est la lecon deja payee sur `//exemple.com` : **valider la FORME avant
     * le contenu, et ne jamais recopier une regle de securite**. Ici l'adresse
     * est d'abord reduite a sa forme BINAIRE par `inet_pton`, les formes
     * mappees et compatibles sont ramenees a leur IPv4, et la comparaison porte
     * sur des OCTETS. Une notation nouvelle ne peut plus contourner la regle,
     * parce que la regle ne regarde plus la notation.
     *
     * ══ CE QUI EST REFUSE ═════════════════════════════════════════════════
     *
     *   IPv4   0/8   127/8   169.254/16   224/4 (multicast)   240/4 (reserve)
     *   IPv6   ::    ::1     fe80::/10    ff00::/8
     *
     * 240/4 va au-dela de ce que le legacy annoncait : c'est de l'espace
     * reserve, jamais joignable en SSH, et `255.255.255.255` en fait partie.
     * Les adresses privees RFC1918 restent AUTORISEES — un reseau d'entreprise
     * est la cible normale de RootWarden.
     */
    public function valideIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $brut = @inet_pton($ip);
        if ($brut === false) {
            return false;
        }

        $brut = $this->reduitEnIpv4($brut);

        return strlen($brut) === 4 ? $this->ipv4Utilisable($brut) : $this->ipv6Utilisable($brut);
    }

    /**
     * Ramene `::ffff:a.b.c.d` et `::a.b.c.d` a leurs quatre octets IPv4.
     *
     * Les deux notations designent une machine IPv4 ; les laisser en seize
     * octets ferait passer les controles IPv4 a cote de leur objet.
     */
    private function reduitEnIpv4(string $brut): string
    {
        if (strlen($brut) !== 16) {
            return $brut;
        }
        if (str_starts_with($brut, str_repeat("\0", 10) . "\xff\xff")) {
            return substr($brut, 12);
        }
        // `::a.b.c.d` (IPv4-compatible, obsolete mais toujours resolue). `::`
        // et `::1` en sont exclus : ils ne designent pas une machine IPv4 et
        // sont traites par la regle IPv6.
        $queue = substr($brut, 12);
        if (str_starts_with($brut, str_repeat("\0", 12))
            && $queue !== "\0\0\0\0" && $queue !== "\0\0\0\1") {
            return $queue;
        }

        return $brut;
    }

    /** @param  string  $brut  quatre octets */
    private function ipv4Utilisable(string $brut): bool
    {
        /** @var array<int, int> $o */
        $o = array_values(unpack('C4', $brut));

        return ! (
            $o[0] === 0                          // 0.0.0.0/8
            || $o[0] === 127                     // bouclage 127/8
            || ($o[0] === 169 && $o[1] === 254)  // lien-local 169.254/16
            || $o[0] >= 224                      // multicast 224/4 et reserve 240/4
        );
    }

    /** @param  string  $brut  seize octets */
    private function ipv6Utilisable(string $brut): bool
    {
        /** @var array<int, int> $o */
        $o = array_values(unpack('C16', $brut));

        return ! (
            $brut === str_repeat("\0", 16)                // non specifiee ::
            || $brut === str_repeat("\0", 15) . "\1"       // bouclage ::1
            || ($o[0] === 0xFE && ($o[1] & 0xC0) === 0x80) // lien-local fe80::/10
            || $o[0] === 0xFF                             // multicast ff00::/8
        );
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

    /* ═══ Etiquettes et notes — sous-lot D6b ════════════════════════════════ */

    /**
     * Les etiquettes de TOUTES les machines, en une requete.
     *
     * Le legacy en emet une PAR machine, dans sa boucle d'affichage — plus une
     * pour les notes. Trente machines valent soixante-et-une requetes la ou deux
     * suffisent. Ce n'est pas un defaut de comportement, donc pas un ecart de
     * parite ; c'est une raison de ne pas recopier la forme.
     *
     * @return array<int, list<string>> machine_id => etiquettes
     */
    public function etiquettesParMachine(): array
    {
        $sortie = [];
        foreach (DB::table('machine_tags')->orderBy('tag')->get() as $l) {
            $sortie[(int) $l->machine_id][] = (string) $l->tag;
        }

        return $sortie;
    }

    /**
     * Les cinq dernieres notes de chaque machine, en une requete.
     *
     * Le legacy borne a cinq par machine (`LIMIT 5`) ; on garde cette borne, et
     * on l'ANNONCE a l'ecran plutot que de laisser croire qu'il n'y en a pas
     * d'autres.
     *
     * @return array<int, list<array<string, mixed>>> machine_id => notes
     */
    public function notesParMachine(): array
    {
        $sortie = [];
        $lignes = DB::table('server_notes')
            ->select('id', 'machine_id', 'author', 'content', 'created_at')
            ->orderByDesc('created_at')->orderByDesc('id')->get();

        foreach ($lignes as $l) {
            $mid = (int) $l->machine_id;
            $sortie[$mid] ??= [];
            if (count($sortie[$mid]) < self::NOTES_PAR_MACHINE) {
                $sortie[$mid][] = (array) $l;
            }
        }

        return $sortie;
    }

    /**
     * Normalise une etiquette, exactement comme le legacy le fait EN JAVASCRIPT
     * (`manage_servers.php:555`) et **en PHP** (`server_actions.php:113`).
     *
     * Les deux existent parce que la premiere ne protege rien : une requete
     * forgee ne passe pas par le navigateur. Ici il n'y en a qu'UNE, cote
     * serveur — et la regle est ANNONCEE sous le champ, plutot que d'amputer la
     * saisie en silence.
     */
    public function normaliseEtiquette(string $brut): string
    {
        return (string) preg_replace('/[^a-z0-9_-]/', '', mb_strtolower(trim($brut)));
    }

    /**
     * Pose une etiquette. `insertOrIgnore` reprend l'`INSERT IGNORE` du legacy :
     * reposer une etiquette deja presente n'est pas une erreur.
     *
     * @return string|null cle i18n de l'erreur, ou null si l'etiquette est posee
     */
    public function poseEtiquette(int $machine, string $brut): ?string
    {
        $tag = $this->normaliseEtiquette($brut);
        if ($tag === '') {
            return 'serveurs.err_etiquette_vide';
        }
        if (mb_strlen($tag) > 50) {
            return 'serveurs.err_etiquette_longue';
        }
        if (DB::table('machines')->where('id', $machine)->doesntExist()) {
            return 'serveurs.err_introuvable';
        }
        DB::table('machine_tags')->insertOrIgnore(['machine_id' => $machine, 'tag' => $tag]);

        return null;
    }

    /** Retire une etiquette d'une machine. */
    public function retireEtiquette(int $machine, string $brut): void
    {
        DB::table('machine_tags')
            ->where('machine_id', $machine)
            ->where('tag', $this->normaliseEtiquette($brut))
            ->delete();
    }

    /**
     * Pose une note. L'auteur vient de la SESSION, jamais du formulaire : une
     * note dont on choisit l'auteur ne vaut rien comme trace.
     *
     * @return string|null cle i18n de l'erreur, ou null si la note est posee
     */
    public function poseNote(int $machine, string $contenu, string $auteur): ?string
    {
        $contenu = trim($contenu);
        if ($contenu === '') {
            return 'serveurs.err_note_vide';
        }
        if (DB::table('machines')->where('id', $machine)->doesntExist()) {
            return 'serveurs.err_introuvable';
        }
        DB::table('server_notes')->insert([
            'machine_id' => $machine,
            'author' => mb_substr($auteur, 0, 100),
            'content' => $contenu,
        ]);

        return null;
    }

    /**
     * Supprime une note — **de CETTE machine**.
     *
     * `server_actions.php:180` fait `DELETE FROM server_notes WHERE id = ?`, sans
     * regarder a quelle machine la note appartient. L'identifiant suffit donc a
     * supprimer n'importe quelle note du parc. Ici la note est resolue par le
     * COUPLE : viser la note d'une autre machine ne supprime rien.
     *
     * @return bool false si aucune note ne correspond au couple
     */
    public function supprimeNote(int $machine, int $note): bool
    {
        return DB::table('server_notes')
            ->where('id', $note)->where('machine_id', $machine)->delete() > 0;
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
