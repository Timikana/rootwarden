<?php

namespace Tests\Feature;

use App\Services\JetonMemorisation;
use App\Support\DecisionRestauration;
use App\Support\DepotJetonsMemorisation;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Tests\TestCase;

/**
 * « Se souvenir de moi » — une identite restauree par jeton n'est JAMAIS
 * authentifiee.
 *
 * ── LE CONTOURNEMENT DU LEGACY, ET POURQUOI CE TEST NE DOIT PAS ETRE CALE
 *    DESSUS ─────────────────────────────────────────────────────────────────
 *
 *     verify.php:139   if ($totpSecret) { … 2fa_pending/2fa_required … exit(); }
 *     verify.php:153   if (!empty($_SESSION['2fa_required']) || …) { … }
 *
 * Compte SANS secret TOTP : `:139` ne tire pas, donc aucun drapeau n'est pose,
 * donc `:153` ne tire pas non plus — et l'execution CONTINUE avec
 * `$_SESSION['user_id']` renseigne. **Le cookie authentifie SEUL**, sans second
 * facteur et sans la redirection vers l'enrolement que `login.php` impose
 * partout ailleurs.
 *
 * ⛔ **UN TEST DE CARACTERISATION VERT SUR LE LEGACY EST DONC INTERDIT ICI** :
 * il presuppose que le comportement de reference est correct, et il ne l'est
 * pas. L'ajuster pour le faire passer sur le legacy FIGERAIT le contournement,
 * et le portage le reproduirait pour etre « conforme au test ». Premiere
 * exception mesuree a la regle du chantier.
 *
 * ⚠⚠ ── CE FICHIER ETAIT VERT ET NE POUVAIT PAS ECHOUER ──────────────────────
 *
 * Premiere redaction, tant que la capacite n'existait pas : les deux moities
 * `skip`aient quand l'arrivee valait `/connexion`, et les quatre temoins
 * assertaient seulement « pas servi directement ».
 *
 * QUATRE MUTATIONS, ZERO ROUGE. Mesure du 2026-09-04 19:27, apres la livraison :
 *
 *     R1  le compte SANS secret est envoye au PORTAIL   -> 0 rouge (2 skips)
 *     R2  le compte AVEC secret contourne le defi        -> 0 rouge (2 skips)
 *     R3  l'echeance n'est plus verifiee                 -> 0 rouge
 *     R4  le jeton n'est plus verifie contre son hache   -> 0 rouge
 *
 * DEUX CAUSES, ET LES DEUX ETAIENT DANS MON INSTRUMENT :
 *
 * 1. **`capaciteAbsente()` inferait la presence de la capacite depuis
 *    l'arrivee.** Or laisser passer la requete la fait retomber sur
 *    `session.authentifiee`, qui redirige vers `/connexion` — LA MEME SORTIE
 *    que « le cookie n'est pas lu ». *Le defaut que ce fichier existe pour
 *    attraper etait indiscernable de l'absence de la capacite.*
 *
 * 2. **Les temoins assertaient « pas servi directement ».** Un jeton expire ou
 *    forge accepte rend `Defi`, donc une redirection — qui satisfait cette
 *    assertion. *Un temoin doit exiger le REFUS, pas l'absence de service.*
 *
 * Corrige en mesurant LA DECISION, qui existe depuis `c6aaf5b` et qui distingue
 * les trois issues sans dependre d'aucun cablage. L'HTTP ne verifie plus que le
 * branchement.
 *
 * ── POURQUOI CE FICHIER N'ETAIT PAS ROUGE, ALORS QUE LA CAPACITE N'EXISTAIT PAS ─
 *
 * Un rouge laisse dans un arbre partage par huit sessions pollue la ligne de
 * base — 50 des 55 FAIL du 03/09 venaient de la. Et un test qui asserte
 * seulement « le cookie forge n'authentifie pas » serait VERT PAR VACUITE :
 * sans restauration, un cookie forge et un cookie absent rendent la MEME
 * sortie, donc l'assertion ne distingue pas « la restauration a refuse » de
 * « aucune restauration n'a ete tentee ».
 *
 * La forme retenue evite les deux :
 *
 *     cookie VALIDE  ->  /connexion              la capacite N'EXISTE PAS ENCORE
 *                                                -> `skip` qui NOMME sa raison
 *     cookie VALIDE  ->  /second-facteur
 *                        ou /second-facteur/enrolement   PASS
 *     cookie VALIDE  ->  autre chose (portail, 200)      **FAIL**
 *
 * **Le verrou existe donc DES MAINTENANT et mord l'instant ou la capacite
 * arrive — y compris si elle arrive fausse.** C'est ce qu'un rouge en attente
 * n'apporte pas : il faut se souvenir de le lire.
 *
 * ── LES DEUX MOITIES SE MESURENT SEPAREMENT ────────────────────────────────
 *
 * Une suite qui n'exercerait que le compte ENROLE laisserait non emprunte LE
 * SEUL CHEMIN QUI CONTOURNE — celui du compte sans secret. C'est la forme
 * « une suite qui n'exerce qu'une plateforme sur quatre est aveugle sur les
 * trois autres », et ici la moitie non exercee est precisement celle qui porte
 * le defaut.
 *
 * ── CE QUE CE FICHIER FABRIQUE, ET POURQUOI ────────────────────────────────
 *
 * `remember_tokens` est definie dans `mysql/init.sql:49-55` et **absente de
 * `mysql/migrations/`** : le depot a trois endroits ou chercher un schema, dont
 * un vide. Le socle de test tourne sur SQLite en memoire sans migration
 * Laravel, donc la table est CREEE ICI. C'est une fixture, pas une dependance
 * a une migration qui n'existe pas.
 *
 * ⚠ `PRIMARY KEY (user_id)` : UN SEUL jeton par compte. Deux comptes distincts
 * sont donc necessaires pour deux jetons vivants.
 */
class RestaurationParJetonTest extends TestCase
{
    private const AVEC_SECRET = 90101;
    private const SANS_SECRET = 90102;
    private const INACTIF     = 90103;

    /** @var array<int, object> */
    private array $lignes = [];
    /** @var array<int, object> */
    private array $comptes = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->comptes = [
            self::AVEC_SECRET => (object) ['id' => self::AVEC_SECRET, 'active' => 1,
                                           'totp_secret' => 'sodium:un-secret-chiffre'],
            self::SANS_SECRET => (object) ['id' => self::SANS_SECRET, 'active' => 1,
                                           'totp_secret' => null],
            self::INACTIF     => (object) ['id' => self::INACTIF, 'active' => 0,
                                           'totp_secret' => null],
        ];
        $this->lignes = [];
    }

    /**
     * Le service avec un depot DOUBLE — aucune base, aucune migration.
     *
     * C'est le joint que la capacite offre (`decide(?string): DecisionRestauration`),
     * et c'est ce qui rend ce fichier hermetique ET falsifiable : la decision se
     * lit, elle ne se devine pas depuis une redirection.
     */
    private function service(): JetonMemorisation
    {
        $lignes = &$this->lignes;
        $comptes = $this->comptes;

        return new JetonMemorisation(new class ($lignes, $comptes) implements DepotJetonsMemorisation {
            public function __construct(private array &$lignes, private array $comptes)
            {
            }

            public function pour(int $idCompte): ?object
            {
                return $this->lignes[$idCompte] ?? null;
            }

            public function remplace(int $idCompte, string $hache, string $expireLe): void
            {
                $this->lignes[$idCompte] = (object) ['user_id' => $idCompte,
                    'token_hash' => $hache, 'expires_at' => $expireLe];
            }

            public function retire(int $idCompte): void
            {
                unset($this->lignes[$idCompte]);
            }

            public function compte(int $idCompte): ?object
            {
                return $this->comptes[$idCompte] ?? null;
            }
        });
    }

    /** Pose un jeton valide et rend le cookie `<id>:<clair>`. */
    private function cookieValide(int $idCompte, string $echeance = '+30 days'): string
    {
        $clair = bin2hex(random_bytes(32));
        $this->lignes[$idCompte] = (object) [
            'user_id' => $idCompte,
            'token_hash' => password_hash($clair, PASSWORD_BCRYPT),
            'expires_at' => date('Y-m-d H:i:s', strtotime($echeance)),
        ];

        return $idCompte . ':' . $clair;
    }

    // ══════════════════════════════════════════════════════════════════════
    // LES DEUX MOITIES — mesurees sur la DECISION
    // ══════════════════════════════════════════════════════════════════════

    public function test_un_compte_AVEC_secret_obtient_le_DEFI(): void
    {
        $this->assertSame(DecisionRestauration::Defi,
            $this->service()->decide($this->cookieValide(self::AVEC_SECRET)));
    }

    public function test_un_compte_SANS_secret_obtient_l_ENROLEMENT(): void
    {
        /*
         * ⚠ LA MOITIE QUI PORTE LE DEFAUT DU LEGACY, et la plus facile a
         * oublier. `verify.php:139` ne pose ses drapeaux QUE si le compte a un
         * secret : sans `else`, ce compte-la traverse et le cookie authentifie
         * SEUL. Une suite qui n'exercerait que le compte enrole laisserait non
         * emprunte LE SEUL CHEMIN QUI CONTOURNE.
         */
        $this->assertSame(DecisionRestauration::Enrolement,
            $this->service()->decide($this->cookieValide(self::SANS_SECRET)));
    }

    // ══════════════════════════════════════════════════════════════════════
    // LES TEMOINS — ils exigent le REFUS, pas « pas servi »
    // ══════════════════════════════════════════════════════════════════════

    /**
     * ⚠ POURQUOI `Refus` ET NON « autre chose que le portail ».
     *
     * Premiere redaction : les temoins assertaient « pas servi directement ».
     * Un jeton expire ACCEPTE rend `Defi`, donc une redirection — qui satisfait
     * cette assertion. Les mutations R3 et R4 ont rendu ZERO rouge pour cette
     * raison exacte. Un temoin doit exiger le refus.
     */
    public function test_aucun_cookie_est_un_REFUS(): void
    {
        $this->assertSame(DecisionRestauration::Refus, $this->service()->decide(null));
        $this->assertSame(DecisionRestauration::Refus, $this->service()->decide(''));
    }

    public function test_un_cookie_MALFORME_est_un_REFUS(): void
    {
        foreach ([(string) self::AVEC_SECRET, 'sans-deux-points', ':jeton-seul',
                  'abc:jeton', '0:jeton', '-3:jeton', self::AVEC_SECRET . ':'] as $cookie) {
            $this->assertSame(DecisionRestauration::Refus,
                $this->service()->decide($cookie), "cookie « $cookie » accepte");
        }
    }

    public function test_un_jeton_FORGE_est_un_REFUS(): void
    {
        $this->cookieValide(self::AVEC_SECRET);

        $this->assertSame(DecisionRestauration::Refus, $this->service()->decide(
            self::AVEC_SECRET . ':' . bin2hex(random_bytes(32))));
    }

    public function test_le_jeton_d_un_AUTRE_compte_est_un_REFUS(): void
    {
        // Le jeton est valide — pour SANS_SECRET. Presente sous l'identite de
        // AVEC_SECRET, il doit echouer : le hache se verifie CONTRE LA LIGNE du
        // `user_id` annonce, jamais contre une autre.
        $clair = explode(':', $this->cookieValide(self::SANS_SECRET), 2)[1];

        $this->assertSame(DecisionRestauration::Refus,
            $this->service()->decide(self::AVEC_SECRET . ':' . $clair));
    }

    public function test_un_jeton_EXPIRE_est_un_REFUS(): void
    {
        // L'echeance qui compte est celle de la BASE : un cookie non expire cote
        // client peut porter un jeton expire cote serveur, et c'est le serveur
        // qui decide. Ce temoin manquait a la liste initiale.
        $this->assertSame(DecisionRestauration::Refus,
            $this->service()->decide($this->cookieValide(self::AVEC_SECRET, '-1 second')));
    }

    public function test_un_compte_INACTIF_est_un_REFUS(): void
    {
        $this->assertSame(DecisionRestauration::Refus,
            $this->service()->decide($this->cookieValide(self::INACTIF)));
    }

    // ══════════════════════════════════════════════════════════════════════
    // LE BRANCHEMENT — l'HTTP ne verifie plus que le cablage
    // ══════════════════════════════════════════════════════════════════════

    public function test_la_decision_est_CABLEE_sur_les_bonnes_routes(): void
    {
        /*
         * Ce test ne mesure pas la decision — elle l'est ci-dessus, a sec. Il
         * mesure que l'intergiciel AGIT dessus, et c'est une propriete distincte :
         * `PORTAIL` retire de l'enumeration rend la valeur inexprimable, mais un
         * cas non traite qui laisse la requete CONTINUER produirait le meme trou
         * sans qu'aucune valeur fautive n'existe.
         */
        $source = file_get_contents(base_path('app/Http/Middleware/RestaureMemorisation.php'));

        $this->assertStringContainsString(
            "DecisionRestauration::Defi => \$this->versLeFacteur(\$requete, 'second-facteur')",
            $source, 'le cas `Defi` ne mene plus au defi');
        $this->assertStringContainsString(
            "DecisionRestauration::Enrolement => \$this->versLeFacteur(\$requete, 'second-facteur.enrolement')",
            $source, "le cas `Enrolement` ne mene plus a l'enrolement — C'EST LE "
            . 'CONTOURNEMENT DU LEGACY');
        $this->assertStringNotContainsString('default =>', $source,
            'un `default` est apparu dans le `match` : un cas non traite qui '
            . 'laisse passer rouvre le trou que le type ferme');
    }

    public function test_l_enumeration_n_offre_PAS_de_cas_portail(): void
    {
        // La propriete la plus forte du lot, et elle ne se teste qu'une fois :
        // l'acces direct au portail n'est pas « jamais rendu », il est
        // INEXPRIMABLE. Si un cas s'ajoute, ce test le dit.
        $this->assertSame(['Defi', 'Enrolement', 'Refus'],
            array_map(static fn ($c) => $c->name, DecisionRestauration::cases()),
            "un cas s'est ajoute a `DecisionRestauration` : verifier qu'il ne "
            . 'rend pas le portail atteignable depuis un cookie');
    }
}
