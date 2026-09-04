<?php

namespace Tests\Feature;

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
 * ── POURQUOI CE FICHIER N'EST PAS ROUGE, ALORS QUE LA CAPACITE N'EXISTE PAS ─
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

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('remember_tokens', function (Blueprint $table) {
            $table->integer('user_id')->primary();
            $table->string('token_hash', 255);
            $table->dateTime('expires_at')->nullable();
        });
        Schema::create('users', function (Blueprint $table) {
            $table->integer('id')->primary();
            $table->string('name', 255)->nullable();
            $table->string('email', 255)->nullable();
            $table->string('password', 255)->nullable();
            $table->string('totp_secret', 255)->nullable();
            $table->integer('role_id')->default(1);
            $table->tinyInteger('active')->default(1);
        });

        DB::table('users')->insert([
            ['id' => self::AVEC_SECRET, 'name' => 'avec-secret',
             'totp_secret' => 'sodium:un-secret-chiffre', 'role_id' => 1, 'active' => 1],
            ['id' => self::SANS_SECRET, 'name' => 'sans-secret',
             'totp_secret' => null, 'role_id' => 1, 'active' => 1],
        ]);
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('remember_tokens');
        Schema::dropIfExists('users');
        parent::tearDown();
    }

    /** Un jeton VALIDE pour ce compte, et le cookie qui le porte. */
    private function jetonValide(int $idCompte, string $expiration = '+30 days'): string
    {
        $clair = bin2hex(random_bytes(32));
        DB::table('remember_tokens')->insert([
            'user_id' => $idCompte,
            'token_hash' => password_hash($clair, PASSWORD_BCRYPT),
            'expires_at' => date('Y-m-d H:i:s', strtotime($expiration)),
        ]);

        return $idCompte . ':' . $clair;
    }

    /**
     * Ou aboutit une requete portant ce cookie.
     *
     * Au RESEAU et non au DOM : la redirection vers l'enrolement et l'affichage
     * du portail se distinguent par l'URL FINALE, pas par une ancre. Une
     * assertion sur le contenu de la page ne verrait pas la difference entre
     * « on m'a redirige » et « on m'a servi ».
     */
    private function aboutitA(?string $cookie): string
    {
        $requete = $this->visiteur();
        if ($cookie !== null) {
            $requete = $requete->withCookie('remember_token', $cookie);
        }
        $reponse = $requete->get('/accueil');

        if ($reponse->isRedirect()) {
            return (string) parse_url((string) $reponse->headers->get('Location'), PHP_URL_PATH);
        }

        return '(servi directement, statut ' . $reponse->getStatusCode() . ')';
    }

    private function capaciteAbsente(string $arrivee): bool
    {
        return $arrivee === '/connexion';
    }

    // ══════════════════════════════════════════════════════════════════════
    // MOITIE 1 — le compte ENROLE doit tomber sur le DEFI
    // ══════════════════════════════════════════════════════════════════════

    public function test_un_compte_AVEC_secret_restaure_par_jeton_tombe_sur_le_defi(): void
    {
        $arrivee = $this->aboutitA($this->jetonValide(self::AVEC_SECRET));

        if ($this->capaciteAbsente($arrivee)) {
            $this->markTestSkipped(
                "SANS OBJET POUR L'INSTANT : la restauration par jeton n'existe "
                . "pas encore dans le portage (0 ecriture de `remember_tokens`), "
                . "donc le cookie n'est pas lu et la requete tombe sur "
                . '/connexion. CE SKIP NOMME SA FENETRE : il ne vaut pas « rien a '
                . "signaler ». Ce test mord l'instant ou la capacite arrive, y "
                . 'compris si elle arrive fausse.');
        }

        $this->assertSame('/second-facteur', $arrivee,
            "un compte AVEC secret TOTP restaure par jeton doit tomber sur le "
            . "DEFI. Il aboutit sur « $arrivee ».");
    }

    // ══════════════════════════════════════════════════════════════════════
    // MOITIE 2 — LE CHEMIN QUI CONTOURNE DANS LE LEGACY
    // ══════════════════════════════════════════════════════════════════════

    public function test_un_compte_SANS_secret_restaure_par_jeton_tombe_sur_l_ENROLEMENT(): void
    {
        /*
         * ⚠ C'EST LA MOITIE QUI PORTE LE DEFAUT, ET LA PLUS FACILE A OUBLIER.
         *
         * Dans le legacy, ce compte-la traverse : `verify.php:139` ne tire pas
         * faute de secret, aucun drapeau n'est pose, et l'execution continue
         * avec l'identite renseignee. Le portage doit l'envoyer a l'ENROLEMENT
         * — jamais au portail.
         */
        $arrivee = $this->aboutitA($this->jetonValide(self::SANS_SECRET));

        if ($this->capaciteAbsente($arrivee)) {
            $this->markTestSkipped(
                "SANS OBJET POUR L'INSTANT : la restauration n'existe pas encore. "
                . 'Ce test est le plus important du fichier — il exerce le seul '
                . 'chemin que le legacy laisse passer — et il mord des que la '
                . 'capacite arrive.');
        }

        $this->assertSame('/second-facteur/enrolement', $arrivee,
            "un compte SANS secret TOTP restaure par jeton doit tomber sur "
            . "l'ENROLEMENT, jamais sur le portail. Il aboutit sur « $arrivee ». "
            . "C'EST LE CONTOURNEMENT DU LEGACY (`verify.php:139`) : la condition "
            . 'sur le secret ne tirait pas, aucun drapeau n\'etait pose, et le '
            . 'cookie authentifiait seul.');
    }

    // ══════════════════════════════════════════════════════════════════════
    // LES TEMOINS — sans eux, « pas de restauration » et « restauration
    // refusee » rendent la meme sortie
    // ══════════════════════════════════════════════════════════════════════

    public function test_aucun_cookie_n_authentifie(): void
    {
        // Le point de comparaison. Il est vert aujourd'hui ET demain, et il ne
        // prouve rien SEUL — c'est sa valeur : il donne la sortie de reference
        // a laquelle les autres se comparent.
        $this->assertSame('/connexion', $this->aboutitA(null));
    }

    public function test_un_cookie_FORGE_n_authentifie_pas(): void
    {
        $arrivee = $this->aboutitA(self::AVEC_SECRET . ':' . bin2hex(random_bytes(32)));

        $this->assertNotSame('(servi directement, statut 200)', $arrivee,
            'un jeton invente a authentifie');
        $this->assertContains($arrivee, ['/connexion', '/second-facteur',
                                         '/second-facteur/enrolement'],
            "un cookie forge aboutit sur « $arrivee » : il n'a le droit de mener "
            . "qu'a un refus ou a un facteur d'authentification.");
    }

    public function test_un_user_id_SEUL_sans_jeton_n_authentifie_pas(): void
    {
        $arrivee = $this->aboutitA((string) self::AVEC_SECRET);

        $this->assertNotSame('(servi directement, statut 200)', $arrivee);
    }

    public function test_le_jeton_d_un_AUTRE_compte_n_authentifie_pas(): void
    {
        // Le jeton est valide — pour SANS_SECRET. Presente sous l'identite de
        // AVEC_SECRET, il doit echouer : le hache est verifie CONTRE LA LIGNE
        // du `user_id` annonce.
        $valide = $this->jetonValide(self::SANS_SECRET);
        $clair = explode(':', $valide, 2)[1];

        $arrivee = $this->aboutitA(self::AVEC_SECRET . ':' . $clair);

        $this->assertNotSame('(servi directement, statut 200)', $arrivee,
            "le jeton d'un autre compte a authentifie");
    }

    public function test_un_jeton_EXPIRE_n_authentifie_pas(): void
    {
        /*
         * L'echeance qui compte est celle de la BASE, pas celle du cookie : un
         * cookie non expire cote client peut porter un jeton expire cote
         * serveur, et c'est le serveur qui decide. Ce temoin manquait a la
         * liste initiale.
         */
        $arrivee = $this->aboutitA($this->jetonValide(self::AVEC_SECRET, '-1 day'));

        $this->assertNotSame('(servi directement, statut 200)', $arrivee,
            'un jeton expire a authentifie');
    }

    // ══════════════════════════════════════════════════════════════════════
    // LE RELEVE DE L'ETAT — pour que la bascule se voie
    // ══════════════════════════════════════════════════════════════════════

    public function test_l_etat_de_la_capacite_est_DIT(): void
    {
        /*
         * Ce test ne juge rien : il rend l'etat LISIBLE dans le journal de la
         * suite. Sans lui, quatre `skip` silencieux se lisent comme quatre
         * tests satisfaits — et la bascule « la capacite est arrivee » ne se
         * verrait nulle part.
         */
        $arrivee = $this->aboutitA($this->jetonValide(self::AVEC_SECRET));

        if ($this->capaciteAbsente($arrivee)) {
            // ══ POURQUOI UN `skip` ET NON UNE ASSERTION QUI PASSE ═══════════
            //
            // Premier jet : une assertion toujours vraie, dont le MESSAGE
            // portait l'etat. Elle passait — donc le message ne s'affichait
            // JAMAIS, et sa docstring affirmait « rend l'etat lisible dans le
            // journal » sans le faire. Un texte qui affirme plus que son code,
            // dans le test meme qui existe pour rendre un etat visible.
            //
            // Un `skip` AFFICHE sa raison. C'est le seul mecanisme de PHPUnit
            // qui porte du texte jusqu'au journal sans echouer.
            $this->markTestSkipped(
                'ETAT : restauration par jeton ABSENTE (le cookie est ignore, '
                . 'arrivee /connexion). CONSEQUENCE A LIRE AVEC LES VERTS DE CE '
                . 'FICHIER : les temoins « cookie forge », « user_id seul », '
                . '« jeton d autrui » et « jeton expire » sont VACUES pour '
                . "l'instant — ils passent parce qu'aucun cookie n'est lu, pas "
                . "parce qu'un refus a eu lieu. Ils deviennent porteurs le jour "
                . 'ou la capacite arrive.');
        }

        $this->addToAssertionCount(1);
    }
}
