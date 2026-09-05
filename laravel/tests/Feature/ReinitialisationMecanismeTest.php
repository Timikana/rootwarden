<?php

namespace Tests\Feature;

use App\Http\Controllers\Auth\ReinitialisationController;
use Tests\TestCase;

/**
 * Reinitialisation de mot de passe — le MECANISME qui egalise le temps, et la
 * garde qui dit quand il cesse de valoir.
 *
 * ══ CE QUE CE FICHIER NE MESURE PAS, ET C'EST L'ESSENTIEL A LIRE ═════════
 *
 * **Il ne mesure AUCUN temps.** L'ecart entre « adresse connue » et « adresse
 * inconnue » ne se tranche qu'au RESEAU, en chronometrant jusqu'a la FERMETURE
 * DE CONNEXION et non jusqu'au premier octet. Cette mesure n'est pas faite, et
 * trois raisons la retiennent : elle consomme la limite de debit — qui compte
 * les demandes RECUES, ce qui est sa qualite —, la branche connue exige un jeton
 * reel sur un compte reel, et c'est le banc.
 *
 * Ce fichier verrouille donc **que le mecanisme reste en place**, pas qu'il
 * suffise. *C'est ce qui se perime sans bruit.*
 *
 * ══ POURQUOI LE MECANISME NE SUFFIT PAS ICI — MESURE ═════════════════════
 *
 *     /etc/apache2/mods-enabled/php.load  ->  LoadModule php_module libphp.so
 *     binaire php-fpm                     ->  aucun
 *
 * Sous mod_php, `Response::send()` ne peut appeler ni `fastcgi_finish_request`
 * ni `litespeed_finish_request` : il ne fait que vider les tampons
 * (`symfony/http-foundation/Response.php:405-421`). **La connexion reste ouverte
 * jusqu'a la fin du script, donc APRES les rappels `terminating()`.**
 *
 * > `terminating()` deplace le travail apres l'ECRITURE de la reponse, pas
 * > apres sa FIN. Sous php-fpm ce sont la meme chose ; sous mod_php, non.
 *
 * ⚠ ET UN MAILLON DE MA PROPRE DEMONSTRATION NE PROUVAIT RIEN. J'avais cite
 * `function_exists('fastcgi_finish_request') -> NON`, mesure EN CLI : cette
 * fonction appartient au SAPI FPM et rend faux en ligne de commande **meme sur
 * une machine ou php-fpm sert le web**. Les deux autres maillons prouvent la
 * conclusion ; celui-la est retire. *Un maillon faux dans une chaine juste se
 * recopie ensuite dans un dossier ou il ne prouve plus rien.*
 *
 * ══ D'OU LA GARDE, ET POURQUOI ELLE DOIT ETRE UN EVENEMENT ═══════════════
 *
 * `mail.default` valait `log` : le defaut etait LATENT. Il devient vivant le jour
 * ou un transport reseau est configure — et ce jour-la, personne ne relira ce
 * fichier. **Un commentaire, meme juste, ne produit aucun evenement le jour ou
 * sa premisse cesse d'etre vraie.**
 *
 * ══ CE JOUR EST ARRIVE — 2026-09-05, commit `fff1f8d` ════════════════════
 *
 *     config('mail.default')       smtp
 *     MAIL_SMTP_HOST               ssl0.ovh.net:465     fournisseur EXTERNE
 *
 * **Le defaut n'est plus latent : il est VIVANT.** La garde tire, et la mesure
 * au reseau — differee plus bas — est desormais la seule chose qui manque.
 * *Ce fichier n'a pas ete silencie : son marqueur de regime a ete RETOURNE.*
 *
 * ══ ET LA VALEUR NE VIENT PAS D'OU ON IRA LA CHERCHER ════════════════════
 *
 *     laravel/.env  (= /var/www/html/.env)   MAIL_MAILER=log
 *     environnement du process               MAIL_MAILER=smtp   <- CELUI-CI
 *
 * `LoadEnvironmentVariables` appelle `safeLoad()`, qui **n'ecrase pas** une
 * variable deja presente dans l'environnement. `srv-docker.env` est injecte par
 * `env_file:` au DEMARRAGE du conteneur ; le fichier `.env` perd.
 *
 * > ⚠ **Desarmer le SMTP en editant `.env` ne desarme RIEN** : `.env` porte
 * > deja `log`, et il est deja perdant. C'est un faux remede qui se lit comme
 * > une precaution — la meme forme que `Mail::queue` sous `queue.default=sync`.
 * > Le seul levier est `srv-docker.env` **plus une recreation du conteneur**.
 */
class ReinitialisationMecanismeTest extends TestCase
{
    private function source(): string
    {
        $chemin = base_path('app/Http/Controllers/Auth/ReinitialisationController.php');
        $this->assertFileExists($chemin);

        return (string) file_get_contents($chemin);
    }

    /**
     * La source sans ses commentaires, par le lexeur de PHP lui-meme.
     *
     * Ce fichier PORTE la demonstration en commentaire : y chercher `Mail::` ou
     * `terminating(` sans depouiller trouverait les mentions du texte et non les
     * appels. Une expression reguliere sur du PHP a deja fait rendre l'INVERSE
     * de la verite ici — les apostrophes francaises ouvraient de fausses chaines.
     */
    private function sourceDepouillee(): string
    {
        $sortie = '';
        foreach (token_get_all($this->source()) as $jeton) {
            if (is_array($jeton) && in_array($jeton[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            $sortie .= is_array($jeton) ? $jeton[1] : $jeton;
        }

        // TEMOIN : le depouillement n'a pas emporte le code.
        $this->assertStringContainsString('TRANSPORTS_LOCAUX', $sortie,
            'le retrait des commentaires a emporte le code : mesure invalide');

        return $sortie;
    }

    // ══════════════════════════════════════════════════════════════════════
    // LE MECANISME : un seul envoi, et il est APRES la reponse
    // ══════════════════════════════════════════════════════════════════════

    public function test_l_envoi_est_UNIQUE_et_situe_APRES_terminating(): void
    {
        $code = $this->sourceDepouillee();

        $this->assertSame(1, substr_count($code, 'Mail::'),
            'il y a plus (ou moins) d\'un envoi : le mecanisme ne peut plus etre '
            . 'raisonne sur un seul point');

        $posteTerminating = strpos($code, 'terminating(');
        $posteEnvoi = strpos($code, 'Mail::');

        $this->assertNotFalse($posteTerminating, '`terminating(` a disparu');
        $this->assertLessThan($posteEnvoi, $posteTerminating,
            "l'envoi n'est plus DANS le rappel `terminating()` : il se produit "
            . 'pendant la requete, et le temps de la branche connue redevient '
            . 'observable meme sous php-fpm');
    }

    public function test_aucune_mise_en_FILE_n_est_employee(): void
    {
        /*
         * `queue.default = sync` : `Mail::queue` s'EXECUTERAIT EN LIGNE. Une
         * mise en file aurait donc l'APPARENCE d'un correctif sans en avoir
         * l'effet — c'est la forme la plus couteuse d'un faux remede, parce
         * qu'elle se lit comme une precaution.
         */
        $code = $this->sourceDepouillee();

        $this->assertStringNotContainsString('Mail::queue', $code);
        $this->assertStringNotContainsString('->queue(', $code);
    }

    // ══════════════════════════════════════════════════════════════════════
    // LA GARDE DE TRANSPORT — celle qui se perimera le plus silencieusement
    // ══════════════════════════════════════════════════════════════════════

    public function test_la_liste_des_transports_locaux_est_FERMEE_et_minimale(): void
    {
        // Une liste fermee, et le sens du repli : un transport INCONNU doit etre
        // traite comme distant. Se tromper du cote qui journalise coute un
        // message ; se tromper de l'autre rouvre un oracle EN SILENCE.
        $locaux = ReinitialisationController::TRANSPORTS_LOCAUX;

        foreach (['log', 'array', 'null'] as $attendu) {
            $this->assertContains($attendu, $locaux, "« $attendu » n'est plus local");
        }
        foreach (['smtp', 'ses', 'mailgun', 'postmark', 'resend', 'sendmail'] as $distant) {
            $this->assertNotContains($distant, $locaux,
                "« $distant » est declare LOCAL : l'envoi est un aller-retour "
                . "reseau, et la garde ne se declenchera pas le jour ou il sert");
        }
    }

    public function test_un_transport_INCONNU_est_traite_comme_distant(): void
    {
        // La propriete du REPLI, mesuree sur des valeurs qui n'existent pas :
        // c'est le cas d'un transport ajoute par une version future de Laravel,
        // ou d'une faute de frappe dans une variable d'environnement.
        foreach (['smtp2go', 'brevo', 'sm tp', 'SMTP', 'Log', ''] as $inconnu) {
            $this->assertNotContains($inconnu, ReinitialisationController::TRANSPORTS_LOCAUX,
                "« $inconnu » serait traite comme local");
        }
    }

    public function test_la_garde_PRECEDE_le_rappel_et_journalise(): void
    {
        $code = $this->sourceDepouillee();

        $posteGarde = strpos($code, 'TRANSPORTS_LOCAUX, true)');
        $posteTerminating = strpos($code, 'terminating(');

        $this->assertNotFalse($posteGarde,
            'la garde de transport a disparu : le defaut redevient LATENT, et '
            . 'rien ne le dira le jour ou un SMTP sera pose');
        $this->assertLessThan($posteTerminating, $posteGarde,
            'la garde ne precede plus le rappel');
        $this->assertStringContainsString('Log::warning', $code,
            'la garde ne produit plus d\'evenement : un commentaire ne se '
            . 'declenche pas le jour ou sa premisse cesse d\'etre vraie');
    }

    public function test_l_avertissement_NOMME_la_consequence_ET_le_remede(): void
    {
        /*
         * Un avertissement qui dit seulement « transport non local » envoie
         * chercher dans la configuration ; il ne dit ni ce qui est en jeu ni
         * quoi faire. Celui-ci doit nommer les deux — c'est ce qui le rend
         * lisible par quelqu'un qui n'a pas ce dossier en tete.
         */
        $source = $this->source();

        foreach (['mesurable', 'php-fpm', 'fermeture de connexion'] as $terme) {
            $this->assertStringContainsString($terme, $source,
                "l'avertissement ne nomme plus « $terme »");
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // LE REGIME MESURE — et il se lit chez le SERVANT, pas chez le BANC
    // ══════════════════════════════════════════════════════════════════════

    /**
     * L'environnement du processus qui SERT le portail.
     *
     * ⚠ POURQUOI PAS `config('mail.default')`. Depuis E-447, `phpunit.xml` porte
     * `force="true"` : le banc impose `MAIL_MAILER=array` et est donc, par
     * construction, hors d'atteinte du SMTP reel. **C'est exactement ce qu'on
     * voulait — et ca eteindrait ce marqueur.** Une surete visible achetee par
     * une alerte qui s'eteint, sans que rien ne rougisse pour le dire.
     *
     * Le marqueur doit donc lire l'objet dont il parle. PID 1 de ce conteneur EST
     * `apache2` : `/proc/1/environ` rend l'environnement fige a son exec —
     * c'est-a-dire celui que `env_file:` a injecte, celui que le SAPI web voit.
     * `force="true"` ne l'atteint pas.
     *
     * Le nom du processus est VERIFIE avant lecture : ailleurs (integration
     * continue, poste local), PID 1 est autre chose, et lire son environnement
     * rendrait une valeur plausible et fausse.
     */
    private function environnementDuServant(): ?array
    {
        $nom = @file_get_contents('/proc/1/comm');
        if ($nom === false || ! in_array(trim($nom), ['apache2', 'httpd'], true)) {
            return null;
        }

        $brut = @file_get_contents('/proc/1/environ');
        if ($brut === false || $brut === '') {
            return null;
        }

        $vars = [];
        foreach (explode("\0", $brut) as $paire) {
            if ($paire === '') {
                continue;
            }
            [$cle, $valeur] = array_pad(explode('=', $paire, 2), 2, '');
            $vars[$cle] = $valeur;
        }

        // TEMOIN : un environnement de service porte toujours PATH. Un tableau
        // vide ou minuscule signifierait que le decoupage a echoue, et rendrait
        // « transport absent » — c'est-a-dire un DEDOUANEMENT.
        return isset($vars['PATH']) ? $vars : null;
    }

    public function test_le_transport_DU_SERVICE_est_DISTANT_et_la_garde_TIRE(): void
    {
        /*
         * Ce test ne juge pas la configuration : il DATE le regime dans lequel les
         * autres tests de ce fichier sont lus. Il portait « local », il porte
         * « distant » depuis le 2026-09-05 (`fff1f8d`) — c'est le meme instrument,
         * retourne le jour ou sa premisse a change, et non un instrument eteint.
         *
         * S'il rougit, c'est que le transport du SERVICE est redevenu local : le
         * defaut de temps redevient latent, et il faut retourner ce marqueur une
         * seconde fois plutot que le contourner.
         */
        $env = $this->environnementDuServant();

        if ($env === null) {
            $this->markTestSkipped(
                "FENETRE D'OBSERVATION ABSENTE : PID 1 n'est pas le serveur web, ou "
                . "son environnement est illisible. Ce marqueur ne vaut que dans le "
                . 'conteneur qui sert. Ni PASS ni FAIL — et surtout pas un feu vert.');
        }

        $transport = $env['MAIL_MAILER'] ?? null;

        if ($transport === null) {
            $this->markTestSkipped(
                "FENETRE D'OBSERVATION ABSENTE : le service ne porte aucune variable "
                . '`MAIL_MAILER`. Sa valeur vient alors de `.env`, et ce marqueur ne '
                . 'la mesure pas.');
        }

        $this->assertNotContains($transport, ReinitialisationController::TRANSPORTS_LOCAUX,
            "le transport du SERVICE est « $transport », qui EST local. Le regime a "
            . 'change depuis le 2026-09-05 : retourner ce marqueur, et relire la '
            . 'garde — elle ne se declenchera plus.');
    }

    public function test_le_BANC_lui_est_INSENSIBLE_et_ca_doit_le_rester(): void
    {
        /*
         * Le pendant du precedent, et il verrouille E-447. Le banc doit rester
         * LOCAL quoi que porte le service : c'est ce que `force="true"` obtient.
         *
         * S'il rougit, c'est que `force="true"` a saute de `phpunit.xml` — et
         * alors toute suite qui atteindrait un envoi enverrait un COURRIEL REEL.
         * *L'exposition etait latente le 2026-09-06 — un seul envoyeur, quatre
         * routes, aucune suite ne les appelle — mais la latence n'est pas une
         * garde : elle tient a ce qu'aucun test n'a encore ete ecrit.*
         */
        $duBanc = (string) config('mail.default');

        $this->assertContains($duBanc, ReinitialisationController::TRANSPORTS_LOCAUX,
            "le banc sert le transport « $duBanc », qui n'est PAS local. Verifier "
            . '`force="true"` sur `<env name="MAIL_MAILER">` dans `phpunit.xml` : '
            . 'sans lui, l\'environnement du conteneur gagne et le banc est cable '
            . 'sur le SMTP reel.');
    }

    public function test_la_valeur_du_SERVICE_ne_vient_PAS_du_fichier_env(): void
    {
        /*
         * ⚠ LE POINT QUI COUTE, ET IL SURVIT AU `force`. Le premier reflexe pour
         * desarmer un envoi est d'editer `.env`. Le service porte pourtant un
         * transport distant alors que `.env` porte une valeur locale : la valeur
         * vient de l'environnement, que `safeLoad()` refuse d'ecraser.
         *
         * > `.env` porte deja la valeur sure. Quelqu'un qui l'ouvre POUR VERIFIER
         * > y lit `log`, en conclut que l'envoi est desarme, et ne fait rien. Il
         * > n'a meme pas besoin d'editer pour se tromper.
         *
         * Ce test existe pour qu'une telle conclusion soit DEMENTIE par une suite,
         * et pas seulement par un commentaire. Il compare le SERVICE au FICHIER —
         * jamais le banc, dont la valeur est desormais imposee.
         *
         * ══ QUATRIEME REGIME DE LECTURE ══════════════════════════════════
         * Le meme nom designe des objets differents : l'ARBRE et le SERVICE,
         * MySQL et SQLite, la BASE et le fichier, et — signale le 2026-09-05 — un
         * montage de FICHIER epingle a un inode que `mv` detache en silence. Ici
         * le partage est autre : le fichier est bien le meme des deux cotes
         * (montage de REPERTOIRE, 2745 o), mais **il n'est pas la SOURCE**.
         * *« Le fichier que je lis est-il celui que le service lit » et « le
         * service lit-il ce fichier » sont deux questions distinctes.*
         */
        $env = $this->environnementDuServant();

        if ($env === null || ! isset($env['MAIL_MAILER'])) {
            $this->markTestSkipped(
                "FENETRE D'OBSERVATION ABSENTE : l'environnement du servant n'est pas "
                . "lisible ici. Il n'y a pas d'ecrasement a exhiber.");
        }

        $chemin = base_path('.env');

        if (! is_readable($chemin)) {
            $this->markTestSkipped(
                "FENETRE D'OBSERVATION ABSENTE : `.env` illisible par ce compte. "
                . "⚠ Ne PAS conclure « aucune ligne MAIL_ » d'un compte sans droits : "
                . "un refus d'acces rend zero exactement comme une absence.");
        }

        $lignes = preg_grep('/^\s*MAIL_MAILER\s*=/', file($chemin, FILE_IGNORE_NEW_LINES));

        if ($lignes === false || $lignes === []) {
            $this->markTestSkipped(
                '`.env` ne porte aucune ligne `MAIL_MAILER` : il n\'y a pas de valeur '
                . 'perdante a exhiber, donc rien a demontrer ici.');
        }

        $duFichier = trim(explode('=', (string) reset($lignes), 2)[1] ?? '');
        $duService = $env['MAIL_MAILER'];

        $this->assertNotSame($duFichier, $duService,
            "`.env` et l'environnement du service s'accordent tous deux sur "
            . "« $duService » : la demonstration de l'ecrasement n'est plus visible "
            . "ici. Ce n'est pas une regression — mais le piege du faux remede "
            . 'redevient invisible.');

        $this->assertContains($duFichier, ReinitialisationController::TRANSPORTS_LOCAUX,
            "⚠ `.env` porte « $duFichier », qui n'est PAS local, alors que le service "
            . "impose « $duService ». Quel que soit le gagnant, les deux sont "
            . 'distants : plus aucun des deux leviers ne desarme.');
    }
}
