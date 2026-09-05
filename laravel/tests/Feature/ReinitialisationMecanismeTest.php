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
    // LE REGIME MESURE — pour que la bascule se voie
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_transport_courant_est_DISTANT_et_la_garde_TIRE(): void
    {
        /*
         * Ce test ne juge pas la configuration : il DATE le regime dans lequel
         * les autres tests de ce fichier sont lus. Il portait « local », il
         * porte « distant » — c'est le meme instrument, retourne le jour ou sa
         * premisse a change, et non un instrument qu'on eteint.
         *
         * S'il rougit MAINTENANT, c'est que quelqu'un est repasse en transport
         * local : le defaut redevient latent, et il faudra retourner ce
         * marqueur une seconde fois plutot que de le contourner.
         */
        $transport = (string) config('mail.default');

        $this->assertNotContains($transport, ReinitialisationController::TRANSPORTS_LOCAUX,
            "le transport courant est « $transport », qui EST local. Le regime a "
            . 'change depuis le 2026-09-05 : retourner ce marqueur, et relire la '
            . 'garde — elle ne se declenchera plus.');
    }

    public function test_la_valeur_SERVIE_ne_vient_PAS_du_fichier_env(): void
    {
        /*
         * ⚠ LE POINT QUI COUTE. Le premier reflexe, pour desarmer un envoi, est
         * d'editer `.env`. Ici `.env` porte DEJA `log` et le transport est
         * pourtant `smtp` : la valeur vient de l'environnement du process, que
         * `safeLoad()` refuse d'ecraser.
         *
         * Ce test existe pour qu'une tentative de desarmement par `.env` soit
         * DEMENTIE par une suite, et pas seulement par un commentaire.
         *
         * ══ QUATRIEME REGIME DE LECTURE ══════════════════════════════════
         * Le meme nom peut designer deux objets : l'ARBRE et le SERVICE, MySQL
         * et SQLite, la BASE et le fichier, et — signale par le DSI le
         * 2026-09-05 — un montage de FICHIER epingle a un inode que `mv` ou
         * `git checkout` detache en silence. Ici, le partage est autre : le
         * fichier est bien le meme des deux cotes (2745 o, montage de
         * REPERTOIRE), mais il n'est pas la SOURCE. *« Le fichier que je lis
         * est-il celui que le service lit » et « le service lit-il ce fichier »
         * sont deux questions distinctes.*
         */
        $depuisEnvironnement = getenv('MAIL_MAILER');

        if ($depuisEnvironnement === false || $depuisEnvironnement === '') {
            $this->markTestSkipped(
                'FENETRE D\'OBSERVATION ABSENTE : aucune variable `MAIL_MAILER` '
                . "dans l'environnement du process. Ce test ne vaut que la ou "
                . '`srv-docker.env` est injecte par `env_file:` — hors conteneur, '
                . "il n'y a pas d'ecrasement a constater. Ni PASS ni FAIL.");
        }

        $this->assertSame($depuisEnvironnement, (string) config('mail.default'),
            "le transport servi ne suit plus la variable d'environnement : la "
            . 'demonstration ci-dessous ne porte plus.');

        $chemin = base_path('.env');
        if (! is_readable($chemin)) {
            $this->markTestSkipped(
                "FENETRE D'OBSERVATION ABSENTE : `.env` illisible par ce compte. "
                . "⚠ Ne PAS conclure « pas de ligne MAIL_ » d'un compte nul : un "
                . "refus d'acces rend zero exactement comme une absence.");
        }

        $lignes = preg_grep('/^\s*MAIL_MAILER\s*=/', file($chemin, FILE_IGNORE_NEW_LINES));

        if ($lignes === false || $lignes === []) {
            $this->markTestSkipped(
                '`.env` ne porte aucune ligne `MAIL_MAILER` : il n\'y a pas de '
                . 'valeur perdante a exhiber, donc rien a demontrer ici.');
        }

        $duFichier = trim(explode('=', (string) reset($lignes), 2)[1] ?? '');

        $this->assertNotSame($duFichier, $depuisEnvironnement,
            "`.env` et l'environnement s'accordent : la demonstration de "
            . "l'ecrasement n'est plus visible sur cette machine. Ce n'est pas "
            . 'une regression — mais le piege du faux remede redevient invisible.');

        $this->assertContains($duFichier, ReinitialisationController::TRANSPORTS_LOCAUX,
            "⚠ `.env` porte « $duFichier », qui n'est PAS local, alors que "
            . "l'environnement impose « $depuisEnvironnement ». Quel que soit le "
            . 'gagnant, les deux sont distants : plus aucun des deux leviers ne '
            . 'desarme.');
    }
}
