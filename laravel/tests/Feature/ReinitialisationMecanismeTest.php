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
 * `mail.default` vaut `log` : le defaut est LATENT. Il devient vivant le jour ou
 * un transport reseau est configure — et ce jour-la, personne ne relira ce
 * fichier. **Un commentaire, meme juste, ne produit aucun evenement le jour ou
 * sa premisse cesse d'etre vraie.**
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

    public function test_le_transport_courant_est_LOCAL_et_la_garde_dort(): void
    {
        /*
         * Ce test ne juge pas la configuration : il DATE le regime dans lequel
         * les autres tests de ce fichier ont ete ecrits. Tant qu'il passe, le
         * defaut de temps est LATENT et la garde ne s'est jamais declenchee.
         *
         * S'il rougit, ce n'est PAS une regression : c'est que l'exploitant a
         * pose un transport reseau — et alors la mesure au reseau, aujourd'hui
         * differee, devient la seule chose qui manque.
         */
        $transport = (string) config('mail.default');

        $this->assertContains($transport, ReinitialisationController::TRANSPORTS_LOCAUX,
            "le transport courant est « $transport », qui n'est PAS local. Le "
            . "defaut de temps n'est plus latent : sous mod_php, l'envoi precede "
            . 'la fermeture de connexion. Mesurer au reseau avant de conclure, '
            . 'et ne pas contourner ce test.');
    }
}
