<?php

namespace Tests\Feature;

use App\Support\RoutesBackend;
use Tests\TestCase;

/**
 * L'AFFICHAGE DE `sshd_config` — LA CAPACITE EXISTE, RIEN NE LA TENAIT.
 *
 * La chaine etait complete et n'etait mesuree par aucun test : bouton, bloc
 * d'affichage, `litConfig`, neuf libelles, passerelle. Ce fichier gele ce qui
 * la rend une capacite de LECTURE, et rien d'autre.
 *
 * ══ POURQUOI CE N'EST PAS UN TEST DECORATIF ══════════════════�
 *
 * La fermeture du module se fait « par l'ABSENCE d'appel » — c'est ecrit dans
 * `AuditSshController` et dans `audit-ssh.js`. Mesure du 2026-09-08 sur
 * `RoutesBackend`, en depouillant la prose avant d'extraire (80 % du fichier
 * est du commentaire, et son apostrophe francaise ouvre de fausses chaines) :
 *
 *     /ssh-audit/config        autorisee  reserveeAdmin=NON   <- la lecture
 *     /ssh-audit/save-config   autorisee  reserveeAdmin=NON   <- ECRIT le fichier
 *     /ssh-audit/toggle        autorisee  reserveeAdmin=NON   <- ECRIT une directive
 *     /ssh-audit/restore       autorisee  reserveeAdmin=NON   <- ECRASE par un backup
 *     /ssh-audit/reload        autorisee  reserveeAdmin=NON   <- RELANCE sshd
 *     /ssh-audit/fix           autorisee  reserveeAdmin=NON   <- ECRIT une directive
 *
 * **La passerelle transmettrait les cinq.** Leur seule garde est le
 * `@require_role(2)` du backend. L'absence d'appel n'est donc pas une elegance
 * de portage : c'est l'etage que le portage tient lui-meme.
 *
 * ⚠ ET L'ANCRE EST LE CHEMIN ENTIER, PAS LE MOT. `/ssh-audit/toggle` bascule une
 * DIRECTIVE sshd et n'est composee nulle part ; `/ssh-audit/schedules/<id>/toggle`
 * bascule une PLANIFICATION et **est** composee, legitimement. Une sonde ancree
 * sur `toggle` seul rougirait sur la seconde et couvrirait la premiere par
 * accident — meme piege que `scan` contre `scan-all` sur ce chantier.
 */
class AffichageSshdConfigLectureSeuleTest extends TestCase
{
    /** Les cinq chemins qui ECRIVENT `sshd_config` ou relancent le service. */
    private const ECRITURES = [
        '/ssh-audit/save-config',
        '/ssh-audit/toggle',
        '/ssh-audit/restore',
        '/ssh-audit/reload',
        '/ssh-audit/fix',
    ];

    /** Les neuf libelles que `audit-ssh.js` demande par `t('…')`. */
    private const CLES_JS = [
        'cfg_titre', 'cfg_texte', 'cfg_lire', 'cfg_sans_serveur',
        'cfg_titre_resultat', 'cfg_en_cours', 'cfg_refus', 'cfg_echec', 'cfg_vide',
    ];

    private function fichier(string $relatif): string
    {
        $chemin = base_path($relatif);
        $this->assertFileExists($chemin, "fichier introuvable : $relatif");

        return (string) file_get_contents($chemin);
    }

    /** Le JS sans ses commentaires — sinon la prose porte les motifs cherches. */
    private function jsSansCommentaires(string $source): string
    {
        $sansBloc = (string) preg_replace('#/\*.*?\*/#s', '', $source);

        return (string) preg_replace('#^\s*//.*$#m', '', $sansBloc);
    }

    private function javascript(): string
    {
        $code = $this->jsSansCommentaires($this->fichier('public/js/audit-ssh.js'));

        // TEMOIN : le depouillement n'a pas emporte le code mesure.
        $this->assertStringContainsString('function litConfig', $code,
            'le retrait des commentaires a emporte le code : mesure invalide');

        return $code;
    }

    // ══════════════════════════════════
    // LA CHAINE — quatre maillons, et chacun rend du VIDE tout seul
    // ══════════════════════════════════

    public function test_la_chaine_d_affichage_est_complete(): void
    {
        $vue = $this->fichier('resources/views/audit-ssh.blade.php');
        $code = $this->javascript();

        // TEMOIN : la vue porte bien des ancres.
        $this->assertStringContainsString('data-rw=', $vue,
            "la vue ne porte plus d'ancre : mesure invalide");

        /*
         * L'ancre EXACTE, guillemet de fermeture comprise. `audit-ssh-config`
         * est sous-chaine de `-bloc`, `-titre` et `-contenu` : un
         * `assertStringContainsString('audit-ssh-config')` serait satisfait par
         * le seul bloc de resultat, bouton disparu. La capacite deviendrait
         * inatteignable sans qu'aucune assertion ne bouge.
         */
        $this->assertStringContainsString('data-rw="audit-ssh-config"', $vue,
            "le bouton de lecture a disparu de l'ecran : la capacite existe et "
            . "n'est plus atteignable");

        foreach (['bloc', 'titre', 'contenu'] as $part) {
            $this->assertStringContainsString("data-rw=\"audit-ssh-config-$part\"", $vue,
                "l'ancre d'affichage `$part` a disparu : `litConfig` teste ses "
                . 'trois ancres ensemble et ne rendrait plus RIEN, en silence');
        }

        $this->assertStringContainsString("'/ssh-audit/config'", $code,
            'le portage ne demande plus la configuration au backend');
    }

    // ══════════════════════════════════
    // LES LIBELLES — dans les DEUX catalogues, et par CLE
    // ══════════════════════════════════

    public function test_les_neuf_libelles_sont_dans_LES_DEUX_catalogues(): void
    {
        /*
         * Une cle que la JS attend et que le catalogue ne porte pas ne rend pas
         * son nom : `t()` rend `undefined`, donc du VIDE — un ecran muet, pas
         * un ecran faux. C'est invisible a toute assertion de forme.
         *
         * On CHARGE le catalogue et on interroge la CLE : une sous-chaine
         * `cfg_vide` survit a un renommage en `cfg_vide_retire`.
         */
        foreach (['lang/fr/ssh_audit.php', 'lang/en/ssh_audit.php'] as $catalogue) {
            $cles = require base_path($catalogue);
            $this->assertIsArray($cles, "catalogue illisible : $catalogue");

            // TEMOIN POSITIF : le catalogue du module est fourni.
            $this->assertGreaterThan(40, count($cles),
                "catalogue anormalement pauvre : mesure invalide ($catalogue)");

            foreach (self::CLES_JS as $cle) {
                $this->assertArrayHasKey($cle, $cles,
                    "`$cle` manque a $catalogue. `audit-ssh.js` la demande : "
                    . "l'ecran afficherait du VIDE, pas un libelle fautif.");
            }

            // Le libelle de la vue, qui ANNONCE la lecture seule a l'ecran.
            $this->assertArrayHasKey('cfg_lecture_seule', $cles,
                "`cfg_lecture_seule` manque a $catalogue : la reserve affichee "
                . 'sous le titre disparaitrait sans que rien ne rougisse');
        }
    }

    // ══════════════════════════════════
    // ⛔ L'INVARIANT — MONTRER, JAMAIS TOUCHER
    // ══════════════════════════════════

    public function test_aucun_appel_d_ECRITURE_sur_sshd_config(): void
    {
        $code = $this->javascript();

        foreach (self::ECRITURES as $chemin) {
            $this->assertStringNotContainsString($chemin, $code,
                "le portage compose desormais `$chemin`. **La passerelle "
                . 'transmet ce chemin** et ne le reserve pas a un role 2 : sa '
                . "seule garde est le backend. L'affichage de `sshd_config` est "
                . 'une capacite de LECTURE — si cette ecriture est une decision, '
                . 'elle se prend explicitement, avec sa garde et son inscription '
                . 'dans `TableDesGardes`.');
        }
    }

    public function test_CONTRE_TEMOIN_la_lecture_elle_est_bien_composee(): void
    {
        /*
         * ⚠ SANS CE TEST, LE PRECEDENT EST VRAI A VIDE. Une `audit-ssh.js`
         * reduite a un fichier vide — ou dont le depouillement aurait tout
         * emporte — satisferait les cinq assertions d'absence.
         *
         * Une universelle negative ne prouve quelque chose que si l'instrument
         * a montre, sur le meme texte, qu'il sait rendre le positif.
         */
        $code = $this->javascript();

        $this->assertStringContainsString("ecris('/ssh-audit/config'", $code,
            "la lecture n'est plus composee : les assertions d'absence "
            . 'ci-dessus ne mesurent plus rien');
    }

    // ══════════════════════════════════
    // LA PASSERELLE — ce qui rend l'invariant PORTEUR
    // ══════════════════════════════════

    public function test_la_passerelle_ne_reserve_PAS_les_ecritures_a_l_admin(): void
    {
        /*
         * ⚠ CE TEST NE DEMANDE PAS UN CHANGEMENT. Il gele le CONSTAT qui donne
         * son poids au test d'absence : si un jour ces cinq chemins passent en
         * `ADMIN_SEULEMENT`, ce rouge sera la BONNE nouvelle, et il faudra
         * retirer ce test en le disant.
         *
         * Il est ecrit ici, a cote de l'invariant qu'il justifie, plutot que
         * dans le fichier de la passerelle : c'est cette absence de reserve qui
         * explique pourquoi la fermeture par absence d'appel est le seul etage
         * porte par le portage.
         */
        foreach (self::ECRITURES as $chemin) {
            $this->assertTrue(RoutesBackend::autorisee($chemin),
                "`$chemin` n'est plus transmis par la passerelle. Si c'est une "
                . "decision, l'invariant d'absence d'appel gagne un second "
                . 'etage et ce test doit etre reecrit.');

            $this->assertFalse(RoutesBackend::reserveeAdmin($chemin),
                "`$chemin` est desormais reserve a l'administration par la "
                . 'passerelle. **Bonne nouvelle** : retirer cette assertion et '
                . "dire, dans le test d'absence, que la garde a gagne un etage.");
        }

        // TEMOIN : la fonction sait dire OUI. Quatre chemins du meme module
        // sont bien reserves — sans quoi `reserveeAdmin` pourrait etre inerte.
        $this->assertTrue(RoutesBackend::reserveeAdmin('/ssh-audit/fleet'),
            '`reserveeAdmin` ne reserve plus rien : les assertions `assertFalse` '
            . 'ci-dessus passeraient sur une fonction en panne');
    }

    // ══════════════════════════════════
    // LE RENDU — un fichier venu d'un serveur entre dans la page
    // ══════════════════════════════════

    public function test_le_contenu_du_fichier_est_rendu_par_textContent(): void
    {
        $code = $this->javascript();

        $this->assertStringContainsString('cfgContenu.textContent', $code,
            "le contenu de `sshd_config` n'est plus rendu par `textContent`");

        $this->assertStringNotContainsString('cfgContenu.innerHTML', $code,
            'le contenu de `sshd_config` est rendu par `innerHTML`. Ce texte '
            . "vient d'un fichier lu sur une machine distante : il est du "
            . 'CONTENU, jamais du balisage.');
    }
}
