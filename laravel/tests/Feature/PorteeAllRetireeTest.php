<?php

namespace Tests\Feature;

use App\Services\PlanificationsCve;
use Tests\TestCase;

/**
 * E-387 — `'all'` n'est plus une portee de planification, ET ELLE L'ETAIT A SIX
 * ETAGES.
 *
 * Le meme defaut vivait dans six endroits qui se rattrapaient l'un l'autre :
 * fermer un seul laissait un formulaire dont la premiere option soumettait une
 * valeur que le serveur refuse, ou un serveur strict derriere un client qui
 * fabrique encore la valeur.
 *
 *     etage 1   PlanificationsCve::CIBLES              la liste fermee
 *     etages 2-3 les deux defauts du service            `?? ''` et non `'all'`
 *     etage 4   planification-cve.js  `saisie()`        plus de repli vers `all`
 *     etage 5   scan-cve.blade.php                      plus d'`<option value="all">`
 *     etage 6   la route backend                        mesuree ailleurs
 *                 (`backend/tests/test_ssh_audit_planification.py`)
 *
 * ┌─ ⚠ CE QUE CE TEST NE DOIT SURTOUT PAS VERROUILLER ─────────────────────────┐
 * │ `planif.cible_all` est CONSERVE dans les deux catalogues, DELIBEREMENT :    │
 * │ `planification-cve.js` en a besoin pour NOMMER une ligne existante de type  │
 * │ `all`. Le retirer afficherait une portee VIDE sur une planification qui     │
 * │ joint tout le parc.                                                         │
 * │                                                                             │
 * │ **Cesser d'OFFRIR n'est pas cesser de SAVOIR LIRE.** Un invariant qui       │
 * │ asserterait « `cible_all` a disparu » verrouillerait le PIRE des deux       │
 * │ etats — et c'est pour ca que la derniere classe de ce fichier existe.       │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
class PorteeAllRetireeTest extends TestCase
{
    private function fichier(string $relatif): string
    {
        $chemin = base_path($relatif);
        $this->assertFileExists($chemin, "fichier introuvable : $relatif");

        return (string) file_get_contents($chemin);
    }

    /**
     * Le PHP sans ses commentaires, par le lexeur de PHP lui-meme.
     *
     * Une expression reguliere sur du PHP a deja fait rendre l'INVERSE de la
     * verite a une mesure de ce chantier : les apostrophes francaises des
     * commentaires ouvraient de fausses chaines. `token_get_all()` est PHP qui
     * lit du PHP.
     */
    private function phpSansCommentaires(string $source): string
    {
        $sortie = '';
        foreach (token_get_all($source) as $jeton) {
            if (is_array($jeton) && in_array($jeton[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            $sortie .= is_array($jeton) ? $jeton[1] : $jeton;
        }

        return $sortie;
    }

    /** Le JS sans ses commentaires — `//` et `/* … *\/`. */
    private function jsSansCommentaires(string $source): string
    {
        $sansBloc = preg_replace('#/\*.*?\*/#s', '', $source);

        return (string) preg_replace('#^\s*//.*$#m', '', (string) $sansBloc);
    }

    // ══════════════════════════════════════════════════════════════════════
    // ETAGE 1 — la liste fermee, lue par REFLEXION et non parsee
    // ══════════════════════════════════════════════════════════════════════

    public function test_la_liste_des_cibles_ne_contient_plus_all(): void
    {
        // La constante est publique : on la LIT. Aucune analyse de source ne
        // peut se tromper sur une valeur qu'on peut demander directement.
        $this->assertNotContains('all', PlanificationsCve::CIBLES,
            "`'all'` est revenu dans `PlanificationsCve::CIBLES` — E-387. Si "
            . "c'est une decision, remplacer ce test par la regle retenue.");
    }

    public function test_les_deux_cibles_restantes_sont_toujours_la(): void
    {
        // LE CONTRE-CAS. Un `CIBLES = []` satisferait le test precedent et
        // casserait la fonctionnalite entiere.
        $this->assertSame(['tag', 'machines'], array_values(PlanificationsCve::CIBLES));
    }

    // ══════════════════════════════════════════════════════════════════════
    // ETAGES 2-3 — les deux defauts du service
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_service_ne_fabrique_plus_all_par_defaut(): void
    {
        $code = $this->phpSansCommentaires(
            $this->fichier('app/Services/PlanificationsCve.php'));

        // TEMOIN : le retrait des commentaires n'a pas mange le code.
        $this->assertStringContainsString('CIBLES', $code,
            'le retrait des commentaires a emporte le code : mesure invalide');

        $this->assertStringNotContainsString("?? 'all'", $code);
        $this->assertStringNotContainsString("'all'", $code,
            "une valeur `'all'` subsiste dans le CODE du service (hors "
            . 'commentaires) : le defaut se refabrique quelque part');
    }

    // ══════════════════════════════════════════════════════════════════════
    // ETAGE 4 — le formulaire ne fabrique plus la valeur
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_javascript_n_attribue_jamais_all_a_un_type(): void
    {
        $code = $this->jsSansCommentaires(
            $this->fichier('public/js/planification-cve.js'));

        $this->assertStringContainsString('function saisie', $code,
            'le retrait des commentaires a emporte le code : mesure invalide');

        // La propriete est sur le TYPE envoye, pas sur la presence du mot.
        // `const brut = … || 'all'` subsiste et est INERTE : `type` part de `''`
        // et n'est affecte que par les branches `tag:` et `multi`. Asserter
        // l'absence du mot ferait rougir un residu sans effet ; asserter que le
        // type ne peut pas VALOIR `'all'` mesure la propriete.
        $this->assertStringNotContainsString("type = 'all'", $code,
            "le repli du formulaire fabrique de nouveau `'all'` — quatrieme "
            . 'etage du defaut E-387');
        $this->assertStringContainsString("let type = ''", $code,
            "le type ne part plus de la chaine vide : verifier ce qu'il vaut "
            . "quand aucune branche ne l'affecte");
    }

    // ══════════════════════════════════════════════════════════════════════
    // ETAGE 5 — l'ecran ne l'OFFRE plus, et c'etait le premier choix
    // ══════════════════════════════════════════════════════════════════════

    public function test_l_ecran_n_offre_plus_la_portee_all(): void
    {
        $vue = $this->fichier('resources/views/scan-cve.blade.php');

        $this->assertStringContainsString('sched-target', $vue,
            'la liste de portee a disparu de la vue : mesure invalide');

        // `all` etait le PREMIER choix de la liste. Une entree libre ABSENTE ne
        // se contourne pas ; une entree offerte se soumet d'un clic.
        $this->assertStringNotContainsString('value="all"', $vue);
        $this->assertStringNotContainsString("value='all'", $vue);
    }

    // ══════════════════════════════════════════════════════════════════════
    // ⚠ L'ANTI-VERROU — ce qui doit RESTER
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_libelle_cible_all_est_CONSERVE_dans_LES_DEUX_catalogues(): void
    {
        // Les deux dans un seul test, et non par `@dataProvider` : le premier
        // jet en utilisait un, PHPUnit ne l'a pas reconnu et a appele la methode
        // SANS argument -> `ArgumentCountError`. Un rouge qui ne parlait pas de
        // `cible_all` du tout. *Un test qui echoue pour une raison etrangere a
        // sa propriete ne mesure pas sa propriete.*
        foreach (['lang/fr/planif.php', 'lang/en/planif.php'] as $catalogue) {
            // ══ LA CLE, PAS LA SOUS-CHAINE — ET LA MUTATION ME L'A APPRIS ═══
            //
            // Premier jet : `assertStringContainsString('cible_all', $texte)`.
            // Mutation A4 — renommer la cle en `'cible_all_retire'` — n'a fait
            // rougir AUCUN test : la sous-chaine `cible_all` est toujours la.
            // **Mon anti-verrou passait sur une mutation qui retire la cle.**
            //
            // On CHARGE donc le catalogue : c'est un `return [...]` PHP, il se
            // lit sans etre parse, et `array_key_exists` ne se laisse pas
            // tromper par un prefixe. Meme geste que la lecture de `CIBLES` par
            // reflexion — *quand on peut demander la valeur, on ne la cherche
            // pas dans le texte.*
            $cles = require base_path($catalogue);
            $this->assertIsArray($cles, "catalogue illisible : $catalogue");

            // TEMOIN POSITIF : un catalogue de planification porte beaucoup de cles.
            $this->assertGreaterThan(20, count($cles),
                "catalogue anormalement pauvre : mesure invalide ($catalogue)");

            $this->assertArrayHasKey('cible_all', $cles,
                "`cible_all` a ete retire de $catalogue. CE ROUGE PROTEGE LE PIRE "
                . 'DES DEUX ETATS : le libelle sert a NOMMER une planification '
                . 'existante de type `all`, que le portage ne cree plus mais doit '
                . 'savoir LIRE. Sans lui, une planification qui joint tout le parc '
                . "s'affiche avec une portee VIDE. Cesser d'OFFRIR n'est pas cesser "
                . 'de SAVOIR LIRE.');
        }
    }
}
