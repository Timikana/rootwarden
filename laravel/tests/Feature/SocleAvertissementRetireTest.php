<?php

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * LA CLE RETIREE NE REVIENT PAS — une garde DERIVEE, pas une verification.
 *
 * ══ POURQUOI CE FICHIER EXISTE ═══════════════════════════════════════════
 *
 * Cette absence etait verifiee A LA MAIN, et consignee SEIZE fois dans
 * `docs/migration/DECISIONS-DSI.md` — seize tours, seize fois la meme commande.
 * Le cout n'est pas la commande : c'est qu'une verification recitee DERIVE,
 * alors qu'une garde REFUSE.
 *
 * L'ordre de preference du depot est *inexprimable > derive > exhaustif >
 * controle*. Le controle manuel etait le dernier ; un `grep` dans un test le
 * resterait. Cette garde est DERIVEE : elle enumere les fichiers depuis le
 * disque et interroge la STRUCTURE, pas le texte.
 *
 * ══ TROIS ETATS, PAS DEUX ════════════════════════════════════════════════
 *
 *     cle ABSENTE          -> l'etat voulu, la garde passe
 *     cle PRESENTE         -> refus, avec le fichier nomme
 *     instrument MUET      -> refus AUSSI
 *
 * Le troisieme est celui qu'on oublie. Une universelle negative est VRAIE A
 * VIDE : « aucun fichier ne porte la cle » passe si la liste de fichiers est
 * vide. Un renommage de `lang/` rendrait donc la garde verte POUR TOUJOURS, en
 * ne mesurant plus rien. C'est pourquoi les comptes parcourus sont ASSERTES non
 * nuls, et pourquoi une cle QUI EXISTE doit etre TROUVEE par le meme
 * instrument.
 *
 * ══ ET POURQUOI LA CLE N'EST JAMAIS ECRITE EN UN SEUL MORCEAU ════════════
 *
 * Une garde qui cherche un motif que sa propre source contient SE TROUVE
 * ELLE-MEME — son message d'erreur, son commentaire, le nom de sa methode.
 * Le defaut a ete paye ailleurs le meme jour : une sonde a signale un
 * COMMENTAIRE qui expliquait le defaut qu'elle cherchait.
 *
 * Le remede n'est pas un filtre mais une ABSENCE : la cle est assemblee a
 * l'execution depuis `FRAGMENTS`, donc le mot complet n'apparait NULLE PART
 * dans ce fichier. Un filtre se contourne ; ce qui n'est pas ecrit ne se
 * trouve pas.
 *
 * ⚠ LIMITE DECLAREE. Pour les fichiers de langue, l'interrogation porte sur le
 * TABLEAU CHARGE — un commentaire qui nomme la cle n'est pas une cle, donc la
 * confusion est inexprimable. Pour les vues Blade il n'y a pas de structure a
 * charger : la recherche y est TEXTUELLE, avec les commentaires Blade et PHP
 * retires. Une cle citee dans une CHAINE d'une vue serait donc signalee. Aucun
 * cas aujourd'hui, et le refus serait du bon cote.
 */
class SocleAvertissementRetireTest extends TestCase
{
    /**
     * La cle, en morceaux — voir le docblock. Ne PAS reassembler ici.
     *
     * @var list<string>
     */
    private const FRAGMENTS = ['socle', 'avertissement'];

    /** Une cle qui EXISTE, pour prouver que l'instrument trouve. */
    private const TEMOIN_PRESENT = 'cgu_titre';

    private function cle(): string
    {
        return implode('_', self::FRAGMENTS);
    }

    /** @return list<string> */
    private function fichiersDeLangue(): array
    {
        return glob(base_path('lang/*/auth.php')) ?: [];
    }

    /** @return list<string> */
    private function vues(): array
    {
        $out = [];
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(base_path('resources/views'))
        );
        foreach ($it as $f) {
            if ($f->isFile() && str_ends_with($f->getFilename(), '.blade.php')) {
                $out[] = $f->getPathname();
            }
        }
        sort($out);

        return $out;
    }

    /** Retire les commentaires Blade et PHP — « cite » n'est pas « employe ». */
    private function depouille(string $t): string
    {
        $t = preg_replace('/\{\{--.*?--\}\}/s', ' ', $t) ?? $t;
        $t = preg_replace('#/\*.*?\*/#s', ' ', $t) ?? $t;

        return preg_replace('#//[^\n]*#', ' ', $t) ?? $t;
    }

    #[Test]
    public function l_instrument_regarde_quelque_chose(): void
    {
        $langues = $this->fichiersDeLangue();
        $vues = $this->vues();

        // ⛔ LE TROISIEME ETAT. Sans ces deux assertions, tout ce fichier est
        //    vrai a vide et le restera silencieusement.
        $this->assertNotEmpty(
            $langues,
            "Aucun fichier `lang/*/auth.php` parcouru : la garde ne mesure RIEN. "
            . "Un renommage de `lang/` la rendrait verte pour toujours."
        );
        $this->assertNotEmpty(
            $vues,
            'Aucune vue Blade parcourue : la garde ne mesure RIEN.'
        );

        // Et la CONTRE-EPREUVE du meme instrument : une cle qui EXISTE doit
        // etre trouvee. Sinon « rien trouve » et « rien cherche » se lisent
        // pareil.
        $trouve = 0;
        foreach ($langues as $f) {
            $t = require $f;
            if (is_array($t) && array_key_exists(self::TEMOIN_PRESENT, $t)) {
                $trouve++;
            }
        }
        $this->assertGreaterThan(
            0,
            $trouve,
            'Le temoin `' . self::TEMOIN_PRESENT . '` n\'est trouve dans AUCUN '
            . 'fichier de langue : l\'instrument ne lit pas ce qu\'il croit lire.'
        );
    }

    #[Test]
    public function la_cle_retiree_est_absente_des_fichiers_de_langue(): void
    {
        $cle = $this->cle();
        foreach ($this->fichiersDeLangue() as $f) {
            $t = require $f;
            $this->assertIsArray($t, "Le fichier de langue $f ne rend pas un tableau.");
            // DERIVE : on interroge la STRUCTURE. Un commentaire qui nomme la
            // cle n'est pas une cle — la confusion est inexprimable ici.
            $this->assertArrayNotHasKey(
                $cle,
                $t,
                "La cle retiree est REVENUE dans $f. Elle avait ete retiree "
                . 'deliberement ; son retour est un defaut, pas une omission.'
            );
        }
    }

    #[Test]
    public function la_cle_retiree_n_est_employee_par_aucune_vue(): void
    {
        $cle = $this->cle();
        foreach ($this->vues() as $f) {
            $t = $this->depouille((string) file_get_contents($f));
            $this->assertStringNotContainsString(
                $cle,
                $t,
                "La vue $f emploie la cle retiree. Si c'est une CITATION dans "
                . 'une chaine, le refus est du bon cote : deplacez-la hors du '
                . 'code rendu.'
            );
        }
    }
}
