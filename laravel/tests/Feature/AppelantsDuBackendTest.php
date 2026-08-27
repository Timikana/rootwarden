<?php

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * QUI, DANS LE PORTAGE, CONSOMME UN VERDICT — ET L'A-T-ON REGARDÉ ?
 *
 * `InventaireDesGardesTest` relève ce que chaque route DÉCLARE. Celui-ci est son
 * complément exact : il relève ce que chaque APPELANT SUPPOSE.
 *
 * ── POURQUOI CE FICHIER NE JUGE RIEN ─────────────────────────────────────────
 *
 * PHP ne sait pas analyser du JavaScript. Lui faire deviner la syntaxe à
 * l'expression régulière reviendrait à réécrire un analyseur — et ce chantier a
 * déjà payé cette faute deux fois : `Navigation.php` compté 32 pour 33, et les
 * jobs de la CI comptés 14 pour 13 parce qu'une classe de caractères oubliait le
 * tiret bas.
 *
 * Le jugement vient donc de `tests/Outils/analyse-appelants.mjs`, qui lit le
 * JavaScript avec `acorn` — le même analyseur que Node. Ce test-ci ne fait
 * qu'une chose : **détecter qu'un fichier a changé depuis le dernier examen**,
 * et nommer la commande à rejouer.
 *
 *     NODE_PATH=/usr/share/nodejs node laravel/tests/Outils/analyse-appelants.mjs \
 *         laravel/public/js --instantane > laravel/tests/Outils/appelants.instantane.json
 *
 * ── CE QU'IL ATTRAPE, ET POURQUOI C'EST SUFFISANT ────────────────────────────
 *
 * Un appelant neuf est de deux sortes :
 *   - il passe par le helper du fichier  → il HÉRITE de son contrôle. Sûr par
 *     construction, et le fichier change quand même : on regarde ;
 *   - il écrit son propre `fetch`        → c'est le cas dangereux, et le fichier
 *     change forcément.
 * Dans les deux cas l'empreinte bouge. **Il n'existe pas de troisième cas.**
 *
 * ── ET IL EST BRUYANT, C'EST ASSUMÉ ──────────────────────────────────────────
 *
 * Toute modification d'un fichier JS le fait rougir, y compris un commentaire.
 * C'est le prix d'une mesure SOLIDE : la seule façon de réduire le bruit serait
 * de ne hacher que « les lignes qui comptent », c'est-à-dire de décider en PHP
 * ce qui compte dans du JavaScript — la faute qu'on vient d'écarter.
 *
 * Le rougissement n'accuse personne : il dit « ce fichier n'a pas été relu par
 * l'analyseur depuis qu'il a changé ». Rafraîchir l'instantané est le geste, et
 * le regarder est la raison d'être du geste.
 */
class AppelantsDuBackendTest extends TestCase
{
    private const INSTANTANE = __DIR__ . '/../Outils/appelants.instantane.json';

    private const DOSSIER_JS = __DIR__ . '/../../public/js';

    /** @return array<string,mixed> */
    private function instantane(): array
    {
        $brut = @file_get_contents(self::INSTANTANE);

        $this->assertNotFalse($brut, 'Instantané absent : ' . self::INSTANTANE);

        $donnees = json_decode($brut, true);

        // Un instantané illisible doit ARRÊTER le test, pas le laisser continuer
        // sur un tableau vide — un relevé vide se lit « aucun appelant fautif »,
        // qui est la conclusion la plus dangereuse.
        $this->assertIsArray($donnees, 'Instantané illisible (JSON invalide)');

        return $donnees;
    }

    #[Test]
    public function chaque_fichier_javascript_figure_dans_l_instantane(): void
    {
        $empreintes = $this->instantane()['empreintes'] ?? [];
        $absents    = [];

        foreach ($this->fichiersJs() as $nom => $_chemin) {
            if (! array_key_exists($nom, $empreintes)) {
                $absents[] = $nom;
            }
        }

        $this->assertSame([], $absents,
            "Des fichiers JavaScript n'ont JAMAIS été examinés par l'analyseur.\n"
            . "Un fichier neuf peut porter un appelant qui ne lit aucun verdict.\n"
            . 'Rejouer : ' . $this->commande() . "\n"
            . 'Absents : ' . implode(', ', $absents));
    }

    #[Test]
    public function l_instantane_ne_nomme_aucun_fichier_disparu(): void
    {
        $connus    = $this->fichiersJs();
        $fantomes  = [];

        foreach (array_keys($this->instantane()['empreintes'] ?? []) as $nom) {
            if (! isset($connus[$nom])) {
                $fantomes[] = $nom;
            }
        }

        // Une attente qui ne porte sur rien passe toujours.
        $this->assertSame([], $fantomes,
            'L\'instantané nomme des fichiers qui n\'existent plus : ' . implode(', ', $fantomes));
    }

    #[Test]
    public function aucun_fichier_n_a_change_depuis_le_dernier_examen(): void
    {
        $empreintes = $this->instantane()['empreintes'] ?? [];
        $modifies   = [];

        foreach ($this->fichiersJs() as $nom => $chemin) {
            if (! isset($empreintes[$nom])) {
                continue; // déjà dit par le premier test
            }

            $reelle = substr(hash('sha256', (string) file_get_contents($chemin)), 0, 16);

            if ($reelle !== $empreintes[$nom]) {
                $modifies[$nom] = "attendu {$empreintes[$nom]}, trouvé {$reelle}";
            }
        }

        $this->assertSame([], $modifies,
            "Des fichiers JavaScript ont changé depuis leur dernier examen.\n"
            . "CE N'EST PAS UNE ACCUSATION : c'est le moment de regarder si un appelant\n"
            . "neuf consomme un verdict sans le lire. Rejouer l'analyseur, LIRE sa sortie,\n"
            . "puis rafraîchir l'instantané dans le même commit que la modification :\n"
            . '  ' . $this->commande() . "\n"
            . json_encode($modifies, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    #[Test]
    public function les_appelants_a_examiner_sont_ceux_qui_ont_ete_qualifies(): void
    {
        /*
         * Les cinq sites que l'analyseur ne peut pas dédouaner tout seul, et qui
         * ont été lus un par un. Le détail de chaque verdict est dans
         * `docs/migration/QA-APPELANTS.md` ; ici on tient seulement le FAIT qu'ils
         * sont cinq et lesquels — pour qu'un sixième ne puisse pas apparaître
         * sans que quelqu'un le nomme.
         */
        $attendus = [
            'cles-ssh.js:189',            // /api/gateway/preflight_check — BACKEND
            'journal-audit.js:73',        // routes Laravel
            'planification-cve.js:78',    // route Laravel
            'planification-cve.js:180',   // routes Laravel
            'scan-cve.js:713',            // route Laravel
        ];

        $reels = array_map(
            fn (array $a) => $a['fichier'] . ':' . $a['ligne'],
            $this->instantane()['a_examiner'] ?? [],
        );

        sort($attendus);
        sort($reels);

        $this->assertSame($attendus, $reels,
            "La liste des appelants à examiner a changé.\n"
            . "Un site qui APPARAÎT n'a jamais été qualifié ; un site qui DISPARAÎT l'a été\n"
            . "par un changement de code qu'il faut relire. Voir docs/migration/QA-APPELANTS.md.");
    }

    /** @return array<string,string> nom => chemin */
    private function fichiersJs(): array
    {
        $table = [];

        foreach (glob(self::DOSSIER_JS . '/*.js') ?: [] as $chemin) {
            $table[basename($chemin)] = $chemin;
        }

        ksort($table);

        return $table;
    }

    private function commande(): string
    {
        return 'NODE_PATH=/usr/share/nodejs node laravel/tests/Outils/analyse-appelants.mjs '
            . 'laravel/public/js --instantane > laravel/tests/Outils/appelants.instantane.json';
    }
}
