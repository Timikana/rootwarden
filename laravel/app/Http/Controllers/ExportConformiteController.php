<?php

namespace App\Http\Controllers;

use App\Services\Conformite;
use Illuminate\Http\Response;

/**
 * Module `security/`, sous-lot S2c : l'export CSV du rapport de conformite.
 *
 * Meme garde que la page (S2a) et MEMES CHIFFRES : tout vient de
 * `Conformite::rapport()`. Deux calculs separes finiraient par ne plus dire la
 * meme chose.
 *
 * LA CHARGE UTILE EST ASSEMBLEE AVANT D'ETRE ENVOYEE, et c'est structurel.
 * `compliance_report.php` ecrit au fil de l'eau dans `php://output` ; comme
 * `verify.php` pose `display_errors=1` quand `DEBUG_MODE=true` et que PHP 8.4
 * deprecie `fputcsv()` appele sans son argument `$escape`, chacun de ses
 * 34 appels injecte un bloc HTML `<b>Deprecated</b>` DANS le fichier telecharge.
 * Mesure : le fichier s'ouvre sur « <br /> » au lieu de son titre, et la section
 * du parc rend 13 lignes pour 3 machines, celle des comptes 34 pour 10.
 *
 * Le plus parlant : la branche PDF DU MEME FICHIER porte deja un
 * `ob_end_clean()` dont le commentaire nomme exactement ce defaut — « purger
 * tout output parasite (notices PHP captures par ob_start en mode debug) avant
 * d'emettre le binaire PDF ». Quelqu'un l'a rencontre et n'en a corrige qu'une
 * moitie. Ici rien ne part avant que tout soit ecrit, donc aucun avertissement,
 * quelle qu'en soit la cause future, ne peut s'y glisser.
 *
 * `$escape` est passe EXPLICITEMENT, a sa valeur historique : la depreciation
 * porte sur l'ABSENCE de l'argument, pas sur sa valeur. Le passer tait
 * l'avertissement sans changer un octet de la sortie.
 *
 * DEUX POPULATIONS DIFFERENTES, REPRISES TELLES QUELLES. Le CSV liste TOUS les
 * comptes ; le tableau de la page saute les inactifs. Deux vues du meme rapport,
 * deux perimetres — restreindre l'un ou elargir l'autre change ce que le rapport
 * DIT, ce qui est une decision et non un effet de bord de portage.
 */
class ExportConformiteController extends Controller
{
    public function __construct(private readonly Conformite $conformite)
    {
    }

    public function __invoke(): Response
    {
        $r = $this->conformite->rapport(date('d/m/Y H:i'));
        $nom = 'rapport_conformite_' . date('Y-m-d') . '.csv';

        return response($this->csv($r), 200, [
            'Content-Type'        => 'text/csv; charset=utf-8',
            'Content-Disposition' => 'attachment; filename="' . $nom . '"',
            'Pragma'              => 'no-cache',
        ]);
    }

    /** @param array<string,mixed> $r */
    private function csv(array $r): string
    {
        $flux = fopen('php://temp', 'r+');
        // Le BOM par `fwrite` et non par `fprintf` : le second traite son
        // argument comme un FORMAT. Les trois octets du BOM n'en contiennent
        // aucun de special, donc le legacy s'en sort — par chance, pas par
        // construction.
        fwrite($flux, "\xEF\xBB\xBF");

        $ligne = static function (array $cellules) use ($flux): void {
            fputcsv($flux, $cellules, ',', '"', '\\');
        };
        $section = static function (string $titre) use ($ligne): void {
            $ligne([]);
            $ligne(['=== ' . $titre . ' ===']);
        };

        $ligne([__('conformite.title') . ' - ' . config('app.name') . ' - ' . $r['date']]);

        $section(__('conformite.csv_section_resume'));
        $ligne([__('conformite.servers'), $r['nbServeurs'], __('conformite.online'), $r['nbEnLigne']]);
        $ligne([__('conformite.csv_comptes_actifs'), $r['nbComptesActifs'],
                __('conformite.2fa_active'), $r['nbAvec2fa']]);
        $ligne([__('conformite.old_ssh_keys'), $r['nbCles90j']]);
        $ligne([__('conformite.posture_avg'), $r['postureMoyenne'] . '/100',
                __('conformite.th_grade'), $r['noteMoyenne']]);

        $section(__('conformite.csv_section_posture'));
        $ligne([__('conformite.th_server'), __('conformite.th_ip'), __('conformite.th_score'),
                __('conformite.th_grade'), __('conformite.th_gaps')]);
        foreach ($r['posture'] as $p) {
            $ligne([$p['name'], $p['ip'], $p['score'] . '/100', $p['grade'], $p['reasons']]);
        }

        $section(__('conformite.csv_section_serveurs'));
        $ligne([__('conformite.th_server'), __('conformite.th_ip'), __('conformite.th_statut'),
                __('conformite.th_environnement'), __('conformite.th_total'),
                __('conformite.th_critical'), __('conformite.th_high'),
                __('conformite.th_last_scan'), __('conformite.th_derniere_maj')]);
        foreach ($r['serveurs'] as $s) {
            $ligne([$s->name, $s->ip, $s->online_status ?? '', $s->environment ?? '',
                    (int) ($s->cve_count ?? 0), (int) ($s->critical_count ?? 0),
                    (int) ($s->high_count ?? 0), $s->last_scan ?? '', $s->last_checked ?? '']);
        }

        // TOUS les comptes, actifs ou non — c'est ce que fait le legacy.
        $section(__('conformite.csv_section_comptes'));
        $ligne([__('conformite.th_user'), __('conformite.th_role'), __('conformite.th_actif'),
                __('conformite.th_2fa'), __('conformite.th_ssh_key'),
                __('conformite.csv_age_cle'), __('conformite.th_last_pwd')]);
        $oui = __('conformite.oui');
        $non = __('conformite.non');
        foreach ($r['comptes'] as $c) {
            $ageCle = ($c->ssh_key && $c->ssh_key_updated_at)
                ? (int) ((time() - strtotime((string) $c->ssh_key_updated_at)) / 86400)
                : '';
            $ligne([$c->name, $c->role_name, $c->active ? $oui : $non,
                    ! empty($c->totp_secret) ? $oui : $non, $c->ssh_key ? $oui : $non,
                    $ageCle, $c->password_updated_at ?? '']);
        }

        $ligne([]);
        $ligne(['SHA-256', $r['empreinte']]);

        rewind($flux);
        $contenu = stream_get_contents($flux);
        fclose($flux);

        return $contenu;
    }
}
