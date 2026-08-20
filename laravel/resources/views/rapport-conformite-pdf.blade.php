{{--
    Le rapport de conformite, mis en page pour le PDF (sous-lot S2b).

    Vue SEPAREE de `rapport-conformite.blade.php`, et non un `@media print` de
    celle-ci : le gabarit du portail porte une barre laterale, un en-tete collant
    et des jetons de theme dont dompdf ne sait rien. Le legacy fait le meme choix
    — il monte un HTML dedie plutot que de reutiliser sa page.

    CSS EN LIGNE et rien d'autre : dompdf ne charge aucune feuille externe, et
    `isRemoteEnabled` est a false. Les couleurs sont ecrites en dur ici, pas en
    jetons `--rw-*` : un PDF n'a pas de theme sombre.
--}}
<!DOCTYPE html>
<html lang="{{ app()->getLocale() }}">
<head>
    <meta charset="UTF-8">
    <style>
        body  { font-family: 'DejaVu Sans', sans-serif; font-size: 10px; color: #1f2937; margin: 18px; }
        h1    { font-size: 18px; color: #1e3a8a; margin: 0 0 2px; }
        h2    { font-size: 12px; color: #374151; margin: 14px 0 6px;
                border-bottom: 1px solid #e5e7eb; padding-bottom: 3px; }
        .meta { font-size: 9px; color: #6b7280; margin: 0 0 10px; }
        table { width: 100%; border-collapse: collapse; margin: 4px 0 0; font-size: 9px; }
        thead { display: table-header-group; }
        th    { background: #f3f4f6; text-align: left; padding: 3px 5px;
                border: 1px solid #e5e7eb; font-weight: bold; }
        td    { padding: 3px 5px; border: 1px solid #e5e7eb; }
        .tuiles      { width: 100%; margin: 4px 0 0; }
        .tuile       { display: inline-block; width: 15%; padding: 5px; margin: 2px 0.4%;
                       border: 1px solid #e5e7eb; text-align: center; vertical-align: top; }
        .tuile b     { display: block; font-size: 14px; }
        .tuile span  { font-size: 8px; color: #6b7280; }
        .alerte { color: #b91c1c; } .ok { color: #15803d; } .neutre { color: #1d4ed8; }
        .pied   { margin-top: 16px; padding-top: 6px; border-top: 1px solid #e5e7eb;
                  font-size: 8px; color: #6b7280; }
        .empreinte { font-family: 'DejaVu Sans Mono', monospace; word-break: break-all; }
    </style>
</head>
<body>

<h1>{{ $appName }} — {{ __('conformite.title') }}</h1>
<p class="meta">
    {{ __('conformite.generated_by') }} {{ $date }}@if ($genereePar !== '') — {{ $genereePar }}@endif
</p>

<h2>{{ __('conformite.section_summary') }}</h2>
<div class="tuiles">
    <div class="tuile"><b class="neutre">{{ $nbServeurs }}</b>
        <span>{{ __('conformite.servers') }} ({{ $nbEnLigne }} {{ __('conformite.online') }})</span></div>
    <div class="tuile"><b class="{{ $nbAvec2fa < $nbComptesActifs ? 'alerte' : 'ok' }}">{{ $nbAvec2fa }}/{{ $nbComptesActifs }}</b>
        <span>{{ __('conformite.2fa_active') }}</span></div>
    <div class="tuile"><b class="{{ $nbCles90j > 0 ? 'alerte' : 'ok' }}">{{ $nbCles90j }}</b>
        <span>{{ __('conformite.old_ssh_keys') }}</span></div>
    <div class="tuile"><b class="{{ $remStats['overdue'] > 0 ? 'alerte' : 'ok' }}">{{ $remStats['overdue'] }}</b>
        <span>{{ __('conformite.overdue_deadlines') }}</span></div>
    <div class="tuile"><b class="{{ $postureMoyenne >= 75 ? 'ok' : ($postureMoyenne >= 60 ? 'neutre' : 'alerte') }}">{{ $postureMoyenne }}/100 ({{ $noteMoyenne }})</b>
        <span>{{ __('conformite.posture_avg') }}</span></div>
    <div class="tuile"><b class="neutre">{{ $nbAvecAgent }}/{{ $nbServeurs }}</b>
        <span>{{ __('conformite.supervision_coverage') }}</span></div>
</div>

<h2>{{ __('conformite.section_posture') }}</h2>
<table>
    <thead>
        <tr>
        <th>{{ __('conformite.th_server') }}</th><th>{{ __('conformite.th_ip') }}</th>
        <th>{{ __('conformite.th_score') }}</th><th>{{ __('conformite.th_grade') }}</th>
        <th>{{ __('conformite.th_gaps') }}</th>
        </tr>
    </thead>
    <tbody>
    @forelse ($posture as $p)
        <tr>
            <td>{{ $p['name'] }}</td><td>{{ $p['ip'] }}</td>
            <td>{{ $p['score'] }}/100</td>
            <td class="{{ in_array($p['grade'], ['D', 'F'], true) ? 'alerte' : ($p['grade'] === 'A' ? 'ok' : '') }}"><b>{{ $p['grade'] }}</b></td>
            <td>{{ $p['reasons'] }}</td>
        </tr>
    @empty
        <tr><td colspan="5">{{ __('conformite.posture_empty') }}</td></tr>
    @endforelse
    </tbody>
</table>

<h2>{{ __('conformite.section_cve') }}</h2>
<table>
    <thead>
        <tr>
        <th>{{ __('conformite.th_server') }}</th><th>{{ __('conformite.th_ip') }}</th>
        <th>{{ __('conformite.th_statut') }}</th><th>{{ __('conformite.th_environnement') }}</th>
        <th>{{ __('conformite.th_total') }}</th><th>{{ __('conformite.th_critical') }}</th>
        <th>{{ __('conformite.th_high') }}</th><th>{{ __('conformite.th_last_scan') }}</th>
        </tr>
    </thead>
    <tbody>
    @foreach ($serveurs as $s)
        <tr>
            <td>{{ $s->name }}</td><td>{{ $s->ip }}</td>
            <td>{{ $s->online_status ?? '—' }}</td><td>{{ $s->environment ?? '—' }}</td>
            <td>{{ (int) ($s->cve_count ?? 0) }}</td>
            <td class="{{ (int) ($s->critical_count ?? 0) > 0 ? 'alerte' : '' }}">{{ (int) ($s->critical_count ?? 0) }}</td>
            <td>{{ (int) ($s->high_count ?? 0) }}</td>
            <td>{{ $s->last_scan ? date('d/m/Y H:i', strtotime((string) $s->last_scan)) : __('conformite.never') }}</td>
        </tr>
    @endforeach
    </tbody>
</table>

{{-- TOUS les comptes, actifs ou non — comme le PDF et le CSV du legacy. La page
     HTML, elle, saute les inactifs : deux perimetres, repris tels quels (E-41). --}}
<h2>{{ __('conformite.section_auth') }}</h2>
<table>
    <thead>
        <tr>
        <th>{{ __('conformite.th_user') }}</th><th>{{ __('conformite.th_role') }}</th>
        <th>{{ __('conformite.th_actif') }}</th><th>{{ __('conformite.th_2fa') }}</th>
        <th>{{ __('conformite.th_ssh_key') }}</th><th>{{ __('conformite.csv_age_cle') }}</th>
        </tr>
    </thead>
    <tbody>
    @foreach ($comptes as $c)
        @php($ageCle = ($c->ssh_key && $c->ssh_key_updated_at)
            ? (int) ((time() - strtotime((string) $c->ssh_key_updated_at)) / 86400) : null)
        <tr>
            <td>{{ $c->name }}</td><td>{{ $c->role_name }}</td>
            <td>{{ $c->active ? __('conformite.oui') : __('conformite.non') }}</td>
            <td class="{{ empty($c->totp_secret) ? 'alerte' : 'ok' }}">{{ ! empty($c->totp_secret) ? __('conformite.oui') : __('conformite.non') }}</td>
            <td>{{ $c->ssh_key ? __('conformite.oui') : __('conformite.non') }}</td>
            <td class="{{ $ageCle !== null && $ageCle > 90 ? 'alerte' : '' }}">{{ $ageCle !== null ? $ageCle : '—' }}</td>
        </tr>
    @endforeach
    </tbody>
</table>

@if ($auditSsh !== [])
    <h2>{{ __('conformite.section_ssh_audit') }}</h2>
    <table>
        <thead>
            <tr>
            <th>{{ __('conformite.th_server') }}</th><th>{{ __('conformite.th_score') }}</th>
            <th>{{ __('conformite.th_grade') }}</th><th>{{ __('conformite.th_critical') }}</th>
            <th>{{ __('conformite.th_high') }}</th><th>{{ __('conformite.th_date') }}</th>
            </tr>
        </thead>
        <tbody>
        @foreach ($auditSsh as $a)
            <tr>
                <td>{{ $a->name }} <span style="color:#9ca3af">{{ $a->ip }}</span></td>
                <td>{{ $a->score }}</td>
                <td class="{{ in_array($a->grade, ['D', 'F'], true) ? 'alerte' : ($a->grade === 'A' ? 'ok' : '') }}"><b>{{ $a->grade }}</b></td>
                <td>{{ (int) ($a->critical_count ?? 0) }}</td>
                <td>{{ (int) ($a->high_count ?? 0) }}</td>
                <td>{{ $a->audited_at ? date('d/m/Y H:i', strtotime((string) $a->audited_at)) : '—' }}</td>
            </tr>
        @endforeach
        </tbody>
    </table>
@endif

@if ($parefeu !== [])
    <h2>{{ __('conformite.section_firewall') }}</h2>
    <table>
        <thead>
            <tr>
            <th>{{ __('conformite.th_date') }}</th><th>{{ __('conformite.th_server') }}</th>
            <th>{{ __('conformite.by') }}</th>
            </tr>
        </thead>
        <tbody>
        @foreach ($parefeu as $h)
            <tr>
                <td>{{ date('d/m/Y H:i', strtotime((string) $h->created_at)) }}</td>
                <td>{{ $h->name }}</td><td>{{ $h->changed_by ?? '—' }}</td>
            </tr>
        @endforeach
        </tbody>
    </table>
@endif

@if ($agentsParMachine !== [])
    <h2>{{ __('conformite.section_supervision') }}</h2>
    <table>
        <thead>
            <tr><th>{{ __('conformite.th_server') }}</th><th>{{ __('conformite.th_agents') }}</th></tr>
        </thead>
        <tbody>
        @foreach ($agentsParMachine as $info)
            <tr>
                <td>{{ $info['nom'] }} <span style="color:#9ca3af">{{ $info['ip'] }}</span></td>
                <td>
                    @foreach ($info['agents'] as $ag)
                        {{ ucfirst((string) $ag->platform) }} {{ $ag->agent_version }}
                        @if (! $ag->config_deployed)
                            ({{ __('conformite.sans_config') }})
                        @endif
                        @if (! $loop->last) · @endif
                    @endforeach
                </td>
            </tr>
        @endforeach
        </tbody>
    </table>
@endif

<div class="pied">
    {{ __('conformite.footer_generated') }} {{ $date }} — {{ $appName }}<br>
    {{ __('conformite.empreinte') }} : <span class="empreinte">{{ $empreinte }}</span>
</div>

</body>
</html>
