@extends('layouts.portail', ['titre' => __('conformite.title')])

@section('corps')
    {{-- Titre a gauche, actions a DROITE. Les deux exports restent servis par
         l'ancien portail : ils appartiennent aux sous-lots S2c (CSV) et S2b
         (PDF). Ils portent donc le MEME marqueur que le menu — un lien qui
         change de portail sans le dire trahit la personne qui clique. --}}
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('conformite.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('conformite.desc') }}</p>
            <p class="rw-aide">
                {{ __('conformite.generated_by') }} {{ $date }}@if ($genereePar !== '') — {{ $genereePar }}@endif
            </p>
        </div>
        <div class="rw-entete-page__actions">
            <button class="rw-bouton" type="button" data-rw="imprimer"
                    onclick="window.print()">{{ __('conformite.btn_print') }}</button>
            {{-- LES DEUX EXPORTS SONT PORTES — CSV en S2c, PDF en S2b : liens
                 internes, sans marqueur « ancien portail » et sans nouvel
                 onglet. Plus aucun aller-retour depuis ce rapport. --}}
            <a class="rw-bouton rw-bouton--discret" data-rw="export-csv"
               href="{{ route('rapport-conformite.csv') }}">{{ __('conformite.btn_csv') }}</a>
            <a class="rw-bouton rw-bouton--discret" data-rw="export-pdf"
               href="{{ route('rapport-conformite.pdf') }}">{{ __('conformite.btn_pdf') }}</a>
        </div>
    </div>

    {{-- Resume executif : six indicateurs. `rw-grille--compacte` les tient deux
         par deux a 390 px au lieu de repousser le rapport sous six ecrans. --}}
    <section class="rw-section">
        <div class="rw-section__entete">
            <h2 class="rw-sous-titre-fort">{{ __('conformite.section_summary') }}</h2>
        </div>
        <div class="rw-grille rw-grille--compacte">
            <div class="rw-tuile">
                <span class="rw-tuile__titre">{{ __('conformite.servers') }}</span>
                <span class="rw-tuile__valeur" data-rw="tuile-valeur">{{ $nbServeurs }}</span>
                <p class="rw-tuile__texte">{{ $nbEnLigne }} {{ __('conformite.online') }} — {{ __('conformite.tuile_serveurs_texte') }}</p>
            </div>
            <div class="rw-tuile">
                <span class="rw-tuile__titre">{{ __('conformite.2fa_active') }}</span>
                <span class="rw-tuile__valeur {{ $nbAvec2fa < $nbComptesActifs ? 'rw-tuile__valeur--alerte' : 'rw-tuile__valeur--ok' }}"
                      data-rw="tuile-valeur">{{ $nbAvec2fa }} / {{ $nbComptesActifs }}</span>
                <p class="rw-tuile__texte">{{ __('conformite.tuile_2fa_texte') }}</p>
            </div>
            <div class="rw-tuile">
                <span class="rw-tuile__titre">{{ __('conformite.old_ssh_keys') }}</span>
                <span class="rw-tuile__valeur {{ $nbCles90j > 0 ? 'rw-tuile__valeur--alerte' : 'rw-tuile__valeur--ok' }}"
                      data-rw="tuile-valeur">{{ $nbCles90j }}</span>
                <p class="rw-tuile__texte">{{ __('conformite.tuile_cles_texte') }}</p>
            </div>
            <div class="rw-tuile">
                <span class="rw-tuile__titre">{{ __('conformite.overdue_deadlines') }}</span>
                <span class="rw-tuile__valeur {{ $remStats['overdue'] > 0 ? 'rw-tuile__valeur--alerte' : 'rw-tuile__valeur--ok' }}"
                      data-rw="tuile-valeur">{{ $remStats['overdue'] }}</span>
                <p class="rw-tuile__texte">{{ __('conformite.tuile_echeances_texte') }}</p>
            </div>
            <div class="rw-tuile">
                <span class="rw-tuile__titre">{{ __('conformite.ssh_audit_avg') }}</span>
                {{-- « Jamais evalue » plutot qu'un tiret : un « - » se lit aussi
                     bien « zero » que « erreur ». --}}
                <span class="rw-tuile__valeur" data-rw="tuile-valeur">{{ $scoreSshMoyen !== null ? $scoreSshMoyen . '/100' : __('conformite.never') }}</span>
                <p class="rw-tuile__texte">{{ __('conformite.tuile_ssh_texte') }}</p>
            </div>
            <div class="rw-tuile">
                <span class="rw-tuile__titre">{{ __('conformite.supervision_coverage') }}</span>
                <span class="rw-tuile__valeur" data-rw="tuile-valeur">{{ $nbAvecAgent }} / {{ $nbServeurs }}</span>
                <p class="rw-tuile__texte">{{ __('conformite.tuile_supervision_texte') }}</p>
            </div>
        </div>
    </section>

    {{-- Posture consolidee. Triee du plus bas au plus haut : ce qui va le plus
         mal se lit en premier, sans defiler. --}}
    <section class="rw-section">
        <div class="rw-section__entete">
            <h2 class="rw-sous-titre-fort">{{ __('conformite.section_posture') }}</h2>
            <span class="rw-aide">{{ __('conformite.posture_avg') }} :
                <strong>{{ $postureMoyenne }}/100 ({{ $noteMoyenne }})</strong></span>
        </div>
        <p class="rw-aide rw-prose">{{ __('conformite.posture_desc') }}</p>
        <div class="rw-tableau-cadre">
            <table class="rw-tableau">
                <thead>
                    <tr>
                        <th>{{ __('conformite.th_server') }}</th>
                        <th class="rw-colonne-secondaire">{{ __('conformite.th_ip') }}</th>
                        <th>{{ __('conformite.th_score') }}</th>
                        <th>{{ __('conformite.th_grade') }}</th>
                        <th>{{ __('conformite.th_gaps') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @forelse ($posture as $p)
                        <tr data-rw="posture-ligne">
                            {{-- `rw-tableau__fort` pose `white-space: nowrap` : le detail
                                 doit sortir de ce flux, d'ou le `<p>` et non un `<br>`. --}}
                            <td class="rw-tableau__fort">{{ $p['name'] }}
                                {{-- Sous 720 px la colonne « Ecarts » quitte le champ, et c'est
                                     elle qui dit quoi faire. Elle revient ici, sous le nom du
                                     serveur, avec le composant deja employe par la derive de
                                     config — une information qu'on n'atteint qu'en decouvrant le
                                     defilement horizontal n'est pas offerte. --}}
                                <p class="rw-detail-ecart rw-etroit-seul">{{ $p['reasons'] }}</p>
                            </td>
                            <td class="rw-tableau__discret rw-colonne-secondaire">{{ $p['ip'] }}</td>
                            <td>{{ $p['score'] }}/100</td>
                            <td><span class="rw-badge rw-badge--note {{ in_array($p['grade'], ['D', 'F'], true) ? 'rw-badge--alerte' : ($p['grade'] === 'A' ? 'rw-badge--ok' : 'rw-badge--attention') }}">{{ $p['grade'] }}</span></td>
                            <td class="rw-tableau__discret rw-colonne-secondaire">{{ $p['reasons'] }}</td>
                        </tr>
                    @empty
                        <tr><td colspan="5" class="rw-tableau__message">{{ __('conformite.posture_empty') }}</td></tr>
                    @endforelse
                </tbody>
            </table>
        </div>
    </section>

    {{-- Vulnerabilites CVE par serveur --}}
    <section class="rw-section">
        <div class="rw-section__entete">
            <h2 class="rw-sous-titre-fort">{{ __('conformite.section_cve') }}</h2>
        </div>
        <div class="rw-tableau-cadre">
            <table class="rw-tableau">
                <thead>
                    <tr>
                        <th>{{ __('conformite.th_server') }}</th>
                        <th class="rw-colonne-secondaire">{{ __('conformite.th_ip') }}</th>
                        <th>{{ __('conformite.th_critical') }}</th>
                        <th>{{ __('conformite.th_high') }}</th>
                        <th>{{ __('conformite.th_total') }}</th>
                        <th>{{ __('conformite.th_last_scan') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($serveurs as $s)
                        <tr>
                            <td class="rw-tableau__fort">{{ $s->name }}</td>
                            <td class="rw-tableau__discret rw-colonne-secondaire">{{ $s->ip }}</td>
                            <td>{{ (int) ($s->critical_count ?? 0) }}</td>
                            <td>{{ (int) ($s->high_count ?? 0) }}</td>
                            <td>{{ (int) ($s->cve_count ?? 0) }}</td>
                            <td class="rw-tableau__discret">{{ $s->last_scan ? date('d/m/Y H:i', strtotime((string) $s->last_scan)) : __('conformite.never') }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    </section>

    {{-- Remediation : la section n'apparait que s'il y a quelque chose a dire,
         comme dans le legacy. Un intitule sans rien dessous laisse croire qu'un
         contenu a disparu. --}}
    @if (array_sum($remStats) > 0)
        <section class="rw-section">
            <div class="rw-section__entete">
                <h2 class="rw-sous-titre-fort">{{ __('conformite.section_remediation') }}</h2>
            </div>
            <div class="rw-grille rw-grille--compacte">
                @foreach (['open', 'in_progress', 'resolved', 'accepted', 'wont_fix'] as $etat)
                    <div class="rw-tuile">
                        <span class="rw-tuile__titre">{{ __('conformite.rem_' . $etat) }}</span>
                        <span class="rw-tuile__valeur">{{ $remStats[$etat] }}</span>
                    </div>
                @endforeach
            </div>
        </section>
    @endif

    {{-- Authentification : les comptes ACTIFS seulement, comme le legacy. --}}
    <section class="rw-section">
        <div class="rw-section__entete">
            <h2 class="rw-sous-titre-fort">{{ __('conformite.section_auth') }}</h2>
        </div>
        <div class="rw-tableau-cadre">
            <table class="rw-tableau">
                <thead>
                    <tr>
                        <th>{{ __('conformite.th_user') }}</th>
                        <th>{{ __('conformite.th_role') }}</th>
                        <th>{{ __('conformite.th_2fa') }}</th>
                        <th>{{ __('conformite.th_ssh_key') }}</th>
                        <th>{{ __('conformite.th_key_age') }}</th>
                        <th>{{ __('conformite.th_last_pwd') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($comptesActifs as $c)
                        @php($ageCle = ($c->ssh_key && $c->ssh_key_updated_at)
                            ? (int) ((time() - strtotime((string) $c->ssh_key_updated_at)) / 86400)
                            : null)
                        <tr>
                            <td class="rw-tableau__fort">{{ $c->name }}</td>
                            <td class="rw-tableau__discret">{{ $c->role_name }}</td>
                            <td>{!! ! empty($c->totp_secret)
                                ? '<span class="rw-badge rw-badge--ok">&#10003;</span>'
                                : '<span class="rw-badge rw-badge--alerte">&#10007;</span>' !!}</td>
                            <td>{!! $c->ssh_key
                                ? '<span class="rw-badge rw-badge--ok">&#10003;</span>'
                                : '<span class="rw-tableau__discret">&mdash;</span>' !!}</td>
                            <td class="{{ $ageCle !== null && $ageCle > 90 ? 'rw-tableau__fort' : 'rw-tableau__discret' }}">{{ $ageCle !== null ? $ageCle . ' j' : '—' }}</td>
                            <td class="rw-tableau__discret">{{ $c->password_updated_at ? date('d/m/Y', strtotime((string) $c->password_updated_at)) : '—' }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    </section>

    @if ($parefeu !== [])
        <section class="rw-section">
            <div class="rw-section__entete">
                <h2 class="rw-sous-titre-fort">{{ __('conformite.section_firewall') }}</h2>
            </div>
            <div class="rw-tableau-cadre">
                <table class="rw-tableau">
                    <thead>
                        <tr>
                            <th>{{ __('conformite.th_date') }}</th>
                            <th>{{ __('conformite.th_server') }}</th>
                            <th>{{ __('conformite.by') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($parefeu as $h)
                            <tr>
                                <td class="rw-tableau__discret">{{ date('d/m/Y H:i', strtotime((string) $h->created_at)) }}</td>
                                <td class="rw-tableau__fort">{{ $h->name }}</td>
                                <td>{{ $h->changed_by ?? '—' }}</td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </section>
    @endif

    @if ($auditSsh !== [])
        <section class="rw-section">
            <div class="rw-section__entete">
                <h2 class="rw-sous-titre-fort">{{ __('conformite.section_ssh_audit') }}</h2>
            </div>
            <div class="rw-tableau-cadre">
                <table class="rw-tableau">
                    <thead>
                        <tr>
                            <th>{{ __('conformite.th_server') }}</th>
                            <th>{{ __('conformite.th_score') }}</th>
                            <th>{{ __('conformite.th_grade') }}</th>
                            <th>{{ __('conformite.th_critical') }}</th>
                            <th>{{ __('conformite.th_high') }}</th>
                            <th>{{ __('conformite.th_date') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($auditSsh as $a)
                            <tr>
                                <td class="rw-tableau__fort">{{ $a->name }}
                                    <span class="rw-tableau__discret">{{ $a->ip }}</span></td>
                                <td>{{ $a->score }}</td>
                                <td><span class="rw-badge rw-badge--note {{ in_array($a->grade, ['D', 'F'], true) ? 'rw-badge--alerte' : ($a->grade === 'A' ? 'rw-badge--ok' : 'rw-badge--attention') }}">{{ $a->grade }}</span></td>
                                <td>{{ (int) ($a->critical_count ?? 0) }}</td>
                                <td>{{ (int) ($a->high_count ?? 0) }}</td>
                                <td class="rw-tableau__discret">{{ $a->audited_at ? date('d/m/Y H:i', strtotime((string) $a->audited_at)) : '—' }}</td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </section>
    @endif

    @if ($agentsParMachine !== [])
        <section class="rw-section">
            <div class="rw-section__entete">
                <h2 class="rw-sous-titre-fort">{{ __('conformite.section_supervision') }}</h2>
            </div>
            <div class="rw-tableau-cadre">
                <table class="rw-tableau">
                    <thead>
                        <tr>
                            <th>{{ __('conformite.th_server') }}</th>
                            <th>{{ __('conformite.th_agents') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($agentsParMachine as $info)
                            <tr>
                                <td class="rw-tableau__fort">{{ $info['nom'] }}
                                    <span class="rw-tableau__discret">{{ $info['ip'] }}</span></td>
                                <td>
                                    @foreach ($info['agents'] as $ag)
                                        <span class="rw-badge">{{ ucfirst((string) $ag->platform) }} {{ $ag->agent_version }}@if (! $ag->config_deployed) — {{ __('conformite.sans_config') }}@endif</span>
                                    @endforeach
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </section>
    @endif

    <p class="rw-note">
        {{ __('conformite.footer_generated') }} {{ $date }}<br>
        {{ __('conformite.empreinte') }} :
        <span class="rw-code" data-rw="empreinte">{{ $empreinte }}</span>
    </p>
@endsection
