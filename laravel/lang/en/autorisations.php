<?php

/**
 * What the gateway authorizes — English.
 *
 * Strict parity with lang/fr/autorisations.php: same key set, same commit.
 */
return [

    'title' => 'What the gateway authorizes',
    'desc'  => "This page is DERIVED from the gateway's code, on every render. It copies no description file: it reads the lists that decide, here and now.",

    // ── WHAT THE PAGE IS NOT ─────────────────────────────────────────────
    'pas_reference_titre' => 'This is not an API reference',
    'pas_reference_texte' => "This page describes neither parameters, nor request bodies, nor responses. It describes AUTHORIZATIONS: what the gateway lets through, what it reserves to administrators, what it relays chunk by chunk. For call contracts there is no up-to-date source in this portal — and saying so is better than pointing at one that would lie.",

    // ── THE THREE LAYERS ─────────────────────────────────────────────────
    'couches_titre' => 'An authorization crosses three layers, and this page describes only one',
    'couche_1' => "The PAGE's guard: the role and permission required by the portal route. Visible in the portal's routes.",
    'couche_2' => 'The GATEWAY: whitelist, administration-only, re-authentication, streamed relay. This is that layer, and it is derived below.',
    'couche_3' => "The backend's DECORATORS: API key, role, permission, machine access. This page cannot see them — the portal does not mount the backend's code — and therefore does not assert them.",
    'couches_aide' => "These three layers have already diverged, and a screen that mixed them would rebuild the very defect it documents. Every statement on this page therefore names its own layer.",

    // ── WHY THIS PAGE REPLACES A FILE ────────────────────────────────────
    'remplace_titre' => 'What this page replaces, and why it does not port it',
    'remplace_texte' => 'The legacy portal served a static 91 KB OpenAPI description, dated 20 August 2026, that nothing regenerated. Measured on 28 August: 146 declared paths against 203 real routes — 139 correct, 7 non-existent, 64 routes left unmentioned.',
    'remplace_detail' => 'The 7 non-existent ones have a single cause: the SSH-audit module is declared there under TWO separators. Ten routes with the hyphen, served; seven with the underscore, returning 404. The same route appears twice under two spellings, one of them false — and nothing in the document says which.',
    'remplace_raison' => 'Porting that file would not have been faithfulness but the copying of a cache: a faithful port reproduces contradictory behaviour and names it, whereas a frozen artefact is not a behaviour. Twenty-six routes changed guard on 27 August alone — no frozen document can keep that pace.',
    'remplace_silence' => "The 64 routes the old description left unmentioned are not documented here either: this page describes the gateway, not the route catalogue. The difference is that it SAYS so. A document that omits what it does not know is more misleading than a dated one, because a reader cannot tell that something is missing.",

    // ── THE WHITELIST ────────────────────────────────────────────────────
    'blanche_titre' => 'Whitelist: what the gateway forwards',
    'blanche_aide' => 'A path absent from this list is refused before it reaches the backend. The comparison is made by SEGMENT: the shape of the last character decides the scope.',
    'th_motif' => 'Entry',
    'th_portee' => 'Scope',
    'portee_espace' => 'namespace',
    'portee_route' => 'route',
    'portee_espace_aide' => 'Ends with « / », « _ » or « - »: every path starting with that string is forwarded.',
    'portee_route_aide' => 'The exact path, or a sub-path separated by « / ».',

    // ── ADMINISTRATION-ONLY ──────────────────────────────────────────────
    'admin_titre' => 'Reserved to administrators',
    'admin_aide' => 'These paths require role 2 at least, at the gateway. This is defence in depth: the backend applies its own guards, and this page does not describe them.',
    'admin_couverte' => 'narrows a whitelist entry',
    'admin_orpheline' => '⚠ matches no whitelist entry: narrows nothing',
    'admin_aucune_orpheline' => 'None of these entries is without object: each one narrows a path the whitelist lets through. This number is computed, not assumed.',

    // ── STREAMED RELAY ───────────────────────────────────────────────────
    'flux_titre' => 'Relayed chunk by chunk',
    'flux_aide' => 'These paths hold their response open while the command runs. The HTTP status leaves BEFORE the work begins: it therefore says nothing about the result, and a screen taking it for a verdict would announce a success that never happened.',
    'flux_hors_liste' => '⚠ this path is authorized by no whitelist entry',
    'flux_par_espace' => 'Four of these paths are not whitelist entries themselves: they pass through a namespace. That is why this list is enumerated from its own source rather than deduced from the whitelist.',

    // ── RE-AUTHENTICATION ────────────────────────────────────────────────
    'reauth_titre' => 'Requires a one-off re-authentication',
    'reauth_aide' => 'These are EXPRESSIONS, not paths: each applies to a finite set of concrete paths and to no other. Rendering them as a list of paths would invent a precision the source does not have.',
    'reauth_aucune' => 'No re-authentication pattern is configured.',

    // ── COUNTERS ─────────────────────────────────────────────────────────
    'compte_blanche' => 'whitelist entries',
    'compte_espaces' => 'of which namespaces',
    'compte_admin' => 'reserved to administrators',
    'compte_flux' => 'relayed as streams',
    'compte_reauth' => 're-authentication patterns',
];
