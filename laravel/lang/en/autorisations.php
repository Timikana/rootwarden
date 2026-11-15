<?php

/**
 * What the gateway authorizes — English.
 *
 * Strict parity with lang/fr/autorisations.php: same key set, same commit.
 * Writing rules: docs/REDACTION-INTERFACE.md.
 */
return [

    'title' => 'What the gateway authorizes',
    'desc'  => "The rules the portal gateway applies to calls to the backend, read from its code on every render.",

    // ── WHAT THIS PAGE COVERS (folded) ───────────────────────────────────
    'couches_titre' => 'What this page covers',
    'couche_1' => 'The guard on each portal page (role and permission): not described here.',
    'couche_2' => 'The gateway: whitelist, administrator reserve, streaming relay, re-authentication. This is what this page describes.',
    'couche_3' => 'The backend\'s own checks: not visible from the portal, so not described.',
    'pas_reference_texte' => 'This is not an API reference: no parameters, no responses, no complete list of routes.',

    // ── WHITELIST ────────────────────────────────────────────────────────
    'blanche_titre' => 'Whitelist: what the gateway forwards',
    'blanche_aide' => 'Any path missing from this list is refused.',
    'th_motif' => 'Entry',
    'th_portee' => 'Scope',
    'portee_espace' => 'namespace',
    'portee_route' => 'route',
    'portee_espace_aide' => 'Ends with « / », « _ » or « - »: every path starting with that string is forwarded.',
    'portee_route_aide' => 'The exact path, or a sub-path separated by « / ».',

    // ── ADMINISTRATOR RESERVE ────────────────────────────────────────────
    'admin_titre' => 'Reserved to administrators',
    'admin_aide' => 'These paths require at least the Administrator role.',
    'admin_couverte' => 'narrows a whitelist entry',
    'admin_orpheline' => '⚠ matches no whitelist entry: no effect',
    'admin_aucune_orpheline' => 'Every entry narrows a path of the whitelist.',

    // ── STREAMING RELAY ──────────────────────────────────────────────────
    'flux_titre' => 'Relayed chunk by chunk',
    'flux_aide' => 'The response arrives while the command runs: its HTTP status says nothing about the outcome.',
    'flux_hors_liste' => '⚠ this path is authorized by no whitelist entry',

    // ── RE-AUTHENTICATION ────────────────────────────────────────────────
    'reauth_titre' => 'Requires a one-off re-authentication',
    'reauth_aide' => 'Paths matching these expressions ask for a fresh TOTP code right before the action.',
    'reauth_aucune' => 'No re-authentication pattern is configured.',

    // ── COUNTERS ─────────────────────────────────────────────────────────
    'compte_blanche' => 'whitelist entries',
    'compte_espaces' => 'of which namespaces',
    'compte_admin' => 'reserved to administrators',
    'compte_flux' => 'relayed as streams',
    'compte_reauth' => 're-authentication patterns',
];
