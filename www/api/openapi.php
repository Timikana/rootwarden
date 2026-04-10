<?php
/**
 * api/openapi.php — Sert le fichier openapi.yaml avec authentification.
 * Accessible uniquement aux admins et superadmins.
 */
require_once __DIR__ . '/../auth/verify.php';
checkAuth([2, 3]);

header('Content-Type: application/x-yaml');
readfile(__DIR__ . '/openapi.yaml');
