<?php
/**
 * api/openapi.php - Sert le fichier openapi.yaml avec authentification.
 * Patch A01 : aligne sur api/docs.php (superadmin uniquement). La spec OpenAPI
 * brute revele toutes les routes/parametres -> meme niveau d'acces que l'UI Swagger.
 */
require_once __DIR__ . '/../auth/verify.php';
checkAuth([ROLE_SUPERADMIN]);

header('Content-Type: application/x-yaml');
readfile(__DIR__ . '/openapi.yaml');
