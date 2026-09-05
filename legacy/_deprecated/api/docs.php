<?php
/**
 * api/docs.php - Swagger UI pour la documentation de l'API RootWarden
 *
 * Accessible uniquement aux admins et superadmins.
 * Charge la spec OpenAPI depuis /api/openapi.php.
 */
require_once __DIR__ . '/../auth/verify.php';
checkAuth([ROLE_SUPERADMIN]);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Docs - RootWarden</title>
    <link rel="stylesheet" href="/api/swagger/swagger-ui.css">
    <style>
        body { margin: 0; background: #fafafa; }
        #swagger-ui .topbar { display: none; }
        .swagger-ui .info .title { font-size: 1.5rem; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="/api/swagger/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '/api/openapi.php',
            dom_id: '#swagger-ui',
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
            layout: 'BaseLayout',
            defaultModelsExpandDepth: 0,
            docExpansion: 'list',
            filter: true,
            tryItOutEnabled: false,
        });
    </script>
</body>
</html>
