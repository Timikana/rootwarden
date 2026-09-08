<?php
/**
 * feature_flags.php - Helper centralise pour les toggles ON/OFF de modules.
 *
 * Lit les variables d'environnement srv-docker.env (chargees dans le conteneur
 * PHP via env_file). Defaults a true pour ne pas casser les deploiements
 * existants apres ajout d'un nouveau flag.
 *
 * Usage :
 *   require_once __DIR__ . '/feature_flags.php';
 *   if (feature_enabled('wazuh')) { ... }
 *
 * Backend Python : voir Config.WAZUH_ENABLED dans backend/config.py.
 * Quand OFF, le blueprint Wazuh n'est pas enregistre (404 natif sur /wazuh/*).
 */

if (!function_exists('feature_enabled')) {
    /**
     * Verifie si un module est actif via la variable d'environnement <NAME>_ENABLED.
     *
     * @param string $name nom du module (ex: 'wazuh', 'graylog')
     * @return bool true si ENABLED=true (ou variable absente, default ON)
     */
    function feature_enabled(string $name): bool
    {
        $envKey = strtoupper($name) . '_ENABLED';
        $val = getenv($envKey);
        if ($val === false || $val === '') return true;  // default ON
        return strtolower($val) === 'true';
    }
}
