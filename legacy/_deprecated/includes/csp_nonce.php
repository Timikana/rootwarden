<?php
/**
 * csp_nonce.php - Generation et exposition du nonce CSP par requete.
 *
 * Patch A05-NEW-04 (OWASP A05 Misconfiguration) :
 * Pour durcir CSP en retirant 'unsafe-inline' sur script-src/style-src,
 * il faut soit migrer TOUS les <script>inline</script> vers des fichiers
 * externes, soit utiliser des nonces. Ce helper genere un nonce par
 * requete et l'expose via csp_nonce() pour usage dans les templates.
 *
 * Migration progressive :
 *   1. Inclure ce fichier en TOP de chaque page (apres session_start).
 *   2. Inclure le nonce dans la CSP : "script-src 'self' 'nonce-XXX'".
 *   3. Sur chaque <script>inline</script>, ajouter nonce="<?= csp_nonce() ?>".
 *   4. Une fois tous les inline scripts marques, retirer 'unsafe-inline'.
 *
 * Etat actuel (corrige) : la CSP reellement emise (csp_header_value() ET le
 * template Apache php/apache-*.conf.tmpl) utilise 'unsafe-inline' SANS nonce.
 * Le nonce N'EST PAS encore inclus dans la CSP : ce helper est pret mais pas
 * cable. La CSP n'apporte donc PAS de barriere XSS sur script-src tant que la
 * migration (nonce sur chaque <script> inline + retrait de 'unsafe-inline')
 * n'est pas terminee et testee en conditions reelles. NE PAS supposer que la
 * CSP protege contre une injection de script -> cf. backlog securite.
 */

if (!function_exists('csp_nonce')) {
    /**
     * Retourne le nonce CSP courant (base64). Le genere et le stocke en
     * session au premier appel par requete.
     */
    function csp_nonce(): string {
        if (session_status() === PHP_SESSION_NONE) session_start();
        if (empty($_SESSION['_csp_nonce_req']) || ($_SESSION['_csp_nonce_ts'] ?? 0) < time() - 1) {
            $_SESSION['_csp_nonce_req'] = base64_encode(random_bytes(16));
            $_SESSION['_csp_nonce_ts'] = time();
        }
        return $_SESSION['_csp_nonce_req'];
    }

    /**
     * Retourne la chaine CSP complete (a passer dans le header).
     *
     * IMPORTANT : la version actuelle utilise 'unsafe-inline' sans nonce.
     * En CSP3 (Chrome moderne), si on declare un nonce dans script-src,
     * 'unsafe-inline' est AUTOMATIQUEMENT IGNORE pour les scripts inline
     * sans nonce -> tous les <script>inline</script> du repo sont casses
     * silencieusement (bridge i18n, tabs, htmx, etc.).
     *
     * Migration progressive : ajouter `nonce="<?= csp_nonce() ?>"` sur CHAQUE
     * <script> inline du repo, PUIS reactiver le nonce ici en retirant
     * 'unsafe-inline'. Tant que tous les inline ne sont pas migres, on
     * reste sur 'unsafe-inline' pure (comme avant le patch A05-NEW-04).
     */
    function csp_header_value(): string {
        return "default-src 'self'; "
             . "script-src 'self' 'unsafe-inline'; "
             . "style-src 'self' 'unsafe-inline'; "
             . "img-src 'self' data:; "
             . "font-src 'self'; "
             . "connect-src 'self'; "
             . "frame-ancestors 'none'; "
             . "base-uri 'self'; "
             . "form-action 'self'";
    }
}
