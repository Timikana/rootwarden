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
 * Etat actuel : 'unsafe-inline' conserve pour retrocompat. Le nonce est
 * inclus dans la CSP en parallele -> CSP3 navigateurs modernes ignorent
 * 'unsafe-inline' si nonce present (defense in depth deja active).
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
     * Retourne la chaine CSP complete (a passer dans le header) avec le
     * nonce courant. Inclut 'unsafe-inline' en parallele pour la
     * retrocompat (CSP3 navigateurs : ignore unsafe-inline si nonce present).
     */
    function csp_header_value(): string {
        $n = csp_nonce();
        return "default-src 'self'; "
             . "script-src 'self' 'nonce-{$n}' 'unsafe-inline'; "
             . "style-src 'self' 'nonce-{$n}' 'unsafe-inline'; "
             . "img-src 'self' data:; "
             . "font-src 'self'; "
             . "connect-src 'self'; "
             . "frame-ancestors 'none'; "
             . "base-uri 'self'; "
             . "form-action 'self'";
    }
}
