<?php
/**
 * lang.php — Systeme d'internationalisation (i18n) RootWarden
 *
 * Detecte la langue active, charge le fichier de traduction correspondant,
 * et fournit les fonctions t() et getLang() a toutes les pages.
 *
 * Langues supportees : fr (defaut), en
 * Stockage : $_SESSION['lang'] + cookie 'lang' (365 jours)
 */

// Changement de langue via GET ?lang=xx
if (isset($_GET['lang']) && in_array($_GET['lang'], ['fr', 'en'], true)) {
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['lang'] = $_GET['lang'];
    }
    setcookie('lang', $_GET['lang'], time() + 86400 * 365, '/', '', true, true);
}

/**
 * Retourne la langue active (fr ou en).
 * Priorite : session > cookie > defaut (fr)
 */
function getLang(): string {
    if (session_status() === PHP_SESSION_ACTIVE && isset($_SESSION['lang'])) {
        return $_SESSION['lang'];
    }
    return $_COOKIE['lang'] ?? 'fr';
}

// Charge le fichier de traduction
$_LANG_DATA = [];

function _loadLang(): void {
    global $_LANG_DATA;
    if (!empty($_LANG_DATA)) return;
    $lang = getLang();
    $file = __DIR__ . '/../lang/' . $lang . '.php';
    if (file_exists($file)) {
        $_LANG_DATA = require $file;
    } else {
        // Fallback FR
        $_LANG_DATA = require __DIR__ . '/../lang/fr.php';
    }
}

/**
 * Retourne la traduction pour une cle donnee.
 *
 * @param string $key    Cle de traduction (ex: 'nav.dashboard')
 * @param array  $params Parametres dynamiques (ex: ['name' => 'Jean'])
 *                       Remplace :name dans la chaine
 * @return string Traduction ou la cle elle-meme si non trouvee
 */
function t(string $key, array $params = []): string {
    global $_LANG_DATA;
    _loadLang();
    $str = $_LANG_DATA[$key] ?? $key;
    foreach ($params as $k => $v) {
        $str = str_replace(':' . $k, (string)$v, $str);
    }
    return $str;
}

/**
 * Retourne un sous-ensemble de traductions pour l'export JS.
 * Filtre par prefixe (ex: 'js.' retourne toutes les cles commencant par 'js.')
 *
 * @param string $prefix Prefixe des cles a exporter
 * @return array Tableau associatif cle => valeur
 */
function getJsTranslations(string $prefix = 'js.'): array {
    global $_LANG_DATA;
    _loadLang();
    $result = [];
    foreach ($_LANG_DATA as $k => $v) {
        if (str_starts_with($k, $prefix)) {
            $result[$k] = $v;
        }
    }
    return $result;
}
