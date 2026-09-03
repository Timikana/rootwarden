<?php
/**
 * lang/en.php - English translations (modular loader)
 *
 * Loads all translation files from lang/en/*.php
 * and returns a merged associative array.
 *
 * Structure: one file per module (login, nav, ssh, admin, etc.)
 * Each file returns an array ['key' => 'value', ...]
 */
$_lang = [];
foreach (glob(__DIR__ . '/en/*.php') as $_f) {
    $_lang = array_merge($_lang, require $_f);
}
return $_lang;
