<?php
/**
 * lang/fr.php — Traductions francaises (loader modulaire)
 *
 * Charge tous les fichiers de traduction depuis lang/fr/*.php
 * et retourne un tableau associatif fusionne.
 *
 * Structure : un fichier par module (login, nav, ssh, admin, etc.)
 * Chaque fichier retourne un array ['cle' => 'valeur', ...]
 */
$_lang = [];
foreach (glob(__DIR__ . '/fr/*.php') as $_f) {
    $_lang = array_merge($_lang, require $_f);
}
return $_lang;
