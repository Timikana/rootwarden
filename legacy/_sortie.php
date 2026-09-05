<?php
/*
 * LA PAGE 404 DE L'ANCIEN PORTAIL — « ce que vous cherchez a demenage ».
 *
 * POURQUOI ELLE EXISTE
 * --------------------
 * Mesure du 2026-09-05 : une URL archivee rendait la page 404 NUE d'Apache.
 *
 *     /_deprecated/terms.php   404   236 o   0 lien   0 mention du portail
 *     /index.php               404   236 o   0 lien   0 mention du portail
 *     TEMOIN /auth/login.php   200  4864 o   6 liens
 *
 * Cinquante et un fichiers ont ete archives dans la journee. Un utilisateur
 * qui suit un signet recevait une page vide qui ne nommait pas le portail, ne
 * le liait pas, et ne disait pas que quelque chose avait bouge.
 *
 * ⚠ LE CODE 404 EST CONSERVE, ET C'EST LE POINT QUI DECIDE.
 * Soixante-douze suites appellent `constateArchivage`, qui asserte le STATUT.
 * Une redirection vers le portail aurait casse ce contrat ET masque les vrais
 * 404 — c'est la solution qui vient d'abord a l'esprit, et c'est la mauvaise.
 * On ne change que le CORPS.
 *
 * ⚠ ET ELLE NE DOIT RIEN POUVOIR CASSER.
 * Pas de `require`, pas de base, pas de session, pas de catalogue de langue :
 * une page d'erreur qui leve une erreur ne laisse plus AUCUNE sortie. Les deux
 * langues sont rendues cote a cote plutot que choisies — c'est deux lignes de
 * texte, et ca supprime toute logique de detection.
 *
 * `LARAVEL_URL` est la MEME source que `menu.php` (huit occurrences) : le
 * portail n'a pas deux adresses selon la page qui le nomme.
 */
$portail = rtrim(getenv('LARAVEL_URL') ?: 'http://localhost:8444', '/');
$portail = htmlspecialchars($portail, ENT_QUOTES, 'UTF-8');
$nom = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $nom ?> — page deplacee</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:flex; align-items:center;
         justify-content:center; background:#f4f6f9; color:#16202e;
         font:15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
  .c { max-width:38rem; padding:32px; text-align:center; }
  h1 { font-size:20px; margin:0 0 6px; }
  p  { margin:0 0 14px; }
  .d { color:#5b6b80; font-size:13px; }
  a.b { display:inline-block; margin-top:8px; padding:10px 22px; border-radius:10px;
        background:#1d4ed8; color:#fff; text-decoration:none; font-weight:600; }
  a.b:hover { background:#1741b6; }
  @media (prefers-color-scheme: dark) {
    body { background:#0f1722; color:#e8eef6; }
    .d { color:#9fb0c4; } a.b { background:#5b8cff; color:#0b1220; }
  }
</style>
</head>
<body>
<div class="c">
    <h1><?= $nom ?> a demenage</h1>
    <p>Cette page appartenait a l'ancienne interface. Elle n'est plus servie.</p>
    <p class="d">This page belonged to the previous interface and is no longer served.</p>
    <a class="b" href="<?= $portail ?>/">Ouvrir le portail &middot; Open the portal</a>
</div>
</body>
</html>
