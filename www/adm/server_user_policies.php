<?php
/**
 * server_user_policies.php - DEPRECATED (v1.36.0).
 *
 * La gestion sudo et SFTP a ete separee en deux pages distinctes pour la clarte :
 *   - /adm/server_user_sudo.php  (droits sudo)
 *   - /adm/server_user_sftp.php  (acces SFTP/SSH)
 * Cette page redirige vers la page sudo en conservant les parametres serveur/user.
 */
$qs = '';
$params = [];
if (isset($_GET['server'])) $params['server'] = (int)$_GET['server'];
if (isset($_GET['user']))   $params['user']   = (int)$_GET['user'];
if ($params) $qs = '?' . http_build_query($params);
header('Location: /adm/server_user_sudo.php' . $qs, true, 302);
exit;
