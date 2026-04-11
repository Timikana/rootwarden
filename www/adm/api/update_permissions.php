<?php
/**
 * update_permissions.php — Mise à jour d'une permission fonctionnelle (endpoint AJAX JSON)
 *
 * Rôle : modifie une permission spécifique d'un utilisateur dans la table `permissions`.
 *        Utilise un INSERT ... ON DUPLICATE KEY UPDATE pour créer la ligne si elle
 *        n'existe pas encore, ou mettre à jour la valeur existante.
 *
 * Accès requis : rôle admin (2) ou superadmin (3) — vérifié par checkAuth().
 *
 * Méthode HTTP : POST avec body JSON (Content-Type: application/json).
 *
 * Body JSON attendu :
 *   {
 *     "user_id":    int,    // identifiant de l'utilisateur cible
 *     "permission": string, // nom de la permission (doit être dans $allowedPermissions)
 *     "value":      0|1     // nouvelle valeur binaire
 *   }
 *
 * Réponse JSON :
 *   { "success": bool, "message": string }
 *
 * Sécurité SQL — whitelist stricte sur le nom de colonne :
 *   Le nom de la permission est interpolé directement dans la requête SQL
 *   (impossible de l'utiliser comme paramètre lié PDO pour un nom de colonne).
 *   La whitelist $allowedPermissions est la seule protection contre l'injection
 *   de colonne SQL ; toute valeur absente de cette liste est rejetée avec une
 *   réponse d'erreur avant l'exécution de la requête.
 *
 * Permissions autorisées (whitelist) :
 *   - can_deploy_keys     : déploiement des clés SSH sur les machines
 *   - can_update_linux    : lancement des mises à jour Linux
 *   - can_manage_iptables : gestion des règles iptables
 *   - can_admin_portal    : accès à l'interface d'administration portail
 *   - can_scan_cve        : déclenchement des scans de vulnérabilités CVE
 */

require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- Contrôle d'accès ---
// Seuls les superadmins peuvent modifier des permissions (empeche auto-elevation admin).
checkAuth([ROLE_SUPERADMIN]); // Superadmin uniquement

// --- Vérification de la méthode HTTP ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée']);
    exit();
}

// --- Validation CSRF (POST, header htmx, ou body JSON) ---
checkCsrfToken();

// --- Lecture du body (JSON ou form-urlencoded pour htmx) ---
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
if (str_contains($contentType, 'application/json')) {
    $data = json_decode(file_get_contents('php://input'), true);
} else {
    $data = $_POST; // htmx envoie en form-urlencoded
}

// --- Validation de la présence des champs obligatoires ---
if (!isset($data['user_id'], $data['permission'], $data['value'])) {
    echo json_encode(['success' => false, 'message' => 'Données manquantes']);
    exit();
}

// Conversion des types pour securiser les parametres lies
$user_id    = intval($data['user_id']);
$permission = $data['permission'];
$value      = intval($data['value']);

// --- Anti-escalation : un superadmin ne peut PAS modifier SES PROPRES permissions ---
if ($user_id === (int) $_SESSION['user_id']) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Impossible de modifier vos propres permissions']);
    exit();
}

// --- Protection : les superadmins ont TOUTES les permissions par bypass, on ne touche pas ---
$targetRoleStmt = $pdo->prepare("SELECT role_id FROM users WHERE id = ?");
$targetRoleStmt->execute([$user_id]);
$targetRoleId = (int) $targetRoleStmt->fetchColumn();
if ($targetRoleId === 3) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Les superadmins ont toutes les permissions par defaut']);
    exit();
}

// --- Whitelist des colonnes autorisees (protection contre l'injection de colonne SQL) ---
// IMPORTANT : le nom de la permission est interpolé dans la requête SQL car PDO
// ne permet pas de paramétrer un nom de colonne. La whitelist est donc critique.
$allowedPermissions = [
    'can_deploy_keys',
    'can_update_linux',
    'can_manage_iptables',
    'can_admin_portal',
    'can_scan_cve',
    'can_manage_remote_users',
    'can_manage_platform_key',
    'can_view_compliance',
    'can_manage_backups',
    'can_schedule_cve',
    'can_manage_fail2ban',
    'can_manage_services',
    'can_audit_ssh',
    'can_manage_supervision',
    'can_cyber_audit',
];

// Rejet immédiat si la permission n'est pas dans la liste autorisée
if (!in_array($permission, $allowedPermissions, true)) {
    echo json_encode(['success' => false, 'message' => 'Permission non valide']);
    exit();
}

// --- Mise à jour en base (INSERT ou UPDATE) ---
// INSERT si l'utilisateur n'a pas encore de ligne dans `permissions`,
// UPDATE si la ligne existe déjà (clé dupliquée sur user_id).
$stmt = $pdo->prepare("INSERT INTO permissions (user_id, $permission) VALUES (?, ?) ON DUPLICATE KEY UPDATE $permission = ?");
$success = $stmt->execute([$user_id, $value, $value]);

if ($success) {
    require_once __DIR__ . '/../includes/audit_log.php';
    audit_log($pdo, ($value ? 'Activation' : 'Desactivation') . " permission $permission pour user #$user_id");
    // htmx : retourne le label HTML mis a jour avec la checkbox
    if (!empty($_SERVER['HTTP_HX_REQUEST'])) {
        $checked = $value ? true : false;
        $checkCls = $checked
            ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800'
            : 'bg-gray-50 dark:bg-gray-700/30 border-gray-200 dark:border-gray-700';
        // Recuperer le label et la description de la permission
        $permLabels = [
            'can_deploy_keys' => ['Deployer cles', 'Deploiement SSH'],
            'can_update_linux' => ['Mises a jour', 'APT update/upgrade'],
            'can_manage_iptables' => ['Iptables', 'Regles pare-feu'],
            'can_admin_portal' => ['Admin portail', 'Gestion portail'],
            'can_scan_cve' => ['Scan CVE', 'Vulnerabilites'],
            'can_manage_remote_users' => ['Users distants', 'Gestion SSH users'],
            'can_manage_platform_key' => ['Cle plateforme', 'Keypair Ed25519'],
            'can_view_compliance' => ['Conformite', 'Rapport securite'],
            'can_manage_backups' => ['Backups', 'Sauvegardes BDD'],
            'can_schedule_cve' => ['Planif. CVE', 'Scans planifies'],
            'can_manage_fail2ban' => ['Fail2ban', 'Bans IP serveurs'],
            'can_manage_services' => ['Services', 'Services systemd'],
            'can_audit_ssh' => ['Audit SSH', 'Audit config SSH'],
            'can_manage_supervision' => ['Supervision', 'Deploiement agents monitoring'],
            'can_cyber_audit' => ['Audit Cyber', 'Score securite serveurs'],
        ];
        $info = $permLabels[$permission] ?? [$permission, ''];
        $checkedAttr = $checked ? 'checked' : '';
        header('HX-Trigger: ' . json_encode(['showToast' => ['message' => 'Permission mise a jour', 'type' => 'success']]));
        echo <<<HTML
<label class="flex items-center gap-2 px-3 py-2 rounded-lg border {$checkCls} cursor-pointer hover:border-blue-300 dark:hover:border-blue-600 transition-colors">
    <input type="checkbox" data-user-id="{$user_id}" data-permission="{$permission}"
           hx-post="api/update_permissions.php" hx-trigger="change" hx-target="closest label" hx-swap="outerHTML"
           hx-vals='{"user_id": "{$user_id}", "permission": "{$permission}"}'
           {$checkedAttr}
           class="form-checkbox h-3.5 w-3.5 text-blue-600 rounded border-gray-300 focus:ring-blue-500 flex-shrink-0">
    <div class="min-w-0">
        <div class="text-xs font-medium text-gray-700 dark:text-gray-300">{$info[0]}</div>
        <div class="text-[10px] text-gray-400 truncate">{$info[1]}</div>
    </div>
</label>
HTML;
        exit;
    }
    echo json_encode(['success' => true, 'message' => 'Permission mise à jour']);
} else {
    echo json_encode(['success' => false, 'message' => 'Erreur lors de la mise à jour']);
}
?>
