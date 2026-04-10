<?php
/**
 * api/notifications.php — API AJAX pour les notifications in-app
 *
 * Actions :
 *   GET  ?action=count              — Nombre de notifications non lues
 *   GET  ?action=list&limit=10      — Dernieres notifications (lues + non lues)
 *   GET  ?action=list_all&page=1    — Historique pagine (20/page)
 *   POST action=read&id=<int>       — Marquer une notification comme lue
 *   POST action=read_all            — Marquer toutes comme lues
 *   POST action=delete&id=<int>     — Supprimer une notification
 */
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
checkAuth([1, 2, 3]);

header('Content-Type: application/json');

$userId = (int)($_SESSION['user_id'] ?? 0);
$roleId = (int)($_SESSION['role_id'] ?? 0);

// Determiner l'action
$action = $_GET['action'] ?? $_POST['action'] ?? '';

// Pour les POST, accepter aussi le JSON body
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true) ?: [];
    if (empty($action)) $action = $data['action'] ?? '';
    // Validation CSRF (htmx auto-inject ou body)
    $csrfToken = $_POST['csrf_token'] ?? $data['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Token CSRF invalide']);
        exit;
    }
}

// Condition WHERE : notifications pour cet utilisateur OU broadcasts (user_id=0) pour admins
$whereUser = "n.user_id = :uid";
if ($roleId >= 2) {
    $whereUser = "(n.user_id = :uid OR n.user_id = 0)";
}

switch ($action) {

    case 'count':
        $stmt = $pdo->prepare("SELECT COUNT(*) as cnt FROM notifications n WHERE {$whereUser} AND n.read_at IS NULL");
        $stmt->execute([':uid' => $userId]);
        echo json_encode(['success' => true, 'count' => (int)$stmt->fetchColumn()]);
        break;

    case 'list':
        $limit = min((int)($_GET['limit'] ?? 10), 50);
        $stmt = $pdo->prepare("SELECT n.id, n.type, n.title, n.message, n.link, n.read_at, n.created_at FROM notifications n WHERE {$whereUser} ORDER BY n.created_at DESC LIMIT :lim");
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $notifs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['success' => true, 'notifications' => $notifs]);
        break;

    case 'list_all':
        $page = max(1, (int)($_GET['page'] ?? 1));
        $perPage = 20;
        $offset = ($page - 1) * $perPage;
        $type = $_GET['type'] ?? '';

        $where = $whereUser;
        $params = [':uid' => $userId];
        if ($type) {
            $where .= " AND n.type = :type";
            $params[':type'] = $type;
        }

        $countStmt = $pdo->prepare("SELECT COUNT(*) FROM notifications n WHERE {$where}");
        $countStmt->execute($params);
        $total = (int)$countStmt->fetchColumn();

        $stmt = $pdo->prepare("SELECT n.id, n.type, n.title, n.message, n.link, n.read_at, n.created_at FROM notifications n WHERE {$where} ORDER BY n.created_at DESC LIMIT {$perPage} OFFSET {$offset}");
        $stmt->execute($params);
        $notifs = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode([
            'success' => true,
            'notifications' => $notifs,
            'total' => $total,
            'page' => $page,
            'pages' => (int)ceil($total / $perPage),
        ]);
        break;

    case 'read':
        $id = (int)($_POST['id'] ?? $data['id'] ?? 0);
        if (!$id) { echo json_encode(['success' => false, 'message' => 'id requis']); break; }
        $stmt = $pdo->prepare("UPDATE notifications SET read_at = NOW() WHERE id = ? AND (user_id = ? OR user_id = 0)");
        $stmt->execute([$id, $userId]);

        // htmx : retourner le badge mis a jour
        if (!empty($_SERVER['HTTP_HX_REQUEST'])) {
            $countStmt = $pdo->prepare("SELECT COUNT(*) FROM notifications n WHERE {$whereUser} AND n.read_at IS NULL");
            $countStmt->execute([':uid' => $userId]);
            $count = (int)$countStmt->fetchColumn();
            header('HX-Trigger: ' . json_encode(['showToast' => ['message' => 'Notification lue', 'type' => 'success'], 'refreshNotifBadge' => ['count' => $count]]));
            echo '<span class="sr-only">Lu</span>';
            exit;
        }
        echo json_encode(['success' => true]);
        break;

    case 'read_all':
        $stmt = $pdo->prepare("UPDATE notifications SET read_at = NOW() WHERE (user_id = ? OR user_id = 0) AND read_at IS NULL");
        $stmt->execute([$userId]);

        if (!empty($_SERVER['HTTP_HX_REQUEST'])) {
            header('HX-Trigger: ' . json_encode(['showToast' => ['message' => 'Toutes marquees lues', 'type' => 'success'], 'refreshNotifBadge' => ['count' => 0]]));
            echo '';
            exit;
        }
        echo json_encode(['success' => true, 'updated' => $stmt->rowCount()]);
        break;

    case 'delete':
        $id = (int)($_POST['id'] ?? $data['id'] ?? 0);
        if (!$id) { echo json_encode(['success' => false, 'message' => 'id requis']); break; }
        $stmt = $pdo->prepare("DELETE FROM notifications WHERE id = ? AND (user_id = ? OR user_id = 0)");
        $stmt->execute([$id, $userId]);
        echo json_encode(['success' => true, 'deleted' => $stmt->rowCount() > 0]);
        break;

    default:
        echo json_encode(['success' => false, 'message' => 'Action inconnue']);
}
