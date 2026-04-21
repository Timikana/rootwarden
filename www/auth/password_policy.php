<?php
/**
 * password_policy.php — Validation centralisee des politiques de mot de passe.
 *
 * Responsabilites :
 *   1. Complexite locale (15 chars, 4 classes)
 *   2. Historique : non-reutilisation des N derniers mots de passe
 *   3. HIBP (HaveIBeenPwned) k-anonymity : verification opt-in via HIBP_ENABLED
 *
 * Toutes les regles retournent null si OK, ou une CLE i18n si le password est rejete.
 */

/** Nombre de mots de passe passes a conserver et refuser. */
if (!defined('PASSWORD_HISTORY_SIZE')) {
    define('PASSWORD_HISTORY_SIZE', 5);
}

/**
 * Verifie la complexite locale. Retourne null si OK.
 * Cle i18n : 'profile.error_password_policy'.
 */
function passwordPolicyCheckComplexity(string $password): ?string {
    if (strlen($password) < 15) return 'profile.error_password_policy';
    if (!preg_match('/[a-z]/', $password)) return 'profile.error_password_policy';
    if (!preg_match('/[A-Z]/', $password)) return 'profile.error_password_policy';
    if (!preg_match('/[0-9]/', $password)) return 'profile.error_password_policy';
    if (!preg_match('/[^a-zA-Z0-9]/', $password)) return 'profile.error_password_policy';
    return null;
}

/**
 * Verifie que le nouveau mot de passe n'est pas dans les PASSWORD_HISTORY_SIZE
 * derniers. Retourne null si OK, cle i18n sinon.
 *
 * Utilise password_verify() sur chaque hash bcrypt (comparison timing-safe).
 */
function passwordPolicyCheckHistory(PDO $pdo, int $userId, string $newPassword): ?string {
    try {
        $stmt = $pdo->prepare(
            "SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT ?"
        );
        // LIMIT avec integer via bindValue (PDO emule) — passons par interpolation apres cast int
        $limit = (int) PASSWORD_HISTORY_SIZE;
        $stmt = $pdo->prepare(
            "SELECT password_hash FROM password_history WHERE user_id = ? "
            . "ORDER BY changed_at DESC LIMIT $limit"
        );
        $stmt->execute([$userId]);
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $oldHash) {
            if (password_verify($newPassword, $oldHash)) {
                return 'profile.error_password_reuse';
            }
        }
        // Egalement comparer au hash courant (pas encore en password_history)
        $cur = $pdo->prepare("SELECT password FROM users WHERE id = ?");
        $cur->execute([$userId]);
        $currentHash = $cur->fetchColumn();
        if ($currentHash && password_verify($newPassword, $currentHash)) {
            return 'profile.error_password_reuse';
        }
    } catch (\Exception $e) {
        error_log('passwordPolicyCheckHistory: ' . $e->getMessage());
    }
    return null;
}

/**
 * Verifie HIBP via k-anonymity. Opt-in via env HIBP_ENABLED=true.
 * Si HIBP injoignable (reseau, timeout), on fail-open (pas de blocage user).
 *
 * Details : https://haveibeenpwned.com/API/v3#PwnedPasswords
 * On envoie les 5 premiers hex du SHA1 du password, on recupere toutes les
 * fins de hash qui matchent ce prefix + leur count de leak, et on compare
 * localement a notre hash complet. Aucun password ni hash complet ne sort.
 */
function passwordPolicyCheckHIBP(string $password): ?string {
    if (strtolower((string)getenv('HIBP_ENABLED')) !== 'true') {
        return null; // opt-in, off par defaut
    }
    $threshold = (int)(getenv('HIBP_THRESHOLD') ?: 10); // seuil de fuites
    $sha1 = strtoupper(sha1($password));
    $prefix = substr($sha1, 0, 5);
    $suffix = substr($sha1, 5);
    $url = 'https://api.pwnedpasswords.com/range/' . $prefix;

    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 3,
            'header' => "User-Agent: RootWarden-HIBP-check\r\nAdd-Padding: true\r\n",
        ],
        'https' => [
            'method' => 'GET',
            'timeout' => 3,
            'header' => "User-Agent: RootWarden-HIBP-check\r\nAdd-Padding: true\r\n",
        ],
    ]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) {
        error_log('HIBP check: API unreachable, fail-open');
        return null;
    }
    foreach (explode("\n", $body) as $line) {
        $line = trim($line);
        if ($line === '') continue;
        [$lineSuffix, $count] = explode(':', $line, 2) + ['', '0'];
        if (strcasecmp($lineSuffix, $suffix) === 0) {
            if ((int)$count >= $threshold) {
                return 'profile.error_password_pwned';
            }
            break; // trouve mais en-dessous du seuil
        }
    }
    return null;
}

/**
 * Validation complete en une passe. Retourne null si OK ou la cle i18n
 * de la premiere regle echouee.
 */
function passwordPolicyValidateAll(PDO $pdo, int $userId, string $newPassword): ?string {
    $e = passwordPolicyCheckComplexity($newPassword); if ($e) return $e;
    $e = passwordPolicyCheckHistory($pdo, $userId, $newPassword); if ($e) return $e;
    $e = passwordPolicyCheckHIBP($newPassword); if ($e) return $e;
    return null;
}

/**
 * Enregistre le hash bcrypt du mot de passe dans password_history apres
 * un changement reussi. A appeler AVANT l'UPDATE users.password.
 * (En fait on enregistre l'ANCIEN avant de le remplacer, pour que
 * passwordPolicyCheckHistory retrouve l'historique complet.)
 *
 * Retention : on garde les PASSWORD_HISTORY_SIZE + 5 dernieres lignes
 * puis on purge plus ancien (evite la croissance infinie).
 */
function passwordPolicyRecordOld(PDO $pdo, int $userId, string $oldHash): void {
    try {
        $pdo->prepare("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)")
            ->execute([$userId, $oldHash]);

        // Purge : garder au plus PASSWORD_HISTORY_SIZE * 2 lignes par user
        $keep = (int) PASSWORD_HISTORY_SIZE * 2;
        $del = $pdo->prepare(
            "DELETE FROM password_history WHERE user_id = ? AND id NOT IN "
            . "(SELECT id FROM (SELECT id FROM password_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT $keep) AS keep_list)"
        );
        $del->execute([$userId, $userId]);
    } catch (\Exception $e) {
        error_log('passwordPolicyRecordOld: ' . $e->getMessage());
    }
}
