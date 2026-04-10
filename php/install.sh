#!/bin/bash
# =============================================================================
# install.sh — Script de premier demarrage RootWarden
# =============================================================================
#
# Execute une seule fois par entrypoint.sh au premier lancement du conteneur.
# Genere les mots de passe des comptes admin/superadmin et les insere en BDD.
#
# Variables d'environnement optionnelles :
#   INIT_SUPERADMIN_PASSWORD : mot de passe souhaite pour le superadmin
#   INIT_ADMIN_PASSWORD      : mot de passe souhaite pour l'admin
#   (si vides, des mots de passe aleatoires sont generes)
#
# Flag : /var/www/html/.installed — empeche la re-execution.
# =============================================================================

set -e

APP_DIR="/var/www/html"
FLAG_FILE="${APP_DIR}/.installed"

# ── Idempotence : ne pas re-executer si deja installe ───────────────────────
if [ -f "${FLAG_FILE}" ]; then
    echo "[RootWarden] Installation deja effectuee — install.sh ignore"
    exit 0
fi

echo "[RootWarden] =============================================="
echo "[RootWarden]  PREMIER DEMARRAGE — Installation en cours..."
echo "[RootWarden] =============================================="

# ── Attente de MySQL (retry loop PDO) ────────────────────────────────────────
MAX_RETRIES=15
RETRY_DELAY=3
echo "[RootWarden] Attente de la base de donnees MySQL..."

for i in $(seq 1 $MAX_RETRIES); do
    if php -r "
        try {
            new PDO(
                'mysql:host=' . getenv('DB_HOST') . ';dbname=' . getenv('DB_NAME'),
                getenv('DB_USER'),
                getenv('DB_PASSWORD'),
                [PDO::ATTR_TIMEOUT => 3]
            );
            echo 'OK';
        } catch (Exception \$e) {
            exit(1);
        }
    " 2>/dev/null | grep -q "OK"; then
        echo "[RootWarden] Base de donnees accessible (tentative ${i}/${MAX_RETRIES})"
        break
    fi

    if [ "$i" -eq "$MAX_RETRIES" ]; then
        echo "[ERREUR] Base de donnees inaccessible apres ${MAX_RETRIES} tentatives"
        echo "[ERREUR] Verifiez DB_HOST, DB_NAME, DB_USER, DB_PASSWORD"
        exit 1
    fi

    echo "[RootWarden] MySQL pas encore pret — nouvelle tentative dans ${RETRY_DELAY}s (${i}/${MAX_RETRIES})"
    sleep $RETRY_DELAY
done

# ── Generation des mots de passe ─────────────────────────────────────────────
generate_password() {
    # Genere un mot de passe aleatoire de 24 caracteres (base64, URL-safe)
    openssl rand -base64 18
}

SUPERADMIN_PASS="${INIT_SUPERADMIN_PASSWORD:-$(generate_password)}"

# ── Hash bcrypt + insertion en BDD via PHP CLI ───────────────────────────────
echo "[RootWarden] Configuration du compte superadmin..."

php -r "
    \$pdo = new PDO(
        'mysql:host=' . getenv('DB_HOST') . ';dbname=' . getenv('DB_NAME'),
        getenv('DB_USER'),
        getenv('DB_PASSWORD'),
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    // Superadmin — hash + force changement au premier login
    \$hash = password_hash('${SUPERADMIN_PASS}', PASSWORD_BCRYPT);
    \$stmt = \$pdo->prepare('UPDATE users SET password = ?, force_password_change = 1 WHERE name = ?');
    \$stmt->execute([\$hash, 'superadmin']);
    echo \"[RootWarden] Compte superadmin configure (\" . \$stmt->rowCount() . \" ligne(s) mise(s) a jour)\n\";
    echo \"[RootWarden] Changement de mot de passe obligatoire a la premiere connexion\n\";

    // Email superadmin (SERVER_ADMIN) pour le reset de mot de passe
    \$adminEmail = getenv('SERVER_ADMIN') ?: '';
    if (\$adminEmail && filter_var(\$adminEmail, FILTER_VALIDATE_EMAIL)) {
        \$pdo->prepare('UPDATE users SET email = ? WHERE name = ?')->execute([\$adminEmail, 'superadmin']);
        echo \"[RootWarden] Email superadmin configure : \$adminEmail\n\";
    }
"

# ── Ecriture securisee des identifiants ──────────────────────────────────────
# Le mot de passe est ecrit dans un fichier temporaire lisible uniquement par root.
# Il est aussi affiche une seule fois dans les logs Docker (premier demarrage).
CREDS_FILE="${APP_DIR}/.first_run_credentials"
cat > "${CREDS_FILE}" <<CREDS_EOF
========================================
 ROOTWARDEN — Identifiants initiaux
========================================
 Login    : superadmin
 Password : ${SUPERADMIN_PASS}

 Ce mot de passe doit etre change a la
 premiere connexion (force par le systeme).
========================================
CREDS_EOF
chmod 600 "${CREDS_FILE}"

# Masquage partiel dans les logs Docker (premiers/derniers caracteres visibles)
PASS_LEN=${#SUPERADMIN_PASS}
if [ "$PASS_LEN" -gt 6 ]; then
    MASKED="${SUPERADMIN_PASS:0:3}$(printf '*%.0s' $(seq 1 $((PASS_LEN - 6))))${SUPERADMIN_PASS: -3}"
else
    MASKED="***"
fi

echo ""
echo "[RootWarden] =============================================="
echo "[RootWarden]  PREMIER DEMARRAGE TERMINE"
echo "[RootWarden] =============================================="
echo "[RootWarden]"
echo "[RootWarden]  Login    : superadmin"
echo "[RootWarden]  Password : ${MASKED}"
echo "[RootWarden]"
echo "[RootWarden]  Mot de passe complet dans : ${CREDS_FILE}"
echo "[RootWarden]  (lisible uniquement depuis le conteneur PHP)"
echo "[RootWarden]"
echo "[RootWarden]  Le changement de mot de passe sera OBLIGATOIRE"
echo "[RootWarden]  a la premiere connexion."
echo "[RootWarden]"
echo "[RootWarden]  Supprimez ce fichier apres la premiere connexion :"
echo "[RootWarden]    docker exec <php_container> rm ${CREDS_FILE}"
echo "[RootWarden] =============================================="
echo ""

# ── Marquer l'installation comme terminee ────────────────────────────────────
touch "${FLAG_FILE}"
echo "[RootWarden] Installation terminee — flag ${FLAG_FILE} cree"
