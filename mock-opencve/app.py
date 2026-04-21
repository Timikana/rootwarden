"""
Mock OpenCVE API - Simule l'API REST OpenCVE pour les tests preprod.

Endpoints implémentés :
  GET /api/cve          - Liste CVE filtrée par vendor/product (pagination)
  GET /api/cve/<cve_id> - Détail d'une CVE

Auth : Basic Auth (n'importe quel user/pass accepté)

Les CVE retournées sont réalistes (vrais IDs, scores CVSS, résumés)
et couvrent les packages courants de Debian Bookworm.
"""

from flask import Flask, request, jsonify
from functools import wraps
import base64

app = Flask(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Base de CVE fictives mais réalistes, indexées par (vendor, product)
# ──────────────────────────────────────────────────────────────────────────────

MOCK_CVES = {
    ("debian", "openssh"): [
        {
            "id": "CVE-2023-38408",
            "summary": "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution.",
            "cvss": {"v3": 9.8, "v2": 7.5},
            "created_at": "2023-07-20T00:00:00Z",
        },
        {
            "id": "CVE-2023-48795",
            "summary": "The SSH transport protocol with certain OpenSSH extensions allows remote attackers to bypass integrity checks (Terrapin attack).",
            "cvss": {"v3": 5.9, "v2": 4.3},
            "created_at": "2023-12-18T00:00:00Z",
        },
        {
            "id": "CVE-2024-6387",
            "summary": "A signal handler race condition in OpenSSH's server (sshd) allows unauthenticated remote code execution (regreSSHion).",
            "cvss": {"v3": 8.1, "v2": 7.0},
            "created_at": "2024-07-01T00:00:00Z",
        },
    ],
    ("debian", "sudo"): [
        {
            "id": "CVE-2023-22809",
            "summary": "In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables.",
            "cvss": {"v3": 7.8, "v2": 6.9},
            "created_at": "2023-01-18T00:00:00Z",
        },
    ],
    ("debian", "openssl"): [
        {
            "id": "CVE-2024-0727",
            "summary": "Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a potential Denial of Service attack.",
            "cvss": {"v3": 5.5, "v2": 4.0},
            "created_at": "2024-01-26T00:00:00Z",
        },
        {
            "id": "CVE-2023-5678",
            "summary": "Issue summary: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or parameters may be very slow.",
            "cvss": {"v3": 5.3, "v2": 4.0},
            "created_at": "2023-11-06T00:00:00Z",
        },
    ],
    ("debian", "libssl3"): [
        {
            "id": "CVE-2024-0727",
            "summary": "Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a potential Denial of Service attack.",
            "cvss": {"v3": 5.5, "v2": 4.0},
            "created_at": "2024-01-26T00:00:00Z",
        },
    ],
    ("debian", "curl"): [
        {
            "id": "CVE-2023-46218",
            "summary": "This flaw allows a malicious HTTP server to set 'super cookies' in curl that are then passed back to more origins than what is otherwise allowed.",
            "cvss": {"v3": 6.5, "v2": 5.0},
            "created_at": "2023-12-06T00:00:00Z",
        },
    ],
    ("debian", "libc6"): [
        {
            "id": "CVE-2023-4911",
            "summary": "A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable (Looney Tunables).",
            "cvss": {"v3": 7.8, "v2": 7.2},
            "created_at": "2023-10-03T00:00:00Z",
        },
        {
            "id": "CVE-2024-2961",
            "summary": "The iconv() function in the GNU C Library may overflow the output buffer when converting strings to the ISO-2022-CN-EXT character set.",
            "cvss": {"v3": 8.8, "v2": 6.8},
            "created_at": "2024-04-17T00:00:00Z",
        },
    ],
    ("debian", "bash"): [
        {
            "id": "CVE-2022-3715",
            "summary": "A flaw was found in the bash package, where a heap-buffer-overflow can occur in valid_parameter_transform.",
            "cvss": {"v3": 7.8, "v2": 6.8},
            "created_at": "2022-10-27T00:00:00Z",
        },
    ],
    ("debian", "apt"): [
        {
            "id": "CVE-2024-3094",
            "summary": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0 (XZ backdoor). APT may process affected packages.",
            "cvss": {"v3": 10.0, "v2": 10.0},
            "created_at": "2024-03-29T00:00:00Z",
        },
    ],
    ("debian", "iptables"): [
        {
            "id": "CVE-2019-11360",
            "summary": "A buffer overflow in iptables-restore in netfilter iptables allows an attacker to crash the program or potentially execute arbitrary code.",
            "cvss": {"v3": 4.2, "v2": 3.5},
            "created_at": "2019-06-05T00:00:00Z",
        },
    ],
    ("debian", "procps"): [
        {
            "id": "CVE-2023-4016",
            "summary": "Under some circumstances, the ps command in procps-ng may allow a local attacker to cause a buffer overflow, crashing ps.",
            "cvss": {"v3": 5.5, "v2": 4.0},
            "created_at": "2023-08-02T00:00:00Z",
        },
    ],
}


# ──────────────────────────────────────────────────────────────────────────────
# Auth middleware (accepte tout en Basic Auth)
# ──────────────────────────────────────────────────────────────────────────────

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        # Accept both Basic Auth and Bearer token
        if not auth.startswith("Basic ") and not auth.startswith("Bearer "):
            return jsonify({"detail": "Authentication credentials were not provided."}), 401
        return f(*args, **kwargs)
    return decorated


# ──────────────────────────────────────────────────────────────────────────────
# Routes API
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/cve")
@require_auth
def list_cves():
    vendor = request.args.get("vendor", "").lower()
    product = request.args.get("product", "").lower()
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))

    # Recherche par (vendor, product)
    cves = MOCK_CVES.get((vendor, product), [])

    # Pagination
    start = (page - 1) * limit
    end = start + limit
    results = cves[start:end]

    return jsonify({
        "count": len(cves),
        "next": f"/api/cve?vendor={vendor}&product={product}&page={page+1}&limit={limit}" if end < len(cves) else None,
        "previous": None if page <= 1 else f"/api/cve?vendor={vendor}&product={product}&page={page-1}&limit={limit}",
        "results": results,
    })


@app.route("/api/cve/<cve_id>")
@require_auth
def get_cve(cve_id):
    for cves in MOCK_CVES.values():
        for cve in cves:
            if cve["id"] == cve_id:
                return jsonify(cve)
    return jsonify({"detail": "Not found."}), 404


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "mock-opencve", "cves_loaded": sum(len(v) for v in MOCK_CVES.values())})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090)
