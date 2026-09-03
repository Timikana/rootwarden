// utils.js - helpers JS partages entre toutes les pages.
// Charge depuis menu.php avant les scripts specifiques.

// ── Auto-injection CSRF token sur fetch() vers api_proxy.php ──────────────
// Defense-in-depth : api_proxy.php force checkCsrfToken() sur POST/PUT/DELETE/
// PATCH depuis v1.17.0. SameSite=Strict mitige deja le CSRF cross-site, mais
// si une XSS reflechie/stockee existe sur le meme origin, le token bloque
// le proxy (l'endpoint le plus puissant de l'app).
// On wrappe fetch() pour ajouter automatiquement le header sur les non-GET
// vers /api_proxy.php - aucune modif requise dans les callers existants.
(function() {
    if (window.__rwFetchPatched) return;
    window.__rwFetchPatched = true;
    const _origFetch = window.fetch.bind(window);
    function _csrfToken() {
        const m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.getAttribute('content') : '';
    }
    window.fetch = function(input, init) {
        try {
            const url = typeof input === 'string' ? input : (input && input.url) || '';
            const method = (init && init.method) || (input && input.method) || 'GET';
            if ((url.indexOf('api_proxy.php') !== -1 || url.indexOf('/adm/api/') !== -1 || url.indexOf('/auth/') !== -1)
                && method.toUpperCase() !== 'GET') {
                const token = _csrfToken();
                if (token) {
                    init = init || {};
                    const h = new Headers(init.headers || {});
                    if (!h.has('X-CSRF-TOKEN')) h.set('X-CSRF-TOKEN', token);
                    init.headers = h;
                }
            }
        } catch (_) { /* fail-open : ne casse jamais le fetch */ }

        // Patch A04-INSEC-N4 : wrapper qui catch les 403 step_up_required et
        // ouvre automatiquement le modal de re-authentification 2FA. Apres
        // verification reussie, on re-execute la requete originale.
        return _origFetch(input, init).then(resp => {
            if (resp.status !== 403) return resp;
            const clone = resp.clone();
            return clone.json().then(j => {
                if (j && j.step_up_required && j.action && window.rwOpenStepUpModal) {
                    return window.rwOpenStepUpModal(j.action).then(ok => {
                        if (ok) return _origFetch(input, init);  // retry
                        return resp;  // user annule : on rend la 403 originale
                    });
                }
                return resp;
            }).catch(() => resp);
        });
    };
})();

// ── Step-up 2FA modal (Patch A04-INSEC-N4) ───────────────────────────────────
// Ouvert automatiquement par window.fetch quand un endpoint sensible renvoie
// 403 + {step_up_required: true, action: "..."}. Demande le code TOTP courant
// et appelle /auth/step_up_verify.php. Apres validation, la requete originale
// est re-executee.
window.rwOpenStepUpModal = function(action) {
    return new Promise((resolve) => {
        // Construit le modal s'il n'existe pas
        let overlay = document.getElementById('rw-stepup-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'rw-stepup-overlay';
            overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);'
                + 'z-index:99999;display:flex;align-items:center;justify-content:center;';
            overlay.innerHTML = `
              <div style="background:#1f2937;color:#e5e7eb;padding:24px;border-radius:12px;
                          max-width:380px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.5);
                          border:1px solid #374151;">
                <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 6px;color:#fbbf24;">
                  Re-authentification 2FA requise
                </h3>
                <p style="font-size:0.85rem;color:#9ca3af;margin:0 0 16px;">
                  Action sensible : <span id="rw-stepup-action" style="color:#fbbf24;font-family:monospace;"></span><br>
                  Entre le code 6 chiffres de ton application TOTP pour confirmer.
                </p>
                <input id="rw-stepup-code" type="text" inputmode="numeric" pattern="[0-9]{6}"
                       maxlength="6" autocomplete="one-time-code"
                       style="width:100%;padding:10px;font-size:1.4rem;text-align:center;
                              letter-spacing:0.5rem;font-family:monospace;background:#111827;
                              color:#fff;border:1px solid #374151;border-radius:8px;">
                <p id="rw-stepup-err" style="color:#ef4444;font-size:0.8rem;margin:8px 0 0;display:none;"></p>
                <div style="display:flex;gap:8px;margin-top:16px;">
                  <button id="rw-stepup-cancel" style="flex:1;padding:8px;background:#374151;
                          color:#fff;border:none;border-radius:6px;cursor:pointer;">Annuler</button>
                  <button id="rw-stepup-ok" style="flex:1;padding:8px;background:#2563eb;
                          color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Valider</button>
                </div>
              </div>`;
            document.body.appendChild(overlay);
        }
        const actionSpan = overlay.querySelector('#rw-stepup-action');
        const codeInput = overlay.querySelector('#rw-stepup-code');
        const errBox = overlay.querySelector('#rw-stepup-err');
        const okBtn = overlay.querySelector('#rw-stepup-ok');
        const cancelBtn = overlay.querySelector('#rw-stepup-cancel');
        actionSpan.textContent = action;
        codeInput.value = '';
        errBox.style.display = 'none';
        overlay.style.display = 'flex';
        setTimeout(() => codeInput.focus(), 50);

        const close = (result) => {
            overlay.style.display = 'none';
            okBtn.onclick = null;
            cancelBtn.onclick = null;
            codeInput.onkeydown = null;
            resolve(result);
        };
        const submit = () => {
            const code = (codeInput.value || '').trim();
            if (!/^\d{6}$/.test(code)) {
                errBox.textContent = 'Code 6 chiffres requis';
                errBox.style.display = 'block';
                return;
            }
            const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
            okBtn.disabled = true;
            // Note : on utilise le fetch d'origine pour ne pas re-declencher le wrapper
            const orig = window.__rwFetchPatched ? window.fetch : fetch;
            orig('/auth/step_up_verify.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-CSRF-TOKEN': csrf},
                body: JSON.stringify({action: action, totp_code: code, csrf_token: csrf})
            }).then(r => r.json()).then(j => {
                okBtn.disabled = false;
                if (j.success) close(true);
                else {
                    errBox.textContent = j.message || 'Erreur de validation';
                    errBox.style.display = 'block';
                    codeInput.select();
                }
            }).catch(err => {
                okBtn.disabled = false;
                errBox.textContent = 'Erreur reseau';
                errBox.style.display = 'block';
            });
        };
        okBtn.onclick = submit;
        cancelBtn.onclick = () => close(false);
        codeInput.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
    });
};

/**
 * Formate une date vers la timezone locale du navigateur.
 * - Accepte ISO 8601 avec Z (UTC) ou format MySQL "YYYY-MM-DD HH:MM:SS"
 *   qu'on interprete comme UTC (le backend tourne en UTC en Docker par defaut).
 * - Retourne `fallback` si l'input est vide / invalide.
 */
window.fmtLocalDate = function(v, fallback = '-') {
    if (!v) return fallback;
    let iso = String(v);
    if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(iso) && !/[zZ]$|[+-]\d{2}:?\d{2}$/.test(iso)) {
        iso = iso.replace(' ', 'T') + 'Z';
    }
    const d = new Date(iso);
    if (isNaN(d.getTime())) return fallback;
    return d.toLocaleString(navigator.language || 'fr-FR', {
        day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
    });
};
