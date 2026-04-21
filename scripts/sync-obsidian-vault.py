#!/usr/bin/env python3
"""
sync-obsidian-vault.py - Synchronisation automatique du vault Obsidian.

Objectif (hybride option B/C) :
  B. Genere automatiquement les stubs + frontmatter factuel (routes, tables,
     imports) pour les fichiers source qui n'ont pas encore de note dans le
     vault.
  C. Pour les notes existantes, met a jour UNIQUEMENT les champs auto-detectes
     (routes, tables, imports, last_synced). Les descriptions, sections "Voir
     aussi", commentaires humains restent intacts.

Scope couvert :
  - backend/*.py              -> 04_Fichiers/backend-*.md
  - backend/routes/*.py       -> 04_Fichiers/backend-routes-*.md
  - www/adm/api/*.php         -> 04_Fichiers/www-adm-api-*.md
  - mysql/migrations/NNN_x.sql -> 08_DB/migrations/NNN_x.md

Usage :
  python scripts/sync-obsidian-vault.py [--dry-run]

Declenche via .git/hooks/post-commit (non bloquant, silencieux si le vault
n'existe pas).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VAULT = REPO / 'obsidian-rootwarden' / 'obsidian-rootwarden-vault'
TODAY = date.today().isoformat()


def _build_real_tables_whitelist() -> set[str]:
    """Scan les fichiers de schema (init.sql + migrations) pour recuperer la
    liste des tables reellement declarees. Sert a filtrer les faux positifs
    quand on scanne du code Python/PHP pour deviner quelles tables il touche.
    """
    names = set()
    paths = [REPO / 'mysql' / 'init.sql'] + sorted((REPO / 'mysql' / 'migrations').glob('*.sql'))
    patterns = [
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)",
        r"ALTER\s+TABLE\s+([a-z_][a-z0-9_]*)",
    ]
    for p in paths:
        if not p.exists():
            continue
        try:
            src = p.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for pat in patterns:
            names.update(x.lower() for x in re.findall(pat, src, flags=re.IGNORECASE))
    return names


REAL_TABLES = _build_real_tables_whitelist()

# Marqueurs delimitant la zone auto-generee du frontmatter
AUTO_BEGIN = '# AUTO-BEGIN (sync-obsidian-vault.py)'
AUTO_END   = '# AUTO-END'


# ────────────────────────────────────────────────────────────────────────────
# Extraction de faits depuis les fichiers source
# ────────────────────────────────────────────────────────────────────────────

def extract_py_routes(src: str) -> list[str]:
    """Extrait les routes Flask declarees via @bp.route('/path', ...)."""
    return sorted(set(re.findall(r"@bp\.route\(\s*['\"]([^'\"]+)['\"]", src)))


def extract_py_tables(src: str) -> list[str]:
    """Extrait les tables MySQL mentionnees, filtrees contre la whitelist
    des tables reellement declarees en migration (anti faux-positif).
    """
    patterns = [
        r"FROM\s+([a-z_][a-z0-9_]*)",
        r"INTO\s+([a-z_][a-z0-9_]*)",
        r"UPDATE\s+([a-z_][a-z0-9_]*)",
        r"JOIN\s+([a-z_][a-z0-9_]*)",
    ]
    found = set()
    for p in patterns:
        found.update(x.lower() for x in re.findall(p, src, flags=re.IGNORECASE))
    return sorted(n for n in found if n in REAL_TABLES)


def extract_py_imports(src: str, repo_root: Path, current: Path) -> list[str]:
    """Imports internes -> wikilinks vers les notes cibles."""
    # Recupere les `from X import Y` et `import X` pour modules internes.
    mods = set()
    for m in re.finditer(r"^(?:from|import)\s+([\w.]+)", src, flags=re.MULTILINE):
        name = m.group(1)
        # On ne garde que les modules internes (pas stdlib / 3rd party)
        if name.startswith(('flask', 'mysql', 're', 'os', 'sys', 'json', 'logging',
                            'datetime', 'hmac', 'hashlib', 'base64', 'paramiko',
                            'typing', 'functools', 'concurrent', 'subprocess',
                            'socket', 'time', 'tempfile', 'shlex', 'ipaddress',
                            'cryptography', 'nacl', 'Crypto', 'packaging')):
            continue
        mods.add(name.split('.')[0])
    return sorted(mods)


def extract_php_tables(src: str) -> list[str]:
    """Tables mentionnees dans du PHP (PDO queries)."""
    return extract_py_tables(src)  # meme regex fonctionne


def extract_php_routes(_src: str) -> list[str]:
    """Les fichiers PHP exposent leur route via leur path fichier."""
    return []


def extract_sql_tables(src: str) -> list[str]:
    """Tables creees ou modifiees par une migration."""
    patterns = [
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)",
        r"ALTER\s+TABLE\s+([a-z_][a-z0-9_]*)",
        r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)",
    ]
    found = set()
    for p in patterns:
        found.update(re.findall(p, src, flags=re.IGNORECASE))
    return sorted(x.lower() for x in found)


# ────────────────────────────────────────────────────────────────────────────
# Manipulation des notes Markdown
# ────────────────────────────────────────────────────────────────────────────

def parse_note(path: Path) -> tuple[dict, str]:
    """Retourne (frontmatter_raw_lines, body) d'une note existante."""
    if not path.exists():
        return {}, ''
    text = path.read_text(encoding='utf-8')
    m = re.match(r'^---\n(.*?)\n---\n(.*)$', text, re.DOTALL)
    if not m:
        return {}, text
    return {'_raw': m.group(1)}, m.group(2)


def render_auto_block(routes, tables, imports_list, last_synced) -> str:
    lines = [AUTO_BEGIN]
    if routes:
        lines.append(f"routes: [{', '.join(routes)}]")
    else:
        lines.append("routes: []")
    if tables:
        lines.append(f"tables: [{', '.join(tables)}]")
    else:
        lines.append("tables: []")
    if imports_list:
        items = ', '.join(imports_list)
        lines.append(f"imports_detected: [{items}]")
    else:
        lines.append("imports_detected: []")
    lines.append(f"last_synced: {last_synced}")
    lines.append(AUTO_END)
    return '\n'.join(lines)


def upsert_auto_block(fm_raw: str, auto_block: str) -> str:
    """Remplace (ou inserere) le bloc auto entre AUTO-BEGIN et AUTO-END."""
    pattern = re.compile(
        rf"{re.escape(AUTO_BEGIN)}.*?{re.escape(AUTO_END)}",
        re.DOTALL,
    )
    if pattern.search(fm_raw):
        return pattern.sub(auto_block, fm_raw)
    # Pas encore present : append en fin de frontmatter
    return fm_raw.rstrip() + '\n\n' + auto_block


def ensure_note(note_path: Path, title: str, stub_frontmatter: str,
                stub_body: str, auto_block: str, dry_run: bool) -> str:
    """Cree la note si absente, sinon met a jour uniquement le bloc auto."""
    if not note_path.exists():
        content = f"---\n{stub_frontmatter.strip()}\n\n{auto_block}\n---\n\n{stub_body}\n"
        if dry_run:
            return f"[DRY] CREATE {note_path.relative_to(VAULT)}"
        note_path.parent.mkdir(parents=True, exist_ok=True)
        note_path.write_text(content, encoding='utf-8')
        return f"CREATE {note_path.relative_to(VAULT)}"

    fm, body = parse_note(note_path)
    new_fm = upsert_auto_block(fm.get('_raw', ''), auto_block)
    if new_fm == fm.get('_raw', ''):
        return ''  # rien a changer
    content = f"---\n{new_fm}\n---\n{body}"
    if dry_run:
        return f"[DRY] UPDATE {note_path.relative_to(VAULT)}"
    note_path.write_text(content, encoding='utf-8')
    return f"UPDATE {note_path.relative_to(VAULT)}"


# ────────────────────────────────────────────────────────────────────────────
# Handlers par type de fichier
# ────────────────────────────────────────────────────────────────────────────

def sync_backend_file(src_path: Path, dry_run: bool) -> str:
    rel = src_path.relative_to(REPO).as_posix()
    is_routes = 'backend/routes/' in rel
    slug = src_path.stem
    name = f"backend-routes-{slug}" if is_routes else f"backend-{slug}"
    note = VAULT / '04_Fichiers' / f"{name}.md"

    src = src_path.read_text(encoding='utf-8', errors='ignore')
    routes = extract_py_routes(src)
    tables = extract_py_tables(src)
    imports_list = extract_py_imports(src, REPO, src_path)
    auto = render_auto_block(routes, tables, imports_list, TODAY)

    stub_fm = f"""type: file
layer: L4
language: python
path: {rel}
tags: [backend]
permissions: []
version_introduced:
last_reviewed: {TODAY}
status: stable"""
    stub_body = f"""# {name}

**Source** : [[Code/{rel}]]

## Role

_Note auto-generee. Complete la description quand tu as le contexte._

## Voir aussi

-"""
    return ensure_note(note, name, stub_fm, stub_body, auto, dry_run)


def sync_www_adm_api(src_path: Path, dry_run: bool) -> str:
    rel = src_path.relative_to(REPO).as_posix()
    slug = src_path.stem
    name = f"www-adm-api-{slug}"
    note = VAULT / '04_Fichiers' / f"{name}.md"

    src = src_path.read_text(encoding='utf-8', errors='ignore')
    tables = extract_php_tables(src)
    auto = render_auto_block([], tables, [], TODAY)

    stub_fm = f"""type: file
layer: L4
language: php
path: {rel}
tags: [frontend, auth]
version_introduced:
last_reviewed: {TODAY}
status: stable"""
    stub_body = f"""# www/adm/api/{src_path.name} - [[Code/{rel}]]

_Note auto-generee. Complete la description quand tu as le contexte._
"""
    return ensure_note(note, name, stub_fm, stub_body, auto, dry_run)


def sync_sql_migration(src_path: Path, dry_run: bool) -> str:
    rel = src_path.relative_to(REPO).as_posix()
    slug = src_path.stem  # ex: 042_user_onboarding
    note = VAULT / '08_DB' / 'migrations' / f"{slug}.md"

    src = src_path.read_text(encoding='utf-8', errors='ignore')
    tables = extract_sql_tables(src)
    auto = render_auto_block([], tables, [], TODAY)

    stub_fm = f"""type: migration
layer: transverse
tags: [db]
language: sql
path: {rel}
version_introduced:
last_reviewed: {TODAY}
status: applied"""
    stub_body = f"""# {slug} - [[Code/{rel}]]

_Migration auto-detectee. Decris l'intention metier en quelques lignes._

## Voir aussi

-"""
    return ensure_note(note, slug, stub_fm, stub_body, auto, dry_run)


# ────────────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true', help='Pas d\'ecriture')
    args = parser.parse_args()

    if not VAULT.exists():
        print(f"[sync-obsidian] vault absent ({VAULT}) - skip.")
        return 0

    actions = []
    for src_path in sorted((REPO / 'backend').rglob('*.py')):
        if '__pycache__' in src_path.parts or 'tests' in src_path.parts:
            continue
        if src_path.name == '__init__.py':
            continue  # package marker, pas de doc dediee
        r = sync_backend_file(src_path, args.dry_run)
        if r:
            actions.append(r)

    api_dir = REPO / 'www' / 'adm' / 'api'
    if api_dir.exists():
        for src_path in sorted(api_dir.glob('*.php')):
            r = sync_www_adm_api(src_path, args.dry_run)
            if r:
                actions.append(r)

    migrations = REPO / 'mysql' / 'migrations'
    if migrations.exists():
        for src_path in sorted(migrations.glob('*.sql')):
            r = sync_sql_migration(src_path, args.dry_run)
            if r:
                actions.append(r)

    if not actions:
        print("[sync-obsidian] vault deja a jour.")
        return 0

    for a in actions:
        print(f"[sync-obsidian] {a}")
    print(f"[sync-obsidian] {len(actions)} action(s).")
    return 0


if __name__ == '__main__':
    sys.exit(main())
