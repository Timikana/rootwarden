"""
docker_monitor.py - Detection des conteneurs Docker sur un serveur distant (SSH).

Pour un serveur donne, inventorie les conteneurs en cours, leur image + tag +
digest local, le projet docker compose associe, et - si la stack provient d'un
depot git clone a cote - le nombre de commits en retard + le changelog
(HEAD..origin). La veille de mise a jour des IMAGES (digest distant) est faite
cote backend par docker_registry.py (le serveur n'a pas forcement Internet).

Les commandes docker sont lancees en root (un conteneur n'est pas listable par
un user hors du groupe docker). git est lance avec safe.directory='*' pour eviter
l'erreur "dubious ownership" quand le depot appartient au user de deploiement.
Best-effort : toute erreur -> le champ concerne reste vide, jamais d'exception.
"""
import json
import shlex
import logging

from ssh_utils import execute_as_root

_log = logging.getLogger(__name__)

_DELIM = '|;|'


def _root(client, root_password, cmd, timeout=30):
    try:
        out, err, code = execute_as_root(client, cmd, root_password, logger=_log, timeout=timeout)
        return (out or ''), (err or ''), code
    except Exception as e:
        _log.debug("docker cmd failed: %s", e)
        return '', str(e), 1


def docker_available(client, root_password):
    out, _, code = _root(client, root_password, "command -v docker || true", timeout=10)
    return bool(out.strip())


def _parse_image(ref):
    """Separe une reference 'repo[:tag]' en (image_sans_tag_ou_complet, tag)."""
    ref = (ref or '').strip()
    tag = ''
    # gere host:port/...:tag (le dernier ':' apres le dernier '/')
    last_slash = ref.rfind('/')
    last_colon = ref.rfind(':')
    if last_colon > last_slash:
        tag = ref[last_colon + 1:]
    return ref, tag


def collect(client, root_password):
    """Retourne la liste des conteneurs en cours avec leurs metadonnees + git."""
    if not docker_available(client, root_password):
        return {'docker': False, 'containers': []}

    out, _, _ = _root(client, root_password,
                      "docker ps --format '{{.Names}}\\t{{.Image}}\\t{{.Status}}'", timeout=30)
    containers = []
    names = []
    for line in out.strip().splitlines():
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        image = parts[1].strip()
        status = parts[2].strip() if len(parts) > 2 else ''
        if not name:
            continue
        names.append(name)
        img, tag = _parse_image(image)
        containers.append({
            'container_name': name, 'image': image, 'image_tag': tag,
            'status': status, 'state': 'running' if status.lower().startswith('up') else 'stopped',
            'local_digest': None, 'compose_project': None, 'git_dir': None,
            'git_behind': 0, 'git_changelog': None,
        })

    # 1) Inspect du CONTENEUR : labels compose (projet + working_dir).
    #    NB : RepoDigests n'existe PAS sur un conteneur, seulement sur l'image.
    for c in containers:
        fmt = ('{{index .Config.Labels "com.docker.compose.project"}}' + _DELIM +
               '{{index .Config.Labels "com.docker.compose.project.working_dir"}}')
        out, _, code = _root(client, root_password,
                             f"docker inspect --format '{fmt}' {shlex.quote(c['container_name'])}",
                             timeout=20)
        if code == 0 and out.strip():
            bits = out.strip().split(_DELIM)
            c['compose_project'] = (bits[0].strip() or None) if len(bits) > 0 else None
            c['git_dir'] = (bits[1].strip() or None) if len(bits) > 1 else None  # candidat .git

    # 2) Inspect de l'IMAGE : digest registre local (RepoDigests). Dedup par image.
    digest_by_image = {}
    for c in containers:
        img = c['image']
        if img not in digest_by_image:
            out, _, code = _root(client, root_password,
                                 f"docker image inspect --format '{{{{if .RepoDigests}}}}{{{{index .RepoDigests 0}}}}{{{{end}}}}' {shlex.quote(img)}",
                                 timeout=20)
            rd = out.strip() if code == 0 else ''
            digest_by_image[img] = rd.split('@', 1)[1] if '@' in rd else None
        c['local_digest'] = digest_by_image[img]

    # Git : pour chaque dossier candidat unique, recuperer commits en retard + changelog
    git_dirs = sorted({c['git_dir'] for c in containers if c['git_dir']})
    git_info = {}
    for d in git_dirs:
        qd = shlex.quote(d)
        _, _, code = _root(client, root_password,
                           f"git -c safe.directory='*' -C {qd} rev-parse --is-inside-work-tree 2>/dev/null",
                           timeout=10)
        if code != 0:
            git_info[d] = {'is_git': False}
            continue
        # fetch best-effort (pas de prompt, timeout) puis comptage + changelog
        _root(client, root_password,
              f"cd {qd} && GIT_TERMINAL_PROMPT=0 timeout 25 git -c safe.directory='*' fetch --quiet 2>/dev/null || true",
              timeout=35)
        cnt, _, _ = _root(client, root_password,
                          f"git -c safe.directory='*' -C {qd} rev-list --count HEAD..@{{u}} 2>/dev/null || echo 0",
                          timeout=10)
        try:
            behind = int((cnt.strip().splitlines() or ['0'])[0])
        except (ValueError, IndexError):
            behind = 0
        changelog = ''
        if behind > 0:
            log, _, _ = _root(client, root_password,
                              f"git -c safe.directory='*' -C {qd} log --oneline --no-decorate -20 HEAD..@{{u}} 2>/dev/null || true",
                              timeout=15)
            changelog = log.strip()
        git_info[d] = {'is_git': True, 'behind': behind, 'changelog': changelog}

    for c in containers:
        gi = git_info.get(c['git_dir'])
        if gi and gi.get('is_git'):
            c['git_behind'] = gi.get('behind', 0)
            c['git_changelog'] = gi.get('changelog') or None
        else:
            c['git_dir'] = None  # pas un depot git -> on n'affiche pas de chemin

    return {'docker': True, 'containers': containers}
