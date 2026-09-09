r"""
test_graylog_ca_path_puits_rsyslog.py

┌─ LE DEFAUT QUE CE TEST FERME ────────────────────────────────────────────────┐
│ `tls_ca_path` etait valide par `len <= 255 and startswith('/')` — aucune      │
│ classe, aucune ancre. Un SAUT DE LIGNE interieur passait, et le `.strip()`    │
│ d'en face ne retire que les bords.                                            │
│                                                                               │
│ COTE SHELL LA VALEUR EST IRREPROCHABLE : elle est encodee en base64, dont      │
│ l'alphabet ne peut pas porter d'apostrophe. Le cliquet des commandes root      │
│ indirectes repond donc « sur » sur ce site, et il a raison — dans SON domaine. │
│                                                                               │
│ MAIS LE PUITS N'EST PAS UN SHELL. C'est                                       │
│ `/etc/rsyslog.d/99-rootwarden-graylog-forward.conf`, relu par rsyslog EN       │
│ ROOT, et sa grammaire est celle de rsyslog. Un saut de ligne ferme la          │
│ directive attendue et en ouvre une autre — dont une qui fait EXECUTER un       │
│ binaire par root.                                                             │
│                                                                               │
│   > Un gage se juge sur son DOMAINE et sur son PUITS, pas sur sa qualite.     │
└──────────────────────────────────────────────────────────────────────────────┘

CHAINE, telle que `gestion-ssh-key-4f` l'a etablie :
  POST /graylog/config  (role 2 + can_manage_graylog)     -> stocke en base
  POST /graylog/deploy  (+ require_machine_access)        -> ecrit sur la machine
  rsyslog charge la directive EN ROOT
Elevation d'un role 2 du portail vers une execution root sur toute machine
accessible, sans detenir d'identifiant SSH.

⚠ LA CHAINE N'A PAS ETE EXERCEE, et ce n'est pas un oubli : l'exercer
reviendrait a ecrire une directive rsyslog sur une machine du parc. Les deux
gardes sont eprouvees en LOGIQUE PURE, hors du service. La demonstration de bout
en bout, si elle est voulue, se fait sur la machine 3 (OpenCVE-Test-OnPrem,
192.168.0.2) et sur le mot de l'exploitant.

DEUX GARDES, ET LA REDONDANCE EST VOULUE :
  a l'ENTREE  `_CA_PATH_RE`, ancree aux deux bouts, en `fullmatch`
  au PUITS    aucune ligne rendue par `_build_forward_conf` ne peut porter un
              saut de ligne — independant de toute classe de caracteres
La seconde existe parce que la premiere se perimera le jour ou quelqu'un
elargira sa classe pour un besoin legitime, sans avoir de raison de lire le puits.
"""

import ast
import os
import re

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FICHIER = os.path.join(RACINE, 'routes', 'graylog.py')
NL = chr(10)


def _source():
    with open(FICHIER, encoding='utf-8') as fh:
        return fh.read()


def _motif_ca():
    """Le motif EXTRAIT du fichier, pas retape.

    Retape, il mesurerait ma memoire ; extrait, il mesure le code.
    """
    m = re.search(r"_CA_PATH_RE\s*=\s*re\.compile\(r'([^']+)'\)", _source())
    assert m, '_CA_PATH_RE introuvable : la garde d entree a disparu'
    return re.compile(m.group(1))


# Les charges sont CONSTRUITES et non ecrites en clair : ce depot est PUBLIC.
# Chacune ferme la directive attendue et en ouvre une autre.
def _charges():
    return [
        ('/a' + NL + '$ActionSendStreamDriverAuthMode anon', 'desarme la verification du pair'),
        ('/a' + NL + 'module(load="omprog")', 'charge un module arbitraire'),
        ('/a' + NL + 'action(type="omprog" binary="/tmp/x")', 'fait EXECUTER un binaire par root'),
        ('/a' + NL + '*.* @@ailleurs:514', 'reexpedie TOUS les journaux'),
        ('/a' + chr(13) + '$Include /tmp/x.conf', 'retour chariot seul'),
    ]


_CA_REELS = (
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/pki/tls/certs/ca-bundle.crt',
    '/usr/local/share/ca-certificates/ma-ca.crt',
    '/etc/ssl/certs/DST_Root_CA_X3.pem',
    '/opt/graylog/ca-2026.pem',
)


def test_les_chemins_de_CA_REELS_passent():
    """TEMOIN POSITIF. Un garde qui refuse tout passerait tous les autres tests.

    Et le cas est le plus BANAL qu'on puisse ecrire : le chemin par defaut que
    le code lui-meme utilise quand le champ est vide.
    """
    motif = _motif_ca()
    for chemin in _CA_REELS:
        assert motif.fullmatch(chemin), f'{chemin!r} refuse alors qu il est legitime'


def test_les_charges_rsyslog_sont_refusees():
    """LE DEFAUT. Chaque charge ouvre une directive non demandee."""
    motif = _motif_ca()
    for charge, libelle in _charges():
        assert not motif.fullmatch(charge), \
            f'ACCEPTE : {libelle} — la garde d entree ne ferme pas le puits'


def test_la_borne_de_longueur_est_CONSERVEE():
    """L'ancienne garde bornait a 255. La nouvelle doit borner pareil.

    Un correctif qui reduit une borne sans le dire casse un usage legitime, et
    ce genre de defaut se presente comme de la prudence.
    """
    motif = _motif_ca()
    assert motif.fullmatch('/' + 'a' * 254), '255 caracteres refuses : la borne a change'
    assert not motif.fullmatch('/' + 'a' * 255), '256 caracteres acceptes : la borne a saute'


def test_le_prefixe_absolu_reste_obligatoire():
    motif = _motif_ca()
    for relatif in ('etc/ssl/x.crt', 'a', '', '../etc/x'):
        assert not motif.fullmatch(relatif), f'{relatif!r} accepte sans / initial'


def test_la_garde_du_PUITS_existe_et_refuse_une_ligne_multiligne():
    """La seconde garde, celle qui ne depend d'aucune classe de caracteres.

    Elle est extraite du fichier et rejouee : sans ca ce test attesterait ma
    memoire du correctif, pas le correctif.
    """
    source = _source()
    assert "'\\n' in ligne" in source or '\\n\' in ligne' in source, \
        'la garde au puits a disparu de _build_forward_conf'
    arbre = ast.parse(source)
    trouvee = False
    for f in ast.walk(arbre):
        if isinstance(f, ast.FunctionDef) and f.name == '_build_forward_conf':
            for n in ast.walk(f):
                if isinstance(n, ast.Raise):
                    trouvee = True
    assert trouvee, '_build_forward_conf ne leve plus rien : la garde au puits est inerte'


def test_LES_SEPT_valeurs_du_puits_sont_toutes_gardees():
    """DERIVE, pas enumere : les valeurs interpolees dans le fichier de conf
    sont lues dans l'AST, et chacune doit avoir une garde nommee.

    C'est ce controle qui a montre que `tls_ca_path` etait la SEULE sans classe —
    et c'est lui qui signalera la prochaine valeur ajoutee sans garde.
    """
    arbre = ast.parse(_source())
    interpolees = set()
    for f in ast.walk(arbre):
        if not (isinstance(f, ast.FunctionDef) and f.name == '_build_forward_conf'):
            continue
        # ⚠ Les f-strings d'un `raise` sont ECARTEES : elles ne vont pas dans le
        #    fichier de conf. Mon premier predicat les comptait, et il a
        #    denonce le `{i}` du message d'erreur de la garde que je venais
        #    d'ajouter — mon propre correctif cassait mon propre test.
        dans_raise = {id(x) for r in ast.walk(f) if isinstance(r, ast.Raise)
                      for x in ast.walk(r)}
        for n in ast.walk(f):
            if not isinstance(n, ast.JoinedStr) or id(n) in dans_raise:
                continue
            for v in n.values:
                if not isinstance(v, ast.FormattedValue):
                    continue
                for x in ast.walk(v):
                    if isinstance(x, ast.Name):
                        interpolees.add(x.id)
    # `datetime` est l'horloge du serveur, pas une entree
    interpolees.discard('datetime')
    attendues = {'host', 'port', 'proto', 'rl_burst', 'rl_interval', 'ca'}
    assert interpolees == attendues, (
        f'les valeurs interpolees dans le fichier de conf ont change : '
        f'{sorted(interpolees)} au lieu de {sorted(attendues)}. '
        f'Chaque valeur NEUVE doit avoir une garde nommee AVANT d atteindre '
        f'rsyslog, qui la relit en root.'
    )
    source = _source()
    gardes = {
        'host': '_HOST_RE',
        'proto': '_VALID_PROTOCOLS',
        'ca': '_CA_PATH_RE',
    }
    for valeur, garde in gardes.items():
        assert garde in source, f'la garde de {valeur} ({garde}) a disparu'


def test_le_motif_est_employe_en_FULLMATCH_et_non_en_MATCH():
    """`fullmatch` est PORTEUR : un `match` ferait revenir la faille.

    En python, `$` s'apparie AUSSI juste avant un saut de ligne terminal. Avec
    ce motif EXACT et inchange :

        _CA_PATH_RE.match('/etc/ssl/ca.crt\\n')      ->  ACCEPTE
        _CA_PATH_RE.fullmatch('/etc/ssl/ca.crt\\n')  ->  refuse

    Donc « simplifier » l'appel en `match` rouvrirait le defaut SANS TOUCHER A
    LA CLASSE — et une relecture du motif ne verrait rien. Un commentaire ne
    garde pas ca : ce test le garde.

    Releve par `gestion-ssh-key-4f` en EPROUVANT le correctif, y compris la
    partie qui suivait sa propre recommandation.
    """
    motif = _motif_ca()
    avec_saut = '/etc/ssl/ca.crt' + NL
    # la mesure qui fonde l'exigence, refaite ici
    assert motif.match(avec_saut), (
        'python a change : `$` ne s apparie plus avant un saut de ligne final. '
        'Le commentaire du motif est a remesurer.'
    )
    assert not motif.fullmatch(avec_saut), \
        '`fullmatch` accepte un saut de ligne final : la propriete a disparu'
    # et l'APPEL dans le code doit etre un fullmatch
    source = _source()
    appels_match = [l.strip() for l in source.split(NL)
                    if '_CA_PATH_RE.match(' in l and not l.strip().startswith('#')]
    assert not appels_match, (
        f'_CA_PATH_RE est appele en `.match` : la faille revient sans que la '
        f'classe bouge.\n  ' + '\n  '.join(appels_match)
    )
    appels_full = [l.strip() for l in source.split(NL)
                   if '_CA_PATH_RE.fullmatch(' in l and not l.strip().startswith('#')]
    assert len(appels_full) == 1, \
        f'{len(appels_full)} appels en `.fullmatch`, 1 attendu'


def test_la_traversee_acceptee_est_un_choix_ASSUME():
    """`/../../etc/shadow` passe la classe, et c'est documente comme tel.

    Ce n'est pas une elevation : rsyslog lit ce fichier en root de toute facon,
    et un bundle de CA illisible fait ECHOUER l'emission TLS au lieu de la
    degrader en clair. Disponibilite, pas confidentialite.

    Le test existe pour que ce choix reste ECRIT : si quelqu'un le durcit un
    jour, il doit le faire en connaissance de cause et non par reflexe — et si
    quelqu'un le lit comme un oubli, ce test lui repond.
    """
    motif = _motif_ca()
    assert motif.fullmatch('/../../etc/shadow'), \
        'la traversee est desormais refusee : mettre a jour le commentaire du motif'
    commentaires = NL.join(l for l in _source().split(NL) if l.strip().startswith('#'))
    assert 'Disponibilite, pas confidentialite' in commentaires, \
        'la raison du choix a disparu des commentaires'


if __name__ == '__main__':
    for nom, fn in sorted(globals().items()):
        if nom.startswith('test_'):
            fn()
            print(f'  ✅ {nom}')
