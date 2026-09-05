"""Ecriture CHAINEE dans `user_logs`.

POURQUOI CE MODULE EXISTE
-------------------------
`user_logs` porte une chaine de hachage (`prev_hash` / `self_hash`) dont la
propriete est celle-ci : on ne peut pas retirer ni modifier une ligne sans que
toutes les suivantes cessent de se verifier.

Mesure du 2026-09-05 : sur 6271 lignes, **1484 n'ont NI `prev_hash` NI
`self_hash`**. Elles ne sont pas « en attente de scellement » : elles sont hors
de la chaine, et elles y sont **par construction**, parce que la tete se calcule
ainsi, ici comme dans le portail PHP :

    SELECT self_hash FROM user_logs
     WHERE self_hash IS NOT NULL          <-- elle SAUTE les lignes nues
     ORDER BY id DESC LIMIT 1

La chaine des 4787 lignes scellees est **intacte** (4787 `prev_hash` distincts,
chacun egal au `self_hash` de la scellee precedente). Les lignes nues ont ete
sautees a l'insertion, et **aucun scellement retroactif ne peut les y remettre**
sans reecrire le `prev_hash` des 4787 autres — c'est-a-dire sans detruire la
seule propriete que la chaine apporte.

> **Une ligne non chainee ne se rattrape pas apres coup. Elle se chaine a
> l'ecriture, ou jamais.**

CE QUE CE MODULE CORRIGE, ET CE QU'IL NE CORRIGE PAS
----------------------------------------------------
Il empeche la production de NOUVELLES lignes nues cote backend. **Il ne repare
pas les 1484 existantes** — elles sont irrattrapables, et le dire est plus
honnete que de leur donner un faux chainage.

⚠ Et il ne suffit pas a lui seul : les ecrivains nus mesures le 2026-09-05
etaient **12, dont 8 dans `backend/routes/`**. Les quatre autres sont dans le
legacy et disparaitront avec lui ; ceux du backend, non — **ils survivent a
l'extinction**, et c'est ce qui rend ce module necessaire plutot que transitoire.

L'EMPREINTE DOIT CONCORDER AVEC PHP, AU CARACTERE PRES
------------------------------------------------------
Le portail Laravel verifie ce que ce module ecrit. `JournalAudit::empreinte`
(`laravel/app/Services/JournalAudit.php`) calcule :

    hash_hmac('sha256', implode('|', [prev, userId, action, ts]), cle)

Trois pieges, chacun rendrait la chaine invalide sans lever d'erreur :

1. **`action` est tronquee a 255** par les ecrivains PHP. On hache la valeur
   TRONQUEE, c'est-a-dire celle qui sera relue.
2. **`ts` doit etre exactement `UNIX_TIMESTAMP(created_at)`**. On n'ecrit donc
   pas `NOW()` en esperant qu'il coincide : on pose `created_at` DEPUIS le `ts`
   qu'on vient de hacher, ce qui rend la coincidence structurelle.
3. **La cle suit la meme cascade que PHP** : `AUDIT_HMAC_KEY`, puis `SECRET_KEY`,
   puis le meme defaut litteral.
"""

import hashlib
import hmac
import logging
import os
import time

logger = logging.getLogger(__name__)

#: Valeur de `prev_hash` quand aucune ligne scellee ne precede.
#: Doit rester identique a `JournalAudit::GENESE` et a `AUDIT_LOG_GENESIS`.
GENESE = 'GENESIS'

#: Longueur de `user_logs.action`. Les ecrivains PHP tronquent a cette valeur
#: AVANT de hacher ; on fait pareil, sans quoi l'empreinte porterait sur un
#: texte que personne ne relira jamais.
ACTION_MAX = 255

_cle_cache = None


def _cle() -> bytes:
    """Cle HMAC, meme cascade que `JournalAudit::cle()` cote PHP.

    Le defaut litteral n'est pas un secret : c'est ce qui permet a une instance
    sans cle dediee de produire une chaine que le portail sait relire. Il est
    identique des deux cotes, et c'est la seule raison de sa presence.
    """
    global _cle_cache
    if _cle_cache is None:
        brute = os.getenv('AUDIT_HMAC_KEY') or os.getenv('SECRET_KEY') or 'rootwarden-audit-default'
        _cle_cache = brute.encode('utf-8')
    return _cle_cache


def empreinte(precedent: str, utilisateur: int, action: str, ts: int) -> str:
    """Reproduit `JournalAudit::empreinte` exactement.

    Toute divergence ici produit une chaine que le portail declare rompue, donc
    un faux positif d'alteration — c'est-a-dire le contraire de ce qu'on veut.
    """
    message = '|'.join([precedent, str(utilisateur), action, str(ts)])
    return hmac.new(_cle(), message.encode('utf-8'), hashlib.sha256).hexdigest()


def journalise(user_id: int, action: str, conn=None) -> bool:
    """Ecrit une ligne CHAINEE dans `user_logs`. Rend True si la ligne est posee.

    :param conn: connexion existante a reutiliser. Si elle est fournie, ce
        module **ne valide pas** — l'appelant garde la main sur sa transaction.
        Sinon une connexion est ouverte, validee et refermee ici.

    ⚠ LE VERROU N'EST PAS UN ORNEMENT. Deux ecritures concurrentes qui lisent la
    tete sans `FOR UPDATE` obtiennent le MEME `prev_hash` et produisent deux
    lignes soeurs : la chaine fourche, et la verification signale une rupture
    la ou il n'y a eu qu'une concurrence. `FOR UPDATE` serialise la lecture de
    la tete avec l'insertion qui la remplace.

    ⚠ ET L'ECHEC NE SE TAIT PAS. Les insertions nues qu'on remplace etaient
    toutes enveloppees d'un `except` muet (`pass`, ou `debug`) : c'est pourquoi
    1484 lignes ont pu se poser hors chaine sans que personne ne le voie
    pendant des mois. Ici l'echec est journalise en WARNING avec sa cause.
    """
    action = (action or '')[:ACTION_MAX]
    ts = int(time.time())
    propre = None
    externe = conn is not None

    try:
        if conn is None:
            from routes.helpers import get_db_connection
            conn = get_db_connection()

        cur = conn.cursor()

        # La tete SAUTE les lignes nues : c'est la semantique deja inscrite en
        # base, et la reproduire est ce qui rend la chaine verifiable par le
        # portail sans traitement particulier.
        cur.execute(
            "SELECT self_hash FROM user_logs "
            "WHERE self_hash IS NOT NULL ORDER BY id DESC LIMIT 1 FOR UPDATE"
        )
        ligne = cur.fetchone()
        precedent = (ligne[0] if ligne and ligne[0] else GENESE)

        propre = empreinte(precedent, int(user_id), action, ts)

        # `created_at` est pose DEPUIS `ts` : l'egalite avec
        # `UNIX_TIMESTAMP(created_at)` devient structurelle au lieu d'etre une
        # coincidence entre deux horloges (celle de Python et celle de MySQL).
        cur.execute(
            "INSERT INTO user_logs (user_id, action, created_at, prev_hash, self_hash) "
            "VALUES (%s, %s, FROM_UNIXTIME(%s), %s, %s)",
            (int(user_id), action, ts, precedent, propre)
        )

        if not externe:
            conn.commit()
        return True

    except Exception as e:
        logger.warning(
            "audit_chain: ligne NON journalisee (user_id=%s action=%.60r) : %s",
            user_id, action, e
        )
        return False

    finally:
        if conn is not None and not externe:
            try:
                conn.close()
            except Exception:
                pass
