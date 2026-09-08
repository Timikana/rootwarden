"""
iptables_manager.py - Gestion des règles iptables/ip6tables pour RootWarden.

Rôle :
    Lecture et application des règles iptables (IPv4 et IPv6) sur des serveurs
    distants via SSH. Toute écriture de règles passe par un encodage base64 afin
    d'éliminer le risque d'injection de commandes shell.

Dépendances clés :
    - ssh_utils.execute_as_root  : exécution de commandes en tant que root via SSH
    - encryption.Encryption      : déchiffrement des mots de passe stockés en BDD
    - config.Config              : paramètres globaux de l'application

Note de sécurité :
    L'écriture des règles dans les fichiers distants utilise exclusivement base64
    (fonction _write_rules_safe) pour éviter tout risque d'injection via les
    caractères spéciaux présents dans les règles iptables.
"""

import base64
import logging
import secrets
import re
import shlex

from config import Config
from encryption import Encryption
from ssh_utils import (
    connect_ssh,
    ssh_session,
    execute_as_root,
    clean_output,
)

_log = logging.getLogger(__name__)

# Instance partagée du moteur de chiffrement/déchiffrement
encryptor = Encryption()


def decrypt_password(encrypted_password: str) -> str:
    """
    Déchiffre un mot de passe chiffré via la classe Encryption.

    Args:
        encrypted_password: Mot de passe chiffré tel que stocké en base de données.

    Returns:
        Le mot de passe en clair, ou une chaîne vide en cas d'erreur ou de valeur nulle.
    """
    if not encrypted_password:
        return ""
    try:
        return encryptor.decrypt_password(encrypted_password)
    except Exception as e:
        _log.error("Erreur déchiffrement iptables_manager : %s", e)
        return ""


# ---------------------------------------------------------------------------
# Lecture des règles
# ---------------------------------------------------------------------------

def get_iptables_rules(client, root_password: str) -> dict:
    """
    Récupère les règles iptables actives (IPv4 + IPv6) et les fichiers rules.v4/v6.

    Exécute quatre commandes en root via SSH :
      - ``iptables -L -v -n``           → règles IPv4 en mémoire
      - ``ip6tables -L -v -n``          → règles IPv6 en mémoire (ou message si absent)
      - ``cat /etc/iptables/rules.v4``  → règles IPv4 persistées sur disque
      - ``cat /etc/iptables/rules.v6``  → règles IPv6 persistées sur disque

    Args:
        client:        Client SSH Paramiko connecté au serveur cible.
        root_password: Mot de passe root en clair pour l'élévation de privilèges.

    Returns:
        dict avec les clés :
            - current_rules_v4 (str) : règles IPv4 actives
            - current_rules_v6 (str) : règles IPv6 actives
            - file_rules_v4    (str) : contenu de /etc/iptables/rules.v4
            - file_rules_v6    (str) : contenu de /etc/iptables/rules.v6

    Raises:
        Exception: Re-lève toute exception SSH ou d'exécution après l'avoir loguée.
    """
    try:
        _log.info("Récupération des règles iptables.")
        rules_v4, _, _   = execute_as_root(client, "iptables -L -v -n", root_password)
        rules_v6, _, _   = execute_as_root(client,
            "ip6tables -L -v -n 2>/dev/null || echo 'No IPv6 rules'", root_password)
        file_v4, _, _    = execute_as_root(client,
            "cat /etc/iptables/rules.v4 2>/dev/null || echo ''", root_password)
        file_v6, _, _    = execute_as_root(client,
            "cat /etc/iptables/rules.v6 2>/dev/null || echo 'No IPv6 rules'", root_password)
        return {
            "current_rules_v4": rules_v4,
            "current_rules_v6": rules_v6,
            "file_rules_v4":    file_v4,
            "file_rules_v6":    file_v6,
        }
    except Exception as e:
        _log.error("get_iptables_rules : %s", e)
        raise


# ---------------------------------------------------------------------------
# Application des règles
# ---------------------------------------------------------------------------

def _write_rules_safe(client, root_password: str, rules: str, dest_path: str) -> None:
    """
    Écrit des règles iptables dans un fichier distant via encodage base64.

    L'encodage base64 garantit qu'aucun caractère spécial contenu dans les règles
    ne peut être interprété comme une commande shell (anti-injection).
    La commande distante décode le base64 puis redirige vers le fichier cible.

    ⚠ CE QUE LE BASE64 PROTÈGE, ET CE QU'IL NE PROTÈGE PAS
    ------------------------------------------------------
    Il protège ``rules``. **Il n'a jamais protégé ``dest_path``**, qui était
    interpolé BRUT dans une commande exécutée en root — et le paragraphe
    ci-dessus se lit comme s'il couvrait toute la commande. *Un commentaire qui
    ratifie le défaut est pire qu'un défaut sans commentaire : il fait passer la
    relecture suivante à côté.*

    ``rules``     sûr par CONSTRUCTION  (base64, aucun caractère ne survit)
    ``dest_path`` sûr par CONVENTION    (les deux appelants passent un littéral)

    **Une sûreté par convention tient tant que personne n'ajoute d'appelant.**
    Or I5 — application et retour arrière — est précisément le sous-lot qui en
    ajoute, et toute fonctionnalité qui *dérive* une destination (sauvegarde
    nommée, fichier d'attente, chemin par machine) transformerait ce paramètre
    en **injection de commande root**.

    ``shlex.quote`` referme la classe AVANT que le premier appelant dérivé
    n'existe. Sur les deux chemins littéraux actuels il ne change rien : ils ne
    portent aucun caractère à échapper, et la commande produite est identique.

    Args:
        client:        Client SSH Paramiko connecté au serveur cible.
        root_password: Mot de passe root en clair pour l'élévation de privilèges.
        rules:         Contenu des règles iptables à écrire (texte brut).
        dest_path:     Chemin absolu du fichier de destination sur le serveur distant.
    """
    encoded = base64.b64encode(rules.encode('utf-8')).decode('ascii')
    execute_as_root(client,
        f"printf '%s' '{encoded}' | base64 -d > {shlex.quote(dest_path)}",
        root_password)


def _charge_puis_ecrit(client, root_password: str, rules: str,
                       dest_path: str, restore_cmd: str) -> None:
    """VALIDE d'abord, INSTALLE ensuite. Leve `RuntimeError` sur tout echec.

    ══ SEC-017 : L'ORDRE ETAIT ECRIRE PUIS CHARGER, ET L'ECHEC ETAIT MUET ══════

    L'ancienne sequence ecrasait `rules.v4` — le fichier de DEMARRAGE — puis
    lancait `iptables-restore` **en jetant son code de retour**, et journalisait
    « appliquees avec succes » de facon INCONDITIONNELLE. Un jeu illisible
    laissait donc :

        le noyau     ses anciennes regles       -> la machine a l'air saine
        le disque    le jeu qui ne charge pas   -> au prochain REDEMARRAGE elle
                                                   se releve SANS PARE-FEU
        l'appelant   un succes                  -> personne ne relie l'incident
                                                   au changement

    Le defaut ne se manifestait pas au moment du geste mais des SEMAINES plus
    tard, deconnecte de sa cause. *Specification : `3128e1d2`.*

    ══ CINQ CONTROLES, ET CHACUN INSPECTE SON CODE DE SORTIE ══════════════════

    Aucun appel de ce fichier ne regardait un code de retour — le mot `code` n'y
    figurait pas une seule fois. **Il n'y avait donc aucun motif correct a imiter
    ICI : le traitement juste est INTRODUIT, pas copie.** *Le dessin vient de
    `sudo_manager` — valider un temporaire, n'installer qu'apres — mais trois de
    ses pieces ne se recopient pas.*

    ══ LES TROIS PIEGES DU MODELE ═════════════════════════════════════════════

    1. `sudo_manager._write_to_remote` JETTE sa valeur de retour. Si l'ecriture
       echoue partiellement, la validation porte sur un temporaire tronque — et
       une validation de syntaxe sur un fichier VIDE REUSSIT. *Le modele est bon
       dans son ORDRE et incomplet dans son PREMIER PAS.* D'ou le controle 2 bis
       ci-dessous, qui n'existe pas dans le modele.
    2. Le mode est **0640**, pas 0440. *`rules.v4` est a 0640 aujourd'hui ;
       `sudo_manager` emploie 0440 parce que `sudoers` l'EXIGE. Copier le mode
       changerait les droits en croyant copier le dessin.*
    3. Le temporaire vit dans **`/etc/iptables/`**, pas dans `/tmp`. *`mv` n'est
       atomique que sur le MEME systeme de fichiers ; `/tmp` et `/etc` peuvent
       etre des montages distincts, et le `mv` degenererait en copie — donc en
       fenetre ou le fichier de demarrage est incomplet.*

    ⚠ **Le temoin qui prouve la propriete porte sur l'EMPREINTE, pas sur le code
    rendu** : `md5sum` de la cible avant, appliquer un jeu illisible, `md5sum`
    apres — il DOIT etre identique. *Un correctif qui rendrait un echec en ayant
    quand meme ecrit passerait un test qui ne lit que le code de retour.*
    """
    rand = secrets.token_hex(8)
    tmp = f"/etc/iptables/.rootwarden-ipt-{rand}.tmp"
    try:
        # 1. Mode et proprietaire poses A LA CREATION : aucune fenetre ou le
        #    fichier existe avec des droits plus larges.
        # nosemgrep: rw-shell-fstring-execute-as-root
        out, err, code = execute_as_root(
            client, f"install -m 0640 -o root -g root /dev/null {tmp}",
            root_password, timeout=10)
        if code != 0:
            # `err or out` : le transport `su` fusionne parfois stderr dans stdout,
            # et un refus qui nomme l'etape sans la CAUSE n'instruit pas.
            raise RuntimeError(
                f"creation du temporaire impossible (code {code}) : "
                f"{((err or out) or 'aucune sortie').strip()[:200]}")

        # 2. Ecrire dans le TEMPORAIRE, jamais dans la cible a ce stade.
        _write_rules_safe(client, root_password, rules, tmp)

        # 2 bis. VERIFIER que l'ecriture a abouti — le pas que le modele omet.
        #        Une validation de syntaxe sur un fichier vide ne dirait rien :
        #        un jeu vide est syntaxiquement valide.
        # nosemgrep: rw-shell-fstring-execute-as-root
        out, err, code = execute_as_root(
            client, f"wc -c < {tmp}", root_password, timeout=10)
        if code != 0 or not out.strip().isdigit() or int(out.strip()) == 0:
            raise RuntimeError("le temporaire est vide ou illisible apres ecriture")

        # 3. VALIDER. En cas d'echec la cible n'a PAS ete touchee.
        # nosemgrep: rw-shell-fstring-execute-as-root
        out, err, code = execute_as_root(
            client, f"{restore_cmd} --test < {tmp}", root_password, timeout=20)
        if code != 0:
            raise RuntimeError(
                f"jeu de regles refuse par {restore_cmd} --test : {(err or out)[:300]}")

        # ══ 4. CHARGER DEPUIS LE TEMPORAIRE — et c'est l'ordre qui compte ═══
        #
        # ⚠ CORRECTION DE LA SPECIFICATION, ETABLIE PAR LE TEMOIN SUR LA MACHINE 3.
        # Elle listait : `--test`, puis `mv`, puis charger. Son TITRE disait
        # « charger puis ecrire » et ses etapes faisaient l'inverse ; j'ai
        # implemente les etapes, et le temoin a refuse.
        #
        # Mesure du 2026-09-08, jeu `-A INPUT -j CETTE_CIBLE_NEXISTE_PAS` :
        #
        #     iptables-restore --test < tmp   ->  code 0   ACCEPTE
        #     iptables-restore     < tmp      ->  code 2   REFUSE
        #
        # **`--test` valide l'ANALYSE, pas l'existence des cibles.** Un jeu qui
        # passe `--test` peut donc echouer au chargement reel — et si le `mv` a
        # eu lieu entre les deux, le fichier de DEMARRAGE porte deja le jeu qui
        # ne charge pas. C'etait exactement SEC-017, reintroduit par un correctif
        # qui suivait une specification contredisant son propre titre.
        #
        # Le seul gage suffisant est le chargement REEL. On charge donc depuis le
        # temporaire, et on n'installe qu'apres.
        # nosemgrep: rw-shell-fstring-execute-as-root
        out, err, code = execute_as_root(
            client, f"{restore_cmd} < {tmp}", root_password, timeout=30)
        if code != 0:
            raise RuntimeError(
                f"{restore_cmd} a refuse le jeu (code {code}) : "
                f"{((err or out) or 'aucune sortie').strip()[:300]} "
                f"— {dest_path} est INTACT")

        # ══ 5. INSTALLER, une fois le chargement PROUVE ══════════════════════
        # `mv` sur le meme systeme de fichiers : atomique. A ce stade le noyau
        # porte deja ces regles, donc le fichier de demarrage ne peut plus
        # diverger du comportement observe.
        # nosemgrep: rw-shell-fstring-execute-as-root
        out, err, code = execute_as_root(
            client,
            f"mv {tmp} {dest_path} && chown root:root {dest_path} "
            f"&& chmod 0640 {dest_path}",
            root_password, timeout=10)
        if code != 0:
            raise RuntimeError(
                f"regles CHARGEES mais installation de {dest_path} impossible "
                f"(code {code}) : {((err or out) or 'aucune sortie').strip()[:200]} "
                f"— le noyau et le fichier de demarrage DIVERGENT")
        _log.info("%s : valide, installe et charge.", dest_path)
    finally:
        # Le temporaire ne survit jamais, meme sur un chemin d'exception. Apres un
        # `mv` reussi il n'existe plus : `rm -f` est alors sans effet.
        # nosemgrep: rw-shell-fstring-execute-as-root
        execute_as_root(client, f"rm -f {tmp}", root_password, timeout=10)


def apply_iptables_rules(client, root_password: str,
                         rules_v4: str, rules_v6: str = None) -> None:
    """
    Applique des règles iptables sur un serveur distant.

    Séquence d'opérations :
      1. Crée les fichiers rules.v4 et rules.v6 si absents (touch + chmod 640).
      2. Écrit les règles IPv4 via _write_rules_safe (encodage base64).
      3. Recharge les règles IPv4 en mémoire via ``iptables-restore``.
      4. Si rules_v6 est fourni, même traitement pour IPv6.

    Args:
        client:        Client SSH Paramiko connecté au serveur cible.
        root_password: Mot de passe root en clair pour l'élévation de privilèges.
        rules_v4:      Règles IPv4 au format iptables-save (texte brut).
        rules_v6:      Règles IPv6 au format ip6tables-save (optionnel).

    Raises:
        Exception: Re-lève toute exception SSH ou d'exécution après l'avoir loguée.
    """
    try:
        _log.info("Application des règles iptables.")

        _charge_puis_ecrit(client, root_password, rules_v4,
                           "/etc/iptables/rules.v4", "iptables-restore")

        if rules_v6:
            _charge_puis_ecrit(client, root_password, rules_v6,
                               "/etc/iptables/rules.v6", "ip6tables-restore")

        _log.info("Règles iptables appliquées avec succès.")
    except Exception as e:
        _log.error("apply_iptables_rules : %s", e)
        raise
