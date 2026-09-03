"""
reboot-garde.py - Etat des gardes qui entourent le redemarrage d'une machine.

Sert au test de caracterisation du sous-lot U5. Il ne touche AUCUNE machine : il
lit et nettoie uniquement la base partagee.

Trois choses comptent avant de cliquer sur « Redemarrer » :

  1. Aucune demande d'approbation APPROUVEE ne doit exister pour la machine et
     le demandeur. `approvals.gate()` la consommerait et le redemarrage partirait
     pour de bon. Le test s'arrete si c'est le cas — il ne clique pas.
  2. Le nombre de traces `command_log` de contexte « reboot » est releve avant et
     apres : il n'est ecrit qu'APRES l'execution SSH. S'il n'a pas bouge, la
     commande n'est jamais partie. C'est cette meme trace qui a garde la memoire
     des deux redemarrages joues par erreur le 2026-08-18.
  3. La demande creee par le test est effacee a la fin, si elle est encore en
     attente — le test rend la base telle qu'il l'a trouvee.

Usage (depuis l'hote) :
    docker exec -i rootwarden_python python - etat <machine_id>
    docker exec -i rootwarden_python python - derniere-demande <machine_id> <user_id>
    docker exec -i rootwarden_python python - oublie-demande <request_id>
  avec le contenu de ce fichier sur l'entree standard.
"""
import sys

sys.path.insert(0, '/app')

from routes.helpers import get_db_connection  # noqa: E402

ACTION = 'reboot_server'


def etat(machine_id):
    """approuvees|en_attente|traces_reboot — les trois nombres qui comptent."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM approval_requests "
            "WHERE action_type = %s AND machine_id = %s AND status = 'approved'",
            (ACTION, machine_id))
        approuvees = cur.fetchone()[0]
        cur.execute(
            "SELECT COUNT(*) FROM approval_requests "
            "WHERE action_type = %s AND machine_id = %s AND status = 'pending'",
            (ACTION, machine_id))
        attente = cur.fetchone()[0]
        cur.execute(
            "SELECT COUNT(*) FROM command_log WHERE context = 'reboot' AND machine_id = %s",
            (machine_id,))
        traces = cur.fetchone()[0]
    print('%d|%d|%d' % (approuvees, attente, traces))


def derniere_demande(machine_id, user_id):
    """id|status de la derniere demande de redemarrage de ce demandeur."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, status FROM approval_requests "
            "WHERE action_type = %s AND machine_id = %s AND requested_by = %s "
            "ORDER BY id DESC LIMIT 1",
            (ACTION, machine_id, user_id))
        ligne = cur.fetchone()
    print('%d|%s' % (ligne[0], ligne[1]) if ligne else 'AUCUNE')


def oublie_demande(request_id):
    """Efface la demande SI elle est encore en attente. Jamais une autre."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM approval_requests WHERE id = %s AND action_type = %s AND status = 'pending'",
            (request_id, ACTION))
        efface = cur.rowcount
        conn.commit()
    print('EFFACEE' if efface else 'INTACTE')


def main():
    action = sys.argv[1]
    if action == 'etat':
        etat(int(sys.argv[2]))
    elif action == 'derniere-demande':
        derniere_demande(int(sys.argv[2]), int(sys.argv[3]))
    elif action == 'oublie-demande':
        oublie_demande(int(sys.argv[2]))
    else:
        print('ACTION INCONNUE')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
