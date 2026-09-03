@extends('layouts.socle', ['titre' => __('auth.cgu_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte rw-carte--large">
        <h1 class="rw-titre">{{ __('auth.cgu_titre') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.cgu_sous_titre') }}</p>

        <div class="rw-etapes">
            <div class="rw-etapes__pas rw-etapes__pas--fait">1. {{ __('auth.etape_identifiants') }}</div>
            <div class="rw-etapes__pas rw-etapes__pas--fait">2. {{ __('auth.etape_second_facteur') }}</div>
            <div class="rw-etapes__pas rw-etapes__pas--courant">3. {{ __('auth.etape_acces') }}</div>
        </div>

        {{--
            ══ UN ENCART ANNONCAIT L'ETAT DE LA MIGRATION. RETIRE. ══════════

            Il disait « Seul le socle d'authentification est porte. Les pages du
            portail restent sur l'ancienne interface. »

            Ecrit le 2026-08-17 (`d41d043`), **il etait VRAI ce jour-la**. Le
            menu est passe a 32 entrees portees sur 32 le 2026-09-02 : la phrase
            est fausse depuis SEIZE JOURS, sur l'ecran ou l'on invite quelqu'un a
            accepter des conditions.

            ── POURQUOI ELLE N'EST PAS REMPLACEE PAR SA NEGATION ────────────

            Un ecran n'a pas a annoncer qu'il est porte : une interface qui se
            felicite d'exister est un decor. La phrase avait un sens parce
            qu'elle PREVENAIT d'un manque ; il n'y a plus de manque a prevenir,
            donc plus rien a dire.

            Ecrire « toutes les pages sont portees » recreerait la meme dette —
            **une affirmation d'etat pourrit au prochain changement**, et c'est
            precisement le motif que ce chantier a paye quatre fois en une nuit
            (`pare-feu`, `superv` ×3, et ici).

            Cette page porte les CONDITIONS D'UTILISATION. L'avancement d'un
            chantier interne n'y a pas sa place.
        --}}

        {{-- Deux actions, donc DEUX formulaires cote a cote — jamais imbriques :
             un formulaire dans un formulaire est invalide et le plus interne
             ne part jamais. Refuser a gauche, accepter a droite.

             `data-rw` est le CONTRAT DOM des tests. Un test ancre sur « le
             premier bouton de type submit » est fragile par construction :
             deplacer un bouton l'a fait cliquer « Refuser » au lieu
             d'« Accepter », et il se deconnectait en croyant entrer. --}}
        <div class="rw-actions">
            <form class="rw-inline rw-actions__gauche" method="POST" action="{{ route('deconnexion') }}">
                @csrf
                <button class="rw-bouton rw-bouton--discret" type="submit"
                        data-rw="cgu-refuser">{{ __('auth.cgu_refuser') }}</button>
            </form>
            <form class="rw-inline" method="POST" action="{{ route('cgu.accepter') }}">
                @csrf
                <button class="rw-bouton" type="submit"
                        data-rw="cgu-accepter">{{ __('auth.cgu_accepter') }}</button>
            </form>
        </div>
    </div>
</div>
@endsection
