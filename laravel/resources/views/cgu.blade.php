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

        <p class="rw-encart">{{ __('auth.socle_avertissement') }}</p>

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
