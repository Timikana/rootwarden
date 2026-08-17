@extends('layouts.socle', ['titre' => __('auth.cgu_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte rw-carte--large">
        <h1 class="rw-titre">{{ __('auth.cgu_titre') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.socle_avertissement') }}</p>

        <form method="POST" action="{{ route('cgu.accepter') }}">
            @csrf
            <button class="rw-bouton" type="submit">{{ __('auth.cgu_accepter') }}</button>
        </form>
    </div>
</div>
@endsection
