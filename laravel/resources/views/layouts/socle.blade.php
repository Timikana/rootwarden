<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{-- Jeton CSRF : la passerelle est dans le groupe `web`, toute requete
         mutante doit le porter (en-tete X-CSRF-TOKEN). --}}
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ $titre ?? config('app.name') }} · {{ config('app.name') }}</title>
    {{-- ?v=<horodatage> : sans cela un navigateur sert indefiniment l'ancienne feuille. --}}
    <link rel="stylesheet" href="/css/rw.css?v={{ @filemtime(public_path('css/rw.css')) ?: '0' }}">
</head>
<body>
@yield('corps')
</body>
</html>
