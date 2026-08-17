<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $titre ?? config('app.name') }} · {{ config('app.name') }}</title>
    {{-- ?v=<horodatage> : sans cela un navigateur sert indefiniment l'ancienne feuille. --}}
    <link rel="stylesheet" href="/css/rw.css?v={{ @filemtime(public_path('css/rw.css')) ?: '0' }}">
</head>
<body>
@yield('corps')
</body>
</html>
