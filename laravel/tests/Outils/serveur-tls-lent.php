<?php
/**
 * Serveur HTTPS/1.1 minimal pour `RelaisFluxTest` : UNE reponse en
 * `Transfer-Encoding: chunked`, un morceau « debut », une pause, puis « fin ».
 *
 * Il reproduit ce qui fait bloquer `read(8192)` : TLS. Le meme echange en HTTP
 * clair, chunked ou non, rend « debut » tout de suite.
 *
 * Usage : php serveur-tls-lent.php <pause en microsecondes>
 * Imprime « pret <port> » quand il ecoute (port choisi par le systeme).
 */
$cle = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$cert = openssl_csr_sign(openssl_csr_new(['commonName' => '127.0.0.1'], $cle), null, $cle, 1);
openssl_x509_export($cert, $pemCert);
openssl_pkey_export($cle, $pemCle);
$pem = tempnam(sys_get_temp_dir(), 'tls');
file_put_contents($pem, $pemCert . $pemCle);

$ctx = stream_context_create(['ssl' => ['local_cert' => $pem, 'allow_self_signed' => true, 'verify_peer' => false]]);
$serveur = stream_socket_server('tls://127.0.0.1:0', $errno, $err,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if ($serveur === false) {
    fwrite(STDERR, "ecoute impossible : $err\n");
    exit(1);
}
$port = (int) substr(strrchr(stream_socket_get_name($serveur, false), ':'), 1);
fwrite(STDOUT, "pret $port\n");
fflush(STDOUT);

$client = stream_socket_accept($serveur, 20);
if ($client !== false) {
    while (($ligne = fgets($client)) !== false && rtrim($ligne) !== '') {
    }
    fwrite($client, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n");
    fwrite($client, "6\r\ndebut\n\r\n");
    usleep((int) ($argv[1] ?? 1500000));
    @fwrite($client, "4\r\nfin\n\r\n0\r\n\r\n");
    fclose($client);
}
unlink($pem);
