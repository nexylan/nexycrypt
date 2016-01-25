<?php

/*
 * Usage:
 *
 * $ composer install
 * php example.php example.com 1
 * # Copy generated file under public folder on .well-known/acme-challenge folder from you domain webroot.
 * php example.php example.com 2
 * # Get the certificate files on cert folder
 */

use Nexy\NexyCrypt\Authorization\Challenge\Http01Challenge;
use Nexy\NexyCrypt\Client;

require_once __DIR__.'/vendor/autoload.php';

if ($argc < 3) {
    echo 'You have to pass domain and step arguments.'.PHP_EOL;
    exit(1);
}
$domain = $argv[1];
$step = intval($argv[2]);

// First commented line is for production.
//$client = new Client();
$client = new Client(null, 'https://acme-staging.api.letsencrypt.org/directory');

$client->register();
$client->agreeTerms();

if (1 === $step) {
    $authorization = $client->authorize($argv[1]);

    $challenge = $authorization->getChallenges()->getHttp01();

    @mkdir('public');
    file_put_contents('public/'.$challenge->getFileName(), $challenge->getFileContent());
    file_put_contents('challenge', serialize($challenge));
}

if (2 === $step) {
    /** @var Http01Challenge $challenge */
    $challenge = unserialize(file_get_contents('challenge'));

    $client->verifyChallenge($challenge);

    $certificate = $client->generateCertificate([$domain]);
    $certificate = $client->signCertificate($certificate);

    @mkdir('cert');
    foreach ($certificate->getFilesArray() as $filename => $content) {
        file_put_contents('cert/'.$filename, $content);
    }
}
