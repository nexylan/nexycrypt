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
use Nexy\NexyCrypt\Exception\AcmeApiException;
use Nexy\NexyCrypt\NexyCrypt;

require_once __DIR__.'/vendor/autoload.php';

if ($argc < 3) {
    echo 'You have to pass domain and step arguments.'.PHP_EOL;
    exit(1);
}

$domains = [];
for ($a = 1; $a < $argc - 1; ++$a) {
    $domains[] = $argv[$a];
}
$step = intval($argv[$a]);

// First commented line is for production.
//$client = new NexyCrypt();
$client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

try {
    if (0 === $step) {
        //create the required account private key
        $client->createKey();
    }

    if (1 === $step) {
        $client->register();
        $client->agreeTerms();
    }

    if (2 === $step) {
        @mkdir('public');

        foreach ($domains as $domain) {
            $authorization = $client->authorize($domain);

            $challenge = $authorization->getChallenges()->getDns01();

            echo sprintf('Record Name: %s.%s', $challenge->getRecordName(), $domain).PHP_EOL;
            echo sprintf('Record Type: %s', $challenge->getRecordType()).PHP_EOL;
            echo sprintf('Record Content: %s', $challenge->getRecordContent()).PHP_EOL;

            @mkdir('public/'.$domain);
            file_put_contents('public/'.$domain.'/challenge', serialize($challenge));
        }
    }

    if (3 === $step) {
        foreach ($domains as $domain) {
            /** @var Http01Challenge $challenge */
            $challenge = unserialize(file_get_contents('public/'.$domain.'/challenge'));

            if (false === $client->verifyChallenge($challenge)) {
                echo sprintf('Invalid challenge for %s', $domain).PHP_EOL;
            };
        }

        @mkdir('cert');

        $certificate = $client->generateCertificate($domains);
        foreach ($certificate->getFilesArray() as $filename => $content) {
            file_put_contents('cert/'.$filename, $content);
        }

        $certificate = $client->signCertificate($certificate);
        foreach ($certificate->getFilesArray() as $filename => $content) {
            file_put_contents('cert/'.$filename, $content);
        }
    }
} catch (AcmeApiException $e) {
    dump($e->getDetails());

    exit(1);
}
