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

use Nexy\NexyCrypt\Authorization\Challenge\Dns01Challenge;
use Nexy\NexyCrypt\Exception\AcmeApiException;
use Nexy\NexyCrypt\NexyCrypt;

require_once __DIR__.'/vendor/autoload.php';

$domains = [];
for ($a = 1; $a < $argc; ++$a) {
    $domains[] = $argv[$a];
}

// First commented line is for production.
//$client = new NexyCrypt();
$client = new NexyCrypt(null, 'https://acme-staging-v02.api.letsencrypt.org/');

try {
    $client->register();

    if (!empty($domains)) {
        @mkdir('public');

        $order = $client->order($domains);

        foreach ($order->getAuthorizations() as $authorization) {
            $challenge = $authorization->getChallenges()->getDns01();

            echo sprintf('Record Name: %s.%s', $challenge->getRecordName(), $authorization->getIdentifier()->getValue()).PHP_EOL;
            echo sprintf('Record Type: %s', $challenge->getRecordType()).PHP_EOL;
            echo sprintf('Record Content: %s', $challenge->getRecordContent()).PHP_EOL;
        }

        file_put_contents('public/order', serialize($order));
        file_put_contents('public/domains', serialize($domains));
    } else {
        /** @var \Nexy\NexyCrypt\Authorization\Order $order */
        $order = unserialize(file_get_contents('public/order'));
        $domains = unserialize(file_get_contents('public/domains'));

        $allGood = true;
        foreach ($order->getAuthorizations() as $authorization) {
            $challenge = $authorization->getChallenges()->getDns01();
            $client->verifyChallenge($challenge);
        }

        if (!$allGood) {
            return;
        }


        @mkdir('cert');

        $certificate = $client->generateCertificate($domains);
        $client->finalize($order, $certificate);
        foreach ($certificate->getFilesArray() as $filename => $content) {
            file_put_contents('cert/'.$filename, $content);
        }
    }
} catch (AcmeApiException $e) {
    dump($e->getDetails());

    exit(1);
}
