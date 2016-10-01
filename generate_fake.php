<?php

//generate the fake .well-known folder and upload the folder to the testing web hosting.

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

    if(1 === $step) {
        $client->register();
        $client->agreeTerms();
    }

    if (2 === $step) {
        $client->register();
        $client->agreeTerms();

        @mkdir('tests/public');

        foreach ($domains as $domain) {
            $authorization = $client->authorize($domain);

            $challenge = $authorization->getChallenges()->getHttp01();

            @mkdir('tests/public/acme-challenge');
            file_put_contents('tests/public/'.'acme-challenge'.'/'.$challenge->getFileName(), $challenge->getFileContent());
            file_put_contents('tests/public/'.'acme-challenge'.'/challenge', serialize($challenge));
        }
    }

    exit(0);
} catch (AcmeApiException $e) {
    var_dump($e->getDetails());

    exit(1);
}
