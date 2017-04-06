<?php

/*
 * Usage:
 *
 * $ composer install
 * $ php issue.php
 */

use Nexy\NexyCrypt\Authorization\Challenge\Http01Challenge;
use Nexy\NexyCrypt\Exception\AcmeApiException;
use Nexy\NexyCrypt\NexyCrypt;

require_once __DIR__.'/vendor/autoload.php';

$domain = 'bad..domain.com';

// First commented line is for production.
//$client = new NexyCrypt();
$client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

try {
    $client->register();
    $client->agreeTerms();

    $authorization = $client->authorize($domain);
} catch (AcmeApiException $e) {
    dump($e->getDetails());

    exit(1);
}
