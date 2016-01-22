<?php

use Nexy\NexyCrypt\Authorization\Challenge\Http01Challenge;
use Nexy\NexyCrypt\Client;

require_once __DIR__.'/vendor/autoload.php';

if ($argc < 3) {
    echo 'You have to pass domain and step arguments.'.PHP_EOL;
    exit(1);
}
$domain = $argv[1];
$step = intval($argv[2]);

$client = new Client();

$client->register();
$client->agreeTerms();

if (1 === $step) {
    $authorization = $client->authorize($argv[1]);
    dump($authorization);

    $challenge = $authorization->getChallenges()->getHttp01();

    @mkdir('public');
    file_put_contents('public/'.$challenge->getFileName(), $challenge->getFileContent());
    file_put_contents('challenge', serialize($challenge));
}

if (2 === $step) {
    /** @var Http01Challenge $challenge */
    $challenge = unserialize(file_get_contents('challenge'));
    dump($challenge);
}
