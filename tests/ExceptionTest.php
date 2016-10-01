<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;

class ExceptionTest extends TestCase
{
    /** @test */
    public function acmeApiExceptionTest()
    {
        //.well-known is not existed in your specified web document root file path

        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

        $this->expectException(\Nexy\NexyCrypt\Exception\AcmeApiException::class);

        try {
            //$client->register();
            //$client->agreeTerms();
            $challenge = unserialize(file_get_contents('public/'.$domain.'/challenge'));
            $client->verifyChallenge($challenge);
        } catch (AcmeApiException $e) {
            throw $e;
        }
    }
}
