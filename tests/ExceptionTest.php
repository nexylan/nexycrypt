<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;
use Nexy\NexyCrypt\Exception\AcmeApiException;

class ExceptionTest extends TestCase
{
     public $domain = 'nexycrypt.esy.es';

    /** @test */
    public function acmeApiExceptionTest()
    {
        /*
        * skip the step0 and step1 and do the step2 directly will be throw the AcmeApiException message:
        * [urn:acme:error:unauthorized] Must agree to subscriber agreement before any further actions
        */

        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

        $this->expectException(AcmeApiException::class);

        @unlink(sys_get_temp_dir().'/nexycrypt.private_key');

        $client->register();
        $client->agreeTerms();

        try {
            $authorization = $client->authorize($this->domain);

            $challenge = $authorization->getChallenges()->getHttp01();
        } catch (AcmeApiException $e) {
            throw $e;
        }
    }
}
