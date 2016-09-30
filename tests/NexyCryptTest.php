<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;

class NexyCryptTest extends TestCase
{
    public $url = 'https://acme-staging.api.letsencrypt.org/';

    public $domain = 'nexycrypt.lionfee.net';

    /** @test */
    public function registerTest()
    {
        //have no own private key

        $cryptClient = new NexyCrypt(null, $this->url);
        $response = $cryptClient->register();

        $this->assertSame(null, $response);

        //have own private key

        $cryptClient = new NexyCrypt('./account.key', $this->url);
        $response = $cryptClient->register();

        $this->assertSame(null, $response);
    }

    /** @test */
    public function agreeTermsTest()
    {
        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->register();
        $response = $cryptClient->agreeTerms();

        $this->assertSame(null, $response);
    }

    /** @test */
    public function authorizeTest()
    {
        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->register();
        $cryptClient->agreeTerms();
        $response = $cryptClient->authorize($this->domain);
        $challenge = $response->getChallenges()->getHttp01();
        $checkFileName = $challenge->getFileName();
        $checkFileContent = $challenge->getFileContent();

        $this->assertSame(true, isset($checkFileName));
        $this->assertSame(true, isset($checkFileContent));

        $this->verifyChallengeTest($cryptClient);
    }

    public function verifyChallengeTest(NexyCrypt $cryptClient)
    {
        $challenge = unserialize(file_get_contents(__DIR__.'/public'.'/acme-challenge'.'/challenge'));
        $response = $cryptClient->verifyChallenge($challenge);

        if($response) {
            $this->assertSame(true, $response);
        } else {
            //you got the failure and make sure you have run the generate_fake.php before running unit testing

            $this->fail();
        }
    }

    /** @test */
    public function generateCertificateTest()
    {

    }

    /** @test */
    public function signCertificateTest()
    {

    }

    /** @test */
    public function getPrivateKeyTest()
    {

    }

}
