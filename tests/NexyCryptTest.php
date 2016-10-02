<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;

class NexyCryptTest extends TestCase
{
    public $url = 'https://acme-staging.api.letsencrypt.org/';

    public $domain = 'nexycrypt.esy.es';

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

        $result = $this->verifyChallengeTest($cryptClient);

        if($result) {
            $this->assertSame(true, $result);
        } else {
            //you got the failure and make sure you have run the generate_fake.php correctly before running unit testing

            $this->fail();
        }

        $generateResult = $this->generateCertificateTest($cryptClient);
        $signResult = $this->signCertificateTest($cryptClient);

        foreach ($generateResult->getFilesArray() as $filename => $content) {
            $this->assertSame(true, isset($content));
        }

        foreach ($signResult->getFilesArray() as $filename => $content) {
            $this->assertSame(true, isset($content));
        }

        $resType = $this->getPrivateKeyTest($cryptClient);

        $this->assertSame('object', gettype($resType));
    }

    public function verifyChallengeTest(NexyCrypt $cryptClient)
    {
        $challenge = unserialize(file_get_contents(__DIR__.'/public'.'/acme-challenge'.'/challenge'));
        $response = $cryptClient->verifyChallenge($challenge);

        return $response;
    }

    public function generateCertificateTest(NexyCrypt $certClient)
    {
        $certificate = $certClient->generateCertificate($this->domain);

        return $certificate;

    }

    public function signCertificateTest(NexyCrypt $certClient)
    {
        $certificate = $certClient->generateCertificate($this->domain);

        return $certificate;
    }

    public function getPrivateKeyTest(NexyCrypt $cryptClient)
    {
        $result = $cryptClient->getPrivateKey();

        return $result;
    }

}
