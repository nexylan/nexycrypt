<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;
use Nexy\NexyCrypt\PrivateKey;
use Nexy\NexyCrypt\Exception\AcmeApiException;

final class NexyCryptTest extends TestCase
{
    public $url = 'https://acme-staging.api.letsencrypt.org/';

    public $domain = 'nexycrypt.esy.es';

    public $keyPath = '/nexycrypt.private_key';

    /** @test */
    public function createTest()
    {
        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->create();

        $this->assertSame(true, file_exists(sys_get_temp_dir().$this->keyPath));
    }

    /** @test */
    public function registerTest()
    {
        // have no own private key
        $cryptClient = new NexyCrypt(null, $this->url);
        $response = $cryptClient->register();

        $this->assertSame(null, $response);

        // have own private key
        $cryptClient = new NexyCrypt('./account.key', $this->url);
        $response = $cryptClient->register();

        $this->assertNull($response);
    }

    /** @test */
    public function agreeTermsTest()
    {
        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->register();
        $response = $cryptClient->agreeTerms();

        $this->assertNull($response);
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

        $this->assertTrue(isset($checkFileName));
        $this->assertTrue(isset($checkFileContent));

        $result = $this->verifyChallengeTest($cryptClient);

        $this->assertTrue($result);

        $generateResult = $this->generateCertificateTest($cryptClient);
        $signResult = $this->signCertificateTest($cryptClient, $generateResult);

        foreach ($generateResult->getFilesArray() as $filename => $content) {
            $this->assertTrue(isset($content));
        }

        foreach ($signResult->getFilesArray() as $filename => $content) {
            $this->assertTrue(isset($content));
        }

        $resType = $this->getPrivateKeyTest($cryptClient);

        $this->assertInstanceOf(PrivateKey::class, $resType);
    }

    /*
    * when the nexycrypt.private_key is missing, we skip the step0 and step1 then do the step2 directly will throw the AcmeApiException message:
    * [urn:acme:error:unauthorized] Must agree to subscriber agreement before any further actions
    */
    /** @test */
    public function acmeApiExceptionTest()
    {
        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

        $this->expectException(AcmeApiException::class);

        @unlink(sys_get_temp_dir().$this->keyPath);

        $client->register();
        $client->agreeTerms();

        try {
            $authorization = $client->authorize($this->domain);

            $challenge = $authorization->getChallenges()->getHttp01();
        } catch (AcmeApiException $e) {
            throw $e;
        }
    }

    /*
    * when the nexycrypt.private_key is missing, we skip the step0 and step1 then do the step2 directly will throw the AcmeApiException message:
    * [urn:acme:error:unauthorized] Must agree to subscriber agreement before any further actions
    */
    /** @test */
    public function weakKeyTest()
    {
        $client = new NexyCrypt('tests/account.key', 'https://acme-staging.api.letsencrypt.org/');

        $this->expectException(AcmeApiException::class);

        $client->register();
        $client->agreeTerms();

        try {
            $authorization = $client->authorize($this->domain);

            $challenge = $authorization->getChallenges()->getHttp01();
        } catch (AcmeApiException $e) {
            throw $e;
        }
    }

    public function verifyChallengeTest(NexyCrypt $cryptClient)
    {
        $challenge = unserialize(file_get_contents(__DIR__.'/'.'public'.'/acme-challenge'.'/challenge'));
        $response = $cryptClient->verifyChallenge($challenge);

        return $response;
    }

    public function generateCertificateTest(NexyCrypt $certClient)
    {
        $certificate = $certClient->generateCertificate([$this->domain]);

        return $certificate;

    }

    public function signCertificateTest(NexyCrypt $certClient, $generateResult)
    {
        $certificate = $certClient->signCertificate($generateResult);

        return $certificate;
    }

    public function getPrivateKeyTest(NexyCrypt $cryptClient)
    {
        $result = $cryptClient->getPrivateKey();

        return $result;
    }

    public function getFtpAccount()
    {
         $accounts = json_decode(file_get_contents('tests/ftpserver.json'), true);

         return $accounts;
    }

}
