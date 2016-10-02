<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;

class NexyCryptTest extends TestCase
{
    public $url = 'https://acme-staging.api.letsencrypt.org/';

    public $domain = 'nexycrypt.esy.es';

    /** @test */
    public function createKeyTest()
    {
        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->createKey();

        $this->assertSame(true, file_exists(sys_get_temp_dir().'/nexycrypt.private_key'));
    }

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

        $this->assertSame(true, $result);

        $result = verifyChallengeFail($cryptClient);

        $this->assertSame(false, $result);

        $generateResult = $this->generateCertificateTest($cryptClient);
        $signResult = $this->signCertificateTest($cryptClient, $generateResult);

        foreach ($generateResult->getFilesArray() as $filename => $content) {
            $this->assertSame(true, isset($content));
        }

        foreach ($signResult->getFilesArray() as $filename => $content) {
            $this->assertSame(true, isset($content));
        }

        $resType = $this->getPrivateKeyTest($cryptClient);

        $this->assertSame('object', gettype($resType));
    }

    public function verifyChallengeFail(NexyCrypt $cryptClient)
    {
        $fileName = 'challenge';

        $this->deleteRemoteFile($fileName);

        // the challenge file is not existed.
        $challenge = unserialize(file_get_contents('tests/public/'.'acme-challenge'.'/challenge'));
        $result = $cryptClient->verifyChallenge($challenge);

        $this->assertSame(false, $result);

        $this->addRemoteFile($fileName);
    }

    public function verifyChallengeTest(NexyCrypt $cryptClient)
    {
        $challenge = unserialize(file_get_contents(__DIR__.'/public'.'/acme-challenge'.'/challenge'));
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

    public function deleteRemoteFile($fileName)
    {
        //this web hosting is only for testing, DO NOT use for ypur production!
        // it will be close in the irregular time.

        $connect = ftp_connect($this->ftpServer);
        $result = ftp_login($connect, $this->user, $this->password);

        ftp_pasv($connect, true);

        if($result === false) {
            die('ftp logn is failed.');
        }

        ftp_chdir($connect, $this->wellKnown);
        ftp_chdir($connect, $this->acmeChallenge);

        ftp_delete($connect, $fileName);

        ftp_close($connect);
    }

    public function addRemoteFile($fileName)
    {
        //this web hosting is only for testing, DO NOT use for ypur production!
        // it will be close in the irregular time.

        $connect = ftp_connect($this->ftpServer);
        $result = ftp_login($connect, $this->user, $this->password);

        ftp_pasv($connect, true);

        if($result === false) {
            die('ftp logn is failed.');
        }

        ftp_chdir($connect, $this->wellKnown);
        ftp_chdir($connect, $this->acmeChallenge);

        ftp_put($connect, $fileName, __DIR__.'/public/acme-challenge'.'/'.$fileName, FTP_ASCII);

        ftp_close($connect);
    }

}
