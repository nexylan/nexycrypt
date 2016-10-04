<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;
use Nexy\NexyCrypt\PrivateKey;
use Nexy\NexyCrypt\Certificate;
use Nexy\NexyCrypt\Exception\AcmeApiException;
use Nexy\NexyCrypt\Authorization\Authorization;
use Nexy\NexyCrypt\Authorization\Identifier;
use Nexy\NexyCrypt\Authorization\Challenge;
use Nexy\NexyCrypt\Authorization\Challenge\Http01Challenge;
use Nexy\NexyCrypt\Authorization\Challenge\Dns01Challenge;
use Nexy\NexyCrypt\Authorization\Challenge\TlsSni01Challenge ;
use Nexy\NexyCrypt\Authorization\Challenge\ChallengeInterface;
use Nexy\NexyCrypt\Authorization\Challenge\ChallengeFactory;
use Nexy\NexyCrypt\Authorization\Challenge\ChallengeCollection;

final class NexyCryptTest extends TestCase
{
    public $url = 'https://acme-staging.api.letsencrypt.org/';

    public $keyPath = '/nexycrypt.private_key';

    public function testCreate()
    {
        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->create();

        $this->assertSame(true, file_exists(sys_get_temp_dir().$this->keyPath));
    }

    public function testRegister()
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

    public function testAgreeTerms()
    {
        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->register();
        $response = $cryptClient->agreeTerms();

        $this->assertNull($response);
    }

    public function testAuthorize()
    {
        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->register();
        $cryptClient->agreeTerms();
        $ftpServer = json_decode(file_get_contents('tests/ftpserver.json'), true);
        $response = $cryptClient->authorize($ftpServer['ftpserver']);
        $challenge = $response->getChallenges()->getHttp01();
        $getDns = $response->getChallenges()->getDns01();
        $getTls = $response->getChallenges()->getTlsSni01();
        $getOfType = $response->getChallenges()->getOfType('http-01');
        $checkFileName = $challenge->getFileName();
        $checkFileContent = $challenge->getFileContent();

        $this->assertTrue(isset($checkFileName));
        $this->assertTrue(isset($checkFileContent));
        $this->assertInstanceOf(Dns01Challenge::class, $getDns);
        $this->assertInstanceOf(TlsSni01Challenge::class, $getTls);
        $this->assertTrue($getOfType instanceof ChallengeInterface);

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

        $result = $this->getMethodCertificateTest($cryptClient, $signResult);
        $fileArr = $signResult->getFilesArray();

        $this->assertInstanceOf(PrivateKey::class, $result['resType']);
        $this->assertSame($fileArr['privkey.pem'], $result['getPrivKey']);
        $this->assertSame($fileArr['pubkey.pem'], $result['getPubKey']);
        $this->assertSame($fileArr['csr.pem'], $result['getCsr']);
        $this->assertSame($fileArr['fullchain.pem'], $result['getFullChain']);
        $this->assertSame($fileArr['cert.pem'], $result['getCert']);
        $this->assertSame($fileArr['chain.pem'], $result['getChain']);
        $this->assertInstanceOf(\DateTime::class, $result['getValidFrom']);
        $this->assertInstanceOf(\DateTime::class, $result['getValidTo']);
    }

    /*
    * when the nexycrypt.private_key is missing, we skip the step0 and step1 then do the step2 directly will throw the AcmeApiException message:
    * [urn:acme:error:unauthorized] Must agree to subscriber agreement before any further actions
    */
    public function testAcmeApiException()
    {
        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

        $this->expectException(AcmeApiException::class);

        @unlink(sys_get_temp_dir().$this->keyPath);

        $client->register();
        $client->agreeTerms();

        try {
            $ftpServer = json_decode(file_get_contents('tests/ftpserver.json'), true);
            $authorization = $client->authorize($ftpServer['ftpserver']);

            $challenge = $authorization->getChallenges()->getHttp01();
        } catch (AcmeApiException $e) {

            throw $e;
        }
    }

    /*
    * when the nexycrypt.private_key or your specified private key size is less than 2048, it wiil get the message: the key is too small.
    */
    public function testWeakKey()
    {
        $client = new NexyCrypt('tests/account.key', 'https://acme-staging.api.letsencrypt.org/');

        $this->expectException(AcmeApiException::class);

        $client->register();
        $client->agreeTerms();

        try {
            $ftpServer = json_decode(file_get_contents('tests/ftpserver.json'), true);
            $authorization = $client->authorize($ftpServer['ftpserver']);

            $challenge = $authorization->getChallenges()->getHttp01();
        } catch (AcmeApiException $e) {
            throw $e;
        }
    }

    public function testGetKey()
    {
        $key = new PrivateKey('tests/account.key');
        $accountKey = $key->getKey();
        $this->assertInternalType('resource', $accountKey);
    }

    public function testExceptionClass()
    {
        $exceptionData = [
            'type' => 'urn:acme:error:unauthorized',
            'detail' => 'Must agree to subscriber agreement before any further actions',
            'status'=> '400',
        ];
        $exception = new AcmeApiException($exceptionData['type'], $exceptionData['detail'], $exceptionData['status']);
        $getType = $exception->getType();
        $getDetails = $exception->getDetails();

        $this->assertSame($exceptionData['type'], $getType);
        $this->assertSame($exceptionData['detail'], $getDetails);
    }

    public function testIdentifier()
    {
        $identifier = new Identifier('type', 'value');
        $type = $identifier->getType();
        $value = $identifier->getValue();

        $this->assertInternalType('string', $type);
        $this->assertInternalType('string', $value);
    }

    public function testAuthorization()
    {
        $authorization = new Authorization();
        $authorization->setIdentifier(new Identifier('type', 'value'));
        $identifier = $authorization->getIdentifier();
        $authorization->setExpires(new \DateTime(substr('2016-10-10T17:40:22.021606949Z', 0, -4)));
        $expires = $authorization->getExpires();
        $key = new PrivateKey('tests/account.key');
        $challengeData = [
            'type' => 'http-01',
            'status' => 'pending',
            'uri' => 'https://acme-staging.api.letsencrypt.org/acme/challenge/k7DmyZTCgHnGQNl2THKxOAQZ6wFKvExs-JaDP4OWPc8/15702577',
            'token' => 'my-zj0dIovJFQUxzvLqydh3SZy1-YxNmaHPVJYo2j2g',
        ];
        $authorization->setStatus($challengeData['status']);
        $status = $authorization->getStatus();
        $challenge = ChallengeFactory::create($challengeData['type'], $challengeData, $key);
        $authorization->addChallenge($challenge);
        $authorization->removeChallenge($challenge);

        $this->assertInstanceOf(Identifier::class, $identifier);
        $this->assertSame($challengeData['status'], $status);
    }

    public function testNullChallenge()
    {
        $key = new PrivateKey('tests/account.key');
        $challenge = ChallengeFactory::create('type', [], $key);
        $this->assertNull($challenge);
    }

    public function testHttp01Challenge()
    {
        $httpChallenge = new Http01Challenge();
        $verifyDir = $httpChallenge->getDirectory();
        $verifyPath = $httpChallenge->getPath();

        $this->assertInternalType('string', $verifyDir);
        $this->assertInternalType('string', $verifyPath);
    }

    public function testDns01Challenge()
    {
        $dnsChallenge = new Dns01Challenge();
        $recordName = $dnsChallenge->getRecordName();
        $recordType = $dnsChallenge->getRecordType();
        $recordContent = $dnsChallenge->getRecordContent();

        $this->assertInternalType('string', $recordName);
        $this->assertInternalType('string', $recordType);
        $this->assertInternalType('string', $recordContent);
    }

    public function testAuthInvalid()
    {
        $this->fakeCreate();
        $this->fakeRegister();
        $this->fakeAuthorize();
        $this->uploadFile();

        $cryptClient = new NexyCrypt(null, $this->url);
        $cryptClient->register();
        $cryptClient->agreeTerms();
        $ftpServer = json_decode(file_get_contents('tests/ftpserver.json'), true);
        $response = $cryptClient->authorize($ftpServer['ftpserver']);
        $challenge = $response->getChallenges()->getHttp01();

        $result = $this->verifyChallengeTest($cryptClient);

        $this->assertFalse($result);
    }

    public function uploadFile()
    {
        $accounts = json_decode(file_get_contents('tests/ftpserver.json'), true);
        $user = $accounts['username'];
        $password = $accounts['password'];
        $ftpServer = $accounts['ftpserver'];

        $connectId = ftp_connect($ftpServer);

        $loginResult = ftp_login($connectId, $user, $password);

        ftp_pasv($connectId, true);

        if (!$loginResult) {
            echo "can't login";
            exit(1);
        }

        @ftp_mkdir($connectId, '.well-known');
        @ftp_mkdir($connectId, '.well-known/acme-challenge');

        ftp_chdir($connectId, '.well-known/acme-challenge');

        $filePath = 'tests/public/acme-challenge';
        $filesArr = scandir($filePath);
        $fileCount = count($filesArr);
        for($index=2;$index<$fileCount;$index++) {
            if($filesArr[$index] !== 'challenge') {
                continue;
            }

            $result = ftp_put($connectId, $filesArr[$index], $filePath.'/'.$filesArr[$index], FTP_ASCII);
            if ($result === false) {
                echo 'cannot upload file: '.$filesArr[$index];
                exit(1);
            }
        }

        ftp_close($connectId);
    }

    public function fakeCreate()
    {
        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');
        $client->create();
    }

    public function fakeRegister()
    {
        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');
        $client->register();
        $client->agreeTerms();
    }

    public function fakeAuthorize()
    {
        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');
        $ftpServer = json_decode(file_get_contents('tests/ftpserver.json'), true);
        $authorization = $client->authorize($ftpServer['ftpserver']);

        $challenge = $authorization->getChallenges()->getHttp01();
        
        $challengePath = 'tests/public/acme-challenge';
        @unlink($challengePath);
        @mkdir($challengePath);
        file_put_contents($challengePath.'/'.$challenge->getFileName(), $challenge->getFileContent());
        file_put_contents($challengePath.'/challenge', serialize($challenge));
    }

    public function verifyChallengeTest(NexyCrypt $cryptClient)
    {
        $challenge = unserialize(file_get_contents(__DIR__.'/'.'public'.'/acme-challenge'.'/challenge'));
        $response = $cryptClient->verifyChallenge($challenge);

        return $response;
    }

    public function generateCertificateTest(NexyCrypt $certClient)
    {
        $ftpServer = json_decode(file_get_contents('tests/ftpserver.json'), true);
        $certificate = $certClient->generateCertificate([$ftpServer['ftpserver']]);

        return $certificate;

    }

    public function signCertificateTest(NexyCrypt $certClient, Certificate $generateResult)
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

    public function getMethodCertificateTest(NexyCrypt $cryptClient, Certificate $signResult)
    {
        $resType = $this->getPrivateKeyTest($cryptClient);
        $fileArr = $signResult->getFilesArray();
        $getPrivKey = $signResult->getPrivkey();
        $getPubKey = $signResult->getPubkey();
        $getCsr = $signResult->getCsr();
        $getFullChain = $signResult->getFullchain();
        $getCert = $signResult->getCert();
        $getChain = $signResult->getChain();
        $getValidFrom = $signResult->getValidFrom();
        $getValidTo = $signResult->getValidTo();

        return [
            'resType' => $resType,
            'fileArr' => $fileArr,
            'getPrivKey' => $getPrivKey,
            'getPubKey' => $getPubKey,
            'getCsr' => $getCsr,
            'getFullChain' => $getFullChain,
            'getCert' => $getCert,
            'getChain' => $getChain,
            'getValidFrom' => $getValidFrom,
            'getValidTo' => $getValidTo,
        ];
    }

}
