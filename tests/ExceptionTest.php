<?php

namespace Nexy\NexyCrypt\Tests;

use PHPUnit\Framework\TestCase;
use Nexy\NexyCrypt\NexyCrypt;

class ExceptionTest extends TestCase
{
     public $ftpServer = 'nexycrypt.esy.es';
     public $user = 'u431315912';
     public $password = '8dpv8LvjEE';
     public $wellKnown = '.well-known';
     public $acmeChallenge = 'acme-challenge';

    /** @test */
    public function acmeApiExceptionTest()
    {
        //.well-known is not existed in your specified web document root file path.

        $client = new NexyCrypt(null, 'https://acme-staging.api.letsencrypt.org/');

        $this->expectException(\Nexy\NexyCrypt\Exception\AcmeApiException::class);

        $fileName = 'challenge';

        $this->deleteRemoteFile($fileName);

        // the challenge file is not existed.
        try {
            $client->register();
            $client->agreeTerms();
            $challenge = unserialize(file_get_contents('tests/public/'.'acme-challenge'.'/challenge'));
            $client->verifyChallenge($challenge);
        } catch (AcmeApiException $e) {
            throw $e;
        }

        $this->addRemoteFile($fileName);
    }

    public function deleteRemoteFile($fileName)
    {
        //this web hosting is only for testing, DO NOT use for ypur production!
        // it will be close in the irregular time.

        $connect = ftp_connect($this->ftpServer);
        $result = ftp_login($connect, $this->user, $this->password);

        ftp_pasv($connectId, true);

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

        ftp_pasv($connectId, true);

        if($result === false) {
            die('ftp logn is failed.');
        }

        ftp_chdir($connect, $this->wellKnown);
        ftp_chdir($connect, $this->acmeChallenge);

        ftp_put($connect, $fileName, __DIR__.'/public/acme-challenge'.'/'.$fileName, FTP_ASCII);

        ftp_close($connect);
    }
}
